#!/usr/bin/python3 -IB
"""Accept a confirmed owner brief through the existing product conductor."""

import argparse
import contextlib
from datetime import datetime, timezone
from decimal import Decimal
import errno
import fcntl
import getpass
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checklist_candidate as candidate
import job_protocol as p
import product_job as product
import provider_billing as billing
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private
from startup_delivery import IDS, load_private

SITE = Path('/etc/dev-pair/product-intake')
CREDENTIALS = billing.CREDENTIALS
SLOT_BILLING = '.billing-reauthorization.json'
ROOT = candidate.ROOT
CATALOGUE = ROOT / 'product-jobs'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
MODEL = billing.MODEL
ROLES = {'maintenance': 'dp-maint', 'development': 'dp-dev'}
MAX_INPUT = 8192
MAX_SLOTS = 64
QUEUE_ATTEMPTS = 8
PREPARE_ATTEMPTS = 4
RETRY_SECONDS = 30
PREPARE_SECONDS = 300
SEED_BYTES = 6 * 1024 * 1024
SEED_ENTRIES = 10000
WORKLOADS = {'checklist-persistence': 'checklist-quadlet', 'general-development': 'devbox-development',
             'general-with-external-validation': 'devbox-development-needs-host'}
CHECKLIST = 'checklist-persistence'
EXTERNAL_PENDING = 'general-with-external-validation'
LEGACY_SCHEDULING_FAILURES = {
    'Job preparation stopped. protected fixed command failed',
    'Job preparation stopped. OSError',
    'Job preparation stopped. TimeoutError',
    'Job preparation stopped. FileNotFoundError',
}
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}')
JOB = re.compile(r'[a-z0-9][a-z0-9-]{0,47}')


def repository_id(value):
    p.require(type(value) is str and REPOSITORY.fullmatch(value)
              and all(part not in ('.', '..') for part in value.split('/')), 'Use an authorized owner/repository name.')
    return value


def job_id(value):
    p.require(type(value) is str and JOB.fullmatch(value), 'Invalid job ID.')
    return value


def owner_text(value, limit, *, optional=False):
    p.require(type(value) is str and len(value.encode()) <= limit and
              (optional or bool(value.strip())) and
              all(char in '\n\t' or char.isprintable() for char in value), 'Owner input is missing, invalid or too long.')
    return value.strip()


def boot_id():
    return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


class DispatchDeferred(Exception):
    pass


def checked_file(path, limit=p.MAX_MESSAGE):
    return candidate.protected_file(path, limit)


def verify_slot_billing(settings, proofs):
    pricing = settings['pricing']
    p.fields(pricing, 'max_context_tokens input_microusd_per_million output_microusd_per_million observed_models '
             'context_evidence_sha256 tariff_evidence_sha256')
    for kind, raw in proofs.items():
        p.require(p.sha256(raw) == pricing[kind + '_evidence_sha256'], 'The approved provider pricing evidence has changed.')
    reference = settings['allowance_ref']
    approved, review = billing.validate_proofs(proofs, reference)
    billing.assert_current(review)
    secret = billing.credential_from(CREDENTIALS / reference)
    p.require(settings['billing_scope'] == billing.ALLOWANCE_KIND and
              approved == {key: pricing[key] for key in billing.PRICING} and
              settings['expires_unix'] <= review['expires_unix'] and billing.matches_request(review['request'], reference, secret),
              'The slot exceeds the reviewed provider billing scope.')
    return pricing


def fixed_git(checkout, *args, cap=8192, data=None):
    return candidate.invoke(['/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                             'GIT_NO_LAZY_FETCH=1', 'GIT_NO_REPLACE_OBJECTS=1', 'GIT_TERMINAL_PROMPT=0',
                             *candidate.GIT, '-C', str(checkout), *args],
                            time.monotonic() + 15, cap=cap, data=data)


def verify_bundle(checkout, commit):
    p.require(fixed_git(checkout, 'rev-parse', '--is-shallow-repository') == b'false\n',
              'The approved acquisition requires its full Git history.')
    try:
        bundle = fixed_git(checkout, 'bundle', 'create', '--version=2', '-', 'HEAD', cap=candidate.MAX_BUNDLE)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError('The acquisition cannot produce the bounded Git bundle used to initialize both roles.') from None
    header = b'# v2 git bundle\n' + commit.encode('ascii') + b' HEAD\n\nPACK'
    p.require(bundle.startswith(header), 'The Git bundle does not contain the exact approved acquisition.')
    return bundle


def verify_acquired_git(git, checkout, approval, *, checklist):
    repo, commit, tree = (approval[key] for key in ('repository', 'acquired_commit', 'acquired_tree'))
    if checklist:
        candidate.approved_source(git, checkout, approval, commit)
        return
    origin = git('config', '--local', '--no-includes', '--get-all', 'remote.origin.url').decode().removesuffix('\n')
    p.require(origin in (f'https://github.com/{repo}', f'https://github.com/{repo}.git', f'git@github.com:{repo}.git'),
              'The checkout origin differs from the approved repository.')
    p.require(git('rev-parse', '--show-toplevel').decode().removesuffix('\n') == str(checkout) and
              git('rev-parse', '--verify', 'HEAD').decode().strip() == commit and
              git('rev-parse', '--verify', commit + '^{tree}').decode().strip() == tree,
              'The checkout differs from the approved Git acquisition.')


def exact_private(path, data):
    """Publish a prepared immutable input, or verify its exact retry."""
    if os.path.lexists(path):
        p.require(read_private(path, len(data)) == data, 'A prepared job input changed.')
    else:
        write_private(path, data)
        sync_directory(path.parent)


def stage_document(path, data):
    """Keep the reviewed seed ownership, mode and SELinux label."""
    node = path.lstat()
    p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
              not node.st_mode & 0o222 and len(data) <= 262144, 'The approved startup seed is unsafe.')
    metadata = {key: os.getxattr(path, key) for key in os.listxattr(path)}
    fd, name = tempfile.mkstemp(prefix='.document-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchown(stream.fileno(), node.st_uid, node.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(node.st_mode))
            for key, value in metadata.items():
                os.setxattr(stream.fileno(), key, value)
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def private_leaf(path):
    if not os.path.lexists(path):
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    return trusted_directory(path)


def protect_directory(path):
    return product.h.host_runtime().protected(path, file=False)


def seed_digest(path, destination=None):
    from renewal import TreeCopy

    protect_directory(path)
    entries = 0
    deadline = time.monotonic() + 12
    for folder, directories, filenames in os.walk(path, followlinks=False):
        for name in (*directories, *filenames):
            entries += 1
            node = (Path(folder) / name).lstat()
            p.require(entries <= SEED_ENTRIES and time.monotonic() < deadline and node.st_uid == 0 and
                      not node.st_mode & 0o022 and (stat.S_ISDIR(node.st_mode) or
                      stat.S_ISREG(node.st_mode) and node.st_nlink == 1), 'The reviewed role seed contains an unsafe input.')
    reader = TreeCopy(SEED_BYTES, deadline)
    reader.entries = SEED_ENTRIES
    return reader.visit(path, destination)


def manifest_bytes(manifest):
    # The public approval command hashes this exact on-disk serialization.
    import gptbox
    return gptbox.image_inputs_bytes(manifest)


class Intake:
    def __init__(self, site=SITE, root=ROOT):
        self.site = site
        self.root = root
        self.catalogue = root / 'product-jobs'
        self.queue = self.catalogue / 'intake'

    @contextlib.contextmanager
    def lock(self):
        path = trusted_directory(self.catalogue) / 'intake.lock'
        p.private_file(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def catalogue_settings(self):
        row = p.loads(checked_file(self.site / 'repositories.json'))
        p.fields(row, 'schema repositories slots')
        p.number(row['schema'], 1, 1)
        repositories, slots = row['repositories'], row['slots']
        p.require(type(repositories) is dict and 0 < len(repositories) <= MAX_SLOTS and
                  type(slots) is list and 0 < len(slots) <= MAX_SLOTS, 'The approved site catalogue is incomplete.')
        p.require(len(set(map(job_id, slots))) == len(slots), 'The site catalogue repeats a job ID.')
        for repo, entry in repositories.items():
            repository_id(repo)
            p.fields(entry, 'commit startup_revision destination workloads' if 'workloads' in entry
                     else 'commit startup_revision destination')
            p.digest(entry['commit'], 40)
            p.digest(entry['startup_revision'], 40)
            owner_text(entry['destination'], 250)
            workloads = entry.get('workloads', [CHECKLIST])
            p.require(type(workloads) is list and 0 < len(workloads) <= len(WORKLOADS) and
                      all(type(item) is str and item in WORKLOADS for item in workloads) and len(set(workloads)) == len(workloads),
                      'The approved repository workload policy is invalid.')
        return repositories, slots

    def source(self, repository, config, *, checklist=True, include_bundle=False):
        from owner_source import require_private_directory

        require_private_directory(self.site)
        base = self.site / 'repositories' / repository
        checkout = protect_directory(base / 'acquired')
        startup = protect_directory(base / 'startup')
        cache = protect_directory(self.site / 'standards')
        tree, startup_sha, bundle = self.verify_source(repository, config, checkout, startup, cache, checklist=checklist)
        result = (checkout, startup, cache, tree, startup_sha)
        return (*result, bundle) if include_bundle else result

    def verify_source(self, repository, config, checkout, startup, cache, *, checklist):
        from owner_source import private_standards

        if private_standards(cache):
            raise FileNotFoundError('The exact private standards cache is incomplete.')
        checked_file(checkout / '.git/config', 8192)
        commit = config['commit']
        tree = fixed_git(checkout, 'rev-parse', '--verify', commit + '^{tree}').decode().strip()
        p.digest(tree, 40)
        verify_acquired_git(lambda *args, **kw: fixed_git(checkout, *args, **kw), checkout,
                            {'repository': repository, 'acquired_commit': commit, 'acquired_tree': tree},
                            checklist=checklist)
        corpus = load_private(startup, cache, config['startup_revision'], time.monotonic() + 20)
        return tree, p.sha256(manifest_bytes(corpus.manifest)), verify_bundle(checkout, commit)

    def release_slots(self):
        import renewal

        controller = renewal.Renewal(self.root, None)
        selected = controller.live_release()
        release = controller.release(selected)
        plan_sha = release['plan_sha256']
        raw = checked_file(controller.control / 'plans' / (plan_sha + '.json'))
        p.require(p.sha256(raw) == plan_sha, 'The approved role launch plan has changed.')
        plan = p.loads(raw)
        p.fields(plan, 'schema maintenance_context_sha256 development_manifests')
        p.number(plan['schema'], 1, 1)
        p.require(type(plan['development_manifests']) is dict, 'The approved job layout is unavailable.')
        return controller, selected, plan['development_manifests']

    def slot_documents(self, job, *, staging=None, replacement=None):
        job_id(job)
        slot = self.site / 'slots' / job if staging is None else staging
        profile = checked_file(slot / 'profile.json')
        roles = {name: checked_file(slot / name / 'profile.json', MAX_INPUT) for name in ROLES}
        overlay = slot / SLOT_BILLING
        if replacement is None and os.path.lexists(overlay):
            replacement = p.loads(checked_file(overlay))
        if replacement is None:
            settings = p.loads(profile)
            p.require(type(settings) is dict and settings.get('billing_scope') == billing.ALLOWANCE_KIND,
                      'This unused slot needs explicit signed provider billing reauthorization.')
            proofs = {kind: checked_file(slot / (MODEL + '.' + kind), 1024 * 1024) for kind in ('context', 'tariff')}
            return profile, roles, proofs
        p.fields(replacement, 'schema binding settings grant proofs consent_sha256')
        p.number(replacement['schema'], 1, 1)
        p.digest(replacement['consent_sha256'])
        p.require(staging is None and replacement['binding'] == self.slot_billing_binding(job, profile, roles),
                  'The existing catalogue or slot changed after billing reauthorization.')
        settings = replacement['settings']
        p.fields(replacement['proofs'], 'context tariff')
        proofs = {kind: raw.encode() for kind, raw in replacement['proofs'].items()}
        roles = {role: p.canonical(dict(p.loads(raw), credential_ref=settings['allowance_ref'],
                                       grant=replacement['grant'])).encode() for role, raw in roles.items()}
        return p.canonical(settings).encode(), roles, proofs

    def slot_billing_binding(self, job, profile, roles):
        return p.identity({'job': job, 'catalogue': p.sha256(checked_file(self.site / 'repositories.json')),
                           'profile': p.sha256(profile), 'roles': {name: p.sha256(raw) for name, raw in roles.items()}})

    def slot(self, job, dev_manifest, *, staging=None, replacement=None):
        from gptbox import capture_release_file
        from provider_broker import grant_document, reserved_cost

        slot = self.site / 'slots' / job if staging is None else staging
        profile, documents, proofs = self.slot_documents(job, staging=staging, replacement=replacement)
        settings = p.loads(profile)
        p.fields(settings, 'schema host_seconds build_seconds turn_seconds allowance_ref spend_microusd expires_unix pricing'
                 ' billing_scope')
        p.require(settings['billing_scope'] == billing.ALLOWANCE_KIND, 'Unknown owner billing scope.')
        p.number(settings['schema'], 1, 1)
        p.number(settings['host_seconds'], 25, 60)
        p.number(settings['build_seconds'], 20, 240)
        p.number(settings['turn_seconds'], 5, 120)
        p.number(settings['spend_microusd'], 1, 100000000)
        p.number(settings['expires_unix'], 1, 2**63 - 1)
        p.require(settings['expires_unix'] > time.time() + 2 * (settings['host_seconds'] + settings['build_seconds']
                                                                + settings['turn_seconds']) + 60,
                  'The approved provider allowance expires before this job can finish.')
        pricing = verify_slot_billing(settings, proofs)
        roles, seeds = {}, {}
        reserve = 0
        for role in ROLES:
            profile = p.loads(documents[role])
            p.fields(profile, 'runtime_sha256 binary_sha256 layout_sha256 credential_ref grant')
            for key in ('runtime_sha256', 'binary_sha256', 'layout_sha256'):
                p.digest(profile[key])
            p.token(profile['credential_ref'])
            p.require(profile['credential_ref'] == settings['allowance_ref'],
                      'The role credential differs from the reviewed provider account.')
            credential = CREDENTIALS / profile['credential_ref']
            # Check custody without loading the credential into the intake process.
            node = credential.lstat()
            protect_directory(credential.parent)
            p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
                      0 < node.st_size <= MAX_INPUT and not node.st_mode & 0o077,
                      'The approved role credential is unavailable.')
            grant = profile['grant']
            p.fields(grant, 'spend_microusd seconds max_requests max_request_bytes max_output_tokens')
            account = pwd.getpwnam(ROLES[role])
            grant = dict(grant, auth_profile='openai-api-key', allowance_ref=settings['allowance_ref'],
                         expires_unix=settings['expires_unix'], **{
                             key: pricing[key] for key in ('max_context_tokens', 'input_microusd_per_million',
                                                           'output_microusd_per_million', 'observed_models')})
            validated = grant_document(p.canonical(dict(grant, schema=1, request_sha256='0' * 64,
                                                         allowance_sha256='0' * 64,
                                                         peer_uid=account.pw_uid, peer_gid=account.pw_gid)).encode())
            p.require(grant['seconds'] >= settings['turn_seconds'] and
                      reserved_cost(validated) <= grant['spend_microusd'] <= settings['spend_microusd'],
                      'The approved role grant does not cover a bounded turn.')
            reserve += grant['spend_microusd']
            roles[role] = dict(profile, grant=grant)
            seeds[role] = seed_digest(slot / role / 'seed')
        p.require(reserve <= settings['spend_microusd'], 'The two role grants exceed the approved job allowance.')
        p.digest(dev_manifest)
        manifest = self.root / 'development/builds' / job / 'inputs' / dev_manifest / 'manifest.json'
        p.require(manifest.resolve(strict=True) == manifest and not manifest.stat().st_mode & 0o222,
                  'The approved DevBox manifest must be a fixed read-only leaf.')
        measured, _, raw = capture_release_file(manifest, p.MAX_MESSAGE, 0, contents=True)
        bound = p.loads(raw)
        p.require(measured == dev_manifest and bound['job'] == job and bound['standards_sha'] == p.STANDARDS,
                  'The approved DevBox layout for this job is missing.')
        return settings, roles, proofs, seeds

    def record(self, job):
        path = trusted_directory(self.queue) / (job_id(job) + '.json')
        return p.loads(read_private(path, p.MAX_MESSAGE))

    def save(self, job, record):
        product.durable_json(trusted_directory(self.queue) / (job_id(job) + '.json'), record)

    def slot_unused(self, job):
        occupied = [self.catalogue / 'jobs' / job, self.catalogue / 'profiles' / job,
                    self.queue / (job + '.plan'),
                    self.root / 'repository-approvals' / (job + '.json'),
                    self.root / 'repository-approvals' / job,
                    self.root / 'provider-allowances' / job,
                    *(self.root / 'renewal/registries' / role / job for role in ROLES)]
        if any(os.path.lexists(path) for path in occupied):
            return False
        for role in ROLES:
            for leaf in ('workspaces', 'state', 'cache'):
                path = self.root / role / leaf / job
                if os.path.lexists(path) and (path.is_symlink() or not path.is_dir() or next(path.iterdir(), None)):
                    return False
        return True

    def unused_slot(self, repo, slots, admitted):
        drafts, free = [], []
        for job in slots:
            if job not in admitted or not self.slot_unused(job):
                continue
            try:
                existing = self.record(job)
            except FileNotFoundError:
                free.append(job)
                continue
            if existing['phase'] == 'awaiting-confirmation' and existing['plan']['agreement']['repository'] == repo:
                drafts.append(job)
        reasons = []
        for job in drafts + free:
            try:
                return job, self.slot(job, admitted[job])
            except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
                reasons.append(product.h.bounded_diagnostic(str(exc)) if type(exc) is ValueError else type(exc).__name__)
        suffix = ' ' + reasons[0] if reasons else ''
        raise ValueError('No unused reviewed job slot is available for this repository.' + suffix)

    def draft(self, request):
        p.fields(request, 'action repository workload brief audience access acceptance constraints external_validation')
        repo = repository_id(request['repository'])
        workload = request['workload']
        p.require(type(workload) is str and workload in WORKLOADS, 'Choose how this outcome should be validated.')
        agreement = {'brief': owner_text(request['brief'], 1800),
                     'audience': owner_text(request['audience'], 350),
                     'access': owner_text(request['access'], 600),
                     'acceptance': owner_text(request['acceptance'], 900),
                     'constraints': owner_text(request['constraints'], 300, optional=True),
                     'external_validation': owner_text(request['external_validation'], 500,
                                                       optional=workload != EXTERNAL_PENDING),
                     'repository': repo, 'workload': workload}
        p.require(workload == EXTERNAL_PENDING or not agreement['external_validation'],
                  'Choose general development with an external validation request for that check.')
        repositories, slots = self.catalogue_settings()
        p.require(repo in repositories, 'This repository is outside the approved site catalogue.')
        config = repositories[repo]
        p.require(workload in config.get('workloads', [CHECKLIST]), 'This workload is outside the repository approval.')
        agreement['destination'] = config['destination']
        with self.lock():
            _, release, admitted = self.release_slots()
            job, (settings, roles, _, seeds) = self.unused_slot(repo, slots, admitted)
            _, _, _, tree, startup = self.source(repo, config, checklist=workload == CHECKLIST)
            # The existing conductor receives these confirmed answers as its bounded brief.
            lines = ['Owner brief', agreement['brief'], 'Intended users', agreement['audience'],
                     'Access and data boundary', agreement['access'], 'Product acceptance', agreement['acceptance'],
                     'Private delivery destination', config['destination'], 'Owner constraints',
                     agreement['constraints'] or 'Use the confirmed site scope below.', 'Site scope']
            if workload == CHECKLIST:
                lines.append('Repair restart persistence in the existing checklist and preserve its access and sharing policy. '
                             'Use the bounded checklist Quadlet check and the reviewed private release process.')
            else:
                lines.append('Edit and test the approved repository in confined DevBox. '
                             'Use the reviewed private release process. Host and external operations require their own admitted adapter.')
            if agreement['external_validation']:
                lines.extend(['Requested external validation pending an admitted adapter', agreement['external_validation']])
            value = {'schema': 1, 'job_id': job, 'adapter': WORKLOADS[workload], 'startup_sha256': startup,
                     'agreement': dict(repository=repo, initial_commit=config['commit'], brief='\n\n'.join(lines),
                                       **{key: settings[key] for key in ('host_seconds', 'build_seconds', 'turn_seconds')})}
            plan = product.plan(p.canonical(value))
            preview = {'plan': plan, 'product_agreement': agreement, 'source_tree': tree,
                       'startup_revision': config['startup_revision'],
                       'standards_sha': p.STANDARDS, 'release_sha256': release, 'dev_manifest_sha256': admitted[job],
                       'site_profile_sha256': p.identity([settings, roles, seeds, config]),
                       'provider_microusd': settings['spend_microusd'], 'expires_unix': settings['expires_unix'],
                       'provider_limits': {name: {key: profile['grant'][key] for key in (
                           'spend_microusd', 'seconds', 'max_requests', 'max_request_bytes',
                           'max_context_tokens', 'max_output_tokens')} for name, profile in roles.items()}}
            self.save(job, {'phase': 'awaiting-confirmation', 'plan': plan, 'preview': preview,
                            'agreement_token': p.identity(preview), 'diagnostics': None})
        return self.status(job)

    def confirm(self, job, token):
        p.digest(token)
        with self.lock():
            p.require_workload_access(self.root)
            saved = self.record(job)
            p.require(saved['agreement_token'] == token and p.identity(saved['preview']) == token,
                      'The agreement draft has changed. Review its exact new digest.')
            if saved['phase'] == 'awaiting-confirmation':
                p.require('product_agreement' in saved['preview'],
                          'Review a new draft with the intended users, access and observable acceptance before confirming.')
                saved['phase'] = 'confirmed'
                self.save(job, saved)
            self.schedule(job, saved, time.monotonic() + 10)
        return self.status(job)

    def published(self, job, plan, *, progress=False):
        root = self.catalogue / 'jobs' / job
        if not os.path.lexists(root):
            return None
        root = trusted_directory(root)
        p.require(product.plan(read_private(root / 'plan.json', p.MAX_MESSAGE)) == plan,
                  'The published product plan differs from the confirmed agreement.')
        state = product.read_progress(root) if progress else product.read_state(root)
        p.require(state['job_id'] == job and state['agreement_sha256'] == product.agreement_sha(plan) and
                  state['repository'] == plan['agreement']['repository'] and state['startup_sha256'] == plan['startup_sha256'],
                  'The published product state differs from the confirmed agreement.')
        return state

    def recovery(self, saved):
        current = boot_id()
        entry = saved.setdefault('recovery', dict(boot=current, after=0, queue_attempts=0, prepare_attempts=0))
        if entry['boot'] != current:
            entry.update(boot=current, after=0)
        return entry

    def block(self, job, saved, reason):
        saved.update(phase='blocked', diagnostics=reason)
        self.save(job, saved)

    def schedule(self, job, saved, deadline):
        p.require_workload_access(self.root)
        if saved['phase'] == 'blocked' and 'recovery' not in saved and saved['diagnostics'] in LEGACY_SCHEDULING_FAILURES:
            state = self.published(job, saved['plan'])
            if state is None or state['phase'] != 'submitted':
                return
            product.source_approval(saved['plan'])
            saved['phase'] = 'confirmed'
        if saved['phase'] == 'submitted':
            if saved.get('scheduled_boot') == boot_id():
                return
            state = self.published(job, saved['plan'])
            p.require(state is not None, 'The acknowledged product plan is unavailable.')
            if state['phase'] in product.TERMINAL or (state['phase'] == 'waiting' and not state.get('retry', {}).get('automatic')):
                return
        elif saved['phase'] not in ('confirmed', 'preparing'):
            return
        entry = self.recovery(saved)
        now = int(time.monotonic())
        if now < entry['after']:
            return
        if entry['queue_attempts'] >= QUEUE_ATTEMPTS or entry['prepare_attempts'] >= PREPARE_ATTEMPTS:
            self.block(job, saved, 'Automatic scheduling recovery reached its limit. The confirmed plan and job evidence are retained.')
            return
        entry['queue_attempts'] += 1
        entry['after'] = now + RETRY_SECONDS
        self.save(job, saved)
        try:
            candidate.invoke([SYSTEMCTL, 'start', '--no-block', 'dev-pair-intake@' + job + '.service'],
                             min(deadline, time.monotonic() + 5))
        except (OSError, ValueError, subprocess.SubprocessError):
            saved['diagnostics'] = 'The agreement is confirmed. Waiting to schedule the same preparation service.'
            self.save(job, saved)

    def reconcile(self):
        p.require_workload_access(self.root)
        end = time.monotonic() + 20
        queue = trusted_directory(self.queue)
        for count, path in enumerate(queue.glob('*.json'), 1):
            p.require(count <= MAX_SLOTS, 'The retained intake catalogue exceeds its bound.')
            if time.monotonic() >= end:
                break
            job = job_id(path.stem)
            with self.lock():
                saved = self.record(job)
                try:
                    self.schedule(job, saved, end)
                except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
                    self.block(job, saved, 'Scheduling recovery stopped. ' + (
                        product.h.bounded_diagnostic(str(exc)) if type(exc) is ValueError else type(exc).__name__))
        return 0

    def status(self, job):
        saved = self.record(job)
        return {'job_id': job, 'phase': saved['phase'], 'agreement_token': saved['agreement_token'],
                'preview': saved['preview'], 'diagnostics': saved['diagnostics']}

    def observed(self, job, status=None):
        status = self.status(job) if status is None else status
        try:
            downstream = self.published(job, status['preview']['plan'], progress=True)
            p.require(downstream is not None or status['phase'] != 'submitted', 'Product state is unavailable.')
        except (OSError, ValueError, KeyError, TypeError):
            if status['phase'] == 'submitted':
                status.update(phase='blocked', diagnostics='The saved agreement is available. Product state is unavailable.')
            return status
        if downstream is not None:
            if status['phase'] == 'submitted' and not status['diagnostics']:
                status.update(downstream)
            else:
                status['product_phase'] = downstream['phase']
                for field in ('maintenance', 'development', 'first', 'final', 'local_validation', 'promotion'):
                    if field in downstream:
                        status[field] = downstream[field]
        return status

    def prepare(self, job):
        p.require_workload_access(self.root)
        # The root-owned unit continues if the caller leaves immediately after confirmation.
        with self.lock():
            record = self.record(job)
            if record['phase'] == 'submitted' and record.get('scheduled_boot') == boot_id():
                return 0
            p.require(record['phase'] in ('confirmed', 'preparing', 'submitted'), 'The owner has not confirmed this agreement.')
            entry = self.recovery(record)
            if entry['prepare_attempts'] >= PREPARE_ATTEMPTS:
                self.block(job, record, 'Automatic preparation reached its limit. The confirmed plan and job evidence are retained.')
                return 2
            entry['prepare_attempts'] += 1
            entry['after'] = int(time.monotonic()) + PREPARE_SECONDS + RETRY_SECONDS
            record['phase'] = 'preparing'
            self.save(job, record)
        try:
            self.stage(job, record)
        except (OSError, ValueError, RuntimeError, KeyError, ImportError, subprocess.SubprocessError, DispatchDeferred) as exc:
            deferred = isinstance(exc, (BlockingIOError, DispatchDeferred)) or str(exc) in (
                'role dispatch frozen by renewal', 'role dispatch frozen pending host observation')
            with self.lock():
                if deferred:
                    entry['after'] = int(time.monotonic()) + RETRY_SECONDS
                    record['diagnostics'] = str(exc) if isinstance(exc, DispatchDeferred) else 'Waiting to continue the same confirmed job.'
                    self.save(job, record)
                    return 75
                self.block(job, record, 'Job preparation stopped. ' + (
                    product.h.bounded_diagnostic(str(exc)) if type(exc) is ValueError else type(exc).__name__))
            return 2
        with self.lock():
            record.update(phase='submitted', diagnostics=None, scheduled_boot=boot_id())
            self.save(job, record)
        return 0

    def submit_product(self, path, job, plan):
        state = self.published(job, plan)
        if state is not None and (state['phase'] in product.TERMINAL or
                                  (state['phase'] == 'waiting' and not state.get('retry', {}).get('automatic'))):
            return
        product.source_approval(plan)
        try:
            product.submit(path)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            if (not isinstance(exc, ValueError) or str(exc) == 'protected fixed command failed') and self.published(job, plan):
                product.source_approval(plan)
                raise DispatchDeferred('Product plan is durable. Waiting to schedule the same job.') from exc
            raise

    def stage(self, job, record):
        plan = record['plan']
        preview = record['preview']
        p.require(preview['plan'] == plan and preview['standards_sha'] == p.STANDARDS and
                  p.identity(preview) == record['agreement_token'] and plan['job_id'] == job,
                  'Confirmed agreement identity changed.')
        plan_path = self.queue / (job + '.plan')
        if os.path.lexists(self.catalogue / 'jobs' / job):
            # A previous preparation got as far as J publication. The product
            # entry verifies the original plan and owns resumption from here.
            exact_private(plan_path, p.canonical(plan).encode())
            self.submit_product(plan_path, job, plan)
            return

        from provider_broker import load_allowance

        agreement = plan['agreement']
        repository = agreement['repository']
        repositories, slots = self.catalogue_settings()
        p.require(repository in repositories and job in slots, 'The reviewed repository or slot was withdrawn.')
        config = repositories[repository]
        workload = preview.get('product_agreement', {}).get('workload', CHECKLIST)
        p.require(workload in config.get('workloads', [CHECKLIST]) and WORKLOADS.get(workload) == plan['adapter'],
                  'The confirmed workload is outside the repository approval.')
        controller, _, _ = self.release_slots()
        with controller.dispatch_gate():
            _, release, admitted = self.release_slots()
            p.require(release == preview['release_sha256'] and
                      admitted.get(job) == preview['dev_manifest_sha256'], 'The confirmed platform release has changed.')
            settings, roles, proofs, seeds = self.slot(job, admitted[job])
            p.require(p.identity([settings, roles, seeds, config]) == preview['site_profile_sha256'],
                      'The site scope or limits have changed. A new agreement is required.')
            checkout, startup, cache, tree, startup_sha, bundle = self.source(
                repository, config, checklist=workload == CHECKLIST, include_bundle=True)
            p.require((tree, startup_sha) == (preview['source_tree'], plan['startup_sha256']),
                      'The verified source or startup documents have changed.')
            exact_private(plan_path, p.canonical(plan).encode())
            approval = self.approve(plan, checkout, startup, cache, config['startup_revision'], tree)
            allowance = self.allowance(plan, settings, proofs)
            for role, profile in roles.items():
                selection = dict(job=job, repository=repository, agreement_sha256=product.agreement_sha(plan),
                                 model=MODEL, effort=billing.EFFORT)
                profile['grant']['allowance_sha256'] = allowance
                account = pwd.getpwnam(ROLES[role])
                load_allowance(job, allowance).validate_grant(selection, dict(profile['grant'],
                    schema=1, request_sha256='0' * 64, peer_uid=account.pw_uid, peer_gid=account.pw_gid))
                self.stage_role(role, job, profile, seeds[role], approval, startup_sha)
                self.acquire_role(role, job, account, agreement, tree, bundle, checklist=workload == CHECKLIST)
            self.submit_product(plan_path, job, plan)

    def approve(self, plan, checkout, startup, cache, revision, tree):
        job = plan['job_id']
        agreement = plan['agreement']
        path = self.root / 'repository-approvals' / (job + '.json')
        expected = dict(schema=1, job=job, repository=agreement['repository'],
            agreement_sha256=product.agreement_sha(plan), acquired_commit=agreement['initial_commit'],
            acquired_tree=tree, standards_sha=p.STANDARDS, startup_project_revision=revision,
            startup_sha256=plan['startup_sha256'])
        if not os.path.lexists(path):
            candidate.invoke([PYTHON, '-EBs', str(candidate.KIT / 'tools/gptbox.py'), 'approve-job',
                '--job', job, '--repository', agreement['repository'], '--agreement-sha256', expected['agreement_sha256'],
                '--acquired-checkout', str(checkout), '--acquired-sha', agreement['initial_commit'],
                '--startup-project', str(startup), '--startup-project-sha', revision, '--standards-cache', str(cache)],
                time.monotonic() + 35)
        approval = checked_file(path, 4096)
        p.require(p.loads(approval) == expected, 'The repository approval differs from the confirmed agreement.')
        return approval

    def allowance(self, plan, settings, proofs):
        p.require(settings.get('billing_scope') == billing.ALLOWANCE_KIND,
                  'New provider allowances require independently signed project billing.')
        job = plan['job_id']
        root = private_leaf(self.root / 'provider-allowances' / job)
        approval = {'schema': 1, 'kind': billing.ALLOWANCE_KIND,
                    'auth_profile': 'openai-api-key', 'job': job, 'repository': plan['agreement']['repository'],
                    'agreement_sha256': product.agreement_sha(plan),
                    'models': {MODEL: settings['pricing']},
                    **{key: settings[key] for key in ('allowance_ref', 'spend_microusd', 'expires_unix')}}
        raw = p.canonical(approval).encode()
        for kind, proof in proofs.items():
            exact_private(root / (MODEL + '.' + kind), proof)
        exact_private(root / 'allowance.json', raw)
        return p.sha256(raw)

    def stage_role(self, role, job, profile, seed_sha, approval, startup_sha):
        target = private_leaf(private_leaf(self.catalogue / 'profiles' / job) / role)
        raw = self.root / 'repository-approvals' / job
        manifest = checked_file(raw / 'manifest.json', 4096)
        p.require(p.sha256(manifest) == startup_sha, 'The approved startup manifest changed.')
        documents = {'manifest.json': manifest}
        for row in p.loads(manifest)['documents']:
            p.require(row['id'] in IDS, 'The approved startup manifest lists an unsupported item.')
            leaf = row['id'] + '.txt'
            data = checked_file(raw / leaf, 262144)
            p.require(len(data) == row['bytes'] and p.sha256(data) == row['sha256'],
                      'An approved startup document changed.')
            documents[leaf] = data
        p.require(set(documents) == {'manifest.json', *(name + '.txt' for name in IDS)}, 'The startup corpus is incomplete.')
        if not os.path.lexists(target / 'seed'):
            template = self.site / 'slots' / job / role / 'seed'
            with tempfile.TemporaryDirectory(prefix='.seed-', dir=target) as directory:
                copied = Path(directory) / 'seed'
                p.require(seed_digest(template, copied) == seed_sha, 'The reviewed role seed changed.')
                product.closed_write(copied / 'turn' / 'approval.json', approval)
                for name, data in documents.items():
                    stage_document(copied / 'turn' / 'startup' / name, data)
                copied.rename(target / 'seed')
                sync_directory(target)
        seed = protect_directory(target / 'seed')
        p.require(checked_file(seed / 'turn' / 'approval.json', 4096) == approval and all(
            checked_file(seed / 'turn' / 'startup' / name, len(data)) == data for name, data in documents.items()),
            'The prepared role seed differs from the approved input.')
        exact_private(target / 'profile.json', p.canonical(profile).encode())
        parent = protect_directory(self.root / 'turn-inputs' / role)
        turn_path = parent / job
        if not os.path.lexists(turn_path):
            turn_path.mkdir(mode=0o755)
            turn_path.chmod(0o755)
            sync_directory(parent)
        protect_directory(turn_path)

    def acquire_role(self, role, job, account, agreement, tree, bundle, *, checklist=True):
        root = self.root / role
        template = self.site / 'slots' / job / role / 'seed'
        label = os.getxattr(template / 'turn', 'security.selinux').rstrip(b'\0')
        p.require(re.fullmatch(rb'system_u:object_r:container_file_t:s0:c[0-9]+,c[0-9]+', label),
                  'The approved role seed does not have exact job categories.')
        for leaf in ('workspaces', 'state', 'cache'):
            path = root / leaf / job
            parent = path.parent
            info = parent.lstat()
            p.require(parent.resolve(strict=True) == parent and stat.S_ISDIR(info.st_mode) and
                      info.st_uid in (0, account.pw_uid) and not info.st_mode & 0o022,
                      'The approved role storage root is unavailable.')
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.setxattr(fd, 'security.selinux', label)
                    os.fchown(fd, account.pw_uid, account.pw_gid)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                sync_directory(parent)
            info = path.lstat()
            p.require(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode) and
                      (info.st_uid, info.st_gid) == (account.pw_uid, account.pw_gid) and
                      stat.S_IMODE(info.st_mode) == 0o700 and
                      os.getxattr(path, 'security.selinux').rstrip(b'\0') == label,
                      'The current role job directory differs from its reviewed private layout.')
            if leaf in ('state', 'cache'):
                p.require(next(path.iterdir(), None) is None, 'This slot contains prior role state.')
        workspace = root / 'workspaces' / job
        git = candidate.git_runner(workspace, ROLES[role], time.monotonic() + 50, allow_bundle=True)
        commit = agreement['initial_commit']
        verification = {'repository': agreement['repository'], 'acquired_commit': commit, 'acquired_tree': tree}
        contents = {child.name for child in workspace.iterdir()}
        if contents == {'.git'}:
            # Recover the ordinary partial stage before worktree checkout. A
            # retained populated tree must already be the exact clean checkout.
            p.require((workspace / '.git').is_dir() and not (workspace / '.git').is_symlink(),
                      'Retained role acquisition metadata is unavailable.')
        elif contents:
            verify_acquired_git(git, workspace, verification, checklist=checklist)
            p.require(not git('status', '--porcelain', '--untracked-files=all'), 'The retained role checkout has work.')
            return
        else:
            git('init', '--template=')
        origin = 'https://github.com/' + agreement['repository']
        git('config', '--local', '--replace-all', 'remote.origin.url', origin)
        inputs = root / 'conductor-inputs'
        info = inputs.lstat()
        p.require(inputs.resolve(strict=True) == inputs and stat.S_ISDIR(info.st_mode) and
                  (info.st_uid, info.st_gid) == (account.pw_uid, account.pw_gid) and
                  stat.S_IMODE(info.st_mode) == 0o700, 'The fixed role acquisition handoff directory is unavailable.')
        with tempfile.NamedTemporaryFile(prefix='.intake-', dir=inputs) as payload:
            payload.write(bundle)
            payload.flush()
            os.fchown(payload.fileno(), account.pw_uid, account.pw_gid)
            git('fetch', '--no-tags', '--no-recurse-submodules', payload.name, 'HEAD')
            p.require(git('rev-parse', '--verify', 'FETCH_HEAD').decode().strip() == commit,
                      'The exported Git acquisition differs from its approved commit.')
            git('checkout', '--detach', '--no-recurse-submodules', commit)
        verify_acquired_git(git, workspace, verification, checklist=checklist)
        p.require(not git('status', '--porcelain', '--untracked-files=all'), 'The approved role checkout is not clean.')


class SitePending(Exception):
    def __init__(self, prerequisite, message):
        self.observation = {'phase': 'pending', 'prerequisite': prerequisite, 'message': message}


def selected_site(intake):
    from bootstrap import Blocked, Bootstrap
    from commission_host import AUTOMATIC_POLICY, Blocked as CommissionBlocked, Live, read_policy
    from provider_transition import Deferred, Fence

    if not os.path.lexists(AUTOMATIC_POLICY):
        raise SitePending('core-commissioning', 'Finish the protected core installation with ./day0.sh resume.')
    raw = checked_file(Path(AUTOMATIC_POLICY))
    policy = read_policy(raw, p.loads(raw)['source_sha'])
    bootstrap = Bootstrap()
    bootstrap.run.deadline = time.monotonic() + 45
    live = Live(candidate.KIT, bootstrap)
    try:
        controller, selected, manifests = intake.release_slots()
        binding = live.verify_selection(controller, selected, policy)
        guard = bootstrap.verify_final_guard()
        p.require(bootstrap.destination_identity()['machine_id'] == policy['machine_id'],
                  'Owner setup belongs to a different inspected machine.')
    except (Blocked, CommissionBlocked, OSError, ValueError, KeyError, TypeError) as exc:
        raise SitePending('core-commissioning', 'Verify the selected core release and private tailnet cutover.') from exc
    try:
        Fence().require_ready()
        host = controller.release(selected)['components']['host']['artifact_sha256']
        p.digest(host)
        tools = live.installer.HOST_RELEASES / host / 'tools'
        billing.require_broker_release(Path(__file__).resolve().parent, tools)
    except Deferred as exc:
        raise SitePending('provider-transition', str(exc)) from exc
    except (KeyError, TypeError, OSError, ValueError) as exc:
        raise SitePending('provider-billing-runtime',
                          'Select the independently verified host release with matching scoped provider billing.') from exc
    site_sha = binding['site_config_sha256']
    site = live.installer.site_configuration(live.installer.SITE_CONFIGS / (site_sha + '.json'), site_sha)
    name = guard['target']['dns_name']
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    p.require(type(name) is str and re.fullmatch(label + r'\.' + label + r'\.ts\.net', name),
              'Current verified tailnet DNS is unavailable.')
    return controller, selected, manifests, site, binding, 'https://' + name + '/'


def development_labels(path, component, signed, deadline):
    from devbox import db
    from native_placements import directory_fd
    from platform_release_protocol import stream_exact

    config_sha = component['artifact_sha256']
    p.digest(config_sha)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with directory_fd(protect_directory(path.parent)) as parent, \
            os.fdopen(os.open(path.name, flags, dir_fd=parent), 'rb') as stream:
        directory, node = os.fstat(parent), os.fstat(stream.fileno())
        p.require(directory.st_uid == node.st_uid == 0 and not directory.st_mode & 0o022 and
                  stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and
                  stat.S_IMODE(node.st_mode) in (0o400, 0o440, 0o444, 0o600) and
                  0 < node.st_size == signed['archive_bytes'] <= 16 * 1024**3,
                  'Approved DevBox OCI archive is outside protected custody or its signed bound.')
        p.require(stream_exact(stream, node.st_size, deadline) == signed['archive_sha256'] and not stream.read(1),
                  'DevBox OCI archive digest differs from the selected signed transport.')
        stream.seek(0)
        db.check_archive_headers(Path('/proc/self/fd') / str(stream.fileno()), node.st_size, deadline)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            selected = None
            for index, entry in enumerate(archive):
                p.require(index < 512 and time.monotonic() < deadline, 'DevBox archive metadata exceeded its bound.')
                if db.archive_path(entry.name) != 'blobs/sha256/' + config_sha:
                    continue
                p.require(selected is None and entry.isfile() and 0 < entry.size <= db.OCI_METADATA_LIMIT,
                          'Invalid or repeated DevBox OCI config.')
                with archive.extractfile(entry) as config:
                    raw = config.read(db.OCI_METADATA_LIMIT + 1)
                p.require(p.sha256(raw) == config_sha, 'DevBox OCI config digest changed.')
                selected = db.json_data(raw)['config']['Labels']
        p.require(selected is not None, 'The selected DevBox archive lacks the exact OCI config.')
        seen = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        placed = path.parent.lstat()
        p.require((seen.st_dev, seen.st_ino, seen.st_size, seen.st_ctime_ns) ==
                  (node.st_dev, node.st_ino, node.st_size, node.st_ctime_ns) and
                  (placed.st_dev, placed.st_ino) == (directory.st_dev, directory.st_ino),
                  'DevBox OCI archive changed during selection.')
        return selected


def role_site_profiles(intake, controller, selected, binding, job, manifest_sha, geometry):
    import gptbox_runtime
    from devbox import db
    from gptbox import Commands, Gptbox, ROOT as MAINTENANCE_ROOT
    from gptbox_runtime import BUILD, JOB_INPUTS, PROVIDER_DIR
    from platform_release_intake import retained_index

    policy_runtime = p.sha256(Path(gptbox_runtime.__file__).read_bytes())
    release = controller.release(selected)
    portable, selected_index, _ = retained_index(binding['platform_sha256'])
    path = intake.root / 'development/builds' / job / 'inputs' / manifest_sha / 'manifest.json'
    manifest = db.read_manifest(path, manifest_sha, time.monotonic() + 10)
    p.require(manifest['job'] == job and manifest['categories'] == geometry['categories'] and
              manifest['storage_bytes'] == geometry['storage_bytes'], 'Current DevBox slot differs from site authority.')
    outer, inner = manifest['categories']['outer'], manifest['categories']['inner']
    other, = set(outer) - set(inner)
    # The three reserved categories provide a distinct pair for the sibling maintenance role.
    levels = {'development': inner, 'maintenance': sorted((inner[0], other))}
    maintenance = release['components']['maintenance-agent']
    context, revision, artifact = (maintenance[key] for key in ('config_sha256', 'source_revision', 'artifact_sha256'))
    commands = Commands()
    commands.deadline = time.monotonic() + 45
    engine = Gptbox(run=commands)
    engine.preflight(managed_runtime=True)
    engine.target = MAINTENANCE_ROOT + '/' + context
    with engine.lock():
        engine.admitted_maintenance_image(context, revision, artifact, binding['platform_sha256'])
        observed = {'maintenance': engine.maintenance_labels(context, revision, artifact)}
    development = release['components']['development-agent']
    signed = selected_index['components']['development-agent']
    inner = manifest['inner']
    p.require((inner['image_id'], inner['source_sha'], inner['context_sha256']) ==
              (development['artifact_sha256'], development['source_revision'], development['config_sha256']) ==
              (signed['oci_config_sha256'], signed['source_sha'], signed['context_sha256']) and
              all(inner[key] == signed[key] for key in ('archive_sha256', 'archive_bytes')),
              'Selected DevBox role differs from its signed release.')
    # The installed manifest is selected by digest beneath the dp-dev placement.
    # Read config bytes from the separately protected signed portable part.
    observed['development'] = development_labels(portable / 'development/development.oci.tar', development,
                                                 signed, time.monotonic() + 45)
    roles = {}
    for role, name in ROLES.items():
        account = pwd.getpwnam(name)
        row = selected_index['components'][role + '-agent']
        component = release['components'][role + '-agent']
        label = 'system_u:object_r:container_file_t:s0:' + ','.join('c' + str(category) for category in levels[role])
        labels = observed[role]
        binary = row['codex_sha256']
        runtime = labels['dev-pair.runtime']
        p.digest(binary)
        p.digest(runtime)
        p.require(runtime == policy_runtime, 'The selected role needs a matching verified host seed-policy renderer.')
        p.require(labels['dev-pair.role'] == role and labels['dev-pair.standards'] == p.STANDARDS and
                  labels['dev-pair.codex.sha256'] == binary and
                  labels['dev-pair.codex.version'] == row['codex_version'] and
                  labels['org.opencontainers.image.revision'] == component['source_revision'] and
                  labels['dev-pair.context'] == component['config_sha256'],
                  'Selected role labels do not bind the verified runtime and stock binary.')
        placement = ['/work/job', '/state', '/cache/job']
        if role == 'development':
            placement.append(BUILD)
        layout = {'job': job, 'role': role, 'site_config_sha256': binding['site_config_sha256'],
                  'manifest_sha256': manifest_sha, 'uid': account.pw_uid, 'gid': account.pw_gid,
                  'selinux_label': label, 'readonly_mounts': JOB_INPUTS,
                  'provider_mount': str(PROVIDER_DIR), 'work_storage': placement}
        roles[role] = {'runtime_sha256': runtime, 'binary_sha256': binary,
                       'layout_sha256': p.identity(layout), 'layout': layout}
    return roles


def provider_custody(reference):
    from commission_host import Blocked, Live

    if not reference:
        raise SitePending('provider-credential', 'Select a protected scoped credential reference. Keep its value out of the terminal.')
    p.token(reference)
    try:
        stamp = Live.credential_stamp(CREDENTIALS / reference)
    except FileNotFoundError as exc:
        raise SitePending('provider-credential',
                          'Register the scoped root-private API key with provider_billing.py register, then choose its reference.') from exc
    except (Blocked, OSError) as exc:
        raise SitePending('provider-credential-custody', 'Verify root ownership and private mode for the selected API credential.') from exc
    p.require(stamp[-1] <= MAX_INPUT, 'The protected provider credential exceeds the admitted size.')
    return stamp


def billing_authority(reference):
    try:
        return billing.authority(reference)
    except FileNotFoundError as exc:
        raise SitePending('provider-billing-evidence',
                          'Issue independently signed terms with provider_billing.py receive before selecting this credential.') from exc
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SitePending('provider-billing-authority',
                          'The provider custodian must supply valid signed terms for this exact credential and project.') from exc


def owner_provider(options):
    from provider_broker import PROFILE, reserved_cost

    if options.profile is None:
        raise SitePending('provider-profile', 'Select the independently authorized direct API profile for the first owner slot.')
    if options.profile != PROFILE:
        raise SitePending('unsupported-provider-profile', 'The installed broker needs a direct OpenAI API key and bounded allowance.')
    stamp = provider_custody(options.credential_ref)
    pricing, proofs, review = billing_authority(options.credential_ref)
    asserted = {'max_context_tokens': options.context_tokens, 'input_microusd_per_million': options.input_rate,
                'output_microusd_per_million': options.output_rate, 'observed_models': options.observed_model}
    p.require(all(value is None or value == pricing[key] for key, value in asserted.items()),
              'Requested billing values differ from the independently reviewed evidence.')
    limits = {'max_requests': options.requests, 'max_request_bytes': options.request_bytes,
              'max_output_tokens': options.output_tokens, 'seconds': options.turn_seconds}
    if None in limits.values() or options.spend_microusd is None or options.expires_unix is None:
        raise SitePending('provider-allowance', 'Supply the actual approved cap, expiry and request bounds from your provider authority.')
    for value, low, high in ((options.host_seconds, 25, 60), (options.build_seconds, 20, 240),
                             (options.turn_seconds, 5, 120), (options.expires_unix, 1, 2**63 - 1),
                             (limits['max_output_tokens'], 16, 65536)):
        p.number(value, low, high)
    if options.expires_unix <= time.time() + 2 * (options.host_seconds + options.build_seconds + options.turn_seconds) + 60:
        raise SitePending('provider-allowance-expired', 'The approved API allowance must cover the full bounded first job.')
    p.require(options.expires_unix <= review['expires_unix'], 'The job allowance expires after the signed provider terms.')
    for kind, raw in proofs.items():
        pricing[kind + '_evidence_sha256'] = p.sha256(raw)
    p.number(limits['max_requests'], 1, 32)
    p.number(options.spend_microusd, 1, 100000000)
    role_spend = reserved_cost(dict(pricing, **limits)) * limits['max_requests']
    p.require(0 < role_spend and 2 * role_spend <= options.spend_microusd,
              'Approved spend does not cover both requested role operation limits.')
    settings = {'schema': 1, 'host_seconds': options.host_seconds, 'build_seconds': options.build_seconds,
                'turn_seconds': options.turn_seconds, 'allowance_ref': options.credential_ref,
                'spend_microusd': options.spend_microusd, 'expires_unix': options.expires_unix, 'pricing': pricing,
                'billing_scope': billing.ALLOWANCE_KIND}
    return settings, dict(limits, spend_microusd=role_spend), proofs, stamp


def verify_startup_adoption(repository, startup, revision):
    from session_controller import SHARED

    checked_file(startup / '.git/config', 8192)
    startup_git = lambda *args, **kw: fixed_git(startup, *args, **kw)
    verify_acquired_git(startup_git, startup, {'repository': repository, 'acquired_commit': revision,
                        'acquired_tree': startup_git('rev-parse', '--verify', revision + '^{tree}').decode().strip()},
                        checklist=False)
    adoption = startup_git('show', revision + ':STANDARDS.md', cap=262144).decode()
    pins = re.findall(r'https://github\.com/oso-gato/standards/blob/([a-zA-Z0-9._-]+)/([^\s)]+)', adoption)
    p.require(set(pins) == {(p.STANDARDS, name) for name in SHARED},
              'The selected project must adopt all three exact shared standards references.')


def first_source(intake, repository, workload):
    tree = intake.site / 'repositories' / repository
    try:
        acquired = protect_directory(tree / 'acquired')
        startup = protect_directory(tree / 'startup')
        config = {key: fixed_git(path, 'rev-parse', '--verify', 'HEAD').decode().strip()
                  for key, path in (('commit', acquired), ('startup_revision', startup))}
        for value in config.values():
            p.digest(value, 40)
        verify_startup_adoption(repository, startup, config['startup_revision'])
        _, _, _, source_tree, startup_sha = intake.source(repository, config, checklist=workload == CHECKLIST)
    except FileNotFoundError as exc:
        raise SitePending('owner-repository-inputs', 'Run the attended owner setup or source recovery to provision the approved checkout and pinned startup inputs.') from exc
    return config, source_tree, startup_sha


def seed_role(path, layout):
    from codex_state import toml
    from gptbox_runtime import LOADER_DIRS, LOADER_FILES, role_policy

    group = layout['gid']
    label = layout['selinux_label'].encode()

    def metadata(leaf, mode):
        directory = mode == 0o750
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
        fd = os.open(leaf, flags)
        try:
            node = os.fstat(fd)
            p.require(node.st_uid == 0 and (stat.S_ISDIR(node.st_mode) if directory else
                      stat.S_ISREG(node.st_mode) and node.st_nlink == 1), 'First owner seed stage changed.')
            os.fchown(fd, 0, group)
            os.setxattr(fd, 'security.selinux', label)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)

    dirs = ['requirements', 'turn/startup', *('loaders/' + name for name in LOADER_DIRS)]
    for name in dirs:
        (path / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    requirements, configuration = role_policy(
        'Read the complete verified startup documents supplied by the controller and follow the authorized product agreement.',
        live=True, development=layout['role'] == 'development')
    contents = {'requirements/requirements.toml': toml(requirements).encode(),
                'loaders/config.toml': toml(configuration).encode(),
                'loaders/hooks.json': b'{"hooks":{}}\n',
                'turn/request.json': b'{}\n', 'turn/approval.json': b'{}\n',
                'turn/prompt.txt': b'Prepared at job dispatch.\n', 'turn/startup/manifest.json': b'{}\n'}
    contents.update({f'loaders/{name}': b'' for name in LOADER_FILES if f'loaders/{name}' not in contents})
    contents.update({f'turn/startup/{name}.txt': b'Prepared at job confirmation.\n' for name in IDS})
    for name, data in contents.items():
        leaf = path / name
        write_private(leaf, data)
        metadata(leaf, 0o440)
    for folder, _, _ in os.walk(path, topdown=False):
        metadata(Path(folder), 0o750)


class FirstCatalogue:
    """Materialize an exact root-confirmed first slot before it can admit jobs."""

    def __init__(self, intake):
        self.intake = intake
        self.site = intake.site
        self.catalogue = self.site / 'repositories.json'

    def configured(self, approval=None):
        if not os.path.lexists(self.catalogue):
            return None
        repositories, slots = self.intake.catalogue_settings()
        if approval is not None:
            retained = read_private(self.site / 'slots' / slots[0] / '.first-approval', 4096)
            p.require(p.loads(retained) == {'confirm_sha256': approval,
                                           'catalogue_sha256': p.sha256(checked_file(self.catalogue))},
                      'The existing owner catalogue belongs to another approval.')
        return {'phase': 'configured', 'repositories': sorted(repositories), 'slots': slots}

    def available_billing_slots(self):
        _, jobs = self.intake.catalogue_settings()
        return [job for job in jobs if self.intake.slot_unused(job) and
                not os.path.lexists(self.intake.queue / (job + '.json'))]

    def billing_limits(self, job):
        slot = self.site / 'slots' / job_id(job)
        settings = p.loads(checked_file(slot / 'profile.json'))
        limits = {key: settings[key] for key in ('host_seconds', 'build_seconds', 'turn_seconds')}
        grants = [p.loads(checked_file(slot / role / 'profile.json', MAX_INPUT))['grant'] for role in ROLES]
        for key, field in (('requests', 'max_requests'), ('request_bytes', 'max_request_bytes'),
                           ('output_tokens', 'max_output_tokens')):
            limits[key] = min(grant[field] for grant in grants)
        return limits

    def reauthorization(self, job, options):
        p.require(job_id(job) in self.available_billing_slots(),
                  'Billing reauthorization requires an unused configured slot without a retained draft or job.')
        _, release, manifests, _, _, _ = selected_site(self.intake)
        p.require(job in manifests, 'The selected release does not admit this owner slot.')
        limits = self.billing_limits(job)
        p.require(all(getattr(options, key) == limits[key] for key in ('host_seconds', 'build_seconds', 'turn_seconds')) and
                  all(getattr(options, key) <= limits[key] for key in ('requests', 'request_bytes', 'output_tokens')),
                  'Billing reauthorization must preserve the existing slot’s nonbilling bounds.')
        settings, grant, proofs, credential = owner_provider(options)
        slot = self.site / 'slots' / job
        base = checked_file(slot / 'profile.json')
        roles = {role: checked_file(slot / role / 'profile.json', MAX_INPUT) for role in ROLES}
        selection = {'schema': 1, 'binding': self.intake.slot_billing_binding(job, base, roles),
                     'settings': settings, 'grant': grant, 'proofs': {kind: raw.decode() for kind, raw in proofs.items()}}
        approval = p.identity({'selection': selection, 'credential_stamp': credential,
                               'release': release, 'development_manifest': manifests[job]})
        scope = dict(selection, consent_sha256=approval)
        self.intake.slot(job, manifests[job], replacement=scope)
        return scope

    def replace_billing(self, job, options, approval):
        from renewal import Renewal

        p.digest(approval)
        with self.lock(), self.intake.lock(), Renewal(self.intake.root, None).lock(shared=True):
            scope = self.reauthorization(job, options)
            p.require(scope['consent_sha256'] == approval, 'The signed provider scope changed. Review the exact new selection.')
            path = protect_directory(self.site / 'slots' / job) / SLOT_BILLING
            if os.path.lexists(path) and p.loads(checked_file(path)) == scope:
                return
            billing.replace_record(path, scope)

    def preview(self, options):
        from bootstrap import Blocked
        from provider_broker import grant_document

        if options.repository is None or options.workload is None:
            raise SitePending('owner-catalogue-selection',
                              'Select the authorized repository and workload. Run owner_intake.py --inspect-site --help for the bounded inputs.')
        repository = repository_id(options.repository)
        config, source_tree, startup_sha = first_source(self.intake, repository, options.workload)
        settings, grant, proofs, credential = owner_provider(options)
        controller, release, manifests, site, binding, destination = selected_site(self.intake)
        if options.destination is not None:
            p.require(options.destination == destination, 'Selected destination differs from the approved private site.')
        config.update(destination=destination, workloads=[options.workload])
        slots = self.site / 'slots'
        if os.path.lexists(slots):
            protect_directory(slots)
        choices = [job for job in sorted(site['jobs']) if job in manifests and self.intake.slot_unused(job) and
                   not os.path.lexists(self.intake.queue / (job + '.json'))]
        if not choices:
            raise SitePending('owner-slot-capacity', 'No unused approved job slot is available for the first owner catalogue.')
        job = choices[0]
        try:
            roles = role_site_profiles(self.intake, controller, release, binding, job, manifests[job], site['jobs'][job])
        except (Blocked, FileNotFoundError) as exc:
            raise SitePending('owner-role-profile', 'Complete the verified selected role images and exact DevBox slot placement.') from exc
        for role in roles.values():
            layout = role['layout']
            pricing = {key: settings['pricing'][key] for key in ('max_context_tokens', 'input_microusd_per_million',
                                                                  'output_microusd_per_million', 'observed_models')}
            grant_document(p.canonical(dict(grant, **pricing, schema=1, auth_profile=options.profile,
                request_sha256='0' * 64, allowance_sha256='0' * 64, peer_uid=layout['uid'], peer_gid=layout['gid'],
                allowance_ref=settings['allowance_ref'], expires_unix=settings['expires_unix'])).encode())
            role['credential_ref'] = options.credential_ref
            role['grant'] = grant
        catalogue = {'schema': 1, 'repositories': {repository: config}, 'slots': [job]}
        plan = {'catalogue': catalogue, 'release_sha256': release, 'site_config_sha256': binding['site_config_sha256'],
                'development_manifest_sha256': manifests[job], 'standards_sha': p.STANDARDS,
                'source_tree': source_tree, 'startup_sha256': startup_sha, 'provider_profile': options.profile,
                'provider_model': MODEL, 'provider_effort': billing.EFFORT, 'credential_stamp': credential,
                'slot_profile': settings, 'roles': roles}
        return plan, proofs

    @contextlib.contextmanager
    def lock(self):
        path = protect_directory(self.site) / '.first-catalogue.lock'
        flags = os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path, flags, 0o600), 'rb') as stream:
            p.private_file(path)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def initialize(self, options):
        from platform_release_intake import durable_record
        from platform_release_protocol import canonical as release_bytes
        from renewal import Renewal

        approval = options.confirm_sha256
        p.digest(approval)
        existing = self.configured(approval)
        if existing is not None:
            return existing
        with self.lock(), Renewal(self.intake.root, None).lock(shared=True):
            existing = self.configured(approval)
            if existing is not None:
                return existing
            plan, proofs = self.preview(options)
            p.require(p.identity(plan) == approval, 'The first owner selection changed. Inspect and confirm the exact current selection.')
            job, = plan['catalogue']['slots']
            slots = protect_directory(self.site)
            slots = private_leaf(slots / 'slots')
            destination = slots / job
            proof = {'confirm_sha256': approval, 'catalogue_sha256': p.sha256(release_bytes(plan['catalogue']))}
            manifest = plan['development_manifest_sha256']
            with tempfile.TemporaryDirectory(prefix='.first-slot-', dir=slots) as temporary:
                staged = Path(temporary) / job
                staged.mkdir(mode=0o700)
                exact_private(staged / 'profile.json', p.canonical(plan['slot_profile']).encode())
                exact_private(staged / '.first-approval', p.canonical(proof).encode())
                for kind, raw in proofs.items():
                    exact_private(staged / (MODEL + '.' + kind), raw)
                for role, row in plan['roles'].items():
                    folder = private_leaf(staged / role)
                    values = {key: value for key, value in row.items() if key != 'layout'}
                    exact_private(folder / 'profile.json', p.canonical(values).encode())
                    seed_role(folder / 'seed', row['layout'])
                    sync_directory(folder)
                verified = self.intake.slot(job, manifest, staging=staged)
                if os.path.lexists(destination):
                    trusted_directory(destination)
                    p.require(p.loads(read_private(destination / '.first-approval', 4096)) == proof and
                              self.intake.slot(job, manifest) == verified,
                              'A staged owner slot belongs to another approval.')
                else:
                    staged.rename(destination)
                    sync_directory(slots)
            # The public catalogue is the commit marker. O_TMPFILE plus a no-replace link preserves older authority.
            durable_record(self.catalogue, plan['catalogue'])
        return self.configured(approval)


def setup_answer(incoming, outgoing, prompt):
    outgoing.write(prompt + ' ')
    outgoing.flush()
    value = incoming.readline(1025)
    p.require(value.endswith('\n') and len(value) <= 1024, 'The setup answer was interrupted or too long.')
    return value.strip()


def setup_secret(outgoing, prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt, stream=outgoing).strip()
        except getpass.GetPassWarning as exc:
            raise ValueError('Credential input requires a private controlling terminal.') from exc


def enroll_billing_reviewer(ask, say):
    existing = billing.reviewer_state()
    key = ask('OpenSSH public key supplied by the independent billing custodian, or Enter to wait.')
    if not key:
        return False
    public, actual = billing.reviewer_key(key)
    fingerprint = ask('SHA256 fingerprint separately authenticated with the independent billing custodian.')
    p.require(fingerprint == actual, 'The key differs from the independently authenticated billing fingerprint.')
    say(f'Billing signature authority for this VPS and the provider-billing principal: {actual}')
    if ask('Enroll this exact independent billing custodian? [y/N]').lower() not in ('y', 'yes'):
        return False
    billing.set_reviewer(public, fingerprint, existing)
    return True


def setup_provider(ask, say, outgoing):
    from provider_transition import Deferred

    reference = setup_secret(outgoing, 'Protected credential reference: ')
    p.token(reference)
    if not os.path.lexists(CREDENTIALS / reference):
        path = ask('Absolute path to a root-private scoped API key file, or Enter to use a hidden prompt.')
        if path:
            billing.register(reference, Path(path))
        else:
            secret = setup_secret(outgoing, 'Scoped OpenAI project API key, or Enter to wait: ')
            if not secret:
                raise SitePending('provider-credential', 'Provider credential setup is pending.')
            billing.register_secret(reference, secret)
            del secret
    provider_custody(reference)
    try:
        return reference, billing_authority(reference)
    except SitePending:
        if not billing.has_reviewer() and not enroll_billing_reviewer(ask, say):
            raise SitePending('provider-billing-reviewer', 'Enrollment of the independent billing custodian is pending.') from None
    request, target = billing.setup_handoff(reference)
    say(f'Send the protected VPS-bound billing request {request} to the independently enrolled billing custodian.')
    say(f'Return the custodian’s signed bundle as a root-private mode 0600 file at {target}, then reopen this setup.')

    def accept(path):
        try:
            raw = billing.bounded_file(billing.protected(path, private=True), billing.BUNDLE_LIMIT,
                                       owner=0, mode=0o600)
            billing.receive(reference, raw)
        except Deferred:
            raise
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            reason = str(exc) if type(exc) is ValueError else 'Verify the root-private bundle path and retry.'
            raise SitePending('provider-billing-authority', 'The signed billing bundle was rejected. ' + reason) from exc

    if os.path.lexists(target):
        try:
            accept(target)
        except SitePending as wait:
            say(wait.observation['message'])
        else:
            return reference, billing_authority(reference)
    supplied = ask('Absolute path to the returned signed billing bundle, or Enter to wait.')
    if not supplied:
        raise SitePending('provider-billing-evidence', 'First owner billing is waiting for the independent signed bundle.')
    accept(Path(supplied))
    return reference, billing_authority(reference)


def setup_site(first, incoming, outgoing):
    from gptbox_runtime import PROVIDER_BODY_MAX
    from owner_source import provision
    from provider_broker import PROFILE, reserved_cost
    from provider_transition import Deferred, Fence

    def say(message):
        print(message, file=outgoing, flush=True)

    def ask(prompt):
        return setup_answer(incoming, outgoing, prompt)

    try:
        existing = first.configured()
        job = None
        repository = workload = None
        manage = existing is not None
        if existing is None:
            say('Choose the approved repository and workload for the first owner job.')
            choice = ask('Repository (owner/name), or enter billing to manage provider authority.')
            manage = choice == 'billing'
            if not manage:
                repository = repository_id(choice)
                say('1 Checklist persistence   2 General development   3 General development with an external check')
                choice = ask('Workload [1/2/3]')
                p.require(choice in ('1', '2', '3'), 'Choose one of the listed workloads.')
                workload = tuple(WORKLOADS)[int(choice) - 1]
                if not provision(first.intake, repository, workload, ask, say):
                    return
        if manage:
            action = ask('Billing action [reauthorize/withdraw-key/rotate-reviewer/withdraw-reviewer/discard-pending/Enter]')
            if not action:
                return
            if action == 'rotate-reviewer':
                if enroll_billing_reviewer(ask, say):
                    say('Billing reviewer rotated. Reopen setup to obtain fresh terms for an unused slot.')
                return
            if action == 'withdraw-reviewer':
                prior = billing.reviewer_state()
                if ask('Withdraw billing authority and hold future sends? [y/N]').lower() in ('y', 'yes'):
                    billing.set_reviewer(None, None, prior)
                    say('Independent billing reviewer authority was withdrawn.')
                return
            if action == 'withdraw-key':
                reference = setup_secret(outgoing, 'Credential reference to withdraw: ')
                p.token(reference)
                if ask('Withdraw this exact credential’s billing terms? [y/N]').lower() in ('y', 'yes'):
                    billing.withdraw_reference(reference)
                    say('The selected credential’s billing terms were withdrawn.')
                return
            if action == 'discard-pending':
                fence = Fence()
                intended = fence.intent()
                if intended is None:
                    say('There is no pending billing operation.')
                elif ask('Discard the pending billing operation and retain any custody already committed? [y/N]').lower() in ('y', 'yes'):
                    fence.discard(intended)
                    say('The pending billing operation was discarded.')
                return
            p.require(action == 'reauthorize', 'Choose one of the billing actions.')
            p.require(existing is not None, 'An unused configured catalogue slot is required for reauthorization.')
            slots = first.available_billing_slots()
            if not slots:
                raise SitePending('unused-provider-slot', 'No configured slot is unused and free of retained drafts or jobs.')
            job = slots[0] if len(slots) == 1 else job_id(ask('Unused slot (' + ', '.join(slots) + ')'))
            p.require(job in slots, 'Choose a currently unused configured slot.')
        say('Choose a registered OpenAI project credential with independently issued billing terms.')
        reference, (values, proofs, review) = setup_provider(ask, say, outgoing)
        terms_expiry = datetime.fromtimestamp(review['expires_unix'], timezone.utc)
        say(f'OpenAI organization {review["organization"]} and project {review["project"]}.')
        say(f'The signed provider terms are valid until {terms_expiry:%Y-%m-%d %H:%M} UTC.')
        text = ask('Approved total job budget in USD')
        p.require(re.fullmatch(r'(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,6})?', text),
                  'Enter the approved USD amount with at most six decimals.')
        spend = int(Decimal(text) * 1000000)
        try:
            expiry = datetime.strptime(ask('Approved expiry in UTC (YYYY-MM-DD HH:MM)'), '%Y-%m-%d %H:%M')
        except ValueError as exc:
            raise ValueError('Enter the approved expiry in UTC as YYYY-MM-DD HH:MM.') from exc
        limits = first.billing_limits(job) if job is not None else {
            'requests': 4, 'request_bytes': PROVIDER_BODY_MAX, 'output_tokens': 4096,
            'host_seconds': 45, 'build_seconds': 120, 'turn_seconds': 90}
        output_tokens = limits['output_tokens']
        cost = reserved_cost(dict(values, max_output_tokens=output_tokens))
        requests = min(limits['requests'], spend // (2 * cost))
        minimum = 1 if job is not None else 2
        p.require(requests >= minimum, f'The approved total does not cover {minimum} bounded requests per role.')
        options = argparse.Namespace(repository=repository, workload=workload, destination=None, profile=PROFILE,
            credential_ref=reference, spend_microusd=spend, expires_unix=int(expiry.replace(tzinfo=timezone.utc).timestamp()),
            context_tokens=None, input_rate=None, output_rate=None, observed_model=None,
            **dict(limits, requests=requests), confirm_sha256=None)
        if job is not None:
            scope = first.reauthorization(job, options)
            p.require({kind: raw.encode() for kind, raw in scope['proofs'].items()} == proofs,
                      'The protected billing evidence changed. Start setup again.')
            say(f'Unused slot {job}, GPT-6.2 Sol High, up to {requests} requests per role, '
                f'{output_tokens} output tokens each and {options.turn_seconds}s per turn.')
            say(f'Shared API ceiling USD {Decimal(spend) / 1000000:.6f} until {expiry:%Y-%m-%d %H:%M} UTC.')
            if ask('Confirm this exact signed billing reauthorization? [y/N]').lower() in ('y', 'yes'):
                first.replace_billing(job, options, scope['consent_sha256'])
                say('Signed billing reauthorization is active for the unused slot. Resume Day 0.')
            return
        plan, selected_proofs = first.preview(options)
        p.require(proofs == selected_proofs, 'The protected billing evidence changed. Start setup again.')
        config = plan['catalogue']['repositories'][repository]
        say(f"{repository} at {config['commit']}")
        say(f"Workload {workload}. Slot {plan['catalogue']['slots'][0]}. Destination {config['destination']}")
        say(f"Startup revision {config['startup_revision']}. GPT-6.2 Sol High for both roles.")
        say(f"Shared API ceiling USD {Decimal(spend) / 1000000:.6f} until {expiry:%Y-%m-%d %H:%M} UTC.")
        say(f"Up to {requests} requests per role, {output_tokens} output tokens each and {options.turn_seconds}s per turn.")
        if ask('Confirm this exact owner setup? [y/N]').lower() not in ('y', 'yes'):
            say('Setup remains pending.')
            return
        options.confirm_sha256 = p.identity(plan)
        first.initialize(options)
        say('Owner catalogue configured. The protected activation checks can now continue.')
    except SitePending as wait:
        say(wait.observation['message'])
    except Deferred as wait:
        say(str(wait))
    except (EOFError, KeyboardInterrupt):
        say('Setup was interrupted. Run the same setup command to inspect the retained state.')


def catalogue_command(intake, argv):
    p.require(os.getuid() == os.geteuid() == 0 and not os.environ.get('SUDO_USER'),
              'Use the protected root commissioning terminal for first owner setup.')
    first = FirstCatalogue(intake)
    if argv[:1] in (['--setup-site'], ['--restore-source'], ['--rotate-source-credential']):
        p.require(len(argv) == 1, 'Run the attended command without additional arguments.')
        try:
            with open('/dev/tty', encoding='utf-8') as incoming, open('/dev/tty', 'w', encoding='utf-8') as outgoing:
                p.require(incoming.isatty() and outgoing.isatty(), 'First owner setup requires the controlling terminal.')
                if argv[0] == '--setup-site':
                    setup_site(first, incoming, outgoing)
                else:
                    from owner_source import restore, rotate
                    action = restore if argv[0] == '--restore-source' else rotate
                    action(first, incoming, outgoing)
        except OSError as exc:
            if exc.errno in (errno.ENXIO, errno.ENOTTY):
                raise ValueError('Open the protected root terminal to run first owner setup.') from exc
            raise
        return 0
    parser = argparse.ArgumentParser(prog='owner_intake.py', description='Inspect and confirm the exact first owner site.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--inspect-site', action='store_true')
    mode.add_argument('--initialize-site', action='store_true')
    parser.add_argument('--repository')
    parser.add_argument('--workload', choices=tuple(WORKLOADS))
    parser.add_argument('--destination')
    parser.add_argument('--profile')
    parser.add_argument('--credential-ref')
    parser.add_argument('--spend-microusd', type=int)
    parser.add_argument('--expires-unix', type=int)
    parser.add_argument('--context-tokens', type=int)
    parser.add_argument('--input-rate', type=int)
    parser.add_argument('--output-rate', type=int)
    parser.add_argument('--observed-model', action='append')
    parser.add_argument('--requests', type=int)
    parser.add_argument('--request-bytes', type=int)
    parser.add_argument('--output-tokens', type=int)
    parser.add_argument('--host-seconds', type=int, default=45)
    parser.add_argument('--build-seconds', type=int, default=120)
    parser.add_argument('--turn-seconds', type=int, default=90)
    parser.add_argument('--confirm-sha256')
    options = parser.parse_args(argv)
    p.require(options.initialize_site == (options.confirm_sha256 is not None), 'Initialize requires the exact inspected confirmation SHA-256.')
    try:
        if options.initialize_site:
            report = first.initialize(options)
        else:
            report = first.configured()
            if report is None:
                plan, _ = first.preview(options)
                public = {key: value for key, value in plan.items() if key != 'credential_stamp'}
                report = {'phase': 'awaiting-confirmation', 'scope': public, 'confirm_sha256': p.identity(plan)}
        respond(report)
    except SitePending as wait:
        respond(wait.observation)
    return 0


def respond(result):
    print(p.canonical(result), flush=True)


def follow(intake, job):
    previous = None
    end = time.monotonic() + 120
    while True:
        status = intake.status(job)
        if status['phase'] == 'submitted' and not status['diagnostics']:
            return product.main(['reattach', job])
        status = intake.observed(job, status)
        if status != previous:
            respond(status)
            previous = status
        if status['phase'] in ('awaiting-confirmation', 'blocked') or time.monotonic() >= end:
            return 2 if status['phase'] == 'blocked' else 0
        time.sleep(1)


def main():
    os.umask(0o077)
    try:
        p.require(os.geteuid() == 0, 'The installed intake service requires its protected account.')
        intake = Intake()
        if sys.argv[1:2] and sys.argv[1] in ('--setup-site', '--restore-source', '--rotate-source-credential',
                                              '--inspect-site', '--initialize-site'):
            return catalogue_command(intake, sys.argv[1:])
        if sys.argv[1:] == ['--reconcile'] and not os.environ.get('SUDO_USER'):
            return intake.reconcile()
        if len(sys.argv) == 3 and sys.argv[1] == '--prepare' and not os.environ.get('SUDO_USER'):
            return intake.prepare(job_id(sys.argv[2]))
        p.require(len(sys.argv) == 1 and os.environ.get('SUDO_USER') == 'core',
                  'Use the installed dev-pair command from the named operator account.')
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        p.require(len(data) <= MAX_INPUT, 'The owner request exceeds its byte limit.')
        request = p.loads(data)
        p.require(type(request) is dict and 'action' in request, 'The owner request is incomplete.')
        action = request['action']
        if action in ('draft', 'submit'):
            from commission_host import ACTIVATION, AUTOMATIC_POLICY, Blocked, require_installed_workload, workload_guard_files

            if any(os.path.lexists(path) for path in (ACTIVATION, AUTOMATIC_POLICY, *workload_guard_files(('owner-intake',)))):
                try:
                    require_installed_workload('owner-intake', owner_entry=True)
                except Blocked:
                    raise ValueError('Current approved owner workload authority is held.') from None
        if action == 'draft':
            respond(intake.draft(request))
            return 0
        p.require(action in ('submit', 'status', 'reattach', 'agreement'), 'The owner request names an unknown operation.')
        p.fields(request, 'action job agreement_token' if action == 'submit' else 'action job')
        job = job_id(request['job'])
        if action == 'reattach':
            return follow(intake, job)
        if action == 'submit':
            result = intake.confirm(job, request['agreement_token'])
        else:
            result = intake.status(job)
        result = intake.observed(job, result)
        respond(result)
        return 2 if action != 'agreement' and result['phase'] == 'blocked' else 0
    except FileNotFoundError:
        print('Dev-pair intake or the requested job is unavailable. Check the job ID and installed site profile.', file=sys.stderr)
    except BlockingIOError:
        print('Dev-pair intake is busy. Retry the same operation.', file=sys.stderr)
        return 75
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as exc:
        detail = product.h.bounded_diagnostic(str(exc)) if type(exc) is ValueError else type(exc).__name__
        print('Dev-pair intake stopped. ' + detail, file=sys.stderr)
    return 2


if __name__ == '__main__':
    # The attended provisioning helper shares this command's protected input checks.
    sys.modules['owner_intake'] = sys.modules[__name__]
    raise SystemExit(main())
