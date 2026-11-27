#!/usr/bin/python3 -IB
"""Accept a confirmed owner brief through the existing product conductor."""

import contextlib
import fcntl
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checklist_candidate as candidate
import job_protocol as p
import product_job as product
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private
from startup_delivery import IDS, load_private

SITE = Path('/etc/dev-pair/product-intake')
CREDENTIALS = Path('/etc/dev-pair/provider-credentials')
ROOT = candidate.ROOT
CATALOGUE = ROOT / 'product-jobs'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
MODEL = 'gpt-6.2-sol'
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


def fixed_git(checkout, *args, cap=8192, data=None):
    return candidate.invoke(['/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                             'GIT_NO_LAZY_FETCH=1', 'GIT_NO_REPLACE_OBJECTS=1', 'GIT_TERMINAL_PROMPT=0',
                             *candidate.GIT, '-C', str(checkout), *args],
                            time.monotonic() + 15, cap=cap, data=data)


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

    def source(self, repository, config, *, checklist=True):
        base = self.site / 'repositories' / repository
        checkout = protect_directory(base / 'acquired')
        startup = protect_directory(base / 'startup')
        checked_file(checkout / '.git/config', 8192)
        commit = config['commit']
        tree = fixed_git(checkout, 'rev-parse', '--verify', commit + '^{tree}').decode().strip()
        p.digest(tree, 40)
        verify_acquired_git(lambda *args, **kw: fixed_git(checkout, *args, **kw), checkout,
                            {'repository': repository, 'acquired_commit': commit, 'acquired_tree': tree},
                            checklist=checklist)
        cache = protect_directory(self.site / 'standards')
        corpus = load_private(startup, cache, config['startup_revision'], time.monotonic() + 20)
        return checkout, startup, cache, tree, p.sha256(manifest_bytes(corpus.manifest))

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

    def slot(self, job, dev_manifest):
        from gptbox import capture_release_file
        from provider_broker import grant_document, reserved_cost

        slot = self.site / 'slots' / job
        settings = p.loads(checked_file(slot / 'profile.json'))
        p.fields(settings, 'schema host_seconds build_seconds turn_seconds allowance_ref spend_microusd expires_unix pricing')
        p.number(settings['schema'], 1, 1)
        p.number(settings['host_seconds'], 25, 60)
        p.number(settings['build_seconds'], 20, 240)
        p.number(settings['turn_seconds'], 5, 120)
        p.number(settings['spend_microusd'], 1, 100000000)
        p.number(settings['expires_unix'], 1, 2**63 - 1)
        p.require(settings['expires_unix'] > time.time() + 2 * (settings['host_seconds'] + settings['build_seconds']
                                                                + settings['turn_seconds']) + 60,
                  'The approved provider allowance expires before this job can finish.')
        pricing = settings['pricing']
        p.fields(pricing, 'max_context_tokens input_microusd_per_million output_microusd_per_million observed_models '
                 'context_evidence_sha256 tariff_evidence_sha256')
        proofs = {}
        for kind in ('context', 'tariff'):
            p.digest(pricing[kind + '_evidence_sha256'])
            proofs[kind] = checked_file(slot / (MODEL + '.' + kind), 1024 * 1024)
            p.require(p.sha256(proofs[kind]) == pricing[kind + '_evidence_sha256'],
                      'The approved provider pricing evidence has changed.')
        roles, seeds = {}, {}
        reserve = 0
        for role in ROLES:
            profile = p.loads(checked_file(slot / role / 'profile.json', MAX_INPUT))
            p.fields(profile, 'runtime_sha256 binary_sha256 layout_sha256 credential_ref grant')
            for key in ('runtime_sha256', 'binary_sha256', 'layout_sha256'):
                p.digest(profile[key])
            p.token(profile['credential_ref'])
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
        exact_private(plan_path, p.canonical(plan).encode())
        if os.path.lexists(self.catalogue / 'jobs' / job):
            # A previous preparation got as far as J publication. The product
            # entry verifies the original plan and owns resumption from here.
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
            checkout, startup, cache, tree, startup_sha = self.source(repository, config, checklist=workload == CHECKLIST)
            p.require((tree, startup_sha) == (preview['source_tree'], plan['startup_sha256']),
                      'The verified source or startup documents have changed.')
            approval = self.approve(plan, checkout, startup, cache, config['startup_revision'], tree)
            allowance = self.allowance(plan, settings, proofs)
            bundle = fixed_git(checkout, 'bundle', 'create', '-', 'HEAD', cap=candidate.MAX_BUNDLE)
            for role, profile in roles.items():
                selection = dict(job=job, repository=repository, agreement_sha256=product.agreement_sha(plan),
                                 model=MODEL)
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
        job = plan['job_id']
        root = private_leaf(self.root / 'provider-allowances' / job)
        approval = {'schema': 1, 'kind': 'verified-full-billable-context',
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
    raise SystemExit(main())
