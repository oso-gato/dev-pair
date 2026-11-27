#!/usr/bin/python3
"""Observe and advance one protected checklist product delivery."""
import argparse
import contextlib
import fcntl
import os
from pathlib import Path
import pwd
import re
import ssl
import stat
import subprocess
import time

from bootstrap import Blocked, Commands
import checklist_candidate as candidate
import checklist_proposal as proposal
from checklist_review_gate import main_protection, policy_identity
import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory, write_private
import product_job as product

SITE = Path('/etc/dev-pair/product-release')
EVIDENCE = candidate.ROOT / 'product-release-evidence'
FENCE = candidate.ROOT / 'renewal-fence'
REGISTRY = 'ghcr.io/oso-gato/dev-pair/checklist'
PUBLISHER = '.github/workflows/checklist-release.yml'
MERGE_WORKFLOW = '.github/workflows/checklist-product-merge.yml'
SCOPE = 'checklist-persistence'
TERMINAL = product.PROMOTION_TERMINAL
RETRYABLE = {'proposal-transport', 'github-observation', 'destination-observation'}
RETRY_DELAYS = (180, 360, 720)


class Wait(OSError):
    """A fixed condition can be observed without replacing the candidate."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def policy(raw):
    value = p.loads(raw)
    p.fields(value, 'version repository dns_name developer_id developer_login fork observer_id merge_actor_id '
                    'merge_gate_app_id merge_workflow_sha256 expires_unix')
    p.number(value['version'], 1, 1)
    for key in ('developer_id', 'observer_id', 'merge_actor_id', 'merge_gate_app_id'):
        p.number(value[key], 1, 2**63 - 1)
    p.number(value['expires_unix'], 1, 2**63 - 1)
    p.digest(value['merge_workflow_sha256'])
    p.require(len({value[key] for key in ('developer_id', 'observer_id', 'merge_actor_id')}) == 3 and
              value['repository'] == proposal.REPOSITORY, 'independent scoped product release custody required')
    dns_name(value['dns_name'])
    return value


def dns_name(value):
    p.require(type(value) is str and len(value) <= 253, 'exact private checklist destination required')
    name = value.removeprefix('https://').removesuffix('/')
    p.require(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net', name)
              and value in (name, f'https://{name}/'), 'exact private tailnet DNS destination required')
    return name


def inputs(root, job, plan, state):
    approval_raw, approval = product.source_approval(plan)
    intake_root = trusted_directory(product.CATALOGUE / 'intake')
    intake = p.loads(read_private(intake_root / (job + '.json'), p.MAX_MESSAGE))
    preview, agreement = intake['preview'], intake['preview']['product_agreement']
    p.require(intake['phase'] == 'submitted' and intake['plan'] == preview['plan'] == plan and
              p.identity(preview) == intake['agreement_token'] and preview['standards_sha'] == p.STANDARDS and
              agreement['repository'] == plan['agreement']['repository'] == proposal.REPOSITORY and
              agreement['workload'] == SCOPE and not agreement['external_validation'] and
              preview['source_tree'] == approval['acquired_tree'], 'owner-confirmed checklist source and scope required')

    store = trusted_directory(root / 'candidate')
    material = p.loads(read_private(store / 'receipt.json', p.MAX_MESSAGE))
    p.fields(material, 'binding candidate_sha tree_sha bundle_sha256 head_ref')
    binding = material['binding']
    checkpoint = p.validate(state['repair'], 'checkpoint')
    local = state['development']['local_validation']
    final = state['final']
    result = p.validate(final['result'], 'result')
    retained = state['development']
    initial = p.validate(state['initial'], 'checkpoint')
    expected = {'job_id': job, 'base_sha': plan['agreement']['initial_commit'],
                'checkpoint_sha256': p.identity(initial), 'agreement_sha256': product.agreement_sha(plan),
                'approval_sha256': p.sha256(approval_raw), 'startup_sha256': plan['startup_sha256'],
                'operation': job + '-development', 'snapshot_sha256': local['snapshot_sha256'],
                'validation_sha256': p.identity(local), **{key: retained[key] for key in
                    ('session_uuid', 'events_sha256', 'request_sha256')}}
    p.require(material == state['materialized'] and all(binding[key] == item for key, item in expected.items()) and
              local['exit_status'] == 0 and
              (material['head_ref'] == 'HEAD' or material['head_ref'].startswith('refs/heads/')) and
              material['candidate_sha'] == checkpoint['candidate']['source_revision'] != binding['base_sha'] and
              result['job_id'] == checkpoint['job_id'] == initial['job_id'] == job and
              result['request_id'] == job + '-r2' and initial['candidate']['source_revision'] == binding['base_sha'] and
              result['checkpoint_id'] == checkpoint['checkpoint_id'] and result['candidate'] == checkpoint['candidate'] and
              result['test'] == checkpoint['test'] and result['executor']['boundary'] == p.APP_QUADLET_BOUNDARY and
              p.result_progress(result) == final['progress'] == 'host-checks-passed' and
              result['cleanup']['status'] == 'complete', 'normal candidate validation and authenticated host pass required')
    for key in ('candidate_sha', 'tree_sha'):
        p.digest(material[key], 40)
    p.digest(material['bundle_sha256'])
    bundle = read_private(store / 'candidate.bundle', proposal.GIT_TRANSFER)
    p.require(p.sha256(bundle) == material['bundle_sha256'], 'tested candidate bundle changed')
    return ({
        'agreement_token': intake['agreement_token'], 'agreement_sha256': binding['agreement_sha256'],
        'repository': agreement['repository'], 'base_sha': binding['base_sha'], 'dns_name': dns_name(agreement['destination']),
        'candidate_sha': material['candidate_sha'], 'tree_sha': material['tree_sha'],
        'bundle_sha256': material['bundle_sha256'], 'materialization_sha256': p.identity(material),
        'host_result_sha256': p.identity(result), 'host_attempt_id': result['attempt_id'],
    }, bundle, result)


@contextlib.contextmanager
def dispatch_gate():
    lock = candidate.h.host_runtime().protected(FENCE / 'owner.lock', file=True)
    with lock.open('rb') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Wait('destination-fenced') from exc
        if os.path.lexists(FENCE / 'frozen'):
            raise Wait('destination-fenced')
        yield


def root_directory(path, group, mode):
    node = path.lstat()
    p.require(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISDIR(node.st_mode) and
              (node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)) == (0, group, mode),
              'protected proposal transfer directory required')


def stage(job, request, bundle):
    account = pwd.getpwnam(proposal.DEVELOPER)
    p.require(account.pw_uid == account.pw_gid >= 1000 and Path(account.pw_dir) == proposal.HOME and
              account.pw_shell == '/usr/sbin/nologin' and os.getgrouplist(proposal.DEVELOPER, account.pw_gid) == [account.pw_gid],
              'dedicated nonlogin proposal account required')
    root_directory(proposal.ROOT, account.pw_gid, 0o750)
    root_directory(proposal.INBOX, account.pw_gid, 0o750)
    box = proposal.INBOX / job
    if not os.path.lexists(box):
        box.mkdir(mode=0o700)
    initial = box.lstat()
    if (initial.st_uid == 0 and initial.st_gid in (0, account.pw_gid) and
            stat.S_ISDIR(initial.st_mode) and stat.S_IMODE(initial.st_mode) == 0o700):
        os.chown(box, 0, account.pw_gid)
        box.chmod(0o750)
        sync_directory(proposal.INBOX)
    root_directory(box, account.pw_gid, 0o750)
    for name, data in (('request.json', p.canonical(request).encode()), ('candidate.bundle', bundle)):
        target = box / name
        if not os.path.lexists(target):
            # One protected pending leaf survives an interrupted staging pass.
            pending = box / ('.pending-' + name)
            if os.path.lexists(pending):
                previous = pending.lstat()
                p.require(stat.S_ISREG(previous.st_mode) and previous.st_uid == 0 and previous.st_nlink == 1,
                          'untrusted interrupted proposal staging file')
                pending.unlink()
            write_private(pending, data)
            with pending.open('rb') as stream:
                os.fchown(stream.fileno(), 0, account.pw_gid)
                os.fchmod(stream.fileno(), 0o440)
                os.fsync(stream.fileno())
            os.replace(pending, target)
            sync_directory(box)
        node = target.lstat()
        p.require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and
                  (node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)) == (0, account.pw_gid, 0o440) and
                  p.read_data(target, proposal.GIT_TRANSFER) == data, 'protected proposal transfer changed')


class Live:
    def __init__(self, policy, job, binding, end):
        from destination_release import Destination
        from release_trust import ReleaseTrust

        self.policy, self.job, self.binding, self.end = policy, job, binding, end
        self.registry_auth = SITE / 'registry/config.json'
        if os.path.lexists(self.registry_auth):
            candidate.protected_file(self.registry_auth, 4096)
            read_private(self.registry_auth, 4096)
        else:
            self.registry_auth = None
        self.hub = proposal.Hub(proposal.token(read_private(SITE / 'read.token', 512)), end,
                                registry_auth=self.registry_auth)
        proposal.permissions(self.hub, proposal.REPOSITORY, policy['observer_id'], push=False)
        self.trust = ReleaseTrust(self.hub.gh)
        self.rules = self.trust.policy('checklist')
        p.require(self.rules['components']['checklist']['registry'] == REGISTRY and
                  self.rules['components']['checklist']['workflow'] == PUBLISHER and
                  not set(self.rules['reviewer_ids']) & {policy['developer_id'], policy['observer_id'], policy['merge_actor_id']},
                  'trusted reviewers, publication, proposer and merge actor require separate authority')
        observed_hub = self.hub

        class ReleaseCommands(Commands):
            def __call__(self, *args, **options):
                if args[0] == proposal.GH:
                    return observed_hub.gh(*args, **options).decode()
                return super().__call__(*args, **options)

        class ScopedDestination(Destination):
            @contextlib.contextmanager
            def release_gate(target, *, require_cutover=True):
                p.require(require_cutover, 'product promotion requires the approved final destination')
                with super().release_gate(require_cutover=True) as (setup, uid, dns):
                    p.require(dns == binding['dns_name'], 'destination differs from the confirmed agreement')
                    yield setup, uid, dns

        self.destination = ScopedDestination(run=ReleaseCommands())


    def live_host_result(self, result):
        context, peer, principals = product.h.tls_principal(product.Q_CLIENT, maintenance=False)
        host = product.h.host_runtime()
        output = candidate.invoke(candidate.as_role(host.ACCOUNT, product.PYTHON, '-EBs',
            product.KIT / 'tools/jobs.py', '--state', host.HOME / 'ledger', 'status', result['request_id']),
            self.end)
        request = p.validate(p.loads(output)['request'], 'request')
        p.require(request['boundary'] == p.APP_QUADLET_BOUNDARY and p.identity(request) == result['request_sha256'],
                  'host request differs from the consumed candidate test')
        controller = result['executor']['controller_id']
        product.h.check_host_status_request(request, controller, principals)
        status = product.h.exchange(product.HOST_PORT, context, peer, 'status', request)
        product.h.check_reply('status', status, request, controller)
        p.require(status['state'] == 'completed' and status['result'] == result, 'authenticated host result changed')

    def find(self, request):
        return proposal.find_pull(self.hub, request)

    def propose(self, request, bundle):
        with dispatch_gate():
            self.protection(request)
            stage(self.job, request, bundle)
            args = candidate.as_role(proposal.DEVELOPER, product.PYTHON, '-EBs',
                                     product.KIT / 'tools/checklist_proposal.py', self.job)
            try:
                proposal.capture(args, self.end, timeout=112)
            except proposal.CommandFailed as exc:
                if exc.exit_status == os.EX_NOPERM:
                    raise proposal.AuthorityDenied('the protected developer grant was denied') from exc
                if exc.exit_status == os.EX_UNAVAILABLE:
                    raise proposal.ObservationUnavailable('the protected developer read was unavailable') from exc
                if exc.exit_status == 2:
                    raise ValueError('the protected developer policy was rejected') from exc
                raise

    def protection(self, request):
        trust = self.trust
        base = request['base_sha']
        main = trust.api('branches/main')
        if main['commit']['sha'] != base:
            raise Wait('stale-reviewed-base')
        main_protection(trust, base, self.rules['check'])
        trust.workflow(MERGE_WORKFLOW, base, self.policy['merge_workflow_sha256'])
        env = trust.api('environments/checklist-merge')
        branches = trust.api('environments/checklist-merge/deployment-branch-policies?per_page=100')
        rules = trust.api('environments/checklist-merge/deployment_protection_rules')
        p.require(env['name'] == 'checklist-merge' and env['deployment_branch_policy'] == {
                    'protected_branches': False, 'custom_branch_policies': True} and
                  branches['total_count'] == 1 and
                  [(item['name'], item['type']) for item in branches['branch_policies']] == [('main', 'branch')] and
                  rules['total_count'] == 1 and len(rules['custom_deployment_protection_rules']) == 1 and
                  rules['custom_deployment_protection_rules'][0]['enabled'] is True and
                  rules['custom_deployment_protection_rules'][0]['app']['id'] == self.policy['merge_gate_app_id'],
                  'protected upstream workflow-specific merge permission required')
        trust.checklist_environment(self.rules['writer_app_id'])

    def review(self, pull, request):
        source = pull['merge_commit_sha']
        p.digest(source, 40)
        p.require(pull['merged'] is True and pull['merged_by']['id'] == self.policy['merge_actor_id'],
                  'merged revision did not come from the independent merge actor')
        if self.trust.api('branches/main')['commit']['sha'] != source:
            raise Wait('stale-production-source')
        row = self.trust.tree(source)
        p.require(row['tree']['sha'] == request['tree_sha'] and [item['sha'] for item in row['parents']] ==
                  [request['base_sha'], request['candidate_sha']], 'merged tree or parents differ from the authorized candidate')
        review = self.trust.review(source, self.rules)
        p.require(review['pull_request'] == pull['number'] and review['review_head'] == request['candidate_sha'] and
                  review['source_tree'] == request['tree_sha'], 'merged review evidence differs from the authorized head')
        return source, review

    def published(self, source, review):
        row = self.trust.api('actions/workflows/checklist-release.yml/runs?branch=main&event=push&head_sha=' +
                             source + '&per_page=20')
        runs = row['workflow_runs']
        p.require(row['total_count'] == len(runs) <= 1, 'ambiguous protected CI publication')
        if not runs or runs[0]['status'] != 'completed':
            raise Wait('ci-publication')
        run = runs[0]
        p.require(run['event'] == 'push' and run['head_sha'] == source and run['head_branch'] == 'main' and
                  run['path'] == PUBLISHER and run['repository']['full_name'] == proposal.REPOSITORY,
                  'publication run differs from exact reviewed main push')
        if run['conclusion'] != 'success':
            raise Wait('ci-run-unsuccessful')
        p.number(run['id'], 1, 2**63 - 1)
        args = ['/usr/bin/skopeo', 'inspect', '--no-tags', '--format', '{{.Digest}}']
        if self.registry_auth is not None:
            args.extend(('--authfile', self.registry_auth))
        try:
            digest = proposal.capture([*args, 'docker://' + REGISTRY + ':' + source], self.end, ceiling=256).decode().strip()
        except proposal.Unavailable as exc:
            raise Wait('ci-publication') from exc
        p.require(re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'OCI publication did not resolve to an exact manifest')
        release = self.trust.verify('checklist', source, REGISTRY + '@' + digest, run['id'])
        p.require(all(release[key] == value for key, value in review.items()), 'published OCI has different independent review evidence')
        return release

    def activation(self):
        return self.destination.initial_activation()

    def deploy(self, release):
        self.destination.deploy(release['source_sha'], release['subject'], release['run_id'],
                                None if self.registry_auth is None else str(self.registry_auth))

    def evidence(self):
        path = EVIDENCE / (self.job + '.json')
        if not os.path.lexists(path) or not os.path.lexists(str(path) + '.sig'):
            raise Wait('signed-destination-evidence')
        candidate.protected_file(path, p.MAX_MESSAGE)
        candidate.protected_file(Path(str(path) + '.sig'), 8192)
        return path

    def confirm(self, evidence):
        self.destination.confirm(str(evidence))


def matches(activation, release, binding):
    attempt = release.get('run_attempt')
    return (type(attempt) is int and attempt > 0 and activation is not None and
            type(activation.get('run_attempt')) is int and activation['run_attempt'] == attempt and
            all(activation.get(key) == release[key] for key in
                ('source_sha', 'subject', 'run_id', 'artifact_sha256', 'source_tree', 'pull_request', 'review_head')) and
            activation.get('dns_name') == binding['dns_name'] and not activation.get('quarantined'))


def advance(state, binding, bundle, result, site, backend, save):
    def transition(phase, **evidence):
        state.update(phase=phase, reason=None, **evidence)
        save(state)

    job = state['job_id']
    request = proposal.request_shape(dict(version=1, job_id=job, agreement_sha256=binding['agreement_sha256'],
        repository=binding['repository'], base_sha=binding['base_sha'], candidate_sha=binding['candidate_sha'],
        tree_sha=binding['tree_sha'], bundle_sha256=binding['bundle_sha256'], release_binding_sha256=p.identity(binding),
        review_policy_sha256=policy_identity(backend.rules),
        developer_id=site['developer_id'], developer_login=site['developer_login'], fork=site['fork'],
        branch=proposal.branch(job, binding['candidate_sha'])))
    p.require(state.get('proposal') in (None, request), 'durable proposal grant or candidate changed')
    if not state.get('host_verified'):
        backend.live_host_result(result)
        transition('observing-proposal', host_verified=True, proposal=request)
    pull = backend.find(request)
    if pull is None:
        p.require(state.get('pull_request') is None, 'recorded pull request is no longer observable')
        transition('proposing', proposal=request)
        try:
            backend.propose(request, bundle)
        except proposal.ObservationUnavailable:
            raise
        except proposal.Unavailable as exc:
            # A timeout may follow either external write. Only exact readback authorizes another advance.
            pull = backend.find(request)
            if pull is None:
                raise Wait('proposal-transport') from exc
        if pull is None:
            pull = backend.find(request)
        if pull is None:
            raise Wait('proposal-transport')
    p.require(state.get('pull_request') in (None, pull['number']), 'durable pull request identity changed')
    if pull['state'] == 'open':
        transition('awaiting-independent-review-and-merge', pull_request=pull['number'], pull_url=pull['html_url'])
        if pull['base']['sha'] != request['base_sha']:
            raise Wait('stale-reviewed-base')
        return
    p.require(pull['merged'] is True, 'protected proposal was closed ahead of a reviewed merge')
    if state.get('release') is None:
        source, review = backend.review(pull, request)
        p.require(state.get('merged_source') in (None, source), 'durable merged source changed')
        transition('awaiting-protected-ci', pull_request=pull['number'], pull_url=pull['html_url'], merged_source=source)
        release = backend.published(source, review)
        transition('publication-verified', release=release)
    else:
        release = state['release']
        p.require(pull['merge_commit_sha'] == release['source_sha'] == state['merged_source'] and
                  pull['merged_by']['id'] == site['merge_actor_id'], 'previously attested publication changed')
    activation = backend.activation()
    active = activation['active']
    if not matches(active, release, binding) or activation['route_pending']:
        pending = activation['pending']
        p.require(pending is None or pending['operation'] == 'deploy' and matches(pending['release'], release, binding),
                  'another deployment requires independent resolution')
        if active and active.get('quarantined'):
            p.require(active['artifact_sha256'] != release['artifact_sha256'],
                      'correction requires an independently verified different digest')
        else:
            p.require(not active or matches(active, release, binding) or
                      activation['confirmed'] == active['artifact_sha256'],
                      'an earlier deployment requires independent confirmation')
        transition('deploying')
        backend.deploy(release)
        activation = backend.activation()
    p.require(matches(activation['active'], release, binding) and not activation['pending'] and not activation['route_pending'],
              'exact tailnet release is yet to be observed')
    active = activation['active']
    if activation['confirmed'] != release['artifact_sha256'] or active.get('verified_destination') is not True:
        transition('awaiting-independent-destination', destination='https://' + binding['dns_name'] + '/')
        evidence = backend.evidence()
        transition('confirming-destination')
        backend.confirm(evidence)
        activation = backend.activation()
        active = activation['active']
    p.require(matches(active, release, binding) and active['verified_destination'] is True and
              activation['confirmed'] == release['artifact_sha256'] and not activation['pending'] and
              not activation['route_pending'], 'authenticated destination confirmation is still pending')
    p.digest(active['destination_receipt_sha256'])
    transition('confirmed', destination='https://' + binding['dns_name'] + '/',
               destination_receipt_sha256=active['destination_receipt_sha256'])


def record(root):
    path = root / 'promotion.json'
    return p.loads(read_private(path, p.MAX_MESSAGE)) if os.path.lexists(path) else None


def hold(state, reason, *, manual=False):
    state['reason'] = reason
    if reason in RETRYABLE:
        previous = state.get('observation_retry', {})
        failures = previous.get('failures', 0) + 1
        if failures <= len(RETRY_DELAYS):
            state['observation_retry'] = {'reason': reason, 'failures': failures,
                                          'after_unix': int(time.time()) + RETRY_DELAYS[failures - 1]}
            return
        manual = True
    state.pop('observation_retry', None)
    if manual:
        state['resume_required'] = True


def automatic_due(state):
    return not state or (not state.get('resume_required') and
                         state.get('observation_retry', {}).get('after_unix', 0) <= int(time.time()))


def run(job, *, resume_held=False):
    root = trusted_directory(product.job_path(job))
    value = product.plan(read_private(root / 'plan.json', p.MAX_MESSAGE))
    p.require(value['job_id'] == job, 'protected release job changed')
    with os.fdopen(os.open(root / 'promotion.lock', os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600), 'rb') as lock:
        p.private_file(root / 'promotion.lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        saved = record(root) or {'version': 1, 'job_id': job, 'plan_sha256': p.identity(value),
                                 'phase': 'awaiting-validated-candidate', 'reason': None}
        p.require(saved['job_id'] == job and saved['plan_sha256'] == p.identity(value), 'durable promotion plan changed')
        if saved['phase'] in TERMINAL:
            return saved
        if resume_held and saved.pop('resume_required', False):
            saved.pop('observation_retry', None)
        if not automatic_due(saved):
            return saved

        def write(state):
            product.durable_json(root / 'promotion.json', state)

        state = product.read_state(root)
        local = state['phase']
        if local == 'blocked':
            saved['phase'] = 'validation-blocked'
        elif local in ('awaiting-external-validation', 'local-validation-recorded'):
            saved['phase'] = 'external-adapter-needed' if local == 'awaiting-external-validation' else 'local-only'
        elif local == 'passed':
            if state.get('materialized') is None:
                if state.get('repair') and state['repair']['candidate']['source_revision'] != value['agreement']['initial_commit']:
                    saved['reason'] = 'verified-candidate-bundle-required'
                else:
                    saved['phase'] = 'no-changed-candidate'
            elif state['materialized']['candidate_sha'] == value['agreement']['initial_commit']:
                saved['phase'] = 'no-changed-candidate'
            else:
                try:
                    binding, bundle, result = inputs(root, job, value, state)
                    p.require(saved.get('binding') in (None, binding), 'durable release candidate changed')
                    saved['binding'] = binding
                    candidate.protected_file(SITE / 'policy.json', 4096)
                    site = policy(read_private(SITE / 'policy.json', 4096))
                    p.require(site['dns_name'] == binding['dns_name'] and site['repository'] == binding['repository'],
                              'protected promotion scope differs from the owner agreement')
                    authority_left = site['expires_unix'] - time.time()
                    if not 0 < authority_left <= 31 * 86400:
                        raise Wait('scoped-release-grant-expired')
                    backend = Live(site, job, binding, time.monotonic() + min(authority_left, 210))
                    advance(saved, binding, bundle, result, site, backend, write)
                    saved.pop('observation_retry', None)
                except Wait as exc:
                    hold(saved, exc.reason)
                except proposal.AuthorityDenied:
                    hold(saved, 'github-authority-denied', manual=True)
                except proposal.ObservationUnavailable:
                    hold(saved, 'github-observation')
                except Blocked as exc:
                    if str(exc) == 'checklist release is frozen by renewal':
                        hold(saved, 'destination-fenced')
                    else:
                        hold(saved, 'protected-release-policy-rejected', manual=True)
                except proposal.Unavailable:
                    hold(saved, 'destination-observation' if saved['phase'] in ('deploying', 'confirming-destination')
                         else 'github-observation')
                except FileNotFoundError:
                    hold(saved, 'protected-custody-or-evidence-missing')
                except (ConnectionError, TimeoutError, ssl.SSLEOFError):
                    hold(saved, 'destination-observation')
                except (OSError, ValueError, KeyError, TypeError, IndexError, ImportError, subprocess.SubprocessError):
                    hold(saved, 'protected-scope-or-evidence-rejected', manual=True)
        write(saved)
        return saved


def scan():
    jobs = trusted_directory(product.JOBS)
    rows = sorted(jobs.iterdir())
    p.require(len(rows) <= 128, 'protected promotion catalogue reached its service limit')
    for path in rows:
        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', path.name) is None:
            continue
        root = trusted_directory(product.job_path(path.name))
        prior = record(root)
        if ((prior is None or prior['phase'] not in TERMINAL) and automatic_due(prior) and (root / 'state.json').is_file() and
                product.read_state(root)['phase'] in product.TERMINAL):
            candidate.invoke([product.SYSTEMCTL, 'start', '--no-block', 'dev-pair-promotion@' + path.name + '.service'],
                             time.monotonic() + 8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    advance_command = commands.add_parser('advance')
    advance_command.add_argument('job')
    advance_command.add_argument('--resume-held', action='store_true')
    commands.add_parser('status').add_argument('job')
    commands.add_parser('scan')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        p.require(os.geteuid() == 0, 'installed protected product controller required')
        if args.command == 'scan':
            scan()
        else:
            row = (run(args.job, resume_held=args.resume_held) if args.command == 'advance' else
                   record(trusted_directory(product.job_path(args.job))))
            print(p.canonical(row))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(2, 'Protected checklist promotion unavailable (' + type(exc).__name__ + ').\n')


if __name__ == '__main__':
    main()
