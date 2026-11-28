"""Deliberate renewal of a complete signed platform at an existing managed site."""
import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import pwd
import re
import runpy
import stat
import subprocess
import time

import renewal as r
import renewal_site as s
from renewal import protocol as p

SCOPE = 'stable'
IDENTITY = 'stable-bindings'
OFFER = 'offers/stable.json'
REQUEST = 'requests/stable.json'
POLICY = 'bootstrap/host-commissioning/automatic-policy.json'
INSTALLED = Path('/usr/libexec/dev-pair/tools/stable_renewal.py')
FIELDS = ('schema operation machine_id previous_release_sha256 previous_platform_sha256 '
          'previous_base_platform_sha256 previous_base_intake_sha256 target_release_sha256 '
          'platform_sha256 intake_sha256 site_config_sha256 affected_jobs')


def machine_id():
    path = Path('/etc/machine-id')
    value = s.protected_bytes(path, 33).decode('ascii').removesuffix('\n')
    p.digest(value, 32)
    return value


def site_commitment(controller):
    value = r.read_json(controller.root / POLICY)
    p.fields(value, 'schema source_sha machine_id platform_sha256 site_config_sha256 checklist timers')
    r.require(type(value['schema']) is int and value['schema'] == 1 and value['machine_id'] == machine_id()
              and value['timers'] == [], 'stable renewal requires the original managed site and machine')
    for name in ('platform_sha256', 'site_config_sha256'):
        p.digest(value[name])
    p.digest(value['source_sha'], 40)
    return value


def path_for(controller, platform):
    p.digest(platform)
    return controller.control / IDENTITY / (platform + '.json')


def local_binding(resolver, reference, site_hash):
    controller = resolver.controller
    release = controller.release(reference)
    value = r.read_json(controller.control / 'platform-bindings' / (reference + '.json'))
    p.fields(value, 'schema release_sha256 platform_sha256 base_platform_sha256 site_config_sha256 plan_sha256 intake_sha256')
    directory, index, intake = resolver.index(value['platform_sha256'])
    r.require(type(value['schema']) is int and value['schema'] == 1 and value['release_sha256'] == reference
              and value['site_config_sha256'] == site_hash and value['plan_sha256'] == release['plan_sha256']
              and value['intake_sha256'] == intake and
              value['base_platform_sha256'] == (index['base_platform_sha256'] or directory.name)
              and release['source_revision'] == index['source_sha'],
              'local stable selection differs from its exact signed intake and site')
    _, full, _ = resolver.index(value['base_platform_sha256'])
    r.require(full['kind'] == s.FULL, 'local release lacks the complete signed stable base')
    for name, published in s.artifact_rows(index, full).items():
        selected = release['components'][name]
        artifact = published['bundle_manifest_sha256'] if name == 'host' else published['oci_config_sha256']
        r.require((selected['source_revision'], selected['artifact_sha256']) == (published['source_sha'], artifact) and
                  (name == 'host' or selected['config_sha256'] == published['context_sha256']) and
                  (name not in r.SCOPE_COMPONENTS['agent'] or selected['codex_version'] == published['codex_version']),
                  'local stable component differs from its signed portable identity')
    r.require(release['components']['maintenance-agent'].get('platform_sha256') == directory.name,
              'stable release lacks the exact historical maintenance admission')
    return value


def settled(resolver, site_hash):
    controller = resolver.controller
    reference = controller.live_release()
    _, state = controller.transition()
    r.require(r.read_json(controller.control / 'site-current.json') == reference and
              (state is None or state['phase'] in r.TERMINAL) and
              not os.path.lexists(controller.root / 'renewal-fence/frozen'),
              'the current local release and workload effect fence must be settled')
    return local_binding(resolver, reference, site_hash)


def lineage(resolver, platform, initial, site_hash, machine, source=None):
    """Bind every local full transition back to the immutable commissioning origin."""
    seen = set()
    while platform != initial:
        r.require(platform not in seen and len(seen) < r.MAX_ATTEMPTS,
                  'stable platform history is cyclic or exceeds its retained bound')
        seen.add(platform)
        value = binding(resolver.controller, platform, resolver=resolver, machine=machine)
        r.require(value['site_config_sha256'] == site_hash, 'stable history changes the original approved site')
        platform = value['previous_base_platform_sha256']
    _, index, _ = resolver.index(initial)
    r.require(index['kind'] == s.FULL and index['previous_platform_sha256'] is None and index['schema'] == 2 and
              source in (None, index['source_sha']),
              'stable history lacks the original signed full installation')


def validate_successor(resolver, prior, index, platform, site):
    r.require(index['kind'] == s.FULL and index['schema'] == 2 and index['base_platform_sha256'] is None and
              index['previous_platform_sha256'] == prior['base_platform_sha256'] and
              platform not in (prior['platform_sha256'], prior['base_platform_sha256']),
              'stable renewal requires an exact full successor of the retained stable base')
    commitment = site_commitment(resolver.controller)
    r.require(prior['site_config_sha256'] == commitment['site_config_sha256'], 'stable renewal changes the commissioned site')
    lineage(resolver, prior['base_platform_sha256'], commitment['platform_sha256'],
            commitment['site_config_sha256'], commitment['machine_id'], commitment['source_sha'])
    previous = resolver.controller.release(prior['release_sha256'])
    r.require(previous['config_sha256'] == site['host_config_sha256'], 'stable renewal changes site configuration')
    _, base_index, base_intake = resolver.index(prior['base_platform_sha256'])
    r.require(index['source_sha'] != base_index['source_sha'] and
              all(tuple(map(int, index['components'][component]['codex_version'].split('.'))) >=
                  tuple(map(int, previous['components'][component]['codex_version'].split('.')))
                  for component in r.SCOPE_COMPONENTS['agent']),
              'stable successor repeats its source or regresses selected agent tooling')
    return commitment, base_intake


def store(resolver, offer, target, previous, successor):
    commitment, base_intake = successor
    value = {'schema': 1, 'operation': offer['operation'], 'machine_id': commitment['machine_id'],
             'previous_release_sha256': previous['release_sha256'],
             'previous_platform_sha256': previous['platform_sha256'],
             'previous_base_platform_sha256': previous['base_platform_sha256'],
             'previous_base_intake_sha256': base_intake, 'target_release_sha256': target['release_sha256'],
             'platform_sha256': target['platform_sha256'], 'intake_sha256': target['intake_sha256'],
             'site_config_sha256': target['site_config_sha256'], 'affected_jobs': offer['affected_jobs']}
    controller = resolver.controller
    directory = controller.control / IDENTITY
    try:
        r.create_directory(directory)
    except FileExistsError:
        r.trusted_directory(directory)
    resolver.store(path_for(controller, target['platform_sha256']), value)
    return binding(controller, target['platform_sha256'], resolver=resolver)


def binding(controller, platform, *, resolver=None, machine=None):
    resolver = resolver or s.Resolver(controller, portable=controller.root / 'platform-releases')
    value = r.read_json(path_for(controller, platform))
    p.fields(value, FIELDS)
    p.token(value['operation'])
    r.require(type(value['schema']) is int and value['schema'] == 1 and value['platform_sha256'] == platform and
              value['machine_id'] == (machine_id() if machine is None else machine), 'stable approval belongs to another machine or package')
    site = value['site_config_sha256']
    p.digest(site)
    old = local_binding(resolver, value['previous_release_sha256'], site)
    new = local_binding(resolver, value['target_release_sha256'], site)
    _, old_base, old_intake = resolver.index(value['previous_base_platform_sha256'])
    _, successor, _ = resolver.index(platform)
    r.require(old['platform_sha256'] == value['previous_platform_sha256'] and
              old['base_platform_sha256'] == value['previous_base_platform_sha256'] and
              old_base['kind'] == successor['kind'] == s.FULL and old_base['schema'] == successor['schema'] == 2 and
              old_intake == value['previous_base_intake_sha256'] and
              successor['previous_platform_sha256'] == old['base_platform_sha256'] and
              new['base_platform_sha256'] == new['platform_sha256'] == platform and
              new['intake_sha256'] == value['intake_sha256'] and old['release_sha256'] != new['release_sha256'],
              'stable approved source, predecessor or intake receipt differs')
    config_raw = s.protected_bytes(resolver.configs / (site + '.json'), 65536)
    r.require(r.sha(config_raw) == site, 'the exact approved stable site changed')
    config = s.closed_site(config_raw)
    r.require(value['affected_jobs'] == sorted(config['jobs']), 'stable approval omits a configured job')
    return value


def for_release(controller, reference):
    p.digest(reference)
    row = r.read_json(controller.control / 'platform-bindings' / (reference + '.json'))
    approval = binding(controller, row['platform_sha256'])
    r.require(approval['target_release_sha256'] == reference, 'stable approval targets a different local release')
    return approval


def bound_request(controller, request):
    grant = for_release(controller, request['target_sha256'])
    r.require(request['scope'] == SCOPE and request['previous_sha256'] == grant['previous_release_sha256'] and
              all(request[key] == grant[key] for key in ('operation', 'affected_jobs')),
              'stable approval differs from its immutable request')
    return grant


def verify_transition(controller, desired):
    """Authorize a fixed host executor only inside the exact existing effect fence."""
    p.fields(desired, 'operation release_sha256 component')
    attempt, state = controller.transition()
    r.require(attempt is not None and state['phase'] in ('applying', 'rolling-back')
              and r.read_json(controller.root / 'renewal-fence/frozen') == attempt.name,
              'stable host activation lacks the existing exact effect fence')
    request = r.checked_request(state['request'], SCOPE)
    grant = bound_request(controller, request)
    component = 'target_sha256' if state['phase'] == 'applying' else 'previous_sha256'
    reference = request[component]
    r.require(desired['operation'] == request['operation'] and desired['release_sha256'] == reference and
              desired['component'] == controller.release(reference)['components']['host'],
              'stable host activation does not select the journaled component')
    current = controller.live_release()
    selected = r.read_json(controller.control / 'site-current.json')
    participants = {request['previous_sha256'], request['target_sha256']}
    r.require({current, selected} <= participants, 'stable selectors escaped their protected transition')
    commitment = site_commitment(controller)
    lineage(s.Resolver(controller, portable=controller.root / 'platform-releases'),
            grant['platform_sha256'], commitment['platform_sha256'], commitment['site_config_sha256'],
            commitment['machine_id'], commitment['source_sha'])
    return grant


def approved_request(controller, approval):
    p.fields(approval, 'schema offer_sha256 request')
    r.require(type(approval['schema']) is int and approval['schema'] == 1,
              'unsupported stable approval schema')
    raw = r.read_private(controller.control / OFFER, r.MAX_CONTROL)
    r.require(r.sha(raw) == approval['offer_sha256'], 'approved stable offer changed or was withdrawn')
    offer = s.offer_record(r.loads(raw), SCOPE)
    request = r.checked_request(approval['request'], SCOPE)
    grant = bound_request(controller, request)
    r.require(offer['platform_sha256'] == grant['platform_sha256'] and
              offer['site_config_sha256'] == grant['site_config_sha256'] and
              offer['previous_release_sha256'] == request['previous_sha256'] and
              all(offer[key] == request[key] for key in ('operation', 'affected_jobs', 'reason')),
              'protected stable offer and scoped request differ')
    return request, offer


def native_observation(controller, request, offer, boots):
    observation = r.read_json(controller.control / 'platform-observations' / (request['target_sha256'] + '.json'))
    resolver = s.Resolver(controller, portable=controller.root / 'platform-releases')
    native = local_binding(resolver, request['target_sha256'], offer['site_config_sha256'])
    directory, _, _ = resolver.index(offer['platform_sha256'])
    p.fields(observation, 'schema release_sha256 platform_sha256 base_platform_sha256 site_config_sha256 '
                          'plan_sha256 intake_sha256 boot_id installed_sha256')
    r.require(all(observation[key] == value for key, value in native.items()) and observation['boot_id'] in boots and
              observation['installed_sha256'] == r.sha(s.protected_bytes(directory / 'installed.json', 65536)),
              'stable release lacks its exact authorized native installed readback')


def active_request(controller, approval):
    request, offer = approved_request(controller, approval)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    native_observation(controller, request, offer, {boot})
    return request


def frozen_request(controller, attempt, state, original_boot, current_boot):
    request, offer = approved_request(controller, r.read_json(controller.control / REQUEST))
    r.require(attempt is not None and state['phase'] in ('applying', 'verifying', 'accepted') and
              type(state['schema']) is int and state['schema'] == 1 and state['attempt_id'] == attempt.name and
              r.checked_request(state['request'], SCOPE) == request and
              r.read_json(controller.root / 'renewal-fence/frozen') == attempt.name and
              forward_started(controller, request), 'stable recovery lacks its exact approved forward-only transition')
    previous, target = request['previous_sha256'], request['target_sha256']
    r.require({controller.live_release(), r.read_json(controller.control / 'site-current.json')} <= {previous, target},
              'stable recovery selectors escaped the approved participants')
    native_observation(controller, request, offer, {original_boot, current_boot})
    commitment = site_commitment(controller)
    lineage(s.Resolver(controller, portable=controller.root / 'platform-releases'), offer['platform_sha256'],
            commitment['platform_sha256'], commitment['site_config_sha256'],
            commitment['machine_id'], commitment['source_sha'])
    return request


def access(controller):
    from bootstrap import Bootstrap
    from destination_observation import STABLE_CANDIDATE

    return s.CandidateAccess(controller, Bootstrap(), kind=STABLE_CANDIDATE)


def host_bundle(controller, approval):
    from platform_release_install import HOST_RELEASES, check_host_bundle

    _, index, _ = s.Resolver(controller, portable=controller.root / 'platform-releases').index(approval['platform_sha256'])
    row = index['components']['host']
    release = controller.release(approval['target_release_sha256'])
    r.require(release['components']['host']['artifact_sha256'] == row['bundle_manifest_sha256'] and
              release['components']['host']['source_revision'] == row['source_sha'],
              'stable host executable lacks exact full publisher authority')
    directory = HOST_RELEASES / row['bundle_manifest_sha256']
    check_host_bundle(directory, row, time.monotonic() + 30)
    return directory


def forward_started(controller, request):
    from provider_transition import STATE

    root = controller.root / STATE.removeprefix('/var/lib/dev-pair/')
    if not any(os.path.lexists(root / name) for name in ('fixed-pending.json', 'fixed-' + request['target_sha256'] + '.json')):
        return False
    from host_fixed_migration import forward_started as observed

    return observed(controller, request)


def reviewed_driver(controller, grant):
    return r.SiteDriver(host_bundle(controller, grant) / 'runtime/renewal/driver')


def confirm_kit_source(expected):
    """Admit an ordinary verified successor checkout for pre-stable installs."""
    if Path(__file__).absolute() == INSTALLED:
        r.require(expected is None, 'a source-kit pin is used only from the reviewed successor checkout')
        return
    p.digest(expected, 40)
    from commission_host import verify_checkout

    verify_checkout(Path(__file__).absolute().parents[1], expected, 0)


def match_kit_bundle(controller, grant, expected):
    if expected is None:
        return
    release = controller.release(grant['target_release_sha256'])
    r.require(release['source_revision'] == expected, 'successor kit does not identify the exact approved full publisher')
    bundle = host_bundle(controller, grant)
    script = Path(__file__).absolute()
    r.require(s.protected_bytes(script, 262144) ==
              s.protected_bytes(bundle / 'tools/stable_renewal.py', 262144),
              'successor entry point differs from its signed immutable host bundle')


@contextmanager
def lease(controller):
    path = controller.control / 'stable-owner.lock'
    with os.fdopen(os.open(path, os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'rb') as stream:
        node = os.fstat(stream.fileno())
        r.require(stat.S_ISREG(node.st_mode) and node.st_uid == node.st_gid == 0 and node.st_nlink == 1 and
                  stat.S_IMODE(node.st_mode) == 0o600, 'protected stable release lease required')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        r.require(path.lstat().st_ino == node.st_ino, 'stable release lease changed')
        yield


def prepare(controller, reason, *, source=None, run=None, platform=None, kit_source=None):
    from bootstrap import Bootstrap
    import platform_release_install as installer
    from platform_release_protocol import hex_id

    intake = installer.intake
    resolver = s.Resolver(controller, portable=controller.root / 'platform-releases')
    p.text(reason, 512)
    if kit_source is not None:
        r.require(source in (None, kit_source), 'expert source differs from the successor kit')
        source = kit_source
    r.require((run is None) == (platform is None) and (source is not None or run is None),
              'expert release pins require source, run and portable digest together')
    if source is not None:
        hex_id(source, 40)
    if platform is not None:
        hex_id(platform)
    commitment = site_commitment(controller)
    site_sha = commitment['site_config_sha256']
    site = installer.site_configuration(resolver.configs / (site_sha + '.json'), site_sha)
    Bootstrap().verify_workload_access()
    with controller.lock():
        prior = settled(resolver, site_sha)
        old_offer = r.read_json(controller.control / OFFER) if os.path.lexists(controller.control / OFFER) else None
        if old_offer is not None:
            s.offer_record(old_offer, SCOPE)
            if old_offer['previous_release_sha256'] == prior['release_sha256']:
                r.require(old_offer['reason'] == reason and platform in (None, old_offer['platform_sha256']),
                          'a different stable window is already staged for this live selection')
                platform = old_offer['platform_sha256']
            else:
                old_offer = None
    end = time.monotonic() + intake.CONTROL_SECONDS
    with intake.intake_lock():
        intake.recover_transfer()
        if platform is None:
            source, run, platform = intake.discover_full(source, prior['base_platform_sha256'], end)
        if not os.path.lexists(resolver.portable / platform):
            intake.acquire(source, run, platform, prior['base_platform_sha256'], end)
        _, index, _ = resolver.index(platform)
        r.require(source in (None, index['source_sha']) and run in (None, index['publisher_run']),
                  'staged full publisher differs from the requested source or run')
        validate_successor(resolver, prior, index, platform, site)
        installer.install(platform, site_sha, time.monotonic() + installer.TIME_LIMIT,
                          stable_previous=prior['release_sha256'])
    operation = 'stable-' + r.identity([prior['release_sha256'], platform, reason])[:48]
    offer = {'schema': 2, 'scope': SCOPE, 'operation': operation, 'platform_sha256': platform,
             'previous_release_sha256': prior['release_sha256'], 'site_config_sha256': site_sha,
             'affected_jobs': sorted(site['jobs']), 'reason': reason}
    with controller.lock():
        r.require(settled(resolver, site_sha) == prior, 'protected live selection changed during stable staging')
        if old_offer is not None:
            r.require(old_offer == offer, 'prepared stable window differs from the retained offer')
        binding = resolver.resolve(offer)
        match_kit_bundle(controller, for_release(controller, binding['release_sha256']), kit_source)
        r.replace_json(controller.control / OFFER, offer)
        target = binding['release_sha256']
        access(controller).prepare(offer, target)
        previous, replacement = (controller.release(reference)['components'] for reference in (prior['release_sha256'], target))
    return {'phase': 'awaiting-independent-stable-access', 'operation': operation, 'source_sha': index['source_sha'],
            'publisher_run': index['publisher_run'], 'platform_sha256': platform, 'release_sha256': target,
            'affected_jobs': offer['affected_jobs'], 'reason': reason,
            'changes': {name: {'previous': previous[name], 'target': replacement[name]}
                        for name in sorted(previous) if previous[name] != replacement[name]}}


def apply(controller, operation, *, kit_source=None):
    with controller.lock():
        attempt, state = controller.transition()
        if state is not None and (state['phase'] not in r.TERMINAL or controller.unfinished_thaw(attempt, state)):
            r.require(state['request']['scope'] == SCOPE and state['request']['operation'] == operation,
                      'a different protected operation requires recovery')
            grant = bound_request(controller, state['request'])
            match_kit_bundle(controller, grant, kit_source)
            controller.driver = reviewed_driver(controller, grant)
            return controller.resume(attempt, state)
        offer = s.offer_record(r.read_json(controller.control / OFFER), SCOPE)
        r.require(offer['operation'] == operation, 'confirm the exact prepared stable maintenance window')
        grant = binding(controller, offer['platform_sha256'])
        match_kit_bundle(controller, grant, kit_source)
        controller.driver = reviewed_driver(controller, grant)
        target = grant['target_release_sha256']
        if state is not None and state['request']['operation'] == operation and state['phase'] == 'completed':
            r.require(controller.live_release() == target and r.read_json(controller.control / 'site-current.json') == target,
                      'completed stable window no longer selects the live release')
            controller.verify_driver('observe', state, target)
            return state
        access(controller).fresh(target, offer['previous_release_sha256'], operation)
        request = {'schema': 1, 'scope': SCOPE, 'operation': operation, 'previous_sha256': offer['previous_release_sha256'],
                   'target_sha256': target, 'affected_jobs': offer['affected_jobs'], 'reason': offer['reason']}
        approval = {'schema': 1, 'offer_sha256': r.identity(offer), 'request': request}
        active_request(controller, approval)
        r.replace_json(controller.control / REQUEST, approval)
    return controller.apply(SCOPE)


def pending_review(observer):
    recover = getattr(observer, 'recover_request', None)
    return (recover() if recover is not None else None) or observer.request()


def enroll_stable_reviewer(host, fingerprint, incoming):
    from bootstrap import SIGNER_TRUST_LOCK
    from destination_observation import STABLE_TRUST, bounded_file, stable_host_trust, stable_signer

    p.require(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint) is not None,
              'the separately supplied stable reviewer fingerprint is required')
    line = incoming.readline(1025)
    p.require(line.endswith('\n') and len(line) <= 1024, 'paste the authorized stable reviewer public key')
    public = host.observer_public_key(line)
    p.require(host.signer_fingerprint(public) == fingerprint, 'stable reviewer key differs from its authorized fingerprint')
    material = public.split()[1].encode()
    with host.lock(SIGNER_TRUST_LOCK):
        p.require(material not in bounded_file(host.signer_trust_file(), 16384).split(),
                  'stable reviewed authority must be outside all other host signing grants')
        host.atomic(STABLE_TRUST, stable_signer(public).decode('ascii'), mode=0o600)
        stable_host_trust(host)
    return {'phase': 'stable-reviewer-enrolled', 'fingerprint': fingerprint}


def broker_unit(request):
    p.digest(request)
    return 'dev-pair-stable-' + request


def system_command(*args, allowed=(0,)):
    completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                               timeout=15, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'}, check=False)
    p.require(completed.returncode in allowed and len(completed.stdout) <= 16384,
              'the exact stable access gateway operation was unavailable')
    return completed.stdout.decode()


def start_observer(bundle, request, pending, *, command=system_command):
    from systemd_service_profile import exec_start_matches, manager_properties

    directory = broker_unit(request)
    unit = directory + '.service'
    script = str(bundle / 'runtime/renewal/agent-observer')
    argv = ('/usr/bin/python3', '-IB', script, 'stable-listen', request)
    properties = ('LoadState', 'ActiveState', 'Type', 'User', 'Group', 'ExecStart', 'RuntimeDirectory')

    def show():
        raw = command('/usr/bin/systemctl', 'show', '--all', '--property=' + ','.join(properties), unit)
        return manager_properties(raw, properties)

    loaded = command('/usr/bin/systemctl', 'show', '--all', '--property=LoadState', '--value', unit,
                     allowed=(0, 1, 4)).strip()
    if loaded == 'not-found':
        remaining = pending['candidate']['requested_at'] + 3600 - int(time.time())
        p.require(0 < remaining <= 3600, 'the exact stable access window expired')
        command('/usr/bin/systemd-run', '--quiet', '--collect', '--service-type=exec', '--unit=' + unit,
                '--property=User=root', '--property=Group=root', '--property=UMask=0077',
                '--property=RuntimeDirectory=' + directory, '--property=RuntimeDirectoryMode=0755',
                '--property=RuntimeDirectoryPreserve=no', '--property=RuntimeMaxSec=' + str(remaining),
                '--property=TimeoutStopSec=15s', '--property=KillMode=control-group',
                '--property=MemoryMax=1G', '--property=TasksMax=384', *argv)
    row = show()
    p.require(row['LoadState'] == 'loaded' and row['ActiveState'] in ('active', 'activating') and row['Type'] == 'exec'
              and (row['User'], row['Group'], row['RuntimeDirectory']) == ('root', 'root', directory)
              and exec_start_matches(row['ExecStart'], ' '.join(argv)),
              'the loaded stable access gateway differs from the exact allowed operation')
    path = Path('/run') / directory / 'observer'
    until = time.monotonic() + 5
    while not os.path.lexists(path):
        p.require(time.monotonic() < until, 'the exact stable access socket could not be observed')
        time.sleep(.05)
    parent, leaf = path.parent.lstat(), path.lstat()
    p.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022
              and stat.S_ISSOCK(leaf.st_mode) and (leaf.st_uid, leaf.st_gid) == (0, pwd.getpwnam('core').pw_gid)
              and stat.S_IMODE(leaf.st_mode) == 0o660,
              'the stable access socket has different protected ownership')
    return unit


def poll_access(controller, *, kit_source=None):
    from bootstrap import Blocked
    from day0_access_exchange import ExchangeUnavailable, exchange
    from destination_observation import encoding, stable_host_trust

    with controller.lock():
        observer = access(controller)
        pending = pending_review(observer)
        reference = pending['role_artifacts']['release_sha256']
        grant = for_release(controller, reference)
        match_kit_bundle(controller, grant, kit_source)
        raw = encoding(pending)
        request_id = r.sha(raw)
        operation = pending['candidate']['operation']
        result = {'phase': 'awaiting-independent-stable-access', 'operation': operation, 'request_id': request_id}
        try:
            stable_host_trust(observer.host)
        except FileNotFoundError:
            return {**result, 'access_state': 'stable-reviewer-trust-required'}
        try:
            observer.fresh(reference, pending['candidate']['previous_release_sha256'], operation, expected=pending)
        except (Blocked, OSError, ValueError):
            bundle = host_bundle(controller, grant)
        else:
            return {**result, 'phase': 'stable-access-preapproved'}
    unit = start_observer(bundle, request_id, pending)
    try:
        response = exchange(raw)
    except ExchangeUnavailable:
        return {**result, 'access_state': 'station-unavailable'}
    if response is None:
        return {**result, 'access_state': 'waiting-for-independent-approval'}
    with controller.lock():
        observer.receive(response, pending)
    # The confirmed proof is durable. Failure to stop the scoped broker leaves
    # only a fixed deadline, local socket and already-spent challenge budget.
    try:
        system_command('/usr/bin/systemctl', 'stop', unit)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return {**result, 'phase': 'stable-access-preapproved'}


def apply_with_access(controller, operation, *, kit_source=None):
    with controller.lock():
        attempt, state = controller.transition()
        if state is not None and state['request']['operation'] == operation:
            recover = getattr(access(controller), 'recover_request', None)
            poll = (recover is not None and recover() is not None
                    if state['phase'] not in r.TERMINAL or controller.unfinished_thaw(attempt, state) else
                    state['phase'] == 'deferred')
        else:
            offer = s.offer_record(r.read_json(controller.control / OFFER), SCOPE)
            r.require(offer['operation'] == operation, 'confirm the exact prepared stable maintenance window')
            poll = True
    if poll:
        report = poll_access(controller, kit_source=kit_source)
        if report['phase'] != 'stable-access-preapproved':
            return report
    return apply(controller, operation, kit_source=kit_source)


def named_access_probe(controller, grant, pending, role):
    from bootstrap import Bootstrap

    host = Bootstrap()
    # The SSH tuple remains in the authenticated command process. The gate
    # checks sshd ancestry, an owned established socket, and its actual route.
    driver = runpy.run_path(str(reviewed_driver(controller, grant).path))['access_probe']
    with p.workload_access_lease(controller.root):
        return driver({'role': role, 'source_sha': pending['source_sha'],
                       'candidate': pending['role_artifacts']['release_sha256']}, candidate=True,
                      stable=True, peer_reader=host.observed_ssh_peer)


def main():
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit-source-sha', help='independently received reviewed successor checkout commit')
    actions = parser.add_subparsers(dest='action', required=True)
    build = actions.add_parser('prepare')
    build.add_argument('--reason', required=True)
    build.add_argument('--source-sha')
    build.add_argument('--run-id', type=int)
    build.add_argument('--platform-sha256')
    actions.add_parser('access-request')
    reply = actions.add_parser('access-response')
    reply.add_argument('receipt', type=Path)
    observation = actions.add_parser('access-probe')
    observation.add_argument('--role', required=True, choices=r.ROLES)
    activate = actions.add_parser('apply')
    activate.add_argument('--operation', required=True)
    actions.add_parser('access-status', help='send or poll through the enrolled independent station')
    trust = actions.add_parser('reviewer-trust', help='pin the independently supplied stable review key')
    trust.add_argument('--fingerprint', required=True)
    args = parser.parse_args()
    from bootstrap import Blocked, Bootstrap
    from commission_host import Blocked as CommissionBlocked
    from destination_observation import MAX_ACCESS_ENVELOPE

    try:
        r.require(os.getuid() == os.geteuid() == 0, 'stable renewal requires the authorized root maintenance terminal')
        os.umask(0o077)
        confirm_kit_source(args.kit_source_sha)
        controller = r.Renewal(r.DEFAULT_ROOT, r.SiteDriver(r.DEFAULT_DRIVER), ledger_user=r.LEDGER_USER)
        if args.action == 'reviewer-trust':
            result = enroll_stable_reviewer(Bootstrap(), args.fingerprint, sys.stdin)
        elif args.action in ('prepare', 'apply'):
            with lease(controller):
                if args.action == 'prepare':
                    result = prepare(controller, args.reason, source=args.source_sha, run=args.run_id,
                                     platform=args.platform_sha256, kit_source=args.kit_source_sha)
                    result['access_review'] = poll_access(controller, kit_source=args.kit_source_sha)
                else:
                    p.token(args.operation)
                    result = apply_with_access(controller, args.operation, kit_source=args.kit_source_sha)
        elif args.action == 'access-status':
            result = poll_access(controller, kit_source=args.kit_source_sha)
        elif args.action == 'access-probe':
            pending = access(controller).request()
            grant = for_release(controller, pending['role_artifacts']['release_sha256'])
            match_kit_bundle(controller, grant, args.kit_source_sha)
            result = named_access_probe(controller, grant, pending, args.role)
        else:
            with controller.lock():
                observer = access(controller)
                pending = pending_review(observer)
                match_kit_bundle(controller, for_release(controller, pending['role_artifacts']['release_sha256']),
                                 args.kit_source_sha)
                if args.action == 'access-request':
                    from destination_observation import encoding
                    sys.stdout.buffer.write(encoding(pending))
                    return 0
                observer.receive(s.protected_bytes(args.receipt, MAX_ACCESS_ENVELOPE), pending)
                result = {'phase': 'stable-access-preapproved', 'operation': pending['candidate']['operation']}
        print(r.canonical(result))
        return 0 if result.get('phase') not in ('blocked', 'rejected', 'rolled-back') else 2
    except (Blocked, OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        detail = str(error)[:300] if isinstance(error, (ValueError, Blocked, CommissionBlocked)) else type(error).__name__
        parser.exit(2, 'stable renewal held: ' + detail + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
