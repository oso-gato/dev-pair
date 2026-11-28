"""Apply the bounded, signed fixed provider boundary during a stable host renewal."""
import os
from pathlib import Path
import time
from itertools import islice

import job_protocol as p
import platform_release_install as installer
import provider_billing as billing
import provider_transition as transition
import renewal as r
from ledger_recovery import sync_directory

INSTALL = '/usr/libexec/dev-pair'
MANIFEST = 'runtime/commissioning/manifest.json'
TEMPORARY = transition.TEMPLATE + '.d/90-dev-pair-fixed-migration.conf'
CLOSED = '/usr/bin/false'
TEMP_BYTES = b'[Service]\nExecCondition=\nExecCondition=/usr/bin/false\n'
CONTEXT = ('operation machine_id previous_release_sha256 previous_base_platform_sha256 previous_base_intake_sha256 '
           'target_release_sha256 platform_sha256 intake_sha256 site_config_sha256')
MAX_MIGRATIONS = 32
MAX_FILE = 256 * 1024
COURIER = f'{INSTALL}/tools/billing_courier.py'
# These entrypoints form the fixed billing launch and recovery chain. The full
# release may change other files, but those changes need their own activation.
CHAIN = {
    transition.TEMPLATE: ('runtime/renewal/dev-pair-provider@.service', 0o644),
    transition.DROP_IN: ('runtime/renewal/provider-start-fence.conf', 0o644),
    COURIER: ('tools/billing_courier.py', 0o755),
    f'{INSTALL}/tools/day0_access_exchange.py': ('tools/day0_access_exchange.py', 0o755),
    **{f'{INSTALL}/renewal/{name}': (f'runtime/renewal/{name}', 0o755)
       for name in ('provider-run', 'driver', 'host-release')},
    **{f'{INSTALL}/tools/{name}.py': (f'tools/{name}.py', 0o755 if name == 'owner_intake' else 0o644)
       for name in ('provider_billing', 'provider_broker', 'provider_transition', 'host_fixed_migration',
                    'commission_host', 'owner_intake', 'owner_source', 'renewal', 'renewal_site', 'stable_renewal',
                    'bootstrap', 'destination_observation', 'destination_release', 'managed_backing', 'devbox',
                    'platform_release_install', 'platform_release_intake')},
}
# Old bundles may contain a source without having installed a fixed copy.
# Its absence must agree with both the signed inventory and the live path.
OLD_OPTIONAL = {transition.DROP_IN, COURIER, *(
    f'{INSTALL}/tools/{name}.py' for name in ('provider_transition', 'host_fixed_migration', 'provider_billing',
        'stable_renewal', 'owner_source', 'day0_access_exchange', 'destination_observation', 'managed_backing'))}


def fixed_inputs(directory, host, *, previous=False):
    """Read the bounded install map only from the verified immutable host bundle."""
    installer.check_host_bundle(directory, host, time.monotonic() + 25)
    manifest = billing.bounded_file(billing.protected(directory / 'manifest.json'), 1 << 20, owner=0)
    p.require(p.sha256(manifest) == host['bundle_manifest_sha256'], 'Signed fixed-file bundle manifest changed.')
    files = r.loads(manifest)['files']

    def verified(source, limit):
        path = billing.protected(directory / source)
        info = path.lstat()
        p.require(not info.st_mode & 0o222, 'Fixed host migration requires immutable release files.')
        raw = billing.bounded_file(path, limit, owner=0)
        p.require(p.sha256(raw) == files[source], 'An authenticated fixed-file source changed.')
        return raw

    package = p.loads(verified(MANIFEST, 65536))
    p.fields(package, 'schema files')
    p.number(package['schema'], 1, 1)
    p.require(type(package['files']) is list and 0 < len(package['files']) <= 128, 'Invalid signed fixed-file inventory.')
    observed = {}
    for row in package['files']:
        p.fields(row, 'source target mode feature')
        target = row['target']
        if target not in CHAIN:
            continue
        source, mode = CHAIN[target]
        p.require(target not in observed and row == {
            'source': source, 'target': target, 'mode': f'{mode:04o}', 'feature': 'base'},
            'The signed release changes a fixed activation path, permission or feature.')
        observed[target] = verified(source, MAX_FILE)
    missing = set(CHAIN) - observed.keys()
    p.require(missing <= (OLD_OPTIONAL if previous else {COURIER}),
              'The signed host release is missing a required fixed billing path.')
    return {target: observed.get(target) for target in CHAIN}


def exact_path(path, mode):
    if not os.path.lexists(path):
        return None
    return billing.bounded_file(billing.protected(path), MAX_FILE, owner=0, mode=mode)


class Migration:
    def __init__(self, app, authority, predecessor, successor):
        self.app = app
        self.fence = transition.Fence(app.root, app.run)
        self.old, self.new = predecessor, successor
        self.changed = predecessor != successor
        p.fields(authority, CONTEXT)
        for key, value in authority.items():
            if key == 'operation':
                p.token(value)
            else:
                p.digest(value, 32 if key == 'machine_id' else 64)
        p.require(authority['previous_release_sha256'] != authority['target_release_sha256'] and
                  authority['previous_base_platform_sha256'] != authority['platform_sha256'],
                  'A fixed migration needs a distinct signed full predecessor and successor.')
        p.require(set(predecessor) == set(successor) == set(CHAIN) and
                  all(type(value) is bytes and 0 < len(value) <= MAX_FILE or
                      path == COURIER and value is None
                      for path, value in successor.items()) and
                  predecessor[transition.TEMPLATE] == successor[transition.TEMPLATE] and
                  successor[transition.DROP_IN] == ('[Service]\nExecCondition=' + transition.CONDITION + '\n').encode(),
                  'The reviewed package differs from the supported provider service and fence.')
        p.require(successor[COURIER] is not None or
                  (predecessor[COURIER] is None and
                   b'from billing_courier import ' not in successor[f'{INSTALL}/tools/owner_intake.py']),
                  'The signed host package would remove or omit the billing courier required by owner setup.')
        if predecessor[transition.DROP_IN] is not None:
            p.require(predecessor[transition.DROP_IN] == successor[transition.DROP_IN],
                      'The predecessor uses an unrecognized provider fence.')
        self.intent = {'schema': 1, **authority, 'files': {
            target: [p.sha256(predecessor[target]) if predecessor[target] is not None else None,
                     p.sha256(successor[target]) if successor[target] is not None else None] for target in CHAIN}}
        self.pending = self.fence.state / transition.FIXED_PENDING
        self.blocked = self.fence.state / transition.FIXED_BLOCKED
        self.evidence = self.fence.state / ('fixed-' + authority['target_release_sha256'] + '.json')

    def record(self, path):
        if not os.path.lexists(path):
            return None
        value = p.loads(self.fence.read(path, 65536))
        p.fields(value, 'intent phase installed')
        p.require(value['intent'] == self.intent and value['phase'] in ('prepared', 'closed', 'drained', 'installed', 'complete') and
                  type(value['installed']) is list and set(value['installed']) <= set(CHAIN) and
                  value['installed'] == sorted(set(value['installed'])),
                  'An existing fixed migration belongs to another exact operation or changed.')
        return value

    def save(self, path, phase, leaves):
        billing.replace_record(path, {'intent': self.intent, 'phase': phase, 'installed': sorted(leaves)})

    def files(self, *, initial=False, final=False):
        seen = set()
        for target, (_, mode) in CHAIN.items():
            actual = exact_path(self.fence.path(target), mode)
            allowed = (self.old[target],) if initial else (self.new[target],) if final else (self.old[target], self.new[target])
            p.require(actual in allowed, 'Protected fixed bytes differ from the signed migration at ' + target)
            if actual == self.new[target]:
                seen.add(target)
        return seen

    def close(self):
        self.fence.hold()
        drop = self.fence.path(TEMPORARY)
        p.require(exact_path(drop, 0o644) in (None, TEMP_BYTES), 'A foreign temporary provider guard is present.')
        self.app.atomic(TEMPORARY, TEMP_BYTES.decode(), mode=0o644)
        p.require(exact_path(drop, 0o644) == TEMP_BYTES, 'The exact temporary provider guard could not be installed.')
        self.app.run('/usr/sbin/restorecon', '-F', TEMPORARY, timeout=10)
        self.fence.manager('daemon-reload', timeout=20)

    def idle(self, end, *, temporary):
        if temporary:
            drops = ((transition.DROP_IN,) if os.path.lexists(self.fence.path(transition.DROP_IN)) else ()) + (TEMPORARY,)
            condition = CLOSED
        else:
            drops, condition = (transition.DROP_IN,), transition.CONDITION
        remaining = max(0, end - time.monotonic())
        p.require(remaining > 0, 'Fixed provider migration reached its bounded idle deadline.')
        return self.fence.idle(end, drops=drops, condition=condition)

    def prepare(self, *, end):
        self.fence.mkdir()
        with billing.lock(self.fence.state):
            self.fence.deadline = end
            p.require(self.fence.intent() is None, 'Finish the attended provider custody operation before fixed migration.')
            if os.path.lexists(self.blocked):
                p.require(p.loads(self.fence.read(self.blocked, 4096)) == {'operation': self.intent['operation'],
                          'target_release_sha256': self.intent['target_release_sha256']},
                          'A different held provider migration requires protected recovery.')
            if not self.changed:
                self.files(initial=True)
                return
            completed = self.record(self.evidence)
            if completed is not None:
                p.require(completed['phase'] == 'complete' and set(completed['installed']) == set(CHAIN),
                          'Fixed provider migration completion evidence is incomplete.')
                self.files(final=True)
                return
            saved = self.record(self.pending)
            if saved is None:
                self.files(initial=True)
                p.require(not os.path.lexists(self.fence.path(TEMPORARY)), 'An unowned temporary provider guard is present.')
                with os.scandir(self.fence.state) as entries:
                    members = list(islice(entries, 1025))
                    p.require(len(members) <= 1024 and sum(item.name.startswith('fixed-') for item in members) < MAX_MIGRATIONS,
                              'The fixed provider migration history reached its retention bound.')
                self.save(self.pending, 'prepared', ())
            leaves = self.files()
            if saved is not None and saved['phase'] == 'installed' and len(leaves) == len(CHAIN):
                p.require(self.idle(end, temporary=False), 'Current provider activation still has unsettled unit state.')
                return
            self.close()
            self.save(self.pending, 'closed', leaves)
            while not self.idle(end, temporary=True):
                time.sleep(min(0.25, max(0, end - time.monotonic())))
            self.save(self.pending, 'drained', leaves)
            for target in CHAIN:
                if target not in leaves:
                    _, mode = CHAIN[target]
                    p.require(exact_path(self.fence.path(target), mode) == self.old[target],
                              'Fixed predecessor file changed before replacement.')
                    expected = self.old[target].decode() if self.old[target] is not None else None
                    self.app.atomic(target, self.new[target].decode(), mode=mode, expected=expected)
                    p.require(exact_path(self.fence.path(target), mode) == self.new[target],
                              'The fixed successor file changed after publication.')
                    leaves.add(target)
                    self.save(self.pending, 'drained', leaves)
            self.files(final=True)
            installed = [target for target in CHAIN if self.new[target] is not None]
            self.app.run('/usr/sbin/restorecon', '-F', *installed, timeout=20)
            self.fence.manager('daemon-reload', timeout=20)
            p.require(self.idle(end, temporary=True), 'The temporary provider fence could not be confirmed after file migration.')
            drop = self.fence.path(TEMPORARY)
            p.require(exact_path(drop, 0o644) == TEMP_BYTES, 'The temporary provider guard changed.')
            drop.unlink()
            sync_directory(drop.parent)
            self.fence.manager('daemon-reload', timeout=20)
            p.require(self.idle(end, temporary=False), 'The permanent provider fence could not be confirmed.')
            self.save(self.pending, 'installed', leaves)

    def finish(self, *, end):
        if not self.changed:
            return
        self.fence.deadline = end
        with billing.lock(self.fence.state):
            saved = self.record(self.pending)
            completed = self.record(self.evidence)
            self.files(final=True)
            p.require(saved is not None or completed is not None, 'Fixed provider migration has no protected activation record.')
            if completed is not None:
                p.require(completed['phase'] == 'complete' and set(completed['installed']) == set(CHAIN),
                          'Fixed provider migration completion evidence is incomplete.')
            else:
                p.require(saved['phase'] == 'installed' and self.idle(end, temporary=False),
                          'The exact installed provider closure lacks final idle readback.')
                self.save(self.evidence, 'complete', CHAIN)
            if saved is not None:
                self.pending.unlink()
                sync_directory(self.pending.parent)
            if os.path.lexists(self.blocked):
                p.require(p.loads(self.fence.read(self.blocked, 4096)) == {'operation': self.intent['operation'],
                          'target_release_sha256': self.intent['target_release_sha256']},
                          'Another fixed provider rollback hold is present.')
                self.blocked.unlink()
                sync_directory(self.blocked.parent)
        self.fence.converge()


def authorized(app, controller, authority):
    from commission_host import AUTOMATIC_POLICY, Commission, Live, read_policy

    policy_raw = exact_path(app.path(AUTOMATIC_POLICY), 0o600)
    p.require(policy_raw is not None, 'Protected initial commissioning must precede a stable migration.')
    policy = read_policy(policy_raw, p.loads(policy_raw)['source_sha'])
    p.require(authority['machine_id'] == policy['machine_id'] == app.destination_identity()['machine_id'] and
              authority['site_config_sha256'] == policy['site_config_sha256'],
              'The fixed provider migration differs from the protected original machine or site.')
    # The protected site file and initial signed base stay in their original
    # locations. Only the stable-scoped successor's host files are activated.
    fact = Commission(Path(INSTALL), app.root, app.run, 0, Live(Path(INSTALL), app))
    fact.require_first_site(policy['machine_id'], policy['site_config_sha256'])
    prior_id, new_id = authority['previous_base_platform_sha256'], authority['platform_sha256']
    _, prior, prior_sha = installer.intake.retained_index(prior_id)
    _, new, new_sha = installer.intake.retained_index(new_id)
    p.require(all(row['schema'] == 2 and row['kind'] == 'dev-pair-platform-release' and
                  row['base_platform_sha256'] is None for row in (prior, new)) and
              new['previous_platform_sha256'] == prior_id and
              (prior_sha, new_sha) == (authority['previous_base_intake_sha256'], authority['intake_sha256']),
              'Fixed provider migration requires exact protected signed full releases in predecessor order.')
    old_release = controller.release(authority['previous_release_sha256'])
    incoming = controller.release(authority['target_release_sha256'])
    sites = installer.SITE_CONFIGS / (authority['site_config_sha256'] + '.json')
    site = installer.site_configuration(sites, authority['site_config_sha256'])
    pairs = []
    for index, release in ((prior, old_release), (new, incoming)):
        row = index['components']['host']
        host = release['components']['host']
        p.require(host == {'source_revision': row['source_sha'], 'artifact_sha256': row['bundle_manifest_sha256'],
                           'config_sha256': site['host_config_sha256']},
                  'The fixed activation host differs from its signed full index or original site configuration.')
        directory = installer.HOST_RELEASES / row['bundle_manifest_sha256']
        pairs.append(fixed_inputs(directory, row, previous=index is prior))
    return Migration(app, {key: authority[key] for key in CONTEXT.split()}, *pairs)


def forward_started(controller, request):
    """Tell the existing stable recovery loop whether exact forward work exists."""
    p.require(request['scope'] == 'stable', 'Fixed provider recovery needs the stable renewal scope.')
    operation = request['operation']
    previous, target = (request[key] for key in ('previous_sha256', 'target_sha256'))
    p.token(operation)
    p.digest(previous)
    p.digest(target)
    root = controller.root / Path(transition.STATE).name
    pending, complete = root / transition.FIXED_PENDING, root / ('fixed-' + target + '.json')
    records = []
    for path in (pending, complete):
        if not os.path.lexists(path):
            continue
        row = p.loads(transition.Fence.read(path, 65536))
        p.fields(row, 'intent phase installed')
        intent = row['intent']
        p.fields(intent, 'schema files ' + CONTEXT)
        p.number(intent['schema'], 1, 1)
        p.require((intent['operation'], intent['previous_release_sha256'], intent['target_release_sha256']) ==
                  (operation, previous, target) and
                  (row['phase'] == 'complete' if path == complete else
                   row['phase'] in ('prepared', 'closed', 'drained', 'installed')) and type(row['installed']) is list and
                  all(type(leaf) is str and leaf in CHAIN for leaf in row['installed']) and row['installed'] == sorted(set(row['installed'])) and
                  (row['phase'] not in ('installed', 'complete') or set(row['installed']) == set(CHAIN)),
                  'A fixed provider recovery record names a different stable transition or invalid phase.')
        p.require(type(intent['files']) is dict and intent['files'].keys() == CHAIN.keys(),
                  'Fixed provider recovery file scope changed.')
        for path, pair in intent['files'].items():
            p.require(type(pair) is list and len(pair) == 2, 'Invalid fixed provider recovery identities.')
            if pair[0] is not None:
                p.digest(pair[0])
            if path != COURIER or pair != [None, None]:
                p.digest(pair[1])
        records.append(intent)
    p.require(len(records) < 2 or records[0] == records[1], 'Fixed provider recovery records disagree.')
    return bool(records)


def refuse_incompatible_rollback(app, authority):
    fence = transition.Fence(app.root, app.run)
    candidate = authority['target_release_sha256']
    p.digest(candidate)
    if any(os.path.lexists(path) for path in (fence.state / transition.FIXED_PENDING,
                                              fence.state / ('fixed-' + candidate + '.json'))):
        # A fixed-code transition never restores old paid behavior. Retain
        # both approvals and the exact installed bytes for forward recovery.
        with billing.lock(fence.state):
            blocked = fence.state / transition.FIXED_BLOCKED
            identity = {'operation': authority['operation'], 'target_release_sha256': candidate}
            if os.path.lexists(blocked):
                p.require(p.loads(fence.read(blocked, 4096)) == identity, 'A different fixed provider rollback hold is present.')
            else:
                billing.replace_record(blocked, identity)
            fence.hold()
        raise ValueError('The predecessor is incompatible with the protected fixed billing migration. Provider starts remain held.')
