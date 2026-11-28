"""Exercise the installed promotion entry in a disposable, network-isolated root."""
from contextlib import redirect_stderr, redirect_stdout
# Load standard-library extensions and their dynamic dependencies before entering the private root.
import ctypes
import fcntl
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import sysconfig
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
INSTALL = Path('/usr/libexec/dev-pair')
START = '/var/lib/dev-pair'
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
JOB = 'first-checklist'
DNS = 'erebus.example.ts.net'
ITEM = 'Observed checklist item'


def materialize_root(root):
    # Keep only the standard library, checked source copies, and the stock OpenSSH verifier.
    library = Path(sysconfig.get_path('stdlib'))
    shutil.copytree(library, root / library.relative_to('/'),
                    ignore=shutil.ignore_patterns('site-packages', 'dist-packages', '__pycache__', 'test', 'tests'))
    executables = ['/usr/bin/ssh-keygen', '/usr/bin/python3']
    extensions = [module.__file__ for name, module in sys.modules.copy().items()
                  if name in ('_ctypes', '_ssl', '_bz2', '_lzma', '_hashlib', '_sqlite3')]
    dependencies = subprocess.run(['ldd', *executables, *extensions], capture_output=True, text=True,
                                  check=True, timeout=10).stdout.splitlines()
    for value in sorted({*executables, *(word for line in dependencies for word in line.split() if word.startswith('/') and ':' not in word)}):
        source = Path(value)
        target = root / source.relative_to('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)
    (root / 'tmp').mkdir(mode=0o700)
    recipe = json.loads((REPO / 'runtime/commissioning/manifest.json').read_bytes())
    for row in recipe['files']:
        location = Path(row['target'])
        if not location.is_relative_to(INSTALL) or row['feature'] != 'base':
            continue
        target = root / location.relative_to('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / row['source'], target)
        target.chmod(int(row['mode'], 8))


def reviewed_pair(root):
    """Record two exact disposable Git revisions with changed destination verifier bytes."""
    files = {str(path.relative_to(root / INSTALL.relative_to('/'))): path.read_bytes()
             for area in ('tools', 'runtime') for path in (root / INSTALL.relative_to('/') / area).rglob('*')
             if path.is_file()}
    with tempfile.TemporaryDirectory() as location:
        source = Path(location)
        for name, raw in files.items():
            write(source / name, raw)
        git = ['/usr/bin/git', '-C', location, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid']
        subprocess.run([*git, 'init', '-q'], check=True, capture_output=True, timeout=10)
        subprocess.run([*git, 'add', '.'], check=True, capture_output=True, timeout=10)
        subprocess.run([*git, 'commit', '-qm', 'Original approved host'], check=True, capture_output=True, timeout=10)
        initial = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        name = 'tools/destination_release.py'
        observation = 'tools/destination_observation.py'
        entry = b"\nif __name__ == '__main__':\n"
        witness = entry + b"    print('Selected host launched', file=sys.stderr)\n"
        newer = {**files, name: files[name] + b'\n# Second independently selected fixture host.\n',
                 observation: files[observation].replace(entry, witness)}
        for item in (name, observation):
            write(source / item, newer[item])
        subprocess.run([*git, 'commit', '-qam', 'Renew approved host code'], check=True, capture_output=True, timeout=10)
        renewed = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        assert initial != renewed
        for revision, bundle in ((initial, files), (renewed, newer)):
            assert all(subprocess.check_output([*git, 'show', f'{revision}:{item}'], timeout=10) == bundle[item]
                       for item in ('tools/bootstrap.py', name, observation))
    return initial, files, renewed, newer


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    path.chmod(mode)
    return path


def exact_state(renewal, protocol, publication, revision, contents, *, original=False):
    bundle = {'schema': 1, 'source_revision': revision, 'state_contract': 1,
              'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()}}
    manifest = publication.canonical(bundle)
    artifact = publication.digest(manifest)
    store = INSTALL / 'host-releases' / artifact
    write(store / 'manifest.json', manifest, 0o444)
    if not (store / 'tools').exists():
        for name, raw in contents.items():
            write(store / name, raw, 0o444)
    for directory in reversed(sorted(path for path in store.rglob('*') if path.is_dir())):
        directory.chmod(0o555)
    store.chmod(0o555)
    components, files = {}, {}
    for role in protocol.ROLES:
        row = {**dict.fromkeys(('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256', 'archive_sha256'), 'b' * 64),
               'source_sha': revision, 'archive_bytes': 1}
        if role != 'devbox':
            row.update(codex_version='0.169.0', codex_source_sha='c' * 40, codex_sha256='d' * 64)
        components[protocol.COMPONENT[role]] = row
        files[role] = {'name': f'platform-{role}-{revision}', 'files': {
            'part.json': {'sha256': 'e' * 64, 'bytes': 1},
            role + '.oci.tar': {'sha256': row['archive_sha256'], 'bytes': row['archive_bytes']}}}
    components['host'] = {'source_sha': revision, 'bundle_manifest_sha256': artifact}
    files['host'] = {'name': f'platform-host-{revision}', 'files': {
        'host.tar': {'sha256': 'a' * 64, 'bytes': 1},
        'host-manifest.json': {'sha256': artifact, 'bytes': len(manifest)}}}
    index = {'schema': 2, 'kind': 'dev-pair-platform-release', 'repository': 'oso-gato/dev-pair',
             'source_sha': revision, 'publisher_run': 81, 'standards_sha': protocol.STANDARDS,
             'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1}, 'previous_platform_sha256': None,
             'base_platform_sha256': None, 'components': components, 'transports': files}
    raw = publication.canonical(index)
    platform = publication.digest(raw)
    intake = publication.canonical({'schema': 2, 'platform_sha256': platform, 'source_sha': revision,
                                   'publisher_run': 81, 'kind': index['kind']})
    write(f'{START}/platform-releases/{platform}/platform.json', raw, 0o444)
    write(f'{START}/platform-releases/{platform}/intake.json', intake)
    host = {'source_revision': revision, 'config_sha256': '9' * 64, 'artifact_sha256': artifact}
    entry = {'schema': 1, 'components': {'host': host}}
    raw = renewal.json_bytes(entry)
    site = hashlib.sha256(raw).hexdigest()
    control = Path(START) / 'renewal'
    write(control / 'site-current.json', renewal.json_bytes(site))
    write(control / 'current.json', renewal.json_bytes(site))
    write(control / 'releases' / (site + '.json'), raw)
    write(control / 'platform-bindings' / (site + '.json'), renewal.json_bytes({
        'schema': 1, 'release_sha256': site, 'base_platform_sha256': platform,
        'platform_sha256': platform, 'intake_sha256': publication.digest(intake),
        'site_config_sha256': '8' * 64, 'plan_sha256': '7' * 64}))
    write(control / 'host-selection.json', renewal.json_bytes(host))
    write(control / 'host-observed.json', renewal.json_bytes({'schema': 2, 'boot_id': BOOT, 'component': host,
          'launch_root': str(store), 'role_launch_seconds': 100, 'hostname': 'erebus', 'platform': 'fedora-44',
          'selinux': 'enforcing', 'handoff': {}}))
    write(f'{START}/renewal-fence/selected-host.json', renewal.json_bytes({'schema': 1, 'artifact_sha256': artifact}), 0o644)
    if original:
        write(f'{START}/renewal-fence/owner.lock', b'', 0o644)
        write(f'{START}/bootstrap/host-commissioning/intent.json', renewal.json_bytes({
            'schema': 1, 'source_sha': revision, 'platform_sha256': platform, 'machine_id': '1' * 32}))
    return store


def select_agent_attempt(renewal, protocol, publication, source):
    control = Path(START) / 'renewal'
    previous = renewal.read_json(control / 'site-current.json')
    binding = renewal.read_json(control / 'platform-bindings' / (previous + '.json'))
    base = binding['base_platform_sha256']
    base_index = json.loads((Path(START) / 'platform-releases' / base / 'platform.json').read_bytes())
    roles = ('maintenance', 'development')
    publication_index = {**base_index, 'kind': 'dev-pair-agent-release', 'source_sha': source, 'publisher_run': 84,
                         'previous_platform_sha256': base, 'base_platform_sha256': base,
                         'components': {protocol.COMPONENT[role]: {**base_index['components'][protocol.COMPONENT[role]],
                                                                 'source_sha': source} for role in roles},
                         'transports': {role: {**base_index['transports'][role], 'name': f'platform-{role}-{source}'}
                                        for role in roles}}
    raw = publication.canonical(publication_index)
    platform = publication.digest(raw)
    receipt = publication.canonical({'schema': 2, 'platform_sha256': platform, 'source_sha': source,
                                     'publisher_run': 84, 'kind': publication_index['kind']})
    write(f'{START}/platform-releases/{platform}/platform.json', raw, 0o444)
    write(f'{START}/platform-releases/{platform}/intake.json', receipt)
    stable = renewal.read_json(control / 'releases' / (previous + '.json'))
    raw = renewal.json_bytes({**stable, 'fixture_agent_source': source})
    selected = publication.digest(raw)
    write(control / 'releases' / (selected + '.json'), raw)
    write(control / 'platform-bindings' / (selected + '.json'), renewal.json_bytes({**binding, 'release_sha256': selected,
          'platform_sha256': platform, 'intake_sha256': publication.digest(receipt)}))
    for name in ('current', 'site-current'):
        write(control / (name + '.json'), renewal.json_bytes(selected))
    return selected


def projection(root):
    materialize_root(root)
    match, initial_code, successor, renewed_code = reviewed_pair(root)
    os.chroot(root)
    os.chdir('/')
    sys.path.insert(0, str(INSTALL / 'tools'))
    import bootstrap
    import destination_observation as station
    import destination_release as destination
    import platform_release as publication
    import platform_release_protocol as protocol
    import product_release as release
    import promotion_setup as setup
    import renewal

    assert Path(bootstrap.__file__) == INSTALL / 'tools/bootstrap.py'
    assert Path(setup.__file__) == INSTALL / 'tools/promotion_setup.py'
    assert not (INSTALL / '.git').exists()
    os.umask(0o077)
    write('/dev/null', b'', 0o666)
    write('/etc/machine-id', '1' * 32 + '\n')
    write('/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\n', 0o644)
    write('/proc/sys/kernel/random/boot_id', BOOT + '\n')
    write('/proc/sys/kernel/hostname', 'erebus\n')
    store = exact_state(renewal, protocol, publication, match, initial_code, original=True)
    Path(START).chmod(0o755)
    fixture = Path('/run/fixture')
    fixture.mkdir(mode=0o700, parents=True)
    release.EVIDENCE.mkdir(mode=0o700)
    release.SITE.mkdir(mode=0o700, parents=True)
    write(release.SITE / setup.ENROLLMENT, renewal.json_bytes({'version': 1, 'state': 'active', 'dns_name': DNS,
          'expires_unix': int(time.time()) + 120, 'trust_sha256': '1' * 64,
          'files': {str(path): '2' * 64 for path in setup.files({}, '', '', '', None)}}))
    host_identity = '6' * 64
    source = '5' * 40
    image = release.REGISTRY + '@sha256:' + host_identity
    guard = '4' * 64
    public = {'ipv4': '8.8.8.8', 'ipv6': None}
    provider = 'hostinger://fixture/recovery'
    current = {'source_sha': source, 'subject': image, 'run_id': 179, 'run_attempt': 3,
               'artifact_sha256': host_identity, 'dns_name': DNS, 'source_tree': '3' * 40, 'pull_request': 6,
               'review_head': '2' * 40, 'promotion_job_id': JOB}
    saved = {'job_id': JOB, 'phase': 'awaiting-independent-destination', 'release': current,
             'binding': {'dns_name': DNS}}
    storage = release.product.job_path(JOB)
    storage.mkdir(mode=0o700, parents=True)
    write(storage / 'promotion.json', renewal.json_bytes(saved))
    activation = {'version': 2, 'active': current, 'previous': None, 'pending': None, 'confirmed': None, 'route_pending': False}
    write(destination.ACTIVATION, renewal.json_bytes(activation))
    ready = {'platform_sha': match, 'machine_id': '1' * 32, 'uid': 2200}
    write(destination.PROVISION, renewal.json_bytes(ready))
    write(destination.CONTROL + '/ready.json', renewal.json_bytes(ready))
    write(destination.MANAGED_INTENT, renewal.json_bytes({'filesystem': 'fixture', 'reserve_inodes': 4096}))
    old_site = renewal.read_json(Path(START) / 'renewal/site-current.json')
    listener = {'version': 2, 'site': old_site, 'boot': BOOT, 'phase': 'ready', 'recovery_after': 1}
    write(destination.MANAGED_LISTENER, renewal.json_bytes(listener))

    def run(*args, input_text=None, **kw):
        if args == ('/usr/sbin/getenforce',):
            return 'Enforcing\n'
        assert args[:3] == ('/usr/bin/ssh-keygen', '-Y', 'verify')
        return subprocess.run(args, input=input_text, text=True, capture_output=True, check=True,
                              timeout=kw['timeout']).stdout

    class DestinationObservation:
        def __init__(self):
            super().__init__(run=run)

        def account(self):
            return 2200

        def mount_observation(self, path, filesystem, *, max_inodes):
            assert (path, filesystem) == (START, 'fixture') and max_inodes >= 4096

        def physical_reserve(self, reserve):
            assert reserve == 4096

        def verify_managed_executor(self, site, uid):
            assert self.runtime_selected_host(self.destination_identity()['boot_id'])[0] == site and uid == 2200

        def manager_job(self, name):
            assert name == destination.U_RECOVERY
            return False, 'success'

        def recovery_start(self):
            return 2

        def require_recovery_enabled(self):
            return

        def verify_workload_access(self):
            return {'target': {'dns_name': DNS}}

        def tailscale_state(self):
            return None, DNS

        def storage_ready(self, path, uid):
            assert (path, uid) == (destination.LIVE, 2200)

        def verify_final_guard(self):
            return {'guard_sha256': guard, 'public_addresses': public, 'provider_recovery': provider}

        def data_items(self, uid, path):
            assert uid == 2200
            return [{'id': 1, 'done': True, 'title': ITEM}]

        def health(self, uid, dns, app, inventory):
            assert app['artifact_sha256'] == host_identity and dns == DNS and len(inventory) == 64

        def serve_config(self, dns):
            return dns == DNS

    class NativeDestinationProjection(DestinationObservation, destination.Destination):
        pass

    signing_key = fixture / 'reviewer'
    generated = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(signing_key)],
                               input=b'', capture_output=True, timeout=10)
    assert generated.returncode == 0, generated.stderr.decode()
    write(bootstrap.TRUST_SIGNERS, 'dev-pair-access-review namespaces="dev-pair-destination" ' + signing_key.with_suffix('.pub').read_text())
    observed = NativeDestinationProjection()
    identity = observed.destination_identity()
    now = int(time.time())
    plan = {'kind': 'checklist-release', 'dns_name': DNS, 'provider_recovery': provider, 'public_addresses': public,
            'rollback_image': None}
    probes = [{**dict(zip(('endpoint', 'vantage', 'outcome'), values)), 'test': action, 'family': family,
               'client_id': values[1] + '-fixture', 'observed_at': now - 40, 'evidence_sha256': '1' * 64}
              for (action, family), values in station.probe_plan(plan).items()]
    proof = {'version': 1, **identity, 'source_sha': match, 'release_source': source, 'image': image,
             'dns_name': DNS, 'guard_sha256': guard, 'job_id': JOB, 'publisher_run_id': 179, 'publisher_run_attempt': 3,
             'issued_at': now - 30, 'expires_at': now + 120,
             'item_id': 1, 'item_title_sha256': hashlib.sha256(ITEM.encode()).hexdigest(), 'probes': probes}
    receipt = fixture / 'receipt.json'

    def signed(value):
        raw = station.encoding(value)
        write(receipt, raw)
        signature = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', station.FINAL_NAMESPACE, '-f', str(signing_key)],
                                   input=raw, capture_output=True, check=True, timeout=10).stdout
        write(receipt.with_suffix('.json.sig'), signature)
        return station.access_envelope(raw, signature)

    def run_import(data, expected, processor=setup, target_module=destination, boundary=NativeDestinationProjection):
        with (patch.object(target_module, 'Destination', boundary),
              patch.object(processor, 'Destination', boundary),
              patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(data))),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error):
            result = processor.main(['import-proof', JOB])
            assert result == expected, (result, error.getvalue())
            return error.getvalue()

    active_path = Path(destination.ACTIVATION)
    good = signed(proof)
    legacy = {key: value for key, value in proof.items() if key not in destination.JOB_PROOF_BINDING}
    assert 'stale or belongs to another machine/boot' in run_import(signed(legacy), 2)
    for key_name, wrong in (('job_id', 'another-checklist'), ('publisher_run_id', 180), ('publisher_run_attempt', 2)):
        value = {**proof, key_name: wrong}
        envelope = signed(value)
        try:
            observed.confirm(str(receipt), job_id=JOB)
        except bootstrap.Blocked as error:
            assert 'exact release, job or publisher attempt' in str(error), str(error)
        else:
            raise AssertionError('stale signed proof confirmed a different activation')
        denied = run_import(envelope, 2)
        assert 'exact release, job or publisher attempt' in denied, denied
    assert json.loads(active_path.read_bytes()) == activation
    assert not setup.evidence_envelope(JOB).exists()
    with patch.object(destination, 'ReleaseTrust') as publisher:
        publisher.return_value.verify.return_value = dict(current)
        try:
            observed.deploy(source, image, current['run_id'], None, job_id=JOB, run_attempt=2)
        except bootstrap.Blocked as error:
            assert 'checked job or publisher attempt' in str(error), str(error)
        else:
            raise AssertionError('stale publisher attempt authorized a deployment')

    actual_d = INSTALL / 'tools/destination_release.py'
    original = actual_d.read_bytes()
    try:
        write(actual_d, original + b'\n# altered installed control file\n', 0o644)
        assert 'differs from the selected signed host bundle' in run_import(good, 2)
    finally:
        write(actual_d, original, 0o644)
    assert not setup.evidence_envelope(JOB).exists()
    print('Installed source rejected changed fixed verifier bytes against the selected immutable host bundle.')

    assert not run_import(good, 0)
    target = setup.evidence_envelope(JOB)
    first = target.stat().st_ino
    assert not run_import(good, 0) and target.stat().st_ino == first
    modified = {**current, 'run_attempt': 4}
    write(active_path, renewal.json_bytes({**activation, 'active': modified}))
    write(storage / 'promotion.json', renewal.json_bytes({**saved, 'release': modified}))
    assert 'exact release, job or publisher attempt' in run_import(good, 2)
    assert target.stat().st_ino == first
    write(active_path, renewal.json_bytes(activation))
    write(storage / 'promotion.json', renewal.json_bytes(saved))
    print('Real OpenSSH signatures reject different jobs, publisher runs and attempts at import and confirmation. Replay rechecks a changed attempt.')

    live = object.__new__(release.Live)
    live.job = JOB
    live.destination = observed
    live.confirm(target)
    d_state = json.loads(active_path.read_bytes())
    assert d_state['confirmed'] == host_identity and d_state['active']['promotion_job_id'] == JOB
    observed_digest = d_state['active']['destination_receipt_sha256']
    assert observed_digest == hashlib.sha256(station.encoding(proof)).hexdigest()
    write(storage / 'promotion.json', renewal.json_bytes({**saved, 'phase': 'confirmed', 'destination_receipt_sha256': observed_digest}))
    assert not run_import(good, 0) and target.stat().st_ino == first
    assert 'not awaiting independent destination checks' in run_import(signed({**proof, 'publisher_run_attempt': 4}), 2)
    print('Installed import and ordinary Live.confirm share the selected immutable verifier, with receipt replay after settled confirmation.')

    standalone = {key: value for key, value in current.items() if key != 'promotion_job_id'}
    write(active_path, renewal.json_bytes({**activation, 'active': standalone}))
    signed(legacy)
    assert observed.confirm(str(receipt))['confirmed'] is True
    assert 'promotion_job_id' not in json.loads(active_path.read_bytes())['active']
    assert not (INSTALL / '.git').exists() and (store / 'manifest.json').exists()
    print('Separately scoped standalone confirmation retains its legacy signed receipt contract.')

    control = Path(START) / 'renewal'
    fence = Path(START) / 'renewal-fence/owner.lock'
    selection = [control / f'{name}.json' for name in ('current', 'site-current', 'host-selection', 'host-observed')]
    selection.append(fence.with_name('selected-host.json'))
    before = {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in selection}
    historical = {Path(path): Path(path).read_bytes() for path in (destination.PROVISION, destination.CONTROL + '/ready.json')}
    write(active_path, renewal.json_bytes(activation))
    write(storage / 'promotion.json', renewal.json_bytes(saved))
    assert not run_import(good, 0)
    changed = exact_state(renewal, protocol, publication, successor, renewed_code)
    assert changed != store and (changed / 'tools/destination_release.py').read_bytes() != original

    class SelectedCommand(Exception):
        pass

    with patch.object(os, 'execve', side_effect=SelectedCommand) as shell:
        try:
            setup.main(['import-proof', JOB])
        except SelectedCommand:
            pass
        else:
            raise AssertionError('fixed ingress failed to launch signed changed host code')
        assert shell.call_args.args[0] == '/usr/bin/python3'
        assert shell.call_args.args[1] == ['/usr/bin/python3', '-EBs', str(changed / 'tools/promotion_setup.py'), 'import-proof', JOB]
    launched = subprocess.run(['/usr/bin/python3', '-EBs', str(INSTALL / 'tools/destination_observation.py'), 'export-release', JOB],
                              capture_output=True, text=True, timeout=15)
    assert 'Selected host launched' in launched.stderr, launched.stderr
    print('The fixed export command executed changed code from the selected immutable bundle.')

    original_modules = {key: module for key, module in sys.modules.copy().items()
                        if str(getattr(module, '__file__', '')).startswith(str(INSTALL) + '/')}
    for key in original_modules:
        del sys.modules[key]
    sys.path.insert(0, str(changed / 'tools'))
    try:
        chosen_d = importlib.import_module('destination_release')
        chosen_station = importlib.import_module('destination_observation')
        chosen_setup = importlib.import_module('promotion_setup')
        chosen_release = importlib.import_module('product_release')
        chosen_bootstrap = importlib.import_module('bootstrap')
        assert Path(chosen_d.__file__) == changed / 'tools/destination_release.py'

        class SelectedDestination(DestinationObservation, chosen_d.Destination):
            pass

        chosen = SelectedDestination()

        def export_current():
            with patch.object(chosen_d, 'Destination', SelectedDestination):
                return chosen_station.export_release(JOB)

        def imported(data, expected):
            return run_import(data, expected, chosen_setup, chosen_d, SelectedDestination)

        def denied(action, expectation):
            try:
                action()
            except (chosen_bootstrap.Blocked, ValueError) as error:
                assert expectation in str(error), str(error)
            else:
                raise AssertionError('outdated or unsettled authority was accepted')

        assert export_current()['source_sha'] == successor
        assert 'differs from the selected host release' in imported(good, 2)
        selected_live = object.__new__(chosen_release.Live)
        selected_live.job, selected_live.destination = JOB, chosen
        try:
            selected_live.evidence()
        except chosen_release.Wait as error:
            assert error.reason == 'signed-destination-evidence-displaced'
        else:
            raise AssertionError('previous host proof remained eligible after renewal')

        with fence.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            denied(export_current, 'frozen by renewal')
        transition = control / 'transition.json'
        write(transition, renewal.json_bytes('fixture-renewal'))
        write(control / 'attempts/fixture-renewal/journal.json', renewal.json_bytes({'phase': 'rolling-back'}))
        denied(export_current, 'frozen by renewal')
        transition.unlink()
        write(destination.MANAGED_LISTENER, renewal.json_bytes({**listener, 'phase': 'observe'}))
        denied(export_current, 'completed managed listener')
        write(destination.MANAGED_LISTENER, renewal.json_bytes(listener))
        write(control / 'current.json', renewal.json_bytes(old_site))
        denied(export_current, 'frozen by renewal')
        write(control / 'current.json', (control / 'site-current.json').read_bytes())

        reboot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        host_observation = control / 'host-observed.json'
        write('/proc/sys/kernel/random/boot_id', reboot + '\n')
        denied(export_current, 'site or boot observation')
        write(host_observation, renewal.json_bytes({**json.loads(host_observation.read_bytes()), 'boot_id': reboot}))
        renewed = {**proof, 'source_sha': successor, 'boot_id': reboot}
        assert export_current()['boot_id'] == reboot
        assert not imported(signed(renewed), 0)
        selected_live.confirm(chosen_setup.evidence_envelope(JOB))
        assert chosen.initial_activation()['active']['promotion_job_id'] == JOB
        assert all(path.read_bytes() == original for path, original in historical.items())

        write(active_path, renewal.json_bytes(activation))
        rejected = {key: value for key, value in renewed.items()
                    if key not in {'item_id', 'item_title_sha256', 'probes'}}
        rejected.update(failed_check='authorized-browser', observation_sha256='7' * 64)
        signed({**rejected, 'publisher_run_attempt': 2})
        denied(lambda: chosen.reject(str(receipt)), 'does not bind this first release')
        signed(rejected)
        with (patch.object(chosen, 'data_snapshot', return_value='8' * 64),
              patch.object(chosen, 'quarantine', return_value={'quarantined': True})):
            assert chosen.reject(str(receipt))['quarantined'] is True
        assert chosen.initial_activation()['pending']['operation'] == 'reject'
        print(f'Current selected host {successor} accepted signed release and failure evidence after renewal; retained provision {match}.')
    finally:
        sys.path.pop(0)
        for key, module in list(sys.modules.items()):
            if str(getattr(module, '__file__', '')).startswith(str(changed) + '/'):
                del sys.modules[key]
        sys.modules.update(original_modules)

    write(active_path, renewal.json_bytes(activation))
    for path, (raw, mode) in before.items():
        write(path, raw, mode)
    write(control / 'host-observed.json', renewal.json_bytes({**json.loads(before[control / 'host-observed.json'][0]), 'boot_id': reboot}))
    with patch.object(destination, 'Destination', NativeDestinationProjection):
        assert station.export_release(JOB)['source_sha'] == match
    assert 'differs from the selected host release' in run_import(signed(renewed), 2)
    assert not run_import(signed({**proof, 'boot_id': reboot}), 0)
    live.confirm(setup.evidence_envelope(JOB))
    assert all(path.read_bytes() == original for path, original in historical.items())
    print('Current boot rollback selected the original signed source without rewriting provisioning history.')
    agent_site = select_agent_attempt(renewal, protocol, publication, successor)
    assert agent_site != old_site
    with patch.object(destination, 'Destination', NativeDestinationProjection):
        assert station.export_release(JOB)['source_sha'] == match
    assert live.evidence() == setup.evidence_envelope(JOB)
    print('An independently selected agent-only index retained the steady checklist proof source on the same boot.')


class InstalledPromotionProof(unittest.TestCase):
    def test_fixed_installed_entry_without_git_and_job_publication_binding(self):
        program = Path('/usr/bin/python3')
        unshare = shutil.which('unshare')
        if not unshare or not program.is_file() or not all(shutil.which(name) for name in ('ssh-keygen', 'ldd', 'git')):
            self.skipTest('private Linux user/network namespace, stock Python or OpenSSH unavailable')
        with tempfile.TemporaryDirectory() as location:
            result = subprocess.run([unshare, '--user', '--map-root-user', '--net', '--', str(program), '-B',
                                     str(Path(__file__).resolve()), '--projection', location], capture_output=True,
                                    text=True, timeout=60, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})
        if result.returncode and re.fullmatch(r'unshare: .*Operation not permitted\n', result.stderr):
            self.skipTest('private Linux user/network namespaces unavailable')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Separately scoped standalone confirmation', result.stdout)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--projection']:
        projection(Path(sys.argv[2]))
    else:
        unittest.main()
