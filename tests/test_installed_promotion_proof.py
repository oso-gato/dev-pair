"""Exercise the installed promotion entry in a disposable, network-isolated root."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
# Load standard-library extensions and their dynamic dependencies before entering the private root.
import ctypes
import hashlib
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
MATCH = 'a' * 40
JOB = 'first-checklist'
DNS = 'erebus.example.ts.net'
ITEM = 'Observed checklist item'


def materialize_root(root):
    # Keep only the standard library, checked source copies, and the stock OpenSSH verifier.
    library = Path(sysconfig.get_path('stdlib'))
    shutil.copytree(library, root / library.relative_to('/'),
                    ignore=shutil.ignore_patterns('site-packages', 'dist-packages', '__pycache__', 'test', 'tests'))
    dependencies = subprocess.run(['ldd', '/usr/bin/ssh-keygen'], capture_output=True, text=True,
                                  check=True, timeout=10).stdout.splitlines()
    for value in ('/usr/bin/ssh-keygen', *(word for line in dependencies for word in line.split() if word.startswith('/'))):
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


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    path.chmod(mode)
    return path


def exact_state(renewal, protocol, publication):
    bundle = {'schema': 1, 'source_revision': MATCH, 'state_contract': 1, 'files': {}}
    for module in sorted((INSTALL / 'tools').iterdir()):
        bundle['files']['tools/' + module.name] = hashlib.sha256(module.read_bytes()).hexdigest()
    manifest = publication.canonical(bundle)
    artifact = publication.digest(manifest)
    store = INSTALL / 'host-releases' / artifact
    write(store / 'manifest.json', manifest, 0o444)
    for name in bundle['files']:
        write(store / name, (INSTALL / name).read_bytes(), 0o444)
    (store / 'tools').chmod(0o555)
    store.chmod(0o555)
    components, files = {}, {}
    for role in protocol.ROLES:
        row = {**dict.fromkeys(('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256', 'archive_sha256'), 'b' * 64),
               'source_sha': MATCH, 'archive_bytes': 1}
        if role != 'devbox':
            row.update(codex_version='0.169.0', codex_source_sha='c' * 40, codex_sha256='d' * 64)
        components[protocol.COMPONENT[role]] = row
        files[role] = {'name': f'platform-{role}-{MATCH}', 'files': {
            'part.json': {'sha256': 'e' * 64, 'bytes': 1},
            role + '.oci.tar': {'sha256': row['archive_sha256'], 'bytes': row['archive_bytes']}}}
    components['host'] = {'source_sha': MATCH, 'bundle_manifest_sha256': artifact}
    files['host'] = {'name': f'platform-host-{MATCH}', 'files': {
        'host.tar': {'sha256': 'a' * 64, 'bytes': 1},
        'host-manifest.json': {'sha256': artifact, 'bytes': len(manifest)}}}
    index = {'schema': 2, 'kind': 'dev-pair-platform-release', 'repository': 'oso-gato/dev-pair',
             'source_sha': MATCH, 'publisher_run': 81, 'standards_sha': protocol.STANDARDS,
             'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1}, 'previous_platform_sha256': None,
             'base_platform_sha256': None, 'components': components, 'transports': files}
    raw = publication.canonical(index)
    platform = publication.digest(raw)
    intake = publication.canonical({'schema': 2, 'platform_sha256': platform, 'source_sha': MATCH,
                                   'publisher_run': 81, 'kind': index['kind']})
    write(f'{START}/platform-releases/{platform}/platform.json', raw, 0o444)
    write(f'{START}/platform-releases/{platform}/intake.json', intake)
    host = {'source_revision': MATCH, 'config_sha256': '9' * 64, 'artifact_sha256': artifact}
    entry = {'schema': 1, 'components': {'host': host}}
    raw = renewal.json_bytes(entry)
    site = hashlib.sha256(raw).hexdigest()
    control = Path(START) / 'renewal'
    write(control / 'site-current.json', renewal.json_bytes(site))
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
    return store


def projection(root):
    materialize_root(root)
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
    store = exact_state(renewal, protocol, publication)
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

    def run(*args, input_text=None, **kw):
        assert args[:3] == ('/usr/bin/ssh-keygen', '-Y', 'verify')
        return subprocess.run(args, input=input_text, text=True, capture_output=True, check=True,
                              timeout=kw['timeout']).stdout

    class NativeDestinationProjection(destination.Destination):
        def __init__(self):
            super().__init__(run=run)

        @contextmanager
        def release_gate(self, *, require_cutover=True):
            assert require_cutover
            yield {'platform_sha': MATCH}, 2200, DNS

        def verify_final_guard(self):
            return {'guard_sha256': guard, 'public_addresses': public, 'provider_recovery': provider}

        def data_items(self, uid, path):
            assert uid == 2200
            return [{'id': 1, 'done': True, 'title': ITEM}]

        def health(self, uid, dns, app, inventory):
            assert app['artifact_sha256'] == host_identity and dns == DNS and len(inventory) == 64

        def serve_config(self, dns):
            return dns == DNS

    key = fixture / 'reviewer'
    generated = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(key)],
                               input=b'', capture_output=True, timeout=10)
    assert generated.returncode == 0, generated.stderr.decode()
    write(bootstrap.TRUST_SIGNERS, 'dev-pair-access-review namespaces="dev-pair-destination" ' + key.with_suffix('.pub').read_text())
    observed = NativeDestinationProjection()
    identity = observed.destination_identity()
    now = int(time.time())
    plan = {'kind': 'checklist-release', 'dns_name': DNS, 'provider_recovery': provider, 'public_addresses': public,
            'rollback_image': None}
    probes = [{**dict(zip(('endpoint', 'vantage', 'outcome'), values)), 'test': action, 'family': family,
               'client_id': values[1] + '-fixture', 'observed_at': now - 40, 'evidence_sha256': '1' * 64}
              for (action, family), values in station.probe_plan(plan).items()]
    proof = {'version': 1, **identity, 'source_sha': MATCH, 'release_source': source, 'image': image,
             'dns_name': DNS, 'guard_sha256': guard, 'job_id': JOB, 'publisher_run_id': 179, 'publisher_run_attempt': 3,
             'issued_at': now - 30, 'expires_at': now + 120,
             'item_id': 1, 'item_title_sha256': hashlib.sha256(ITEM.encode()).hexdigest(), 'probes': probes}
    receipt = fixture / 'receipt.json'

    def signed(value):
        raw = station.encoding(value)
        write(receipt, raw)
        signature = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', station.FINAL_NAMESPACE, '-f', str(key)],
                                   input=raw, capture_output=True, check=True, timeout=10).stdout
        write(receipt.with_suffix('.json.sig'), signature)
        return station.access_envelope(raw, signature)

    def run_import(data, expected):
        with (patch.object(destination, 'Destination', NativeDestinationProjection),
              patch.object(setup, 'Destination', NativeDestinationProjection),
              patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(data))),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error):
            result = setup.main(['import-proof', JOB])
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


class InstalledPromotionProof(unittest.TestCase):
    def test_fixed_installed_entry_without_git_and_job_publication_binding(self):
        program = Path('/usr/bin/python3')
        unshare = shutil.which('unshare')
        if not unshare or not program.is_file() or not shutil.which('ssh-keygen') or not shutil.which('ldd'):
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
