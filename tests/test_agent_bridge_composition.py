"""Combine normal publisher, transport, discovery and approval with local boundary fixtures."""
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
import zipfile

import test_renewal_portable as local
import test_agent_release_bridge as scheduled
import agent_release_bridge as bridge
import bootstrap as host_bootstrap
import day0_access_exchange as access_exchange
import destination_observation as observation
import platform_release as publish
import platform_release_intake as intake
import platform_release_install as installer
import native_placement_release as placement
import native_placements as native_host
import gptbox as roles
import test_native_placement_release as native_fixture
import platform_release_protocol as protocol
import renewal as renewal
import renewal_site as site


class RootNode:
    st_uid = 0

    def __init__(self, node):
        self.node = node

    def __getattr__(self, key):
        return getattr(self.node, key)


class RootPath(type(Path())):
    def lstat(self):
        return RootNode(super().lstat())


class FixtureOwner:
    """Project the local test UID into the production root-only call sites."""
    def __init__(self, effective_uid=0):
        self.effective_uid = effective_uid

    def __getattr__(self, name):
        return getattr(os, name)

    def getuid(self):
        return 0

    def geteuid(self):
        return self.effective_uid

    def uname(self):
        return SimpleNamespace(nodename='erebus', machine='x86_64')

    def fstat(self, fd):
        return RootNode(os.fstat(fd))


class ObservationFixture:
    """Actual site selectors, narrowed trust, queue and signatures with local kernel/provider projections."""
    def __init__(self, case, destination):
        self.case, self.destination = case, destination
        self.root = destination.root
        self.mailbox = self.root / 'station-mailbox'
        self.mailbox.mkdir(mode=0o700)
        self.dns = 'erebus.fixture.ts.net'
        self.addresses = {'ipv4': '100.64.0.40', 'ipv6': 'fd7a:115c:a1e0::40'}

        class FixtureHost(host_bootstrap.Bootstrap):
            def path(host, value):
                relative = Path(value).relative_to('/')
                platform = Path('var/lib/dev-pair')
                return (host.root / relative.relative_to(platform)) if relative.is_relative_to(platform) else host.root / relative

            def directory(host, value, mode=0o700, owner=None):
                projected = '/' + str(host.path(value).relative_to(host.root))
                return super().directory(projected, mode=mode, owner=owner)

        self.host = FixtureHost(self.root, self.system)
        self.host.atomic('/etc/machine-id', '1' * 32 + '\n')
        self.host.atomic('/proc/sys/kernel/random/boot_id', destination.boot + '\n')
        self.host.atomic(host_bootstrap.STATE + '/node.json', '{"node_id":"fixture-node","tailnet":"fixture"}\n')
        self.host.atomic(host_bootstrap.GUARD_PATH, self.host.guard_rules([], tailnet_only=True))
        self.host.atomic(host_bootstrap.SSH_CUTOVER, host_bootstrap.SSH_CUTOVER_CONFIG)
        keys = {}
        for name in ('core', 'collector', 'reviewer'):
            key = self.root / (name + '-key')
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(key)], check=True, timeout=5)
            keys[name] = self.host.observer_public_key(key.with_suffix('.pub').read_text())
        self.host.atomic('/etc/ssh/dev-pair-keys/core', keys['core'] + '\n')
        self.host.atomic(host_bootstrap.TRUST_SIGNERS,
                         f'dev-pair-access-review namespaces="{observation.FINAL_NAMESPACE}" {keys["reviewer"]}\n')
        self.host.update_agent_observer(self.host.signer_fingerprint(keys['collector']), public=keys['collector'])
        self.signers = self.host.signer_trust_file()
        self.station_signing = self.root / 'station-signing.json'
        self.station_signing.write_bytes(observation.encoding({
            'collector_key': str(self.root / 'collector-key.pub'),
            'reviewer_key': str(self.root / 'reviewer-key.pub'),
            'final_trust': str(self.signers),
        }))

    def system(self, *args, **options):
        if args[0] == '/usr/sbin/nft':
            return '{"nftables":[{"table":{"family":"inet","name":"dev_pair_bootstrap"}}]}\n'
        if args[0] == '/usr/bin/tailscale':
            return json.dumps({'CurrentTailnet': {'Name': 'fixture'}, 'BackendState': 'Running',
                               'Self': {'ID': 'fixture-node', 'DNSName': self.dns, 'Online': True},
                               'TailscaleIPs': list(self.addresses.values())})
        if args[:2] == ('/usr/sbin/sshd', '-t'):
            return ''
        if args[:2] == ('/usr/sbin/sshd', '-T'):
            return ('permitrootlogin no\nallowusers core\nauthenticationmethods publickey\n'
                    'passwordauthentication no\nkbdinteractiveauthentication no\n'
                    'authorizedkeysfile /etc/ssh/dev-pair-keys/core\n')
        raise AssertionError('Unexpected host observation command ' + repr(args))

    def initialize(self, reference):
        release = site.role_artifacts(self.destination.controller, reference)
        self.guard = {'phase': 'complete', 'target': {'source_sha': 'a' * 40, 'tailnet': 'fixture',
                                                        'node_id': 'fixture-node', 'dns_name': self.dns},
                      'guard_sha256': self.host.guard_hash(), 'core_keys_sha256': self.host.access_keys_digest(),
                      'acl_sha256': 'e' * 64, 'role_artifacts': release,
                      'provider_recovery': 'hostinger://fixture/recovery', 'public_addresses': {'ipv4': '8.8.4.4', 'ipv6': None}}
        self.host.atomic(host_bootstrap.CUTOVER, observation.encoding(self.guard).decode())
        self.host.publish_workload_gate('admitted', release)

    def transport(self, request):
        raw = observation.encoding(request)
        result = io.BytesIO()
        access_exchange.receive(self.mailbox, access_exchange.COMMAND + ' ' + observation.digest(raw),
                                io.BytesIO(raw), result, int(time.time()))
        return result.getvalue() or None

    def independent_observation(self, request, native):
        reference = request['role_artifacts']['release_sha256']
        plan = {key: value for key, value in request.items() if key in observation.AGENT_SITE_FIELDS}
        plan.update({key: request['candidate'][key] for key in ('guard_sha256', 'acl_sha256', 'host_artifact_sha256')})
        plan.update(devbox_image=request['role_artifacts']['devbox_image'], provider_recovery=self.guard['provider_recovery'],
                    public_addresses=self.guard['public_addresses'])
        directory = self.root / ('station-' + reference[:24])
        directory.mkdir(mode=0o700)

        def challenge(binding, family, wire, *_):
            raw, signature = observation.read_access_envelope(io.BytesIO(wire))
            proof, fingerprint = observation.verify_agent_observer(raw, signature, self.host)
            observation.agent_probe_challenge(proof)
            self.case.assertEqual(proof['request_sha256'], observation.digest(observation.encoding(binding)))
            self.case.assertEqual((proof['candidate'], proof['family']), (reference, family))
            self.case.assertEqual(self.destination.controller.live_release(), request['candidate']['previous_release_sha256'])
            platform = request['candidate']['platform_sha256']
            if proof['role'] == 'maintenance':
                outcome = next(call for call in native['calls'] if call[:2] == ('maintenance-observed', platform))
            else:
                outcome = next(call for call in native['calls'] if call == ('placement', 'stage', platform))
            role_result = observation.expected_role_probe(binding, proof['role'] + '-authorized', family)
            return observation.encoding({**role_result, 'challenge_sha256': fingerprint,
                                         'runtime_result_sha256': renewal.identity(list(outcome))})

        real_sign = observation.sign_observation

        def sign_fixture(raw, public, namespace):
            key = self.root / ('collector-key' if namespace == observation.NAMESPACE else 'reviewer-key')
            self.case.assertEqual(public.read_text().split(), key.with_suffix('.pub').read_text().split()[:2])
            return real_sign(raw, key, namespace)

        with (patch.object(observation, 'ssh_candidate_probe', side_effect=challenge),
              patch.object(observation, 'configured_signers', return_value=self.signers),
              patch.object(observation, 'measure_tailnet_policy', return_value=self.guard['acl_sha256']),
              patch.object(observation, 'STATION_SIGNING', self.station_signing),
              patch.object(observation, 'sign_observation', side_effect=sign_fixture)):
            collection = directory / 'collection.bundle'
            collection.write_bytes(observation.collect_candidate(request, plan, directory, None, None,
                                                                 self.root / 'collector-key.pub'))
            response = observation.assemble_candidate(request, plan, collection, self.root / 'reviewer-key.pub', None)
            access_exchange.publish(self.mailbox, observation.digest(observation.encoding(request)), io.BytesIO(response),
                                    int(time.time()))

    def select(self, candidate_access, request):
        control = self.destination.controller.control
        fence = self.root / 'renewal-fence' / 'frozen'
        attempt_id = request['operation']
        directory = control / 'attempts' / attempt_id
        directory.mkdir(mode=0o700, parents=True)
        path = directory / 'journal.json'
        journal = {'phase': 'applying', 'request': request}
        renewal.replace_json(path, journal)
        renewal.replace_json(control / 'transition.json', attempt_id)
        renewal.replace_json(fence, attempt_id)
        target = request['target_sha256']
        candidate_access.accept(target, attempt_id)
        renewal.replace_json(control / 'site-current.json', target)
        self.host.restore_retained_workload_gate(target)
        renewal.replace_json(control / 'current.json', target)
        renewal.replace_json(path, {**journal, 'phase': 'completed'})
        fence.unlink()
        self.case.assertEqual(self.host.verify_workload_access()['role_artifacts']['release_sha256'], target)


class NightlyComposition(TestCase):
    def setUp(self):
        # The intake and install commands both set this in their own process.
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)

    def test_two_scheduled_packages_through_production_cli_transport_and_local_approval(self):
        self.run_composition(('schedule', 'schedule'))

    def test_fixed_manual_dispatch_uses_the_same_signed_intake_and_approval(self):
        self.run_composition(('schedule', 'workflow_dispatch'))

    def run_composition(self, events):
        destination = local.PortableSiteTests()
        temporary = tempfile.TemporaryDirectory
        with patch.object(local.tempfile, 'TemporaryDirectory', side_effect=lambda: temporary(dir=Path(__file__).resolve().parents[2])):
            destination.setUp()
        self.addCleanup(destination.doCleanups)
        store = destination.root / 'platform-releases'
        control = destination.controller.control
        checkout = native_host.SOURCE
        names = ('tools/native_placements.py', 'tools/native_placement_release.py', 'tools/platform_release.py',
                 'tools/platform_release_protocol.py', 'tools/platform_release_install.py', 'tools/bootstrap.py',
                 'tools/gptbox.py', 'tools/fedora_oci.py', 'tools/native_io.py', 'tools/storage.py', *native_host.ENTRY_FILES)
        source_files = {name: (checkout / name).read_bytes() for name in names}
        destination.host = protocol.canonical({'schema': 1, 'source_revision': 'a'*40, 'state_contract': 1,
                                               'files': {name: publish.digest(raw) for name, raw in source_files.items()}})
        destination.host_sha = publish.digest(destination.host)
        first, initial_inputs = destination.stage('a', native=True)
        path = store / first / 'intake.json'
        path.write_bytes(protocol.canonical(renewal.read_json(path)))
        path.chmod(0o600)
        (store / first / 'installed.json').unlink()
        shutil.rmtree(initial_inputs)
        stage_index = publish.readonly_json(store / first / 'platform.json')[1]
        initial_claim = site.maintenance_claim(store / first, stage_index)
        site.maintenance_path(destination.root, initial_claim, destination.boot).unlink()
        selector = runpy.run_path(str(local.TOOLS.parent / 'runtime/renewal/agent-candidate'))['controller_offer']
        native = {'calls': [], 'stage': {}, 'signed': {}, 'blobs': {}, 'artifacts': {}, 'run': None,
                  'occupied': False, 'placement': {}}
        input_helper = publish.public_inputs

        def part(directory, role, source, end, tooling=None):
            raw, value = publish.readonly_json(directory / 'part.json')
            self.assertEqual(value['image']['source_sha'], source)
            self.assertEqual(value['image']['role'], role)
            return value, publish.digest(raw)

        def stamp(day, hour, minute=0):
            return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)

        def query(endpoint, end, *, limit=intake.META_LIMIT, output=None):
            run = native['run']
            if endpoint == 'branches/main':
                return {'name': 'main', 'protected': True, 'commit': {'sha': run['head_sha']}}
            if endpoint.startswith('actions/workflows/'):
                self.assertIn('event=' + run['event'], endpoint)
                return {'workflow_runs': [run] if native['occupied'] else []}
            if endpoint == f"actions/runs/{run['id']}":
                return run
            if endpoint == f"actions/runs/{run['id']}/artifacts?per_page=100":
                return native['artifacts'][run['id']]
            if endpoint.startswith('actions/artifacts/') and endpoint.endswith('/zip'):
                blob = native['blobs'][int(endpoint.split('/')[2])]
                self.assertLessEqual(len(blob), limit)
                output.write(blob)
                output.flush()
                return None
            raise AssertionError(f'Unexpected endpoint {endpoint}')

        def attestation(path, digest, source, run, role, end):
            self.assertEqual((source, digest, path.read_bytes()), native['signed'][run])
            self.assertIn(role, ('maintenance', 'development'))
            native['calls'].append(('attested', run, role))

        maint = roles.Gptbox(destination.root)
        developer = roles.DevelopmentGptbox(destination.root)
        developer.lock = nullcontext
        developer_protected = developer.protected
        developer.protected = lambda path: path if Path(path).is_relative_to(checkout) else developer_protected(path)
        maint.preflight = lambda *, managed_runtime: self.assertIs(managed_runtime, True)
        maint.maintenance_host_readiness = lambda context: None
        maint.live_boot_id = lambda: destination.boot
        maint.lock = nullcontext
        maint.run = SimpleNamespace(phase=lambda *args, **kwargs: nullcontext())
        projection = native_fixture.PlacementFixture()

        def observe_maintenance(root, binding, part, diffs, producer, receipt):
            _, import_record = maint.read_config_record(root + '/maintenance-import.json')
            self.assertEqual(import_record['oci_manifest_sha256'], binding['oci_manifest_sha256'])
            self.assertEqual(import_record['archive_sha256'], part['archive_sha256'])
            native['calls'].append(('maintenance-observed', binding['platform_sha256'], part['codex_version']))
            return maint.import_admission(binding['platform_sha256'], binding['context_sha256'], binding['source_sha'],
                                         binding['image_id'], binding['oci_manifest_sha256'], binding['boot_id'], producer)

        def placement_mounts(active, producer, account, candidate, previous):
            active.item, active.previous = candidate, previous
            active.job, active.boot = candidate.job, destination.boot
            active.establish = lambda: None
            active.load_outer = lambda: None
            active.save = lambda: None
            active.outer_label = 'fixture-label'
            active.build_volume = SimpleNamespace(capacity=candidate.geometry['storage_bytes'])
            active.job_state = native['placement'].setdefault(candidate.job, {'categories': candidate.geometry['categories'],
                                                                            'manifests': {}, 'preflight': None})
            active.input_root = destination.root / 'development/builds' / candidate.job / 'inputs'
            active.input_root.mkdir(mode=0o755, parents=True, exist_ok=True)
            active.build_inputs = lambda: native_host.directory_fd(active.input_root)
            active.copy_verified = projection.fixture_copy

            def shape():
                return {'identity': candidate.identity, 'prior': candidate.previous, 'boot': destination.boot,
                        'archive': publish.digest(candidate.inner_path.read_bytes())}

            active.admission_binding = shape
            active.preflight = lambda binding: self.assertEqual(binding['archive'], candidate.inner['archive_sha256'])

        @contextmanager
        def projected_label_directory(parent, name, uid, gid, *, mode, label, create):
            with projection.child(parent, name, uid, gid, mode=mode, label=label, create=create) as (fd, created):
                if created:
                    os.fchmod(fd, mode)
                yield fd, created

        def projected_label_file(parent, name, writer, label):
            projection.write(parent, name, writer, label)
            os.chmod(name, 0o444, dir_fd=parent)

        def host_archive(directory, source, end, unpack=None):
            self.assertEqual(source, 'a'*40)
            self.assertEqual((directory / 'host-manifest.json').read_bytes(), destination.host)
            if unpack is not None:
                (unpack / 'manifest.json').write_bytes(destination.host)
                (unpack / 'manifest.json').chmod(0o444)
                for name, raw in source_files.items():
                    path = unpack / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                    path.chmod(0o444)
            return destination.host_sha

        def execute_native(argv, end, **kwargs):
            output = io.StringIO()
            if argv[2] == str(installer.G_ENTRY):
                # Projected native receipts live in this process. Keep the
                # one-shot installer's handlers and timer inside this call.
                handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
                started = time.monotonic()
                delay, interval = signal.setitimer(signal.ITIMER_REAL, 0)
                try:
                    with redirect_stdout(output):
                        self.assertEqual(placement.install_cli(argv[4:]), 0)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
                    if delay:
                        signal.setitimer(signal.ITIMER_REAL, max(delay - (time.monotonic() - started), 0.000001), interval)
                native['calls'].append(('placement', argv[5], argv[7]))
            elif argv[2] == str(installer.P_ENTRY):
                with redirect_stdout(output):
                    self.assertEqual(roles.maintenance_install_cli(argv[3], argv[4:]), 0)
            else:
                raise AssertionError(f'Unexpected native command {argv}')
            return 0, output.getvalue().encode()

        def native_runner(name, *args, timeout):
            fields = dict(zip(args, args[1:]))
            identity = fields['--platform-sha256']
            if name == 'platform_release_intake.py':
                self.assertIn('--agent-only', args)
                with intake.intake_lock():
                    intake.acquire(fields['--source'], int(fields['--run-id']), identity, fields['--previous'],
                                   time.monotonic() + timeout, agent=True)
                native['calls'].append(('retained-predecessor', identity, fields['--previous']))
            else:
                self.assertEqual(name, 'platform_release_install.py')
                self.assertEqual(fields['--site-config-sha256'], destination.config_sha)
                with intake.intake_lock():
                    installer.install(identity, fields['--site-config-sha256'], time.monotonic() + timeout)
                native['calls'].append(('observed-install', identity))

        def resolve(offer):
            resolver = adapter['resolver']
            return resolver(offer, boot=destination.boot, hostname='erebus')

        adapter = {'resolver': destination.resolve.resolve}
        fixture_resolver = destination.resolve
        ordinary_json = publish.readonly_json
        original_checked_file = host_bootstrap.checked_file
        original_workload_gate = renewal.protocol.require_workload_access

        def checked_fixture_file(path, *, secret=False):
            path = Path(path)
            if not path.is_relative_to(destination.root):
                return original_checked_file(path, secret=secret)
            for leaf in (path, *path.parents):
                info = leaf.lstat()
                self.assertIn(info.st_uid, (0, os.getuid()))
                self.assertFalse(info.st_mode & 0o022)
                self.assertTrue(stat.S_ISREG(info.st_mode) if leaf == path else stat.S_ISDIR(info.st_mode))
            self.assertLessEqual(path.stat().st_size, 16384)
            return path

        def fixture_workload_gate(root, **scope):
            self.assertEqual(root, destination.root)
            with patch.object(renewal.protocol, 'os', FixtureOwner()):
                return original_workload_gate(RootPath(root), **scope)

        with ExitStack() as stack:
            stack.enter_context(patch.object(bridge, 'os', FixtureOwner(os.geteuid())))
            stack.enter_context(patch.object(intake, 'os', FixtureOwner()))
            stack.enter_context(patch.object(intake, 'file_hash', side_effect=lambda path, maximum, end, **kwargs:
                                            protocol.file_hash(path, maximum, end, owner=os.getuid())))
            stack.enter_context(patch.object(publish, 'readonly_json', side_effect=lambda path, owner=None: ordinary_json(path)))
            stack.enter_context(patch.object(renewal, 'DEFAULT_ROOT', destination.root))
            stack.enter_context(patch.object(site, 'Resolver', return_value=fixture_resolver))
            stack.enter_context(patch.object(fixture_resolver, 'resolve', side_effect=resolve))
            stack.enter_context(patch.object(intake, 'ROOT', store))
            stack.enter_context(patch.object(intake, 'portable_volume', return_value=(store.stat().st_dev, 42, 17, ('99',))))
            stack.enter_context(patch.object(intake, 'GITHUB', '/usr/bin/python3'))
            stack.enter_context(patch.object(intake, 'protected', side_effect=lambda path, **kwargs: path))
            stack.enter_context(patch.object(intake, 'read_api', side_effect=query))
            stack.enter_context(patch.object(intake, 'verify_subject', side_effect=attestation))
            stack.enter_context(patch.object(publish, 'validate_image_part', side_effect=part))
            stack.enter_context(patch.object(publish, 'validate_host', side_effect=host_archive))
            stack.enter_context(patch.object(publish, 'publication_evidence', wraps=publish.publication_evidence))
            stack.enter_context(patch.object(installer, 'ROOT', destination.root))
            stack.enter_context(patch.object(installer, 'ADAPTER', destination.root / 'bootstrap/gptbox-adapter'))
            stack.enter_context(patch.object(installer, 'HOST_RELEASES', destination.root / 'host-releases'))
            stack.enter_context(patch.object(installer, 'SITE_CONFIGS', destination.root / 'site-configs'))
            stack.enter_context(patch.object(installer, 'G_ENTRY', checkout / 'tools/native_placements.py'))
            stack.enter_context(patch.object(installer, 'P_ENTRY', checkout / 'tools/gptbox.py'))
            stack.enter_context(patch.object(installer, 'file_hash', side_effect=lambda path, maximum, end, **kwargs:
                                            protocol.file_hash(path, maximum, end, owner=os.getuid())))
            stack.enter_context(patch.object(installer, 'regular', side_effect=lambda path, maximum, owner=None:
                                            protocol.regular(path, maximum, os.getuid())))
            stack.enter_context(patch.object(installer, 'machine', return_value=destination.boot))
            stack.enter_context(patch.object(installer, 'maintenance_identity', return_value=(None, Path('/run/user/1000'))))
            stack.enter_context(patch.object(installer, 'bounded_volume', return_value={'device': f'{os.major(store.stat().st_dev)}:{os.minor(store.stat().st_dev)}'}))
            stack.enter_context(patch.object(installer, 'recover_maintenance'))
            stack.enter_context(patch.object(installer, 'observe_maintenance_engine'))
            stack.enter_context(patch.object(installer, 'bounded', side_effect=execute_native))
            stack.enter_context(patch.object(installer.devbox, 'storage_mount'))
            stack.enter_context(patch.object(installer.devbox, 'check_label'))
            stack.enter_context(patch.object(placement, 'os', FixtureOwner()))
            stack.enter_context(patch.object(placement, 'RELEASES', store))
            stack.enter_context(patch.object(placement, 'RENEWAL', control))
            stack.enter_context(patch.object(placement, 'SITE_CONFIGS', destination.root / 'site-configs'))
            stack.enter_context(patch.object(placement.ReleasePlacement, '__init__', placement_mounts))
            stack.enter_context(patch.object(native_host, 'DevelopmentGptbox', return_value=developer))
            stack.enter_context(patch.object(native_host, 'managed_snapshot'))
            stack.enter_context(patch.object(native_host, 'role_account'))
            stack.enter_context(patch.object(native_host, 'private_child', projected_label_directory))
            stack.enter_context(patch.object(native_host, 'stable_file', projected_label_file))
            stack.enter_context(patch.object(roles, 'PLATFORM_RELEASES', '/platform-releases'))
            stack.enter_context(patch.object(roles, 'ROOT', '/bootstrap/gptbox-adapter'))
            factory = stack.enter_context(patch.object(roles, 'Gptbox', return_value=maint))
            factory.import_admission.side_effect = maint.import_admission
            stack.enter_context(patch.object(maint, 'prove_installed_maintenance', side_effect=observe_maintenance))
            stack.enter_context(patch.object(publish, 'source_checkout'))
            stack.enter_context(patch.object(host_bootstrap, 'checked_file', side_effect=checked_fixture_file))
            stack.enter_context(patch.object(observation, 'checked_file', side_effect=checked_fixture_file))
            stack.enter_context(patch.object(renewal.protocol, 'require_workload_access', side_effect=fixture_workload_gate))
            observers = ObservationFixture(self, destination)
            stack.enter_context(patch.object(host_bootstrap, 'Bootstrap', return_value=observers.host))
            controller = bridge.Site(renewal, site, intake, protocol)
            stack.enter_context(patch.object(controller, 'run_tool', side_effect=native_runner))
            stack.enter_context(patch.object(controller, 'dispatch', side_effect=lambda: native['calls'].append(('dispatched',))))
            stack.enter_context(patch.object(controller, 'exchange_observation', side_effect=observers.transport))
            installer.install(first, destination.config_sha, time.monotonic() + 30)
            initial = resolve(destination.offer(first))
            for name in ('current.json', 'site-current.json'):
                renewal.replace_json(control / name, initial['release_sha256'])
            observers.initialize(initial['release_sha256'])
            prior = first
            for (day, run_id, letter, version), event_name in zip(((26, 22, 'b', '2.0.0'), (27, 23, 'c', '3.0.0')), events):
                source = letter * 40
                on_demand = event_name == 'workflow_dispatch'
                run = scheduled.run_row(run_id, stamp(day, 19, 6), head_sha=source, event=event_name)
                native['run'] = run
                native['occupied'] = False
                self.assertEqual(controller.cycle(bridge.selection_window(stamp(day, 19), on_demand)),
                                 {'status': 'awaiting-publication'})
                staged, input_directory = destination.stage(letter, agent=True, base=first, stable=version,
                                                             local_prior=prior, run=run_id, native=True)
                shutil.rmtree(input_directory)
                interim = publish.readonly_json(store / staged / 'platform.json')[1]
                claim = site.maintenance_claim(store / staged, interim)
                site.maintenance_path(destination.root, claim, destination.boot).unlink()
                remote = destination.root / ('publisher-' + str(run_id))
                (remote / 'parts').mkdir(parents=True)
                for role in ('maintenance', 'development'):
                    shutil.copytree(store / staged / role, remote / 'parts' / publish.artifact_name(role, source))
                event = remote / 'event.json'
                observed_event = {'ref': 'main', 'inputs': {}} if on_demand else {'schedule': '0 19 * * *'}
                event.write_bytes(protocol.canonical(observed_event))
                tooling = {'schema': 1, 'kind': 'dev-pair-verified-codex-pin-proposal', 'reviewed_source_sha': source,
                           'source_sha': source, 'tag': 'rust-v' + version, 'version': version, 'release_id': run_id,
                           'assets': {'archive': {'sha256': '9' * 64, 'bytes': 1}, 'bundle': {'sha256': '8' * 64, 'bytes': 1}},
                           'binary': {'sha256': 'f' * 64, 'bytes': 1}, 'verification_sha256': '7' * 64,
                           'approved_pins_match': False, 'cached_assets': []}
                tooling_file = remote / 'tooling.json'
                tooling_file.write_bytes(input_helper.canonical(tooling))
                env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': publish.REPOSITORY, 'GITHUB_EVENT_NAME': event_name,
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_SHA': source, 'GITHUB_RUN_ID': str(run_id), 'GITHUB_EVENT_PATH': str(event),
                       'GITHUB_WORKFLOW_REF': publish.REPOSITORY + '/.github/workflows/agent-refresh.yml@refs/heads/main'}
                arguments = ['platform_release.py', 'assemble', '--agent-only', '--site-chain', '--source', source,
                             '--input', str(remote / 'parts'), '--output', str(remote / 'subjects'),
                             '--run-id', str(run_id), '--base-platform', first, '--refresh-tooling', str(tooling_file),
                             '--approved-artifact-bytes', str(publish.AGENT_BUDGET)]
                stdout = io.StringIO()
                with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', arguments), redirect_stdout(stdout):
                    self.assertEqual(publish.main(), 0)
                self.assertEqual(stdout.getvalue().strip(), staged)
                signed = (remote / 'subjects/platform.json').read_bytes()
                native['signed'][run_id] = (source, staged, signed)
                leaves = {publish.artifact_name('subjects', source): {'platform.json': signed},
                          f'agent-tooling-{source}': {'tooling.json': tooling_file.read_bytes()}}
                for role in ('maintenance', 'development'):
                    name = publish.artifact_name(role, source)
                    leaves[name] = {path.name: path.read_bytes() for path in (remote / 'parts' / name).iterdir()}
                rows = []
                for offset, (name, items) in enumerate(leaves.items(), start=1):
                    artifact = io.BytesIO()
                    with zipfile.ZipFile(artifact, 'w') as archive:
                        for leaf, raw in items.items():
                            archive.writestr(leaf, raw)
                    data = artifact.getvalue()
                    identifier = run_id * 10 + offset
                    native['blobs'][identifier] = data
                    rows.append({'name': name, 'id': identifier, 'expired': False,
                                 'size_in_bytes': len(data), 'digest': 'sha256:' + publish.digest(data)})
                native['artifacts'][run_id] = {'artifacts': rows, 'total_count': len(rows)}
                shutil.rmtree(store / staged)
                native['occupied'] = True
                window = bridge.selection_window(stamp(day, 22, 30), on_demand)
                selected_old = destination.controller.live_release()
                previous_offer = controller.offer.read_bytes() if controller.offer.exists() else None
                previous_dispatches = native['calls'].count(('dispatched',))
                self.assertEqual(controller.cycle(window)['status'], 'awaiting-independent-observation')
                self.assertEqual(destination.controller.live_release(), selected_old)
                self.assertEqual(native['calls'].count(('dispatched',)), previous_dispatches)
                self.assertEqual(controller.offer.read_bytes() if controller.offer.exists() else None, previous_offer)
                request_binding = controller.observation.request()
                self.assertEqual(request_binding['candidate']['platform_sha256'], staged)
                self.assertEqual(request_binding['candidate']['previous_release_sha256'], selected_old)
                observers.independent_observation(request_binding, native)
                self.assertEqual(controller.cycle(window)['status'], 'queued')
                self.assertIn(('retained-predecessor', staged, prior), native['calls'])
                self.assertIn(('observed-install', staged), native['calls'])
                self.assertIn(('placement', 'preflight', staged), native['calls'])
                self.assertIn(('placement', 'stage', staged), native['calls'])
                self.assertIn(('maintenance-observed', staged, version), native['calls'])
                self.assertIn(('attested', run_id, 'maintenance'), native['calls'])
                self.assertIn(('attested', run_id, 'development'), native['calls'])
                self.assertEqual(native['calls'][-1], ('dispatched',))
                with patch.dict(selector.__globals__, {'CONTROL': control, 'Resolver': lambda _: fixture_resolver,
                                                      'official_version': lambda: version}):
                    result = selector(destination.controller)
                self.assertEqual(result['status'], 'verified')
                proof = store / staged / 'site-predecessor.json'
                prior_proof = proof.read_bytes()
                observed_install = store / staged / 'installed.json'
                retained_install = observed_install.read_bytes()
                with intake.intake_lock():
                    installer.install(staged, destination.config_sha, time.monotonic() + 30)
                self.assertEqual(observed_install.read_bytes(), retained_install)
                proof.unlink()
                with self.assertRaises((OSError, ValueError)):
                    installer.install(staged, destination.config_sha, time.monotonic() + 30)
                proof.write_bytes(prior_proof)
                proof.chmod(0o600)
                request = destination.controller.active_request('agent')
                self.assertEqual(request['target_sha256'], result['release_sha256'])
                self.assertEqual(request['previous_sha256'], renewal.read_json(control / 'current.json'))
                observers.select(controller.observation, request)
                prior = staged
        self.assertEqual(len([leaf for leaf in store.iterdir() if len(leaf.name) == 64]), 3)
