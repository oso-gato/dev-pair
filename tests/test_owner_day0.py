"""Exercise the interactive owner control flow with local physical boundaries projected."""
from contextlib import contextmanager, nullcontext, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import owner_day0 as day
import bootstrap as bootstrap
import gptbox
import public_inputs

SOURCE = 'a' * 40
MACHINE = 'b' * 32
BOOT = '11111111-2222-3333-4444-555555555555'


def safe_local(path):
    node = path.lstat()
    if not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or node.st_mode & 0o022:
        raise bootstrap.Blocked('protected test file required')
    return path


class DayZeroTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(patch.object(day, 'local_file', side_effect=safe_local))
        self.entry = day.DayZero(self.directory / 'dev-pair', Mock())
        self.identity = {'machine_id': MACHINE, 'boot_id': BOOT, 'host': 'erebus', 'selinux': '1'}

    def test_commission_imports_custodian_handoff_and_registers_the_exact_credential_once(self):
        waiting_trust = {'phase': 'pending', 'prerequisite': 'release-trust'}
        waiting_read = {'phase': 'pending', 'prerequisite': 'release-read-custody'}
        awaiting_release = {'phase': 'pending', 'prerequisite': 'initial-full-release-selection'}
        self.entry.call = Mock(side_effect=[waiting_trust, {}, waiting_read, {}, awaiting_release])
        handoff = '/root/custodian-handoff.json'
        approved_fingerprint = 'c' * 64
        secret = 'fixture secret never passed in an invocation'
        credential = self.directory / 'anonymous-token'

        @contextmanager
        def entered(value):
            self.assertEqual(value, secret)
            yield credential

        with patch.object(day, 'answer', side_effect=[handoff, approved_fingerprint]), \
                patch.object(day, 'secret_answer', return_value=secret), patch.object(day, 'secret_file', entered):
            self.assertEqual(self.entry.commission_apply(SOURCE, object()), awaiting_release)
        invocations = [call.args for call in self.entry.call.call_args_list]
        apply = ('commission_host.py', 'apply', '--source-sha', SOURCE)
        self.assertEqual(invocations, [apply,
            ('release_setup.py', 'install', '--source-sha', SOURCE, '--handoff', handoff, '--sha256', approved_fingerprint),
            apply, ('release_setup.py', 'register-read', '--source-sha', SOURCE, '--token-file', credential), apply])
        self.assertNotIn(secret, repr(invocations))

    def test_commission_waits_without_authority_or_an_attached_terminal(self):
        pending = {'phase': 'pending', 'prerequisite': 'release-trust'}
        self.entry.call = Mock(return_value=pending)
        with patch.object(day, 'answer', side_effect=AssertionError('attempted unattended prompt')):
            self.assertEqual(self.entry.commission_apply(SOURCE, None), pending)
        self.entry.call.assert_called_once()
        self.entry.call.reset_mock()
        with patch.object(day, 'answer', return_value=''), patch.object(day, 'secret_answer',
                                                                      side_effect=AssertionError('prompted for unapproved credential')):
            self.assertEqual(self.entry.commission_apply(SOURCE, object()), pending)
        self.entry.call.assert_called_once()

    def test_legacy_finalize_accepts_staged_receipt_and_waits_without_a_terminal(self):
        self.entry.app.status.return_value = {'phase': 'temporary-bootstrap'}
        self.entry.receiving_access = Mock()
        with patch.object(day, 'HANDOFF', self.directory), redirect_stdout(io.StringIO()) as message:
            self.assertFalse(self.entry.finalize())
            self.assertIn('./day0.sh access-request', message.getvalue())
            with self.assertRaisesRegex(bootstrap.Blocked, 'complete pinned SHA'):
                self.entry.finalize(SOURCE, tty=object())
            admitted = self.directory / 'cutover.json'
            admitted.touch()
            self.assertTrue(self.entry.finalize())
        self.entry.receiving_access.assert_not_called()
        self.entry.app.finalize.assert_called_once_with(str(admitted))

    def test_commission_reports_each_admitted_and_held_feature(self):
        tool = self.entry.repo / 'tools/commission_host.py'
        tool.parent.mkdir(parents=True)
        tool.touch()
        self.entry.stage = Mock()
        self.entry.app.status.return_value = {'access_scope': 'full'}
        self.entry.call = Mock(return_value={'phase': 'ready', 'owner_terminal': None,
            'timers': {'dev-pair-checklist-spool.timer': {'next': ['scheduled']}},
            'held_features': ['agent-renewal', 'owner-intake'],
            'pending_features': {'agent-renewal': 'release-read-custody', 'owner-intake': 'owner-catalogue-selection'}})
        self.entry.commission(self.identity, SOURCE)
        _, _, stage, details = self.entry.stage.call_args.args
        self.assertEqual(stage, 'managed-listener-ready')
        self.assertIn('Checklist cleanup is scheduled.', details)
        self.assertIn('Agent renewal is held pending release read custody.', details)
        self.assertIn('Owner intake is held pending owner catalogue selection.', details)
        self.assertIn('Run ./day0.sh resume to continue first owner setup.', details)
        self.assertNotIn('terminal is available', details)

    def test_resume_uses_single_pinned_source_for_core_roles_and_owner_setup(self):
        tool = self.entry.repo / 'tools/commission_host.py'
        tool.parent.mkdir(parents=True)
        tool.touch()
        stage = self.entry.stage = Mock()
        self.entry.original = Mock(return_value=self.identity)
        self.entry.ensure_git = Mock(return_value=SOURCE)
        self.entry.resume_maintenance = Mock(return_value=True)
        self.entry.enroll = Mock(return_value=True)
        self.entry.receiving_access = Mock(side_effect=[False, True, True])
        self.entry.setup_owner = Mock(return_value=True)
        self.entry.app.status.return_value = {'prepared': True, 'phase': 'temporary-bootstrap'}
        self.entry.app.verify_workload_access.side_effect = bootstrap.Blocked('independent role receipt pending')
        selected = '1' * 64
        ready = {'phase': 'ready', 'selected_release': selected}
        self.entry.commission_apply = Mock(side_effect=[
            {**ready, 'pending_features': {'owner-intake': 'workload-access'}},
            {**ready, 'pending_features': {'owner-intake': 'owner-catalogue-selection'}},
            {**ready, 'owner_terminal': '/usr/local/bin/dev-pair'},
        ])
        previous = {'machine_id': MACHINE, 'source_sha': SOURCE}

        def current(path):
            return {'desired.json': {'gptbox_context_sha256': '2' * 64}, 'progress.json': previous}.get(path.name)

        tty = object()
        with (patch.object(day, 'record', side_effect=current),
              patch.object(day, 'kit_source', return_value=(SOURCE, True)),
              patch.object(self.entry, 'owner_lock', side_effect=nullcontext)):
            self.entry.start(None, tty)
            self.entry.commission_apply.assert_not_called()
            self.entry.setup_owner.assert_not_called()
            self.entry.start(None, tty)
        self.assertEqual(
            [(item.args, item.kwargs) for item in self.entry.receiving_access.call_args_list],
            [((SOURCE, SOURCE, tty), {}), ((SOURCE, SOURCE, tty), {}),
             ((SOURCE, SOURCE, tty), {'workload': True})],
        )
        self.assertEqual([item.args for item in self.entry.commission_apply.call_args_list], [(SOURCE, tty)] * 3)
        self.entry.setup_owner.assert_called_once_with(tty)
        self.assertEqual(stage.call_args.args[2], 'owner-terminal-ready')

    def test_first_owner_ready_offers_promotion_then_reapplies_only_after_enrollment(self):
        tool = self.entry.repo / 'tools/commission_host.py'
        tool.parent.mkdir(parents=True)
        tool.touch()
        self.entry.stage = Mock()
        ready = {'phase': 'ready', 'owner_terminal': '/usr/local/bin/dev-pair'}
        held = {**ready, 'pending_features': {'checklist-promotion': 'promotion-enrollment'}}
        scheduled = {**ready, 'timers': {'dev-pair-promotion-scan.timer': {'next': ['scheduled']}}}
        tty = object()
        self.entry.setup_promotion = Mock(side_effect=[False, True])
        self.entry.commission_apply = Mock(side_effect=[held, held, scheduled])
        self.entry.commission(self.identity, SOURCE, tty=tty)
        self.assertEqual(self.entry.commission_apply.call_count, 1)
        self.assertIn('Checklist promotion is held', self.entry.stage.call_args.args[3])
        self.entry.commission(self.identity, SOURCE, tty=tty)
        self.assertEqual(self.entry.commission_apply.call_count, 3)
        self.assertIn('Checklist promotion is scheduled.', self.entry.stage.call_args.args[3])

    def test_day0_reopens_billing_setup_when_the_configured_slot_is_held(self):
        tty = object()
        tool = self.entry.repo / 'tools/commission_host.py'
        tool.parent.mkdir(parents=True)
        tool.touch()
        self.entry.stage = Mock()
        self.entry.setup_owner = Mock(return_value=True)
        ready = {'phase': 'ready', 'selected_release': '1' * 64}
        self.entry.commission_apply = Mock(side_effect=[
            {**ready, 'pending_features': {'owner-intake': 'provider-slot-authority'}},
            {**ready, 'owner_terminal': '/usr/local/bin/dev-pair'},
        ])
        self.entry.commission(self.identity, SOURCE, tty=tty)
        self.entry.setup_owner.assert_called_once_with(tty)
        self.assertEqual(self.entry.commission_apply.call_count, 2)
        self.assertEqual(self.entry.stage.call_args.args[2], 'owner-terminal-ready')

    def test_station_response_may_resume_checked_recovery_but_cannot_select_another_scope(self):
        from destination_observation import access_envelope

        envelope = access_envelope(b'fixed fixture receipt', b'fixture signature')
        target = {'source_sha': SOURCE, 'machine_id': MACHINE, 'tailnet': 'tail',
                  'node_id': 'fixture', 'dns_name': 'erebus.tail.ts.net'}
        signed = {**target, 'kind': bootstrap.CORE_ACCESS_CUTOVER, 'boot_id': BOOT,
                  'execution_route': 'provider-recovery'}
        self.entry.app.signed_evidence.return_value = signed
        history = {'phase': 'applying', 'target': target,
                   'intent': {'claims': {'boot_id': 'earlier boot', 'execution_route': 'tailnet-core'}}}
        with patch.object(day, 'STATE', self.directory), patch.object(day, 'record', return_value=history):
            with self.assertRaisesRegex(bootstrap.Blocked, 'different access stage'):
                self.entry.apply_access(SOURCE, SOURCE, io.BytesIO(envelope), workload=True)
            self.entry.app.finalize.assert_not_called()
            self.entry.apply_access(SOURCE, '3' * 40, io.BytesIO(envelope), workload=False)
        self.assertEqual(self.entry.app.finalize.call_args.kwargs, {'recover': True, 'previous_source': '3' * 40})

    def test_matching_legacy_full_applying_journal_uses_native_scoped_recovery(self):
        from destination_observation import access_envelope

        target = {'source_sha': SOURCE, 'machine_id': MACHINE, 'tailnet': 'tail',
                  'node_id': 'fixture', 'dns_name': 'erebus.tail.ts.net'}
        signed = {**target, 'kind': bootstrap.CORE_ACCESS_CUTOVER, 'boot_id': BOOT,
                  'execution_route': 'provider-recovery', 'keys_sha256': '1' * 64, 'acl_sha256': '2' * 64,
                  'provider_recovery': 'hostinger://fixture/recovery', 'public_addresses': {'ipv4': None, 'ipv6': None},
                  'tailnet_addresses': {'ipv4': '100.64.0.1', 'ipv6': 'fd7a:115c:a1e0::1'}}
        legacy = {key: value for key, value in signed.items() if key not in ('kind', 'tailnet_addresses')}
        app = bootstrap.Bootstrap(self.directory)

        def journal(data, expected, previous, raw, recover, historical):
            return app.initial_cutover_journal(data, expected, previous, raw, 'temporary', 'permanent',
                                               bootstrap.ATTENDED_ACCESS, recover=recover, previous_source=historical,
                                               receipt_sha='3' * 64, legacy_origin={})

        initial = journal(legacy, target, {}, '', False, None)
        previous = json.loads(initial)
        mismatch = {**previous, 'target': {**target, 'machine_id': 'f' * 32}}
        self.entry.app.signed_evidence.return_value = signed

        with patch.object(day, 'STATE', self.directory), patch.object(day, 'record') as stored:
            for prior in (mismatch, previous):
                stored.return_value = prior
                self.entry.app.finalize.side_effect = (
                    lambda path, *, recover, previous_source: journal(signed, target, prior, initial, recover, previous_source)
                )
                message = io.BytesIO(access_envelope(b'provider fixture', b'signature fixture'))
                if prior is mismatch:
                    with self.assertRaises(bootstrap.Blocked):
                        self.entry.apply_access(SOURCE, SOURCE, message, workload=False)
                    self.assertFalse(self.entry.app.finalize.call_args.kwargs['recover'])
                else:
                    accepted = json.loads(self.entry.apply_access(SOURCE, SOURCE, message, workload=False))
                    digest = sha256(initial.encode()).hexdigest()
                    self.assertEqual(accepted['recovery_predecessor_sha256'], digest)
                    self.assertEqual(app.text(bootstrap.STATE + '/cutover-recovery/' + digest + '.json'), initial)

    def test_attended_trust_preserves_other_protected_signers_and_reuses_the_access_key(self):
        target = self.directory / 'allowed_signers'
        signing_key = self.directory / 'review'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-N', '', '-t', 'ed25519', '-f', str(signing_key)],
                       check=True, timeout=5, capture_output=True)
        public = signing_key.with_suffix('.pub').read_text()
        old = '# protected authority from the provider\n'
        target.write_text(old)
        target.chmod(0o640)

        def write(path, content, *, mode, expected):
            self.assertEqual((path, mode, expected), (str(target), 0o640, old))
            target.write_text(content)

        self.entry.app.atomic.side_effect = write
        self.entry.app.lock.return_value = nullcontext()
        fingerprint = bootstrap.Bootstrap.signer_fingerprint(public)
        with (patch.object(day, 'TRUST_SIGNERS', str(target)),
              patch.object(day, 'answer', side_effect=[public, 'SHA256:incorrect', public, fingerprint]) as prompt):
            with self.assertRaisesRegex(bootstrap.Blocked, 'fingerprint differs'):
                self.entry.access_trust(None)
            self.assertEqual(target.read_text(), old)
            self.assertTrue(self.entry.access_trust(None))
            self.assertTrue(self.entry.access_trust(None))
        self.assertEqual(prompt.call_count, 4)
        self.entry.app.atomic.assert_called_once()
        self.assertEqual(target.read_text(), old + 'dev-pair-access-review namespaces="dev-pair-destination" ' +
                         ' '.join(public.split()[:2]) + '\n')

    def test_collector_setup_requires_independent_fingerprint_and_withdraws_by_identity(self):
        public = 'independent public key from the station'
        fingerprint = 'SHA256:' + 'x' * 43
        self.entry.app.agent_observer_signers.return_value = None
        with patch.object(day, 'answer', side_effect=[public, '']):
            self.assertFalse(self.entry.setup_agent_observer(None))
        self.entry.app.update_agent_observer.assert_not_called()
        with patch.object(day, 'answer', side_effect=[public, fingerprint]):
            self.assertTrue(self.entry.setup_agent_observer(None))
        self.entry.app.update_agent_observer.assert_called_once_with(fingerprint, public=public)
        self.entry.app.agent_observer_signers.return_value = b'enrolled collector'
        with patch.object(day, 'answer', return_value=fingerprint):
            self.assertTrue(self.entry.setup_agent_observer(None, revoke=True))
        self.entry.app.update_agent_observer.assert_called_with(fingerprint)

    def test_gitless_kit_verification_and_signed_prerequisite(self):
        repo = self.entry.repo
        for name in ('day0.sh', 'tools/owner_day0.py', 'runtime/dev-pair-test@.service', '.git/HEAD', '.git/index'):
            leaf = repo / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(name.encode())
        marker = self.directory / 'SOURCE'
        marker.write_text(SOURCE + '\n')
        manifest = self.directory / 'MANIFEST.sha256'
        files = [marker, *[path for path in repo.rglob('*') if path.is_file()]]
        manifest.write_text(''.join(f'{sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.directory)}\n' for path in files))
        git = self.directory / 'git'
        with patch.object(day, 'GIT', git):
            self.assertEqual(day.kit_source(repo), (SOURCE, True))
            self.entry.app.destination_source.return_value = SOURCE
            with patch.object(day.subprocess, 'run') as command:
                self.assertEqual(self.entry.ensure_git(SOURCE, True), SOURCE)
            self.assertEqual(command.call_args.args[0][-3:], ['--enablerepo=updates', 'install', 'git-core'])
            self.assertIn('--setopt=gpgcheck=1', command.call_args.args[0])
            self.entry.app.destination_source.assert_called_once_with(SOURCE)
            safe_manifest = manifest.read_text()
            manifest.write_text(safe_manifest + '1' * 64 + '  dev-pair/../outside\n')
            with self.assertRaisesRegex(bootstrap.Blocked, 'outside its approved source'):
                day.kit_source(repo)
            manifest.write_text(safe_manifest)
            (repo / 'day0.sh').write_bytes(b'changed')
            with self.assertRaisesRegex(bootstrap.Blocked, 'bytes differ'):
                day.kit_source(repo)

    def test_public_checkout_uses_owner_supplied_pin_without_fabricated_manifest(self):
        path = self.directory / 'SOURCE'
        path.write_text(SOURCE + '\n')
        self.assertEqual(day.kit_source(self.entry.repo), (SOURCE, False))
        with self.assertRaisesRegex(bootstrap.Blocked, 'differs'):
            day.kit_source(self.entry.repo, 'c' * 40)

    def test_ordinary_resume_rechecks_signed_stable_checkout_without_touching_enrollment(self):
        old, new = SOURCE, 'd' * 40
        state = self.directory / 'day0'
        state.mkdir()
        original = state / 'progress.json'
        old_state = {'source_sha': old, 'machine_id': MACHINE, 'phase': 'owner-terminal-ready', 'next': 'retained'}
        original.write_text(json.dumps(old_state))
        original.chmod(0o600)
        output = self.directory / 'successor'
        (output / 'tools').mkdir(parents=True)
        (output / 'tools/commission_host.py').touch()
        self.entry.original = Mock(return_value=self.identity)
        self.entry.ensure_git = Mock()
        self.entry.owner_lock = nullcontext
        self.entry.stable_site = Mock(return_value={'source_sha': new, 'original_source_sha': old})
        self.entry.stable_checkout = Mock(return_value=output)
        self.entry.call = Mock(return_value={'phase': 'ready', 'held_features': ['owner-intake']})
        self.entry.stage = Mock()
        self.entry.enroll = Mock(side_effect=AssertionError('enrollment ran during a settled recheck'))
        self.entry.select_source = Mock(side_effect=AssertionError('old source selection ran during a stable recheck'))
        self.entry.maintenance_receipt = Mock(side_effect=AssertionError('old runtime probed during a stable recheck'))
        with (patch.object(day, 'STATE', state), patch.object(day, 'kit_source', return_value=(old, True))):
            self.entry.start(None, object())
        self.entry.stable_checkout.assert_called_once_with(self.entry.stable_site.return_value, old)
        self.entry.call.assert_called_once_with('commission_host.py', 'apply', '--source-sha', new, timeout=1800, checkout=output)
        self.assertEqual(self.entry.progress, state / 'stable-progress.json')
        self.assertEqual(json.loads(original.read_text()), old_state)

    def test_archived_source_can_only_route_to_exact_signed_stable_controller(self):
        import commission_host

        old, new = SOURCE, 'd' * 40
        package = self.directory / ('dev-pair-day0-' + new)
        checkout = package / 'dev-pair'
        bundle = self.directory / 'bundle'
        for folder in (checkout, bundle):
            (folder / 'tools').mkdir(parents=True)
            for name in ('bootstrap.py', 'commission_host.py'):
                (folder / 'tools' / name).write_text(name)
        (package / 'SOURCE').write_text(new + '\n')
        authority = {'source_sha': new, 'original_source_sha': old, 'commissioning_source_sha': old, 'bundle': bundle}
        with (patch.object(day, 'OWNER_KITS', self.directory),
              patch.object(commission_host, 'verify_checkout') as exact):
            self.assertEqual(self.entry.stable_checkout(authority, old), checkout)
            exact.assert_called_once_with(checkout, new, 0)
            with self.assertRaisesRegex(bootstrap.Blocked, 'original or the selected'):
                self.entry.stable_checkout(authority, 'a' * 39 + 'b')
            (checkout / 'tools/bootstrap.py').write_text('foreign executable')
            with self.assertRaisesRegex(bootstrap.Blocked, 'differs from its independently approved host bundle'):
                self.entry.stable_checkout(authority, old)

    def test_continuation_retains_the_original_completed_maintenance_evidence(self):
        state = self.directory / 'day0'
        bootstrap_state = self.directory / 'bootstrap'
        state.mkdir()
        bootstrap_state.mkdir()
        historical = day.INITIAL_MAINTENANCE_SOURCE
        context, image = 'c' * 64, 'd' * 64

        def save_record(path, value):
            path.write_text(json.dumps(value, sort_keys=True) + '\n')
            path.chmod(0o600)

        original = {'source_sha': historical, 'machine_id': MACHINE}
        result = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': historical, 'context_sha256': context,
                  'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
                  'assembled_image_id': image}
        journal = {'phase': 'complete', 'maintenance_gptbox': 'complete', 'result': result,
                   'target': {'source_sha': historical, 'context_sha256': context}}
        original_files = {state / 'progress.json': original, bootstrap_state / 'initialize.json': journal,
                          bootstrap_state / 'host-ready.json': {'source_sha': historical},
                          bootstrap_state / 'desired.json': {'gptbox_context_sha256': context}}
        for path, value in original_files.items():
            save_record(path, value)
        before = {path: path.read_bytes() for path in original_files}
        self.entry.maintenance_receipt = Mock(return_value=image)
        with (patch.object(day, 'BOOTSTRAP', str(bootstrap_state)), patch.object(day, 'STATE', state),
              patch.object(day, 'save', side_effect=lambda _app, path, value: save_record(path, value))):
            self.assertEqual(self.entry.select_source(self.identity, SOURCE, original), (historical, image))
            self.assertEqual(self.entry.select_source(self.identity, SOURCE, original), (historical, image))
            self.assertEqual(self.entry.progress, state / 'continuation-progress.json')
            with self.assertRaisesRegex(bootstrap.Blocked, 'continuation differs'):
                self.entry.select_source(self.identity, 'e' * 40, original)
            self.entry.maintenance_receipt.return_value = 'e' * 64
            with self.assertRaisesRegex(bootstrap.Blocked, 'sealed maintenance image'):
                self.entry.select_source(self.identity, SOURCE, original)
        self.assertEqual({path: path.read_bytes() for path in original_files}, before)
        self.assertEqual(json.loads((state / 'continuation.json').read_text())['maintenance_source_sha'], historical)

    def test_historical_test_only_tree_uses_real_protected_git_objects(self):
        checkout = self.directory / 'temporary'
        checkout.mkdir()

        def git(*args, path=checkout):
            return subprocess.check_output(['/usr/bin/git', '-C', str(path), *args], env=day.ENV)

        git('init', '-q')
        git('config', 'user.name', 'Fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        (checkout / 'day0.sh').write_text('production bytes')
        git('add', '.')
        git('commit', '-qm', 'original')
        production = sha256(git('ls-tree', '-r', '-z', 'HEAD').rstrip(b'\0')).hexdigest()
        (checkout / 'tests').mkdir()
        (checkout / 'tests/test_earlier.py').write_text('fixture bytes')
        git('add', '.')
        git('commit', '-qm', 'test-only successor')
        historical = git('rev-parse', 'HEAD').decode().strip()
        parent = self.directory / ('dev-pair-day0-' + historical)
        parent.mkdir()
        repo = parent / 'dev-pair'
        checkout.rename(repo)
        (parent / 'SOURCE').write_text(historical + '\n')
        with (patch.object(day, 'OWNER_KITS', self.directory),
              patch.object(day, 'INITIAL_MAINTENANCE_PRODUCTION_TREE', production)):
            self.assertTrue(self.entry.compatible_predecessor(historical))
            (repo / 'day0.sh').write_text('unreviewed production bytes')
            with self.assertRaisesRegex(bootstrap.Blocked, 'differs from its recorded pin'):
                self.entry.compatible_predecessor(historical)

    def test_distinct_local_recovery_session_confirms_same_boot_and_source(self):
        path = self.directory / 'recovery.json'
        pending = path.with_name('challenge.json')
        pending.write_text(json.dumps({'schema': 1, 'machine_id': MACHINE, 'boot_id': BOOT, 'source_sha': SOURCE,
                                       'owner_checkout': str(self.entry.repo), 'created_at': int(time.time()), 'origin_session': 1001, 'code': 'test-code'}))
        pending.chmod(0o600)
        self.entry.original = Mock(return_value=self.identity)
        self.entry.app.ssh_ancestors.return_value = []
        records = []
        with (patch.object(day, 'ATTENDED_RECEIPT', str(path)), patch.object(day, 'kit_source', return_value=(SOURCE, False)),
              patch.object(day, 'secret_answer', return_value='test-code'), patch.dict(os.environ, {}, clear=True),
              patch.object(day, 'save', side_effect=lambda app, path, value: records.append(value)),
              patch.object(day.os, 'getsid', return_value=1001) as session):
            with self.assertRaisesRegex(bootstrap.Blocked, 'different current hPanel session'):
                self.entry.confirm_recovery(None, SOURCE)
            session.return_value = 1002
            self.entry.confirm_recovery(None, SOURCE)
        self.assertEqual(records[0]['kind'], bootstrap.ATTENDED_ACCESS)
        self.assertNotIn('code', records[0])
        self.assertEqual((records[0]['origin_session'], records[0]['confirmed_session']), (1001, 1002))
        self.assertNotIn('public_ssh_denied', records[0])

    def test_reboot_pause_resumes_same_source_without_second_host_or_core_setup(self):
        state = self.directory / 'state'
        boot = self.directory / 'bootstrap'
        boot.mkdir()
        desired = boot / 'desired.json'
        desired.write_text(json.dumps({'gptbox_context_sha256': 'a' * 64}))
        desired.chmod(0o600)
        self.entry.progress = state / 'progress.json'
        self.entry.original = Mock(return_value=self.identity)
        self.entry.ensure_git = Mock(return_value=SOURCE)
        self.entry.selinux = Mock(side_effect=[False, True, True])
        self.entry.transport = Mock(side_effect=[None, ['--bootstrap-source', '192.0.2.44/32'],
                                                   ['--bootstrap-source', '192.0.2.44/32']])
        self.entry.storage_geometry = Mock(return_value=(20480, 262144, 4096))
        self.entry.managed_storage = Mock()
        self.entry.inputs = Mock(return_value=('context', 'upstream', 'a' * 64))
        self.entry.prepare = Mock(return_value='b' * 64)
        self.entry.maintenance_receipt = Mock(return_value='b' * 64)
        self.entry.enroll = Mock(return_value=False)
        self.entry.app.status.side_effect = [{'prepared': False}, {'prepared': False}, {'prepared': False}, {'prepared': True}]

        def write(path, contents, **kwargs):
            target = Path(path)
            target.write_text(contents)
            target.chmod(0o600)

        original_stat = os.fstat

        def projected_stat(descriptor):
            node = original_stat(descriptor)
            return SimpleNamespace(st_uid=0, st_nlink=node.st_nlink, st_mode=node.st_mode)

        self.entry.app.atomic.side_effect = write
        with (patch.object(day, 'STATE', state), patch.object(day, 'BOOTSTRAP', str(boot)),
              patch.object(day, 'kit_source', return_value=(SOURCE, True)),
              patch.object(day, 'secure_directory', side_effect=lambda path: path.mkdir(exist_ok=True) or path),
              patch.object(day.os, 'fstat', side_effect=projected_stat),
              patch.object(day, 'answer', return_value='yes') as prompt,
              redirect_stdout(io.StringIO())):
            self.entry.start(None, None)
            self.entry.selinux.assert_not_called()
            self.entry.start(None, None)
            self.entry.prepare.assert_not_called()
            self.identity['boot_id'] = '11111111-2222-3333-4444-000000000000'
            self.entry.start(None, None)
            self.entry.start(None, None)
            prompt.assert_called_once()
            self.entry.prepare.assert_called_once()
            self.assertEqual(self.entry.maintenance_receipt.call_count, 2)
        record = json.loads(self.entry.progress.read_bytes())
        self.assertEqual(record['machine_id'], MACHINE)
        self.assertEqual(record['phase'], 'host-bootstrap-complete')
        self.assertNotIn('password', self.entry.progress.read_text())

    def test_normal_initializer_uses_the_verified_sanitized_checkout_and_ephemeral_core_password(self):
        boot = self.directory / 'bootstrap'
        boot.mkdir()
        password = 'fixture-private-core-input'
        ephemeral = self.directory / 'ephemeral'
        context = self.directory / 'extracted' / 'context'
        upstream = context.parent / 'distrobox'
        sanitized = context.parent / 'dev-pair'
        for checkout in (self.entry.repo, sanitized):
            (checkout / 'tools').mkdir(parents=True)
            for entry in ('bootstrap.py', 'gptbox.py'):
                (checkout / 'tools' / entry).write_text('exact ' + entry)
        seen = []
        probes = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': SOURCE, 'context_sha256': 'a' * 64,
                  'boundary_and_version_cycles': 2, 'runtime_container_removed': True, 'job_admission': False,
                  'assembled_image_id': 'b' * 64}

        @contextmanager
        def file(value):
            self.assertEqual(value, password)
            ephemeral.write_text(value)
            try:
                yield ephemeral
            finally:
                ephemeral.unlink()

        def call(name, *arguments, checkout, **kwargs):
            self.assertEqual(checkout, sanitized)
            if '--password-file' in arguments:
                self.assertTrue(ephemeral.exists())
            seen.append((name, *map(str, arguments)))
            return ({'phase': 'complete', 'maintenance_gptbox': 'complete', 'result': probes}
                    if name == 'bootstrap.py' else probes)

        self.entry.call = call
        with (patch.object(day, 'BOOTSTRAP', str(boot)), patch.object(day, 'secret_file', side_effect=file),
              patch.object(day, 'secret_answer', return_value=password) as prompt):
            input_paths = (context, upstream, 'a' * 64)
            initial = self.entry.prepare(SOURCE, ['--bootstrap-source', '192.0.2.44/32'], input_paths, None)
            self.assertEqual(initial, 'b' * 64)
            self.assertFalse(ephemeral.exists())
            prepared = self.entry.prepare(SOURCE, (), input_paths, None, already_prepared=True)
            self.assertEqual(prepared, initial)
            self.assertEqual(prompt.call_count, 2)
        self.assertEqual(seen[0][:2], ('bootstrap.py', 'initialize'))
        self.assertEqual(seen[1][:2], ('gptbox.py', 'assemble-prepared-maintenance'))
        self.assertNotIn(password, ' '.join(map(str, seen)))
        self.assertNotIn('--password-file', seen[1])
        with self.assertRaisesRegex(bootstrap.Blocked, 'both offline'):
            self.entry.probes({**probes, 'boundary_and_version_cycles': 1}, SOURCE, 'a' * 64)

    def test_enforcing_host_does_not_arm_relabel_or_reboot(self):
        self.entry.call = Mock(return_value={'live': 'Enforcing', 'persistent': 'enforcing', 'policy_present': True})
        with patch.object(day, 'ROOT', self.directory), patch.object(day, 'answer') as prompt:
            self.assertTrue(self.entry.selinux(self.identity, SOURCE, None))
        self.entry.call.assert_called_once_with('selinux_bootstrap.py', 'inspect')
        prompt.assert_not_called()

    def test_attended_guard_retains_existing_ssh_only_until_checked_cutover(self):
        temporary = bootstrap.Bootstrap.guard_rules([], retain_ssh=True)
        final = bootstrap.Bootstrap.guard_rules([], tailnet_only=True)
        self.assertIn('\nadd rule inet dev_pair_bootstrap input tcp dport 22 accept\n', temporary)
        self.assertNotIn('\nadd rule inet dev_pair_bootstrap input tcp dport 22 accept\n', final)
        self.assertIn('tcp dport { 22, 443 } drop', final)
        with self.assertRaises(bootstrap.Blocked):
            bootstrap.Bootstrap.guard_rules([], retain_ssh=True, tailnet_only=True)


    def test_admitted_sanitized_git_layout_from_normal_checkout(self):
        def commit(repo):
            for args in (('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                                        'commit', '-qm', 'owner source fixture')):
                subprocess.run(['/usr/bin/git', '-C', str(repo), *args], check=True)
            return subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()

        tree = Path(gptbox.__file__).resolve().parents[1]
        source = self.entry.repo
        (source / 'tools').mkdir(parents=True)
        for name in (*gptbox.ADAPTER_SOURCE_FILES, 'public_inputs.py'):
            (source / 'tools' / name).write_bytes((tree / 'tools' / name).read_bytes())
        runtime = source / 'runtime/devbox'
        runtime.mkdir(parents=True)
        (runtime / 'controller.py').write_bytes((tree / 'runtime/devbox/controller.py').read_bytes())
        revision = commit(source)
        upstream = self.directory / 'upstream'
        upstream.mkdir()
        for name in ('distrobox-init', 'distrobox-enter'):
            (upstream / name).write_text('fixture script\n')
        upstream_revision = commit(upstream)
        work = self.directory / 'work'
        (work / 'home').mkdir(parents=True)
        selected, distrobox = work / 'extracted/dev-pair', work / 'extracted/distrobox'
        for original, revision_pin, name, target in ((source, revision, 'dev-pair', selected),
                                                     (upstream, upstream_revision, 'distrobox', distrobox)):
            packed = work / name
            public_inputs.clean_checkout(original, revision_pin, packed, work)
            # The actual public-input handoff inventories files and recreates
            # the required ancestry. Stock Git's empty directories are omitted.
            for leaf in packed.rglob('*'):
                if leaf.is_file():
                    copy = target / leaf.relative_to(packed)
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    copy.write_bytes(leaf.read_bytes())
        app = gptbox.Gptbox(self.directory, lambda *args, **kwargs: subprocess.check_output(args, text=True))
        with (patch.object(gptbox, '__file__', str(selected / 'tools/gptbox.py')),
              patch.object(public_inputs, '__file__', str(selected / 'tools/public_inputs.py')),
              patch.object(gptbox, 'DBX_SHA', upstream_revision)):
            app.protect_host_sources(distrobox, revision)
            app.source(revision)
            self.assertFalse((selected / '.git/index').exists())
        self.assertEqual(subprocess.check_output(['/usr/bin/git', '-C', str(source), 'status', '--porcelain'], text=True), '')

    def test_physical_free_inodes_are_distinct_from_future_inner_capacity(self):
        from managed_backing import ParentSpace

        with (patch.object(day, 'record', return_value=None), patch.object(day.managed_backing, 'provisioning_space') as volume,
              redirect_stdout(io.StringIO())):
            volume.return_value = ParentSpace('ext4', 30 * 1024 * day.MIB, 6000)
            self.assertEqual(self.entry.storage_geometry(), (20480, 262144, 4096))
            volume.return_value = ParentSpace('ext4', 20 * 1024 * day.MIB, 6000)
            with self.assertRaisesRegex(bootstrap.Blocked, 'physical reserve'):
                self.entry.storage_geometry()
            volume.return_value = ParentSpace('btrfs', 30 * 1024 * day.MIB, None, 200 * day.MIB, 16384)
            self.assertEqual(self.entry.storage_geometry(), (20480, 262144, 4096))
            volume.return_value = ParentSpace('btrfs', 30 * 1024 * day.MIB, None, 100 * day.MIB, 16384)
            with self.assertRaisesRegex(bootstrap.Blocked, 'Btrfs metadata reserve'):
                self.entry.storage_geometry()

    def test_existing_relabel_marker_runs_the_lower_enforcing_gate(self):
        self.entry.call = Mock(side_effect=[{'live': 'Enforcing', 'persistent': 'enforcing', 'policy_present': True},
                                           bootstrap.Blocked('foreign relabel is pending')])
        self.entry.stage = Mock()
        with patch.object(day.os.path, 'lexists', side_effect=lambda path: str(path) == '/.autorelabel'):
            with self.assertRaisesRegex(bootstrap.Blocked, 'foreign relabel'):
                self.entry.selinux(self.identity, SOURCE, None)
        self.assertEqual(self.entry.call.call_args.args[1], 'converge')

    def authority_source(self):
        upstream = self.entry.repo
        (upstream / 'tools').mkdir(parents=True)
        original = Path(bootstrap.__file__).read_bytes()
        (upstream / 'tools/bootstrap.py').write_bytes(original)
        for args in (('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                                    'commit', '-qm', 'authority source fixture')):
            subprocess.run(['/usr/bin/git', '-C', str(upstream), *args], check=True)
        revision = subprocess.check_output(['/usr/bin/git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
        return upstream, revision

    @staticmethod
    def native_call(*args, **kwargs):
        return subprocess.run(args, text=True, input=kwargs.get('input_text'), capture_output=True, timeout=10, check=True).stdout

    @contextmanager
    def projected_root_ancestry(self):
        original = Path.lstat

        def projected(path):
            node = original(path)
            return SimpleNamespace(st_mode=node.st_mode & ~0o022, st_uid=0, st_nlink=node.st_nlink, st_size=node.st_size)

        with patch.object(Path, 'lstat', projected):
            yield

    def test_signed_provider_receipt_retains_its_closed_schema_and_git_authority(self):
        source, revision = self.authority_source()
        key = self.directory / 'issuer'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        allowed = self.directory / 'allowed-signers'
        principal = 'dev-pair-provider-console'
        allowed.write_text(principal + ' ' + key.with_suffix('.pub').read_text())
        receipt = self.directory / 'provider.json'
        app = bootstrap.Bootstrap(self.directory, self.native_call)
        app.destination_identity = Mock(return_value={'machine_id': MACHINE, 'boot_id': BOOT})
        fields = {'provider', 'provider_vps_id', 'transport', 'reopened_root', 'public_ssh_denied'}
        data = {'version': 1, 'source_sha': revision, 'machine_id': MACHINE, 'boot_id': BOOT, 'issued_at': int(time.time()),
                'expires_at': int(time.time()) + 300, 'provider': 'hostinger', 'provider_vps_id': 'fixture-vps',
                'transport': 'out-of-band', 'reopened_root': True, 'public_ssh_denied': True}

        def sign(value):
            receipt.write_text(json.dumps(value) + '\n')
            receipt.with_suffix('.json.sig').unlink(missing_ok=True)
            subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-q', '-n', 'dev-pair-destination', '-f', str(key),
                            str(receipt)], capture_output=True, check=True)

        with (self.projected_root_ancestry(), patch.object(bootstrap, '__file__', str(source / 'tools/bootstrap.py')),
              patch.object(bootstrap, 'TRUST_SIGNERS', '/allowed-signers')):
            sign(data)
            self.assertEqual(app.recent_destination_evidence(str(receipt), principal, fields, lifetime=7200), data)
            sign({**data, 'source_sha': 'a' * 40})
            with self.assertRaisesRegex(bootstrap.Blocked, 'source checkout differs'):
                app.recent_destination_evidence(str(receipt), principal, fields, lifetime=7200)
            sign({**data, 'owner_checkout': str(source)})
            with self.assertRaisesRegex(bootstrap.Blocked, 'evidence is stale'):
                app.recent_destination_evidence(str(receipt), principal, fields, lifetime=7200)

    def test_real_attended_authority_in_initialize_from_sanitized_no_index_source(self):
        source, revision = self.authority_source()
        work = self.directory / 'context'
        (work / 'home').mkdir(parents=True)
        sanitized = work / 'dev-pair'
        public_inputs.clean_checkout(source, revision, sanitized, work)
        self.assertFalse((sanitized / '.git/index').exists())
        receipt = self.directory / 'recovery.json'
        proof = {'schema': 1, 'kind': bootstrap.ATTENDED_ACCESS, 'source_sha': revision, 'machine_id': MACHINE,
                 'boot_id': BOOT, 'created_at': int(time.time()), 'origin_session': 1001, 'confirmed_session': 1002,
                 'owner_checkout': str(source)}
        receipt.write_text(json.dumps(proof))
        receipt.chmod(0o600)
        app = gptbox.Gptbox(self.directory, self.native_call)
        app.destination_identity = Mock(return_value={'machine_id': MACHINE, 'boot_id': BOOT})
        app.ssh_ancestor = Mock(return_value=False)
        app.preflight = Mock()
        app.check_gptbox_inputs = Mock(return_value=(None, None, {'source_sha': revision}))
        app.protected = lambda path: Path(path)
        mark = app.path(bootstrap.STATE + '/operator-password-set')
        mark.parent.mkdir(parents=True)
        mark.touch()
        context = 'b' * 64
        with (self.projected_root_ancestry(), patch.object(bootstrap, '__file__', str(sanitized / 'tools/bootstrap.py')),
              patch.object(bootstrap, 'ATTENDED_RECEIPT', str(receipt)), patch.dict(os.environ, {}, clear=True)):
            reply = app._initialize(str(work), context, str(work), revision, None, console_receipt=str(receipt))
            self.assertEqual(reply['preview'], 'initialize')
            self.assertTrue(app.attended_access)
            self.assertFalse((sanitized / '.git/index').exists())
            runner = Mock(side_effect=self.native_call)
            runner.phase.return_value = nullcontext()
            argv = ['gptbox.py', 'initialize', '--apply', '--context', str(work), '--expected-context-sha256', context,
                    '--distrobox-source', str(work), '--source-sha', revision, '--console-receipt', str(receipt)]
            with (patch.object(gptbox, 'Gptbox', return_value=app), patch.object(sys, 'argv', argv),
                  patch.object(app, 'run', runner),
                  patch.object(app, 'lock', side_effect=RuntimeError('physical state boundary')) as lock):
                with self.assertRaisesRegex(RuntimeError, 'physical state boundary'):
                    gptbox.main()
                lock.assert_called_once_with('initialize.lock')
            receipt.write_text(json.dumps({**proof, 'source_sha': 'a' * 40}))
            with self.assertRaisesRegex(bootstrap.Blocked, 'source checkout differs'):
                app._initialize(str(work), context, str(work), revision, None, console_receipt=str(receipt))


    def test_managed_listener_readiness_does_not_claim_an_owner_terminal(self):
        controller = self.entry.repo / 'tools/commission_host.py'
        controller.parent.mkdir(parents=True)
        controller.touch()
        self.entry.stage = Mock()
        self.entry.call = Mock(return_value={'phase': 'ready', 'owner_terminal': None, 'held_features': ['owner-intake']})
        self.entry.commission(self.identity, SOURCE)
        self.assertEqual(self.entry.stage.call_args.args[2], 'managed-listener-ready')
        self.assertIn('remain held', self.entry.stage.call_args.args[3])
        self.entry.call.return_value = {'phase': 'ready', 'owner_terminal': '/usr/local/bin/dev-pair', 'held_features': []}
        self.entry.commission(self.identity, SOURCE)
        self.assertEqual(self.entry.stage.call_args.args[2], 'owner-terminal-ready')

    def test_prepared_marker_cannot_bypass_an_interrupted_initializer_journal(self):
        state = self.directory / 'bootstrap'
        state.mkdir()
        expected = 'a' * 64
        journal = state / 'initialize.json'
        body = {'schema': 2, 'phase': 'maintenance-gptbox', 'maintenance_gptbox': 'blocked',
                'target': {'source_sha': SOURCE, 'context_sha256': expected},
                'native_units': ['dev-pair-initialize-adapter-1234abcd-5678efab']}
        journal.write_text(json.dumps(body))
        journal.chmod(0o600)
        self.entry.stage = Mock()
        access = ['--bootstrap-source', '192.0.2.44/32']
        self.entry.transport = Mock(return_value=access)
        paths = (self.directory / 'context', self.directory / 'upstream', expected)
        self.entry.inputs = Mock(return_value=paths)
        self.entry.maintenance_receipt = Mock(return_value='b' * 64)

        def initialize(*args, **kwargs):
            self.assertFalse(kwargs['already_prepared'])
            journal.write_text(json.dumps({**body, 'phase': 'complete', 'maintenance_gptbox': 'complete'}))
            return 'b' * 64

        self.entry.prepare = Mock(side_effect=initialize)
        with patch.object(day, 'BOOTSTRAP', str(state)):
            self.assertTrue(self.entry.resume_maintenance(self.identity, SOURCE, expected, None))
            self.entry.prepare.assert_called_once_with(SOURCE, access, paths, None, already_prepared=False)
            self.assertTrue(self.entry.resume_maintenance(self.identity, SOURCE, expected, None))
            self.entry.prepare.assert_called_once()
            self.entry.transport.assert_called_once()
            self.entry.inputs.assert_called_once()
            self.entry.maintenance_receipt.return_value = None
            with self.assertRaisesRegex(bootstrap.Blocked, 'completed initializer is missing'):
                self.entry.resume_maintenance(self.identity, SOURCE, expected, None)
