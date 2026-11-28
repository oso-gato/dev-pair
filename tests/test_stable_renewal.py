"""Exercise deliberate stable intake, local approval and durable role continuity."""
import copy
from base64 import b64encode
from contextlib import nullcontext
import hashlib
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import test_candidate_agent_observation as access_fixture
import test_platform_initial_intake as intake_fixture
import test_renewal as continuity_fixture

import bootstrap
import commission_host as commission
import destination_observation as observation
import platform_release_intake as intake
import platform_release_protocol as protocol
import renewal as r
import renewal_site as site
import stable_renewal as stable
from gptbox import image_inputs_bytes

MACHINE = 'f' * 32
BOOT = Path('/proc/sys/kernel/random/boot_id').read_text().strip()


class StablePublisherSelection(unittest.TestCase):
    def test_only_current_protected_full_publication_for_retained_base_is_selected(self):
        fixture = intake_fixture.InitialIntakeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old = '7' * 64
        fixture.add(17)
        fixture.add(18, previous='8' * 64)
        fixture.add(19, previous=old, expired=True)
        fixture.add(20, previous=old)
        fixture.add(21, previous=old)
        source, run, digest = intake.discover_full(None, old, fixture.end)
        self.assertEqual((source, run, digest), (fixture.source, 21, r.sha(protocol.canonical(fixture.indexes[21]))))
        self.assertEqual([call.args[3] for call in fixture.verify.call_args_list], [21] * 4 + [20] * 4)
        fixture.acquire.assert_not_called()
        fixture.add(22, previous=old, image='f' * 64)
        with self.assertRaisesRegex(protocol.Blocked, 'disagree'):
            intake.discover_full(None, old, fixture.end)
        fixture.branch['protected'] = False
        with self.assertRaisesRegex(protocol.Blocked, 'protected main'):
            intake.discover_full(None, old, fixture.end)


class NativeAuthority(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1]
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=parent)))
        self.control = self.root / 'renewal'
        self.config = self.root / 'config'
        self.hosts = self.root / 'host-releases'
        self.packages = self.root / 'platform-releases'
        for directory in (self.control, self.config, self.hosts, self.packages,
                          *(self.control / name for name in ('offers', 'requests', 'plans', 'releases', 'platform-bindings',
                                                            'platform-observations', 'attempts'))):
            directory.mkdir(mode=0o700)
        self.controller = r.Renewal(self.root, None)
        self.site = {'schema': 1, 'hostname': socket.gethostname(), 'jobs': {
            'job-1': {'storage_bytes': 8 * 1024**3, 'categories': {'inner': [10, 11], 'outer': [10, 11, 12]}}},
            'host_config_sha256': r.sha(b'exact retained host config')}
        self.site_sha = r.identity(self.site)
        (self.config / (self.site_sha + '.json')).write_bytes(r.json_bytes(self.site))
        (self.config / (self.site['host_config_sha256'] + '.json')).write_bytes(b'exact retained host config')
        self.reader = Mock()
        self.resolver = site.Resolver(self.controller, portable=self.packages, configs=self.config,
                                      hosts=self.hosts, host_configs=self.config, development_reader=self.reader)
        self.enterContext(patch.object(stable, 'machine_id', return_value=MACHINE))
        defaults = site.Resolver
        self.enterContext(patch.object(site, 'Resolver', side_effect=lambda controller, **opts:
                                       defaults(controller, portable=self.packages, configs=self.config,
                                                hosts=self.hosts, host_configs=self.config, development_reader=self.reader)))
        self.origin = self.package('a', 41)
        origin = self.resolver.resolve(self.offer('initial', self.origin, None), boot=BOOT)
        self.initial = origin['release_sha256']
        r.replace_json(self.control / 'current.json', self.initial)
        r.replace_json(self.control / 'site-current.json', self.initial)
        path = self.root / stable.POLICY
        path.parent.mkdir(parents=True)
        r.replace_json(path, {'schema': 1, 'source_sha': 'a' * 40, 'machine_id': MACHINE, 'platform_sha256': self.origin,
                              'site_config_sha256': self.site_sha, 'timers': [], 'checklist': {}})

    def offer(self, scope, platform_sha, previous):
        return {'schema': 2, 'scope': scope, 'operation': 'maintenance-window', 'platform_sha256': platform_sha,
                'previous_release_sha256': previous, 'site_config_sha256': self.site_sha, 'affected_jobs': ['job-1'],
                'reason': 'Review of the agreed platform repairs'}

    def package(self, source_digit, run, *, previous=None, agent=False, version='1.2.3'):
        source = source_digit * 40
        model = self.site
        ctl = type('Fixture', (), {'source': source})()
        index = intake_fixture.InitialIntakeTests.index(ctl, run, image=source_digit * 64, previous=previous)
        if agent:
            index.update(kind=site.AGENT, base_platform_sha256=self.origin)
            del index['components']['host'], index['components']['devbox']
            del index['transports']['host'], index['transports']['devbox']
        else:
            manifest = r.json_bytes({'source_revision': source})
            host_dig = r.sha(manifest)
            index['components']['host']['bundle_manifest_sha256'] = host_dig
            index['transports']['host']['files']['host-manifest.json'] = {'sha256': host_dig, 'bytes': len(manifest)}
            directory = self.hosts / host_dig
            directory.mkdir(mode=0o700)
            (directory / 'manifest.json').write_bytes(manifest)
        for role in ('maintenance-agent', 'development-agent'):
            index['components'][role]['codex_version'] = version
        inner_image = index['components']['development-agent']
        inner = {key: inner_image[key] for key in ('source_sha', 'context_sha256', 'archive_sha256', 'archive_bytes')}
        inner.update(image_id=inner_image['oci_config_sha256'], inputs_sha256='1' * 64, sealed_sha256='2' * 64,
                     diff_ids=['sha256:' + '3' * 64])
        files = {'development': r.json_bytes({'producer': inner}),
                 'maintenance': r.json_bytes({'producer': {'result_sha256': '4' * 64}})}
        for role, raw in files.items():
            index['transports'][role]['files']['part.json'] = {'sha256': r.sha(raw), 'bytes': len(raw)}
        raw = protocol.canonical(index)
        reference = r.sha(raw)
        directory = self.packages / reference
        directory.mkdir(mode=0o700)
        (directory / 'platform.json').write_bytes(raw)
        (directory / 'intake.json').write_bytes(protocol.canonical({'schema': 2, 'platform_sha256': reference,
            'source_sha': source, 'publisher_run': run, 'kind': index['kind']}))
        for role, member in files.items():
            part = directory / role
            part.mkdir()
            (part / 'part.json').write_bytes(member)
        claim = site.maintenance_claim(directory, index)
        proof = site.maintenance_path(self.root, claim, BOOT)
        proof.parent.mkdir(parents=True)
        proof.write_bytes(image_inputs_bytes({**claim, 'boot_id': BOOT}))
        proof.chmod(0o600)
        base_sha = self.origin if agent else reference
        base = self.resolver.index(base_sha)[1] if agent else index
        outer = base['components']['devbox']
        job = 'job-1'
        local = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': r.STANDARDS, 'job': job,
                 **model['jobs'][job], 'outer': {'source_sha': outer['source_sha'], 'image_id': outer['oci_config_sha256']},
                 'inner': inner}
        components = {role: {key: index['components'][name][key] for key in ('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256')}
                      for role, name in (('maintenance', 'maintenance-agent'), ('development', 'development-agent'))}
        components['maintenance']['result_sha256'] = r.sha(proof.read_bytes())
        components['development'].update(inner_sha256=r.sha(image_inputs_bytes(inner)),
                                         jobs={job: {'manifest_sha256': r.sha(r.json_bytes(local) + b'\n')}})
        components['devbox'] = {name: outer[name] for name in ('oci_config_sha256', 'oci_manifest_sha256')}
        components['host'] = {'manifest_sha256': base['components']['host']['bundle_manifest_sha256']}
        (directory / 'installed.json').write_bytes(protocol.canonical({'schema': 1, 'platform_sha256': reference,
            'base_platform_sha256': base_sha, 'site_config_sha256': self.site_sha, 'boot_id': BOOT,
            'source_sha': source, 'components': components}))
        return reference

    def agent(self):
        agent_package = self.package('b', 42, previous=self.origin, agent=True, version='1.2.4')
        agent = self.resolver.resolve(self.offer('agent', agent_package, self.initial), boot=BOOT)['release_sha256']
        r.replace_json(self.control / 'current.json', agent)
        r.replace_json(self.control / 'site-current.json', agent)
        return agent_package, agent

    def test_stable_preserves_actual_nightly_rollback_and_holds_foreign_or_incomplete_scope(self):
        agent_package, agent = self.agent()
        successor = self.package('c', 43, previous=self.origin, version='1.2.4')
        for offer in (self.offer('stable', successor, self.initial),
                      {**self.offer('stable', successor, agent), 'affected_jobs': []}):
            with self.assertRaisesRegex(ValueError, 'exact live predecessor and all affected jobs'):
                self.resolver.resolve(offer, boot=BOOT)
        with self.assertRaisesRegex(ValueError, 'distinct portable agent'):
            self.resolver.resolve(self.offer('agent', successor, agent), boot=BOOT)
        wrong = self.package('d', 44, previous=agent_package, version='1.2.4')
        with self.assertRaisesRegex(ValueError, 'retained stable base'):
            self.resolver.resolve(self.offer('stable', wrong, agent), boot=BOOT)
        downgrade = self.package('e', 45, previous=self.origin)
        with self.assertRaisesRegex(ValueError, 'regresses selected agent'):
            self.resolver.resolve(self.offer('stable', downgrade, agent), boot=BOOT)
        offer = self.offer('stable', successor, agent)
        target = self.resolver.resolve(offer, boot=BOOT)['release_sha256']
        approval = stable.for_release(self.controller, target)
        self.assertEqual((approval['previous_base_platform_sha256'], approval['previous_platform_sha256'],
                          approval['previous_release_sha256']), (self.origin, agent_package, agent))
        self.assertEqual(self.controller.live_release(), agent)
        stable.lineage(self.resolver, successor, self.origin, self.site_sha, MACHINE)
        self.assertEqual(set(self.controller.release(target)['components']), r.COMPONENTS)
        r.replace_json(self.control / stable.OFFER, offer)
        request = {'schema': 1, 'scope': 'stable', 'operation': offer['operation'], 'previous_sha256': agent,
                   'target_sha256': target, 'affected_jobs': offer['affected_jobs'], 'reason': offer['reason']}
        approval = {'schema': 1, 'offer_sha256': r.identity(offer), 'request': request}
        r.replace_json(self.control / stable.REQUEST, approval)
        self.assertEqual(self.controller.active_request('stable'), request)
        scope = {**offer, 'reason': 'Changed after approval'}
        r.replace_json(self.control / stable.OFFER, scope)
        with self.assertRaisesRegex(ValueError, 'changed or was withdrawn'):
            self.controller.active_request('stable')

    def test_day0_checks_an_installed_stable_successor_without_reapplying_old_source_bytes(self):
        successor = self.package('c', 43, previous=self.origin)
        target = self.resolver.resolve(self.offer('stable', successor, self.initial), boot=BOOT)['release_sha256']
        transition = self.enterContext(patch.object(self.controller, 'transition', return_value=(None, None)))
        self.enterContext(patch.object(self.controller, 'host_fence', return_value=nullcontext()))
        services = Mock()
        identity = {'machine_id': MACHINE, 'boot_id': BOOT}
        services.identity.return_value = identity
        services.renewal.return_value = self.controller
        services.verify_selection.side_effect = lambda _, selected, policy: stable.local_binding(
            self.resolver, selected, policy['site_config_sha256'])
        commissioner = commission.Commission(self.root, self.root, Mock(), self.root.stat().st_uid, services)
        commissioner.path = lambda name: self.root / name.removeprefix('/var/lib/dev-pair/').lstrip('/')
        commissioner.inspect = Mock(return_value=identity)
        commissioner.package = Mock(side_effect=AssertionError('stable recheck tried to package original source'))
        policy_path = self.root / stable.POLICY
        policy = r.read_json(policy_path)
        policy['checklist'] = {'tls_profile': commission.CHECKLIST_SERVER, **commission.DEFAULT_CHECKLIST}
        policy_path.write_bytes(commission.encoded(policy))
        original = policy_path.read_bytes()
        driver = self.root / 'legacy-fixed-driver'
        driver.write_bytes(b'exact previous fixed bytes')

        (self.control / 'transition.json').touch()
        transition.return_value = (None, {'phase': 'applying', 'request': {'scope': 'stable'}})
        with self.assertRaisesRegex(commission.Pending, 'stable-release-recovery'):
            commissioner.automatic('apply', 'a' * 40)
        transition.return_value = (None, {'phase': 'completed', 'request': {'scope': 'stable'}})
        for selector in ('current', 'site-current'):
            r.replace_json(self.control / (selector + '.json'), target)
        report = commissioner.automatic('apply', 'c' * 40)
        self.assertEqual((report['phase'], report['selected_release']), ('ready', target))
        self.assertEqual(set(report['held_features']), set(commission.TIMERS))
        self.assertEqual(policy_path.read_bytes(), original)
        self.assertEqual(driver.read_bytes(), b'exact previous fixed bytes')

    def test_frozen_readback_requires_the_original_offer_and_only_its_exact_participants(self):
        successor = self.package('c', 43, previous=self.origin)
        offer = self.offer('stable', successor, self.initial)
        target = self.resolver.resolve(offer, boot=BOOT)['release_sha256']
        request = {'schema': 1, 'scope': 'stable', 'operation': offer['operation'], 'previous_sha256': self.initial,
                   'target_sha256': target, 'affected_jobs': offer['affected_jobs'], 'reason': offer['reason']}
        r.replace_json(self.control / stable.OFFER, offer)
        r.replace_json(self.control / stable.REQUEST, {'schema': 1, 'offer_sha256': r.identity(offer), 'request': request})
        attempt = self.control / 'attempts' / offer['operation']
        attempt.mkdir(mode=0o700)
        state = {'schema': 1, 'phase': 'verifying', 'attempt_id': attempt.name, 'request': request}
        (self.root / 'renewal-fence').mkdir()
        r.replace_json(self.root / 'renewal-fence/frozen', attempt.name)
        newer_boot = '12345678-1234-4234-8123-123456789abd'
        with patch.object(stable, 'forward_started', return_value=True):
            self.assertEqual(stable.frozen_request(self.controller, attempt, state, BOOT, newer_boot), request)
            r.replace_json(self.control / 'site-current.json', 'f' * 64)
            with self.assertRaisesRegex(ValueError, 'selectors escaped'):
                stable.frozen_request(self.controller, attempt, state, BOOT, newer_boot)
            r.replace_json(self.control / 'site-current.json', self.initial)
            r.replace_json(self.control / stable.OFFER, {**offer, 'reason': 'unapproved different purpose'})
            with self.assertRaisesRegex(ValueError, 'changed or was withdrawn'):
                stable.frozen_request(self.controller, attempt, state, BOOT, newer_boot)


class StableContinuity(unittest.TestCase):
    def setUp(self):
        self.fx = continuity_fixture.RenewalTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.controller = self.fx.renewal
        self.target = self.target_release()
        self.operation = 'stable-fixture-window'
        self.offer = {'schema': 2, 'scope': 'stable', 'operation': self.operation, 'platform_sha256': 'b' * 64,
                      'previous_release_sha256': self.fx.prior, 'site_config_sha256': 'a' * 64,
                      'affected_jobs': ['product'], 'reason': 'Deliberate reviewed stable update'}
        r.replace_json(self.fx.control / stable.OFFER, self.offer)
        r.replace_json(self.fx.control / 'site-current.json', self.fx.prior)
        grant = {'target_release_sha256': self.target}
        self.enterContext(patch.object(stable, 'binding', return_value=grant))
        self.enterContext(patch.object(stable, 'bound_request', return_value=grant))
        self.enterContext(patch.object(stable, 'active_request', side_effect=lambda _, approval: approval['request']))
        self.observer = Mock()
        self.observer.recover_request.return_value = None
        self.enterContext(patch.object(stable, 'access', return_value=self.observer))
        self.install = self.enterContext(patch.object(stable, 'reviewed_driver', return_value=self.controller.driver))

    def target_release(self):
        selected = copy.deepcopy(self.controller.release(self.fx.prior))
        selected.update(source_revision='b' * 40, plan_sha256='b' * 64)
        for name, value in selected['components'].items():
            value.update(source_revision='b' * 40, artifact_sha256='b' * 64)
            if name != 'host':
                value['config_sha256'] = 'b' * 64
        target = r.identity(selected)
        r.replace_json(self.fx.control / 'releases' / (target + '.json'), selected)
        return target

    def test_deliberate_stable_uses_existing_exact_job_and_session_recovery(self):
        old = self.controller.driver
        obsolete = self.fx.root / 'obsolete-fixed-driver'
        obsolete.write_text('#!/bin/sh\nexit 99\n')
        obsolete.chmod(0o700)
        self.controller.driver = r.SiteDriver(obsolete)
        with self.assertRaisesRegex(ValueError, 'exact prepared'):
            stable.apply(self.controller, 'other-window')
        state = stable.apply(self.controller, self.operation)
        self.assertEqual((state['phase'], state['request']['scope']), ('completed', 'stable'))
        self.assertEqual(self.controller.driver.path, old.path)
        self.assertEqual(obsolete.read_text(), '#!/bin/sh\nexit 99\n')
        self.fx.assert_sessions_preserved(state, self.target)

    def test_broken_replacement_without_persistent_fixed_change_rolls_back(self):
        (self.fx.root / 'disrupt-release').write_text(self.target)
        state = stable.apply(self.controller, self.operation)
        self.assertEqual(state['phase'], 'rolled-back')
        self.fx.assert_sessions_preserved(state, self.fx.prior)

    def test_irreversible_exact_forward_change_retries_once_under_the_same_job_fence(self):
        original = self.controller.verify_driver
        attempts = []

        def fail_after_fixed(action, state, release):
            if action == 'activate':
                attempts.append(release)
                if len(attempts) == 1:
                    raise ValueError('fixture interruption after fixed-file publication')
            return original(action, state, release)

        with patch.object(stable, 'forward_started', return_value=True), \
                patch.object(self.controller, 'verify_driver', side_effect=fail_after_fixed):
            state = stable.apply(self.controller, self.operation)
        self.assertEqual((state['phase'], state['forward_attempts']), ('completed', 1))
        self.assertEqual(attempts, [self.target, self.target])
        self.fx.assert_sessions_preserved(state, self.target)

    def test_current_boot_access_wait_does_not_spend_a_forward_effect_attempt(self):
        original = self.controller.verify_driver
        pending = {'boot_id': '12345678-1234-4234-8123-123456789abc', 'scope': 'fixture recovery'}
        self.observer.recover_request.return_value = pending
        self.observer.fresh.side_effect = [None, None, FileNotFoundError('fresh proof'), None]
        attempted = []

        def fail_once(action, state, release):
            if action == 'activate':
                attempted.append(release)
                if len(attempted) == 1:
                    raise ValueError('fixture interruption after published fixed state')
            return original(action, state, release)

        with (patch.object(stable, 'forward_started', return_value=True),
              patch.object(self.controller, 'verify_driver', side_effect=fail_once)):
            paused = stable.apply(self.controller, self.operation)
            self.assertEqual(paused['phase'], 'verifying')
            self.assertEqual(paused['forward_access_pending']['request_sha256'], r.sha(observation.encoding(pending)))
            self.assertNotIn('forward_attempts', paused)
            self.assertEqual(r.read_json(self.fx.root / 'renewal-fence/frozen'), paused['attempt_id'])
            state = stable.apply(self.controller, self.operation)
        self.assertEqual((state['phase'], state['forward_attempts']), ('completed', 1))
        self.assertEqual(attempted, [self.target, self.target])
        self.fx.assert_sessions_preserved(state, self.target)

    def test_nightly_request_cannot_select_a_stable_target(self):
        self.fx.request(self.target, scope='agent', operation='agent-approved')
        with self.assertRaisesRegex(ValueError, 'outside approved scope'):
            self.controller.apply('agent')
        self.assertEqual(self.controller.live_release(), self.fx.prior)


class IndependentStableAccess(unittest.TestCase):
    def test_original_signature_is_retained_but_a_new_boot_requires_its_own_signed_recovery(self):
        fixture = access_fixture.CandidateObservation()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old, target = fixture.previous, fixture.reference
        operation = 'stable-' + 'a' * 48
        new_boot = '12345678-1234-4234-8123-123456789abd'
        fixture.releases[target]['components']['host']['artifact_sha256'] = '8' * 64
        fixture.releases[target]['components']['devbox']['artifact_sha256'] = '9' * 64
        observer = site.CandidateAccess(fixture.controller, fixture.host, kind=observation.STABLE_CANDIDATE)
        grant = {'previous_release_sha256': old, 'operation': operation}
        approver = fixture.gen_key('recovery-stable-reviewer')
        stable_trust = observation.stable_signer(approver.with_suffix('.pub').read_text())
        plan = bootstrap.Bootstrap.access_probe_plan(fixture.route['dns_name'], fixture.guard['provider_recovery'],
                                                     fixture.guard['public_addresses'])
        fixture.host.access_probe_plan.return_value = plan
        fixture.host.verify_access_probes.side_effect = bootstrap.Bootstrap().verify_access_probes

        def sign(body, signer, namespace):
            payload = observation.encoding(body)
            signature = subprocess.check_output(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(signer), '-n', namespace],
                                                input=payload, stderr=subprocess.DEVNULL, timeout=5)
            return payload, signature

        def signed(binding, *, legacy=False):
            now = int(time.time())
            body = {key: value for key, value in binding.items() if key != 'job_id'}
            probes = [{'test': test, 'family': family, 'endpoint': endpoint, 'vantage': vantage,
                       'client_id': 'client-' + vantage, 'outcome': outcome, 'observed_at': now, 'evidence_sha256': 'e' * 64}
                      for (test, family), (endpoint, vantage, outcome) in plan.items()]
            body.update(issued_at=now, expires_at=now + 300, probes=probes, execution_route='tailnet-core',
                        acl_sha256=fixture.guard['acl_sha256'], provider_recovery=fixture.guard['provider_recovery'],
                        public_addresses=fixture.guard['public_addresses'])
            if not legacy:
                request_id = r.sha(observation.encoding(binding))
                approval = {'kind': 'approve-stable-workload', 'version': 1, 'request_sha256': request_id,
                            'machine_id': binding['machine_id'], 'boot_id': binding['boot_id'],
                            'approved_at': now, 'expires_at': binding['candidate']['requested_at'] + 3600}
                measurements = []
                for role in observation.AGENT_ROLES:
                    for family in observation.FAMILIES:
                        reading = observation.expected_role_probe(binding, role + '-authorized', family)
                        reading.update(challenge_sha256=r.identity([binding['boot_id'], role, family]),
                                       runtime_result_sha256='7' * 64)
                        measurements.append({'role': role, 'family': family, 'reading': reading, 'observed_at': now})
                _, collector = sign({'request_sha256': request_id, 'readings': measurements}, fixture.authorized,
                                    observation.NAMESPACE)
                policy = {'method': 'tailscale-policy-api-v2', 'sha256': fixture.guard['acl_sha256'],
                          'request_sha256': request_id, 'boot_id': binding['boot_id'], 'observed_at': now}
                grant_wire = observation.access_envelope(*sign(approval, approver, observation.STABLE_NAMESPACE))
                body.update(probes=measurements, observation='named-stable-challenges',
                            collector_signature=b64encode(collector).decode(), policy_measurement=policy,
                            stable_approval=b64encode(grant_wire).decode())
            return observation.access_envelope(*sign(body, fixture.reviewer, observation.FINAL_NAMESPACE))

        with (patch.object(stable, 'for_release', return_value=grant),
              patch.object(stable, 'forward_started', return_value=True),
              patch.object(observation, 'stable_host_trust', return_value=stable_trust),
              patch.object(stable, 'frozen_request') as checked):
            origin = observer.prepare(grant, target)
            old_wire = signed(origin, legacy=True)
            retained = observer.proof_path(target)
            r.replace_json(retained, {'envelope': old_wire.decode('ascii'), 'accepted_at': int(time.time())})
            before = hashlib.sha256(retained.read_bytes()).hexdigest()
            fixture.attempt = fixture.root / 'attempt'
            fixture.attempt.mkdir(mode=0o700)
            fixture.journal = {'schema': 1, 'phase': 'applying', 'attempt_id': fixture.attempt.name,
                               'request': {'scope': 'stable', 'target_sha256': target,
                                           'previous_sha256': old, 'operation': operation}}
            (fixture.root / 'renewal-fence').mkdir()
            r.replace_json(fixture.root / 'renewal-fence/frozen', fixture.attempt.name)
            self.assertIsNone(observer.recover_request())
            fixture.identity['boot_id'] = new_boot
            recovery = observer.recover_request()
            checked.assert_called_once_with(fixture.controller, fixture.attempt, fixture.journal, origin['boot_id'], new_boot)
            self.assertEqual(recovery['boot_id'], new_boot)
            self.assertEqual(recovery['role_artifacts'], origin['role_artifacts'])
            self.assertEqual(recovery['candidate']['operation'], operation)
            with self.assertRaisesRegex(ValueError, 'distinct attended'):
                observer.receive(old_wire, recovery)
            with self.assertRaisesRegex(ValueError, 'different request or boot'):
                observer.receive(signed(origin), recovery)
            observer.receive(signed(recovery), recovery)
            observer.accept(target, operation)
            self.assertIsNotNone(r.read_json(observer.recovery_proof_path(observer.recovery_context()))['accepted_at'])
            self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), before)
            self.assertEqual(r.read_json(observer.pending), origin)

    def test_daily_collector_cannot_approve_the_exact_stable_window(self):
        from base64 import b64encode
        from io import BytesIO

        import day0_access_exchange as courier

        fixture = access_fixture.CandidateObservation()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old, target = fixture.previous, fixture.reference
        operation = 'stable-' + 'a' * 48
        fixture.releases[target]['components']['host']['artifact_sha256'] = '8' * 64
        fixture.releases[target]['components']['devbox']['artifact_sha256'] = '9' * 64
        observer = site.CandidateAccess(fixture.controller, fixture.host, kind=observation.STABLE_CANDIDATE)
        grant = {'previous_release_sha256': old, 'operation': operation}
        plan_key = fixture.gen_key('attended-plan')
        stable_trust = observation.stable_signer(plan_key.with_suffix('.pub').read_text())
        with patch.object(stable, 'for_release', return_value=grant), \
                patch.object(observation, 'stable_host_trust', return_value=stable_trust):
            pending = observer.prepare(grant, target)
            now = int(time.time())
            raw = observation.encoding(pending)
            request_id = r.sha(raw)
            approval = {'kind': 'approve-stable-workload', 'version': 1, 'request_sha256': request_id,
                        'machine_id': pending['machine_id'], 'boot_id': pending['boot_id'],
                        'approved_at': now, 'expires_at': pending['candidate']['requested_at'] + 3600}

            def sign(value, signer, namespace):
                payload = observation.encoding(value)
                return payload, subprocess.check_output(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(signer),
                    '-n', namespace], input=payload, stderr=subprocess.DEVNULL, timeout=5)

            probes = []
            for role in observation.AGENT_ROLES:
                for family in observation.FAMILIES:
                    reading = observation.expected_role_probe(pending, role + '-authorized', family)
                    reading.update(challenge_sha256=r.identity([role, family]), runtime_result_sha256='7' * 64)
                    probes.append({'role': role, 'family': family, 'reading': reading, 'observed_at': now})
            _, collector = sign({'request_sha256': request_id, 'readings': probes}, fixture.authorized,
                                observation.NAMESPACE)
            policy = {'method': 'tailscale-policy-api-v2', 'sha256': fixture.guard['acl_sha256'],
                      'request_sha256': request_id, 'boot_id': pending['boot_id'], 'observed_at': now}
            body = {key: value for key, value in pending.items() if key != 'job_id'}
            body.update(issued_at=now, expires_at=now + 300, probes=probes, execution_route='tailnet-core',
                        acl_sha256=fixture.guard['acl_sha256'], provider_recovery=fixture.guard['provider_recovery'],
                        public_addresses=fixture.guard['public_addresses'], observation='named-stable-challenges',
                        collector_signature=b64encode(collector).decode(), policy_measurement=policy)

            def wire(approver):
                approval_wire = observation.access_envelope(*sign(approval, approver, observation.STABLE_NAMESPACE))
                complete = {**body, 'stable_approval': b64encode(approval_wire).decode()}
                return observation.access_envelope(*sign(complete, fixture.reviewer, observation.FINAL_NAMESPACE))

            nightly = {**body, 'observation': 'named-candidate-challenges'}
            with self.assertRaisesRegex(ValueError, 'distinct attended'):
                observer.receive(observation.access_envelope(*sign(nightly, fixture.reviewer, observation.FINAL_NAMESPACE)), pending)
            with self.assertRaisesRegex(bootstrap.Blocked, 'invalid independent signature'):
                observer.receive(wire(fixture.reviewer), pending)
            response = wire(plan_key)
            mailbox = fixture.root / 'mailbox'
            mailbox.mkdir(mode=0o700)
            command = 'day0-access-v1 ' + request_id
            waiting = BytesIO()
            courier.receive(mailbox, command, BytesIO(raw), waiting, now)
            self.assertEqual(waiting.getvalue(), b'')
            with patch.object(observation, 'stable_station_trust', return_value=stable_trust), \
                    patch.object(observation, 'station_signing', return_value={
                        'reviewer_key': fixture.reviewer, 'collector_key': fixture.authorized}), \
                    patch.object(observation, 'current_station_signer', side_effect=lambda key, namespace:
                        ('dev-pair-access-review' if key == fixture.reviewer else 'dev-pair-observer-authorized',
                         fixture.signers)):
                courier.publish(mailbox, request_id, BytesIO(response), now)
            received = BytesIO()
            courier.receive(mailbox, command, BytesIO(raw), received, now)
            observer.receive(received.getvalue(), pending)
            self.assertIsNone(observer.admitted(target, fixture.guard))
            self.assertFalse(fixture.access.proof_path(target).exists())
            fixture.journal = {'phase': 'applying', 'request': {'scope': 'stable', 'target_sha256': target,
                                                                'previous_sha256': old, 'operation': operation}}
            fixture.attempt = Path('attempt')
            (fixture.root / 'renewal-fence').mkdir()
            r.replace_json(fixture.root / 'renewal-fence/frozen', fixture.attempt.name)
            observer.accept(target, operation)
            self.assertEqual(observer.admitted(target, fixture.guard)['role_artifacts'], pending['role_artifacts'])


if __name__ == '__main__':
    unittest.main()
