import contextlib
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import agent_release_bridge as bridge

SOURCE = '1' * 40
BASE = '2' * 64
SITE = '3' * 64


def timestamp(day, hour, minute=0):
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


def release(run, version, binary, image, *, schema=3, previous=None):
    components = {}
    for role in ('maintenance-agent', 'development-agent'):
        components[role] = {'codex_version': version, 'codex_source_sha': SOURCE, 'codex_sha256': binary * 64,
                            'oci_manifest_sha256': image * 64}
    return bridge.Candidate(run, SOURCE, format(run, '064x'), {'schema': schema, 'kind': 'dev-pair-agent-release',
                           'base_platform_sha256': BASE, 'previous_platform_sha256': previous, 'components': components})


def run_row(identifier, date, **overrides):
    repo = {'full_name': bridge.REPOSITORY}
    return {'id': identifier, 'head_sha': SOURCE, 'head_branch': 'main', 'event': 'schedule', 'status': 'completed',
            'conclusion': 'success', 'run_attempt': 1, 'path': '.github/workflows/agent-refresh.yml',
            'repository': repo, 'head_repository': repo, 'created_at': date.strftime('%Y-%m-%dT%H:%M:%SZ'), **overrides}


class LocalSite(bridge.Site):
    """Exercise both bridge lock phases, with bounded stand-ins for F and U effects."""
    def __init__(self, directory, current):
        self.binding = self.binding_for(current)
        self.current = current
        self.state = None
        self.candidate = None
        self.offer = directory / 'offer.json'
        self.controller = SimpleNamespace(lock=self.lock)
        self.site = SimpleNamespace(offer_record=lambda offer, scope: offer)
        self.renewal = SimpleNamespace(read_json=lambda path: json.loads(path.read_bytes()),
                                       replace_json=lambda path, value: path.write_text(json.dumps(value)))
        self.resolver = SimpleNamespace(resolve=self.resolve)
        self.trace = []
        self.locked = False
        self.race = None

    def binding_for(self, value):
        return {'release_sha256': format(value.run + 100000, '064x'), 'platform_sha256': value.digest,
                'base_platform_sha256': BASE, 'site_config_sha256': SITE}

    @contextlib.contextmanager
    def lock(self):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    @contextlib.contextmanager
    def lease(self):
        yield

    def live(self):
        assert self.locked
        return self.binding, self.current.index

    def transition(self):
        assert self.locked
        return 'ready', self.state

    def discover(self, window):
        assert not self.locked
        self.trace.append(('discover', window[2]))
        return self.candidate

    def stage(self, candidate, binding):
        assert not self.locked
        self.trace.append(('verify-and-install', candidate.run, binding['platform_sha256']))
        if self.race:
            self.current = self.race
            self.binding = self.binding_for(self.race)

    def resolve(self, offer):
        assert self.locked
        self.trace.append(('resolve', offer['previous_release_sha256']))

    def dispatch(self):
        assert not self.locked and self.offer.is_file()
        self.trace.append(('reconcile', json.loads(self.offer.read_bytes())['platform_sha256']))

    def accept(self):
        self.binding = self.binding_for(self.candidate)
        self.current = self.candidate


class AgentBridgeTests(unittest.TestCase):
    def test_nightly_window_and_later_readback(self):
        self.assertIsNone(bridge.selection_window(timestamp(26, 18, 59), False))
        begin = timestamp(26, 19)
        first = bridge.selection_window(begin, False)
        later = bridge.selection_window(timestamp(26, 22), False)
        self.assertEqual(first, (begin, begin, 'schedule'))
        self.assertEqual(later, (begin, timestamp(26, 22), 'schedule'))
        self.assertIsNone(bridge.selection_window(timestamp(27, 0, 16), False))
        self.assertEqual(bridge.selection_window(timestamp(27, 11), True)[2], 'workflow_dispatch')

    def test_discovery_rejects_other_event_fork_attempt_time_and_source(self):
        window = bridge.selection_window(timestamp(26, 22), False)
        good = run_row(7, timestamp(26, 19, 5))
        later = run_row(8, timestamp(26, 19, 8))
        rows = [good, later, {**later, 'id': 9, 'run_attempt': 2}, {**later, 'id': 10, 'event': 'workflow_dispatch'},
                {**later, 'id': 11, 'head_repository': {'full_name': 'foreign/dev-pair'}},
                {**later, 'id': 12, 'head_sha': '7' * 40}, run_row(13, timestamp(26, 18))]
        self.assertEqual(bridge.publisher_runs({'workflow_runs': rows}, SOURCE, window), [8, 7])
        with self.assertRaisesRegex(bridge.BridgeError, 'ambiguous'):
            bridge.publisher_runs({'workflow_runs': [good, good]}, SOURCE, window)

    def test_two_nights_bind_current_local_predecessor_after_delayed_build(self):
        with tempfile.TemporaryDirectory() as directory:
            initial = release(1, '0.169.0', '4', '5')
            first = release(2, '0.170.0', '6', '7')
            second = release(3, '0.171.0', '8', '9')
            site = LocalSite(Path(directory), initial)
            for day, prior, candidate in [(26, initial, first), (27, first, second)]:
                site.candidate = None
                initial_window = bridge.selection_window(timestamp(day, 19), False)
                self.assertEqual(site.cycle(initial_window)['status'], 'awaiting-publication')
                site.candidate = candidate
                later_window = bridge.selection_window(timestamp(day, 21, 30), False)
                self.assertEqual(site.cycle(later_window)['status'], 'queued')
                offer = json.loads(site.offer.read_text())
                self.assertEqual(offer['previous_release_sha256'], site.binding_for(prior)['release_sha256'])
                self.assertEqual(offer['platform_sha256'], candidate.digest)
                self.assertIn(('verify-and-install', candidate.run, prior.digest), site.trace)
                self.assertEqual(site.trace[-1], ('reconcile', candidate.digest))
                site.accept()
                self.assertEqual(site.cycle(later_window)['status'], 'no-new-image')

    def test_requires_new_eligible_signed_identity_and_keeps_legacy_exact_chain(self):
        original = release(1, '0.169.0', '4', '5')
        binding = {'base_platform_sha256': BASE, 'platform_sha256': original.digest}
        with self.assertRaisesRegex(bridge.BridgeError, 'same stable version'):
            bridge.eligible(release(2, '0.169.0', '6', '7'), binding, original.index)
        with self.assertRaisesRegex(bridge.BridgeError, 'roll back'):
            bridge.eligible(release(3, '0.168.0', '6', '7'), binding, original.index)
        with self.assertRaisesRegex(bridge.BridgeError, 'stale signed predecessor'):
            bridge.eligible(release(4, '0.170.0', '6', '7', schema=2, previous='a' * 64), binding, original.index)
        self.assertTrue(bridge.eligible(release(5, '0.170.0', '6', '7', schema=2, previous=original.digest),
                                         binding, original.index))
        self.assertTrue(bridge.eligible(release(6, '0.169.0', '4', '7'), binding, original.index))

    def test_predecessor_race_never_publishes_offer_or_dispatches(self):
        with tempfile.TemporaryDirectory() as directory:
            first = release(1, '0.169.0', '4', '5')
            site = LocalSite(Path(directory), first)
            site.candidate = release(2, '0.170.0', '6', '7')
            site.race = release(3, '0.171.0', '8', '9')
            result = site.cycle(bridge.selection_window(timestamp(26, 21), False))
            self.assertEqual(result['status'], 'predecessor-changed')
            self.assertFalse(site.offer.exists())
            self.assertEqual([item[0] for item in site.trace], ['discover', 'verify-and-install'])


if __name__ == '__main__':
    unittest.main()
