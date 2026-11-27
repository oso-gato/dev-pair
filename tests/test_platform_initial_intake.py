import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import platform_release_intake as intake
from platform_release_protocol import ARCHIVE_LIMIT, Blocked, COMPONENT, ROLES, STANDARDS, canonical


class InitialIntakeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.portable = self.root / 'platform-releases'
        self.portable.mkdir()
        self.source = 'a' * 40
        self.end = time.monotonic() + 20
        self.branch = {'protected': True, 'commit': {'sha': self.source}}
        self.runs, self.indexes, self.asset_rows = [], {}, {}
        self.rechecked = []
        self.owner = os.getuid()
        volume = (self.portable.stat().st_dev, 173, 20 * ARCHIVE_LIMIT, ('37',))
        self.enterContext(mock.patch.object(intake, 'ROOT', self.portable))
        self.enterContext(mock.patch.object(intake, 'GITHUB', '/usr/bin/python3'))
        self.enterContext(mock.patch.object(intake, 'protected', side_effect=lambda path, **_: path))
        self.enterContext(mock.patch.object(intake, 'intake_limit'))
        self.enterContext(mock.patch.object(intake, 'portable_volume', return_value=volume))
        self.enterContext(mock.patch.object(intake, 'read_api', side_effect=self.api))
        self.enterContext(mock.patch.object(intake, 'fetch_artifact', side_effect=self.fetch))
        self.verify = self.enterContext(mock.patch.object(intake, 'verify_subject'))
        self.acquire = self.enterContext(mock.patch.object(intake, 'acquire', side_effect=self.selected))
        self.enterContext(mock.patch.object(intake.os, 'getuid', return_value=0))
        self.enterContext(mock.patch.object(intake.os, 'geteuid', return_value=0))
        ordinary = intake.release.readonly_json
        self.enterContext(mock.patch.object(intake.release, 'readonly_json', side_effect=lambda path, _owner=None:
                              ordinary(path, self.owner)))

    def index(self, run, *, image='e' * 64, previous=None):
        host = {'source_sha': self.source, 'bundle_manifest_sha256': '1' * 64}
        images = {'source_sha': self.source, 'context_sha256': '2' * 64, 'oci_config_sha256': image,
                  'oci_manifest_sha256': '3' * 64, 'archive_sha256': '4' * 64, 'archive_bytes': 8192}
        tooling = {'codex_version': '1.2.3', 'codex_source_sha': '5' * 40, 'codex_sha256': '6' * 64}
        components = {'host': host}
        transports = {'host': {'name': intake.release.artifact_name('host', self.source), 'files': {
            'host-manifest.json': {'sha256': host['bundle_manifest_sha256'], 'bytes': 300},
            'host.tar': {'sha256': '7' * 64, 'bytes': 8192}}}}
        for role in ROLES:
            components[COMPONENT[role]] = dict(images) if role == 'devbox' else {**images, **tooling}
            transports[role] = {'name': intake.release.artifact_name(role, self.source), 'files': {
                f'{role}.oci.tar': {'sha256': images['archive_sha256'], 'bytes': images['archive_bytes']},
                'part.json': {'sha256': f'{run:064x}', 'bytes': 300}}}
        return {'schema': 2, 'kind': 'dev-pair-platform-release', 'repository': intake.release.REPOSITORY,
                'source_sha': self.source, 'publisher_run': run, 'standards_sha': STANDARDS,
                'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1}, 'previous_platform_sha256': previous,
                'base_platform_sha256': None, 'components': components, 'transports': transports}

    def add(self, run, *, image='e' * 64, previous=None, expired=False, **updates):
        repo = {'full_name': intake.release.REPOSITORY}
        row = {'id': run, 'run_attempt': 1, 'path': '.github/workflows/platform-release.yml',
               'event': 'push', 'status': 'completed', 'conclusion': 'success', 'head_branch': 'main',
               'head_sha': self.source, 'repository': repo, 'head_repository': repo, **updates}
        self.runs.append(row)
        self.indexes[run] = self.index(run, image=image, previous=previous)
        self.asset_rows[run] = [{'name': intake.release.artifact_name(part, self.source), 'id': 10 * run + offset,
                                 'expired': expired, 'digest': 'sha256:' + '8' * 64, 'size_in_bytes': 400}
                                for offset, part in enumerate(('subjects', *ROLES, 'host'))]

    def api(self, endpoint, _end):
        if endpoint == 'branches/main':
            return self.branch
        if endpoint.startswith('actions/workflows/'):
            self.assertIn(f'head_sha={self.source}', endpoint)
            self.assertIn('event=push', endpoint)
            self.assertIn('branch=main', endpoint)
            return {'total_count': len(self.runs), 'workflow_runs': self.runs}
        run = int(endpoint.split('/')[2])
        if '/artifacts?' in endpoint:
            rows = self.asset_rows[run]
            return {'total_count': len(rows), 'artifacts': rows}
        self.rechecked.append(run)
        return next(row for row in self.runs if row['id'] == run)

    def fetch(self, rows, name, stage, wanted, _end):
        self.assertEqual(set(wanted), {'platform.json'})
        run = rows[name]['id'] // 10
        (stage / 'platform.json').write_bytes(canonical(self.indexes[run]))

    @staticmethod
    def selected(source, run, identity, previous, end):
        return {'schema': 2, 'platform_sha256': identity, 'source_sha': source, 'publisher_run': run,
                'kind': 'dev-pair-platform-release'}

    def test_chooses_newest_equal_artifacts_and_checks_only_relevant_publications(self):
        self.add(101)
        self.add(103, previous='b' * 64)
        self.add(105, head_repository={'full_name': 'fork/dev-pair'})
        self.add(106, run_attempt=2)
        self.add(102)
        result = intake.acquire_initial(self.source, self.end)
        self.assertEqual(result['publisher_run'], 102)
        self.assertEqual(self.rechecked, [103, 102, 101])
        self.assertEqual([call.args[3] for call in self.verify.call_args_list], [102] * 4 + [101] * 4)
        self.assertEqual([call.args[4] for call in self.verify.call_args_list], [*ROLES, 'host'] * 2)
        self.assertEqual(list(self.portable.iterdir()), [])
        self.acquire.assert_called_once_with(self.source, 102, result['platform_sha256'], None, self.end)

    def test_conflicting_verified_images_and_unavailable_attestation_do_not_stage(self):
        self.add(101)
        self.add(102, image='f' * 64)
        with self.assertRaisesRegex(Blocked, 'publications disagree'):
            intake.acquire_initial(self.source, self.end)
        self.verify.side_effect = subprocess.CalledProcessError(2, ['/usr/bin/python3'])
        with self.assertRaises(subprocess.CalledProcessError):
            intake.acquire_initial(self.source, self.end)
        self.acquire.assert_not_called()
        self.assertEqual(list(self.portable.iterdir()), [])

    def test_distinguishes_unpublished_source_expiration_and_missing_publication(self):
        self.branch['commit']['sha'] = 'b' * 40
        with self.assertRaises(intake.InitialReleaseUnavailable) as unavailable:
            intake.acquire_initial(self.source, self.end)
        self.assertEqual(unavailable.exception.phase, 'initial-source-not-published')
        self.branch['commit']['sha'] = self.source
        with self.assertRaises(intake.InitialReleaseUnavailable) as unavailable:
            intake.acquire_initial(self.source, self.end)
        self.assertEqual(unavailable.exception.phase, 'initial-full-release-selection')
        self.add(101, expired=True)
        with self.assertRaises(intake.InitialReleaseUnavailable) as unavailable:
            intake.acquire_initial(self.source, self.end)
        self.assertEqual(unavailable.exception.phase, 'initial-release-artifacts-expired')
        self.verify.assert_not_called()
        self.acquire.assert_not_called()

    def test_partial_listing_is_not_authority_for_unique_selection(self):
        for run in range(101, 101 + intake.INITIAL_RUN_LIMIT + 1):
            self.add(run)
        with self.assertRaisesRegex(Blocked, 'inventory is incomplete or exceeds'):
            intake.acquire_initial(self.source, self.end)
        self.verify.assert_not_called()
        self.acquire.assert_not_called()

    def test_staged_initial_receipt_can_resume_until_any_live_selector_exists(self):
        self.add(101)
        raw = canonical(self.indexes[101])
        identity = intake.release.digest(raw)
        stage = self.portable / identity
        stage.mkdir()
        (stage / 'platform.json').write_bytes(raw)
        receipt = self.selected(self.source, 101, identity, None, self.end)
        (stage / 'intake.json').write_bytes(canonical(receipt))
        (stage / 'intake.json').chmod(0o600)
        with mock.patch.object(intake, 'verify_local_parts') as verify:
            self.assertEqual(intake.acquire_initial(self.source, self.end), receipt)
            verify.assert_called_once_with(stage, self.indexes[101], self.end)
        control = self.root / 'renewal'
        control.mkdir()
        (control / 'site-current.json').write_bytes(canonical('c' * 64))
        with self.assertRaisesRegex(Blocked, 'interrupted site selection'):
            intake.acquire_initial(self.source, self.end)
        self.assertEqual(self.rechecked, [])
        self.acquire.assert_not_called()
