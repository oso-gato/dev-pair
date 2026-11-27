import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checklist_merge_gate as merge
import checklist_proposal as proposal
from checklist_review_gate import policy_identity
import job_protocol as p
from ledger_recovery import read_private, write_private
import product_job as product
import product_release as delivery

A = 'a' * 40
B = 'b' * 40
C = 'c' * 40
D = 'd' * 40
JOB = 'checklist-repair'
REPO = proposal.REPOSITORY
DNS = 'erebus.example.ts.net'
SITE = {'developer_id': 10, 'developer_login': 'release-dev', 'fork': 'approved-org/dev-pair', 'merge_actor_id': 30}
CHECK = {'context': 'release-source-check', 'app_id': 93, 'workflow': '.github/workflows/release-check.yml',
         'sha256': 'e' * 64}
REVIEW_RULES = dict(reviewer_ids=[20], check=CHECK)


def request(base=A, head=B, tree=C, bundle=b'candidate'):
    return dict(version=1, job_id=JOB, agreement_sha256='1'*64, repository=REPO, base_sha=base,
                candidate_sha=head, tree_sha=tree, bundle_sha256=p.sha256(bundle), release_binding_sha256='2'*64,
                review_policy_sha256=policy_identity(REVIEW_RULES), developer_id=10, developer_login='release-dev',
                fork=SITE['fork'], branch=proposal.branch(JOB, head))


def pull(req, *, merged=False):
    return dict(number=7, state='closed' if merged else 'open', merged=merged, draft=False,
                user={'id': req['developer_id'], 'login': req['developer_login']}, head={'repo': {'full_name': req['fork']}, 'ref': req['branch'],
                                                        'sha': req['candidate_sha']},
                base={'repo': {'full_name': REPO}, 'ref': 'main', 'sha': req['base_sha']},
                body=proposal.pull_body(req), html_url=f'https://github.com/{REPO}/pull/7',
                merge_commit_sha=D if merged else None, merged_by={'id': 30} if merged else None)


class LocalProposalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work, self.fork, self.upstream, self.home, self.bundle = [self.root / leaf
            for leaf in ('work', 'fork', 'upstream', 'home', 'bundle')]
        for path in (self.home, self.work, self.fork, self.upstream):
            path.mkdir()
        self.git(self.work, 'init', '-b', 'main')
        self.git(self.work, 'config', 'user.name', 'Local test')
        self.git(self.work, 'config', 'user.email', 'local@example.test')
        self.source = self.work / 'examples/checklist/checklist.py'
        self.source.parent.mkdir(parents=True)
        self.source.write_text('# baseline\n')
        (self.work / 'README.md').write_text('# other file\n')
        self.git(self.work, 'add', '.')
        self.git(self.work, 'commit', '-m', 'initial')
        self.base = self.git(self.work, 'rev-parse', 'HEAD').decode().strip()
        for remote in (self.fork, self.upstream):
            self.git(remote, 'init', '--bare')
            self.git(self.work, 'push', str(remote), 'main')
        self.pull = None
        self.calls = 0

    @staticmethod
    def git(path, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(path), *args], capture_output=True,
                              check=True, timeout=8).stdout

    def candidate(self, path):
        path.write_text('# tested successor\n')
        self.git(self.work, 'add', str(path))
        self.git(self.work, 'commit', '-m', 'bounded improvement')
        rev = self.git(self.work, 'rev-parse', 'HEAD').decode().strip()
        tree = self.git(self.work, 'rev-parse', 'HEAD^{tree}').decode().strip()
        self.git(self.work, 'branch', 'materialized', rev)
        self.git(self.work, 'bundle', 'create', str(self.bundle), 'refs/heads/materialized', '^' + self.base)
        return request(self.base, rev, tree, self.bundle.read_bytes())

    def test_real_incremental_git_and_lost_proposal_response(self):
        req = self.candidate(self.source)
        with self.transport():
            with self.assertRaises(proposal.Unavailable):
                self.propose(req)
            self.assertEqual(self.propose(req), {'pull_request': 7, 'head': req['candidate_sha']})
        revision = self.git(self.fork, 'rev-parse', 'refs/heads/' + req['branch']).decode().strip()
        self.assertEqual(revision, req['candidate_sha'])
        self.assertEqual(self.calls, 1)

    def test_real_unapproved_git_delta_never_creates_remote_branch(self):
        req = self.candidate(self.work / 'README.md')
        with self.transport():
            with self.assertRaisesRegex(ValueError, 'outside the approved checklist scope'):
                self.propose(req)
        self.assertEqual(self.git(self.fork, 'for-each-ref', 'refs/heads/dev-pair-products'), b'')
        self.assertEqual(self.calls, 0)

    def transport(self):
        test = self
        run_git = proposal.git_call

        class Hub:
            def __init__(self, secret, end):
                pass

            def get(self, endpoint):
                if endpoint == 'user':
                    return {'id': 10}
                if endpoint.startswith('repos/' + REPO + '/pulls?'):
                    return [] if test.pull is None else [test.pull]
                if endpoint == 'repos/' + REPO + '/pulls/7':
                    return test.pull
                fork = endpoint == 'repos/' + SITE['fork']
                return dict(full_name=SITE['fork'] if fork else REPO, fork=fork, parent={'full_name': REPO},
                            permissions={'admin': False, 'maintain': False, 'push': fork, 'pull': True})

            def post_pull(self, req):
                test.calls += 1
                test.pull = pull(req)
                raise proposal.Unavailable('fixture response ended after accepted PR')

        def local(repository, end, *args, secret=None, login=None, bundle=False):
            locations = {'https://github.com/' + REPO + '.git': str(test.upstream),
                         'https://github.com/' + SITE['fork'] + '.git': str(test.fork)}
            return run_git(repository, end, *(locations.get(arg, arg) for arg in args),
                           bundle=bundle or any(arg in locations for arg in args))

        return mock.patch.multiple(proposal, HOME=self.home, Hub=Hub, git_call=local)

    def propose(self, req):
        return proposal.propose(req, self.bundle, 'fixture-fork', 'fixture-PR', time.monotonic() + 30)


class TrustFixture:
    def __init__(self, req):
        self.req = req
        self.row = pull(req)
        self.review_head = req['candidate_sha']
        self.reviewer = 20
        self.merge_calls = []
        self.workflows = []

    def api(self, path, *, pages=False):
        req = self.req
        return {
            'pulls?state=open&base=main&per_page=30': [self.row] if not self.row['merged'] else [],
            'pulls/7': self.row,
            'branches/main': {'protected': True, 'commit': {'sha': req['base_sha']}},
            'branches/main/protection': {'enforce_admins': {'enabled': True}, 'allow_force_pushes': {'enabled': False},
                'allow_deletions': {'enabled': False}, 'required_pull_request_reviews': {
                    'dismiss_stale_reviews': True, 'require_last_push_approval': True, 'required_approving_review_count': 1},
                'required_status_checks': {'strict': True, 'checks': [{'context': CHECK['context'], 'app_id': CHECK['app_id']}] }},
            f'compare/{req["base_sha"]}...{req["candidate_sha"]}?per_page=100':
                {'status': 'ahead', 'ahead_by': 1, 'behind_by': 0,
                 'files': [{'filename': 'examples/checklist/checklist.py', 'status': 'modified'}]},
            'pulls/7/reviews?per_page=100': [{'user': {'id': self.reviewer}, 'state': 'APPROVED',
                                              'commit_id': self.review_head, 'id': 78}],
            f'commits/{req["candidate_sha"]}/check-runs?filter=latest&per_page=100':
                {'check_runs': [{'id': 94, 'name': CHECK['context'], 'app': {'id': CHECK['app_id']},
                                 'head_sha': req['candidate_sha'], 'conclusion': 'success',
                                 'details_url': f'https://github.com/{REPO}/actions/runs/99/job/94'}]},
            'actions/runs/99': {'path': CHECK['workflow'], 'head_sha': req['candidate_sha'], 'event': 'pull_request',
                                'conclusion': 'success', 'repository': {'full_name': REPO}},
            'check-runs/94/annotations?per_page=100': [{'title': 'dev-pair-release-tree', 'annotation_level': 'notice',
                'path': CHECK['workflow'], 'message': ':'.join([req['candidate_sha'], D, req['tree_sha'], D])}],
        }[path]

    def get(self, endpoint):
        if endpoint == 'user':
            return {'id': 30}
        return {'full_name': REPO, 'permissions': {'admin': False, 'maintain': False, 'push': True, 'pull': True}}

    def main(self, sha):
        assert self.api('branches/main')['commit']['sha'] == sha

    def workflow(self, path, sha, expected):
        self.workflows.append((path, sha, expected))

    def tree(self, sha):
        req = self.req
        parents = [req['base_sha'], req['candidate_sha']] if sha == D else [req['base_sha']]
        return {'tree': {'sha': self.req['tree_sha']}, 'parents': [{'sha': parent} for parent in parents]}

    def merge(self, number, sha):
        self.merge_calls.append((number, sha))
        self.row = pull(self.req, merged=True)
        return {'merged': True, 'sha': D}


class MergeGateTests(unittest.TestCase):
    def test_off_host_gate_current_review_and_exact_checked_tree(self):
        policy = dict(version=1, developer_id=10, fork=SITE['fork'], merge_actor_id=30, reviewer_ids=[20], check=CHECK,
                      expires_unix=int(time.time()) + 120)
        trust = TrustFixture(request())
        merge.load_policy(policy)
        trust.review_head = A
        self.assertEqual(merge.act(trust, trust, policy)['phase'], 'awaiting-independent-review-or-current-check')
        trust.review_head = B
        trust.reviewer = 10
        self.assertEqual(merge.act(trust, trust, policy)['phase'], 'awaiting-independent-review-or-current-check')
        self.assertEqual(trust.merge_calls, [])
        trust.reviewer = 20
        self.assertEqual(merge.act(trust, trust, policy), {'pull_request': 7, 'merge_commit_sha': D})
        self.assertIn((CHECK['workflow'], D, CHECK['sha256']), trust.workflows)
        self.assertEqual(merge.act(trust, trust, policy)['phase'], 'awaiting-independent-review-or-current-check')
        self.assertEqual(trust.merge_calls, [(7, B)])
        with self.assertRaisesRegex(ValueError, 'custody must be separate'):
            merge.load_policy(dict(policy, merge_actor_id=10))

    def test_proposal_head_changed_after_lookup(self):
        trust = TrustFixture(request())
        trust.row['head']['sha'] = A
        with self.assertRaisesRegex(ValueError, 'different actor, head or base'):
            merge.act(trust, trust, dict(SITE, reviewer_ids=[20], check=CHECK))
        self.assertEqual(trust.merge_calls, [])


class PipelineFixture:
    rules = REVIEW_RULES

    def __init__(self):
        self.pull = None
        self.calls = []
        self.interrupted = True
        self.proof = False
        self.deployed = {'active': None, 'pending': None, 'route_pending': False, 'confirmed': None}

    def live_host_result(self, result):
        self.calls.append('authenticated host status')

    def find(self, req):
        return None if self.pull is None else proposal.match_pull(self.pull, req)

    def propose(self, req, bundle):
        self.calls.append('scoped proposal')
        self.pull = pull(req)
        if self.interrupted:
            raise proposal.Unavailable('fixture response ended after proposal creation')

    def review(self, row, req):
        self.calls.append('independent review')
        return D, dict(pull_request=7, review_head=B, source_tree=C)

    def published(self, source, review):
        self.calls.append('protected OCI')
        return dict(source_sha=source, subject=delivery.REGISTRY + '@sha256:' + '3'*64, run_id=99,
                    artifact_sha256='3'*64, **review)

    def activation(self):
        return self.deployed

    def deploy(self, release):
        self.calls.append('native deployment adapter')
        self.deployed['active'] = dict(release, dns_name=DNS)
        if self.interrupted:
            raise proposal.Unavailable('fixture response ended after durable activation')

    def evidence(self):
        if not self.proof:
            raise delivery.Wait('signed-destination-evidence')
        return 'external-proof'

    def confirm(self, evidence):
        self.calls.append('independent destination confirmation')
        active = self.deployed['active']
        active.update(verified_destination=True, destination_receipt_sha256='4'*64)
        self.deployed['confirmed'] = active['artifact_sha256']
        if self.interrupted:
            raise proposal.Unavailable('fixture response ended after authentication')


class PromotionPipelineTests(unittest.TestCase):
    def setUp(self):
        local = tempfile.TemporaryDirectory()
        self.addCleanup(local.cleanup)
        self.root = Path(local.name)
        self.state = self.root / 'promotion.json'
        self.backend = PipelineFixture()
        self.binding = dict(agreement_sha256='1'*64, repository=REPO, base_sha=A, candidate_sha=B, tree_sha=C,
                            bundle_sha256=p.sha256(b'candidate'), dns_name=DNS)
        product.durable_json(self.state, {'job_id': JOB, 'phase': 'awaiting-validated-candidate'})

    def advance(self):
        state = p.loads(read_private(self.state, 16384))
        delivery.advance(state, self.binding, b'candidate', 'result', SITE, self.backend,
                         lambda row: product.durable_json(self.state, row))
        return p.loads(read_private(self.state, 16384))

    def test_reattach_after_lost_proposal_deploy_and_confirmation(self):
        current = self.advance()
        self.assertEqual(current['phase'], 'awaiting-independent-review-and-merge')
        self.backend.pull = pull(current['proposal'], merged=True)
        with self.assertRaisesRegex(proposal.Unavailable, 'durable activation'):
            self.advance()
        with self.assertRaisesRegex(delivery.Wait, 'signed-destination-evidence'):
            self.advance()
        self.backend.proof = True
        with self.assertRaisesRegex(proposal.Unavailable, 'after authentication'):
            self.advance()
        current = self.advance()
        self.assertEqual(current['phase'], 'confirmed')
        self.assertEqual(current['destination'], 'https://' + DNS + '/')
        self.assertEqual(current['destination_receipt_sha256'], '4'*64)
        self.assertEqual(self.backend.calls, ['authenticated host status', 'scoped proposal', 'independent review',
                                             'protected OCI', 'native deployment adapter',
                                             'independent destination confirmation'])

    def test_stale_base_and_changed_head_preserve_existing_proposal(self):
        self.advance()
        self.backend.pull['base']['sha'] = D
        with self.assertRaisesRegex(delivery.Wait, 'stale-reviewed-base'):
            self.advance()
        self.backend.pull['head']['sha'] = D
        with self.assertRaisesRegex(ValueError, 'different actor, head or base'):
            self.advance()
        self.assertEqual(self.backend.calls, ['authenticated host status', 'scoped proposal'])

    def test_returned_site_gate_and_other_active_effect_are_held(self):
        current = self.advance()
        self.backend.pull = pull(current['proposal'], merged=True)
        self.backend.deployed['pending'] = {'operation': 'rollback', 'release': {'source_sha': A}}
        with self.assertRaisesRegex(ValueError, 'another deployment'):
            self.advance()
        self.assertNotIn('native deployment adapter', self.backend.calls)
        self.backend.deployed['pending'] = None
        deploy = self.backend.deploy
        self.backend.deploy = mock.Mock(side_effect=delivery.Wait('destination-fenced'))
        with self.assertRaisesRegex(delivery.Wait, 'destination-fenced'):
            self.advance()
        self.backend.deploy = deploy
        self.backend.interrupted = False
        self.backend.proof = True
        self.assertEqual(self.advance()['phase'], 'confirmed')
        self.assertEqual(self.backend.calls.count('native deployment adapter'), 1)


class ProtectedProductInputTests(unittest.TestCase):
    def setUp(self):
        local = tempfile.TemporaryDirectory()
        self.addCleanup(local.cleanup)
        self.catalogue = Path(local.name)
        self.root = self.catalogue / 'jobs' / JOB
        self.intake = self.catalogue / 'intake'
        self.store = self.root / 'candidate'
        self.store.mkdir(mode=0o700, parents=True)
        self.root.chmod(0o700)
        self.intake.mkdir(mode=0o700)
        self.plan = {'schema': 1, 'job_id': JOB, 'adapter': 'checklist-quadlet',
                     'agreement': {'repository': REPO, 'initial_commit': A, 'brief': 'Retain checklist data after restart',
                                   'host_seconds': 45, 'build_seconds': 60, 'turn_seconds': 90},
                     'startup_sha256': 'a'*64}
        self.approval = {'acquired_tree': 'f'*40}
        self.approval_bytes = p.canonical(self.approval).encode()
        test = {'revision': '1'*64, 'recipe': 'checklist-host', 'recipe_sha256': '2'*64}

        def checkpoint(index, rev):
            return p.envelope('checkpoint', job_id=JOB, checkpoint_id=f'{JOB}-c{index}',
                              candidate={'source_revision': rev, 'artifact_sha256': '3'*64}, test=test,
                              summary='Bound local fixture OCI', evidence=[])

        initial, repair = checkpoint(1, A), checkpoint(2, B)
        result = p.envelope('result', job_id=JOB, request_id=JOB + '-r2', request_sha256='5'*64,
                            checkpoint_id=repair['checkpoint_id'], candidate=repair['candidate'], test=test,
                            executor={'controller_id': 'fixture', 'environment': 'local fixture',
                                      'boundary': p.APP_QUADLET_BOUNDARY, 'implementation_sha256': '2'*64},
                            attempt_id='bound-attempt', status='pass', checks=[{'id': 'restart', 'expected': 'same item',
                                'actual': 'same item', 'status': 'pass', 'exit_status': 0, 'diagnostics': 'fixture',
                                'evidence': []}], diagnostics='fixture', evidence=[], effects=[],
                            cleanup={'status': 'complete', 'diagnostics': 'fixture cleanup'})
        local_result = {'exit_status': 0, 'snapshot_sha256': '7'*64}
        turn = {'session_uuid': 'f1fb0a04-3284-4621-8253-5fc326643287', 'events_sha256': 'd'*64,
                'request_sha256': 'c'*64}
        source = dict(job_id=JOB, base_sha=A, checkpoint_sha256=p.identity(initial),
                      agreement_sha256=product.agreement_sha(self.plan), approval_sha256=p.sha256(self.approval_bytes),
                      startup_sha256=self.plan['startup_sha256'], operation=JOB + '-development',
                      snapshot_sha256=local_result['snapshot_sha256'], validation_sha256=p.identity(local_result), **turn)
        material = dict(binding=source, candidate_sha=B, tree_sha=C, bundle_sha256=p.sha256(b'candidate'), head_ref='HEAD')
        self.state = {'phase': 'passed', 'job_id': JOB, 'initial': initial, 'repair': repair, 'materialized': material,
                      'development': dict(turn, local_validation=local_result),
                      'final': {'progress': 'host-checks-passed', 'result': result}}
        preview = {'plan': self.plan, 'product_agreement': {'repository': REPO, 'workload': delivery.SCOPE,
                   'destination': 'https://' + DNS + '/', 'external_validation': ''}, 'standards_sha': p.STANDARDS,
                   'source_tree': self.approval['acquired_tree']}
        self.owner = {'preview': preview, 'plan': self.plan, 'phase': 'submitted', 'agreement_token': p.identity(preview)}
        product.durable_json(self.root / 'plan.json', self.plan)
        product.durable_json(self.root / 'state.json', self.state)
        product.durable_json(self.intake / (JOB + '.json'), self.owner)
        product.durable_json(self.store / 'receipt.json', material)
        write_private(self.store / 'candidate.bundle', b'candidate')
        config = self.catalogue / 'site'
        config.mkdir(mode=0o700)
        policy = dict(SITE, version=1, repository=REPO, dns_name=DNS, observer_id=12, merge_gate_app_id=18,
                      merge_workflow_sha256='d'*64, expires_unix=int(time.time()) + 3600)
        product.durable_json(config / 'policy.json', policy)
        self.use(mock.patch.multiple(product, CATALOGUE=self.catalogue, JOBS=self.catalogue / 'jobs',
                                     source_approval=lambda unused: (self.approval_bytes, self.approval)))
        self.use(mock.patch.object(delivery, 'SITE', config))
        self.use(mock.patch.object(delivery.candidate, 'protected_file', lambda path, limit: read_private(path, limit)))

    def use(self, patch):
        patch.start()
        self.addCleanup(patch.stop)

    def test_ordinary_job_reattachment_joins_agreement_evidence_and_release_without_private_grants(self):
        backend = PipelineFixture()
        backend.interrupted = False
        backend.proof = True
        with mock.patch.object(delivery, 'Live', return_value=backend):
            current = delivery.run(JOB)
            self.assertEqual(current['binding']['agreement_token'], self.owner['agreement_token'])
            self.assertEqual(current['binding']['host_attempt_id'], 'bound-attempt')
            backend.pull = pull(current['proposal'], merged=True)
            self.assertEqual(delivery.run(JOB)['phase'], 'confirmed')
            self.assertEqual(delivery.run(JOB)['phase'], 'confirmed')
        view = product.read_progress(self.root)
        self.assertEqual(view['promotion']['destination'], 'https://' + DNS + '/')
        self.assertEqual(view['promotion']['phase'], 'confirmed')
        self.assertEqual(view['promotion']['image'], delivery.REGISTRY + '@sha256:' + '3'*64)
        self.assertNotIn('binding', view['promotion'])
        self.assertEqual(backend.calls.count('native deployment adapter'), 1)

    def test_changed_bundle_or_confirmation_cannot_request_external_work(self):
        (self.store / 'candidate.bundle').write_bytes(b'changed')
        with mock.patch.object(delivery, 'Live') as backend:
            self.assertEqual(delivery.run(JOB)['reason'], 'protected-scope-or-evidence-rejected')
            backend.assert_not_called()
        (self.store / 'candidate.bundle').write_bytes(b'candidate')
        self.owner['preview']['product_agreement']['destination'] = 'https://other.example.ts.net/'
        product.durable_json(self.intake / (JOB + '.json'), self.owner)
        with mock.patch.object(delivery, 'Live') as backend:
            self.assertEqual(delivery.run(JOB)['reason'], 'protected-scope-or-evidence-rejected')
            backend.assert_not_called()


if __name__ == '__main__':
    unittest.main()
