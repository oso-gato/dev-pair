import contextlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import owner_intake as intake
import job_protocol as p
import product_job as product

REPOSITORIES = ('owner/one', 'owner/two')
MANIFESTS = {f'job-{key}': key * 64 for key in ('a', 'b', 'c')}


def public_client():
    script = ROOT / 'runtime/product-job/dev-pair'
    loader = importlib.machinery.SourceFileLoader('owner_terminal', str(script))
    spec = importlib.util.spec_from_loader('owner_terminal', loader)
    client = importlib.util.module_from_spec(spec)
    loader.exec_module(client)
    return client


class OwnerIntakeTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.site = self.root / 'site'
        self.site.mkdir()
        for path in ('product-jobs', 'product-jobs/jobs', 'product-jobs/intake',
                     'product-jobs/profiles', 'provider-allowances', 'repository-approvals'):
            (self.root / path).mkdir(mode=0o700)
        lock = self.root / 'product-jobs/intake.lock'
        lock.touch(mode=0o600)
        self.intake = intake.Intake(self.site, self.root)
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.object(intake, 'protect_directory', side_effect=self.protect))
        self.patches.enter_context(mock.patch.object(intake, 'checked_file', side_effect=lambda path, limit=65536:
                                                   p.read_data(path, limit)))
        self.patches.enter_context(mock.patch.object(intake, 'load_private', side_effect=self.startup))
        self.patches.enter_context(mock.patch.object(self.intake, 'release_slots',
            return_value=(SimpleNamespace(dispatch_gate=contextlib.nullcontext), 'd' * 64, MANIFESTS)))
        self.patches.enter_context(mock.patch.object(self.intake, 'slot', side_effect=self.slot))
        self.patches.enter_context(mock.patch.object(product, 'JOBS', self.root / 'product-jobs/jobs'))
        self.settings = {}
        for remote in REPOSITORIES:
            root = self.site / 'repositories' / remote
            repo = root / 'acquired'
            repo.mkdir(parents=True)
            (root / 'startup').mkdir()
            self.git(repo, 'init', '--template=')
            self.git(repo, 'config', 'remote.origin.url', 'https://github.com/' + remote)
            app = repo / 'examples/checklist/checklist.py'
            app.parent.mkdir(parents=True)
            app.write_text('"""Approved checklist fixture for ' + remote + '."""\n')
            self.git(repo, 'add', '--all')
            self.git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'starting checklist')
            sha = self.git(repo, 'rev-parse', 'HEAD').strip().decode()
            self.settings[remote] = {'commit': sha, 'startup_revision': sha, 'destination': 'Private checklist review'}
        (self.site / 'standards').mkdir()
        (self.site / 'repositories.json').write_text(p.canonical(
            {'schema': 1, 'repositories': self.settings, 'slots': list(MANIFESTS)}))

    def git(self, folder, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(folder), *args],
                                       stderr=subprocess.DEVNULL, timeout=5)

    def protect(self, path):
        self.assertTrue(path.is_dir())
        return path

    def startup(self, project, cache, revision, end):
        self.assertTrue(project.is_dir() and cache.is_dir())
        self.assertGreater(end, time.monotonic())
        return SimpleNamespace(manifest={'version': 1, 'project_revision': revision, 'standards_sha': p.STANDARDS})

    def slot(self, job, manifest):
        self.assertEqual(MANIFESTS[job], manifest)
        profile = {'grant': {'spend_microusd': 20000, 'seconds': 60, 'max_requests': 2, 'max_request_bytes': 8192,
                             'max_context_tokens': 2000, 'max_output_tokens': 256}}
        return ({'host_seconds': 30, 'build_seconds': 60, 'turn_seconds': 30, 'allowance_ref': 'site-plan',
                 'spend_microusd': 45000, 'expires_unix': 2_000_000_000, 'pricing': {}},
                {role: {'grant': dict(profile['grant'])} for role in intake.ROLES},
                {'context': b'fixture billable context', 'tariff': b'fixture price'}, {role: 'e' * 64 for role in intake.ROLES})

    @staticmethod
    def request(repo=REPOSITORIES[0]):
        return {'action': 'draft', 'repository': repo, 'brief': 'Repair persistence for returning checklist users.',
                'acceptance': 'The same completed item appears once after restart.', 'constraints': 'Preserve existing data.',
                'audience': 'Existing checklist users.', 'access': 'Keep current private permissions and item ownership.',
                'workload': intake.CHECKLIST, 'external_validation': ''}

    def next_recovery(self, worker, job):
        saved = worker.record(job)
        saved['recovery']['after'] = 0
        worker.save(job, saved)
        return worker.reconcile()

    def test_previews_actual_git_commit_and_uses_another_reviewed_slot_for_another_repo(self):
        with mock.patch.object(intake.candidate, 'invoke', wraps=intake.candidate.invoke) as invoke:
            first = self.intake.draft(self.request())
            second = self.intake.draft(self.request(REPOSITORIES[1]))
        self.assertEqual((first['job_id'], second['job_id']), ('job-a', 'job-b'))
        agreement = first['preview']['plan']['agreement']
        self.assertEqual(agreement['initial_commit'], self.settings[REPOSITORIES[0]]['commit'])
        self.assertIn('Preserve existing data.', agreement['brief'])
        self.assertEqual(first['preview']['standards_sha'], p.STANDARDS)
        self.assertEqual(first['preview']['provider_microusd'], 45000)
        self.assertTrue(all(cmd.args[0][0] != intake.SYSTEMCTL for cmd in invoke.call_args_list))
        with self.assertRaisesRegex(ValueError, 'outside the approved'):
            self.intake.draft(self.request('other/project'))

    def test_once_confirmed_the_old_draft_cannot_start_and_an_owned_slot_is_not_reassigned(self):
        first = self.intake.draft(self.request())
        replacement = self.intake.draft(dict(self.request(), constraints='Keep existing IDs.'))
        job = replacement['job_id']
        self.assertEqual(first['job_id'], job)
        self.assertNotEqual(first['agreement_token'], replacement['agreement_token'])
        with mock.patch.object(intake.candidate, 'invoke') as invoke:
            with self.assertRaisesRegex(ValueError, 'draft has changed'):
                self.intake.confirm(job, first['agreement_token'])
            invoke.assert_not_called()
            confirmed = self.intake.confirm(job, replacement['agreement_token'])
        self.assertEqual(confirmed['phase'], 'confirmed')
        self.assertEqual(invoke.call_args.args[0], [intake.SYSTEMCTL, 'start', '--no-block',
                                                 'dev-pair-intake@job-a.service'])
        self.assertEqual(self.intake.status(job), confirmed)
        self.assertEqual(self.intake.draft(self.request())['job_id'], 'job-b')

    def test_confirm_then_disconnect_prepares_the_exact_durable_job_from_the_saved_record(self):
        draft = self.intake.draft(self.request())
        job = draft['job_id']
        starts = []
        run = intake.candidate.invoke
        approval = {'raw': None}
        saved_profiles = []

        def run_command(command, deadline, **options):
            if command[0] == intake.SYSTEMCTL:
                unit = command[-1]
                starts.append(unit)
                if starts.count(unit) == 1:
                    raise OSError('Scheduling was temporarily unavailable.')
                return b''
            if 'approve-job' in command:
                args = dict(zip(command[4::2], command[5::2]))
                settings = self.settings[REPOSITORIES[0]]
                row = dict(schema=1, job=job, repository=REPOSITORIES[0], standards_sha=p.STANDARDS,
                    acquired_commit=settings['commit'], acquired_tree=draft['preview']['source_tree'],
                    startup_project_revision=settings['startup_revision'],
                    agreement_sha256=product.agreement_sha(draft['preview']['plan']),
                    startup_sha256=draft['preview']['plan']['startup_sha256'])
                self.assertEqual(args['--acquired-sha'], row['acquired_commit'])
                self.assertEqual(args['--agreement-sha256'], row['agreement_sha256'])
                approval['raw'] = p.canonical(row).encode()
                (self.root / 'repository-approvals' / (job + '.json')).write_bytes(approval['raw'])
                return b''
            return run(command, deadline, **options)

        def stage_seed(role, job_id, profile, seed, raw, startup):
            self.assertEqual(job_id, job)
            self.assertEqual(raw, approval['raw'])
            self.assertEqual(startup, draft['preview']['plan']['startup_sha256'])
            saved_profiles.append((role, profile))

        def acquire(role, job_id, account, agreement, tree, bundle, *, checklist):
            self.assertEqual(job_id, job)
            self.assertTrue(checklist)
            self.assertEqual(agreement['initial_commit'], self.settings[REPOSITORIES[0]]['commit'])
            self.assertTrue(bundle.startswith(b'# v2 git bundle\n') or bundle.startswith(b'# v3 git bundle\n'))
            observed = self.root / (role + '.bundle')
            observed.write_bytes(bundle)
            acquired = self.site / 'repositories' / REPOSITORIES[0] / 'acquired'
            self.assertIn(agreement['initial_commit'].encode(), self.git(acquired, 'bundle', 'list-heads', observed))

        def verify_allowance(job_id, digest):
            raw = (self.root / 'provider-allowances' / job_id / 'allowance.json').read_bytes()
            self.assertEqual(p.sha256(raw), digest)
            self.assertEqual(p.loads(raw)['agreement_sha256'], product.agreement_sha(draft['preview']['plan']))
            return SimpleNamespace(validate_grant=lambda selection, grant: self.assertEqual(grant['allowance_sha256'], digest))

        with mock.patch.object(intake.candidate, 'invoke', side_effect=run_command), \
                mock.patch.object(intake.candidate, 'protected_file', side_effect=lambda path, cap=p.MAX_MESSAGE:
                                  p.read_data(path, cap)), \
                mock.patch.object(self.intake, 'stage_role', side_effect=stage_seed), \
                mock.patch.object(self.intake, 'acquire_role', side_effect=acquire), \
                mock.patch.object(intake.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001)), \
                mock.patch.object(product, 'source_approval',
                                  side_effect=lambda value: self.assertEqual(value, draft['preview']['plan'])), \
                mock.patch.dict(sys.modules, {'provider_broker': SimpleNamespace(load_allowance=verify_allowance)}):
            accepted = self.intake.confirm(job, draft['agreement_token'])
            self.assertEqual(accepted['phase'], 'confirmed')
            self.assertIn('Waiting to schedule', accepted['diagnostics'])
            # A fresh worker reads the saved agreement after the front-door
            # invocation has returned, and hands off to the real J submit path.
            with contextlib.ExitStack() as installed:
                worker = intake.Intake(self.site, self.root)
                installed.enter_context(mock.patch.object(worker, 'release_slots', self.intake.release_slots))
                installed.enter_context(mock.patch.object(worker, 'slot', self.intake.slot))
                installed.enter_context(mock.patch.object(worker, 'stage_role', side_effect=stage_seed))
                installed.enter_context(mock.patch.object(worker, 'acquire_role', side_effect=acquire))
                self.assertEqual(self.next_recovery(worker, job), 0)
                self.assertEqual(worker.prepare(job), 75)
                self.assertIn('Product plan is durable', worker.status(job)['diagnostics'])
                published = product.job_path(job) / 'plan.json'
                initial = published.read_bytes()
                original_node = published.stat().st_ino
                self.assertEqual(self.next_recovery(worker, job), 0)
                outcome = worker.prepare(job)
                self.assertEqual(outcome, 0, worker.status(job)['diagnostics'])
                self.assertEqual(worker.status(job)['phase'], 'submitted')
                self.assertEqual(worker.prepare(job), 0)
                self.assertEqual(published.stat().st_ino, original_node)
                self.assertEqual(published.read_bytes(), initial)
                with mock.patch.object(intake, 'boot_id', return_value='00000000-0000-4000-8000-000000000001'):
                    self.assertEqual(worker.reconcile(), 0)
                    self.assertEqual(worker.prepare(job), 0)
                terminal = product.read_state(product.job_path(job))
                terminal['phase'] = 'blocked'
                product.durable_json(product.job_path(job) / 'state.json', terminal)
                with mock.patch.object(intake, 'boot_id', return_value='00000000-0000-4000-8000-000000000002'):
                    self.assertEqual(worker.reconcile(), 0)
        self.assertEqual(starts, ['dev-pair-intake@job-a.service', 'dev-pair-intake@job-a.service',
                                  'dev-pair-product@job-a.service', 'dev-pair-intake@job-a.service',
                                  'dev-pair-product@job-a.service', 'dev-pair-intake@job-a.service',
                                  'dev-pair-product@job-a.service'])
        self.assertEqual([role for role, _ in saved_profiles], list(intake.ROLES))
        self.assertEqual(product.read_state(product.job_path(job))['phase'], 'blocked')
        self.assertEqual(product.plan((product.job_path(job) / 'plan.json').read_bytes()), draft['preview']['plan'])

    def test_local_bundle_initializes_two_clean_role_checkouts_and_preserves_dirty_work(self):
        repo = REPOSITORIES[0]
        job = 'job-a'
        draft = self.intake.draft(self.request())
        agreement = draft['preview']['plan']['agreement']
        tree = draft['preview']['source_tree']
        acquired = self.site / 'repositories' / repo / 'acquired'
        bundle = intake.fixed_git(acquired, 'bundle', 'create', '-', 'HEAD', cap=intake.candidate.MAX_BUNDLE)
        label = b'system_u:object_r:container_file_t:s0:c12,c15'
        endpoint = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        for role in intake.ROLES:
            for leaf in ('workspaces', 'state', 'cache', 'conductor-inputs'):
                (self.root / role / leaf).mkdir(mode=0o700, parents=True)

        def local_git(workspace, role, end, *, allow_bundle):
            self.assertTrue(allow_bundle)
            return lambda *args, cap=8192: self.git(workspace, *args)

        with mock.patch.object(intake.candidate, 'git_runner', side_effect=local_git), \
                mock.patch.object(intake.os, 'getxattr', return_value=label), \
                mock.patch.object(intake.os, 'setxattr'):
            for role in intake.ROLES:
                self.intake.acquire_role(role, job, endpoint, agreement, tree, bundle)
                workspace = self.root / role / 'workspaces' / job
                self.assertEqual(self.git(workspace, 'rev-parse', 'HEAD').decode().strip(), agreement['initial_commit'])
                self.assertFalse(self.git(workspace, 'status', '--porcelain', '--untracked-files=all'))
                self.intake.acquire_role(role, job, endpoint, agreement, tree, bundle)
                edit = workspace / 'durable-note'
                edit.write_text('Keep this draft.')
                with self.assertRaisesRegex(ValueError, 'retained role checkout has work'):
                    self.intake.acquire_role(role, job, endpoint, agreement, tree, bundle)
                self.assertEqual(edit.read_text(), 'Keep this draft.')

    def test_terminal_invocation_keeps_the_brief_file_on_the_unprivileged_side(self):
        client = public_client()
        brief_path = self.root / 'brief.txt'
        brief_path.write_text('Keep one completed item after a restart.')
        expected = {'job_id': 'job-a', 'phase': 'awaiting-confirmation', 'agreement_token': 'f' * 64,
                    'preview': self.intake.draft(self.request())['preview'], 'diagnostics': None}
        with mock.patch.object(client.subprocess, 'run', return_value=SimpleNamespace(
                stdout=p.canonical(expected).encode(), returncode=0)) as run, \
             mock.patch.object(client.sys, 'argv', ['dev-pair', 'draft', REPOSITORIES[0], '--brief-file', str(brief_path),
                                                    '--acceptance', 'One completed item', '--workload', intake.CHECKLIST,
                                                    '--audience', 'Current users', '--access', 'Existing private access']), \
             mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(client.main(), 0)
        self.assertEqual(run.call_args.args[0], client.COMMAND)
        self.assertEqual(p.loads(run.call_args.kwargs['input'])['brief'], brief_path.read_text())
        self.assertNotIn(str(brief_path), str(run.call_args))
        self.assertIn('Confirm when ready with dev-pair submit job-a', output.getvalue())

    def test_slot_selection_skips_expired_authority_and_retained_job(self):
        retained = product.job_path('job-b')
        retained.mkdir()
        sentinel = retained / 'retained.txt'
        sentinel.write_text('Keep this previous job.')

        def slot(job, manifest):
            if job == 'job-a':
                raise ValueError('The approved provider allowance expired.')
            return self.slot(job, manifest)

        self.intake.slot.side_effect = slot
        draft = self.intake.draft(self.request())
        self.assertEqual(draft['job_id'], 'job-c')
        self.assertEqual([call.args[0] for call in self.intake.slot.call_args_list], ['job-a', 'job-c'])
        self.assertEqual(sentinel.read_text(), 'Keep this previous job.')

    def test_agreement_and_repeat_confirmation_render_the_protected_blocked_record(self):
        client = public_client()
        draft = self.intake.draft(self.request())
        job, token = draft['job_id'], draft['agreement_token']
        self.intake.block(job, self.intake.record(job), 'Selected role layout is unavailable.')

        def protected(command, *, input, stdout, check):
            result = io.StringIO()
            previous_umask = os.umask(0o077)
            try:
                with mock.patch.object(intake, 'Intake', return_value=self.intake), \
                        mock.patch.object(intake.os, 'geteuid', return_value=0), \
                        mock.patch.dict(intake.os.environ, {'SUDO_USER': 'core'}), \
                        mock.patch.object(intake.sys, 'argv', [intake.__file__]), \
                        mock.patch.object(intake.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(input))), \
                        contextlib.redirect_stdout(result):
                    code = intake.main()
            finally:
                os.umask(previous_umask)
            self.assertEqual(command, client.COMMAND)
            return SimpleNamespace(returncode=code, stdout=result.getvalue().encode())

        with mock.patch.object(client.subprocess, 'run', side_effect=protected):
            for argv, code in ((['agreement', job], 0), (['submit', job, token], 2)):
                with self.subTest(action=argv[0]), mock.patch.object(client.sys, 'argv', ['dev-pair', *argv]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(client.main(), code)
                    self.assertIn('Job job-a · blocked', output.getvalue())
                    self.assertIn('Selected role layout is unavailable.', output.getvalue())
                    if argv[0] == 'agreement':
                        self.assertIn('The same completed item appears once after restart.', output.getvalue())

    def test_named_status_and_reattach_keep_validation_visible_through_confirmed_delivery(self):
        client = public_client()
        draft = self.intake.draft(self.request())
        job, plan = draft['job_id'], draft['preview']['plan']
        saved = self.intake.record(job)
        self.intake.save(job, dict(saved, phase='submitted'))
        root = product.job_path(job)
        root.mkdir(mode=0o700)
        state = {'job_id': job, 'agreement_sha256': product.agreement_sha(plan), 'phase': 'passed',
                 'repository': plan['agreement']['repository'], 'startup_sha256': plan['startup_sha256'],
                 'materialized': {'bundle_sha256': 'd' * 64}}
        product.durable_json(root / 'plan.json', plan)
        product.durable_json(root / 'state.json', state)
        url = 'https://erebus.example.ts.net/'
        image = 'ghcr.io/oso-gato/dev-pair/checklist@sha256:' + 'a' * 64
        pending = {'version': 1, 'job_id': job, 'plan_sha256': p.identity(plan),
                   'phase': 'awaiting-independent-destination', 'release': {'subject': image}, 'destination': url}
        product.durable_json(root / 'promotion.json', pending)

        def invoke(action):
            data = p.canonical({'action': action, 'job': job}).encode()
            with mock.patch.object(intake, 'Intake', return_value=self.intake), \
                    mock.patch.object(intake.os, 'geteuid', return_value=0), \
                    mock.patch.dict(intake.os.environ, {'SUDO_USER': 'core'}), \
                    mock.patch.object(intake.sys, 'argv', [intake.__file__]), \
                    mock.patch.object(intake.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(data))), \
                    contextlib.redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(intake.main(), 0)
            return [p.loads(line.encode()) for line in stream.getvalue().splitlines()]

        rows = invoke('status')
        self.assertEqual(rows[0]['phase'], 'passed')
        self.assertEqual(rows[0]['promotion']['phase'], 'awaiting-independent-destination')
        confirmed = dict(pending, phase='confirmed', destination_receipt_sha256='b' * 64)
        with mock.patch.object(product.time, 'sleep',
                               side_effect=lambda _: product.durable_json(root / 'promotion.json', confirmed)) as pause:
            events = invoke('reattach')
        pause.assert_called_once()
        self.assertEqual([event['phase'] for event in events], ['passed', 'passed'])
        self.assertEqual([event['promotion']['phase'] for event in events], ['awaiting-independent-destination', 'confirmed'])
        final, = invoke('status')
        with contextlib.redirect_stdout(io.StringIO()) as terminal:
            client.show(final)
        self.assertIn('Delivery confirmed', terminal.getvalue())
        self.assertIn(url, terminal.getvalue())
        self.assertIn(image, terminal.getvalue())
        self.assertEqual(product.read_state(root), state)
        product.durable_json(root / 'promotion.json', dict(confirmed, plan_sha256='c'*64))
        held, = invoke('status')
        self.assertEqual(held['phase'], 'passed')
        self.assertEqual(held['promotion']['phase'], 'observation-held')

    def test_ambiguous_sharing_draft_asks_about_access_and_refuses_empty_acceptance(self):
        client = public_client()
        with mock.patch.object(client.sys, 'argv', ['dev-pair', 'start', REPOSITORIES[0]]), \
                mock.patch.object(client.sys, 'stdin', SimpleNamespace(isatty=lambda: True)), \
                mock.patch('builtins.input', side_effect=['Let the team share checklists.', 'Team members', 'Creators may share', '']) as answers, \
                mock.patch.object(client, 'query') as query, contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(client.main(), 2)
        query.assert_not_called()
        self.assertIn('Who may share', answers.call_args_list[2].args[0])
        self.assertIn('Describe acceptance', error.getvalue())
        with self.assertRaisesRegex(ValueError, 'Owner input is missing'):
            self.intake.draft(dict(self.request(), acceptance=''))

    def test_general_authorized_git_draft_binds_requested_local_and_external_validation(self):
        repo = REPOSITORIES[1]
        acquired = self.site / 'repositories' / repo / 'acquired'
        self.git(acquired, 'rm', 'examples/checklist/checklist.py')
        (acquired / 'product.txt').write_text('Shared note fixture.\n')
        self.git(acquired, 'add', 'product.txt')
        self.git(acquired, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'note')
        self.settings[repo].update(commit=self.git(acquired, 'rev-parse', 'HEAD').decode().strip(),
                                   workloads=['general-development', intake.EXTERNAL_PENDING])
        (self.site / 'repositories.json').write_text(p.canonical(
            {'schema': 1, 'repositories': self.settings, 'slots': list(MANIFESTS)}))
        stock_plan = product.plan

        def installed_plan(raw):
            value = p.loads(raw)
            self.assertEqual(value['adapter'], 'devbox-development-needs-host')
            # Exercise the optional adapter at the product boundary even on
            # the baseline checkout where the generic J worker isn't merged.
            return stock_plan(p.canonical(dict(value, adapter='checklist-quadlet'))) | {'adapter': value['adapter']}

        with mock.patch.object(product, 'plan', side_effect=installed_plan):
            draft = self.intake.draft(dict(self.request(repo), brief='Let the team share notes.',
                workload=intake.EXTERNAL_PENDING, external_validation='Observe access through the private gateway.',
                audience='Signed-in team members.', access='Only the author can publish. Members may view.',
                acceptance='A second member can read one note shared by the author.'))
        agreement = draft['preview']['product_agreement']
        self.assertEqual(agreement['external_validation'], 'Observe access through the private gateway.')
        self.assertIn('Only the author can publish.', draft['preview']['plan']['agreement']['brief'])
        self.assertIn('A second member can read one note', draft['preview']['plan']['agreement']['brief'])
        self.assertNotIn('Quadlet', draft['preview']['plan']['agreement']['brief'])
