"""Exercise ordinary source edits and the candidate publisher with stock Codex."""

import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import sys
import tempfile
import time
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import candidate_git
import checklist_candidate as candidate
import job_protocol as p
import product_job as job

PIN = 'b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b'
SESSION = '01a21ce9-a96d-7a13-85e7-fa8bbbcf6ba4'


def git(workspace, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(workspace), *args],
                                   stderr=subprocess.DEVNULL, timeout=8).decode().strip()


def staged_role_policy(source, root):
    script = '''
from pathlib import Path
import sys
sys.path[:0] = [str(Path(sys.argv[1]) / leaf) for leaf in ("tools", "tests")]
from role_entry_stock import runtime, state
requirements, config = runtime.role_policy("Use only the local fixture source.", live=True, development=True)
for name, value in (("requirements.toml", requirements), ("config.toml", config)):
    (Path(sys.argv[2]) / name).write_text(state.toml(value))
'''
    subprocess.run(['/usr/bin/python3', '-B', '-c', script, str(source), str(root)], check=True, timeout=15)


def stock(binary, policy, workspace, text):
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--symlink', '/usr/bin', '/bin',
            '--symlink', '/usr/lib', '/lib', '--symlink', '/usr/lib64', '/lib64',
            '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--dir', '/etc/codex',
            '--ro-bind', str(policy / 'requirements.toml'), '/etc/codex/requirements.toml',
            '--dir', '/state/codex',
            '--ro-bind', str(policy / 'config.toml'), '/state/codex/config.toml',
            '--dir', '/home/gpt', '--dir', '/work/build', '--bind', str(workspace), '/work/job',
            '--ro-bind', str(binary), '/opt/dev-pair/bin/codex', '--chdir', '/work/job',
            '--setenv', 'HOME', '/home/gpt', '--setenv', 'CODEX_HOME', '/state/codex',
            '--setenv', 'PATH', '/usr/bin:/bin', '--',
            '/opt/dev-pair/bin/codex', 'sandbox', '--include-managed-config',
            '-P', 'product-child', '-C', '/work/job', '--', '/usr/bin/bash', '-c', text]
    return subprocess.run(argv, capture_output=True, timeout=20, check=False,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})


def observe(base, script, output):
    item = {'id': 'item_4', 'type': 'command_execution', 'command': shlex.join(['/usr/bin/bash', '-c', script])}
    rows = [{'type': 'thread.started', 'thread_id': SESSION}, {'type': 'turn.started'},
        {'type': 'item.started', 'item': item}, {'type': 'item.completed', 'item':
        dict(item, status='completed', exit_code=output.returncode, aggregated_output=output.stdout.decode())},
        {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': p.canonical(
            {'base_sha': base, 'summary': 'The edited source passed the local fixture.'})}}, {'type': 'turn.completed'}]
    raw = '\n'.join(map(p.canonical, rows)).encode()
    return job.proposal(raw, source=True), raw


def run(binary, role_source):
    assert p.sha256(binary.read_bytes()) == PIN
    results = []
    with tempfile.TemporaryDirectory(prefix='dp-stock-source-') as temporary:
        location = Path(temporary)
        staged_role_policy(role_source, location)
        spec = importlib.util.spec_from_file_location('approved_role', role_source / 'tools' / 'gptbox_runtime.py')
        p_runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(p_runtime)
        for adapter, leaf in ((job.CHECKLIST_ADAPTER, 'examples/checklist/checklist.py'),
                              (job.LOCAL_ADAPTER, 'shared-note.txt'),
                              (job.EXTERNAL_ADAPTER, 'shared-note.txt')):
            root = location / adapter
            workspace = root / 'development/workspaces/demo'
            workspace.mkdir(parents=True)
            (root / 'development/conductor-inputs').mkdir(mode=0o700)
            jobs = root / 'jobs'
            jobs.mkdir(mode=0o700)
            private = jobs / 'demo'
            private.mkdir(mode=0o700)
            git(workspace, 'init', '--template=', '-b', 'main')
            git(workspace, 'config', 'user.name', 'Fixture')
            git(workspace, 'config', 'user.email', 'fixture@example.invalid')
            git(workspace, 'remote', 'add', 'origin', 'https://github.com/owner/product')
            (workspace / leaf).parent.mkdir(parents=True, exist_ok=True)
            (workspace / leaf).write_text('initial fixture\n')
            git(workspace, 'add', '.')
            git(workspace, 'commit', '-m', 'Approved baseline')
            base = git(workspace, 'rev-parse', 'HEAD')
            git(workspace, 'checkout', '--detach', base)
            approval = {'repository': 'owner/product', 'acquired_commit': base,
                        'acquired_tree': git(workspace, 'rev-parse', 'HEAD^{tree}')}
            work = p.envelope('checkpoint', job_id='demo', checkpoint_id='demo-c1',
                candidate={'source_revision': base, 'artifact_sha256': 'a' * 64},
                test=job.local_recipe(), summary='Approved local fixture', evidence=[])
            conductor = object.__new__(job.FedoraJob)
            conductor.job = 'demo'
            conductor.approval = approval
            conductor.approval_raw = p.canonical(approval).encode()
            conductor.agreement_sha = 'a' * 64
            conductor.agreement = {'build_seconds': 25}
            conductor.plan = {'startup_sha256': 'b' * 64}
            conductor.gptbox = p_runtime
            conductor.runtime = mock.Mock(dispatch_gate=contextlib.nullcontext)
            conductor.controller = mock.Mock()
            conductor.controller.ledger.checkpoint.return_value = ('fixture', {}, work)
            user = pwd.getpwuid(os.getuid())
            with contextlib.ExitStack() as fixture:
                fixture.enter_context(mock.patch.multiple(job, ROOT=root, JOBS=jobs))
                fixture.enter_context(mock.patch.object(candidate, 'as_role', side_effect=lambda role, *args, **kw: list(map(str, args))))
                fixture.enter_context(mock.patch.object(candidate.pwd, 'getpwnam', return_value=user))
                conductor.approve_development_base('demo-development', work)
            edit = stock(binary, location, workspace, "printf 'fixed fixture\\n' > " + shlex.quote(leaf) +
                         " && printf 'new source\\n' > owned-note.txt && /usr/bin/git add -- " + shlex.quote(leaf))
            if edit.returncode != 128 or b'Read-only file system' not in edit.stderr:
                raise AssertionError((edit.returncode, edit.stdout.decode(errors='replace'), edit.stderr.decode(errors='replace')))
            assert git(workspace, 'rev-parse', 'HEAD') == base
            prefix, suffix = candidate_git.witness()
            code = ('from pathlib import Path; assert Path(' + repr(leaf) +
                    ').read_text() == "fixed fixture\\n"; assert Path("owned-note.txt").read_text() == "new source\\n"; print("fresh test passed")')
            script = prefix + '/usr/bin/python3 -IB -c ' + shlex.quote(code) + suffix
            success = stock(binary, location, workspace, script)
            if success.returncode:
                debug = stock(binary, location, workspace,
                              '/usr/bin/find /work/job -maxdepth 2 -printf "%D %y %p\\n"')
                raise AssertionError((success.returncode, success.stdout.decode(errors='replace'),
                                      success.stderr.decode(errors='replace'), debug.stdout.decode(errors='replace')))
            assert b'fresh test passed' in success.stdout
            proposed, events = observe(base, script, success)
            development = dict(proposed, operation='demo-development', session_uuid=SESSION,
                               events_sha256=p.sha256(events), request_sha256='c' * 64)
            record = root / 'development/state/demo/turns/demo-development'
            record.mkdir(parents=True)
            (record / 'events.jsonl').write_bytes(events)
            (record / 'result.json').write_text(p.canonical({
                'owned_cleanup': 'reaped', 'status': 'completed-turn', 'runtime_admitted': True,
                'request_sha256': development['request_sha256'], 'session_uuid': SESSION,
                'events_sha256': development['events_sha256'], 'events_bytes': len(events)}))
            with contextlib.ExitStack() as fixture:
                fixture.enter_context(mock.patch.multiple(job, ROOT=root, JOBS=jobs))
                fixture.enter_context(mock.patch.object(job, 'read_role', side_effect=lambda path, uid, maximum: p.read_data(path, maximum)))
                fixture.enter_context(mock.patch.object(candidate, 'as_role', side_effect=lambda role, *args, **kw: list(map(str, args))))
                fixture.enter_context(mock.patch.object(candidate.pwd, 'getpwnam', return_value=user))
                completed = conductor.materialize(work, development)
                assert conductor.materialize(work, development) == completed
            revision = completed['candidate_sha']
            assert revision != base and git(workspace, 'rev-parse', 'HEAD') == revision
            assert git(workspace, 'rev-list', '--count', base + '..HEAD') == '1'
            assert git(workspace, 'status', '--porcelain=v1', '--untracked-files=all') == ''
            assert git(workspace, 'show', 'HEAD:' + leaf) == 'fixed fixture'
            assert git(workspace, 'show', 'HEAD:owned-note.txt') == 'new source'
            results.append({'adapter': adapter, 'sandbox_git_add_exit': edit.returncode, 'fresh_test_exit': success.returncode,
                            'original_base': base, 'candidate': revision, 'commits_created': 1,
                            'source_sha256': completed['binding']['snapshot_sha256'], 'replayed_exact': True, 'clean': True})
    print(json.dumps({'binary_sha256': PIN, 'stock_sandbox': True, 'production_role_authentication': False,
                      'stock_event_framing_fixture': True, 'cases': results}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--role-source', required=True, type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.role_source.resolve(strict=True))
