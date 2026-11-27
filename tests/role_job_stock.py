"""Offline stock CLI start/resume through the real role broker transport."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from role_entry_stock import runtime, state, tools, stage, RUNTIME
from test_provider_broker import broker, FakeResponse, selection, grant, MODEL

CLAIM = 'fixture-actor'
PROMPTS = {'first': b'Produce one initial assistant message.', 'next': b'Continue the original active session.'}
ANSWERS = {'first': 'Initial job work saved.', 'next': 'Resumed original job work.'}


class MockProvider:
    def __init__(self, operation):
        self.operation = operation
        self.calls = []

    def responses(self, raw, _deadline):
        body = json.loads(raw)
        texts = [part.get('text', '') for row in body['input'] if row.get('role') == 'user'
                 for part in row.get('content', ())]
        text = '\n'.join(texts)
        assert PROMPTS[self.operation].decode() in text
        assert all(f'Synthetic fixture document {name}' in text for name in runtime.STARTUP_IDS)
        self.calls.append({'model': body['model'], 'effort': body['reasoning']['effort']})
        response = {'id': 'resp_fixture_' + self.operation, 'model': MODEL,
                    'usage': {'input_tokens': 100, 'output_tokens': 12, 'total_tokens': 112}}
        items = [{'type': 'response.created', 'response': response},
                 {'type': 'response.output_item.done', 'item': {
                     'id': 'msg_fixture_' + self.operation, 'type': 'message', 'role': 'assistant',
                     'content': [{'type': 'output_text', 'text': ANSWERS[self.operation]}]}},
                 {'type': 'response.completed', 'response': response}]
        raw = b''.join(f'event: {item["type"]}\ndata: {json.dumps(item)}\n\n'.encode() for item in items)
        result = FakeResponse(raw)
        return result, result


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o444)


def fixtures(root, runner):
    f = stage(root)
    shutil.rmtree(f / 'credentials')
    with runner.rpc(frozen=False) as call:
        state.verify_skills_response(call('skills/list', {'cwds': ['/job'], 'forceReload': True}))
    shutil.copytree(runner.fixture / 'state/codex/skills', f / 'state/codex/skills', dirs_exist_ok=True)
    (f / 'work/resource.txt').write_text('stays across runtime launches\n')
    command = ['/usr/bin/git', '-C', str(f / 'work')]
    subprocess.run([*command, 'init', '-q'], check=True)
    subprocess.run([*command, 'add', 'resource.txt'], check=True)
    subprocess.run([*command, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-q', '-m', 'fixture'], check=True)
    head = subprocess.check_output([*command, 'rev-parse', 'HEAD'], text=True).strip()
    requirements, config = runtime.role_policy('Read the supplied synthetic fixture startup documents.', live=True)
    policy = state.toml(requirements).encode()
    profile = state.toml(config).encode()
    for path in (f / 'etc/codex/requirements.toml', f / 'state/codex/config.toml'):
        path.unlink()
    write(f / 'etc/codex/requirements.toml', policy)
    write(f / 'state/codex/config.toml', profile)
    documents = []
    for ident in runtime.STARTUP_IDS:
        raw = f'Synthetic fixture document {ident}.\n'.encode()
        write(f / 'startup' / (ident + '.txt'), raw)
        documents.append({'id': ident, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    manifest = broker.canonical({'version': 1, 'mode': 'private-runtime', 'project_revision': head,
                                 'standards_sha': runtime.STANDARDS, 'documents': documents})
    write(f / 'startup/manifest.json', manifest)
    details = {**selection(), 'role': 'maintenance', 'logical_session': CLAIM, 'candidate_sha': head}
    for key, value in (('config', profile), ('requirements', policy), ('startup', manifest)):
        details[key + '_sha256'] = hashlib.sha256(value).hexdigest()
    return f, details


def inner_mode(operation, request_sha):
    # SELinux and OCI placements require the native runner. The Linux fixture
    # still holds the same loopback-only namespace, cap/NNP and frozen mounts.
    runtime.verify_job_environment = runtime.verify_turn_environment
    runtime.provider_peer_label = lambda: None
    runtime.BASE = Path(RUNTIME).parent
    runtime.entry('job-turn', 'sample', operation, request_sha)


def execute(f, binary, operation, request_sha, channel, deadline):
    fixed = Path(__file__).resolve()
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--uid', '0', '--gid', '0',
            '--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_SETPCAP', '--cap-add', 'CAP_SETFCAP',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for path in ('/usr/bin', '/usr/lib/x86_64-linux-gnu', '/usr/lib64', '/usr/lib/locale',
                 '/usr/lib/python3.13', '/usr/lib/python3', '/usr/share'):
        argv += ['--ro-bind', path, path]
    for source, dest in [(f / 'image', str(Path(RUNTIME).parent)), (f / 'etc/codex', '/etc/codex'),
                         (f / operation, '/run/dev-pair-turn'), (channel, '/run/dev-pair-provider'),
                         (f / 'home', '/home/gpt'), (binary, runtime.CODEX)]:
        argv += ['--ro-bind', str(source), str(dest)]
    for source, dest in [('work', '/work/job'), ('cache', '/cache/job'), ('state', '/state')]:
        argv += ['--bind', str(f / source), dest]
    for path in (fixed, fixed.with_name('role_entry_stock.py'), fixed.with_name('test_provider_broker.py'),
                 Path(state.__file__), Path(tools.__file__), Path(runtime.__file__), Path(broker.__file__),
                 Path(state.__file__).with_name('public_inputs.py'), Path(state.__file__).with_name('fedora_oci.py')):
        argv += ['--ro-bind', str(path), '/opt/' + path.name]
    argv += ['--remount-ro', '/', '--chdir', '/work/job', '--', '/usr/bin/python3', '-I', '/opt/role_job_stock.py',
             'setup', str(os.stat('/proc/self/ns/net').st_ino), operation, request_sha]
    process = subprocess.Popen(argv, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               env={'PATH': '/usr/bin:/bin'}, start_new_session=True)
    try:
        code, output = tools.capture(process, deadline, [0])
    finally:
        tools.stop(process)
    if code != 0:
        raise RuntimeError(output['stderr'].decode(errors='replace'))
    return json.loads(output['stdout'])


def setup_mode(netns, operation, request_sha):
    tools.private_loopback(int(netns), setup=True)
    args = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
            '--die-with-parent', '--uid', '1000', '--gid', '1000', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev']
    for path in ('/state', '/work/job', '/cache/job', '/tmp'):
        args += ['--bind', path, path]
    for path in runtime.JOB_READONLY_MOUNTS:
        args += ['--ro-bind', str(path), str(path)]
    args += ['--cap-drop', 'ALL', '--chdir', '/work/job', '--', '/usr/bin/python3', '-I', '/opt/role_job_stock.py',
             'inner', operation, request_sha]
    os.execve(args[0], args, {'PATH': '/usr/bin:/bin'})


def run(binary):
    results = []
    with tempfile.TemporaryDirectory(prefix='dp-live-fixture-') as tmp:
        root = Path(tmp)
        runner = state.Harness(root, binary)
        f, details = fixtures(root / 'role', runner)
        for operation in ('first', 'next'):
            identity = {**details, 'operation': operation, 'turn_seconds': 8,
                        'prompt_sha256': hashlib.sha256(PROMPTS[operation]).hexdigest()}
            if results:
                identity.update(action='resume', session_uuid=results[0]['session_uuid'])
            raw = broker.canonical(identity)
            request_sha = hashlib.sha256(raw).hexdigest()
            write(f / operation / 'request.json', raw)
            write(f / operation / 'prompt.txt', PROMPTS[operation])
            shutil.copytree(f / 'startup', f / operation / 'startup')
            channel = root / ('broker-' + operation)
            channel.mkdir()
            channel.chmod(0o750)
            permission = {**grant(request_sha), 'max_request_bytes': 262144}
            evidence = broker.Journal(root / f'{operation}.json', identity, permission)
            provider = MockProvider(operation)
            end = time.monotonic() + 12
            worker = threading.Thread(target=broker.listen, args=(channel / 'responses.sock', provider, identity,
                                                                  permission, evidence, end), daemon=True)
            worker.start()
            try:
                while evidence.value['status'] != 'listening':
                    assert worker.is_alive() and end - time.monotonic() > 10
                    time.sleep(.01)
                result = execute(f, runner.binary, operation, request_sha, channel, end)
                if result['status'] != 'completed-turn':
                    diagnostic = f / 'state/turns' / operation
                    raise RuntimeError(str(result) + (diagnostic / 'stderr.txt').read_text()[-1600:] +
                                       str([json.loads(row).get('type') for row in
                                            (diagnostic / 'events.jsonl').read_text().splitlines()]))
                assert ANSWERS[operation].encode() in (f / 'state/turns' / operation / 'events.jsonl').read_bytes()
                assert provider.calls == [{'model': MODEL, 'effort': 'high'}]
                results.append(result)
            finally:
                worker.join(12)
                assert not worker.is_alive()
        assert results[0]['session_uuid'] == results[1]['session_uuid']
    print(json.dumps({'binary_sha256': state.CODEX_SHA, 'results': results, 'owned_cleanup': True,
                      'provider': 'synthetic-stream', 'native_selinux_tested': False}))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        run(Path(sys.argv[1]))
    elif sys.argv[1] == 'setup':
        setup_mode(*sys.argv[2:])
    elif sys.argv[1] == 'inner':
        inner_mode(*sys.argv[2:])
