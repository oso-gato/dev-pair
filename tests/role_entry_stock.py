"""One real pinned CLI turn through the image entry in a private loopback fixture."""
import argparse
import ctypes
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

source = Path(__file__).resolve()
sys.path.insert(0, str(source.parent if source.parent == Path('/opt') else source.parents[1] / 'tools'))
import codex_state as state
import codex_tools as tools
import gptbox_runtime as runtime

MODEL = 'gpt-6.2-sol'
EFFORT = 'high'
PROMPT = b'Return the result of this synthetic headless role turn.'
DIRECTIVE = 'Synthetic managed startup for a single local role turn.'
ANSWER = 'Synthetic headless role turn completed.'
PORT = 39162
RUNTIME = '/usr/lib/dev-pair/gptbox/runtime.py'
ENDPOINT = f'http://127.0.0.1:{PORT}/v1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stage(root):
    root = Path(root)
    f = root / 'fixture'
    for path in ('image', 'work', 'state/codex', 'state/sqlite', 'state/logs', 'etc/codex',
                 'credentials', 'turn', 'home', 'cache'):
        (f / path).mkdir(mode=0o700, parents=True, exist_ok=True)
    requirements, config = runtime.role_policy(DIRECTIVE)
    req = state.toml(requirements).encode()
    cfg = state.toml(config).encode()
    source = Path(runtime.__file__).read_bytes()
    image = {'role': 'maintenance', 'files': {RUNTIME: digest(source), str(runtime.CODEX): state.CODEX_SHA}}
    request = {'schema': 1, 'operation': 'first-turn', 'role': 'maintenance', 'provider': 'gptbox',
               'model': MODEL, 'effort': EFFORT, 'standards_sha': runtime.STANDARDS, 'endpoint': ENDPOINT,
               'requirements_sha256': digest(req), 'config_sha256': digest(cfg), 'prompt_sha256': digest(PROMPT)}
    files = {'image/runtime.py': source, 'image/inputs.json': tools.canonical(image),
             'etc/codex/requirements.toml': req, 'state/codex/config.toml': cfg,
             'state/codex/hooks.json': b'{"hooks":{}}', 'state/codex/AGENTS.md': b'',
             'state/codex/AGENTS.override.md': b'', 'turn/request.json': tools.canonical(request),
             'turn/prompt.txt': PROMPT, 'credentials/api-key': runtime.OFFLINE_KEY + b'\n'}
    for path, data in files.items():
        (f / path).write_bytes(data)
        (f / path).chmod(0o400 if path.startswith('credentials/') else 0o444)
    for name in runtime.LOADER_DIRS:
        (f / 'state/codex' / name).mkdir(parents=True)
    return f


class Backend:
    def __init__(self):
        self.requests = 0
        self.action_end = time.monotonic() + 10
        self.error = None
        self.bodies = 0

    def request(self, body):
        self.bodies += 1
        tools.require(self.bodies == 1 and self.requests <= 3, 'one synthetic Responses POST required')
        tools.require(body.get('model') == MODEL and body.get('reasoning', {}).get('effort') == EFFORT,
                      'wire model and effort differ from saved selection')
        messages = body['input']
        values = [(item.get('role'), part.get('text')) for item in messages for part in item.get('content', [])
                  if isinstance(part, dict)]
        tools.require(('user', PROMPT.decode()) in values, 'stdin prompt did not reach stock CLI')
        tools.require(any(role == 'developer' and DIRECTIVE in (text or '') for role, text in values),
                      'managed startup directive absent from the actual request')
        response = {'id': 'offline-turn-1', 'usage': {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}}
        messages = [{'type': 'response.created', 'response': response},
                    {'type': 'response.output_item.done', 'item': {'type': 'message', 'id': 'offline-result',
                     'role': 'assistant', 'content': [{'type': 'output_text', 'text': ANSWER}]}},
                    {'type': 'response.completed', 'response': response}]
        return ''.join(f"event: {item['type']}\ndata: {json.dumps(item)}\n\n" for item in messages).encode()


def launch(host_netns):
    net = tools.private_loopback(host_netns)
    backend = Backend()
    with tools.FixtureServer(('127.0.0.1', PORT), tools.Handler) as server:
        server.connections = 0
        server.sequence = backend
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        thread.start()
        try:
            argv = ['/usr/bin/python3', '-I', RUNTIME, 'entry', 'turn']
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       stdin=subprocess.DEVNULL, start_new_session=True,
                                       env={'PATH': '/usr/bin:/bin', 'CODEX_HOME': '/invalid-inherited-state'})
            try:
                exit_code, output = tools.capture(process, time.monotonic() + 22, [0])
            finally:
                tools.stop(process)
            if exit_code or backend.error:
                turn = Path('/state/turns/first-turn')
                error = turn / 'stderr.txt'
                events = turn / 'events.jsonl'
                suffix = error.read_bytes()[-1600:].decode(errors='replace') if error.is_file() else ''
                shapes = [json.loads(line).get('type') for line in events.read_bytes().splitlines()] if events.is_file() else []
                raise ValueError(f'headless entry failed {exit_code}: {backend.error}, {shapes}, {output["stderr"]!r}, {suffix}')
            result = json.loads(output['stdout'])
            operation = Path('/state/turns/first-turn')
            events = (operation / 'events.jsonl').read_bytes()
            saved = json.loads((operation / 'result.json').read_bytes())
            uuid = result['session_uuid']
            rollouts = list(Path('/state/codex/sessions').rglob(f'*{uuid}.jsonl'))
            tools.require(result == saved and result['runtime_admitted'] is False and
                          result['events_sha256'] == digest(events) and ANSWER.encode() in events and
                          len(rollouts) == 1 and ANSWER.encode() in rollouts[0].read_bytes(),
                          'missing completed agent message or durable stock session')
            tools.require(backend.bodies == 1 and 1 <= backend.requests <= 3 and backend.error is None,
                          'wrong Responses traffic')
            negative = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                      timeout=4, env={'PATH': '/usr/bin:/bin'})
            tools.require(negative.returncode == 2 and not negative.stdout and backend.bodies == 1,
                          'duplicate operation was not suppressed')
            print(json.dumps({'result': result, 'loopback': net, 'requests': backend.requests,
                              'body_requests': backend.bodies, 'connections': server.connections,
                              'managed_startup_observed': True, 'stock_rollout_verified': True,
                              'duplicate_exit': negative.returncode, 'duplicate_request_delta': 0,
                              'listener_stopped': True}, sort_keys=True))
        finally:
            server.shutdown()
            thread.join(timeout=2)
            tools.require(not thread.is_alive(), 'local listener did not stop')


def setup(host_netns):
    tools.private_loopback(host_netns, setup=True)
    argv = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
            '--die-with-parent', '--uid', '1000', '--gid', '1000', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev']
    for path in ('/state', '/work/job', '/cache/job', '/tmp'):
        argv += ['--bind', path, path]
    for path in runtime.TURN_READONLY_MOUNTS:
        argv += ['--ro-bind', str(path), str(path)]
    argv += ['--cap-drop', 'ALL', '--chdir', '/work/job', '--', '/usr/bin/python3', '-I', '/opt/role-fixture.py',
             '--launch', str(host_netns)]
    os.execve(argv[0], argv, {'PATH': '/usr/bin:/bin'})


def run(binary, report):
    tools.require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'owned process reaper unavailable')
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='dp-role-entry-') as temp:
        runner = state.Harness(temp, binary)  # Copies and verifies the exact pinned 0.169.0 executable.
        f = stage(Path(temp) / 'role')
        with runner.rpc(frozen=False) as call:
            state.verify_skills_response(call('skills/list', {'cwds': ['/job'], 'forceReload': True}))
        source_skills = runner.fixture / 'state/codex/skills'
        skills_sha = digest(tools.canonical(state.inventory(source_skills)))
        shutil.copytree(source_skills, f / 'state/codex/skills', dirs_exist_ok=True)
        argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--uid', '0', '--gid', '0',
                '--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_SETPCAP', '--cap-add', 'CAP_SETFCAP',
                '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
                '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
        # The fixture uses the image's exact runtime path without writing the host /usr.
        for path in ('/usr/bin', '/usr/lib/x86_64-linux-gnu', '/usr/lib64', '/usr/lib/locale',
                     '/usr/lib/python3.13', '/usr/lib/python3', '/usr/share'):
            argv += ['--ro-bind', path, path]
        for source, dest in [('image', '/usr/lib/dev-pair/gptbox'), ('etc/codex', '/etc/codex'),
                             ('credentials', '/credentials'), ('turn', '/run/dev-pair-turn'), ('home', '/home/gpt')]:
            argv += ['--ro-bind', str(f / source), dest]
        for source, dest in [('work', '/work/job'), ('cache', '/cache/job'), ('state', '/state')]:
            argv += ['--bind', str(f / source), dest]
        for source, dest in [(runner.binary, runtime.CODEX), (Path(__file__).resolve(), '/opt/role-fixture.py'),
                             (Path(state.__file__), '/opt/codex_state.py'), (Path(tools.__file__), '/opt/codex_tools.py'),
                             (Path(state.__file__).with_name('public_inputs.py'), '/opt/public_inputs.py'),
                             (Path(state.__file__).with_name('fedora_oci.py'), '/opt/fedora_oci.py'),
                             (Path(runtime.__file__), '/opt/gptbox_runtime.py')]:
            argv += ['--ro-bind', str(source), str(dest)]
        argv += ['--remount-ro', '/', '--chdir', '/work/job', '--', '/usr/bin/python3', '-I', '/opt/role-fixture.py',
                 '--setup', str(os.stat('/proc/self/ns/net').st_ino)]
        # -I does not add the script directory. The fixed fixture entry adds /opt only below.
        process = subprocess.Popen(argv, env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                   preexec_fn=state.child_limits)
        try:
            status, output = tools.capture(process, start + 35, [0], runner.budget)
        finally:
            tools.stop(process)
            tools.reap_owned(start + 38)
        tools.require(status == 0, 'isolated role run failed: ' + output['stderr'][-3500:].decode(errors='replace'))
        result = json.loads(output['stdout'])
        result.update(owned_fixture_cleanup=True, binary_sha256=state.CODEX_SHA,
                      frozen_skills_inventory_sha256=skills_sha,
                      runtime_sha256=digest(Path(runtime.__file__).read_bytes()), elapsed_seconds=round(time.monotonic() - start, 3))
    with Path(report).open('x') as destination:
        json.dump(result, destination, sort_keys=True, indent=2)
        destination.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--launch', type=int)
    parser.add_argument('--setup', type=int)
    args = parser.parse_args()
    if args.launch:
        launch(args.launch)
    elif args.setup:
        setup(args.setup)
    else:
        run(args.binary, args.report)
