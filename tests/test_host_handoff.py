import contextlib
import copy
import os
import pathlib
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import host_handoff as h
import job_protocol as p


APP = '''\
import argparse
import json
import pathlib
import socket
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('command', choices=['serve'])
parser.add_argument('--database')
parser.add_argument('--listen-fd', type=int)
args = parser.parse_args()
assert not pathlib.Path(OUTSIDE).exists()
try:
    pathlib.Path(OUTSIDE).read_text()
except FileNotFoundError:
    pass
else:
    raise AssertionError('controller canary was readable')
if CANARY_PORT:
    try:
        socket.create_connection(('127.0.0.1', CANARY_PORT), timeout=0.2).close()
    except OSError:
        pass
    else:
        raise AssertionError('unrelated controller listener was reachable')
db = sqlite3.connect(args.database)
db.execute('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, title TEXT, done INTEGER)')
if MODE == 'forget':
    db.execute('DELETE FROM items')
db.commit()


def item(row):
    return {'id': row[0], 'title': row[1], 'done': bool(row[2])}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == '/items':
            length = int(self.headers['Content-Length'])
            title = json.loads(self.rfile.read(length))['title']
            cursor = db.execute('INSERT INTO items(title,done) VALUES (?,0)', (title,))
            db.commit()
            self.reply(201, item((cursor.lastrowid, title, 0)))
        else:
            item_id = int(self.path.split('/')[2])
            db.execute('UPDATE items SET done=1 WHERE id=?', (item_id,))
            db.commit()
            if MODE == 'stall':
                time.sleep(30)
            self.reply(200, item(db.execute('SELECT * FROM items WHERE id=?', (item_id,)).fetchone()))

    def do_GET(self):
        self.reply(200, [item(row) for row in db.execute('SELECT * FROM items ORDER BY id')])


server = HTTPServer(('127.0.0.1', 0), Handler, bind_and_activate=False)
server.socket.close()
server.socket = socket.socket(fileno=args.listen_fd)
port = server.socket.getsockname()[1]
if MODE == 'stall':
    pathlib.Path('listening-port').write_text(str(port))
print(f'http://127.0.0.1:{port}', flush=True)
server.serve_forever()
'''


@unittest.skipUnless(h.BWRAP.is_file() and h.APP_PYTHON.is_file() and shutil.which('openssl'),
                     'requires local bubblewrap, system Python and OpenSSL test principals')
class AuthenticatedHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check = subprocess.run([str(h.BWRAP), '--unshare-all', '--unshare-user', '--disable-userns',
                                '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
                                '--symlink', 'usr/lib64', '/lib64', '--', '/usr/bin/true'],
                               capture_output=True, timeout=3)
        if check.returncode:
            raise unittest.SkipTest('local unprivileged namespace sandbox is unavailable')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dev-pair-host-handoff-')
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.state = self.root / 'ledger'
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir(mode=0o700)
        self.secret_canary = self.write('outside-canary', b'controller-private test canary')
        self.maintenance = self.tls('maintenance')
        self.development = self.tls('development')
        self.peer(self.maintenance, self.development)
        self.peer(self.development, self.maintenance)
        self.budget = {'seconds': 9, 'artifact_bytes': p.MAX_MESSAGE, 'spend_usd': 0}
        self.job = p.envelope('job', job_id='checklist-proof', standards_sha=p.STANDARDS,
                              agreement_sha256='1' * 64, budgets=self.budget, max_requests=6,
                              selection={'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                                         'runtime_sha256': '2' * 64, 'verification': 'unverified-record-only'})
        self.jobs('job', self.write('job.json', p.canonical(self.job).encode()))

    def write(self, name, data):
        path = self.root / name
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(data)
        return path

    def tls(self, name):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '2', '-subj', '/CN=' + name, '-keyout', directory / 'key.pem',
                        '-out', directory / 'cert.pem'], check=True, capture_output=True, timeout=4)
        for child in directory.iterdir():
            child.chmod(0o600)
        return directory

    def peer(self, role, peer):
        return self.write(str(role.relative_to(self.root) / 'peer.pem'), (peer / 'cert.pem').read_bytes())

    def fixture(self, mode, *, canary_port=0):
        source = f'MODE = {mode!r}\nOUTSIDE = {str(self.secret_canary)!r}\nCANARY_PORT = {canary_port}\n' + APP
        return self.write(mode + '.py', source.encode())

    def run_cli(self, program, *args, input=None, ok=True):
        proc = subprocess.run([sys.executable, '-B', TOOLS / program, *map(str, args)],
                              input=input, capture_output=True, timeout=16)
        if not ok:
            self.assertEqual(proc.returncode, 2, proc.stdout)
            return proc.stderr.decode()
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        return p.loads(proc.stdout)

    def jobs(self, *args, **kwargs):
        return self.run_cli('jobs.py', '--state', self.state, *args, **kwargs)

    def checkpoint(self, artifact, name, revision=None):
        data = artifact.read_bytes()
        candidate = {'source_revision': revision or p.sha256(data)[:40], 'artifact_sha256': p.sha256(data)}
        checkpoint = p.envelope('checkpoint', job_id=self.job['job_id'], checkpoint_id='cp-' + name,
                                candidate=candidate, test=h.recipe_identity(), summary='Checklist candidate', evidence=[])
        path = self.write(name + '-checkpoint.json', p.canonical(checkpoint).encode())
        self.jobs('checkpoint', path)
        return path, candidate

    @contextlib.contextmanager
    def server(self, artifact, candidate, *, tls=None):
        process = subprocess.Popen([sys.executable, '-B', TOOLS / 'host_handoff.py', 'serve',
                                    '--state', self.state, '--scratch', self.scratch, '--candidate', artifact,
                                    '--tls', tls or self.maintenance, '--job-id', self.job['job_id'],
                                    '--source-revision', candidate['source_revision'],
                                    '--artifact-sha256', candidate['artifact_sha256'], '--lifetime', '25'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 4)[0], 'executor readiness timed out')
            line = process.stdout.readline(512)
            if not line:
                self.fail(process.stderr.read(2048).decode())
            yield process, p.loads(line)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=3)

    def request(self, checkpoint, request_id, ready, *, tls=None):
        return self.run_cli('host_handoff.py', 'request', checkpoint, request_id,
                            '--seconds', self.budget['seconds'], '--artifact-bytes', self.budget['artifact_bytes'],
                            '--controller-id', ready['controller_id'], '--tls', tls or self.development)

    def send_command(self, operation, ready, *, tls=None):
        return ['send', operation, '--port', ready['port'], '--controller-id', ready['controller_id'],
                '--tls', tls or self.development]

    def send(self, operation, ready, request, *, tls=None, ok=True):
        return self.run_cli('host_handoff.py', *self.send_command(operation, ready, tls=tls),
                            input=p.canonical(request).encode(), ok=ok)

    def failure_repair_journey(self, good, *, revision=None, bad=None, bad_revision=None):
        bad = bad or self.fixture('forget')
        cp_bad, candidate_bad = self.checkpoint(bad, 'bad', bad_revision)
        with self.server(bad, candidate_bad) as (_, first):
            request_bad = self.request(cp_bad, 'bad-candidate', first)
            self.assertEqual(self.send('submit', first, request_bad)['state'], 'pending')
        with self.server(bad, candidate_bad) as (_, second):
            self.assertEqual(first['controller_id'], second['controller_id'])
            failed = self.send('execute', second, request_bad)
            self.assertEqual(failed['status'], 'fail', failed)
            self.assertEqual(failed['cleanup']['status'], 'complete')
            self.assertIn('missing', failed['checks'][0]['actual'])
            self.assertEqual(self.send('consume', second, request_bad)['progress'], 'repair-required')
        cp_good, candidate_good = self.checkpoint(good, 'good', revision)
        with self.server(good, candidate_good) as (_, third):
            stale = self.send('consume', third, request_bad, ok=False)
            self.assertIn('outside the approved job and candidate', stale)
            request_good = self.request(cp_good, 'repaired-candidate', third)
            self.assertEqual(self.send('submit', third, request_good)['state'], 'pending')
            passed = self.send('execute', third, request_good)
            self.assertEqual(passed['status'], 'pass', passed)
            self.assertEqual(passed['cleanup']['status'], 'complete')
            self.assertEqual(len(passed['effects']), 3)
        backup, restored = self.root / 'backup', self.root / 'restored'
        self.jobs('backup', backup)
        self.run_cli('jobs.py', '--state', restored, 'restore', backup)
        self.state = restored
        with self.server(good, candidate_good) as (_, fourth):
            self.assertEqual(third['controller_id'], fourth['controller_id'])
            self.assertEqual(self.send('execute', fourth, request_good), passed)
            consumed = self.send('consume', fourth, request_good)
            self.assertEqual(consumed, {'progress': 'process-checks-passed', 'result': passed})
            self.assertEqual(self.send('consume', fourth, request_good), consumed)
            self.assertEqual(self.send('submit', fourth, request_good)['result'], passed)
            changed = copy.deepcopy(request_good)
            changed['budgets']['seconds'] -= 1
            self.assertIn('collision', self.send('execute', fourth, changed, ok=False))
            self.assertIn('collision', self.send('submit', fourth, changed, ok=False))
        inspected = self.jobs('inspect', self.job['job_id'])
        self.assertEqual([item['result'] for item in inspected['requests']], [failed, passed])
        self.assertEqual(inspected['progress'], 'process-checks-passed')
        events = self.jobs('events')
        self.assertEqual([event['event'] for event in events].count('execution-reserved'), 2)
        self.assertEqual([event['event'] for event in events].count('consumed'), 2)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return {'failed': failed, 'passed': passed, 'consumed': consumed,
                'requests': [request_bad, request_good], 'events': events}

    def test_real_process_failure_repair_with_private_mount_and_network(self):
        with socket.socket(socket.AF_INET) as canary:
            canary.bind(('127.0.0.1', 0))
            canary.listen(1)
            good = self.fixture('persistent', canary_port=canary.getsockname()[1])
            self.failure_repair_journey(good)
            self.assertEqual(select.select([canary], [], [], 0)[0], [])

    def test_mutual_tls_exact_grant_and_trusted_result_binding(self):
        artifact = self.fixture('persistent')
        cp, candidate = self.checkpoint(artifact, 'only')
        intruder = self.tls('intruder')
        self.peer(intruder, self.maintenance)
        impostor = self.tls('impostor-server')
        self.peer(impostor, self.development)
        with self.server(artifact, candidate, tls=impostor) as (_, fake):
            request = self.request(cp, 'one-request', fake)
            self.assertIn('TLS', self.send('submit', fake, request, ok=False))
        with self.server(artifact, candidate) as (_, ready):
            forged = self.request(cp, 'one-request', ready, tls=intruder)
            self.assertIn('TLS', self.send('submit', ready, forged, tls=intruder, ok=False))
            request = self.request(cp, 'one-request', ready)
            context, peer, _ = h.tls_principal(self.development, maintenance=False)
            scoped = copy.deepcopy(request)
            scoped['candidate']['source_revision'] = 'a' * 40
            with self.assertRaisesRegex(ValueError, 'outside the approved'):
                h.exchange(ready['port'], context, peer, 'submit', scoped)
            for key in ('url', 'command', 'service', 'path'):
                with self.assertRaisesRegex(ValueError, 'unknown fields'):
                    h.exchange(ready['port'], context, peer, 'submit', dict(request, **{key: 'denied'}))
            self.assertIn('unknown request', self.jobs('status', request['request_id'], ok=False))
            path = self.write('unauthenticated.json', p.canonical(request).encode())
            self.assertIn('authenticated transport', self.jobs('submit', path, ok=False))
            self.assertEqual(self.send('submit', ready, request)['state'], 'pending')
            self.assertIn('authenticated transport', self.jobs('execute-local', request['request_id'],
                                                               '--artifact', artifact, ok=False))
            result = self.send('execute', ready, request)
            self.assertEqual(result['status'], 'pass', result)
            for key in ('request_sha256', 'implementation_sha256', 'environment', 'controller_id'):
                forged = copy.deepcopy(result)
                if key == 'request_sha256':
                    forged[key] = 'a' * 64
                elif key == 'implementation_sha256':
                    forged['executor'][key] = 'a' * 64
                else:
                    forged['executor'][key] = 'forged'
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    h.check_reply('execute', forged, request, ready['controller_id'])
            self.checkpoint(artifact, 'new-checkpoint', candidate['source_revision'])
            for operation in h.OPERATIONS:
                self.assertIn('stale checkpoint', self.send(operation, ready, request, ok=False))

    def test_kill_after_effect_preserves_attempt_and_refuses_replay(self):
        artifact = self.fixture('stall')
        cp, candidate = self.checkpoint(artifact, 'unknown')
        with self.server(artifact, candidate) as (executor, ready):
            request = self.request(cp, 'unknown-outcome', ready)
            self.send('submit', ready, request)
            client = subprocess.Popen([sys.executable, '-B', TOOLS / 'host_handoff.py',
                                       *map(str, self.send_command('execute', ready))],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                client.stdin.write(p.canonical(request).encode())
                client.stdin.close()
                client.stdin = None
                deadline = time.monotonic() + 5
                while True:
                    databases = list(self.scratch.glob('*/checklist.sqlite3'))
                    if databases:
                        with contextlib.closing(sqlite3.connect(databases[0].as_uri() + '?mode=ro',
                                                               uri=True, timeout=0.2)) as db:
                            if db.execute('SELECT name FROM sqlite_master WHERE name=?', ('items',)).fetchone():
                                rows = db.execute('SELECT id,title,done FROM items').fetchall()
                                if rows and rows[0][2]:
                                    break
                    self.assertLess(time.monotonic(), deadline, 'item completion was never committed')
                    time.sleep(0.02)
                workspace = databases[0].parent
                port = int((workspace / 'listening-port').read_text())
                executor.kill()
                executor.wait(timeout=3)
                _, stderr = client.communicate(timeout=4)
                self.assertEqual(client.returncode, 2, stderr.decode())
            finally:
                if client.poll() is None:
                    client.kill()
                    client.communicate(timeout=3)
        status = self.jobs('status', request['request_id'])
        self.assertEqual(status['attempt_id'], workspace.name)
        self.assertEqual(rows, [(1, h.RECIPE + '-' + status['attempt_id'], 1)])
        self.assertEqual(status['state'], 'in-flight')
        with self.server(artifact, candidate) as (_, restarted):
            self.assertEqual(self.send('submit', restarted, request), status)
            self.assertIn('execution refused', self.send('execute', restarted, request, ok=False))
            self.assertIn('no completed result', self.send('consume', restarted, request, ok=False))
        self.assertIn('remains unresolved', self.jobs('reconcile', request['request_id'], '--diagnostic', 'seen',
                                                      '--evidence', 'inspection', ok=False))
        self.assertEqual([event['event'] for event in self.jobs('events')].count('execution-reserved'), 1)
        self.assertEqual(list(self.scratch.iterdir()), [workspace])
        with contextlib.closing(sqlite3.connect(databases[0].as_uri() + '?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('SELECT id,title,done FROM items').fetchall(), rows)
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', port), timeout=1).close()


if __name__ == '__main__':
    unittest.main()
