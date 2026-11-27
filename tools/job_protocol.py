"""Version 1 job protocol and trusted-controller recovery ledger.

Transport authentication belongs to the local process adapter. The filesystem
principal that owns this module and ledger is the controller.
"""
import contextlib
import base64
import fcntl
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

VERSION = 1
STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
WORKLOAD_ACCESS = 'workload-access.json'
WORKLOAD_LEASE = 'renewal-fence/driver.lock'
RECIPE = 'local-json-message-v1'
APP_PROCESS_BOUNDARY = 'local-app-process'
APP_QUADLET_BOUNDARY = 'fedora-checklist-quadlet'
AUTHENTICATED_BOUNDARIES = (APP_PROCESS_BOUNDARY, APP_QUADLET_BOUNDARY)
QUADLET_ENVIRONMENT = 'Fedora 44 user systemd and rootless Podman Quadlet executor with SELinux enforcement gate.'
HOST_EFFECT_RECEIPT = 'durable-effect-receipt'
HOST_EFFECT_ARMED = 'host-effect-armed'
HOST_RESULT_STAGED = 'host-result-staged'
HOST_EFFECT_CLOSED = 'host-effect-closed'
HOST_ABSENCE_EVIDENCE = ['generated-unit-absent', 'rootless-container-absent', 'disposable-workspace-absent']
MAX_MESSAGE = 65536
# Requests reserve three quarters of the envelope for executor diagnostics,
# per-check actual/verdict fields, identity and reconciliation evidence. These
# are canonical encoded byte budgets (including JSON escaping), not characters.
MAX_REQUEST_BYTES = 16384
MAX_RECONCILIATION_BYTES = 8192


def require(ok, message):
    if not ok:
        raise ValueError(message)


@contextlib.contextmanager
def workload_access_lease(root, *, exclusive=False):
    path = root / WORKLOAD_LEASE
    for parent in path.parents:
        node = parent.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022,
                'unprotected workload dispatch lease ancestry')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink in (1, 2) and
                stat.S_IMODE(node.st_mode) == 0o644, 'unprotected workload dispatch lease')
        if os.geteuid() == 0:
            try:
                earlier = (root / 'renewal' / 'driver.lock').lstat()
            except FileNotFoundError:
                pass
            else:
                require((earlier.st_dev, earlier.st_ino) == (node.st_dev, node.st_ino),
                        'historical renewal uses a different workload dispatch lease')
        fcntl.flock(stream, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        live = path.lstat()
        require((live.st_dev, live.st_ino) == (node.st_dev, node.st_ino), 'workload dispatch lease changed')
        yield


def require_workload_access(root=pathlib.Path('/var/lib/dev-pair'), *, release=None, images=None):
    """Read the root controller's public, credential-free authorization state."""
    flag = root / WORKLOAD_ACCESS
    try:
        fd = os.open(flag, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise ValueError('managed workload access observation is unavailable') from None
    with os.fdopen(fd, 'rb') as stream:
        for parent in (root, *root.parents):
            node = parent.lstat()
            require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022,
                    'unprotected workload access ancestry')
        node = os.fstat(stream.fileno())
        require(stat.S_ISREG(node.st_mode) and (node.st_uid, node.st_nlink, stat.S_IMODE(node.st_mode)) == (0, 1, 0o644)
                and 0 < node.st_size <= 512, 'unprotected workload access observation')
        raw = stream.read(513)
        current = flag.lstat()
        require((current.st_dev, current.st_ino) == (node.st_dev, node.st_ino), 'workload access observation changed')
    require(len(raw) <= 512, 'workload access observation changed')
    gate = loads(raw)
    fields(gate, 'schema phase release_sha256 images')
    require(type(gate['schema']) is int and gate['schema'] == 1 and gate['phase'] in ('legacy', 'held', 'admitted'),
            'invalid workload access observation')
    if gate['phase'] in ('admitted', 'legacy') and gate['release_sha256'] is not None:
        digest(gate['release_sha256'])
        fields(gate['images'], 'maintenance development devbox')
        for value in gate['images'].values():
            digest(value)
        require(release is None or release == gate['release_sha256'], 'current release requires independent workload access review')
        require(images is None or all(gate['images'].get(role) == image for role, image in images.items()),
                'selected role image requires independent workload access review')
    else:
        require(gate['phase'] == 'legacy' and gate['release_sha256'] is None and gate['images'] is None,
                'independent workload access review is pending')
        require(release is None, 'standalone access review has no verified managed workload selection')
        for marker in (root / 'renewal', root / 'renewal-fence' / 'selected-host.json'):
            try:
                marker.lstat()
            except FileNotFoundError:
                continue
            raise ValueError('standalone access review has no verified managed workload selection')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def identity(value):
    return sha256(canonical(value).encode())


def loads(data):
    require(len(data) <= MAX_MESSAGE, 'message exceeds protocol byte limit')
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate JSON field')
            obj[key] = value
        return obj
    def invalid(value):
        raise ValueError('non-finite JSON value')
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except RecursionError as exc:
        raise ValueError('JSON nesting limit exceeded') from exc


def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), 'missing or unknown fields')


def text(value, limit=2000):
    require(type(value) is str and 0 < len(value) <= limit and
            all(ord(c) >= 32 for c in value), 'invalid text')


def token(value):
    require(type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value), 'invalid ID')


def digest(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value), 'invalid digest')


def number(value, low, high):
    require(type(value) is int and low <= value <= high, 'invalid numeric budget')


def references(value):
    require(type(value) is list and len(value) <= 32, 'invalid evidence references')
    for item in value:
        text(item)


def app_transport(request):
    values = request['fixtures']
    require(len(values) == 3, 'application request requires three transport bindings')
    prefixes = ('controller:', 'development-cert-sha256:', 'maintenance-cert-sha256:')
    require(all(value.startswith(prefix) for value, prefix in zip(values, prefixes)),
            'invalid application transport bindings')
    controller, development, maintenance = [value[len(prefix):] for value, prefix in zip(values, prefixes)]
    token(controller)
    digest(development)
    digest(maintenance)
    require(development != maintenance, 'distinct test principals required')
    return controller, development, maintenance


def app_environment(request):
    app_transport(request)
    description = (QUADLET_ENVIRONMENT if request['boundary'] == APP_QUADLET_BOUNDARY else
                   'Local Linux namespace sandbox over mutually authenticated loopback TLS.')
    return description + ' ' + ' '.join(request['fixtures'][1:])


def candidate(value):
    fields(value, 'source_revision artifact_sha256')
    digest(value['source_revision'], 40)
    digest(value['artifact_sha256'])


def test_identity(value):
    fields(value, 'revision recipe recipe_sha256')
    digest(value['revision'])
    token(value['recipe'])
    digest(value['recipe_sha256'])


def recipe_identity():
    implementation = sha256(pathlib.Path(__file__).read_bytes())
    return {'revision': implementation, 'recipe': RECIPE, 'recipe_sha256': implementation}


def budgets(value):
    fields(value, 'seconds artifact_bytes spend_usd')
    number(value['seconds'], 1, 60)
    number(value['artifact_bytes'], 1, MAX_MESSAGE)
    require(type(value['spend_usd']) is int and value['spend_usd'] == 0, 'paid execution unsupported')


def validate(obj, kind=None):
    require(type(obj) is dict and type(obj.get('version')) is int and obj['version'] == VERSION,
            'unsupported protocol version')
    kind = kind or obj.get('kind')
    require(obj.get('kind') == kind, 'wrong message kind')
    shapes = {
        'job': 'version kind job_id standards_sha agreement_sha256 selection budgets max_requests',
        'checkpoint': 'version kind job_id checkpoint_id candidate test summary evidence',
        'request': 'version kind job_id request_id checkpoint_id candidate test boundary reason capabilities permitted_effects workspace fixtures budgets checks cleanup',
        'result': 'version kind job_id request_id request_sha256 checkpoint_id candidate test executor attempt_id status checks diagnostics evidence effects cleanup',
    }
    require(kind in shapes, 'unsupported message kind')
    fields(obj, shapes[kind])
    token(obj['job_id'])
    if kind == 'job':
        require(obj['standards_sha'] == STANDARDS, 'standards pin mismatch')
        digest(obj['agreement_sha256'])
        fields(obj['selection'], 'provider model effort runtime_sha256 verification')
        require(obj['selection']['verification'] == 'unverified-record-only', 'agent runtime admission unsupported')
        require(obj['selection']['provider'] == 'gptbox', 'unsupported provider')
        require(type(obj['selection']['model']) is str and
                re.fullmatch(r'gpt-[a-z0-9]+(?:[.-][a-z0-9]+)+', obj['selection']['model']) and
                obj['selection']['model'] not in ('gpt-latest', 'gpt-default', 'gpt-auto'), 'explicit model identity required')
        require(obj['selection']['effort'] in ('low', 'medium', 'high', 'xhigh'), 'unsupported effort')
        digest(obj['selection']['runtime_sha256'])
        budgets(obj['budgets'])
        number(obj['max_requests'], 1, 100)
    else:
        token(obj['checkpoint_id'])
        candidate(obj['candidate'])
        test_identity(obj['test'])
    if kind == 'checkpoint':
        text(obj['summary'])
        references(obj['evidence'])
    if kind in ('request', 'result'):
        token(obj['request_id'])
        require(type(obj['checks']) is list and 1 <= len(obj['checks']) <= 16, 'invalid checks')
        seen = set()
        for check in obj['checks']:
            fields(check, 'id expected' if kind == 'request' else
                   'id expected actual status exit_status diagnostics evidence')
            token(check['id'])
            require(check['id'] not in seen, 'duplicate check ID')
            seen.add(check['id'])
            text(check['expected'])
            if kind == 'result':
                text(check['actual'])
                require(check['status'] in ('pass', 'fail', 'blocked'), 'invalid check verdict')
                require(check['exit_status'] is None or type(check['exit_status']) is int and
                        0 <= check['exit_status'] <= 255, 'invalid exit status')
                text(check['diagnostics'])
                references(check['evidence'])
    if kind == 'request':
        require(obj['boundary'] in ('local-protocol', 'fedora-host', *AUTHENTICATED_BOUNDARIES),
                'unsupported boundary')
        text(obj['reason'])
        for name in ('capabilities', 'permitted_effects'):
            require(type(obj[name]) is list and len(obj[name]) <= 16 and
                    len(set(map(canonical, obj[name]))) == len(obj[name]), 'invalid scope list')
            for item in obj[name]:
                token(item)
        token(obj['workspace'])  # logical job-owned workspace ID, never a submitted host path
        references(obj['fixtures'])
        if obj['boundary'] in AUTHENTICATED_BOUNDARIES:
            app_transport(obj)
        budgets(obj['budgets'])
        fields(obj['cleanup'], 'plan preserve')
        text(obj['cleanup']['plan'])
        require(obj['cleanup']['preserve'] == ['source', 'checkpoints', 'evidence', 'deliverables'],
                'durable data must be preserved')
    if kind == 'result':
        digest(obj['request_sha256'])
        text(obj['attempt_id'], 100)
        fields(obj['executor'], 'controller_id environment boundary implementation_sha256')
        token(obj['executor']['controller_id'])
        text(obj['executor']['environment'])
        require(obj['executor']['boundary'] in ('local-protocol', *AUTHENTICATED_BOUNDARIES),
                'unverified executor boundary')
        digest(obj['executor']['implementation_sha256'])
        require(obj['status'] == verdict(obj['checks']), 'aggregate verdict mismatch')
        text(obj['diagnostics'])
        references(obj['evidence'])
        references(obj['effects'])
        fields(obj['cleanup'], 'status diagnostics')
        require(obj['cleanup']['status'] in ('complete', 'not-needed', 'unresolved'), 'invalid cleanup')
        text(obj['cleanup']['diagnostics'])
    size_limit = MAX_REQUEST_BYTES if kind == 'request' else MAX_MESSAGE
    require(len(canonical(obj).encode()) <= size_limit,
            'request exceeds response-reserving byte limit' if kind == 'request' else 'message exceeds protocol byte limit')
    return obj


def verdict(checks):
    states = {check['status'] for check in checks}
    return 'fail' if 'fail' in states else 'blocked' if 'blocked' in states else 'pass'


def result_progress(result):
    if result['status'] == 'pass':
        return {APP_PROCESS_BOUNDARY: 'process-checks-passed', APP_QUADLET_BOUNDARY: 'host-checks-passed'}.get(
            result['executor']['boundary'], 'local-checks-passed')
    return 'repair-required' if result['status'] == 'fail' else 'blocked'


def match_result(request, result, controller_id):
    require(result['executor']['controller_id'] == controller_id, 'controller identity mismatch')
    require(result['request_id'] == request['request_id'] and result['request_sha256'] == identity(request) and
            all(result[key] == request[key] for key in ('job_id', 'checkpoint_id', 'candidate', 'test')),
            'result identity mismatch')
    require([(c['id'], c['expected']) for c in result['checks']] ==
            [(c['id'], c['expected']) for c in request['checks']], 'result check mismatch')
    authenticated = request['boundary'] in AUTHENTICATED_BOUNDARIES
    expected_boundary = request['boundary'] if authenticated else 'local-protocol'
    require(result['executor']['boundary'] == expected_boundary, 'result boundary mismatch')
    if authenticated:
        require(app_transport(request)[0] == controller_id and
                result['executor']['implementation_sha256'] == request['test']['recipe_sha256'] and
                result['executor']['environment'] == app_environment(request),
                'result implementation or transport identity mismatch')


def host_effect_journal(request):
    return request['boundary'] == APP_QUADLET_BOUNDARY and HOST_EFFECT_RECEIPT in request['capabilities']


def effect_identity(request, attempt):
    return {'request_id': request['request_id'], 'attempt_id': attempt, 'request_sha256': identity(request)}


def validate_staged_host_result(request, result, attempt, controller):
    validate(result, 'result')
    match_result(request, result, controller)
    require(result['attempt_id'] == attempt and result['cleanup']['status'] in ('complete', 'not-needed'),
            'staged host result or cleanup identity mismatch')
    if result['cleanup']['status'] == 'not-needed':
        require(result['status'] == 'blocked' and not result['effects'], 'unstaged resources contradict host result')


def closed_host_result(request, attempt, controller, armed, staged, closure):
    fields(closure, 'request_id attempt_id request_sha256 mode evidence')
    require(all(closure[k] == value for k, value in effect_identity(request, attempt).items()),
            'host closure identity mismatch')
    mode, evidence = closure['mode'], closure['evidence']
    references(evidence)
    if mode == 'cleaned':
        require(armed and staged is not None and evidence == ['owned-cleanup-completed'], 'invalid host cleanup closure')
        return staged
    require(evidence == HOST_ABSENCE_EVIDENCE, 'host reconciliation requires exact resource absence evidence')
    if mode == 'recovered-result':
        require(armed and staged is not None, 'host observation unavailable for recovery')
        return staged
    require(mode == 'zero-effect' and not armed and staged is None, 'unresolved effect cannot be closed as absent')
    diagnostics = 'The prior controller stopped before arming the effect. The owned resources were absent.'
    checks = [dict(check, actual='No checklist action was started', status='blocked',
                   diagnostics=diagnostics, exit_status=None, evidence=evidence) for check in request['checks']]
    return envelope('result', **{key: request[key] for key in ('job_id', 'request_id', 'checkpoint_id', 'candidate', 'test')},
                    request_sha256=closure['request_sha256'], attempt_id=attempt, status='blocked', checks=checks,
                    executor={'controller_id': controller, 'environment': app_environment(request),
                              'boundary': APP_QUADLET_BOUNDARY, 'implementation_sha256': request['test']['recipe_sha256']},
                    diagnostics=diagnostics, evidence=['effect-id:' + attempt, *evidence], effects=[],
                    cleanup={'status': 'not-needed', 'diagnostics': 'No owned unit, container or test workspace'})


def envelope(kind, **values):
    return validate(dict(version=VERSION, kind=kind, **values), kind)


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            'ledger files must be private regular files owned by controller')


class Ledger:
    """Only trusted controller processes may open this database or call mutators.

    Request JSON grants no authority. Same-UID controller/code compromise is
    outside this boundary; mode checks do not authenticate remote senders.
    """
    def __init__(self, directory, *, host_history=None):
        self.root = pathlib.Path(directory).absolute()
        self.host_history = host_history
        # Never follow a symlink component. Ancestors are operator-managed;
        # private leaf prevents a different UID from replacing database paths.
        for part in [self.root, *self.root.parents]:
            require(not part.is_symlink(), 'symlink state path denied')
            if part.exists() and part != self.root:
                ancestor = part.stat()
                require(ancestor.st_uid in (0, os.getuid()) and
                        (not ancestor.st_mode & 0o022 or
                         ancestor.st_uid == 0 and ancestor.st_mode & stat.S_ISVTX),
                        'state ancestors must be trusted and not writable by other principals')
        try:
            self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            created = False
        else:
            created = True
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700, 'state directory must be controller-owned mode 0700')
        self.path = self.root / 'ledger.sqlite3'
        # A crash after exclusive destination reservation must never silently
        # initialize an empty ledger or admit a partially restored database.
        require(created or self.path.exists(), 'incomplete existing ledger directory')
        from ledger_recovery import check_admission
        check_admission(self.root)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        for name in ('ledger.sqlite3', 'ledger.sqlite3-journal', 'ledger.sqlite3-wal', 'ledger.sqlite3-shm'):
            path = self.root / name
            if path.exists() or path.is_symlink():
                private_file(path)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        # Rollback journal avoids persistent WAL files and makes backup portable
        # through SQLite's backup API, never by copying a live database file.
        self.db.execute('PRAGMA journal_mode=DELETE')
        with self.transaction():
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            require(version in (0, VERSION), 'unsupported ledger version')
            self.db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body TEXT NOT NULL, PRIMARY KEY(kind,id))')
            self.db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, checkpoint TEXT, state TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, job TEXT NOT NULL, state TEXT NOT NULL, attempt TEXT, result TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL, body TEXT NOT NULL)')
            self.db.execute('INSERT OR IGNORE INTO metadata VALUES (?,?)', ('controller_id', 'local-' + uuid.uuid4().hex))
            self.db.execute('PRAGMA user_version=1')
        self.controller_id = self.db.execute('SELECT value FROM metadata WHERE key=?', ('controller_id',)).fetchone()[0]

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def event(self, name, body):
        self.db.execute('INSERT INTO events(at,event,body) VALUES (?,?,?)', (time.time(), name, canonical(body)))

    def record(self, kind, record_id):
        row = self.db.execute('SELECT body FROM records WHERE kind=? AND id=?', (kind, record_id)).fetchone()
        require(row is not None, 'unknown ' + kind)
        return validate(loads(row['body']), kind)

    def put(self, obj, record_id):
        old = self.db.execute('SELECT body FROM records WHERE kind=? AND id=?', (obj['kind'], record_id)).fetchone()
        if old:
            require(old['body'] == canonical(obj), 'ID collision: identity mismatch')
            return False
        self.db.execute('INSERT INTO records VALUES (?,?,?)', (obj['kind'], record_id, canonical(obj)))
        self.event(obj['kind'], obj)
        return True

    def no_inflight(self, job_id):
        require(self.db.execute('SELECT 1 FROM requests WHERE job=? AND state=?',
                               (job_id, 'in-flight')).fetchone() is None,
                'unresolved in-flight effects require reconciliation')

    def create_job(self, obj):
        validate(obj, 'job')
        with self.transaction():
            if self.put(obj, obj['job_id']):
                self.db.execute('INSERT INTO jobs VALUES (?,NULL,?)', (obj['job_id'], 'awaiting-checkpoint'))
        return obj

    def checkpoint(self, obj):
        validate(obj, 'checkpoint')
        with self.transaction():
            self.record('job', obj['job_id'])
            if self.db.execute('SELECT 1 FROM records WHERE kind=? AND id=?', ('checkpoint', obj['checkpoint_id'])).fetchone():
                self.put(obj, obj['checkpoint_id'])
                return obj  # an old duplicate never moves current state backwards
            self.no_inflight(obj['job_id'])
            self.put(obj, obj['checkpoint_id'])
            self.db.execute('UPDATE jobs SET checkpoint=?,state=? WHERE id=?',
                            (obj['checkpoint_id'], 'awaiting-result', obj['job_id']))
        return obj

    def current(self, obj):
        row = self.db.execute('SELECT checkpoint FROM jobs WHERE id=?', (obj['job_id'],)).fetchone()
        require(row is not None and row['checkpoint'] == obj['checkpoint_id'], 'stale checkpoint')
        cp = self.record('checkpoint', obj['checkpoint_id'])
        require(cp['candidate'] == obj['candidate'] and cp['test'] == obj['test'], 'candidate/test mismatch')

    def submit(self, obj, *, authenticated=False):
        validate(obj, 'request')
        require(obj['boundary'] not in AUTHENTICATED_BOUNDARIES or authenticated,
                'application request requires authenticated transport')
        with self.transaction():
            old = self.db.execute('SELECT body FROM records WHERE kind=? AND id=?',
                                  ('request', obj['request_id'])).fetchone()
            if old is None:
                self._submit(obj)
            else:
                require(old['body'] == canonical(obj), 'ID collision: request mismatch')
                if authenticated:
                    self.current(obj)
        return self.status(obj['request_id'])

    def _submit(self, obj):
        job = self.record('job', obj['job_id'])
        self.current(obj)
        self.no_inflight(obj['job_id'])
        count = self.db.execute('SELECT count(*) FROM requests WHERE job=?', (obj['job_id'],)).fetchone()[0]
        require(count < job['max_requests'], 'job request budget exhausted')
        for name in ('seconds', 'artifact_bytes', 'spend_usd'):
            require(obj['budgets'][name] <= job['budgets'][name], 'request exceeds job budget')
        self.put(obj, obj['request_id'])
        self.db.execute('INSERT INTO requests VALUES (?,?,?,NULL,NULL)', (obj['request_id'], obj['job_id'], 'pending'))

    def produce_request(self, job_id, request_id, expected_message, boundary, reason):
        """Produce, then submit using the identical schema as the consumer."""
        job = self.record('job', job_id)
        row = self.db.execute('SELECT checkpoint FROM jobs WHERE id=?', (job_id,)).fetchone()
        require(row is not None and row['checkpoint'], 'job has no checkpoint')
        cp = self.record('checkpoint', row['checkpoint'])
        request = envelope('request', job_id=job_id, request_id=request_id, checkpoint_id=cp['checkpoint_id'],
                           candidate=cp['candidate'], test=cp['test'], boundary=boundary, reason=reason,
                           capabilities=['local-json-read'], permitted_effects=['read-artifact', 'write-ledger'],
                           workspace=job_id, fixtures=[], budgets=job['budgets'],
                           checks=[{'id': 'json-object', 'expected': 'object containing only a message string'},
                                   {'id': 'message-equals', 'expected': expected_message}],
                           cleanup={'plan': 'No disposable resources; preserve durable records',
                                    'preserve': ['source', 'checkpoints', 'evidence', 'deliverables']})
        return self.submit(request)

    def status(self, request_id):
        row = self.db.execute('SELECT * FROM requests WHERE id=?', (request_id,)).fetchone()
        require(row is not None, 'unknown request')
        request = self.record('request', request_id)
        result = validate(loads(row['result']), 'result') if row['result'] else None
        if result is not None:
            match_result(request, result, self.controller_id)
            require(row['state'] == 'completed' and row['attempt'] == result['attempt_id'], 'attempt mismatch')
        return {'request': request, 'state': row['state'], 'attempt_id': row['attempt'], 'result': result,
                'reconciliation_required': row['state'] == 'in-flight'}

    def _reserve(self, request, attempt):
        self.db.execute('UPDATE requests SET state=?,attempt=? WHERE id=?',
                        ('in-flight', attempt, request['request_id']))
        self.event('execution-reserved', effect_identity(request, attempt))

    def begin(self, request_id, *, authenticated_request=None):
        with self.transaction():
            status = self.status(request_id)
            self.check_transport(status, authenticated_request)
            request = status['request']
            if status['state'] == 'completed':
                if authenticated_request is not None:
                    self.current(authenticated_request)
                return None, status['result']
            require(status['state'] == 'pending', 'unresolved in-flight effects require reconciliation; execution refused')
            self.current(request)
            self.no_inflight(request['job_id'])
            attempt = str(uuid.uuid4())
            if host_effect_journal(request):
                # The external record must commit before this transaction can
                # publish a reservation. A restored job can lag that record.
                self._host_history().reserve(request, attempt, identity(self.record('job', request['job_id'])),
                                             identity(self.record('checkpoint', request['checkpoint_id'])))
            self._reserve(request, attempt)
        return attempt, None

    def check_transport(self, status, authenticated_request):
        if authenticated_request is not None:
            require(status['request'] == authenticated_request, 'ID collision: request mismatch')
        else:
            require(status['request']['boundary'] not in AUTHENTICATED_BOUNDARIES,
                    'application request requires authenticated transport')

    def make_result(self, request, attempt, checks, diagnostics, evidence=None):
        return envelope('result', **{name: request[name] for name in
                        ('job_id', 'request_id', 'checkpoint_id', 'candidate', 'test')},
                        request_sha256=identity(request), attempt_id=attempt,
                        executor={'controller_id': self.controller_id, 'environment': 'local controller; Fedora host unverified',
                                  'boundary': 'local-protocol', 'implementation_sha256': recipe_identity()['recipe_sha256']},
                        status=verdict(checks), checks=checks, diagnostics=diagnostics, evidence=evidence or [],
                        effects=['controller ledger writes only; local recipe may read the supplied artifact'],
                        cleanup={'status': 'not-needed', 'diagnostics': 'No disposable resources created; all durable records retained'})

    def finish(self, result):
        validate(result, 'result')
        with self.transaction():
            status = self.status(result['request_id'])
            request = status['request']
            require(status['state'] == 'in-flight' and status['attempt_id'] == result['attempt_id'], 'attempt mismatch')
            match_result(request, result, self.controller_id)
            require(not host_effect_journal(request), 'host effect requires a verified closure')
            self._store_result(result)
        return result

    def _store_result(self, result):
        self.db.execute('UPDATE requests SET state=?,result=? WHERE id=?',
                        ('completed', canonical(result), result['request_id']))
        self.event('result', result)

    def _host_history(self):
        require(self.host_history is not None and self.host_history.identity['controller_id'] == self.controller_id,
                'authoritative host execution history is unavailable')
        return self.host_history

    def _host_events(self, request_id):
        rows = self.db.execute("SELECT event,body FROM events WHERE event IN (?,?,?) AND "
                               "json_extract(body,'$.request_id')=? ORDER BY sequence LIMIT 4",
                               (HOST_EFFECT_ARMED, HOST_RESULT_STAGED, HOST_EFFECT_CLOSED, request_id))
        return [(row['event'], loads(row['body'])) for row in rows]

    def _host_prefix(self, request, events):
        existing = self.db.execute('SELECT 1 FROM requests WHERE id=?', (request['request_id'],)).fetchone()
        if existing is None:
            require(not self._host_events(request['request_id']), 'missing request before host events')
            return None, 0
        stored = self.status(request['request_id'])
        self.check_transport(stored, request)
        observed = self._host_events(request['request_id'])
        require(observed == events[:len(observed)], 'job snapshot conflicts with authoritative host event history')
        require(stored['state'] != 'pending' or not observed, 'pending request contains host events')
        return stored, len(observed)

    def _project_host_history(self, entry, *, mirror=False):
        request, attempt = entry['request'], entry['attempt']
        require(entry['job_sha'] == identity(self.record('job', request['job_id'])) and
                entry['checkpoint_sha'] == identity(self.record('checkpoint', request['checkpoint_id'])),
                'job snapshot differs from the authoritative host job or checkpoint')
        events = []
        if entry['armed']:
            events.append((HOST_EFFECT_ARMED, effect_identity(request, attempt)))
        if entry['staged'] is not None:
            events.append((HOST_RESULT_STAGED, entry['staged']))
        if entry['closure'] is not None:
            events.append((HOST_EFFECT_CLOSED, entry['closure']))
        stored, observed = self._host_prefix(request, events)
        result = entry['result']
        if stored is not None:
            require(stored['attempt_id'] in (None, attempt), 'job snapshot has a conflicting host attempt')
            require(stored['result'] is None or (stored['result'] == result and observed == len(events)),
                    'job snapshot conflicts with the authoritative host result')
        if mirror and (stored is None or stored['state'] != 'completed'):
            self.current(request)
            if stored is None:
                self._submit(request)
            if stored is None or stored['state'] == 'pending':
                self.no_inflight(request['job_id'])
                self._reserve(request, attempt)
            for event, value in events[observed:]:
                self.event(event, value)
            if result is not None:
                self._store_result(result)
        state = 'completed' if result is not None else 'in-flight'
        return {'request': request, 'state': state, 'attempt_id': attempt, 'result': result,
                'reconciliation_required': state == 'in-flight'}

    def host_status(self, request):
        entry = self._host_history().lookup(request)
        if entry is not None:
            return self._project_host_history(entry)
        stored = self.status(request['request_id'])
        self.check_transport(stored, request)
        require(stored['state'] == 'pending', 'host attempt has no authoritative execution history; recovery required')
        return stored

    def host_admission(self, request):
        history = self._host_history()
        with self.transaction():
            job = self.record('job', request['job_id'])
            entries = history.for_job(request['job_id'], job['max_requests'])
            attempts = {entry['id']: entry['attempt'] for entry in entries}
            for row in self.db.execute('SELECT id,attempt FROM requests WHERE job=? AND attempt IS NOT NULL',
                                       (request['job_id'],)):
                stored = self.record('request', row['id'])
                require(stored['boundary'] != APP_QUADLET_BOUNDARY or attempts.get(row['id']) == row['attempt'],
                        'job snapshot has an unverified or conflicting host attempt')
            for entry in entries:
                self._project_host_history(entry, mirror=True)

    def host_effect_state(self, request, attempt):
        status = self.status(request['request_id'])
        self.check_transport(status, request)
        self.current(request)
        entry = self._host_history().lookup(request)
        require(entry is not None and status['state'] == 'in-flight' and
                status['attempt_id'] == entry['attempt'] == attempt and entry['closure'] is None,
                'host effect receipt does not match an active attempt')
        return bool(entry['armed']), entry['staged']

    def arm_host_effect(self, request, attempt):
        with self.transaction():
            armed, _ = self.host_effect_state(request, attempt)
            require(not armed, 'host effect already armed; replay refused')
            self._host_history().arm(request, attempt)
            self.event(HOST_EFFECT_ARMED, effect_identity(request, attempt))

    def stage_host_result(self, request, result):
        with self.transaction():
            armed, staged = self.host_effect_state(request, result['attempt_id'])
            require(armed and staged is None, 'host effect cannot record another observation')
            self._host_history().stage(request, result)
            self.event(HOST_RESULT_STAGED, result)

    def close_host_effect(self, request, attempt, mode, evidence):
        with self.transaction():
            armed, staged = self.host_effect_state(request, attempt)
            closure = dict(effect_identity(request, attempt), mode=mode, evidence=evidence)
            result = closed_host_result(request, attempt, self.controller_id, armed, staged, closure)
            self._host_history().close_effect(closure, result, armed=armed, staged=staged)
            self.event(HOST_EFFECT_CLOSED, closure)
            self._store_result(result)
        return result

    def blocked_checks(self, request, reason):
        return [dict(check, actual='Not executed', status='blocked', exit_status=None,
                     diagnostics=reason, evidence=[]) for check in request['checks']]

    def execute(self, request_id, artifact):
        attempt, existing = self.begin(request_id)
        if existing:
            return existing
        request = self.record('request', request_id)
        started = time.monotonic()
        reason = None
        if request['boundary'] != 'local-protocol':
            reason = 'No verified Fedora host executor/transport; host checks remain blocked'
        elif request['test'] != recipe_identity():
            reason = 'Unsupported or changed trusted local recipe identity'
        elif request['capabilities'] != ['local-json-read'] or request['permitted_effects'] != ['read-artifact', 'write-ledger']:
            reason = 'Requested capability/effects are outside the fixed local controller policy'
        elif request['fixtures']:
            reason = 'Local recipe accepts no fixtures'
        elif [check['id'] for check in request['checks']] != ['json-object', 'message-equals'] or request['checks'][0]['expected'] != 'object containing only a message string':
            reason = 'Unsupported expected checks for fixed local recipe'
        if reason:
            return self.finish(self.make_result(request, attempt, self.blocked_checks(request, reason), reason))
        # Read a bounded regular data file through a non-following FD. Never
        # execute or import candidate content. No submitted path enters a shell.
        try:
            # A fixed trusted reader is a separate, bounded process so a slow
            # filesystem cannot defeat the wall-time budget. Candidate bytes
            # never become executable code or command arguments.
            worker = subprocess.Popen([sys.executable, '-I', str(pathlib.Path(__file__).resolve()),
                                       '--read-data', str(artifact), str(request['budgets']['artifact_bytes'])],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
            try:
                output, error = worker.communicate(timeout=request['budgets']['seconds'])
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.communicate()
                raise ValueError('local read time budget exceeded')
            require(worker.returncode == 0, error.decode('utf-8', 'replace')[:1500] or 'local reader failed')
            data = base64.b64decode(output, validate=True)
            require(sha256(data) == request['candidate']['artifact_sha256'], 'artifact digest mismatch')
            require(time.monotonic() - started <= request['budgets']['seconds'], 'local read time budget exceeded')
        except (OSError, ValueError) as exc:
            reason = json.dumps(str(exc), ensure_ascii=True)[1:-1][:1500] or 'Local data read failed'
            return self.finish(self.make_result(request, attempt, self.blocked_checks(request, reason), reason))
        evidence = ['artifact-sha256:' + sha256(data)]
        try:
            document = loads(data)
            valid = type(document) is dict and set(document) == {'message'} and type(document['message']) is str
        except (ValueError, UnicodeError):
            document, valid = None, False
        checks = []
        for check in request['checks']:
            passed = valid if check['id'] == 'json-object' else valid and document['message'] == check['expected']
            actual = 'Valid message document' if check['id'] == 'json-object' and valid else 'Invalid message document'
            if check['id'] == 'message-equals' and valid:
                # Candidate strings are untrusted: bounded JSON escaping keeps diagnostics usable.
                actual = 'message=' + json.dumps(document['message'])[:1500]
            checks.append(dict(check, actual=actual, status='pass' if passed else 'fail', exit_status=0 if passed else 1,
                               diagnostics='Expected value matched' if passed else 'Repair the data candidate and request fresh validation',
                               evidence=evidence))
        return self.finish(self.make_result(request, attempt, checks, 'Fixed local data recipe; no host acceptance', evidence))

    def reconcile(self, request_id, diagnostic, evidence):
        text(diagnostic)
        references(evidence)
        require(evidence, 'reconciliation requires an inspection evidence reference')
        require(len(canonical({'diagnostics': diagnostic, 'evidence': evidence}).encode()) <= MAX_RECONCILIATION_BYTES,
                'reconciliation diagnostics/evidence exceed reserved byte budget')
        with self.transaction():
            status = self.status(request_id)
            require(status['state'] == 'in-flight', 'only in-flight attempts require reconciliation')
            require(status['request']['boundary'] not in AUTHENTICATED_BOUNDARIES,
                    'application attempt remains unresolved; inspect the owned scratch without replay')
            # This controller has never dispatched anything beyond its fixed,
            # read-only local recipe. External host effects cannot be reconciled here.
            self.event('reconciliation', {'request_id': request_id, 'attempt_id': status['attempt_id'],
                                          'diagnostics': diagnostic, 'evidence': evidence})
            result = self.make_result(status['request'], status['attempt_id'],
                                      self.blocked_checks(status['request'], 'Interrupted; explicit controller reconciliation closed without replay'),
                                      diagnostic, evidence)
            self._store_result(result)
        return result

    def consume(self, request_id, *, authenticated_request=None):
        with self.transaction():
            status = self.status(request_id)
            self.check_transport(status, authenticated_request)
            require(status['state'] == 'completed', 'no completed result')
            result = status['result']
            self.current(result)
            progress = result_progress(result)
            consumed = {'request_id': request_id, 'request_sha256': result['request_sha256'], 'progress': progress}
            if authenticated_request is not None and self.db.execute(
                    'SELECT 1 FROM events WHERE event=? AND body=?', ('consumed', canonical(consumed))).fetchone():
                return {'progress': progress, 'result': result}
            self.db.execute('UPDATE jobs SET state=? WHERE id=?', (progress, result['job_id']))
            self.event('consumed', consumed)
        return {'progress': progress, 'result': result}

    def inspect(self, job_id):
        job = self.record('job', job_id)
        row = self.db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        requests = [self.status(r['id']) for r in self.db.execute('SELECT id FROM requests WHERE job=? ORDER BY rowid', (job_id,))]
        return {'job': job, 'checkpoint_id': row['checkpoint'], 'progress': row['state'], 'requests': requests}

    def events(self):
        return [dict(sequence=r['sequence'], at=r['at'], event=r['event'], body=loads(r['body']))
                for r in self.db.execute('SELECT * FROM events ORDER BY sequence')]


def read_data(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'artifact must be a regular data file')
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'artifact exceeds byte budget')
    return data


if __name__ == '__main__':
    # Internal fixed data reader; no submitted scripts or commands.
    try:
        require(len(sys.argv) == 4 and sys.argv[1] == '--read-data', 'unsupported worker invocation')
        limit = int(sys.argv[3])
        number(limit, 1, MAX_MESSAGE)
        sys.stdout.buffer.write(base64.b64encode(read_data(sys.argv[2], limit)))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
