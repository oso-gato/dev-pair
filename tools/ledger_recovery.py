"""Bounded, trusted-local ledger snapshots; hashes record integrity, not authority."""
import math
import os
import pathlib
import resource
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import job_protocol as p

SECONDS = 10
MAX_SNAPSHOT = 16 * 1024 * 1024
MAX_ROWS = 4096
MAX_EVENTS = 8192
MAX_MANIFEST = 16384
SCHEMA = (
    'CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'CREATE TABLE records (kind TEXT, id TEXT, body TEXT NOT NULL, PRIMARY KEY(kind,id))',
    'CREATE TABLE jobs (id TEXT PRIMARY KEY, checkpoint TEXT, state TEXT NOT NULL)',
    'CREATE TABLE requests (id TEXT PRIMARY KEY, job TEXT NOT NULL, state TEXT NOT NULL, attempt TEXT, result TEXT)',
    'CREATE TABLE events (sequence INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL, body TEXT NOT NULL)',
)


def trusted_directory(path, *, create=False):
    path = pathlib.Path(path).absolute()
    for part in [path, *path.parents]:
        p.require(not part.is_symlink(), 'symlink recovery path denied')
        if part.exists() and part != path:
            s = part.stat()
            p.require(s.st_uid in (0, os.getuid()) and
                      (not s.st_mode & 0o022 or s.st_uid == 0 and s.st_mode & stat.S_ISVTX),
                      'untrusted recovery ancestor')
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
        sync_directory(path.parent)
    s = path.lstat()
    p.require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
              stat.S_IMODE(s.st_mode) == 0o700, 'recovery directory must be private and owned')
    return path


def read_private(path, limit):
    p.private_file(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
                  s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= limit,
                  'invalid recovery file or byte limit')
        data = stream.read(limit + 1)
    p.require(len(data) <= limit, 'recovery file exceeds byte limit')
    return data


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(root, value):
    # Link is an atomic no-replace publication, including against another owner.
    temporary = root / 'complete.pending'
    write_private(temporary, p.canonical(value).encode())
    os.link(temporary, root / 'COMPLETE', follow_symlinks=False)
    temporary.unlink()
    sync_directory(root)


def check_admission(root):
    """Called before Ledger opens a restored database for any mutable use."""
    if not (root / 'RECOVERY').exists() and not (root / 'RECOVERY').is_symlink():
        p.require(not any((root / n).exists() or (root / n).is_symlink()
                          for n in ('COMPLETE', 'manifest.json', 'complete.pending')),
                  'incomplete recovery directory')
        return
    marker = p.loads(read_private(root / 'RECOVERY', MAX_MANIFEST))
    p.fields(marker, 'kind instance_id')
    p.require(marker['kind'] == 'restore', 'backup is not a mutable ledger')
    p.digest(marker['instance_id'], 32)
    complete = p.loads(read_private(root / 'COMPLETE', MAX_MANIFEST))
    p.fields(complete, 'kind instance_id manifest_sha256')
    p.require(complete['kind'] == 'restore' and complete['instance_id'] == marker['instance_id'],
              'incomplete restoration identity')
    p.require(p.sha256(read_private(root / 'manifest.json', MAX_MANIFEST)) == complete['manifest_sha256'],
              'restoration manifest identity mismatch')


def connect_readonly(path, deadline):
    p.private_file(path)
    p.require(path.stat().st_size <= MAX_SNAPSHOT, 'snapshot byte limit exceeded')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.1)
    db.enable_load_extension(False)
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA query_only=ON')
    def progress():
        return int(time.monotonic() >= deadline)
    db.set_progress_handler(progress, 1000)
    return db


def validate_database(path, deadline):
    db = connect_readonly(path, deadline)
    try:
        p.require(db.execute('PRAGMA user_version').fetchone()[0] == p.VERSION,
                  'unsupported snapshot database version')
        expected = sqlite3.connect(':memory:')
        try:
            for sql in SCHEMA:
                expected.execute(sql)
            schema = 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'
            p.require(db.execute(schema).fetchall() == expected.execute(schema).fetchall(),
                      'unsupported snapshot schema or executable SQL objects')
        finally:
            expected.close()
        p.require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'snapshot integrity failure')
        tables = {}
        for name in ('metadata', 'records', 'jobs', 'requests', 'events'):
            cap = MAX_EVENTS if name == 'events' else MAX_ROWS
            # Table names and limits are fixed trusted constants.
            rows = db.execute('SELECT * FROM ' + name + ' ORDER BY rowid LIMIT ?', (cap + 1,)).fetchall()
            p.require(len(rows) <= cap, 'snapshot row limit exceeded')
            tables[name] = rows
        p.require(len(tables['metadata']) == 1 and tables['metadata'][0][0] == 'controller_id',
                  'invalid controller metadata')
        controller = tables['metadata'][0][1]
        p.token(controller)
        records = {}
        for kind, record_id, body in tables['records']:
            p.require(kind in ('job', 'checkpoint', 'request'), 'invalid stored record kind')
            obj = p.validate(p.loads(body), kind)
            p.require(body == p.canonical(obj), 'noncanonical record')
            key = {'job': 'job_id', 'checkpoint': 'checkpoint_id', 'request': 'request_id'}[kind]
            p.require(obj[key] == record_id, 'record identity mismatch')
            records[kind, record_id] = obj
        jobs, requests, seen_records = {}, {}, set()
        reconciliation = None
        def record(kind, key):
            p.require((kind, key) in records, 'missing referenced record')
            return records[kind, key]
        def current(obj):
            p.require(obj['job_id'] in jobs and jobs[obj['job_id']][0] == obj['checkpoint_id'],
                      'invalid current checkpoint reference')
            cp = record('checkpoint', obj['checkpoint_id'])
            p.require(all(obj[k] == cp[k] for k in ('job_id', 'candidate', 'test')),
                      'checkpoint identity mismatch')
        # Replay only the fixed data protocol, never SQL or submitted commands.
        for index, (sequence, at, event, body) in enumerate(tables['events'], 1):
            p.require(sequence == index and type(at) in (int, float) and math.isfinite(at) and
                      0 < at < 1e12, 'invalid event ordering or timestamp')
            obj = p.loads(body)
            p.require(body == p.canonical(obj), 'noncanonical event')
            p.require(reconciliation is None or event == 'result', 'incomplete reconciliation transaction')
            if event in ('job', 'checkpoint', 'request'):
                p.validate(obj, event)
                key = obj[{'job': 'job_id', 'checkpoint': 'checkpoint_id', 'request': 'request_id'}[event]]
                p.require(record(event, key) == obj and (event, key) not in seen_records,
                          'missing or duplicate record event')
                seen_records.add((event, key))
                if event == 'job':
                    jobs[key] = [None, 'awaiting-checkpoint']
                elif event == 'checkpoint':
                    p.require(obj['job_id'] in jobs and not any(
                        r['job'] == obj['job_id'] and r['state'] == 'in-flight' for r in requests.values()),
                        'checkpoint crosses unresolved attempt')
                    jobs[obj['job_id']] = [key, 'awaiting-result']
                else:
                    current(obj)
                    job = record('job', obj['job_id'])
                    p.require(sum(r['job'] == obj['job_id'] for r in requests.values()) < job['max_requests'],
                              'request budget exceeded')
                    p.require(not any(r['job'] == obj['job_id'] and r['state'] == 'in-flight'
                                      for r in requests.values()), 'request crosses unresolved attempt')
                    p.require(all(obj['budgets'][k] <= job['budgets'][k] for k in job['budgets']),
                              'request exceeds recorded budget')
                    requests[key] = dict(job=obj['job_id'], state='pending', attempt=None, result=None)
            elif event == 'execution-reserved':
                p.fields(obj, 'request_id attempt_id request_sha256')
                req = record('request', obj['request_id']); current(req)
                p.require(obj['request_id'] in requests, 'reservation before request')
                row = requests[obj['request_id']]
                p.require(row['state'] == 'pending' and not any(
                    r['job'] == row['job'] and r['state'] == 'in-flight' for r in requests.values()),
                    'duplicate or conflicting attempt')
                p.require(str(uuid.UUID(obj['attempt_id'])) == obj['attempt_id'] and
                          obj['request_sha256'] == p.identity(req), 'reservation identity mismatch')
                row.update(state='in-flight', attempt=obj['attempt_id'])
            elif event == 'result':
                p.validate(obj, 'result')
                req = record('request', obj['request_id'])
                p.require(obj['request_id'] in requests, 'result before request')
                row = requests[obj['request_id']]
                p.require(row['state'] == 'in-flight' and row['attempt'] == obj['attempt_id'] and
                          obj['request_sha256'] == p.identity(req) and
                          obj['executor']['controller_id'] == controller and
                          all(obj[k] == req[k] for k in ('job_id', 'checkpoint_id', 'candidate', 'test')) and
                          [(c['id'], c['expected']) for c in obj['checks']] ==
                          [(c['id'], c['expected']) for c in req['checks']], 'result identity mismatch')
                if reconciliation is not None:
                    p.require(obj['request_id'] == reconciliation['request_id'] and obj['status'] == 'blocked' and
                              obj['diagnostics'] == reconciliation['diagnostics'] and
                              obj['evidence'] == reconciliation['evidence'] and
                              all(c['status'] == 'blocked' for c in obj['checks']),
                              'reconciliation result mismatch')
                    reconciliation = None
                row.update(state='completed', result=body)
            elif event == 'reconciliation':
                p.fields(obj, 'request_id attempt_id diagnostics evidence')
                p.text(obj['diagnostics']); p.references(obj['evidence'])
                p.require(obj['request_id'] in requests and obj['evidence'] and
                          requests[obj['request_id']]['state'] == 'in-flight' and
                          requests[obj['request_id']]['attempt'] == obj['attempt_id'],
                          'invalid reconciliation event')
                p.require(len(p.canonical({'diagnostics': obj['diagnostics'], 'evidence': obj['evidence']}).encode())
                          <= p.MAX_RECONCILIATION_BYTES, 'reconciliation byte limit exceeded')
                reconciliation = obj
            elif event == 'consumed':
                p.fields(obj, 'request_id request_sha256 progress')
                req = record('request', obj['request_id']); current(req)
                p.require(obj['request_id'] in requests and requests[obj['request_id']]['state'] == 'completed',
                          'consumed incomplete request')
                result = p.loads(requests[obj['request_id']]['result'])
                progress = {'pass': 'local-checks-passed', 'fail': 'repair-required', 'blocked': 'blocked'}[result['status']]
                p.require(obj['progress'] == progress and obj['request_sha256'] == p.identity(req),
                          'consumed identity mismatch')
                jobs[req['job_id']][1] = progress
            else:
                raise ValueError('unknown recovery event')
        p.require(reconciliation is None, 'incomplete reconciliation transaction')
        p.require(seen_records == set(records), 'missing historical record event')
        p.require(sorted(tables['jobs']) == sorted((key, *value) for key, value in jobs.items()),
                  'job checkpoint or progress mismatch')
        p.require(sorted(tables['requests']) == sorted((key, r['job'], r['state'], r['attempt'], r['result'])
                  for key, r in requests.items()), 'request state or result mismatch')
        return {'controller_id': controller, 'counts': {k: len(v) for k, v in tables.items()},
                'table_sha256': {k: p.identity(v) for k, v in tables.items()}}
    finally:
        db.close()


def manifest_for(snapshot, summary, backup_id):
    data = read_private(snapshot, MAX_SNAPSHOT)
    return {'version': 1, 'protocol_version': p.VERSION, 'backup_id': backup_id,
            'snapshot_bytes': len(data), 'snapshot_sha256': p.sha256(data),
            'implementation_sha256': p.sha256(pathlib.Path(__file__).read_bytes()),
            'protocol_implementation_sha256': p.recipe_identity()['recipe_sha256'], 'summary': summary}


def backup(source, destination, deadline):
    source = trusted_directory(source)
    check_admission(source)
    for name in ('ledger.sqlite3', 'ledger.sqlite3-journal', 'ledger.sqlite3-wal', 'ledger.sqlite3-shm'):
        f = source / name
        if f.exists() or f.is_symlink():
            p.private_file(f)
    src = connect_readonly(source / 'ledger.sqlite3', deadline)
    page_size = src.execute('PRAGMA page_size').fetchone()[0]
    root = trusted_directory(destination, create=True)
    backup_id = uuid.uuid4().hex
    write_private(root / 'RECOVERY', p.canonical({'kind': 'backup', 'instance_id': backup_id}).encode())
    target = root / 'snapshot.sqlite3'
    write_private(target, b'')
    dst = sqlite3.connect(target, timeout=0.1)
    try:
        dst.execute('PRAGMA page_size=4096')
        dst.execute('PRAGMA max_page_count=4096')
        def progress(status, remaining, total):
            p.require(time.monotonic() < deadline, 'backup deadline exceeded')
            p.require(total * page_size <= MAX_SNAPSHOT, 'snapshot byte limit exceeded')
        src.backup(dst, pages=64, progress=progress, sleep=0.01)
    finally:
        dst.close(); src.close()
    summary = validate_database(target, deadline)
    manifest = manifest_for(target, summary, backup_id)
    write_private(root / 'manifest.json', p.canonical(manifest).encode())
    # SQLite closed its journal; explicitly persist the database before admission.
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    publish(root, {'kind': 'backup', 'instance_id': backup_id,
                   'manifest_sha256': p.identity(manifest)})
    return {'backup_id': backup_id, 'manifest_sha256': p.identity(manifest), **summary}


def restore(source, destination, deadline):
    source = trusted_directory(source)
    marker = p.loads(read_private(source / 'RECOVERY', MAX_MANIFEST))
    complete = p.loads(read_private(source / 'COMPLETE', MAX_MANIFEST))
    p.fields(marker, 'kind instance_id'); p.fields(complete, 'kind instance_id manifest_sha256')
    p.require(marker['kind'] == complete['kind'] == 'backup' and marker['instance_id'] == complete['instance_id'],
              'incomplete backup')
    manifest_data = read_private(source / 'manifest.json', MAX_MANIFEST)
    manifest = p.loads(manifest_data)
    p.fields(manifest, 'version protocol_version backup_id snapshot_bytes snapshot_sha256 implementation_sha256 protocol_implementation_sha256 summary')
    p.require(type(manifest['version']) is int and manifest['version'] == 1 and
              type(manifest['protocol_version']) is int and manifest['protocol_version'] == p.VERSION,
              'unsupported recovery manifest version')
    p.require(p.sha256(manifest_data) == complete['manifest_sha256'] and
              manifest['backup_id'] == marker['instance_id'], 'backup manifest identity mismatch')
    p.digest(manifest['backup_id'], 32)
    for key in ('snapshot_sha256', 'implementation_sha256', 'protocol_implementation_sha256'):
        p.digest(manifest[key])
    p.number(manifest['snapshot_bytes'], 1, MAX_SNAPSHOT)
    root = trusted_directory(destination, create=True)
    instance = uuid.uuid4().hex
    write_private(root / 'RECOVERY', p.canonical({'kind': 'restore', 'instance_id': instance}).encode())
    data = read_private(source / 'snapshot.sqlite3', MAX_SNAPSHOT)
    p.require(len(data) == manifest['snapshot_bytes'] and p.sha256(data) == manifest['snapshot_sha256'],
              'snapshot length or hash mismatch')
    snapshot = root / 'ledger.sqlite3'
    write_private(snapshot, data)
    summary = validate_database(snapshot, deadline)
    p.require(summary == manifest['summary'], 'snapshot summary mismatch')
    write_private(root / 'manifest.json', manifest_data)
    publish(root, {'kind': 'restore', 'instance_id': instance, 'manifest_sha256': p.sha256(manifest_data)})
    return {'restoration_id': instance, 'backup_id': manifest['backup_id'],
            'manifest_sha256': p.sha256(manifest_data), **summary}


def run(operation, source, destination):
    p.require(operation in ('backup', 'restore'), 'unsupported recovery operation')
    started = time.monotonic()
    # Only fixed reviewed worker code runs. No submitted SQL, path or payload is executable.
    worker = subprocess.Popen([sys.executable, '-I', str(pathlib.Path(__file__).resolve()),
                               operation, str(source), str(destination)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
    try:
        out, error = worker.communicate(timeout=max(0.001, SECONDS - 0.5 - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        worker.kill()
        try:
            worker.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            raise ValueError('recovery worker termination unresolved; incomplete destination preserved')
        raise ValueError('recovery operation deadline exceeded; incomplete destination preserved')
    p.require(len(out) <= MAX_MANIFEST and len(error) <= 1024, 'recovery diagnostic byte limit')
    p.require(worker.returncode == 0, error.decode('utf-8', 'replace').strip() or 'recovery worker failed')
    return p.loads(out)


if __name__ == '__main__':
    try:
        p.require(len(sys.argv) == 4 and sys.argv[1] in ('backup', 'restore'), 'invalid recovery worker')
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SNAPSHOT, MAX_SNAPSHOT))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        value = globals()[sys.argv[1]](sys.argv[2], sys.argv[3], time.monotonic() + SECONDS - 0.25)
        print(p.canonical(value))
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError, OverflowError) as exc:
        # Never include untrusted database bodies or native error strings.
        print('Recovery blocked: invalid or unavailable snapshot (' + type(exc).__name__ + ')', file=sys.stderr)
        sys.exit(2)
