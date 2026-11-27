"""Read-only continuity for a general job's accepted DevBox validation."""
import base64
from pathlib import Path
import re
import shlex
import zlib

import renewal as r
from renewal import protocol as p

LOCAL = 'devbox-development'
EXTERNAL = 'devbox-development-needs-host'
RECIPE = 'devbox-local-validation-inputs'
WORK = '''import base64, json, re, resource, subprocess, sys, tempfile, zlib
from pathlib import Path
expected = json.loads(sys.argv[1])
git = ('/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null')
def observe(*args):
    return subprocess.check_output([*git, *args], timeout=5).decode().strip()
assert observe('rev-parse', '--verify', 'HEAD') == expected['candidate_sha']
assert observe('rev-parse', '--verify', 'HEAD^{tree}') == expected['tree_sha']
dirty = bool(observe('status', '--porcelain=v1', '--untracked-files=all'))
assert dirty == expected['dirty']
scanner = zlib.decompress(base64.b64decode(sys.argv[2]))
scope = {'__name__': 'protected_candidate_observation'}
exec(compile(scanner, '<verified-source-scanner>', 'exec'), scope)
workspace = Path.cwd()
source, entries = scope['scan'](workspace, retain=expected['role'] == 'development', sandbox=True)
assert expected['source_sha256'] in (None, source)
expected['source_sha256'] = source
count = 0
if expected['role'] == 'development':
    with tempfile.TemporaryDirectory(prefix='dev-pair-product-test-', dir='/tmp') as scratch:
        root = Path(scratch)
        for name, mode, data in entries:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = base64.b64decode(data)
            if mode == '120000':
                path.symlink_to(raw.decode())
            else:
                with path.open('xb') as stream:
                    stream.write(raw)
                path.chmod(0o700 if mode == '100755' else 0o600)
        def bound_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
        with tempfile.TemporaryFile(dir='/tmp') as output:
            code = subprocess.call(expected['test_argv'], cwd=root, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, timeout=8, preexec_fn=bound_output)
            output.seek(0)
            rows = re.findall(rb'^Ran ([1-9][0-9]*) tests? in [0-9.]+s$', output.read(65537), re.M)
        assert code == 0 and len(rows) == 1
        count = int(rows[0])
    assert scope['scan'](workspace, sandbox=True)[0] == source
assert expected['test_count'] in (None, count)
expected['test_count'] = count
print(json.dumps(expected, sort_keys=True))
'''


def approved_unittest(events, observed, prefix, suffix):
    matches = []
    for line in events.splitlines():
        row = r.loads(line)
        item = row.get('item', {})
        if row.get('type') == 'item.completed' and item.get('id') == observed['item_id']:
            command = item['command']
            if r.sha(command.encode()) == observed['command_sha256']:
                matches.append(command)
    r.require(len(matches) == 1, 'verified local test command is missing or ambiguous')
    command = matches[0]
    if not command.startswith(prefix):
        command = shlex.split(command)[-1]
    r.require(command.startswith(prefix) and command.endswith(suffix), 'verified local test wrapper changed')
    args = shlex.split(command[len(prefix):-len(suffix)])
    r.require(args and args[0] in ('python3', '/usr/bin/python3'),
              'no bounded renewal test adapter for the saved local command')
    args = args[1:]
    flags = []
    while args and args[0] in ('-B', '-I', '-IB'):
        flags.append(args.pop(0))
    options = {'-s', '--start-directory', '-p', '--pattern', '-t', '--top-level-directory', '-v', '--verbose', '-q', '--quiet'}
    r.require(args[:2] == ['-m', 'unittest'] and len(args) <= 24 and all(
        word in options or (re.fullmatch(r'[A-Za-z0-9_.*?][A-Za-z0-9_./*?-]{0,159}', word) and
                            '..' not in word.split('/')) for word in args[2:]),
        'no bounded renewal test adapter for the saved local command')
    return ['/usr/bin/python3', '-B', *flags, *args]


def general_command(role, result, read_file):
    p.fields(result, 'recipe role candidate_sha tree_sha validation_phase original_operation validation_sha256 '
                     'validated_snapshot_sha256 snapshot_tool_sha256 source_sha256 dirty test_argv test_count')
    r.require(result['recipe'] == RECIPE and role in r.ROLES and result['role'] == role,
              'general continuation role or recipe changed')
    for key in ('candidate_sha', 'tree_sha'):
        p.digest(result[key], 40)
    r.require(type(result['dirty']) is bool and type(result['test_argv']) is list and
              result['test_argv'][:2] == ['/usr/bin/python3', '-B'], 'invalid fixed local continuation policy')
    r.digest(result['validation_sha256'])
    p.token(result['original_operation'])
    r.require(result['validation_phase'] in ('local-validation-recorded', 'awaiting-external-validation'),
              'general job has no approved validation state')
    import product_job
    source = read_file(Path(product_job.__file__).resolve().with_name('candidate_snapshot.py'), 16384)
    r.require(r.sha(source) == result['snapshot_tool_sha256'], 'general input scanner changed after baseline')
    scanner = base64.b64encode(zlib.compress(source, 9)).decode()
    if result['source_sha256'] is not None:
        r.digest(result['source_sha256'])
        p.number(result['test_count'], int(role == 'development'), 100000)
    return ('/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '15s', '/usr/bin/python3', '-IB', '-c', WORK,
            r.canonical(result), scanner)


def original_turn(root, role, job, saved, read_file):
    from gptbox_runtime import completed_turn

    p.token(saved['operation'])
    base = root / role / 'state' / job / 'turns' / saved['operation']
    account = {'maintenance': 'dp-maint', 'development': 'dp-dev'}[role]
    uid = r.pwd.getpwnam(account).pw_uid
    event_bytes = read_file(base / 'events.jsonl', 4 * 1024 * 1024, uid)
    result = r.loads(read_file(base / 'result.json', 8192, uid))
    r.require(result['schema'] == 2 and result['status'] == 'completed-turn' and result['runtime_admitted'] is True and
              result['owned_cleanup'] == 'reaped' and result['role'] == role and result['job'] == job and
              result['operation'] == saved['operation'] and result['logical_session'] == role and
              result['events_bytes'] == len(event_bytes) and result['events_sha256'] == saved['events_sha256'] == r.sha(event_bytes) and
              result['session_uuid'] == saved['session_uuid'] == completed_turn(event_bytes),
              'accepted stock job evidence changed')
    return result, event_bytes


def saved_validation(root, payload, plan, head, status, read_file):
    import product_job as j

    role, job = payload['role'], payload['job']
    phase = 'awaiting-external-validation' if plan['adapter'] == EXTERNAL else 'local-validation-recorded'
    r.require(plan['adapter'] in (LOCAL, EXTERNAL), 'unknown general product adapter')
    folder = root / 'product-jobs' / 'jobs' / job
    state = r.read_json(folder / 'state.json')
    checkpoint = payload['checkpoint']
    evidence = state.get('local_validation')
    r.require(state['job_id'] == job and state['repository'] == plan['agreement']['repository'] and state['phase'] == phase and
              state['startup_sha256'] == plan['startup_sha256'] and state['agreement_sha256'] == payload['binding']['agreement_sha256'] and
              state['repair'] == checkpoint and type(evidence) is dict and checkpoint['checkpoint_id'] == evidence['checkpoint_id'] and
              checkpoint['candidate']['source_revision'] == evidence['candidate_sha'] == head,
              'current general job has no settled validation for its preserved source')
    r.require(checkpoint['test']['recipe'] == 'devbox-local-command-observation-v1' and
              len(checkpoint['evidence']) == 1 and checkpoint['evidence'][0].startswith('git-tree:'),
              'general job checkpoint lacks the accepted local source identity')
    tree = checkpoint['evidence'][0].removeprefix('git-tree:')
    p.digest(tree, 40)
    r.require(checkpoint['candidate']['artifact_sha256'] == p.identity({'repository': state['repository'], 'revision': head, 'tree': tree}),
              'general job checkout differs from its accepted revision and tree')
    active = state[role]
    r.require(payload['sessions'] == [{'logical_session': role, 'uuid': active['session_uuid']}],
              'general continuation does not cover the enrolled provider UUID')
    current_role, role_events = original_turn(root, role, job, active, read_file)
    dev = state['development']
    dev_role, events = (current_role, role_events) if role == 'development' else original_turn(root, 'development', job, dev, read_file)
    r.require(dev['session_uuid'] == evidence['session_uuid'] and dev['events_sha256'] == evidence['events_sha256'],
              'general job validation differs from its original DevBox turn')
    snapshot = evidence.get('snapshot_sha256')
    if snapshot is None:
        observed = j.observed_validation(events, head)
        prefix, suffix = j.LOCAL_TEST_PREFIX, j.LOCAL_TEST_SUFFIX
    else:
        observed = j.observed_source_validation(events)
        prefix, suffix = j.candidate_git.witness()
        materialized = r.read_json(folder / 'candidate' / 'receipt.json')
        p.fields(materialized, 'binding candidate_sha tree_sha bundle_sha256 head_ref')
        bound = materialized['binding']
        r.require(state['materialized'] == materialized and materialized['candidate_sha'] == head and materialized['tree_sha'] == tree and
                  bound['snapshot_sha256'] == snapshot and bound['job_id'] == job and bound['operation'] == dev['operation'] and
                  bound['session_uuid'] == evidence['session_uuid'] and bound['events_sha256'] == evidence['events_sha256'] and
                  bound['request_sha256'] == dev_role['request_sha256'] == dev['request_sha256'] and
                  bound['agreement_sha256'] == state['agreement_sha256'] and bound['startup_sha256'] == state['startup_sha256'] and
                  bound['base_sha'] == evidence['base_sha'] == state['initial']['candidate']['source_revision'] and
                  bound['checkpoint_sha256'] == p.identity(state['initial']) and bound['validation_sha256'] == p.identity(observed),
                  'trusted tested source materialization differs')
    r.require(all(evidence.get(key) == value for key, value in observed.items()) and observed['exit_status'] == 0,
              'stored general test differs from retained stock evidence')
    args = approved_unittest(events, observed, prefix, suffix)
    scanner_sha = r.sha(read_file(Path(j.__file__).resolve().with_name('candidate_snapshot.py'), 16384))
    return {'recipe': RECIPE, 'role': role, 'candidate_sha': head, 'tree_sha': tree, 'validation_phase': phase,
            'original_operation': current_role['operation'], 'validation_sha256': r.identity(evidence),
            'validated_snapshot_sha256': snapshot, 'snapshot_tool_sha256': scanner_sha, 'source_sha256': None,
            'dirty': bool(status), 'test_argv': args, 'test_count': None}
