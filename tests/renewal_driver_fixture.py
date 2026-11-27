"""Local external adapter with persistent effects and a separately spawned turn."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


def sha(data):
    return hashlib.sha256(data).hexdigest()


def invoke(root, action, payload):
    if action == 'preflight-resume':
        if (root / 'deny-recovery-grant').exists() and payload['release_sha256'] == (root / 'deny-recovery-grant').read_text():
            raise SystemExit(4)
        return {'operation': payload['operation'], 'request_sha256': sha(payload['operation'].encode()),
                'job': payload['job'], 'allowance_sha256': sha(b'fixture allowance'), 'spend_microusd': 1}
    if action == 'preflight-allowance':
        return {'job': payload['job'], 'allowance_sha256': payload['allowance_sha256'],
                'remaining_microusd': payload['needed_microusd'] - int((root / 'insufficient-escrow').exists())}
    if action == 'verify-sessions':
        state = root / payload['role'] / 'state' / payload['job']
        rows = [{'logical_session': path.stem, 'uuid': path.read_text().splitlines()[0]}
                for path in sorted(state.glob('*.txt'))]
        return {'sessions': rows}
    plan = root / 'site-live.json'
    trace = root / 'site-events.jsonl'
    current = json.loads(plan.read_text())
    release = payload['release_sha256']
    if action in ('turn', 'resume-without-effects'):
        assert release == current['release_sha256']
        if (root / 'fail-resume').exists() and release == (root / 'fail-resume').read_text():
            raise SystemExit(3)
        role, job, logical, operation = (payload[key] for key in ('role', 'job', 'logical_session', 'operation'))
        state = root / role / 'state' / job
        history = state / (logical + '.txt')
        if payload['session_uuid'] is None:
            session = str(uuid.uuid5(uuid.NAMESPACE_DNS, role + '/' + job + '/' + logical))
            history.write_text(session + '\n')
        else:
            session = payload['session_uuid']
            assert history.read_text().splitlines()[0] == session
        events = subprocess.check_output([sys.executable, '-c', 'import sys; print(sys.argv[1])', operation], timeout=4)
        with history.open('a') as stream:
            stream.write(operation + '\n')
        if (root / 'duplicate-effect').exists() and action == 'resume-without-effects':
            raise AssertionError('verification has no host effect path')
        return {key: payload[key] for key in ('role', 'job', 'logical_session', 'operation')} | {
            'release_sha256': release, 'session_uuid': session,
            'request_sha256': payload.get('request_sha256', sha(operation.encode())),
            'provider_receipt_sha256': sha(b'local fixture ' + operation.encode()),
            'events_sha256': sha(events), 'progress_sha256': sha(history.read_bytes()), 'child_reaped': True,
        }
    evidence = {key: payload[key] for key in ('release_sha256',)} | {'components': payload['release']['components']}
    with trace.open('a') as log:
        log.write(json.dumps([action, payload['operation'], release]) + '\n')
    if action == 'observe':
        assert evidence == current
    if action == 'activate':
        temporary = plan.with_suffix('.new')
        temporary.write_text(json.dumps(evidence))
        temporary.replace(plan)
        if (root / 'disrupt-release').exists() and release == (root / 'disrupt-release').read_text():
            (root / 'maintenance' / 'workspaces' / 'product' / 'untracked.txt').write_text('changed during bad start')
            (root / 'development' / 'state' / 'product' / 'one.txt').unlink()
        if (root / 'remove-registries').exists() and release == (root / 'remove-registries').read_text():
            for role in ('maintenance', 'development'):
                shutil.rmtree(root / 'renewal' / 'registries' / role / 'product')
        if (root / 'interrupt-release').exists() and release == (root / 'interrupt-release').read_text():
            (root / 'activation-held').touch()
            end = time.monotonic() + 3
            while os.getppid() != 1 and time.monotonic() < end:
                time.sleep(.02)
            (root / 'activation-child-finished').touch()
    return evidence


if __name__ == '__main__':
    print(json.dumps(invoke(Path(sys.argv[1]), sys.argv[2], json.load(sys.stdin))))
