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
    if action == 'preflight-runtime':
        if (root / 'missing-release-artifact').exists() and payload['release_sha256'] == (root / 'missing-release-artifact').read_text():
            raise SystemExit(5)
        return {'role': payload['role'], 'job': payload['job'],
                'artifact_sha256': payload['release']['components'][payload['role'] + '-agent']['artifact_sha256']}
    if action == 'capture-work':
        if (root / 'failed-product-baseline').exists() and payload['role'] == 'development':
            raise SystemExit(7)
        return {'head': 'c' * 40, 'status_sha256': sha(b'dirty'), 'check_sha256': sha(b''), 'check_exit': 0,
                'product_plan_sha256': sha(b'local only'), 'product_result': {'check': 'fixture-only'}}
    if action == 'verify-managed-probe':
        for name in ('workspaces', 'state', 'cache'):
            assert not any((root / 'maintenance' / name / 'gptbox-probe').iterdir())
        return {'scope': 'maintenance-assembly-probe', 'empty': True}
    if action == 'preflight-resume':
        if (root / 'deny-recovery-grant').exists() and payload['release_sha256'] == (root / 'deny-recovery-grant').read_text():
            raise SystemExit(4)
        return {'operation': payload['operation'], 'request_sha256': sha(payload['operation'].encode()),
                'job': payload['job'], 'allowance_sha256': sha(b'fixture allowance'), 'spend_microusd': 1,
                'request_body_floor': 176000, 'max_request_bytes': 524288}
    if action == 'preflight-allowance':
        return {'job': payload['job'], 'allowance_sha256': payload['allowance_sha256'],
                'remaining_microusd': payload['needed_microusd'] - int((root / 'insufficient-escrow').exists())}
    if action == 'verify-sessions':
        state = root / payload['role'] / 'state' / payload['job']
        rows = [{'logical_session': path.stem, 'uuid': path.read_text().splitlines()[0]}
                for path in sorted(state.glob('*.txt'))]
        native = {row['uuid']: {'path': row['logical_session'] + '.txt', 'bytes': 1,
                                'sha256': sha(b'fixture')} for row in rows}
        return {'sessions': rows, 'native': native, 'archived': {}}
    plan = root / 'site-live.json'
    trace = root / 'site-events.jsonl'
    current = json.loads(plan.read_text())
    release = payload['release_sha256']
    if action in ('turn', 'resume-without-effects', 'observe-progress'):
        assert release == current['release_sha256']
        if (root / 'fail-resume').exists() and release == (root / 'fail-resume').read_text():
            raise SystemExit(3)
        role, job, logical, operation = (payload[key] for key in ('role', 'job', 'logical_session', 'operation'))
        state = root / role / 'state' / job
        history = state / (logical + '.txt')
        if action == 'observe-progress':
            session = payload['session_uuid']
            assert history.read_text().splitlines()[0] == session and history.read_text().splitlines().count(operation) == 1
            events = (operation + '\n').encode()
        elif payload['session_uuid'] is None:
            session = str(uuid.uuid5(uuid.NAMESPACE_DNS, role + '/' + job + '/' + logical))
            history.write_text(session + '\n')
        else:
            session = payload['session_uuid']
            assert history.read_text().splitlines()[0] == session
        if action != 'observe-progress':
            events = subprocess.check_output([sys.executable, '-c', 'import sys; print(sys.argv[1])', operation], timeout=4)
            with history.open('a') as stream:
                stream.write(operation + '\n')
        if (root / 'duplicate-effect').exists() and action == 'resume-without-effects':
            raise AssertionError('verification has no host effect path')
        evidence = None
        if action in ('resume-without-effects', 'observe-progress'):
            work = payload['work']
            evidence = {'schema': 1, 'operation': operation, 'checkpoint': payload['checkpoint'],
                        'plan_sha256': work['product_plan_sha256'], 'result': work['product_result'],
                        'next_state': 'retain-pending-host-check' if payload['pending_host'] else 'continue-approved-job',
                        'pending_host': payload['pending_host']}
        return {key: payload[key] for key in ('role', 'job', 'logical_session', 'operation')} | {
            'release_sha256': release, 'session_uuid': session,
            'request_sha256': payload.get('request_sha256', sha(operation.encode())),
            'provider_receipt_sha256': sha(b'local fixture ' + operation.encode()),
            'work_sha256': sha(json.dumps(payload['work'], sort_keys=True, separators=(',', ':')).encode())
            if evidence is not None else None,
            'events_sha256': sha(events), 'child_reaped': True,
            'product': evidence,
            'progress_sha256': sha(json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()) if evidence else None,
        }
    evidence = {key: payload[key] for key in ('release_sha256',)} | {'components': payload['release']['components']}
    with trace.open('a') as log:
        log.write(json.dumps([action, payload['operation'], release]) + '\n')
    if action == 'observe':
        unavailable = root / 'failed-host-observation'
        if unavailable.exists() and unavailable.read_text() in ('', release):
            raise SystemExit(6)
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
