#!/usr/bin/python3
"""Send one successful Fedora producer result to the dedicated write-only VM port."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fedora_ci_guest as guest
import gptbox
from native_io import verify_inactive_cgroup
from platform_release_protocol import ARCHIVE_LIMIT, GIB, Blocked, file_hash, hex_id, json_bytes, require, seconds, send_frame

PORT = Path('/dev/virtio-ports/dev-pair-platform')
MAINTENANCE = Path('/var/lib/dev-pair/maintenance')
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def native_save(context, image, end, destination, account):
    uid = account.pw_uid
    control = '/usr/local/libexec/dev-pair-gptbox'
    runtime = f'/run/user/{uid}'
    number = int(seconds(end, 170))
    require(number > 5, 'maintenance export time exhausted before start')
    unit = f'dev-pair-ci-observe-{context[:16]}.service'
    verify_inactive_cgroup(unit)
    common = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'HOME=' + control + '/home',
              'XDG_RUNTIME_DIR=' + runtime, 'CONTAINERS_CONF=' + control + '/containers.conf',
              'TMPDIR=' + str(destination.parent), '/usr/bin/podman', '--root=' + str(MAINTENANCE / 'images'),
              '--runroot=' + runtime + '/dev-pair-gptbox', '--storage-driver=vfs', '--events-backend=file']
    inspect = ['/usr/sbin/runuser', '--user', 'dp-maint', '--', *common, 'image', 'inspect', 'sha256:' + image]
    output = guest.command(inspect, timeout=seconds(end, 10), maximum=262144)
    row, = json.loads(output)
    require(gptbox.image_id(row['Id']) == image and row['Architecture'] == 'amd64' and row['Os'] == 'linux',
            'maintenance image identity changed before export')
    diffs = gptbox.image_diff_ids(row['RootFS']['Layers'])
    command = ['/usr/bin/systemd-run', '--unit=' + unit, '--description=dev-pair-owned-' + unit,
               '--uid=dp-maint', '--quiet', '--wait', '--collect', '--service-type=exec',
               '--property=RuntimeMaxSec=' + str(number - 3), '--property=TimeoutStopSec=2',
               '--property=KillMode=control-group', '--property=MemoryMax=2G', '--property=TasksMax=512',
               '--property=CPUQuota=100%', '/usr/bin/prlimit', f'--fsize={ARCHIVE_LIMIT}:{ARCHIVE_LIMIT}',
               *common, 'save', '--format=oci-archive', '--output', str(destination), 'sha256:' + image]
    subprocess.run(command, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=seconds(end, number))
    verify_inactive_cgroup(unit)
    return diffs


@contextmanager
def role_artifact(report, end):
    expected = report['inputs']
    source, context = expected['source_sha'], expected['context_sha256']
    role = expected.get('scenario', 'maintenance')
    if role == 'development':
        receipt = guest.validate_development_receipt(report['development']['receipt'], expected)['inner']
        archive = Path(gptbox.DEVELOPMENT_ARTIFACTS) / context / 'release' / gptbox.RELEASE_ARCHIVE
        image = {key: receipt[key] for key in ('image_id', 'archive_sha256', 'archive_bytes', 'diff_ids')}
        yield archive, {**image, 'role': role, 'source_sha': source, 'context_sha256': context}, receipt, 0
        return

    evidence = report['initialization']
    require(evidence['assembled_image_verified'] is True and evidence['runtime_container_removed'] is True and
            evidence['boundary_and_version_cycles'] == 2 and evidence['exit_status'] == 0,
            'maintenance producer evidence is incomplete')
    image = hex_id(evidence['assembled_image_id'])
    require(shutil.disk_usage(MAINTENANCE).free >= 8 * GIB + 2 * ARCHIVE_LIMIT,
            'guest lacks maintenance export overlap and recovery reserve')
    account = pwd.getpwnam('dp-maint')
    require(account.pw_uid >= 1000, 'maintenance export does not have its managed account')
    result_path = Path(gptbox.ROOT) / context / 'result.json'
    raw = gptbox.DevelopmentGptbox().protected_bytes(result_path, 16384, 0o600)
    result = json_bytes(raw)
    require(all(result[key] == evidence[key] for key in ('source_sha', 'context_sha256', 'distrobox_sha',
                'assembled_image_id', 'boundary_and_version_cycles', 'runtime_container_removed', 'job_admission')),
            'maintenance protected result changed before export')
    directory = Path(tempfile.mkdtemp(dir=MAINTENANCE, prefix='ci-platform-export-'))
    os.chown(directory, account.pw_uid, account.pw_gid)
    archive = directory / 'maintenance.oci.tar'
    diffs = native_save(context, image, end, archive, account)
    try:
        digest, size = file_hash(archive, ARCHIVE_LIMIT, end, owner=account.pw_uid)
        proof = {'result': result, 'result_sha256': hashlib.sha256(raw).hexdigest()}
        yield archive, {'role': role, 'source_sha': source, 'context_sha256': context, 'image_id': image,
                        'archive_sha256': digest, 'archive_bytes': size, 'diff_ids': diffs}, proof, account.pw_uid
    finally:
        # Native save was reaped and its exact cgroup was empty before this
        # point. An unresolved save leaves its spool for whole-VM teardown.
        shutil.rmtree(directory)


def main():
    require(os.geteuid() == os.getuid() == 0 and len(sys.argv) == 2, 'native release guest executor required')
    end = float(sys.argv[1])
    require(0 < end - time.monotonic() <= guest.PLATFORM_EXPORT_SECONDS, 'invalid guest export deadline')
    # The parent bounds the subprocess independently. Interrupt a stalled
    # virtio write before allowing the normal guest poweroff path.
    signal.signal(signal.SIGALRM, lambda *_: sys.exit(2))
    signal.setitimer(signal.ITIMER_REAL, seconds(end, guest.PLATFORM_EXPORT_SECONDS))
    report = json_bytes(sys.stdin.buffer.read(guest.REPORT_LIMIT + 1))
    expected = guest.validate_inputs(report['inputs'])
    require(all(row['status'] == 'pass' for row in report['phases'].values()), 'guest phases did not pass')
    device = PORT.resolve(strict=True)
    require(device.parent == Path('/dev') and device.name.startswith('vport'), 'unexpected protected release device')
    with role_artifact(report, end) as (archive, image, receipt, owner):
        fd = os.open(device, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'wb') as output:
            require(stat.S_ISCHR(os.fstat(fd).st_mode), 'protected release port is not a character device')
            send_frame(output, {'schema': 1, 'nonce': expected['platform_export']['nonce'],
                                'image': image, 'receipt': receipt}, archive, end, owner=owner)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit(2)
