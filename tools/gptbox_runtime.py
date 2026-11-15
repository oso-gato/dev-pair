#!/usr/bin/python3
"""Image-owned genuine Distrobox assembly finalizer and frozen probe entry."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time

BASE = Path('/usr/lib/dev-pair/gptbox')
CODEX = Path('/opt/dev-pair/bin/codex')

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def inputs():
    return json.loads((BASE / 'inputs.json').read_text())

def verify_files():
    expected = inputs()
    for path, wanted in expected['files'].items():
        file = Path(path)
        if file.is_symlink() or not file.is_file() or digest(file) != wanted:
            raise RuntimeError('image-owned executable identity mismatch')
    return expected

def finalize():
    if os.getuid() != 0:
        raise RuntimeError('assembly finalizer requires container root')
    expected = verify_files()
    account = pwd.getpwnam('gpt')
    if (account.pw_uid, account.pw_gid, account.pw_dir) != (1000, 1000, '/home/gpt'):
        raise RuntimeError('upstream init did not create intended account')
    for user in ('root', 'gpt'):
        subprocess.run(['/usr/sbin/usermod', '--lock', user], check=True)
    subprocess.run(['/usr/sbin/usermod', '--groups', '', 'gpt'], check=True)
    for path in ('/etc/profile.d', '/home/gpt', '/run/host', '/etc/sudoers.d'):
        target = Path(path)
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)
    for path in ('/usr/bin/distrobox-host-exec', '/usr/bin/host-spawn', '/usr/local/bin/distrobox-host-exec'):
        target = Path(path)
        if target.exists() or target.is_symlink():
            target.unlink()
    Path('/etc/profile.d').mkdir(mode=0o755)
    Path('/etc/sudoers.d').mkdir(mode=0o755)
    Path('/home/gpt').mkdir(mode=0o755)
    Path('/home/gpt/.codex').mkdir(mode=0o755)
    Path('/home/gpt/.agents').mkdir(mode=0o755)
    Path('/etc/profile').write_text('export PATH=/opt/dev-pair/bin:/usr/bin:/bin\n')
    Path('/home/gpt/.bashrc').write_text('# immutable gptbox shell\n')
    Path('/home/gpt/.bash_profile').write_text('. /etc/profile\n')
    Path('/etc/sudoers').write_text('Defaults env_reset\nroot ALL=(ALL) ALL\n')
    Path('/etc/sudoers').chmod(0o440)
    packages = subprocess.run(['/usr/bin/rpm', '-qa', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'],
                              text=True, capture_output=True, check=True).stdout
    (BASE / 'packages.txt').write_text('\n'.join(sorted(packages.splitlines())) + '\n')
    sealed = {'kind': 'genuine-distrobox-assembled', 'inputs_sha256': digest(BASE / 'inputs.json'),
              'source_sha': expected['source_sha'], 'uid': 1000, 'gid': 1000,
              'packages_sha256': digest(BASE / 'packages.txt')}
    (BASE / 'sealed.json').write_text(json.dumps(sealed, sort_keys=True) + '\n')
    for path in BASE.iterdir():
        if path.is_file():
            path.chmod(0o444)
    print(json.dumps(sealed, sort_keys=True))

def frozen():
    if (os.getuid(), os.getgid()) != (1000, 1000):
        raise RuntimeError('frozen init must be unprivileged')
    verify_files()
    sealed = json.loads((BASE / 'sealed.json').read_text())
    if sealed['inputs_sha256'] != digest(BASE / 'inputs.json') or sealed['packages_sha256'] != digest(BASE / 'packages.txt'):
        raise RuntimeError('sealed assembly evidence mismatch')
    print('container_setup_done', flush=True)
    # This process is only immutable keepalive; it launches no agent or shell.
    os.execv('/usr/bin/sleep', ['sleep', 'infinity'])

def probe():
    verify_files()
    if (os.getuid(), os.getgid()) != (1000, 1000) or os.getgroups() not in ([], [1000]):
        raise RuntimeError('runtime identity/groups mismatch')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if int(status['CapEff'].strip(), 16) or status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2':
        raise RuntimeError('runtime capabilities, NNP or seccomp mismatch')
    label = Path('/proc/self/attr/current').read_text().strip()
    if not label.startswith('system_u:system_r:container_t:s0:') or 'unconfined' in label:
        raise RuntimeError('effective container SELinux confinement missing')
    for target in ('/usr', '/etc', '/opt/dev-pair/bin', '/home/gpt', '/home/gpt/.codex', '/home/gpt/.agents'):
        path = Path(target) / '.dev-pair-write-probe'
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as error:
            if error.errno not in (13, 30):
                raise
        else:
            os.close(descriptor)
            path.unlink()
            raise RuntimeError('managed code/configuration is writable')
    for target in ('/etc/hostname', '/etc/hosts', '/etc/resolv.conf', '/etc/profile',
                   '/home/gpt/.bashrc', str(CODEX), '/usr/bin/distrobox-init', __file__):
        if not Path(target).exists():
            continue
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_APPEND)
        except OSError as error:
            if error.errno not in (13, 30):
                raise
        else:
            os.close(descriptor)
            raise RuntimeError('installed executable/configuration permits write access')
    for target in ('/work/job', '/state', '/cache/job'):
        path = Path(target) / '.dev-pair-write-probe'
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, b'bounded writable-state probe\n')
        os.close(descriptor)
        path.unlink()
    for path in ('/run/host', '/usr/bin/distrobox-host-exec', '/usr/bin/host-spawn', '/run/podman/podman.sock'):
        if Path(path).exists() or Path(path).is_symlink():
            raise RuntimeError('host bridge is exposed')
    return {'boundary_probe': 'passed', 'uid': 1000, 'selinux_label': label,
            'codex_home': 'immutable; auth/session adapter not admitted'}

def entry(operation):
    os.environ.clear()
    os.environ.update({'HOME': '/home/gpt', 'CODEX_HOME': '/home/gpt/.codex',
                       'PATH': '/opt/dev-pair/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                       'XDG_RUNTIME_DIR': '/run/user/1000', 'XDG_CACHE_HOME': '/cache/job',
                       'XDG_STATE_HOME': '/state', 'XDG_CONFIG_HOME': '/home/gpt/.config'})
    if operation == 'probe':
        print(json.dumps(probe(), sort_keys=True))
    elif operation == 'version':
        verify_files()
        os.execv(str(CODEX), [str(CODEX), '--version'])
    else:
        raise RuntimeError('only probe/version entry is admitted; authentication/model/job gates remain pending')

if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['finalize']:
            finalize()
        elif sys.argv[1:] == ['frozen']:
            frozen()
        elif len(sys.argv) == 3 and sys.argv[1] == 'entry':
            entry(sys.argv[2])
        else:
            raise RuntimeError('invalid fixed runtime operation')
    except Exception:
        print('gptbox runtime check failed; no readiness or agent admission', file=sys.stderr)
        sys.exit(2)
