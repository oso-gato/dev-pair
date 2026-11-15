"""Synthetic manager/ownership fixture; FIFO/process behavior is real, root/systemd is not."""
import os
import hashlib
import bootstrap
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import native_io


def install(test, root):
    root = Path(root) / 'native-transport'
    root.mkdir(mode=0o700)
    (root / 'records').mkdir(mode=0o700)
    (root / 'streams').mkdir(mode=0o700)
    (root / 'system').mkdir(mode=0o755)
    def protected(path):
        path = Path(path)
        for part in (path, *path.parents):
            if not part.is_relative_to(root):
                break
            if not part.exists() and not part.is_symlink():
                return None
            info = part.lstat()
            if not __import__('stat').S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise ValueError('unsafe synthetic lookup directory')
        return path
    helper = Path(native_io.__file__).with_name('native_relay.py')
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    boundaries = (
        patch.object(native_io, 'ROOT', root),
        patch.object(native_io, 'guard_root', return_value=None),
        patch.object(native_io, 'STREAM_ROOT', root / 'streams'),
        patch.object(native_io, 'PROFILE_ROOT', root / 'system'),
        patch.object(native_io, 'protected_directory', side_effect=protected),
        patch.object(native_io, 'lookup_paths', return_value=(str(root / 'system'),)),
        patch.object(bootstrap, 'lookup_paths', return_value=(str(root / 'system'),)),
        patch.object(bootstrap, 'stage_relay', return_value=(helper, digest)),
        patch.object(native_io, 'stage_relay', return_value=(helper, digest)),
        patch.object(bootstrap, 'expected_uid', return_value=os.getuid()),
        patch.object(native_io, 'expected_uid', return_value=os.getuid()),
        patch.object(bootstrap, 'verify_labels', return_value=None),
        patch.object(native_io, 'verify_labels', return_value=None),
    )
    for item in boundaries:
        item.start()
        test.addCleanup(item.stop)
    return root


def launch_payload(original, args, kwargs, payload):
    # Fake manager opens regular stdin/FIFO outputs itself, exactly at the
    # properties supplied by production. No stdio FD passes through systemd.
    # Run the real relay and wire protocol; only native UID/SELinux admission is
    # simulated because this test process is not a Fedora service.
    if '-I' in args and '--helper' in args:
        index = args.index('-I')
        helper = args[index + 1]
        relay_args = args[index + 2:]
        code = ('import sys;sys.path.insert(0,sys.argv[1]);import native_relay as r;'
                'r.verify_process=lambda uid:"unconfined_service_t";r.verify_fds=lambda value:None;r.verify_profile=lambda args:None;'
                'sys.argv=["relay",*sys.argv[2:]];raise SystemExit(r.main())')
        payload = [sys.executable, '-c', code, str(Path(helper).parent), *relay_args]
    opened = []
    def stream(name, mode):
        value = next(v.split('=', 2)[2] for v in args if v.startswith('--property=' + name + '='))
        if value == 'null':
            return subprocess.DEVNULL
        assert value.startswith('file:')
        result = open(value[5:], mode, buffering=0)
        opened.append(result)
        return result
    try:
        kwargs.update(stdin=stream('StandardInput', 'rb'), stdout=stream('StandardOutput', 'wb'), stderr=stream('StandardError', 'wb'))
        return original(payload, **kwargs)
    finally:
        for value in opened:
            value.close()


def manager(original, calls):
    def run(args, **kwargs):
        calls.append(tuple(args))
        if args[0] == '/usr/sbin/restorecon':
            return original([sys.executable, '-c', 'pass'], **kwargs)
        if args[0] == '/usr/bin/systemctl':
            unit = args[-1]
            text = 'Description=dev-pair-owned-' + unit + '\nLoadState=not-found\nActiveState=inactive\nUser=\n'
            return original([sys.executable, '-c', 'import sys;sys.stdout.write(sys.argv[1])', text], **kwargs)
        if args[0] == '/usr/bin/systemd-run':
            position = args.index('/usr/bin/env') if '/usr/bin/env' in args else (args.index(sys.executable) if sys.executable in args else args.index('/usr/bin/python3'))
            return launch_payload(original, args, kwargs, args[position:])
        return original(args, **kwargs)
    return run
