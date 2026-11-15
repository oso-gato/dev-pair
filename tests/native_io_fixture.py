"""Synthetic manager/ownership fixture; FIFO/process behavior is real, root/systemd is not."""
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import native_io


def install(test, root):
    root = Path(root) / 'native-transport'
    root.mkdir(mode=0o700)
    (root / 'records').mkdir(mode=0o700)
    for item in (patch.object(native_io, 'ROOT', root), patch.object(native_io, 'guard_root', return_value=None)):
        item.start()
        test.addCleanup(item.stop)
    return root


def launch_payload(original, args, kwargs, payload):
    # Fake manager opens regular stdin/FIFO outputs itself, exactly at the
    # properties supplied by production. No stdio FD passes through systemd.
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
            position = args.index('/usr/bin/env') if '/usr/bin/env' in args else args.index(sys.executable)
            return launch_payload(original, args, kwargs, args[position:])
        return original(args, **kwargs)
    return run
