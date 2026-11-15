#!/usr/bin/env python3
"""Fixed QEMU entrypoint copied into the disposable test-tooling image."""
import os
import resource
import sys

OVERLAY_MAX_BYTES = 16 * 1024 ** 3


def limit_output_bytes(limit=OVERLAY_MAX_BYTES):
    if type(limit) is not int or not 1 <= limit <= OVERLAY_MAX_BYTES:
        raise ValueError('file limit cannot exceed the declared 16GiB overlay ceiling')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


if __name__ == '__main__':
    limit_output_bytes()
    os.execv('/usr/bin/qemu-system-x86_64', ['/usr/bin/qemu-system-x86_64', *sys.argv[1:]])
