"""Verify effective system service provenance without admitting arbitrary drop-ins."""
import hashlib
import os
from pathlib import Path
import re
import stat

# Fedora 44 signs the fixed vendor service policy with its protected release key.
# Reuse the same pin as the signed Fedora base-image admission.
from fedora_oci import FINGERPRINT, KEY_SHA

VENDOR = '/usr/lib/systemd/system/service.d/10-timeout-abort.conf'
VENDOR_KEY = '/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary'
FORMAT = ('%{NAME}\t%{RELEASE}\t%{ARCH}\t%{FILEDIGESTALGO}\n'
          '[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES:perms}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\n]')
COMMAND_HOOKS = ('ExecCondition', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')
PROPERTIES = ('NeedDaemonReload', 'RootDirectory', 'RootImage', 'SELinuxContext',
              'TimeoutStartFailureMode', 'TimeoutStopFailureMode', 'KillMode', 'SendSIGKILL', 'FinalKillSignal',
              *COMMAND_HOOKS)
TIMEOUT_FIELDS = ('TimeoutStartFailureMode', 'TimeoutStopFailureMode')


def protected(path, owner, limit, *, mode=None):
    path = Path(path)
    for parent in path.parents:
        node = parent.lstat()
        if not stat.S_ISDIR(node.st_mode) or node.st_uid not in (0, owner) or node.st_mode & 0o022:
            raise ValueError('service profile ancestry is not protected')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        node = os.fstat(stream.fileno())
        if (not stat.S_ISREG(node.st_mode) or (node.st_uid, node.st_gid) != (owner, owner)
                or node.st_nlink != 1 or node.st_mode & 0o022 or not 0 < node.st_size <= limit
                or mode is not None and stat.S_IMODE(node.st_mode) != mode):
            raise ValueError('service profile file is not protected')
        raw = stream.read(limit + 1)
        if len(raw) != node.st_size:
            raise ValueError('service profile changed during observation')
        return raw


def fedora_vendor_profile(path, run, owner):
    raw = protected(path(VENDOR), owner, 8192, mode=0o644)
    key_path = path(VENDOR_KEY)
    if hashlib.sha256(protected(key_path, owner, 8192)).hexdigest() != KEY_SHA:
        raise ValueError('signed Fedora 44 RPM key bytes differ')
    # The local rpmdb is part of the trusted, signed Fedora installation.
    # Neither querying a package name nor comparing the filename alone admits
    # the file. Measure its payload digest, owner and mode from that RPM header.
    query = ('/usr/bin/rpm', '-qf', VENDOR)
    rows = run(*query, '--queryformat', FORMAT, timeout=8).splitlines()
    if not rows or len(rows) > 4096 or not re.fullmatch(r'systemd\t[0-9A-Za-z._+~-]+\.fc44\t(?:x86_64|aarch64)\t8', rows[0]):
        raise ValueError('service policy is outside the installed Fedora 44 systemd RPM')
    exact = [row for row in rows[1:] if row.startswith(VENDOR + '\t')]
    want = f'{VENDOR}\t{hashlib.sha256(raw).hexdigest()}\t-rw-r--r--\troot\troot'
    if exact != [want]:
        raise ValueError('vendor service drop-in differs from the installed RPM payload')
    info = run(*query, '--info', timeout=8)
    signatures = re.findall(r'^Signature\s*:\s*(.+)$', info, re.M)
    if (len(signatures) != 1 or not re.fullmatch(r'RSA/SHA(?:256|384|512), [^\n]+, Key ID ' +
                                               FINGERPRINT[-16:].lower(), signatures[0], re.I)):
        raise ValueError('installed systemd RPM does not name the approved Fedora signing key')
    failure = {}
    service = False
    for line in raw.decode('ascii').splitlines():
        text = line.strip()
        if not text or text.startswith(('#', ';')):
            continue
        if text == '[Service]' and not service:
            service = True
            continue
        field, equals, value = text.partition('=')
        if not service or not equals or field not in TIMEOUT_FIELDS or field in failure or value != 'abort':
            raise ValueError('vendor service drop-in changes unapproved settings')
        failure[field] = value
    if not failure or protected(path(VENDOR), owner, 8192, mode=0o644) != raw:
        raise ValueError('vendor timeout policy is empty or changed')
    return failure


def observe(row, owned, path, run, *, owner=0):
    """Verify exact effective service confinement and the closed drop-in set."""
    observed = row['DropInPaths'].split()
    if len(observed) != len(set(observed)) or set(observed) - {VENDOR} != set(owned):
        raise ValueError('system service loaded an unknown or missing override')
    installed = os.path.lexists(path(VENDOR))
    if installed != (VENDOR in observed):
        raise ValueError('system service manager and vendor drop-in differ')
    failure = fedora_vendor_profile(path, run, owner) if installed else {}
    for field in TIMEOUT_FIELDS:
        if row[field] != failure.get(field, 'terminate'):
            raise ValueError('system service effective timeout mode differs')
    exact = {'NeedDaemonReload': 'no', 'RootDirectory': '', 'RootImage': '', 'SELinuxContext': '',
             'KillMode': 'control-group', 'SendSIGKILL': 'yes'}
    if (any(row[key] != value for key, value in exact.items()) or row['FinalKillSignal'] not in ('9', 'SIGKILL')
            or any(row[key] for key in COMMAND_HOOKS)):
        raise ValueError('system service effective process profile differs')


def exec_start_matches(observed, expected):
    # systemctl's machine-readable display includes one command record with
    # path, argv and execution metadata. Reject appended command records.
    match = re.fullmatch(r'\{\s*path=([^;]+?)\s*;\s*argv\[\]=(.*?)\s*;\s*[^{}]*\}', observed)
    return match is not None and match.group(1) == expected.split()[0] and match.group(2) == expected
