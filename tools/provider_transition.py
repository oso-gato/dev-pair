#!/usr/bin/python3 -IB
"""Fence systemd provider starts while an older invocation drains."""

import base64
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_protocol as p
import provider_billing as billing
from ledger_recovery import sync_directory
from systemd_service_profile import VENDOR, exec_start_matches, manager_properties

STATE = '/var/lib/dev-pair/provider-transition'
RUNTIME = '/run/dev-pair-provider-transition'
READY = RUNTIME + '/ready.json'
TEMPLATE = '/etc/systemd/system/dev-pair-provider@.service'
DROP_IN = TEMPLATE + '.d/50-dev-pair-provider-fence.conf'
LAUNCHER = '/usr/libexec/dev-pair/renewal/provider-run'
GATE = '/usr/libexec/dev-pair/tools/provider_transition.py'
BILLING_TOOLS = ('/usr/libexec/dev-pair/tools/provider_billing.py', '/usr/libexec/dev-pair/tools/provider_broker.py')
CONDITION = '/usr/bin/python3 -IB ' + GATE + ' admit %i'
SYSTEMCTL = '/usr/bin/systemctl'
PREFIX = 'dev-pair-provider@'
WILDCARD = PREFIX + '*.service'
PROBE = PREFIX + '0' * 64 + '.service'
INSTANCE = re.compile(PREFIX + r'([0-9a-f]{64})\.service')
PROPERTIES = ('Id Names LoadState FragmentPath DropInPaths NeedDaemonReload Type User Group ExecStart ExecCondition '
              'ActiveState SubState MainPID ControlPID Job InvocationID ControlGroup KillMode SendSIGKILL').split()
KINDS = ('reviewer', 'withdraw-reference', 'receive')
MAX_INVENTORY = 256
PENDING_LIMIT = 2 * billing.BUNDLE_LIMIT + 4096
GATE_SHA256 = p.sha256(Path(__file__).read_bytes())


class Deferred(ValueError):
    """No current readiness or effective custody effect has been admitted."""


def command(*args, timeout):
    from checklist_candidate import invoke

    return invoke(args, time.monotonic() + timeout, cap=128 * 1024).decode('utf-8')


class Fence:
    def __init__(self, root=Path('/'), run=command, *, deadline=None):
        self.root, self.run = root, run
        self.deadline = deadline
        self.state = self.path(STATE)
        self.runtime = self.path(RUNTIME)
        self.pending = self.state / 'pending.json'
        self.ready = self.path(READY)

    def path(self, location):
        return self.root / location.lstrip('/')

    def manager(self, *args, timeout=5):
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise Deferred('The provider manager observation reached its boot deadline.')
        return self.run(SYSTEMCTL, *args, timeout=timeout)

    @staticmethod
    def read(path, limit):
        return billing.bounded_file(billing.protected(path, private=True), limit, owner=0, mode=0o600)

    def boot(self):
        raw = self.path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        p.require(str(uuid.UUID(raw)) == raw, 'The current broker manager boot identity is unavailable.')
        return raw

    def definition(self):
        records = {}
        for name in (TEMPLATE, DROP_IN, LAUNCHER, GATE, *BILLING_TOOLS):
            path = billing.protected(self.path(name))
            records[name] = p.sha256(billing.bounded_file(path, 128 * 1024, owner=0))
        p.require(billing.bounded_file(self.path(DROP_IN), 512, owner=0) ==
                  ('[Service]\nExecCondition=' + CONDITION + '\n').encode(),
                  'The installed broker start fence differs.')
        p.require(records[GATE] == GATE_SHA256,
                  'The installed provider guard differs from the running controller.')
        return {'schema': 1, 'boot': self.boot(), 'files': records}

    def mkdir(self):
        billing.private_folder(self.state)
        billing.private_folder(self.runtime)

    def hold(self):
        if os.path.lexists(self.ready):
            self.read(self.ready, 4096)
            self.ready.unlink()
            sync_directory(self.runtime)

    def require_ready(self):
        p.require(not os.path.lexists(self.pending), 'Provider billing changes are waiting for old broker instances to drain.')
        try:
            saved = p.loads(self.read(self.ready, 4096))
            p.require(saved == self.definition(), 'The broker start fence needs a new proof for this boot.')
        except FileNotFoundError as exc:
            raise Deferred('Provider starts are fenced pending device readback. Resume Day 0.') from exc

    def unit(self, name):
        p.require(INSTANCE.fullmatch(name), 'The manager returned a foreign provider instance.')
        raw = self.manager('show', '--all', '--property=' + ','.join(PROPERTIES), name)
        row = manager_properties(raw, PROPERTIES)
        p.require(row['Id'] == name and row['Names'] == name and row['LoadState'] == 'loaded',
                  'The exact provider instance is not identifiable in the manager.')
        p.require(row['InvocationID'] == '' or re.fullmatch(r'[0-9a-f]{32}', row['InvocationID']),
                  'The provider invocation identity is unavailable.')
        return row

    def guarded(self, row):
        request, = INSTANCE.fullmatch(row['Id']).groups()
        expected = [DROP_IN]
        if os.path.lexists(self.path(VENDOR)):
            expected.insert(0, VENDOR)
        p.require(row['DropInPaths'].split() == expected and row['FragmentPath'] == TEMPLATE and
                  row['NeedDaemonReload'] == 'no' and row['Type'] == 'exec' and row['User'] == 'root' and
                  row['Group'] in ('root', '') and row['KillMode'] == 'control-group' and row['SendSIGKILL'] == 'yes' and
                  exec_start_matches(row['ExecStart'], LAUNCHER + ' ' + request) and
                  exec_start_matches(row['ExecCondition'], CONDITION.replace('%i', request)),
                  'The running systemd manager has not loaded the exact provider start fence.')

    def inventory(self):
        names = set()
        queued = set()
        for label, args in (('units', ['list-units', '--all']), ('jobs', ['list-jobs'])):
            rows = self.manager(*args, '--plain', '--full', '--no-legend', '--no-pager', WILDCARD).splitlines()
            p.require(len(rows) <= MAX_INVENTORY, 'The exact broker instance inventory exceeds its bound.')
            for raw in rows:
                columns = raw.split()
                if not columns:
                    continue
                field = 0 if label == 'units' else 1
                p.require(len(columns) > field and INSTANCE.fullmatch(columns[field]),
                          'The systemd broker inventory is incomplete or contains an unknown route.')
                if label == 'jobs':
                    p.require(columns[0].isdigit(), 'The systemd broker job identity is invalid.')
                    queued.add(columns[field])
                names.add(columns[field])
        return names, queued

    def unique_template(self):
        raw = self.manager('show', '--property=UnitPath', '--value')
        paths = raw.split()
        p.require(TEMPLATE.rsplit('/', 1)[0] in paths and 1 <= len(paths) <= 32 and len(set(paths)) == len(paths),
                  'The manager unit lookup roots are unavailable.')
        for value in paths:
            relative = PurePosixPath(value)
            p.require(relative.is_absolute() and relative.as_posix() == value and '..' not in relative.parts and
                      any(relative.is_relative_to(root) for root in ('/etc', '/run', '/usr/lib', '/usr/local/lib', '/lib')),
                      'The manager has a foreign unit lookup root.')
            folder = self.path(value)
            if not os.path.lexists(folder):
                continue
            billing.protected(folder, directory=True)
            with os.scandir(folder) as entries:
                for count, item in enumerate(entries):
                    p.require(count < 4096, 'The systemd unit file inventory exceeds its bound.')
                    if item.name.startswith(PREFIX):
                        exact = value + '/' + item.name
                        p.require(exact in (TEMPLATE, DROP_IN.rsplit('/', 1)[0]) and not item.is_symlink(),
                                  'An exact provider instance has an unapproved unit or override.')
                    elif item.is_symlink():
                        target = PurePosixPath(os.readlink(item.path)).name
                        p.require(not target.startswith(PREFIX), 'An unapproved alias can start a provider service.')

    def cgroup_idle(self, row):
        group = row['ControlGroup']
        if not group:
            return True
        path = PurePosixPath(group)
        p.require(path.is_absolute() and path.as_posix() == group and '..' not in path.parts and
                  path.name == row['Id'], 'The provider instance has a foreign control group.')
        directory = self.path('/sys/fs/cgroup' + group)
        p.require(directory.resolve() == directory, 'The provider control group path is not canonical.')
        try:
            lines = (directory / 'cgroup.events').read_text(encoding='ascii').splitlines()
        except FileNotFoundError:
            p.require(not os.path.lexists(directory), 'The provider control group state is unavailable.')
            return True
        states = [line for line in lines if line.startswith('populated ')]
        p.require(states in (['populated 0'], ['populated 1']), 'The provider control group population is unverified.')
        return states == ['populated 0']

    def kernel_idle(self):
        if self.root == Path('/'):
            p.require(self.path('/sys/fs/cgroup/cgroup.controllers').is_file(),
                      'The provider requires the unified kernel cgroup inventory.')
        system = self.path('/sys/fs/cgroup/system.slice')
        instance_slice = system / r'system-dev\x2dpair\x2dprovider.slice'
        for folder in (system, instance_slice):
            if not os.path.lexists(folder):
                continue
            p.require(folder.resolve() == folder and folder.is_dir(), 'The provider cgroup inventory is unavailable.')
            with os.scandir(folder) as children:
                for index, entry in enumerate(children):
                    p.require(index < 4096, 'The systemd cgroup inventory exceeds its bound.')
                    if not entry.name.startswith(PREFIX):
                        continue
                    p.require(INSTANCE.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False),
                              'The provider cgroup inventory contains an unknown route.')
                    group = '/' + str(Path(entry.path).relative_to(self.path('/sys/fs/cgroup')))
                    if not self.cgroup_idle({'ControlGroup': group, 'Id': entry.name}):
                        return False
        return True

    def idle(self, deadline):
        p.require(not os.path.lexists(self.ready), 'The broker start fence is open during the idle check.')
        self.unique_template()
        self.guarded(self.unit(PROBE))
        names, queued = self.inventory()
        for name in sorted(names):
            if time.monotonic() >= deadline:
                raise Deferred('Exact provider instance readback needs another bounded pass. Resume Day 0.')
            if name in queued:
                return False
            row = self.unit(name)
            if (row['ActiveState'] not in ('inactive', 'failed') or row['SubState'] not in ('dead', 'failed') or
                    row['Job'] not in ('0', '') or row['MainPID'] != '0' or row['ControlPID'] != '0' or
                    not self.cgroup_idle(row)):
                return False
            self.guarded(row)
        self.guarded(self.unit(PROBE))
        # A job whose condition had already completed remains loaded until it
        # settles. With starts fenced, new entries cannot advance to ExecStart.
        # Reobserve the inventory before admitting custody or readiness.
        later, queued = self.inventory()
        self.unique_template()
        return not queued and not later - names and self.kernel_idle()

    def intent(self):
        if not os.path.lexists(self.pending):
            return None
        raw = self.read(self.pending, PENDING_LIMIT)
        row = billing.json_bundle(raw)
        p.fields(row, 'schema kind payload')
        p.number(row['schema'], 1, 1)
        p.require(row['kind'] in KINDS and type(row['payload']) is dict, 'Invalid pending provider authority operation.')
        return row

    def apply(self, intent):
        fields = intent['payload']
        if intent['kind'] == 'reviewer':
            p.fields(fields, 'public fingerprint expected')
            return billing._set_reviewer(fields['public'], fields['fingerprint'], fields['expected'])
        if intent['kind'] == 'withdraw-reference':
            p.fields(fields, 'reference')
            return billing._withdraw_reference(fields['reference'])
        p.fields(fields, 'reference data')
        return billing._receive(fields['reference'], base64.b64decode(fields['data'], validate=True))

    def settle(self, intent):
        self.hold()
        snapshot = self.definition()
        if not self.idle(time.monotonic() + 18):
            raise Deferred('An exact provider unit is still starting or finishing. The start fence remains closed. Resume Day 0.')
        result = self.apply(intent) if intent is not None else None
        p.require(snapshot == self.definition() and self.idle(time.monotonic() + 18),
                  'The provider start fence changed during custody readback.')
        if intent is not None:
            self.pending.unlink()
            sync_directory(self.state)
        billing.replace_record(self.ready, snapshot)
        self.require_ready()
        return result

    def converge(self, *, resume_custody=True):
        self.mkdir()
        with billing.lock(self.state):
            intent = self.intent()
            if intent is not None and not resume_custody:
                self.hold()
                raise Deferred('An attended custody operation remains pending. Resume Day 0.')
            if intent is None and os.path.lexists(self.ready):
                try:
                    self.require_ready()
                    self.guarded(self.unit(PROBE))
                    self.unique_template()
                    return
                except (OSError, ValueError, RuntimeError):
                    self.hold()
            self.settle(intent)

    def change(self, kind, payload):
        self.mkdir()
        proposed = {'schema': 1, 'kind': kind, 'payload': payload}
        with billing.lock(self.state):
            current = self.intent()
            if current is None:
                billing.replace_record(self.pending, proposed)
            elif current != proposed:
                raise Deferred('A different exact billing operation is pending. Resume Day 0 to settle it.')
            return self.settle(proposed)

    def discard(self, expected):
        self.mkdir()
        with billing.lock(self.state):
            p.require(expected is not None and self.intent() == expected, 'The pending billing operation changed.')
            self.hold()
            if not self.idle(time.monotonic() + 18):
                raise Deferred('A provider unit is still settling. The pending operation and start fence are retained.')
            self.pending.unlink()
            sync_directory(self.state)
            self.settle(None)


def reprove_boot(deadline):
    if time.monotonic() >= deadline:
        return False
    try:
        Fence(deadline=deadline).converge(resume_custody=False)
    except (OSError, ValueError, RuntimeError):
        return False
    return True


if __name__ == '__main__':
    try:
        p.require(os.getuid() == os.geteuid() == 0 and len(sys.argv) == 3 and sys.argv[1] == 'admit',
                  'The broker guard requires its protected systemd entry.')
        p.digest(sys.argv[2])
        Fence().require_ready()
    except (OSError, ValueError, RuntimeError):
        print('Provider start is fenced pending exact systemd and billing authority.', file=sys.stderr)
        sys.exit(1)
