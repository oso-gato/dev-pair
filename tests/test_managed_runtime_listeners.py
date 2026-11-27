"""Ordinary bootstrap listener gating with private D/U records and fixed live observations."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bootstrap as b

UID = 2110
BOOT = '12345678-1234-1234-1234-123456789abc'
MACHINE = '2' * 32
HOST = '3' * 64
SITE = '4' * 64
APP_ID = '5' * 64
CONTAINER = '6' * 64
DNS = 'erebus.example.ts.net'
Q_PROC, APP_PROC, APP_SUPERVISOR, TS_PROC = '101', '102', '103', '104'
Q_UNIT = f'dev-pair-checklist-executor@{UID}.service'
Q_GROUP = r'/system.slice/system-dev\x2dpair\x2dchecklist\x2dexecutor.slice/' + Q_UNIT
APP_MANAGER = f'/user.slice/user-{UID}.slice/user@{UID}.service'
APP_GROUP = APP_MANAGER + '/app.slice/dp-checklist-app.service'
TS_GROUP = '/system.slice/tailscaled.service'


def line(address, pid, program='fixture'):
    return f'tcp LISTEN 0 128 {address} 0.0.0.0:* users:(("{program}",pid={pid},fd=3))'


@unittest.skipUnless(os.geteuid() == 0, 'requires the private mapped root fixture')
class RuntimeListeners(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/run')))
        self.app = b.Bootstrap(self.root, self.command)
        self.calls = []
        self.listeners = [line('0.0.0.0:22', '91', 'sshd')]
        self.units = {}
        self.serve = {'TCP': {'443': {'HTTPS': True}},
                      'Web': {DNS + ':443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:18279'}}}}}
        self.account = SimpleNamespace(pw_uid=UID, pw_gid=UID, pw_dir=b.CHECKLIST_HOME,
                                       pw_shell='/usr/sbin/nologin')
        self.enterContext(patch.object(b.pwd, 'getpwnam', return_value=self.account))
        self.enterContext(patch.object(os, 'getgrouplist', return_value=[UID]))
        self.put('/etc/os-release', 'ID=fedora\nVERSION_ID=44\n')
        self.put('/proc/1/comm', 'systemd\n')
        self.put('/etc/machine-id', MACHINE)
        self.put('/proc/sys/kernel/random/boot_id', BOOT)
        self.put('/usr/sbin/nft', '')
        self.put('/etc/systemd/system/' + b.CHECKLIST_UNIT, 'fixed independently installed unit')
        self.base = {'version': 1, 'machine_id': MACHINE, 'platform_sha': '0' * 40, 'uid': UID}
        self.app_row = {'Name': 'dp-checklist-app', 'Id': CONTAINER, 'Image': 'sha256:' + APP_ID,
                        'State': {'Running': True}}
        self.tailscale = {'CurrentTailnet': {'Name': 'trusted'}, 'Self': {'ID': 'node-id', 'DNSName': DNS + '.',
                         'Online': True}, 'BackendState': 'Running', 'TailscaleIPs': ['100.64.8.9', 'fd7a:115c:a1e0::9']}
        self.rule = {'chain': {'table': 'dev_pair_bootstrap', 'family': 'inet', 'name': 'input', 'policy': 'drop'}}

    def put(self, path, value, *, mode=0o600):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value if isinstance(value, str) else json.dumps(value))
        target.chmod(mode)
        return target

    def process(self, pid, uid, group, executable, command=None):
        self.put(executable, 'trusted installed executable', mode=0o755)
        self.put(f'/proc/{pid}/stat', f'{pid} (stock process) S ' + '0 ' * 18 + '1729\n')
        self.put(f'/proc/{pid}/status', f'Name:\tfixture\nUid:\t{(str(uid) + " ") * 4}\nGid:\t{(str(uid) + " ") * 4}\n')
        self.put(f'/proc/{pid}/cgroup', '0::' + group + '\n')
        (self.root / f'proc/{pid}/exe').symlink_to(executable)
        fd = self.root / f'proc/{pid}/fd'
        fd.mkdir()
        (fd / '3').symlink_to('socket:[' + pid + '42]')
        if command is not None:
            self.put(f'/proc/{pid}/cmdline', '\0'.join(command) + '\0')

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == '/usr/sbin/runuser':
            offset = next(i for i, part in enumerate(args) if part in ('/usr/bin/systemctl', '/usr/bin/podman'))
            return self.command(*args[offset:], **kwargs)
        if args[:2] == (b.CHECKLIST_ENTRY, '--describe'):
            return json.dumps(self.q_command)
        if args[0] == '/usr/bin/ss':
            return '\n'.join(self.listeners) + '\n'
        if args[:2] == ('/usr/bin/systemctl', 'is-active'):
            return 'inactive\n'
        if args[:2] == ('/usr/bin/systemctl', 'show') or args[:3] == ('/usr/bin/systemctl', '--user', 'show'):
            fields = next(part for part in args if part.startswith('--property=')).split('=', 1)[1].split(',')
            return '\n'.join(key + '=' + self.units[args[-1]][key] for key in fields)
        if args == ('/usr/sbin/getenforce',):
            return 'Enforcing\n'
        if args[:2] == ('/usr/sbin/sshd', '-T'):
            return 'port 22\n'
        if args[:2] == ('/usr/sbin/sshd', '-t'):
            return ''
        if args[:3] == ('/usr/sbin/nft', 'list', 'tables'):
            return 'table inet dev_pair_bootstrap\n'
        if args[:3] == ('/usr/sbin/nft', '-j', '-s'):
            return json.dumps({'nftables': [self.rule]})
        if args == ('/usr/bin/tailscale', 'status', '--json'):
            return json.dumps(self.tailscale)
        if args == ('/usr/bin/tailscale', 'serve', 'status', '--json'):
            return json.dumps(self.serve)
        if args[0] == '/usr/bin/podman' and args[-3:] == ('container', 'inspect', 'dp-checklist-app'):
            return json.dumps([self.app_row])
        if args[0] == '/usr/bin/podman' and args[-3:] == ('port', 'dp-checklist-app', '8000/tcp'):
            return '127.0.0.1:18279\n'
        raise AssertionError('Unexpected or non-observation invocation: ' + repr(args))

    def prepare(self):
        prepared = {'schema': 1, 'standards_sha': b.STANDARDS, 'operator': 'core', 'bootstrap_sha256': 'f' * 64}
        self.put(b.STATE + '/prepared', prepared)
        self.put(b.STATE + '/desired.json', prepared)
        self.put(b.CHECKLIST_CONTROL + '/provision.json', self.base)

    def handoff(self, managed=False, *, first_recovery=False):
        self.prepare()
        if not first_recovery:
            self.put(b.CHECKLIST_CONTROL + '/ready.json', self.base)
        artifact = f'/usr/libexec/dev-pair/host-releases/{HOST}' if managed else '/usr/libexec/dev-pair/checklist'
        self.q_command = ['/usr/bin/python3', '-EBs', artifact + '/tools/host_handoff.py', *b.CHECKLIST_ARGS]
        self.put(self.q_command[2], 'exact admitted controller code')
        if managed:
            self.put(b.CHECKLIST_OVERRIDE, 'pinned managed override')
            self.put(b.CHECKLIST_ENTRY, 'independently protected launch selector')
            self.put(b.CHECKLIST_CONTROL + '/managed-listener.json',
                     {'version': 2, 'boot': BOOT, 'site': SITE, 'phase': 'recovery' if first_recovery else 'ready'})
            self.put('/var/lib/dev-pair/renewal/site-current.json', json.dumps(SITE))
            self.put('/var/lib/dev-pair/renewal-fence/selected-host.json', {'schema': 1, 'artifact_sha256': HOST}, mode=0o644)
            digest = hashlib.sha256(json.dumps(self.q_command, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.put('/var/lib/dev-pair/renewal/host-observed.json', {'schema': 2, 'boot_id': BOOT,
                     'component': {'artifact_sha256': HOST}, 'handoff': {'unit': Q_UNIT, 'command_sha256': digest}})
            if first_recovery:
                self.put('/var/lib/dev-pair/renewal-fence/frozen', json.dumps('boot'))
        self.units[Q_UNIT] = {'Id': Q_UNIT, 'MainPID': Q_PROC, 'ActiveState': 'active', 'ControlGroup': Q_GROUP,
                             'User': 'dp-checklist', 'Group': 'dp-checklist',
                             'FragmentPath': '/etc/systemd/system/' + b.CHECKLIST_UNIT,
                             'DropInPaths': b.CHECKLIST_OVERRIDE if managed else '', 'ExecMainStartTimestampMonotonic': '1729'}
        self.process(Q_PROC, UID, Q_GROUP, '/usr/bin/python3', self.q_command)
        self.listeners.append(line('127.0.0.1:19425', Q_PROC, 'python3'))

    def publish(self):
        quadlet = f'/etc/containers/systemd/users/{UID}/dp-checklist-app.container'
        unit_hash = hashlib.sha256(b'approved pinned Quadlet').hexdigest()
        self.put(quadlet, 'approved pinned Quadlet')
        self.put(b.CHECKLIST_CONTROL + '/release.json', {'version': 2, 'pending': None, 'route_pending': False,
                 'active': {'subject': 'ghcr.io/oso-gato/dev-pair/checklist@sha256:' + 'd' * 64,
                 'unit_sha256': unit_hash, 'image_id': APP_ID, 'dns_name': DNS, 'compatibility': 'checklist-sqlite-v1'}})
        self.put('/etc/dev-pair/checklist/live-containers.conf', '[engine]\nimage_copy_tmp_dir="approved"\n')
        self.units['dp-checklist-app.service'] = {'Id': 'dp-checklist-app.service', 'MainPID': APP_SUPERVISOR,
                'ActiveState': 'active', 'ControlGroup': APP_GROUP, 'SourcePath': quadlet,
                'FragmentPath': f'/run/user/{UID}/systemd/generator/dp-checklist-app.service',
                'DropInPaths': '', 'InvocationID': 'a' * 32}
        self.units['tailscaled.service'] = {'Id': 'tailscaled.service', 'MainPID': TS_PROC,
                                           'ActiveState': 'active', 'ControlGroup': TS_GROUP}
        self.process(APP_SUPERVISOR, UID, APP_GROUP, '/usr/bin/conmon')
        self.process(APP_PROC, UID, APP_MANAGER + '/app.slice/libpod-' + CONTAINER + '.scope', '/usr/libexec/podman/rootlessport')
        self.process(TS_PROC, 0, TS_GROUP, '/usr/sbin/tailscaled')
        self.put(b.STATE + '/node.json', {'tailnet': 'trusted', 'node_id': 'node-id'})
        self.put(b.CUTOVER, {'phase': 'complete', 'guard_sha256': self.app.guard_hash(), 'target': {'dns_name': DNS}})
        self.put(b.GUARD_PATH, self.app.guard_rules([], tailnet_only=True))
        self.put(b.SSH_CUTOVER, b.SSH_CUTOVER_CONFIG)
        self.listeners.append(line('127.0.0.1:18279', APP_PROC, 'rootlessport'))

    def runtime(self):
        return self.app.preflight(managed_runtime=True)

    def assert_blocks(self, expression='managed checklist'):
        with self.assertRaisesRegex(b.Blocked, expression):
            self.runtime()

    def test_virgin_and_installed_direct_paths_require_explicit_runtime_call(self):
        self.assertEqual(self.app.preflight(), self.runtime())
        self.handoff()
        with self.assertRaisesRegex(b.Blocked, 'not vanilla'):
            self.app.preflight()
        self.assertEqual(self.runtime()['selinux'], 'Enforcing')
        self.put(b.CHECKLIST_CONTROL + '/ready.json', dict(self.base, platform_sha='9' * 40))
        self.assert_blocks()

    def test_managed_commissioning_readback_precedes_ready_and_needs_same_boot(self):
        self.handoff(managed=True, first_recovery=True)
        self.runtime()
        self.put('/proc/sys/kernel/random/boot_id', 'abababab-1234-1234-1234-123456789abc')
        self.assert_blocks()

    def test_live_handoff_rejects_foreign_pid_or_other_socket(self):
        self.handoff(managed=True)
        self.runtime()
        self.units[Q_UNIT]['MainPID'] = '812'
        self.assert_blocks()
        self.units[Q_UNIT]['MainPID'] = Q_PROC
        self.listeners.append(line('0.0.0.0:19425', Q_PROC))
        self.assert_blocks()
        self.listeners.pop()
        self.listeners.append(line('127.0.0.1:19999', Q_PROC))
        self.assert_blocks('not vanilla')

    def test_published_loopback_and_exact_tailnet_serve_from_live_supervisors(self):
        self.handoff(managed=True)
        self.publish()
        self.runtime()
        self.listeners.extend((line('100.64.8.9:443', TS_PROC), line('[fd7a:115c:a1e0::9]:443', TS_PROC)))
        self.runtime()
        with self.assertRaisesRegex(b.Blocked, 'not vanilla'):
            self.app.preflight()
        self.listeners[-1] = line('[::]:443', TS_PROC)
        self.assert_blocks()

    def test_managed_app_rejects_foreign_cgroup_image_route_and_staging_state(self):
        self.handoff(managed=True)
        self.publish()
        self.app_row['Image'] = 'sha256:' + '0' * 64
        self.assert_blocks()
        self.app_row['Image'] = 'sha256:' + APP_ID
        actual = APP_MANAGER + '/app.slice/libpod-' + CONTAINER + '.scope'
        self.put('/proc/' + APP_PROC + '/cgroup', '0::' + APP_MANAGER + '/app.slice/unowned.service\n')
        self.assert_blocks()
        self.put('/proc/' + APP_PROC + '/cgroup', '0::' + actual + '\n')
        self.serve['AllowFunnel'] = {DNS + ':443': True}
        self.assert_blocks()
        del self.serve['AllowFunnel']
        state_path = self.root / b.CHECKLIST_CONTROL[1:] / 'release.json'
        original = json.loads(state_path.read_bytes())
        self.put(b.CHECKLIST_CONTROL + '/release.json', dict(original, route_pending=True))
        self.assert_blocks()

    def test_managed_inventory_binding_rejects_socket_replacement_at_readback(self):
        self.handoff()
        run = self.app.run
        observed = 0
        def replace(*args, **kwargs):
            nonlocal observed
            if args[0] == '/usr/bin/ss':
                observed += 1
                if observed == 2:
                    fd = self.root / 'proc' / Q_PROC / 'fd' / '3'
                    fd.unlink()
                    fd.symlink_to('socket:[99]')
            return run(*args, **kwargs)
        self.app.run = replace
        self.assert_blocks()


if __name__ == '__main__':
    unittest.main()
