"""Check first access station setup, scoped enrollment and plan preparation."""

from contextlib import ExitStack
import json
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
from bootstrap import Blocked, CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER
import agent_observer_station
import day0_access_exchange as transport
import day0_access_station as station
import destination_observation as observation


class FirstAccessStationTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir=Path.home())))
        home = self.directory / 'courier'
        home.mkdir(mode=0o755)
        home.chmod(0o755)
        tools = self.directory / 'installed'
        user = os.geteuid() or 12345
        self.courier = SimpleNamespace(pw_uid=user, pw_gid=os.getegid(), pw_name='courier',
                                       pw_dir=str(home), pw_shell='/bin/bash')
        self.reviewer = SimpleNamespace(pw_uid=user + 1)
        self.mailbox = self.directory / 'mailboxes' / 'courier'
        self.site = self.directory / 'site.json'
        self.authorized = home / '.ssh' / 'authorized_keys'
        self.source = '100.65.0.8'
        self.address = '100.65.0.9'
        self.node = 'erebus.home.example.ts.net'
        self.tailnet = 'example.ts.net'
        self.sha = 'a' * 40
        self.acl = 'b' * 64
        self.authorities = {}
        for role in (*station.REVIEW_ROLES, 'host', 'access-review', 'transport', 'new-transport'):
            path = self.directory / role
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)],
                           check=True, capture_output=True, timeout=5)
            self.authorities[role] = path.with_suffix('.pub')
        args = dict(source_sha=self.sha, station_address=self.address, courier_user='courier', reviewer_user='reviewer',
                    acl_oauth=self.directory / 'independent-oauth', dns_name=self.node, tailnet=self.tailnet,
                    provider_recovery='hostinger://reviewed-vps/recovery', public_ipv4='none', public_ipv6='none',
                    execution_route='provider-recovery', station_ssh_host_key=self.authorities['host'],
                    access_review_key=self.authorities['access-review'])
        args.update({role + '_client': 'approved-' + role for role in observation.VANTAGES})
        args.update({role + '_key': self.authorities[role] for role in station.REVIEW_ROLES})
        self.prepare_args = SimpleNamespace(**args)
        self.admit_args = SimpleNamespace(source_sha=self.sha, vps_address=self.source,
                                          courier_key=self.authorities['transport'])
        self.env = self.enterContext(ExitStack())
        state = {
            'CONFIG': self.directory / 'config.json', 'CORE_PROFILE': self.site,
            'REVIEW_SIGNERS': self.directory / 'access-review-signers', 'SIGNERS': str(self.directory / 'signers'),
            'MAILBOX_ROOT': self.mailbox.parent, 'STATION_TOOLS': tools,
            'account': lambda name: {'courier': self.courier, 'reviewer': self.reviewer}[name],
        }
        self.env.enter_context(patch.multiple(station, **state))
        self.env.enter_context(patch.object(station, 'protected', self.project_protection))
        self.env.enter_context(patch.object(station, 'policy_credential', side_effect=lambda path, _: path))
        self.env.enter_context(patch.object(station, 'account_directory', self.project_mailbox))
        self.assets = {tools / name: (TOOLS / name).read_bytes() for name in agent_observer_station.STATION_SCRIPTS}
        self.env.enter_context(patch.object(station, 'verified_assets', return_value=self.assets))
        self.run = Mock(side_effect=self.command)
        self.app = SimpleNamespace(run=self.run, atomic=self.write)
        self.measure = Mock(return_value=(self.acl + '\n').encode())

    @staticmethod
    def project_protection(path, directory=False):
        leaf = Path(path)
        node = leaf.lstat()
        if leaf != leaf.resolve(strict=True) or node.st_mode & 0o022 or (
                directory and not stat.S_ISDIR(node.st_mode)) or (not directory and not stat.S_ISREG(node.st_mode)):
            raise Blocked('projected station path is unsafe')
        return leaf

    @staticmethod
    def project_mailbox(path, uid):
        if path.resolve(strict=True) != path or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise Blocked('projected mailbox is unsafe')
        return path

    @staticmethod
    def write(path, text, *, mode):
        leaf = Path(path)
        leaf.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        leaf.parent.chmod(0o755)
        if not leaf.exists():
            leaf.write_text(text)
            leaf.chmod(mode)

    def command(self, executable, *args, timeout):
        if executable.endswith('tailscale'):
            return json.dumps({'BackendState': 'Running', 'TailscaleIPs': [self.address],
                               'CurrentTailnet': {'Name': self.tailnet}})
        return ('authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand none\ntrustedusercakeys none\n'
                'forcecommand none\npermituserenvironment no\npubkeyauthentication yes\nstrictmodes yes\n'
                'authenticationmethods any\npasswordauthentication no\nkbdinteractiveauthentication no\n'
                f'hostkey {self.authorities["host"].with_suffix("")}\nacceptenv LANG\nacceptenv LC_*\n')

    def prepare(self):
        result = station.prepare(self.prepare_args, self.app, self.measure)
        self.measure.assert_called_with({'user': 'reviewer'},
            (station.PYTHON, '-EBs', station.STATION_TOOLS / 'destination_observation.py',
             'measure-acl', '--tailnet', self.tailnet, '--acl-oauth', self.prepare_args.acl_oauth), limit=256)
        return result

    def binding(self, kind):
        binding = {'version': 1, 'kind': kind, 'job_id': 'host-access', 'source_sha': self.sha,
                   'machine_id': 'c' * 32, 'boot_id': '11111111-2222-3333-4444-555555555555',
                   'dns_name': self.node, 'tailnet': self.tailnet, 'node_id': 'reviewed-node',
                   'keys_sha256': 'd' * 64, 'tailnet_addresses': {'ipv4': self.source, 'ipv6': 'fd7a:115c:a1e0::8'}}
        if kind == WORKLOAD_ACCESS_CUTOVER:
            binding['role_artifacts'] = {key: 'site' if key == 'job' else 'e' * 64 for key in observation.ROLE_ARTIFACTS}
        return binding

    def test_clean_install_creates_reusable_site_and_scoped_openssh_key(self):
        selected = self.prepare()
        self.assertEqual(set(station.STATION_TOOLS.iterdir()), set(self.assets))
        self.assertEqual(selected['courier_uid'], self.courier.pw_uid)
        self.assertEqual(stat.S_IMODE(self.mailbox.stat().st_mode), 0o700)
        self.assertFalse(self.authorized.exists())
        profile = json.loads(self.site.read_bytes())
        self.assertEqual(set(profile), observation.CORE_SITE)
        self.assertEqual(profile['acl_sha256'], self.acl)
        for kind in (CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER):
            plan = observation.prepare_plan(self.binding(kind), profile, int(time.time()), None)
            self.assertEqual(plan['kind'], kind)
            self.assertEqual(plan['clients']['provider'], 'approved-provider')

        installed = station.admit_courier(self.admit_args, self.app)
        self.assertEqual(installed, self.authorized)
        first = installed.read_bytes()
        self.assertTrue(first.startswith(f'restrict,from="{self.source}",command="'.encode()))
        self.assertIn(f'--mailbox {self.mailbox} receive" ssh-ed25519 '.encode(), first)
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
        self.assertEqual(self.prepare(), selected)
        station.admit_courier(self.admit_args, self.app)
        self.assertEqual(installed.read_bytes(), first)
        output = subprocess.run([station.PYTHON, '-IB', str(station.STATION_TOOLS / 'day0_access_exchange.py'),
                                 '--help'], check=True, capture_output=True, timeout=5)
        self.assertIn(b'receive', output.stdout)

    def test_rejects_reused_wildcard_or_unsafe_station_authority_without_rewriting(self):
        self.prepare_args.authorized_key = self.authorities['plan']
        with self.assertRaisesRegex(Blocked, 'separate public keys'):
            self.prepare()
        multi = self.directory / 'wildcard.pub'
        multi.write_bytes(b'* ' + self.authorities['authorized'].read_bytes())
        self.prepare_args.authorized_key = multi
        with self.assertRaises(Blocked):
            self.prepare()
        self.prepare_args.authorized_key = self.authorities['authorized']
        self.prepare()
        before = self.site.read_bytes()
        self.measure.return_value = b'c' * 64 + b'\n'
        with self.assertRaisesRegex(Blocked, 'conflicts'):
            self.prepare()
        self.assertEqual(self.site.read_bytes(), before)

        self.authorized.parent.mkdir()
        self.authorized.parent.chmod(0o755)
        unrelated = self.authorities['new-transport'].read_bytes()
        self.authorized.write_bytes(unrelated)
        with self.assertRaisesRegex(Blocked, 'conflicts'):
            station.admit_courier(self.admit_args, self.app)
        self.assertEqual(self.authorized.read_bytes(), unrelated)
        self.authorized.unlink()
        self.run.side_effect = lambda executable, *args, timeout: self.command(
            executable, *args, timeout=timeout).replace('passwordauthentication no', 'passwordauthentication yes')
        with self.assertRaisesRegex(Blocked, 'key-only authentication'):
            station.admit_courier(self.admit_args, self.app)
        self.assertFalse(self.authorized.exists())

    def test_projected_station_denies_reenrollment_with_a_changed_key_or_reused_signer(self):
        self.prepare()
        self.admit_args.courier_key = self.authorities['access-review']
        with self.assertRaisesRegex(Blocked, 'independent of host and review'):
            station.admit_courier(self.admit_args, self.app)
        self.admit_args.courier_key = self.authorities['transport']
        self.admit_args.vps_address = self.address
        with self.assertRaisesRegex(Blocked, 'station’s address family'):
            station.admit_courier(self.admit_args, self.app)
        self.admit_args.vps_address = self.source
        station.admit_courier(self.admit_args, self.app)
        raw = self.authorized.read_bytes()
        self.admit_args.courier_key = self.authorities['new-transport']
        with self.assertRaisesRegex(Blocked, 'conflicts'):
            station.admit_courier(self.admit_args, self.app)
        self.assertEqual(self.authorized.read_bytes(), raw)



class NightlyStationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.collector = self.agent('collector')
        self.reviewer = self.agent('reviewer')
        self.roster = self.directory / 'collector-allowed'
        self.final = self.directory / 'reviewer-allowed'
        self.roster.write_bytes(
            f'{observation.observer_principal("authorized")} namespaces="{observation.NAMESPACE}" '.encode()
            + self.collector['signer'].read_bytes()
        )
        self.final.write_bytes(
            f'{transport.ACCESS_PRINCIPAL} namespaces="{observation.FINAL_NAMESPACE}" '.encode()
            + self.reviewer['signer'].read_bytes()
        )
        self.enterContext(patch.object(agent_observer_station, 'configured_signers', return_value=self.roster))

    def agent(self, name):
        key = self.directory / name
        socket = self.directory / (name + '.sock')
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True, capture_output=True, timeout=5)
        agent = subprocess.Popen(['/usr/bin/ssh-agent', '-D', '-a', str(socket)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            if agent.poll() is None:
                agent.terminate()
                agent.wait(timeout=5)

        self.addCleanup(stop)
        end = time.monotonic() + 3
        while not socket.exists() and time.monotonic() < end:
            time.sleep(0.01)
        subprocess.run(['/usr/bin/ssh-add', str(key)], check=True, capture_output=True, timeout=5,
                       env={'PATH': '/usr/bin', 'SSH_AUTH_SOCK': str(socket)})
        return {'signer': key.with_suffix('.pub'), 'ssh_agent': socket}

    def test_real_agent_signatures_are_scoped_to_separate_approved_principals(self):
        observed = []

        def caller(profile, command, *, data, limit, timeout):
            observed.append((profile['ssh_agent'], json.loads(data), command[-1]))
            result = subprocess.run([str(arg) for arg in command], input=data, capture_output=True, timeout=timeout,
                                    env={'PATH': '/usr/bin', 'SSH_AUTH_SOCK': str(profile['ssh_agent'])})
            if result.returncode:
                raise Blocked('fixture signer unavailable in selected agent')
            return result.stdout

        admitted = {'collector': self.collector, 'reviewer': self.reviewer}
        source = 'a' * 40
        agent_observer_station.confirm_station_signers(admitted, self.final, source, caller, scratch=self.directory)
        self.assertEqual([(socket, record['role'], ns) for socket, record, ns in observed],
                         [(self.collector['ssh_agent'], 'collector', observation.NAMESPACE),
                          (self.reviewer['ssh_agent'], 'reviewer', observation.FINAL_NAMESPACE)])
        self.assertEqual(len({record['challenge'] for _, record, _ in observed}), 2)
        self.assertTrue(all(record['source_sha'] == source for _, record, _ in observed))

        stale = {**admitted, 'collector': {**self.collector, 'ssh_agent': self.reviewer['ssh_agent']}}
        with self.assertRaisesRegex(Blocked, 'signer unavailable'):
            agent_observer_station.confirm_station_signers(stale, self.final, source, caller, scratch=self.directory)
        self.final.write_bytes(b'* ' + self.reviewer['signer'].read_bytes())
        with self.assertRaisesRegex(Blocked, 'exact independently scoped public trust'):
            agent_observer_station.confirm_station_signers(admitted, self.final, source, caller, scratch=self.directory)
        self.final.write_bytes(
            f'{transport.ACCESS_PRINCIPAL} namespaces="{observation.FINAL_NAMESPACE}" '.encode()
            + self.reviewer['signer'].read_bytes() + b'other-role ' + self.reviewer['signer'].read_bytes()
        )
        with self.assertRaisesRegex(Blocked, 'exact independently scoped public trust'):
            agent_observer_station.confirm_station_signers(admitted, self.final, source, caller, scratch=self.directory)


if __name__ == '__main__':
    unittest.main()
