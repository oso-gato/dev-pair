"""Real local relay/process tests; Fedora sudo policy and manager are not simulated acceptance."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import fedora_ci_guest as guest
from native_io_fixture import install, manager

PACKAGE = b.sudo_package_projection(b'sudo\t1.9.17\t10.p2.fc44\tx86_64\n', b'', True, 0)


def projection(role='dp-maint', output=None, error=b'', **changes):
    if output is None:
        output = ('User ' + role + ' is not allowed to run sudo on erebus.\n').encode()
    context = dict(complete=True, status=0, native_status=0, relay_verified=True,
                   host_verified=True, package=PACKAGE)
    context.update(changes)
    return b.sudo_denial_projection(role, output, error, **context)


class SudoDenialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = install(self, self.tmp.name)
        self.calls = []
        self.records = []
        self.script = 'import os;os.write(1,b"User dp-maint is not allowed to run sudo on erebus.\\n")'
        self.package_script = 'import os;os.write(1,b"sudo\\t1.9.17\\t10.p2.fc44\\tx86_64\\n")'
        original = subprocess.Popen
        base = manager(original, self.calls)
        def dispatch(args, **kwargs):
            if args[0] in ('/usr/bin/rpm','/usr/bin/sudo'):
                script = self.package_script if args[0] == '/usr/bin/rpm' else self.script
                return original([sys.executable,'-c',script], **kwargs)
            if args[0] == '/usr/bin/systemd-run':
                for command, script in (('/usr/bin/rpm', self.package_script), ('/usr/bin/sudo', self.script)):
                    if command in args:
                        position = args.index(command)
                        args = (*args[:position], sys.executable, '-c', script)
                        break
            return base(args, **kwargs)
        self.dispatch = dispatch
        patched = patch.object(b.subprocess, 'Popen', side_effect=dispatch)
        patched.start(); self.addCleanup(patched.stop)
        self.run = b.Commands()
        self.run.native_prefix = 'dev-pair-initialize-prepare-12345678'
        self.run.diagnostic = self.records.append

    def probe(self, role='dp-maint', package=PACKAGE, host=True):
        return self.run('/usr/bin/sudo', '-l', '-U', role, timeout=3,
                        sudo_probe={'role': role, 'host_verified': host, 'package': package})

    def test_real_relay_success_requires_exact_fixed_role_and_package_query(self):
        observed = self.run(*b.SUDO_PACKAGE_QUERY, timeout=3, sudo_package=True)
        self.assertEqual(observed, PACKAGE)
        self.assertFalse(observed['policy_plugin_verified'])
        for role, operation in b.SUDO_ROLES.items():
            text = ('User ' + role + ' is not allowed to run sudo on erebus.\n').encode()
            self.script = 'import os;os.write(1,' + repr(text) + ')'
            result = self.probe(role, observed)
            self.assertEqual(result['outcome'], 'denied')
            self.assertEqual(result['operation_id'], operation)
            self.assertTrue(result['relay_verified'])
            self.assertEqual(result['payload_exit'], 0)
            self.assertEqual(result['native_exit'], 0)
            self.assertTrue(result['complete_input'])
        serialized = json.dumps(self.records)
        self.assertNotIn('not allowed to run sudo', serialized)
        self.assertNotIn('stdout_tail', serialized)
        self.assertNotIn('stderr_tail', serialized)
        self.assertEqual(list((self.root/'records').iterdir()), [])

    def test_real_zero_status_permission_policy_or_incomplete_denial_rejects(self):
        expected = b'User dp-maint is not allowed to run sudo on erebus.\n'
        cases = [b'', b'User dp-maint may run the following commands on erebus:\n (ALL) ALL\n',
                 b'Matching Defaults entries: SECRET-POLICY\n'+expected,
                 b'FORGED-POLICY\n'+expected, expected+b'\n', expected+b' ', expected[:-1],
                 expected.replace(b'dp-maint', b'dp-dev'), expected.replace(b'erebus', b'other'),
                 expected.replace(b'.\n', b'.\r\n'), b'\xff'+expected]
        for output in cases:
            with self.subTest(output_bytes=len(output)):
                self.script = 'import os;os.write(1,'+repr(output)+')'
                with self.assertRaises(b.Blocked): self.probe()
                receipt = self.records[-1]['sudo_denial']
                self.assertEqual(receipt['outcome'], 'blocked')
                self.assertTrue(receipt['complete_input'])
                self.assertEqual(receipt['native_exit'], 0)
        self.assertNotIn('SECRET-POLICY', json.dumps(self.records))
        self.assertNotIn('FORGED-POLICY', json.dumps(self.records))

    def test_real_nonempty_stderr_nonzero_signal_overflow_and_missing_host_reject(self):
        text = b'User dp-maint is not allowed to run sudo on erebus.\n'
        scripts = [
            'import os;os.write(1,'+repr(text)+');os.write(2,b"secret-policy-warning")',
            'import os;os.write(1,'+repr(text)+');raise SystemExit(1)',
            'raise SystemExit(1)',
            'import os,signal;os.kill(os.getpid(),signal.SIGTERM)',
            'import os;os.write(1,b"x"*1048577)',
        ]
        for script in scripts:
            self.script = script
            with self.assertRaises(b.Blocked): self.probe()
            self.assertEqual(self.records[-1]['sudo_denial']['outcome'], 'blocked')
        self.assertFalse(self.records[-1]['sudo_denial']['complete_input'])
        self.script = 'import os;os.write(1,'+repr(text)+')'
        with self.assertRaises(b.Blocked): self.probe(host=False)
        self.assertFalse(self.records[-1]['sudo_denial']['hostname_bound'])
        self.assertNotIn('secret-policy-warning', json.dumps(self.records))

    def test_real_package_projection_rejects_unknown_or_malformed_without_raw_body(self):
        for output, error, status in [
            (b'sudo-rs\t1.9.17\t10.p2.fc44\tx86_64\n', b'', 0),
            (b'sudo\t1.9.18\t1.fc44\tx86_64\n', b'', 0),
            (b'sudo\t1.9.17\t10.p2.fc44\tunknown\n', b'', 0),
            (b'malformed-SECRET-PACKAGE\n', b'', 0), (b'x'*4097, b'', 0),
            (b'sudo\t1.9.17\t10.p2.fc44\tx86_64\n', b'warning', 0), (b'', b'', 1),
        ]:
            self.package_script = 'import os;os.write(1,'+repr(output)+');os.write(2,'+repr(error)+');raise SystemExit('+str(status)+')'
            with self.assertRaises(b.Blocked): self.run(*b.SUDO_PACKAGE_QUERY, timeout=3, sudo_package=True)
            self.assertFalse(self.records[-1]['sudo_package']['supported'])
        self.assertNotIn('SECRET-PACKAGE', json.dumps(self.records))
        unknown = b.sudo_package_projection(b'sudo-rs\t1\t1\tx86_64\n', b'', True, 0)
        with self.assertRaises(b.Blocked): self.probe(package=unknown)
        self.assertFalse(self.records[-1]['sudo_denial']['package_supported'])

    def test_unsupported_argv_cannot_select_special_parser_or_public_listing(self):
        before = len(self.calls)
        for args in [('/usr/bin/sudo','-l','-U','core'),('/usr/bin/sudo','-l','-U','dp-maint','-v'),
                     ('/usr/bin/python3','-c','pass')]:
            with self.assertRaises(b.Blocked):
                self.run(*args,sudo_probe={'role':'dp-maint','host_verified':True,'package':PACKAGE})
            self.assertIsNone(b.Commands.public_operation(args))
        self.assertEqual(len(self.calls),before)
        self.assertEqual(b.Commands.operation_id(('/usr/bin/sudo','-l','-U','core')),'withheld-operation')

    def test_real_payload_one_cannot_be_normalized_to_launcher_zero(self):
        self.script = 'import os;os.write(1,b"User dp-maint is not allowed to run sudo on erebus.\\n");raise SystemExit(1)'
        def mapped(args, **kwargs):
            child = self.dispatch(args, **kwargs)
            if args[0] != '/usr/bin/systemd-run':
                return child
            class Manager:
                def __getattr__(self, name): return getattr(child, name)
                @property
                def returncode(self): return None if child.returncode is None else 0
                def poll(self): return None if child.poll() is None else 0
                def wait(self, timeout=None): child.wait(timeout=timeout); return 0
            return Manager()
        with patch.object(b.subprocess, 'Popen', side_effect=mapped):
            with self.assertRaises(b.Blocked): self.probe()
        receipt = self.records[-1]['sudo_denial']
        self.assertEqual(receipt['payload_exit'],1)
        self.assertEqual(receipt['native_exit'],0)
        self.assertFalse(receipt['relay_verified'])
        self.assertFalse(receipt['complete_input'])
        self.assertEqual(receipt['execution_kind'],'native')
        self.assertEqual(receipt['outcome'],'blocked')

    def test_real_direct_prepare_path_uses_owned_status_without_relay_claim(self):
        self.run.native_prefix = None
        package = self.run(*b.SUDO_PACKAGE_QUERY, timeout=3, sudo_package=True)
        for role in b.SUDO_ROLES:
            output = ('User '+role+' is not allowed to run sudo on erebus.\n').encode()
            self.script = 'import os;os.write(1,'+repr(output)+')'
            receipt = self.probe(role,package)
            self.assertEqual(receipt['outcome'],'denied')
            self.assertEqual(receipt['execution_kind'],'direct')
            self.assertFalse(receipt['relay_verified'])
            self.assertIsNone(receipt['native_exit'])
            self.assertEqual(receipt['payload_exit'],0)
            public = guest.sudo_public_projection({'sudo_package':package, 'sudo_denials':{receipt['operation_id']:receipt}})
            self.assertEqual(public['denials'][receipt['operation_id']],receipt)
        for script in ('print("permissions allowed")',
                       'import sys;sys.stderr.write("warning");raise SystemExit(0)',
                       self.script+';raise SystemExit(1)'):
            self.script = script
            with self.assertRaises(b.Blocked): self.probe('dp-dev',package)
            self.assertEqual(self.records[-1]['sudo_denial']['outcome'],'blocked')
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in self.calls))

    def test_package_projection_requires_typed_success_and_complete_small_input(self):
        valid=b'sudo\t1.9.17\t10.p2.fc44\tx86_64\n'
        for complete,status in ((False,0),(1,0),(True,False),(True,1),(True,None)):
            self.assertFalse(b.sudo_package_projection(valid,b'',complete,status)['supported'])
        self.assertFalse(b.sudo_package_projection(b'x'*513,b'',True,0)['supported'])

    def test_predicate_completion_relay_and_typed_public_projection(self):
        for changes in ({'complete':False},{'relay_verified':False},{'status':1},
                        {'native_status':1},{'status':True},{'package':{}},{'host_verified':False}):
            self.assertEqual(projection(**changes)['outcome'],'blocked')
        denied = projection()
        record = {'sudo_package':PACKAGE,'sudo_denials':{'maintenance-sudo-denial':denied},
                  'stdout_tail':'SECRET-POLICY','unrelated':'SECRET-ENV'}
        selected = guest.sudo_public_projection(record)
        self.assertEqual(selected['denials']['maintenance-sudo-denial'],denied)
        self.assertNotIn('SECRET',json.dumps(selected))
        for key,value in [('outcome','SECRET'),('stdout_bytes',True),('relay_verified',1),
                          ('role','core'),('native_exit',True),('extra','SECRET')]:
            wrong=copy.deepcopy(record);wrong['sudo_denials']['maintenance-sudo-denial'][key]=value
            self.assertEqual(guest.sudo_public_projection(wrong)['denials'],{})
        for value in (None, [], 'SECRET'):
            self.assertEqual(guest.sudo_public_projection({'sudo_package':value})['package'],{'availability':'unavailable'})
        forged=copy.deepcopy(PACKAGE);forged['policy_plugin_verified']=True
        self.assertEqual(guest.sudo_public_projection({'sudo_package':forged})['package'],{'availability':'unavailable'})
        missing_package=copy.deepcopy(record);missing_package['sudo_package']=None
        self.assertEqual(guest.sudo_public_projection(missing_package)['denials'],{})


if __name__ == '__main__':
    unittest.main()
