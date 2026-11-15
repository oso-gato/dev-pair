"""Real owned config files; system manager/UID boundary explicitly injected."""
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bootstrap as b
import native_io as n
import native_relay as r
from native_io_fixture import install, manager

UNIT = 'dev-pair-gptbox-' + 'a'*64 + '.service'
LOOKUP = n.lookup_paths
ROOT_UNIT = 'dev-pair-initialize-prepare-12345678-12345678.service'


class ProfileFiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = install(self, self.temp.name)
        self.paths = (str(self.root / 'system'),)

    def test_canonical_names_and_closed_lookup_schema(self):
        for value in (ROOT_UNIT, ROOT_UNIT[:-8], UNIT, 'dev-pair-ci-observe-'+'b'*16+'.service'):
            self.assertEqual(n.canonical_unit(value), value if value.endswith('.service') else value+'.service')
        for value in (ROOT_UNIT+'.service', '../'+UNIT, 'dev-pair-other.service', 'dev-pair-gptbox-x.service'):
            with self.assertRaises(ValueError): n.canonical_unit(value)
        class Control:
            text = 'UnitPath=/etc/systemd/system /run/systemd/system /usr/lib/systemd/system\n'
            def _call(self,*args,**kwargs): return self.text
        control=Control()
        with patch.object(n,'PROFILE_ROOT',Path('/run/systemd/system')):
            self.assertEqual(LOOKUP(control,1),tuple(control.text[9:].strip().split()))
            for text in ('UnitPath=/private/unknown\n','UnitPath=/run/systemd/system /run/systemd/system\n','UnitPath=/run/systemd/system\nOTHER=secret\n'):
                control.text=text
                with self.assertRaises(ValueError): LOOKUP(control,1)

    def test_scanner_blocks_each_applicable_override_fragment_and_dependency(self):
        baseline = n.configuration_snapshot(self.paths, UNIT)
        for name in ('service.d', 'dev-.service.d', 'dev-pair-.service.d', UNIT+'.d', UNIT+'.wants', UNIT+'.requires', UNIT+'.upholds'):
            directory = self.root/'system'/name; directory.mkdir(mode=0o755)
            marker = directory/'unknown.conf'; marker.write_text('ExecStartPre=DO-NOT-RUN')
            with self.subTest(name=name), self.assertRaises(ValueError): n.configuration_snapshot(self.paths, UNIT)
            marker.unlink(); directory.rmdir()
        fragment = self.root/'system'/UNIT; fragment.symlink_to('/dev/null')
        with self.assertRaises(ValueError): n.configuration_snapshot(self.paths, UNIT)
        fragment.unlink()
        self.assertEqual(n.configuration_snapshot(self.paths, UNIT)[0][:5], baseline[0][:5])

    def test_real_old_atime_scan_keeps_exact_security_and_mutation_evidence(self):
        transport = n.NativeTransport(UNIT); transport.setup(None)
        directory = transport.profile_path
        info = directory.stat()
        os.utime(directory, ns=(1, info.st_mtime_ns))
        before = directory.stat()
        n.configuration_snapshot(self.paths, UNIT, owned_mask=True)
        after = directory.stat()
        self.assertGreater(after.st_atime_ns, before.st_atime_ns)
        self.assertEqual(n.configuration_identity(after), n.configuration_identity(before))
        n.NativeTransport.recover(UNIT)

    def test_real_metadata_mutation_during_scan_still_blocks_including_ctime_only(self):
        transport = n.NativeTransport(UNIT); transport.setup(None)
        directory = transport.profile_path
        original = os.scandir
        from contextlib import contextmanager
        for kind in ('ctime-only', 'mtime-ns', 'mode', 'inode'):
            before = directory.stat()
            @contextmanager
            def mutate(path):
                with original(path) as entries:
                    yield entries
                if Path(path) == directory:
                    if kind == 'ctime-only':
                        directory.chmod(0o700); directory.chmod(0o755)
                    elif kind == 'mtime-ns':
                        os.utime(directory, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
                    elif kind == 'mode':
                        directory.chmod(0o700)
                    else:
                        directory.rename(directory.with_name('saved-profile'))
                        directory.mkdir(mode=0o755)
            with self.subTest(kind=kind), patch.object(n.os, 'scandir', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'Concurrent configuration mutation'):
                    n.configuration_snapshot(self.paths, UNIT, owned_mask=True)
            after = directory.stat()
            if kind == 'ctime-only':
                self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
                self.assertEqual(after.st_mode, before.st_mode)
                self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
            if kind == 'inode':
                self.assertNotEqual(before.st_ino, after.st_ino)
                directory.rmdir(); directory.with_name('saved-profile').rename(directory)
            directory.chmod(0o755)
        n.NativeTransport.recover(UNIT)

    def test_security_identity_covers_all_fields_at_nanosecond_resolution(self):
        fields = dict(st_dev=1, st_ino=2, st_mode=0o40755, st_uid=1000, st_gid=1000,
                      st_nlink=2, st_size=4096, st_mtime_ns=1000000001,
                      st_ctime_ns=1000000002, st_atime_ns=1)
        before = n.configuration_identity(types.SimpleNamespace(**fields))
        for key in fields:
            changed = dict(fields); changed[key] += 1
            with self.subTest(field=key):
                self.assertEqual(n.configuration_identity(types.SimpleNamespace(**changed)) == before,
                                 key == 'st_atime_ns')

    def test_cache_recheck_records_closed_subconditions_before_launch(self):
        original = subprocess.Popen
        for wanted in ('cache-load-state', 'cache-active-state', 'cache-snapshot-directory-mutation', 'cache-snapshot-rejected'):
            calls = []; base = manager(original, calls); count = [0]
            def manager_state(args, **kwargs):
                if args[0] == '/usr/bin/systemctl' and '--property=LoadState' in args:
                    count[0] += 1
                    if count[0] == 2 and wanted in ('cache-load-state', 'cache-active-state'):
                        state = ('LoadState=loaded\nActiveState=inactive' if wanted == 'cache-load-state'
                                 else 'LoadState=not-found\nActiveState=active')
                        return original([sys.executable, '-c', 'print(' + repr(state) + ')'], **kwargs)
                return base(args, **kwargs)
            snapshot = b.configuration_snapshot
            def scanner(*args, **kwargs):
                if kwargs.get('owned_mask') and wanted.startswith('cache-snapshot'):
                    raise ValueError('Concurrent configuration mutation' if wanted.endswith('directory-mutation')
                                     else 'SECRET-SENTINEL-UNKNOWN-ERROR')
                return snapshot(*args, **kwargs)
            records = []; run = b.Commands(); run.metadata_diagnostic = records.append
            with patch.object(b.subprocess, 'Popen', side_effect=manager_state), \
                 patch.object(b, 'configuration_snapshot', side_effect=scanner), self.assertRaises(b.Blocked):
                run('/usr/bin/systemd-run', '--unit=' + UNIT, '--description=dev-pair-owned-' + UNIT,
                    '--property=RuntimeMaxSec=3', sys.executable, '-c', 'raise AssertionError("never")')
            self.assertFalse(any(args[0] == '/usr/bin/systemd-run' for args in calls))
            self.assertEqual(records[-1]['admission_stage'], 'cache-recheck')
            self.assertEqual(records[-1]['admission_reason'], wanted)
            self.assertNotIn('SECRET-SENTINEL', json.dumps(records))
            self.assertFalse(records[-1]['accepted_exit'])

    def test_owned_mask_creation_tamper_and_partial_cleanup(self):
        transport = n.NativeTransport(UNIT); transport.setup(b'NONCREDENTIAL')
        mask = transport.profile_path/n.MASK
        self.assertEqual(mask.read_bytes(), b'')
        self.assertEqual(mask.stat().st_mode & 0o777, 0o644)
        self.assertEqual(transport.profile_path.stat().st_mode & 0o777, 0o755)
        self.assertGreater(transport.state['profile']['after_us'], transport.state['profile']['before_us'])
        n.configuration_snapshot(self.paths, UNIT, owned_mask=True)
        mask.write_bytes(b'changed')
        with self.assertRaises(ValueError): n.NativeTransport.recover(UNIT)
        self.assertEqual(mask.read_bytes(), b'changed')
        mask.write_bytes(b'')
        extra = transport.profile_path/'unknown'; extra.write_text('preserved')
        with self.assertRaises(ValueError): n.NativeTransport.recover(UNIT)
        self.assertTrue(extra.exists()); extra.unlink()
        original = os.unlink
        def interrupted(path, *args, **kwargs):
            if path == n.MASK: raise OSError('fixture mask cleanup failure')
            return original(path, *args, **kwargs)
        with patch.object(n.os, 'unlink', side_effect=interrupted), self.assertRaises(OSError): n.NativeTransport.recover(UNIT)
        self.assertTrue(json.loads(transport.record.read_text())['cleanup_started'])
        n.NativeTransport.recover(UNIT)
        self.assertFalse(mask.exists()); self.assertFalse(transport.record.exists())

    def test_creation_gap_and_old_journal_do_not_own_unknown_mask(self):
        transport = n.NativeTransport(UNIT)
        original = transport.save
        def fail(first=False):
            if transport.state['profile']['directory'] is not None: raise OSError('fixture gap')
            return original(first)
        with patch.object(transport, 'save', side_effect=fail), self.assertRaises(OSError): transport.setup(None)
        with self.assertRaises(ValueError): n.NativeTransport.recover(UNIT)
        self.assertTrue(transport.profile_path.exists())
        # Remove only this test's proven fixture directory and initial intent.
        transport.profile_path.rmdir(); transport.record.unlink()
        transport = n.NativeTransport(UNIT); transport.setup(None)
        state = json.loads(transport.record.read_text()); state['version']=2; del state['profile']
        transport.record.write_text(json.dumps(state))
        with self.assertRaises(ValueError): n.NativeTransport.recover(UNIT)
        self.assertTrue((transport.profile_path/n.MASK).exists())
        (transport.profile_path/n.MASK).unlink(); transport.profile_path.rmdir()
        n.NativeTransport.recover(UNIT)
        self.assertFalse(transport.record.exists())

    def test_unrecorded_stream_deletion_does_not_gain_cleanup_authority(self):
        transport = n.NativeTransport(UNIT); transport.setup(None)
        (transport.path/'stdout').unlink()
        with self.assertRaises(ValueError): n.NativeTransport.recover(UNIT)
        self.assertFalse(json.loads(transport.record.read_text())['cleanup_started'])
        self.assertTrue(transport.profile_path.exists())

    def test_cache_sequence_and_unknown_hook_blocks_before_any_unit_launch(self):
        original = subprocess.Popen; calls=[]
        with patch.object(b.subprocess, 'Popen', side_effect=manager(original,calls)):
            self.assertEqual(b.Commands()('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3',sys.executable,'-c','print("ok")'), 'ok\n')
        starts=[i for i,args in enumerate(calls) if args[0]=='/usr/bin/systemd-run']
        observations=[i for i,args in enumerate(calls) if args[0]=='/usr/bin/systemctl' and '--property=LoadState' in args]
        self.assertGreaterEqual(len([i for i in observations if i<starts[0]]),2)
        self.assertFalse(any('daemon-reload' in args for args in calls))
        directory=self.root/'system'/'dev-pair-.service.d';directory.mkdir(mode=0o755)
        (directory/'evil.conf').write_text('ExecStartPre=marker')
        calls.clear();records=[];run=b.Commands();run.metadata_diagnostic=records.append
        with patch.object(b.subprocess, 'Popen', side_effect=manager(original,calls)), self.assertRaises(b.Blocked):
            run('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3',sys.executable,'-c','pass')
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in calls))
        self.assertEqual(records[-1]['admission_stage'],'configuration-scan')

    def test_real_sigkill_profile_allocation_boundaries(self):
        # Only the process-local root/system manager boundary is injected.
        code = ("import os,sys,time;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import native_io as n;"
                "n.ROOT=Path(sys.argv[2]);n.STREAM_ROOT=n.ROOT/'streams';n.PROFILE_ROOT=n.ROOT/'system';"
                "n.guard_root=lambda:None;n.protected_directory=lambda p:Path(p);t=n.NativeTransport(sys.argv[3]);mode=sys.argv[4];"
                "original=t.save;profile=t.create_profile\n"
                "def save(first=False):\n"
                " if (mode=='intent' and first) or (mode=='file-unproven' and t.state['profile']['file'] is not None and t.state['directory'] is None):\n"
                "  if mode=='intent':original(first)\n"
                "  print('ready',flush=True);time.sleep(10)\n"
                " return original(first)\n"
                "def create():\n"
                " profile();print('ready',flush=True);time.sleep(10)\n"
                "t.save=save\n"
                "if mode=='profile-proven':t.create_profile=create\n"
                "t.setup(None)\n")
        for mode in ('intent','file-unproven','profile-proven'):
            process=subprocess.Popen([sys.executable,'-c',code,str(Path(n.__file__).parent),str(self.root),UNIT,mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            import selectors
            selected=selectors.DefaultSelector();selected.register(process.stdout,selectors.EVENT_READ)
            try:
                self.assertTrue(selected.select(2));self.assertEqual(process.stdout.readline(),b'ready\n')
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
                target=n.NativeTransport(UNIT)
                if mode=='file-unproven':
                    with self.assertRaises(ValueError):n.NativeTransport.recover(UNIT)
                    self.assertTrue((target.profile_path/n.MASK).exists())
                    (target.profile_path/n.MASK).unlink();target.profile_path.rmdir();target.record.unlink()
                else:
                    n.NativeTransport.recover(UNIT)
                    self.assertFalse(target.record.exists());self.assertFalse(target.profile_path.exists())
            finally:
                selected.close()
                if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
                process.stdout.close();process.stderr.close()

    def test_successful_payload_cannot_pass_failed_profile_cleanup(self):
        original=subprocess.Popen;calls=[];records=[];run=b.Commands();run.metadata_diagnostic=records.append
        with patch.object(b.subprocess,'Popen',side_effect=manager(original,calls)),patch.object(n.NativeTransport,'cleanup_profile',side_effect=OSError('fixture cleanup failure')),self.assertRaises(b.Blocked):
            run('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3',sys.executable,'-c','print("ok")')
        self.assertFalse(records[-1]['accepted_exit']);self.assertTrue(records[-1]['relay_verified'])
        self.assertTrue(n.NativeTransport(UNIT).record.exists())
        n.NativeTransport.recover(UNIT)

    def test_concurrent_configuration_change_and_loaded_unit_block_before_start(self):
        original=subprocess.Popen;calls=[];base=manager(original,calls);count=[0]
        def mutate(args,**kwargs):
            if args[0]=='/usr/bin/systemctl' and '--property=LoadState' in args:
                count[0]+=1
                if count[0]==2:
                    directory=self.root/'system'/'dev-pair-.service.d';directory.mkdir(mode=0o755)
                    (directory/'unknown.conf').write_text('ExecStartPre=DO-NOT-RUN')
            return base(args,**kwargs)
        with patch.object(b.subprocess,'Popen',side_effect=mutate),self.assertRaises(b.Blocked):
            b.Commands()('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3',sys.executable,'-c','pass')
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in calls))
        directory=self.root/'system'/'dev-pair-.service.d';(directory/'unknown.conf').unlink();directory.rmdir()
        def loaded(args,**kwargs):
            if args[0]=='/usr/bin/systemctl':
                return original([sys.executable,'-c','print("LoadState=loaded\\nActiveState=inactive")'],**kwargs)
            return base(args,**kwargs)
        calls.clear()
        with patch.object(b.subprocess,'Popen',side_effect=loaded),self.assertRaises(b.Blocked):
            b.Commands()('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3',sys.executable,'-c','pass')
        self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in calls))

    def test_cgroup_population_is_checked_before_profile_deletion(self):
        group=self.root/'cgroups';group.mkdir();leaf=group/UNIT;leaf.mkdir();events=leaf/'cgroup.events'
        with patch.object(n,'CGROUP_ROOT',group):
            events.write_text('populated 1\nfrozen 0\n')
            with self.assertRaises(ValueError):n.verify_inactive_cgroup(UNIT)
            events.write_text('populated 0\nfrozen 0\n');n.verify_inactive_cgroup(UNIT)
            events.write_text('populated 0\npopulated 0\n')
            with self.assertRaises(ValueError):n.verify_inactive_cgroup(UNIT)

    def test_ambiguous_mtime_blocks_launch_but_proven_directory_can_be_reclaimed(self):
        original=Path.lstat
        def same_time(path):
            info=original(path)
            if path==n.PROFILE_ROOT:
                return types.SimpleNamespace(**{key:getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_nlink')},st_mtime_ns=0)
            return info
        transport=n.NativeTransport(UNIT)
        with patch.object(Path,'lstat',same_time):
            with self.assertRaisesRegex(ValueError,'timestamp did not advance'):transport.setup(None)
            self.assertTrue(transport.profile_path.exists())
            n.NativeTransport.recover(UNIT)
            self.assertFalse(transport.record.exists());self.assertFalse(transport.profile_path.exists())

    def test_profile_symlink_hardlink_modes_and_foreign_next_are_preserved(self):
        transport=n.NativeTransport(UNIT);transport.setup(None)
        mask=transport.profile_path/n.MASK
        mask.chmod(0o666)
        with self.assertRaises(ValueError):n.NativeTransport.recover(UNIT)
        mask.chmod(0o644)
        link=self.root/'linked';os.link(mask,link)
        with self.assertRaises(ValueError):n.NativeTransport.recover(UNIT)
        link.unlink();mask.unlink();mask.symlink_to('/dev/null')
        with self.assertRaises(ValueError):n.NativeTransport.recover(UNIT)
        self.assertTrue(mask.is_symlink())
        # The fixture owns the tampered objects; restore only for fixture cleanup.
        mask.unlink();transport.profile_path.rmdir();transport.path.joinpath('stdout').unlink();transport.path.joinpath('stderr').unlink();transport.path.rmdir();transport.record.unlink()
        next_file=transport.record.with_suffix('.next');next_file.write_text('foreign')
        with self.assertRaises(ValueError):n.NativeTransport(UNIT).setup(None)
        with self.assertRaises(ValueError):n.NativeTransport.recover(UNIT)
        self.assertEqual(next_file.read_text(),'foreign')

    def test_native_prefix_is_closed_and_payload_options_cannot_change_unit_owner(self):
        original=subprocess.Popen;calls=[];base=manager(original,calls)
        prefix=('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3')
        with patch.object(b.subprocess,'Popen',side_effect=base):
            result=b.Commands()(*prefix,sys.executable,'-c','import sys;print(sys.argv[1])','--uid=nobody')
            self.assertEqual(result,'--uid=nobody\n')
            for extra in ('--unit='+UNIT,'--property=ExecStartPre=/forbidden','--setenv=SECRET=not-a-real-secret','--service-type=notify'):
                before=len(calls)
                with self.assertRaises(b.Blocked):b.Commands()(*prefix,extra,sys.executable,'-c','pass')
                self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in calls[before:]))

    def test_profile_failure_survives_probe_and_observation_diagnostic_projection(self):
        import gptbox as g
        import fedora_ci_guest as guest
        original=subprocess.Popen;calls=[]
        def gate_process(argv,**kwargs):
            argv=list(argv)
            if len(argv)>2 and argv[1]=='-c' and 'r.verify_profile=lambda args:None;' in argv[2]:
                argv[2]=argv[2].replace('r.verify_profile=lambda args:None;','r.verify_profile=lambda args:(_ for _ in ()).throw(r.ProfileError("RuntimeMaxUSec","missing"));')
            return original(argv,**kwargs)
        app=g.Gptbox(Path(self.temp.name),g.ProbeCommands())
        app.target=g.ROOT+'/'+'a'*64;app.directory(app.target,mode=0o700)
        app.executor=['/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=3']
        with patch.object(b.subprocess,'Popen',side_effect=manager(gate_process,calls)),self.assertRaises(b.Blocked):
            app.execute(sys.executable,'-c','print("must not run")')
        evidence=guest.public_diagnostics(app.path(b.STATE),{'context_sha256':'a'*64})
        self.assertEqual(evidence['adapter']['records'][-1]['relay_failure']['property'],'RuntimeMaxUSec')
        self.assertIn('elapsed_seconds',evidence['adapter']['records'][-1])
        self.assertFalse(evidence['adapter']['records'][-1]['accepted_exit'])
        self.assertIsNone(app.run.metadata_diagnostic)
        observe='dev-pair-ci-observe-'+'b'*16+'.service'
        argv=('/usr/bin/systemd-run','--unit='+observe,'--description=dev-pair-owned-'+observe,'--property=RuntimeMaxSec=3','--property=TimeoutStopSec=1',sys.executable,'-c','pass')
        with patch.object(b.subprocess,'Popen',side_effect=manager(gate_process,calls)),self.assertRaisesRegex(ValueError,'property=RuntimeMaxUSec observed=missing'):
            guest.native_image_capture(Path(__file__).resolve().parents[1],argv,3)


class EffectiveProfile(unittest.TestCase):
    def args(self, family='root'):
        unit=ROOT_UNIT if family=='root' else (UNIT if family=='maintenance' else 'dev-pair-ci-observe-'+'b'*16+'.service')
        return types.SimpleNamespace(unit=unit,key=unit,profile=family,uid=0 if family=='root' else 1000,stdin=1,start_us=1000000,runtime_us=5000000,deadline=time.monotonic()+3)

    def rows(self,args):
        rows=r.expected_profile(args)
        rows.update(User='root' if args.uid==0 else 'dp-maint',Group='root' if args.uid==0 else 'dp-maint')
        return rows

    def proc(self,args):
        def opened(path,*a,**kw):
            if path=='/proc/self/status': return io.StringIO('Uid:\t'+('\t'.join([str(args.uid)]*4))+'\nGid:\t'+('\t'.join([str(args.uid)]*4))+'\n')
            if path=='/proc/self/cgroup': return io.StringIO('0::/system.slice/'+args.unit+'\n')
            raise AssertionError('unexpected proc path')
        return opened

    def test_effective_all_families_and_each_property_mutation(self):
        for family in ('root','maintenance','observation'):
            args=self.args(family);rows=self.rows(args)
            with patch.object(r,'profile_query',return_value=rows),patch('builtins.open',side_effect=self.proc(args)),patch('pwd.getpwuid',return_value=types.SimpleNamespace(pw_gid=args.uid)):
                r.verify_profile(args)
            for key in r.PROFILE_PROPERTIES:
                altered=dict(rows);altered[key]='unexpected-secret-sentinel'
                with self.subTest(family=family,key=key),patch.object(r,'profile_query',return_value=altered),patch('builtins.open',side_effect=self.proc(args)),patch('pwd.getpwuid',return_value=types.SimpleNamespace(pw_gid=args.uid)),self.assertRaises(r.ProfileError) as caught:
                    r.verify_profile(args)
                self.assertNotIn('secret-sentinel',str(caught.exception.value))
                self.assertEqual(caught.exception.key,key)

    def test_proc_identity_cgroup_and_duration_are_strict(self):
        args=self.args();rows=self.rows(args)
        for status in ('Uid:\t0\t1\t0\t0\nGid:\t0\t0\t0\t0\n','Uid:\t0\t0\t0\t0\nGid:\t0\t1\t0\t0\n'):
            with patch.object(r,'profile_query',return_value=rows),patch('builtins.open',return_value=io.StringIO(status)),self.assertRaises(r.ProfileError):r.verify_profile(args)
        proper=self.proc(args)
        def wrong_group(path,*a,**kw):
            return io.StringIO('0::/system.slice/foreign.service\n') if path=='/proc/self/cgroup' else proper(path,*a,**kw)
        with patch.object(r,'profile_query',return_value=rows),patch('builtins.open',side_effect=wrong_group),self.assertRaises(r.ProfileError) as caught:
            r.verify_profile(args)
        self.assertEqual(caught.exception.key,'ProcCgroup')
        self.assertEqual(r.typed_record(b'{"type":"t","data":62001000}', 't', 'RuntimeMaxUSec'), 62001000)
        with self.assertRaises(r.ProfileError):
            r.typed_record(b'{"type":"t","data":false}', 't', 'RuntimeMaxUSec')

    def test_real_bounded_selected_query_rejects_duplicates_excess_and_deadline(self):
        args=self.args();rows=self.rows(args)
        original=subprocess.Popen;observed=[]
        def spawned(argv,**kwargs):
            observed.append(argv)
            if 'GetUnit' in argv:text=json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/test']})
            else:
                schema=r.UNIT_SCHEMA if 'org.freedesktop.systemd1.Unit' in argv else r.SERVICE_SCHEMA
                text=''.join(json.dumps({'type':signature,'data':rows[key]})+'\n' for key,signature in schema)
            return original([sys.executable,'-c','import sys;sys.stdout.write(sys.argv[1])',text],**kwargs)
        with patch.object(r.subprocess,'Popen',side_effect=spawned):
            self.assertEqual(r.profile_query(args.unit,time.monotonic()+2),rows)
        self.assertEqual(len(observed),3)
        self.assertTrue(all(argv[0]=='/usr/bin/busctl' for argv in observed))
        self.assertFalse(any('Environment' in value or 'ExecStart' in value or 'GetAll' in value for argv in observed for value in argv))

    def test_gate_rejection_precedes_input_and_payload_with_bounded_failure_frame(self):
        from test_native_relay import CODE,HELPER,SHA
        code=CODE.replace('r.verify_profile=lambda args:None;', 'r.verify_profile=lambda args:(_ for _ in ()).throw(r.ProfileError("MemoryMax",2147483649));')
        args=[sys.executable,'-c',code,str(HELPER.parent),'--unit',ROOT_UNIT,'--key',ROOT_UNIT,'--profile','root','--start-us','1000000','--runtime-us','1000000',
              '--stdout-node','0:1','--stderr-node','0:2','--uid','0','--stdin','1','--maximum','262144','--deadline',str(time.monotonic()+2),'--helper',SHA,'--',sys.executable,'-c','print("must not run")']
        result=subprocess.run(args,input=b'NONCREDENTIAL-sentinel',capture_output=True,timeout=3)
        self.assertEqual(result.returncode,250);self.assertEqual(result.stdout,b'')
        self.assertLessEqual(len(result.stderr),256);self.assertNotIn(b'NONCREDENTIAL',result.stderr)
        decoder=r.Decoder(262144);decoder.feed(result.stderr)
        self.assertEqual(decoder.failure['property'],'MemoryMax');self.assertEqual(decoder.failure['observed'],2147483649)
        for accepted in (0,1,4,250):
            with self.assertRaises(ValueError):decoder.finish(accepted,0,SHA)
        for property_name,observed in ((['Environment'],'secret'),('Environment','secret'),('MemoryMax',{'secret':'value'}),('MemoryMax','secret-value')):
            body=json.dumps({'v':1,'done':False,'stage':'effective-profile','reason':'rejected','property':property_name,'observed':observed}).encode()
            with self.assertRaises(ValueError):r.Decoder(262144).feed(r.HEADER.pack(b'F',r.MAGIC,len(body))+body)
