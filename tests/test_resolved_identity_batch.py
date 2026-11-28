"""Bracketed identity reads over one historical inventory; no Fedora claim."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_bootstrap as fixture
b=fixture.b

class ResolvedBatchTests(unittest.TestCase):
    setUp=fixture.BootstrapTests.setUp
    stock_resolved=fixture.BootstrapTests.stock_resolved
    def identity_calls(self):
        return [a for a in self.fake.calls if a[:2]==('/usr/bin/systemctl','show') and a[-1]=='systemd-resolved.service' or a[:3]==('/usr/bin/getent','passwd','systemd-resolve')]
    def test_four_captured_rows_bracket_with_four_queries_and_each_call_fresh(self):
        self.stock_resolved()
        self.assertEqual(sum(':5355' in x for x in self.inventory.splitlines()),4)
        for attempt in range(2):
            before=len(self.identity_calls());self.app.preflight()
            self.assertEqual(len(self.identity_calls())-before,4)
        other=fixture.BootstrapTests();other.setUp();self.addCleanup(other.doCleanups);other.stock_resolved()
        other.app.preflight()
        self.assertEqual(len([a for a in other.fake.calls if a[:3]==('/usr/bin/getent','passwd','systemd-resolve')]),2)
    def test_zero_one_two_keep_old_query_counts_and_prepared_rejects_discovery(self):
        self.stock_resolved();lines=self.inventory.splitlines();normal=[x for x in lines if ':5355' not in x];discovery=[x for x in lines if ':5355' in x]
        for count in range(3):
            self.inventory='\n'.join(normal+discovery[:count]);before=len(self.identity_calls());self.app.preflight()
            self.assertEqual(len(self.identity_calls())-before,2*count)
        self.inventory='\n'.join(lines);self.app.state.mkdir(parents=True,exist_ok=True);self.app.path(b.STATE+'/prepared').write_text('yes')
        with self.assertRaises(b.Blocked):self.app.preflight()
    def test_each_original_owner_predicate_still_required(self):
        self.stock_resolved();original=self.inventory
        for replacement in ('"foreign",pid=767','"systemd-resolve",pid=999','"systemd-resolve",pid=767,fd=9),("other",pid=767'):
            lines=original.splitlines();index=next(i for i,line in enumerate(lines) if ':5355' in line)
            lines[index]=lines[index].replace('"systemd-resolve",pid=767',replacement,1);self.inventory='\n'.join(lines)
            with self.assertRaises(b.Blocked):self.app.preflight()
    def test_complete_service_process_and_protected_executable_failures_block(self):
        self.stock_resolved();state=self.resolved_state;account=self.fake.accounts['systemd-resolve']
        for bad in (state.replace('active','inactive'),state.replace('loaded','not-found'),state+'MainPID=767\n',state.replace('User=systemd-resolve','User=root'),state.replace('MainPID=767','MainPID=1')):
            self.resolved_state=bad
            with self.assertRaises(b.Blocked):self.app.preflight()
        self.resolved_state=state
        for uid in ('0','999'):
            self.fake.accounts['systemd-resolve']=account.replace(':193:',':'+uid+':',1)
            with self.assertRaises(b.Blocked):self.app.preflight()
        self.fake.accounts['systemd-resolve']=account
        binary=self.app.path('/usr/lib/systemd/systemd-resolved');binary.chmod(0o666)
        with self.assertRaises(b.Blocked):self.app.preflight()
        binary.chmod(0o644);binary.unlink()
        with self.assertRaises(b.Blocked):self.app.preflight()
    def test_mutations_between_snapshots_reject_pid_start_uid_inode_and_cgroup(self):
        self.stock_resolved();original=self.app.resolved_service
        stat=self.app.path('/proc/767/stat');status=self.app.path('/proc/767/status');group=self.app.path('/proc/767/cgroup');binary=self.app.path('/usr/lib/systemd/systemd-resolved')
        initial=[p.read_bytes() for p in (stat,status,group,binary)];account=self.fake.accounts['systemd-resolve']
        for mutation in ('start','uid','inode','cgroup','missing','malformed'):
            for p,data in zip((stat,status,group,binary),initial):p.write_bytes(data)
            self.fake.accounts['systemd-resolve']=account;calls=[]
            def checked(*,snapshot=False):
                calls.append(snapshot)
                if len(calls)==2:
                    if mutation=='start':stat.write_text('767 (same pid) S '+'0 '*18+'12346 0\n')
                    elif mutation=='uid':
                        status.write_text('Uid:\t194\t194\t194\t194\n');self.fake.accounts['systemd-resolve']=account.replace(':193:',':194:',1)
                    elif mutation=='inode':binary.unlink();binary.write_text('replacement inode')
                    elif mutation=='cgroup':group.write_text('0::/foreign.service\n')
                    elif mutation=='missing':stat.unlink()
                    else:stat.write_text('767 (bad) S truncated')
                return original(snapshot=snapshot)
            with patch.object(self.app,'resolved_service',side_effect=checked),self.assertRaises(b.Blocked):self.app.preflight()
            self.assertEqual(calls,[True,True])
    def test_start_changes_inside_one_snapshot_and_bounded_stat_reject(self):
        self.stock_resolved();original=self.app.resolved_process_start;count=[]
        def changed(pid):
            count.append(pid);return original(pid)+(len(count)>1)
        with patch.object(self.app,'resolved_process_start',side_effect=changed),self.assertRaises(b.Blocked):self.app.preflight()
        self.app.path('/proc/767/stat').write_text('x'*4097)
        with self.assertRaises(b.Blocked):self.app.preflight()

if __name__=='__main__':unittest.main()
