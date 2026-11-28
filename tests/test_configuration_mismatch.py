"""Already-captured snapshot diagnostics never rescan or relax admission."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_io as n
import bootstrap as b
import native_relay as r
import fedora_ci_guest as guest
from native_io_fixture import install,manager

UNIT='dev-pair-gptbox-'+'a'*64+'.service'
ROW=('/etc/systemd/system',1,2,0o40755,0,12345)


class ConfigurationMismatch(unittest.TestCase):
    def test_equal_fields_add_remove_presence_and_order_are_precise(self):
        self.assertEqual(len({p.replace('/lib/systemd/','/usr/lib/systemd/',1) if p.startswith('/lib/systemd/') else p for p in n.LOOKUP_PATHS}),12)
        before=(ROW,('/usr/lib/systemd/system',3,4,0o40755,0,67890))
        self.assertIsNone(n.configuration_mismatch(before,before,UNIT))
        for index,bit in ((1,1),(2,2),(3,3),(4,4),(5,5)):
            changed=list(ROW);changed[index]+=1
            result=n.configuration_mismatch(before,(tuple(changed),before[1]),UNIT)
            self.assertEqual(result['changed_fields'],1<<bit);self.assertFalse(result['order_only_equal'])
            self.assertEqual(result['path_class'],'lookup-directory');self.assertEqual(result['row_index'],0)
        for after in ((ROW,),before+(('/run/systemd/system',5,6,0o40755,0,7),),((ROW[0],None),before[1])):
            result=n.configuration_mismatch(before,after,UNIT)
            self.assertEqual(result['changed_fields'],1);self.assertFalse(result['order_only_equal'])
        result=n.configuration_mismatch(before,tuple(reversed(before)),UNIT)
        self.assertTrue(result['order_only_equal']);self.assertEqual(result['changed_fields'],0)
        self.assertEqual(result['rows'],[2,2]);self.assertEqual(result['row_index'],0)
        own=('/run/systemd/system/'+UNIT+'.d/'+n.MASK,1,2,0o100644,0,0,12345)
        changed=list(own);changed[5]=1
        result=n.configuration_mismatch((own,),(tuple(changed),),UNIT)
        self.assertEqual(result['path_class'],'owned-mask');self.assertEqual(result['changed_fields'],64)
        global_row=('/usr/lib/systemd/system/service.d/'+n.MASK,*own[1:])
        self.assertEqual(n.configuration_mismatch((global_row,),(),UNIT)['path_class'],'global-mask')

    def test_unknown_malformed_and_bound_overflow_are_unavailable_without_values(self):
        for before in ((('/SECRET_PRIVATE',1,2,3,4,5),),((ROW[0],True,2,3,4,5),),((ROW[0],None,3),),
                       (ROW,)*1025,([*ROW],),((ROW[0],10**100,2,3,4,5),)):
            result=n.configuration_mismatch(before,(),UNIT)
            self.assertEqual(result,{'availability':'unavailable'});self.assertNotIn('SECRET',json.dumps(result))

    def test_canonical_alias_rows_cancel_balanced_evidence_before_pairing(self):
        a=('/usr/lib/systemd/system',1,2,0o40755,0,12345)
        b=(*a[:-1],12346);c=(a[0],1,3,0o40755,0,12347)
        root=('/run/systemd/system',1,4,0o40755,0,12345)
        for before,after in [((b,a,root),(b,c,root)),((a,b,root),(c,b,root)),
                ((b,b,a,root),(b,c,b,root)),((a,a,b),(a,c,b))]:
            result=n.configuration_mismatch(before,after,UNIT)
            self.assertEqual(result['availability'],'observed');self.assertEqual(result['changed_fields'],36)
            self.assertEqual(result['row_index'],before.index(a));self.assertFalse(result['order_only_equal'])
            self.assertNotIn('/usr',json.dumps(result))
        self.assertEqual(n.configuration_mismatch((b,a),(b,),UNIT)['changed_fields'],1)
        self.assertTrue(n.configuration_mismatch((b,a),(a,b),UNIT)['order_only_equal'])
        d=(*a[:-1],12348);e=(*c[:-1],12349)
        for before,after in [((a,d),(c,e)),((a,),(c,e)),((a,d),(c,)),((a,a),(c,))]:
            self.assertEqual(n.configuration_mismatch(before,after,UNIT),{'availability':'unavailable'})

    def test_real_controller_rejects_same_third_snapshot_change_before_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=install(self,temp);calls=[];original=b.configuration_snapshot;scans=[]
            def changed(*args,**kwargs):
                value=original(*args,**kwargs);scans.append(value)
                if len(scans)==3:
                    row=list(value[0]);row[5]+=1;return (tuple(row),*value[1:])
                return value
            def project(before,after,unit):
                # Only the known manager-path fixture is mapped to its production
                # spelling; real descriptors/snapshots/controller cleanup remain.
                def mapped(rows):
                    return tuple(('/run/systemd/system'+row[0].removeprefix(str(root/'system')),*row[1:]) for row in rows)
                return n.configuration_mismatch(mapped(before),mapped(after),unit)
            records=[];run=b.Commands();run.metadata_diagnostic=records.append
            with patch.object(b.subprocess,'Popen',side_effect=manager(subprocess.Popen,calls)),\
                    patch.object(b,'configuration_snapshot',side_effect=changed),patch.object(b,'configuration_mismatch',side_effect=project):
                with self.assertRaisesRegex(b.Blocked,'configuration changed before native launch'):
                    run('/usr/bin/systemd-run','--unit='+UNIT,'--description=dev-pair-owned-'+UNIT,'--property=RuntimeMaxSec=5',sys.executable,'-c','raise AssertionError("never")')
            self.assertEqual(len(scans),3);self.assertFalse(any(args[0]=='/usr/bin/systemd-run' for args in calls))
            record=records[-1];self.assertEqual(record['admission_reason'],'cache-final-comparison')
            self.assertFalse(record['native_failure']['launcher_handle_observed'])
            witness=record['native_failure']['cache_comparison'];self.assertEqual(witness['availability'],'observed')
            self.assertEqual(witness['changed_fields'],32);self.assertFalse(record['accepted_exit'])
            self.assertEqual(list((root/'records').iterdir()),[])
            expected={'source_sha':'1'*40,'context_sha256':'a'*64}
            record['diagnostic_identity']={**expected,'phase':'prepare'}
            public=guest.native_failure_projection(record,expected,'prepare')
            self.assertEqual(public['availability'],'observed');self.assertLess(len(json.dumps(public)),1536)
            for key,bad in [('path_class','SECRET'),('lookup_index',12),('row_index',True),('changed_fields',128),('rows',[True,1])]:
                changed_record=copy.deepcopy(record);changed_record['native_failure']['cache_comparison'][key]=bad
                self.assertEqual(guest.native_failure_projection(changed_record,expected,'prepare'),{'availability':'unavailable'})
            changed_record=copy.deepcopy(record);changed_record['admission_reason']='other'
            self.assertEqual(guest.native_failure_projection(changed_record,expected,'prepare'),{'availability':'unavailable'})


if __name__=='__main__':unittest.main()
