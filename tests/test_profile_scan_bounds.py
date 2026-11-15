"""Streaming directory bounds use real filesystem entries and observed iterators."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_io as n
from native_io_fixture import install

UNIT='dev-pair-gptbox-'+'a'*64+'.service'


class Observed:
    def __init__(self,iterator,delay=0):
        self.iterator=iterator;self.consumed=0;self.closed=False;self.delay=delay
    def __enter__(self):
        self.iterator.__enter__();return self
    def __exit__(self,*args):
        self.closed=True;return self.iterator.__exit__(*args)
    def __iter__(self):return self
    def __next__(self):
        entry=next(self.iterator);self.consumed+=1
        if self.delay:time.sleep(self.delay)
        return entry


class StreamingScans(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=install(self,self.temp.name)
        self.paths=(str(self.root/'system'),)

    def watch(self,target,delay=0):
        original=os.scandir;observations=[]
        def scan(path):
            result=original(path)
            if not isinstance(path,int) and Path(path)==target:
                result=Observed(result,delay);observations.append(result)
            return result
        return patch.object(n.os,'scandir',side_effect=scan),observations

    def populate(self,directory,count=20000):
        for index in range(count):
            descriptor=os.open(directory/('foreign-%05d.conf'%index),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.close(descriptor)

    def test_real_twenty_thousand_config_files_stop_on_first_unknown_and_close(self):
        directory=self.root/'system'/'service.d';directory.mkdir(mode=0o755)
        self.populate(directory)
        observed,records=self.watch(directory)
        with observed,self.assertRaisesRegex(ValueError,'Unknown applicable drop-in'):
            n.configuration_snapshot(self.paths,UNIT)
        self.assertEqual(len(records),1);self.assertEqual(records[0].consumed,1);self.assertTrue(records[0].closed)
        self.assertTrue((directory/'foreign-19999.conf').exists())

    def test_real_mask_foreign_entries_stop_immediately_without_changing_journal(self):
        transport=n.NativeTransport(UNIT);transport.setup(None)
        self.populate(transport.profile_path)
        before=transport.record.read_bytes()
        observed,records=self.watch(transport.profile_path)
        with observed,self.assertRaisesRegex(ValueError,'Foreign profile entry'):
            n.NativeTransport.recover(UNIT)
        self.assertEqual(len(records),1);self.assertLessEqual(records[0].consumed,2);self.assertTrue(records[0].closed)
        self.assertEqual(transport.record.read_bytes(),before)
        self.assertTrue((transport.profile_path/'foreign-19999.conf').exists())
        self.assertTrue((transport.profile_path/n.MASK).exists())

    def test_real_stream_foreign_entries_stop_immediately_without_changing_journal(self):
        transport=n.NativeTransport(UNIT);transport.setup(None)
        self.populate(transport.path)
        before=transport.record.read_bytes()
        observed,records=self.watch(transport.path)
        with observed,self.assertRaisesRegex(ValueError,'Unknown or unproven transport entry'):
            n.NativeTransport.recover(UNIT)
        self.assertEqual(len(records),1);self.assertLessEqual(records[0].consumed,3);self.assertTrue(records[0].closed)
        self.assertEqual(transport.record.read_bytes(),before)
        self.assertTrue((transport.path/'foreign-19999.conf').exists())
        self.assertTrue((transport.profile_path/n.MASK).exists())

    def test_configuration_deadline_is_checked_while_consuming_and_iterator_closes(self):
        directory=self.root/'system'/'service.d';directory.mkdir(mode=0o755)
        self.populate(directory,3)
        observed,records=self.watch(directory,delay=.1)
        with observed,self.assertRaisesRegex(ValueError,'deadline exceeded'):
            n.configuration_snapshot(self.paths,UNIT,end=time.monotonic()+.05)
        self.assertEqual(records[0].consumed,1);self.assertTrue(records[0].closed)
        self.assertTrue((directory/'foreign-00000.conf').exists())

    def test_count_and_name_bytes_are_checked_without_exhausting_iterator(self):
        transport=n.NativeTransport(UNIT);transport.setup(None)
        original=os.scandir
        with original(transport.profile_path) as entries:entry=next(entries)
        class Repeated:
            consumed=0;closed=False
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def __iter__(self):return self
            def __next__(self):
                self.consumed+=1
                if self.consumed>1000:raise AssertionError('iterator was eagerly exhausted')
                return entry
        repeated=Repeated()
        def scan(path):return repeated if Path(path)==transport.profile_path else original(path)
        with patch.object(n.os,'scandir',side_effect=scan),self.assertRaisesRegex(ValueError,'inventory bound exceeded'):
            n.configuration_snapshot(self.paths,UNIT,owned_mask=True)
        self.assertEqual(repeated.consumed,257);self.assertTrue(repeated.closed)
        class HugeName:
            name='x'*16385
        oversized=Repeated()
        def next_huge(self):self.consumed+=1;return HugeName()
        with patch.object(Repeated,'__next__',next_huge),patch.object(n.os,'scandir',return_value=oversized),self.assertRaisesRegex(ValueError,'inventory bound exceeded'):
            n.configuration_snapshot(self.paths,UNIT,owned_mask=True)
        self.assertEqual(oversized.consumed,1);self.assertTrue(oversized.closed)

    def test_owned_verification_deadlines_and_success_both_close_streams(self):
        transport=n.NativeTransport(UNIT);transport.setup(None)
        for target,operation in ((transport.profile_path,transport.verify_profile),(transport.path,transport.verify)):
            observed,records=self.watch(target)
            with observed:operation()
            self.assertTrue(records and all(record.closed for record in records))
        transport.deadline=time.monotonic()+.05
        observed,records=self.watch(transport.profile_path,delay=.1)
        with observed,self.assertRaisesRegex(ValueError,'verification deadline exceeded'):
            transport.verify_profile()
        self.assertEqual(records[0].consumed,1);self.assertTrue(records[0].closed)
        self.assertTrue(transport.record.exists())
        transport.deadline=time.monotonic()-1
        with patch.object(n.os,'scandir') as scan,self.assertRaisesRegex(ValueError,'verification deadline exceeded'):
            transport.verify_profile()
        scan.assert_not_called()
