"""Adversarial structural audit projection, not Fedora denial/runtime evidence."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fedora_ci_guest as guest

S = 'system_u:system_r:unconfined_service_t:s0'
T = 'system_u:system_r:system_dbusd_t:s0'


def avc(kind='AVC', number=1, extra='comm="crun"', permissions='read write'):
    body = 'avc: denied { ' + permissions + ' } for ' + extra + ' scontext=' + S + ' tcontext=' + T + ' tclass=fifo_file permissive=0'
    if kind in ('USER_AVC', '1107'):
        body = "msg='" + body + "'"
    return 'type=' + kind + ' msg=audit(179476.123:' + str(number) + '): ' + body


class AuditProjectionTests(unittest.TestCase):
    def test_user_avc_without_comm_or_pid_and_numeric_aliases(self):
        data = '\n'.join(avc(kind, index, '') for index, kind in enumerate(('AVC', 'USER_AVC', '1400', '1107'), 1))
        result = guest.project_avcs(data.encode())
        self.assertEqual(result['typed_seen'], 4)
        self.assertEqual(result['projected'], 4)
        self.assertEqual(result['malformed'], 0)
        self.assertEqual({row['type'] for row in result['records']}, {'AVC', 'USER_AVC'})
        self.assertTrue(all('comm' not in row and 'pid' not in row for row in result['records']))

    def test_quoted_payloads_fake_fields_never_become_security_fields(self):
        extra = 'pid=42 comm="unknown-program" name="scontext=secret_name_t tclass=secret_class" proctitle="synthetic-secret argv=synthetic-secret"'
        for kind in ('AVC', 'USER_AVC'):
            result = guest.project_avcs(avc(kind, extra=extra).encode())
            self.assertEqual(result['projected'], 1)
            row = result['records'][0]
            self.assertEqual(row['scontext'], S)
            self.assertEqual(row['tcontext'], T)
            self.assertEqual(row['pid'], 42)
            self.assertNotIn('comm', row)
            self.assertNotIn('secret', json.dumps(result))
            self.assertEqual(set(row), {'type', 'audit_event_id', 'permissions', 'scontext', 'tcontext', 'tclass', 'permissive', 'pid'})

    def test_duplicate_malformed_huge_lists_contexts_and_lines_reject_without_raw_leak(self):
        malformed = [avc(extra='pid=1 pid=2'), avc(permissions=' '.join('permission' + str(n) for n in range(9))),
                     avc().replace(S, S + ':synthetic_secret'), avc() + ' name="' + 'synthetic-secret' * 400 + '"',
                     avc().replace('comm="crun"', 'comm="unterminated'),
                     'type=USER_AVC msg=audit(1:2): msg=\'avc: denied { read } for scontext=' + S + ' tcontext=' + T + ' tclass=file\' msg=duplicate']
        result = guest.project_avcs('\n'.join(malformed).encode())
        self.assertEqual(result['typed_seen'], len(malformed))
        self.assertEqual(result['malformed'], len(malformed))
        self.assertEqual(result['records'], [])
        self.assertNotIn('synthetic', json.dumps(result))

    def test_count_byte_caps_and_relevance_prioritize_latest_no_comm_domain(self):
        data = '\n'.join(avc(number=n, extra='') for n in range(20))
        result = guest.project_avcs(data.encode(), truncated=True)
        self.assertLessEqual(len(json.dumps(result['records'], sort_keys=True, ensure_ascii=True).encode()), 3000)
        self.assertLessEqual(result['projected'], 8)
        self.assertEqual(result['typed_seen'], 20)
        self.assertEqual(result['omitted_for_cap'], 20 - result['projected'])
        self.assertTrue(result['input_truncated'])
        self.assertEqual(result['records'][0]['audit_event_id'], '179476.123:19')
        long_context = 'system_u:system_r:' + 'x' * 150 + '_t:s0'
        large = '\n'.join(avc(number=n).replace(S, long_context).replace(T, long_context) for n in range(20))
        projected = guest.project_avcs(large.encode())
        self.assertLess(projected['projected'], 8)
        self.assertLessEqual(len(json.dumps(projected['records'], sort_keys=True, ensure_ascii=True).encode()), 3000)

    def test_real_capture_overflow_retains_only_bounded_prefix_then_projects(self):
        line = avc() + '\n'
        code = 'import os,sys;os.write(1,sys.argv[1].encode()+b"synthetic-secret"*10000)'
        with self.assertRaises(guest.CaptureOverflow) as captured:
            guest.capture([sys.executable, '-c', code, line], timeout=2)
        self.assertEqual(len(captured.exception.output), 65536)
        result = guest.project_avcs(captured.exception.output, truncated=True)
        self.assertEqual(result['projected'], 1)
        self.assertTrue(result['input_truncated'])
        self.assertNotIn('synthetic-secret', json.dumps(result))

    def test_root_mount_projection_only_selected_type_and_quota_flags(self):
        raw = b'23 1 0:1 / / rw,relatime - xfs /dev/private-secret rw,prjquota,secret=sentinel\n24 23 0:2 / /home rw - ext4 /dev/other-secret rw,usrquota\n'
        with mock.patch('builtins.open', return_value=io.BytesIO(raw)):
            result = guest.root_filesystem()
        self.assertEqual(result, {'type': 'xfs', 'quota_flags': ['prjquota']})
        self.assertNotIn('secret', json.dumps(result))
