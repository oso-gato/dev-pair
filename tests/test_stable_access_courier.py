"""Exercise ordinary stable polling and the scoped systemd observer boundary."""
from contextlib import nullcontext
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import day0_access_exchange as courier
import destination_observation as observation
import stable_renewal as stable
import systemd_service_profile as profile


class StableAccessCourier(unittest.TestCase):
    def test_ordinary_poll_queues_and_receives_through_the_existing_courier(self):
        pending = {'candidate': {'operation': 'stable-exact-window', 'previous_release_sha256': 'b' * 64},
                   'role_artifacts': {'release_sha256': 'c' * 64}}
        raw = observation.encoding(pending)
        request = stable.r.sha(raw)
        binding, bundle = {'platform_sha256': 'd' * 64}, Path('/exact/signed/stable/host')
        controller = SimpleNamespace(lock=nullcontext)
        observer = Mock()
        observer.recover_request.return_value = pending
        observer.fresh.side_effect = [FileNotFoundError, FileNotFoundError, None]
        with (patch.object(stable, 'access', return_value=observer),
              patch.object(stable, 'for_release', return_value=binding) as selected,
              patch.object(stable, 'match_kit_bundle') as kit,
              patch.object(stable, 'host_bundle', return_value=bundle),
              patch.object(stable, 'start_observer', return_value='exact-scoped.service') as start,
              patch.object(stable, 'system_command') as manager,
              patch.object(observation, 'stable_host_trust'),
              patch.object(courier, 'exchange', side_effect=(None, b'exact station wire')) as exchange):
            first = stable.poll_access(controller, kit_source='e' * 40)
            self.assertEqual((first['request_id'], first['access_state']), (request, 'waiting-for-independent-approval'))
            self.assertEqual(stable.poll_access(controller, kit_source='e' * 40)['phase'], 'stable-access-preapproved')
            self.assertEqual(stable.poll_access(controller, kit_source='e' * 40)['phase'], 'stable-access-preapproved')
        self.assertEqual(exchange.call_count, 2)
        exchange.assert_called_with(raw)
        self.assertEqual(start.call_count, 2)
        start.assert_called_with(bundle, request, pending)
        selected.assert_called_with(controller, pending['role_artifacts']['release_sha256'])
        kit.assert_called_with(controller, binding, 'e' * 40)
        observer.receive.assert_called_once_with(b'exact station wire', pending)
        manager.assert_called_once_with('/usr/bin/systemctl', 'stop', 'exact-scoped.service')
        observer.request.assert_not_called()

    def test_gateway_launches_the_exact_versioned_script_and_limits_lifetime(self):
        bundle = Path('/exact/signed/stable/host')
        request = 'a' * 64
        directory = stable.broker_unit(request)
        unit = directory + '.service'
        argv = ['/usr/bin/python3', '-IB', str(bundle / 'runtime/renewal/agent-observer'), 'stable-listen', request]
        row = {'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active', 'Type': 'exec', 'User': 'root',
               'Group': 'root', 'Transient': 'yes', 'FragmentPath': '/run/systemd/transient/' + unit,
               'DropInPaths': '', 'RuntimeDirectory': directory, 'RuntimeDirectoryPreserve': 'no',
               'ExecStart': '{ path=/usr/bin/python3 ; argv[]=' + ' '.join(argv) + ' ; code=(null) }',
               **dict.fromkeys(profile.PROPERTIES, '')}
        actions = []
        runtime = 't 3600000000\n'

        def manager(*args, **kwargs):
            actions.append(args)
            if args[0] == '/usr/bin/busctl':
                self.assertEqual(args[-1], 'RuntimeMaxUSec')
                return runtime
            if args[0] == '/usr/bin/systemd-run':
                self.assertEqual(list(args[-len(argv):]), argv)
                self.assertIn('--unit=' + unit, args)
                self.assertIn('--property=RuntimeDirectory=' + directory, args)
                self.assertIn('--property=RuntimeMaxSec=3600', args)
                return ''
            if '--value' in args:
                return 'not-found\n' if len(actions) == 1 else 'loaded\n'
            return ''.join(f'{key}={value}\n' for key, value in row.items())

        def socket_stat(path):
            return SimpleNamespace(st_uid=0, st_gid=2000,
                                   st_mode=stat.S_IFSOCK | 0o660 if path.name == 'observer' else stat.S_IFDIR | 0o755)

        now = int(time.time())
        pending = {'candidate': {'requested_at': now}}
        with (patch.object(profile, 'observe') as effective,
              patch.object(stable.time, 'time', return_value=now), patch.object(stable.os.path, 'lexists', return_value=True),
              patch.object(Path, 'lstat', socket_stat),
              patch.object(stable.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=2000))):
            self.assertEqual(stable.start_observer(bundle, request, pending, command=manager), unit)
            effective.assert_called_once()
            runtime = 't 3600000001\n'
            with self.assertRaisesRegex(ValueError, 'lifetime exceeds'):
                stable.start_observer(bundle, request, pending, command=manager)
            row['FragmentPath'] = '/etc/systemd/system/' + unit
            with self.assertRaisesRegex(ValueError, 'differs from the exact allowed operation'):
                stable.start_observer(bundle, request, pending, command=manager)
        self.assertEqual(sum(args[0] == '/usr/bin/systemd-run' for args in actions), 1)


if __name__ == '__main__':
    unittest.main()
