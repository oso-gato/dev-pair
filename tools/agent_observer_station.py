#!/usr/bin/python3 -EBs
"""Reconcile one queued agent observation under three enrolled station accounts."""
import argparse
import getpass
from itertools import islice
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from bootstrap import Blocked, Bootstrap, WORKLOAD_ACCESS_CUTOVER, checked_file, relay
from destination_observation import (AGENT_CANDIDATE, AGENT_ROLES, FAMILIES, FINAL_NAMESPACE, MAX_ACCESS_ENVELOPE,
                                     MAX_ACCESS_PART, NAMESPACE, STATION_SIGNING, approved_signer, bounded_file,
                                     candidate_site, configured_signers, current_station_signer, digest, encoding,
                                     keys, observer_principal, policy_credential, require, state_dir, station_signing,
                                     verify_bytes, verify_file, verify_station_response, write_once)

CONFIG = Path('/etc/dev-pair/agent-observer/station.json')
PYTHON = '/usr/bin/python3'
RUNUSER = '/usr/sbin/runuser'
TOOLS = Path(__file__).resolve().parent
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'}
STATION_TOOLS = Path('/usr/libexec/dev-pair-observer/tools')
STATION_UNITS = ('dev-pair-agent-observer-station.service', 'dev-pair-agent-observer-station.timer')
UNIT_ROOT = Path('/etc/systemd/system')
UNIT_HASHES = ('7080fd6641dab45871d250d8adb69657f1484e85db2b624681cfb4b9263ae881',
               '2add841833bed54ef3a2deffb954532ec0e7285acd017329e58bd4983bd7282e')
STATION_SCRIPTS = ('agent_observer_station.py', 'bootstrap.py', 'day0_access_exchange.py', 'destination_observation.py',
                   'native_io.py', 'native_relay.py', 'release_trust.py', 'selected_payload.py')
RETENTION_SECONDS = 7 * 86400


def canonical_path(value):
    path = Path(value)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'station path must be absolute and canonical')
    return path


def account_directory(path, uid):
    path = canonical_path(path)
    for parent in (path, *path.parents):
        node = parent.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid in (0, uid) and not node.st_mode & 0o022,
                'station account directory has unprotected ancestry')
    node = path.lstat()
    require(node.st_uid == uid and stat.S_IMODE(node.st_mode) == 0o700,
            'station account directory requires private custody')
    return path


def signing_paths(config):
    return {'final_trust': str(config['final_trust']), 'reviewer_key': str(config['reviewer']['signer']),
            'collector_key': str(config['collector']['signer'])}


def configuration(path=CONFIG, *, check_current=True):
    config = json.loads(bounded_file(checked_file(path, secret=True)), object_pairs_hook=relay.unique)
    keys(config, {'site', 'courier', 'collector', 'reviewer', 'final_trust'})
    keys(config['courier'], {'user', 'mailbox'})
    keys(config['collector'], {'user', 'observations', 'ssh_agent', 'core_key', 'known_hosts', 'signer'})
    keys(config['reviewer'], {'user', 'ssh_agent', 'signer', 'acl_oauth'})
    accounts = []
    for role in ('courier', 'collector', 'reviewer'):
        profile = config[role]
        user = profile['user']
        require(type(user) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user), 'invalid independent station account')
        account = pwd.getpwnam(user)
        require(account.pw_uid > 0, 'station principals require separate unprivileged accounts')
        accounts.append(account.pw_uid)
        if role == 'courier':
            profile['mailbox'] = account_directory(profile['mailbox'], account.pw_uid)
            continue
        agent = canonical_path(profile['ssh_agent'])
        node = agent.lstat()
        require(stat.S_ISSOCK(node.st_mode) and node.st_uid == account.pw_uid and not node.st_mode & 0o077,
                'signing agent socket is outside its independent private identity')
        account_directory(agent.parent, account.pw_uid)
        profile['ssh_agent'] = agent
        profile['signer'] = checked_file(profile['signer'])
        if role == 'collector':
            profile['observations'] = account_directory(profile['observations'], account.pw_uid)
            for field in ('core_key', 'known_hosts'):
                profile[field] = checked_file(profile[field])
        else:
            profile['acl_oauth'] = policy_credential(Path(profile['acl_oauth']), account.pw_uid)
    require(len(set(accounts)) == len(accounts), 'courier, collector and reviewer require distinct station accounts')
    config['site'] = checked_file(config['site'])
    config['final_trust'] = checked_file(config['final_trust'])
    selected = (config['collector']['core_key'], config['collector']['signer'], config['reviewer']['signer'])
    material = [bounded_file(path).split()[:2] for path in selected]
    require(all(len(fields) == 2 for fields in material) and len({tuple(fields) for fields in material}) == 3,
            'named SSH, probe and final review require different keys')
    if check_current:
        require(station_signing() == signing_paths(config), 'the station signing authority changed')
        current_station_signer(config['collector']['signer'], NAMESPACE)
        current_station_signer(config['reviewer']['signer'], FINAL_NAMESPACE)
    return config


def call_named(profile, command, *, data=None, limit=MAX_ACCESS_ENVELOPE, file_limit=None, timeout=30):
    require(0 < limit <= MAX_ACCESS_ENVELOPE and (data is None or len(data) <= MAX_ACCESS_ENVELOPE),
            'independent station account transfer exceeds its byte bound')
    ceiling = limit + 1 if file_limit is None else file_limit
    require(0 < ceiling <= MAX_ACCESS_ENVELOPE + 1, 'independent station file output exceeds its bound')
    identity = profile.get('ssh_agent')
    launch = [RUNUSER, '--user', profile['user'], '--', '/usr/bin/env', '-i']
    if identity:
        launch.append('SSH_AUTH_SOCK=' + str(identity))
    launch.extend(('PATH=/usr/bin:/usr/sbin', 'LC_ALL=C.UTF-8', *map(str, command)))

    def limit_files():
        resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # The separate caller has no station configuration or other principal's agent.
    end = time.monotonic() + timeout
    with tempfile.TemporaryFile(dir='/run') as incoming:
        if data is not None:
            incoming.write(data)
            incoming.seek(0)
        with subprocess.Popen(launch, stdin=incoming if data is not None else subprocess.DEVNULL,
                              env=ENV, stdout=subprocess.PIPE, preexec_fn=limit_files, start_new_session=True) as process:
            try:
                output = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.select(max(0, end - time.monotonic())):
                        block = os.read(process.stdout.fileno(), limit + 1 - len(output))
                        if not block:
                            break
                        output.extend(block)
                        require(len(output) <= limit, 'independent station account stdout exceeds its bound')
                    else:
                        raise subprocess.TimeoutExpired(launch, timeout)
                require(process.wait(timeout=max(0, end - time.monotonic())) == 0,
                        'independent station account operation failed')
            except BaseException:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                raise
    return bytes(output)


def next_request(config, caller=call_named):
    courier = config['courier']
    mailbox = courier['mailbox']
    tool = (PYTHON, '-EBs', TOOLS / 'day0_access_exchange.py', '--mailbox', mailbox)
    listing = caller(courier, (*tool, 'pending', '--kind', AGENT_CANDIDATE), limit=16384)
    site = json.loads(bounded_file(config['site']), object_pairs_hook=relay.unique)
    candidates = []
    for name in listing.decode('utf-8').splitlines():
        path = Path(name)
        require(path.parent == mailbox and re.fullmatch(r'[0-9a-f]{64}\.request', path.name),
                'station mailbox selected a foreign leaf')
        raw = bounded_file(path, 16384)
        require(path.stem == digest(raw), 'station mailbox candidate identity changed')
        data = json.loads(raw, object_pairs_hook=relay.unique)
        try:
            candidate_site(data, site, int(time.time()))
        except (Blocked, ValueError, KeyError, TypeError):
            continue  # Stale or mismatched rows remain available for the separate operator route.
        candidates.append((data['candidate']['requested_at'], path.stem, raw))
    if not candidates:
        return None
    _, request, raw = max(candidates)
    return tool, request, raw


def reconcile(config, *, caller=call_named, scratch='/run'):
    selected = next_request(config, caller)
    if selected is None:
        return 'awaiting-candidate'
    tool, request, raw = selected
    collector, reviewer, courier = (config[key] for key in ('collector', 'reviewer', 'courier'))
    observations = collector['observations'] / request
    observer = (PYTHON, '-EBs', TOOLS / 'destination_observation.py')
    caller(collector, (PYTHON, '-EBs', TOOLS / 'agent_observer_station.py', 'cleanup', collector['observations']), limit=1024)
    caller(collector, ('/usr/bin/install', '-d', '-m', '0700', str(observations)), limit=1024)
    with tempfile.TemporaryDirectory(prefix='agent-observation-', dir=scratch) as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        binding = directory / 'binding.json'
        binding.write_bytes(raw)
        binding.chmod(0o644)
        common = ('--binding', binding, '--site', config['site'])
        collected = caller(
            collector, (*observer, '--directory', observations, 'collect-candidate', *common, '--core-key',
                        collector['core_key'], '--known-hosts', collector['known_hosts'], '--signer', collector['signer']),
            timeout=46 * 60)
        records = directory / 'collection.bundle'
        records.write_bytes(collected)
        records.chmod(0o644)
        verified = caller(reviewer, (*observer, 'assemble-candidate', *common, '--collection', records,
                                     '--signer', reviewer['signer'], '--acl-oauth', reviewer['acl_oauth']))
    verify_station_response(verified, json.loads(raw, object_pairs_hook=relay.unique))
    caller(courier, (*tool, 'publish', request), data=verified, limit=1024, file_limit=len(verified))
    return 'candidate-observation-published'


def cleanup(base):
    state_dir(base)
    now = time.time()
    expected = {role + '-' + family + '.json' for role in AGENT_ROLES for family in FAMILIES}
    with os.scandir(base) as entries:
        for count, entry in enumerate(entries, 1):
            require(count <= 128, 'observation retention inventory exceeds its bound')
            if not re.fullmatch(r'[0-9a-f]{64}', entry.name):
                continue
            node = entry.stat(follow_symlinks=False)
            if node.st_uid != os.geteuid() or not stat.S_ISDIR(node.st_mode) or now - node.st_mtime <= RETENTION_SECONDS:
                continue
            path = Path(entry.path)
            leaves = list(islice(path.iterdir(), len(expected) + 1))
            if (len(leaves) <= len(expected) and all(leaf.name in expected and
                 stat.S_ISREG(leaf.lstat().st_mode) for leaf in leaves) and shutil.rmtree.avoids_symlink_attacks):
                shutil.rmtree(path)


def source_assets(sha):
    require(type(sha) is str and re.fullmatch(r'[0-9a-f]{40}', sha), 'exact independently reviewed station source SHA required')
    root = TOOLS.parent
    for directory in (root, *root.parents, root / 'tools', root / 'runtime', root / 'runtime' / 'observer-station'):
        node = directory.lstat()
        require(node.st_uid == 0 and stat.S_ISDIR(node.st_mode) and not node.st_mode & 0o022,
                'station installer source requires a protected root-owned checkout')
    git = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', str(root)]
    env = {**ENV, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}

    def capture(*args):
        return subprocess.check_output([*git, *args], timeout=15, env=env)

    require(capture('rev-parse', '--verify', 'HEAD').decode().strip() == sha and
            not capture('status', '--porcelain=v1', '--untracked-files=all'),
            'station installer source differs from its exact reviewed checkout')
    sources = {f'tools/{name}': STATION_TOOLS / name for name in STATION_SCRIPTS}
    sources.update({f'runtime/observer-station/{unit}': UNIT_ROOT / unit for unit in STATION_UNITS})
    assets = {}
    for source, target in sources.items():
        path = root / source
        node = path.lstat()
        require(node.st_uid == 0 and stat.S_ISREG(node.st_mode) and not node.st_mode & 0o022 and
                0 < node.st_size <= 512 * 1024, 'unsafe reviewed station asset')
        raw = capture('show', sha + ':' + source)
        require(raw == path.read_bytes(), 'station asset differs from the reviewed tree')
        assets[target] = raw
    return assets


def station_site(receipt, guard, host):
    required = {'version', 'kind', 'source_sha', 'machine_id', 'dns_name', 'tailnet', 'node_id', 'tailnet_addresses',
                'keys_sha256', 'acl_sha256', 'provider_recovery', 'public_addresses', 'role_artifacts'}
    require(type(receipt) is dict and required <= receipt.keys() and receipt['version'] == 1 and
            receipt['kind'] == WORKLOAD_ACCESS_CUTOVER and all(type(val) is str and re.fullmatch(r'[0-9a-f]{64}', val)
                                                              for val in (guard, host, receipt['role_artifacts']['devbox_image'])),
            'previous independently signed full workload review and approved host/guard digests required')
    return {**{key: receipt[key] for key in required - {'kind', 'role_artifacts'}}, 'guard_sha256': guard,
            'host_artifact_sha256': host, 'devbox_image': receipt['role_artifacts']['devbox_image']}


def confirm_station_signers(admitted, final_trust, sha, caller=call_named, scratch='/run'):
    authorities = (('collector', configured_signers(), observer_principal('authorized'), NAMESPACE),
                   ('reviewer', final_trust, 'dev-pair-access-review', FINAL_NAMESPACE))
    selected = [(role, principal, namespace, approved_signer(path, admitted[role]['signer'], principal, namespace))
                for role, path, principal, namespace in authorities]
    with tempfile.TemporaryDirectory(prefix='station-signer-', dir=scratch) as directory:
        # Isolate the public input so ssh-keygen cannot fall back to a local
        # private sibling when the selected agent lacks the enrolled key.
        public = Path(directory) / 'approved.pub'
        public.parent.chmod(0o755)
        for role, principal, namespace, approved in selected:
            public.write_bytes(b' '.join(approved.split()[2:4]) + b'\n')
            public.chmod(0o644)
            challenge = {'version': 1, 'kind': 'station-signing-custody', 'role': role, 'source_sha': sha,
                         'challenge': secrets.token_hex(32)}
            payload = encoding(challenge)
            signature = caller(admitted[role], ('/usr/bin/ssh-keygen', '-Y', 'sign', '-f', public, '-n', namespace),
                               data=payload, limit=MAX_ACCESS_PART, timeout=15)
            verified, _ = verify_bytes(payload, signature, principal, approved, namespace)
            require(verified == challenge, 'the enrolled station signer did not answer its independent custody check')


def station_owned():
    """Recognize the exact station unit pair even when its own state is damaged."""
    try:
        return all(digest(bounded_file(checked_file(UNIT_ROOT / unit), 4096)) == expected
                   for unit, expected in zip(STATION_UNITS, UNIT_HASHES))
    except (Blocked, OSError, ValueError, TypeError, KeyError):
        return False


def timer_state():
    timer = STATION_UNITS[1]
    raw = subprocess.check_output(
        ['/usr/bin/systemctl', 'show', timer, '--property=FragmentPath,DropInPaths,ActiveState,UnitFileState'],
        env=ENV, timeout=25, text=True)
    values = dict(line.split('=', 1) for line in raw.splitlines())
    require(values.get('FragmentPath') == str(UNIT_ROOT / timer) and values.get('DropInPaths') == '',
            'the loaded station timer differs from its owned unit')
    return values


def restore_station_hold():
    if station_owned():
        timer_state()
        subprocess.run(['/usr/bin/systemctl', 'disable', '--now', STATION_UNITS[1]], env=ENV, check=True, timeout=25)
        values = timer_state()
        require(values.get('ActiveState') == 'inactive' and values.get('UnitFileState') == 'disabled',
                'the owned independent station timer did not enter its held state')


def install(args):
    try:
        install_station(args)
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        restore_station_hold()
        raise


def install_station(args):
    assets = source_assets(args.source_sha)
    final_trust = checked_file(args.trusted_access_signers)
    review_key = checked_file(args.reviewer_signer)
    final_scope = approved_signer(final_trust, review_key, 'dev-pair-access-review', FINAL_NAMESPACE)
    receipt, _ = verify_file(checked_file(args.access_receipt), 'dev-pair-access-review', final_scope, FINAL_NAMESPACE)
    site = station_site(receipt, args.guard_sha256, args.host_artifact_sha256)
    site_path = CONFIG.with_name('site.json')
    controls = {'site': str(site_path), 'final_trust': str(final_trust),
                'courier': {'user': args.courier_user, 'mailbox': args.mailbox},
                'collector': {'user': args.collector_user, 'observations': args.observations,
                              'ssh_agent': args.collector_agent, 'core_key': args.core_key,
                              'known_hosts': args.known_hosts, 'signer': args.collector_signer},
                'reviewer': {'user': args.reviewer_user, 'ssh_agent': args.reviewer_agent, 'signer': args.reviewer_signer,
                             'acl_oauth': args.acl_oauth}}
    app = Bootstrap()
    all_files = {**assets, site_path: encoding(site), CONFIG: encoding(controls),
                 STATION_SIGNING: encoding(signing_paths(controls))}
    previous_config = None
    for path, raw in all_files.items():
        if os.path.lexists(path):
            for parent in (path, *path.parents):
                node = parent.lstat()
                require(node.st_uid == 0 and not stat.S_ISLNK(node.st_mode) and not node.st_mode & 0o022,
                        'unsafe installed station file')
            existing = bounded_file(path, 512 * 1024)
            legacy = path == CONFIG and existing == encoding({key: value for key, value in controls.items()
                                                              if key != 'final_trust'})
            require(existing == raw or legacy, 'installed station inputs conflict with the approved exact setup')
            if legacy:
                previous_config = existing.decode('utf-8')
    with tempfile.TemporaryDirectory(prefix='candidate-station-config-', dir='/run') as directory:
        staged_site, staged_config = (Path(directory) / name for name in ('site.json', 'station.json'))
        staged_site.write_bytes(encoding(site))
        staged_config.write_bytes(encoding({**controls, 'site': str(staged_site)}))
        admitted = configuration(staged_config, check_current=False)
    confirm_station_signers(admitted, final_trust, args.source_sha, caller=call_named)
    for path, raw in assets.items():
        app.atomic(str(path), raw.decode('utf-8'), mode=0o644)
    observed = call_named(admitted['reviewer'], (PYTHON, '-EBs', STATION_TOOLS / 'destination_observation.py',
                          'measure-acl', '--tailnet', site['tailnet'], '--acl-oauth', admitted['reviewer']['acl_oauth']),
                          limit=256)
    require(observed == (site['acl_sha256'] + '\n').encode('ascii'),
            'current API policy differs from the original independently signed access review')
    for path in (site_path, STATION_SIGNING, CONFIG):
        app.atomic(str(path), all_files[path].decode('utf-8'), mode=0o600 if path == CONFIG else 0o644,
                   expected=previous_config if path == CONFIG else None)
    configuration()
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], env=ENV, check=True, timeout=25)
    timer_state()
    subprocess.run(['/usr/bin/systemctl', 'enable', '--now', STATION_UNITS[1]], env=ENV, check=True, timeout=25)
    enabled = timer_state()
    require(enabled.get('ActiveState') == 'active' and enabled.get('UnitFileState') == 'enabled',
            'the independent station timer did not arm')


def enroll_acl(path):
    require(os.getuid() == os.geteuid() > 0 and sys.stdin.isatty() and sys.stderr.isatty() and
            path.is_absolute() and not os.path.lexists(path),
            'use the independent reviewer terminal and a new private credential path')
    state_dir(path.parent)
    client = input('Tailscale OAuth client ID: ').strip()
    secret = getpass.getpass('Tailscale OAuth client secret: ')
    require(all(re.fullmatch(r'[A-Za-z0-9._~-]{8,512}', value) for value in (client, secret)),
            'Tailscale OAuth credential format is unsupported')
    write_once(path, encoding({'client_id': client, 'client_secret': secret}))
    policy_credential(path)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command')
    cleanup_args = commands.add_parser('cleanup', help='expire this authorized account’s scoped candidate scratch')
    cleanup_args.add_argument('base', type=Path)
    enrollment = commands.add_parser('enroll-acl', help='store the acquired read-only OAuth credential in reviewer custody')
    enrollment.add_argument('file', type=Path)
    setup = commands.add_parser('install', help='install reviewed station assets under enrolled independent identities')
    for key in ('source-sha', 'access-receipt', 'trusted-access-signers', 'guard-sha256', 'host-artifact-sha256',
                'courier-user', 'mailbox', 'collector-user', 'observations', 'collector-agent', 'core-key',
                'known-hosts', 'collector-signer', 'reviewer-user', 'reviewer-agent', 'reviewer-signer', 'acl-oauth'):
        setup.add_argument('--' + key, required=True)
    return parser.parse_args()


def main():
    args = arguments()
    try:
        if args.command == 'enroll-acl':
            enroll_acl(args.file)
            return 0
        if args.command == 'cleanup':
            cleanup(args.base)
            return 0
        require(os.getuid() == os.geteuid() == 0, 'protected station worker requires independent administrator custody')
        os.umask(0o077)
        if args.command == 'install':
            install(args)
            print('Installed the reviewed independent candidate observer timer.')
        else:
            try:
                admitted = configuration()
            except (Blocked, OSError, KeyError, TypeError, ValueError):
                restore_station_hold()
                raise
            try:
                print(reconcile(admitted))
            except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
                # Distinguish failed observations from withdrawn station authority.
                try:
                    configuration()
                except (Blocked, OSError, KeyError, TypeError, ValueError):
                    restore_station_hold()
                raise
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print('Independent candidate observation withheld. ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
