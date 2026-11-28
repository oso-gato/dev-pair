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
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from bootstrap import Blocked, Bootstrap, WORKLOAD_ACCESS_CUTOVER, checked_file, relay
from destination_observation import (AGENT_CANDIDATE, AGENT_ROLES, FAMILIES, FINAL_NAMESPACE, MAX_ACCESS_ENVELOPE,
                                     bounded_file, candidate_site, digest, encoding, keys, policy_credential,
                                     require, state_dir, verify_file, write_once)

CONFIG = Path('/etc/dev-pair/agent-observer/station.json')
PYTHON = '/usr/bin/python3'
RUNUSER = '/usr/sbin/runuser'
TOOLS = Path(__file__).resolve().parent
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C.UTF-8'}
STATION_TOOLS = Path('/usr/libexec/dev-pair-observer/tools')
STATION_UNITS = ('dev-pair-agent-observer-station.service', 'dev-pair-agent-observer-station.timer')
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


def configuration(path=CONFIG):
    config = json.loads(bounded_file(checked_file(path, secret=True)), object_pairs_hook=relay.unique)
    keys(config, {'site', 'courier', 'collector', 'reviewer'})
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
    selected = (config['collector']['core_key'], config['collector']['signer'], config['reviewer']['signer'])
    material = [bounded_file(path).split()[:2] for path in selected]
    require(all(len(fields) == 2 for fields in material) and len({tuple(fields) for fields in material}) == 3,
            'named SSH, probe and final review require different keys')
    return config


def call_named(profile, command, *, data=None, limit=MAX_ACCESS_ENVELOPE, timeout=30):
    identity = profile.get('ssh_agent')
    launch = [RUNUSER, '--user', profile['user'], '--', '/usr/bin/env', '-i']
    if identity:
        launch.append('SSH_AUTH_SOCK=' + str(identity))
    launch.extend(('PATH=/usr/bin:/usr/sbin', 'LC_ALL=C.UTF-8', *map(str, command)))

    def limit_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit + 1, limit + 1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # The separate caller has no station configuration or other principal's agent.
    with tempfile.TemporaryFile(dir='/run') as output:
        args = {'stdin': subprocess.DEVNULL} if data is None else {'input': data}
        process = subprocess.run(launch, **args, env=ENV, stdout=output, stderr=None, timeout=timeout,
                                 preexec_fn=limit_output, check=False)
        require(process.returncode == 0 and output.tell() <= limit,
                'independent station account operation failed')
        output.seek(0)
        return output.read(limit + 1)


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
    caller(courier, (*tool, 'publish', request), data=verified, limit=1024)
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
    sources.update({f'runtime/observer-station/{unit}': Path('/etc/systemd/system') / unit for unit in STATION_UNITS})
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


def install(args):
    assets = source_assets(args.source_sha)
    receipt, _ = verify_file(checked_file(args.access_receipt), 'dev-pair-access-review',
                             checked_file(args.trusted_access_signers), FINAL_NAMESPACE)
    site = station_site(receipt, args.guard_sha256, args.host_artifact_sha256)
    site_path = CONFIG.with_name('site.json')
    controls = {'site': str(site_path), 'courier': {'user': args.courier_user, 'mailbox': args.mailbox},
                'collector': {'user': args.collector_user, 'observations': args.observations,
                              'ssh_agent': args.collector_agent, 'core_key': args.core_key,
                              'known_hosts': args.known_hosts, 'signer': args.collector_signer},
                'reviewer': {'user': args.reviewer_user, 'ssh_agent': args.reviewer_agent, 'signer': args.reviewer_signer,
                             'acl_oauth': args.acl_oauth}}
    with tempfile.TemporaryDirectory(prefix='candidate-station-config-', dir='/run') as directory:
        staged_site, staged_config = (Path(directory) / name for name in ('site.json', 'station.json'))
        staged_site.write_bytes(encoding(site))
        staged_config.write_bytes(encoding({**controls, 'site': str(staged_site)}))
        admitted = configuration(staged_config)
    # The site file is a pinned independent approval. Repeating the same
    # installation is safe. Changed enrolment needs a separately approved setup.
    app = Bootstrap()
    all_files = {**assets, site_path: encoding(site), CONFIG: encoding(controls)}
    for path, raw in all_files.items():
        if os.path.lexists(path):
            for parent in (path, *path.parents):
                node = parent.lstat()
                require(node.st_uid == 0 and not stat.S_ISLNK(node.st_mode) and not node.st_mode & 0o022,
                        'unsafe installed station file')
            require(path.is_file() and path.stat().st_size == len(raw) and path.read_bytes() == raw,
                    'installed station inputs conflict with the approved exact setup')
    for path, raw in assets.items():
        app.atomic(str(path), raw.decode('utf-8'), mode=0o644)
    observed = call_named(admitted['reviewer'], (PYTHON, '-EBs', STATION_TOOLS / 'destination_observation.py',
                          'measure-acl', '--tailnet', site['tailnet'], '--acl-oauth', admitted['reviewer']['acl_oauth']),
                          limit=256)
    require(observed == (site['acl_sha256'] + '\n').encode('ascii'),
            'current API policy differs from the original independently signed access review')
    for path, raw in ((site_path, encoding(site)), (CONFIG, encoding(controls))):
        app.atomic(str(path), raw.decode('utf-8'), mode=0o600 if path == CONFIG else 0o644)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], env=ENV, check=True, timeout=25)
    subprocess.run(['/usr/bin/systemctl', 'enable', '--now', STATION_UNITS[1]], env=ENV, check=True, timeout=25)


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
            print(reconcile(configuration()))
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print('Independent candidate observation withheld. ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
