#!/usr/bin/env python3
"""Prepare one independently operated Day 0 access station and admit its courier."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).absolute().parent))

from agent_observer_station import PYTHON, RUNUSER, STATION_TOOLS, account_directory, call_named, source_assets
from bootstrap import Blocked, Bootstrap, CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER, relay
from day0_access_exchange import ACCESS_NAMESPACE, ACCESS_PRINCIPAL, REQUEST_LIMIT, contact, key, request_value
from destination_observation import (CORE_SITE, FAMILIES, NAMESPACE, SIGNERS, VANTAGES, bounded_file,
                                     encoding, keys, matches, observer_principal, policy_credential, require,
                                     validate_site)

CONFIG = Path('/etc/dev-pair/destination-observer/access-station.json')
CORE_PROFILE = CONFIG.with_name('core-access-site.json')
REVIEW_SIGNERS = CONFIG.with_name('access-review-allowed-signers')
MAILBOX_ROOT = Path('/var/lib/dev-pair-observer/mailboxes')
LOCK = Path('/run/dev-pair-access-station.lock')
HOST_PUBLIC_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
SSHD = Path('/usr/sbin/sshd')
TAILSCALE = Path('/usr/bin/tailscale')
REVIEW_ROLES = ('plan', *VANTAGES)
SOURCE_SHA = r'[0-9a-f]{40}'
FINGERPRINT = r'[0-9a-f]{64}'


def protected(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), 'use canonical protected station paths')
    for leaf in (path, *path.parents):
        info = leaf.lstat()
        kind = (stat.S_ISDIR(info.st_mode) if leaf != path or directory else
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        require(info.st_uid == 0 and kind and not info.st_mode & 0o022,
                'station inputs and authorization require protected root-owned paths')
    return path


def require_dependencies():
    for tool in (Path(PYTHON), Path(RUNUSER), Path('/usr/bin/git'), Path('/usr/bin/ssh-keygen'), SSHD, TAILSCALE):
        binary = tool.resolve(strict=True)
        require(protected(binary).stat().st_mode & 0o111, 'station dependency is not executable')
    git = Path(__file__).absolute().parents[1] / '.git'
    protected(git, directory=True)
    protected(git / 'config')
    protected(git / 'HEAD')


def public_key(path, *, hardware=False):
    lines = bounded_file(protected(path), 8192).decode('ascii').splitlines()
    require(len(lines) == 1, 'each independently admitted authority requires exactly one public key')
    return key(lines[0], hardware=hardware)


def account(name):
    require(matches(r'[a-z_][a-z0-9_-]{0,30}', name), 'station needs an exact dedicated non-root account name')
    user = pwd.getpwnam(name)
    require(user.pw_uid > 0, 'station principals must use unprivileged accounts')
    return user


def verified_assets(sha):
    require(matches(SOURCE_SHA, sha), 'exact reviewed station source SHA required')
    require_dependencies()
    return {path: raw for path, raw in source_assets(sha).items() if path.parent == STATION_TOOLS}


def preflight_files(files):
    for path, (raw, mode) in files.items():
        if os.path.lexists(path):
            existing = protected(path)
            require(stat.S_IMODE(existing.stat().st_mode) == mode and existing.stat().st_size == len(raw)
                    and existing.read_bytes() == raw,
                    'existing station file conflicts with its exact protected setup')
        else:
            for ancestor in path.parents:
                if os.path.lexists(ancestor):
                    protected(ancestor, directory=True)
                    break


def install_files(app, files):
    preflight_files(files)
    for path, (raw, mode) in files.items():
        app.atomic(str(path), raw.decode('utf-8'), mode=mode)


@contextmanager
def setup_lock():
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
    descriptor = os.open(LOCK, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'station setup lock is unsafe')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def station_location(host, tailnet, app):
    state = json.loads(app.run(str(TAILSCALE), 'status', '--json', timeout=15), object_pairs_hook=relay.unique)
    require(state.get('BackendState') == 'Running' and host in state.get('TailscaleIPs', [])
            and (state.get('CurrentTailnet') or {}).get('Name') == tailnet,
            'the independent station address is outside the selected running tailnet')


def authorization_path(courier):
    home = protected(Path(courier.pw_dir), directory=True)
    require(courier.pw_shell in ('/bin/sh', '/bin/bash', '/bin/dash', '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/dash'),
            'the dedicated courier must support its fixed OpenSSH forced command')
    require(home.stat().st_mode & 0o001, 'the protected courier home must be traversable by its account')
    ssh = home / '.ssh'
    if os.path.lexists(ssh):
        require(protected(ssh, directory=True).stat().st_mode & 0o001,
                'the protected courier authorization directory must be traversable')
    return ssh / 'authorized_keys'


def ssh_profile(courier, station, source, host_public_path, app):
    request = f'user={courier},addr={source},laddr={station},lport=22,host={source}'
    raw = app.run(str(SSHD), '-T', '-C', request, timeout=12)
    profile = {}
    for line in raw.splitlines():
        field, value = line.split(' ', 1)
        profile.setdefault(field, []).append(value)
    require(profile.get('authorizedkeysfile') in [['.ssh/authorized_keys'], ['.ssh/authorized_keys .ssh/authorized_keys2']]
            and profile.get('authorizedkeyscommand') == ['none'] and profile.get('trustedusercakeys') == ['none']
            and profile.get('forcecommand') == ['none'] and profile.get('permituserenvironment') == ['no']
            and profile.get('pubkeyauthentication') == ['yes'] and profile.get('strictmodes') == ['yes']
            and profile.get('authenticationmethods') in [['publickey'], ['any']]
            and all(profile.get(option, ['no']) == ['no'] for option in
                    ('passwordauthentication', 'kbdinteractiveauthentication', 'hostbasedauthentication',
                     'gssapiauthentication', 'kerberosauthentication'))
            and all(variable in ('LANG', 'LANGUAGE', 'LC_*') for row in profile.get('acceptenv', [])
                    for variable in row.split()),
            'the selected SSH account requires protected local key-only authentication and no generic overrides')
    require(str(host_public_path.with_suffix('')) in profile.get('hostkey', []),
            'the independently selected Ed25519 host key is not configured for the station SSH route')


def station_inputs(args):
    reviewer, courier = account(args.reviewer_user), account(args.courier_user)
    require(reviewer.pw_uid != courier.pw_uid, 'reviewer and transport require separate station accounts')
    contact(args.station_address, args.courier_user)
    require(matches(r'[A-Za-z0-9._@-]{1,128}', args.tailnet) and args.tailnet != '-', 'use the exact admitted tailnet name')
    host_path = protected(args.station_ssh_host_key)
    require(host_path.suffix == '.pub', 'the station host key input must be its public companion')
    host_key = public_key(host_path)
    review_key = public_key(args.access_review_key, hardware=True)
    signer_keys = [public_key(getattr(args, role + '_key'), hardware=True) for role in REVIEW_ROLES]
    require(len(set([host_key, review_key, *signer_keys])) == len(signer_keys) + 2,
            'host authentication, final review and each observation require separate public keys')
    observers = ''.join(f'{observer_principal(role)} namespaces="{NAMESPACE}" {public}\n'
                        for role, public in zip(REVIEW_ROLES, signer_keys)).encode()
    final = f'{ACCESS_PRINCIPAL} namespaces="{ACCESS_NAMESPACE}" {review_key}\n'.encode()
    site = {'version': 1, 'kind': CORE_ACCESS_CUTOVER, 'dns_name': args.dns_name, 'tailnet': args.tailnet,
            'provider_recovery': args.provider_recovery, 'execution_route': args.execution_route,
            'public_addresses': {family: None if (value := getattr(args, 'public_' + family)) == 'none' else value
                                 for family in FAMILIES},
            'clients': {role: getattr(args, role + '_client') for role in VANTAGES}}
    validate_site(site)
    credential = policy_credential(args.acl_oauth, reviewer.pw_uid)
    config = {'version': 1, 'source_sha': args.source_sha, 'station_address': args.station_address,
              'courier_user': args.courier_user, 'courier_uid': courier.pw_uid, 'reviewer_user': args.reviewer_user,
              'host_key_path': str(host_path), 'host_key': host_key, 'review_key': review_key,
              'signers_sha256': hashlib.sha256(observers).hexdigest()}
    return config, courier, credential, site, observers, final


def ensure_mailbox(courier):
    mailbox = MAILBOX_ROOT / courier.pw_name
    for directory in reversed((MAILBOX_ROOT, *MAILBOX_ROOT.parents)):
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o700)
            directory.chmod(0o755)
        protected(directory, directory=True)
    if not os.path.lexists(mailbox):
        mailbox.mkdir(mode=0o700)
    node = mailbox.lstat()
    if node.st_uid == 0 and stat.S_ISDIR(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o700:
        require(not any(mailbox.iterdir()), 'a root-held courier mailbox needs independent reconciliation')
        os.chown(mailbox, courier.pw_uid, courier.pw_gid)
    account_directory(mailbox, courier.pw_uid)
    return mailbox


def courier_authorization(courier):
    leaf = authorization_path(courier)
    for alternate in ('authorized_keys2', 'rc', 'environment'):
        require(not os.path.lexists(leaf.with_name(alternate)),
                'existing dedicated courier SSH state needs independent reconciliation')
    return leaf


def prepare(args, app, caller=call_named):
    assets = {path: (raw, 0o644) for path, raw in verified_assets(args.source_sha).items()}
    config, courier, credential, site, observers, final = station_inputs(args)
    courier_authorization(courier)
    station_location(config['station_address'], site['tailnet'], app)
    protected_inputs = {CONFIG: (encoding(config), 0o600), Path(SIGNERS): (observers, 0o644),
                        REVIEW_SIGNERS: (final, 0o644)}
    preflight_files({**assets, **protected_inputs})
    install_files(app, assets)
    raw = caller({'user': config['reviewer_user']}, (PYTHON, '-EBs', STATION_TOOLS / 'destination_observation.py',
                 'measure-acl', '--tailnet', site['tailnet'], '--acl-oauth', credential), limit=256)
    require(re.fullmatch(rb'[0-9a-f]{64}\n', raw), 'independent Tailscale policy measurement is unavailable')
    site['acl_sha256'] = raw.decode('ascii').strip()
    keys(site, CORE_SITE)
    files = {**protected_inputs, CORE_PROFILE: (encoding(site), 0o644)}
    preflight_files(files)
    ensure_mailbox(courier)
    install_files(app, files)
    return config


def configured(sha):
    path = protected(CONFIG)
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'station enrollment must remain root-private')
    config = json.loads(bounded_file(path), object_pairs_hook=relay.unique)
    keys(config, {'version', 'source_sha', 'station_address', 'courier_user', 'courier_uid', 'reviewer_user',
                 'host_key_path', 'host_key', 'review_key', 'signers_sha256'})
    require(type(config['version']) is int and config['version'] == 1 and config['source_sha'] == sha
            and matches(FINGERPRINT, config['signers_sha256']), 'station is pinned to another independently approved source')
    courier = account(config['courier_user'])
    contact(config['station_address'], courier.pw_name)
    require(courier.pw_uid == config['courier_uid'] and courier.pw_uid != account(config['reviewer_user']).pw_uid
            and config['host_key'] == public_key(config['host_key_path']),
            'the already approved station account or host key changed')
    return config, courier


def admit_courier(args, app):
    assets = {path: (raw, 0o644) for path, raw in verified_assets(args.source_sha).items()}
    require(all(os.path.lexists(path) for path in assets), 'prepare the exact independent station first')
    preflight_files(assets)
    config, courier = configured(args.source_sha)
    station = config['station_address']
    source, _ = contact(args.vps_address, courier.pw_name)
    require(ipaddress.ip_address(source).version == ipaddress.ip_address(station).version and source != station,
            'choose the independently approved VPS tailnet source in the station’s address family')
    site = json.loads(bounded_file(protected(CORE_PROFILE)), object_pairs_hook=relay.unique)
    keys(site, CORE_SITE)
    validate_site(site)
    station_location(station, site['tailnet'], app)
    public = public_key(args.courier_key)
    signers = bounded_file(protected(Path(SIGNERS)))
    require(hashlib.sha256(signers).hexdigest() == config['signers_sha256']
            and public not in (config['host_key'], config['review_key']) and public.split()[1].encode() not in signers.split(),
            'the VPS transport key must be independent of host and review keys')
    target = courier_authorization(courier)
    ssh_profile(courier.pw_name, station, source, Path(config['host_key_path']), app)
    mailbox = account_directory(MAILBOX_ROOT / courier.pw_name, courier.pw_uid)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(mailbox)), 'mailbox path cannot enter the fixed OpenSSH command')
    command = f'{PYTHON} -IB {STATION_TOOLS / "day0_access_exchange.py"} --mailbox {mailbox} receive'
    contents = f'restrict,from="{source}",command="{command}" {public}\n'
    install_files(app, {target: (contents.encode(), 0o644)})
    return target


def begin_review(args, caller=call_named):
    require(matches(FINGERPRINT, args.request), 'select an exact request ID displayed by the mailbox')
    assets = {path: (raw, 0o644) for path, raw in verified_assets(args.source_sha).items()}
    require(all(os.path.lexists(path) for path in assets), 'prepare the exact independent station first')
    preflight_files(assets)
    config, courier = configured(args.source_sha)
    reviewer = account(config['reviewer_user'])
    ceremony = account_directory(args.directory, reviewer.pw_uid)
    mailbox = account_directory(MAILBOX_ROOT / courier.pw_name, courier.pw_uid)
    transport = STATION_TOOLS / 'day0_access_exchange.py'
    raw = caller({'user': courier.pw_name}, (PYTHON, '-IB', transport, '--mailbox', mailbox, 'export', args.request),
                 limit=REQUEST_LIMIT)
    request = request_value(raw)
    require(hashlib.sha256(raw).hexdigest() == args.request and request['source_sha'] == args.source_sha
            and request['kind'] in (CORE_ACCESS_CUTOVER, WORKLOAD_ACCESS_CUTOVER),
            'the selected request does not match this installed access ceremony')
    operator = STATION_TOOLS / 'destination_observation.py'
    profile = protected(CORE_PROFILE)
    expected = ceremony / 'plan.json'
    reported = caller({'user': reviewer.pw_name}, (PYTHON, '-EBs', operator, '--directory', ceremony,
                       'begin', '--binding', '-', '--site', profile), data=raw, limit=4096, file_limit=REQUEST_LIMIT)
    require(reported == (str(expected) + '\n').encode(), 'the independent reviewer did not retain the selected plan')
    return expected


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('prepare', help='measure the approved tailnet policy and install the independent station')
    admit = commands.add_parser('admit-courier', help='admit the enrolled VPS for only the fixed mailbox command')
    begin = commands.add_parser('begin-review', help='hand off the exact queued request and prepare a named reviewer plan')
    for command in (setup, admit, begin):
        command.add_argument('--source-sha', required=True)
    for argument in ('station-address', 'courier-user', 'reviewer-user', 'dns-name', 'tailnet', 'provider-recovery',
                     'public-ipv4', 'public-ipv6', *(role + '-client' for role in VANTAGES)):
        setup.add_argument('--' + argument, required=True)
    setup.add_argument('--station-ssh-host-key', type=Path, default=HOST_PUBLIC_KEY)
    setup.add_argument('--acl-oauth', type=Path, required=True)
    setup.add_argument('--execution-route', choices=('tailnet-core', 'provider-recovery'), required=True)
    for role in ('access-review', *REVIEW_ROLES):
        setup.add_argument('--' + role + '-key', type=Path, required=True)
    admit.add_argument('--vps-address', required=True)
    admit.add_argument('--courier-key', type=Path, required=True)
    begin.add_argument('--request', required=True)
    begin.add_argument('--directory', type=Path, required=True)
    return parser.parse_args()


def main():
    args = arguments()
    os.umask(0o077)
    try:
        require(os.getuid() == os.geteuid() == 0, 'use the protected terminal of the independent station administrator')
        with setup_lock():
            if args.command == 'prepare':
                selected = prepare(args, Bootstrap())
                print('Independent access station prepared.')
                print(f'Station Tailscale address {selected["station_address"]}')
                print(f'Dedicated courier {selected["courier_user"]}')
                print(f'Station host public key {selected["host_key"]}')
                print(f'Station host fingerprint {Bootstrap.signer_fingerprint(selected["host_key"])}')
                print(f'Access review public key {selected["review_key"]}')
                print(f'Access review fingerprint {Bootstrap.signer_fingerprint(selected["review_key"])}')
            elif args.command == 'admit-courier':
                admit_courier(args, Bootstrap())
                print('Admitted the selected VPS for the fixed access mailbox command.')
            else:
                print(begin_review(args))
        return 0
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print(f'Independent access station setup paused. {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
