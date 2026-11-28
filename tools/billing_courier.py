#!/usr/bin/env python3
"""Exchange exact billing requests and signed terms with a dedicated pinned SSH station."""

import argparse
import base64
import binascii
from contextlib import contextmanager
import fcntl
import grp
import ipaddress
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap import Blocked, Bootstrap
import checklist_candidate as candidate
from day0_access_exchange import contact, protected_file
import job_protocol as p
from ledger_recovery import sync_directory, write_private
import provider_billing as billing

CLIENT = Path('/etc/dev-pair/billing-exchange')
STATION = Path('/var/lib/dev-pair-billing-station')
HOST_PUBLIC_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
COMMAND = 'billing-request-v1'
MAX_REQUESTS = 64
RETENTION = billing.TERMS_LIFETIME + 86400


class Unavailable(ValueError):
    """The enrolled route is currently unable to deliver the exact request."""


def binding(profile):
    return {key: profile[key] for key in ('machine_sha256', 'reviewer_epoch')}


def read_request(raw, profile):
    p.require(0 < len(raw) <= billing.REVIEW_LIMIT, 'Billing request exceeds its bound.')
    row = billing.validate_request(billing.json_bundle(raw))
    p.require(row['schema'] == 2 and row['reviewer_epoch'] is not None and billing.canonical(row) == raw and
              all(row[key] == value for key, value in binding(profile).items()),
              'Billing request differs from this station’s admitted machine or reviewer enrollment.')
    return row


def read_response(raw, request, now):
    p.require(0 < len(raw) <= billing.BUNDLE_LIMIT, 'Signed billing bundle exceeds its bound.')
    bundle = billing.json_bundle(raw)
    p.fields(bundle, 'review signature evidence')
    review = billing.validate_review(bundle['review'], now)
    p.require(review['request'] == request, 'Signed billing terms differ from this exact request.')
    signature = bundle['signature']
    p.require(type(signature) is str and signature.isascii() and 0 < len(signature) <= billing.SIGNATURE_LIMIT and
              signature.startswith('-----BEGIN SSH SIGNATURE-----\n'), 'Invalid signed billing bundle.')
    p.fields(bundle['evidence'], ' '.join(billing.SOURCE_KINDS))
    for kind, payload in bundle['evidence'].items():
        evidence = review['sources'][kind]
        p.require(type(payload) is str and len(payload) == 4 * ((evidence['bytes'] + 2) // 3),
                  'Billing evidence exceeds its signed bound.')
        try:
            body = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError('Billing evidence is malformed.') from exc
        p.require(len(body) == evidence['bytes'] and p.sha256(body) == evidence['sha256'],
                  'Billing evidence differs from the signed review.')
        billing.check_attachment(body)
    return review, signature


def identity_path(profile):
    return CLIENT / (profile['generation'] + '.key')


def hosts_path(profile):
    return CLIENT / (profile['generation'] + '.hosts')


def load_client():
    path = CLIENT / 'current.json'
    if not os.path.lexists(path):
        return None
    raw = billing.bounded_file(protected_file(path), 4096, owner=0, mode=0o600)
    profile = billing.json_bundle(raw)
    p.fields(profile, 'schema host account host_key generation machine_sha256 reviewer_epoch reviewer_key')
    p.require(profile['schema'] == 1 and billing.canonical(profile) == raw, 'Invalid protected billing station profile.')
    contact(profile['host'], profile['account'])
    p.digest(profile['generation'], 32)
    p.digest(profile['machine_sha256'])
    p.digest(profile['reviewer_epoch'], 32)
    p.require(all(billing.reviewer_key(profile[field])[0] == profile[field] for field in ('host_key', 'reviewer_key')),
              'Invalid pinned billing station identities.')
    protected_file(identity_path(profile))
    known = billing.bounded_file(protected_file(hosts_path(profile)), 4096, owner=0, mode=0o600)
    p.require(known == f"{profile['host']} {profile['host_key']}\n".encode('ascii'), 'Pinned billing SSH host key changed.')
    return profile


def reviewer_profile():
    reviewer = billing.reviewer_state()
    p.require(reviewer is not None and reviewer['key'] is not None,
              'Enroll a dedicated independent billing reviewer before station transport.')
    billing.require_distinct_reviewer(reviewer['key'])
    return {'machine_sha256': billing.machine_binding(), 'reviewer_epoch': reviewer['epoch'], 'reviewer_key': reviewer['key']}


def current_client():
    profile = load_client()
    if profile is None:
        return None
    try:
        current = reviewer_profile()
    except ValueError:
        return None
    return profile if all(value == profile[key] for key, value in current.items()) else None


def local_station(address):
    raw = candidate.invoke(['/usr/bin/tailscale', 'status', '--json', '--peers=false'], time.monotonic() + 12, cap=65536)
    value = billing.json_bundle(raw)
    p.require(type(value) is dict and value.get('BackendState') == 'Running' and value.get('TailscaleIPs') and
              address not in value['TailscaleIPs'], 'Select a distinct approved billing station on the running tailnet.')


def public_identity(profile):
    data = candidate.invoke([billing.SSH_KEYGEN, '-y', '-P', '', '-f', str(protected_file(identity_path(profile)))],
                            time.monotonic() + 10, cap=1024)
    return billing.reviewer_key(data.decode('ascii'))


def show_enrollment(profile, say):
    public, fingerprint = public_identity(profile)
    say(f"Admit this VPS on the independent billing station for machine binding {profile['machine_sha256']} "
        f"and billing reviewer enrollment {profile['reviewer_epoch']}.")
    say(f'Billing courier public key {public}')
    say(f'Billing courier fingerprint {fingerprint}')


def configure_client(ask, say):
    authority = reviewer_profile()
    host, account = contact(ask('Independent billing station numeric Tailscale address.'),
                            ask('Dedicated billing SSH courier account.'))
    host_key, fingerprint = billing.reviewer_key(ask('Independent billing station OpenSSH Ed25519 host public key.'))
    p.require(ask('SHA256 host fingerprint separately authenticated with the billing station operator.') == fingerprint,
              'Billing SSH host key differs from its independently authenticated fingerprint.')
    p.require(host_key != authority['reviewer_key'] and
              host_key.split()[1].encode() not in billing.other_signer_keys(billing.signer_rows()),
              'The station host key must be separate from billing and other signing keys.')
    say(f'Billing station {account}@{host}. SSH host fingerprint {fingerprint}.')
    if ask('Confirm this dedicated billing transport? [y/N]').lower() not in ('y', 'yes'):
        return None
    local_station(host)
    folder = billing.private_folder(CLIENT)
    with billing.lock(folder):
        profile = {**authority, 'schema': 1, 'host': host, 'account': account, 'host_key': host_key,
                   'generation': secrets.token_hex(16)}
        expected = load_client()
        with tempfile.TemporaryDirectory(prefix='.identity-', dir=folder) as directory:
            secret = Path(directory) / 'identity'
            candidate.invoke([billing.SSH_KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', str(secret)],
                             time.monotonic() + 10, cap=1024)
            raw = billing.bounded_file(protected_file(secret), 4096, owner=0, mode=0o600)
            write_private(identity_path(profile), raw)
        write_private(hosts_path(profile), f'{host} {host_key}\n'.encode('ascii'))
        sync_directory(folder)
        p.require(load_client() == expected and reviewer_profile() == authority, 'Billing transport authority changed during enrollment.')
        billing.replace_record(folder / 'current.json', profile)
    show_enrollment(profile, say)
    return profile


def exchange(reference, profile):
    p.require(current_client() == profile, 'The billing station belongs to a superseded authority. Re-enroll the approved station.')
    secret = billing.credential_from(billing.CREDENTIALS / reference)
    request = billing.canonical(billing.request_record(reference, secret))
    del secret
    row = read_request(request, profile)
    options = ('BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
               'GlobalKnownHostsFile=/dev/null', f'UserKnownHostsFile={hosts_path(profile)}',
               'HostKeyAlgorithms=ssh-ed25519', 'CheckHostIP=no', 'UpdateHostKeys=no', 'ControlMaster=no',
               'ProxyCommand=none', 'ProxyJump=none', 'ClearAllForwardings=yes', 'ForwardAgent=no',
               'PreferredAuthentications=publickey', 'ConnectTimeout=8', 'ConnectionAttempts=1',
               'ServerAliveInterval=5', 'ServerAliveCountMax=2')
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(identity_path(profile))]
    for value in options:
        argv.extend(('-o', value))
    argv.extend(('--', f"{profile['account']}@{profile['host']}", COMMAND, p.sha256(request)))
    try:
        local_station(profile['host'])
        response = candidate.invoke(argv, time.monotonic() + 25, data=request, cap=billing.BUNDLE_LIMIT)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise Unavailable('The pinned billing station could not be reached. Check the dedicated courier enrollment and retry.') from exc
    if response:
        read_response(response, row, time.time())
    return response or None


def directory(path, uid, gid, mode):
    info = path.lstat()
    p.require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode),
              'Billing station mailbox ownership or mode differs.')
    return path


def station_profile():
    raw = station_read(STATION / 'profile.json', 4096, uid=0)
    profile = billing.json_bundle(raw)
    p.fields(profile, 'schema machine_sha256 reviewer_epoch reviewer_key courier_uid reviewer_uid gid source_sha')
    p.require(profile['schema'] == 1 and billing.canonical(profile) == raw, 'Invalid billing station profile.')
    p.digest(profile['machine_sha256'])
    p.digest(profile['reviewer_epoch'], 32)
    p.digest(profile['source_sha'], 40)
    p.require(billing.reviewer_key(profile['reviewer_key'])[0] == profile['reviewer_key'], 'Invalid billing station signer.')
    for field in ('courier_uid', 'reviewer_uid', 'gid'):
        p.number(profile[field], 1, 2**31 - 1)
    p.require(profile['courier_uid'] != profile['reviewer_uid'], 'Billing station identities must be separate.')
    directory(STATION, 0, profile['gid'], 0o750)
    p.require((STATION / 'profile.json').lstat().st_gid == profile['gid'] and STATION.resolve(strict=True) == STATION,
              'Billing station profile group or path differs.')
    return profile


def station_read(path, maximum, *, uid, gid=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as source:
        node = os.fstat(source.fileno())
        p.require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == uid and
                  (gid is None or node.st_gid == gid) and stat.S_IMODE(node.st_mode) == 0o640 and
                  0 < node.st_size <= maximum, 'Billing station input has unsafe custody or exceeds its bound.')
        raw = source.read(maximum + 1)
        p.require(len(raw) == node.st_size, 'Billing station input changed while reading.')
        return raw


def mailbox(profile, role):
    return directory(STATION / ('requests' if role == 'courier' else 'responses'), profile[role + '_uid'], profile['gid'], 0o2750)


@contextmanager
def mailbox_lock(path, name='.lock'):
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(path / name, flags, 0o600), 'r+b') as stream:
        info = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                  stat.S_IMODE(info.st_mode) == 0o600, 'Billing station mailbox lock is unsafe.')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def store(path, raw, profile, role):
    stage = path.parent / '.staging'
    flags = os.O_CREAT | os.O_NOFOLLOW | os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(stage, flags, 0o600), 'wb') as stream:
        info = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                  (info.st_uid, info.st_gid) == (profile[role + '_uid'], profile['gid']) and
                  stat.S_IMODE(info.st_mode) in (0o600, 0o640), 'Billing station staging file is unsafe.')
        os.fchmod(stream.fileno(), 0o600)
        os.ftruncate(stream.fileno(), 0)
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o640)
        os.fsync(stream.fileno())
    stage.replace(path)
    sync_directory(path.parent)


def leaves(folder, suffix, now, *, prune=False):
    count = 0
    for path in folder.iterdir():
        if path.name in ('.lock', '.staging'):
            continue
        p.require(re.fullmatch(r'[0-9a-f]{64}\.' + suffix, path.name), 'Billing station mailbox contains an unowned entry.')
        count += 1
        p.require(count <= MAX_REQUESTS, 'Billing station mailbox exceeds its bound.')
        if now - path.lstat().st_mtime < RETENTION:
            yield path
        elif prune:
            path.unlink()
    if prune:
        sync_directory(folder)


def exact_request(profile, name, now):
    p.digest(name)
    path = mailbox(profile, 'courier') / (name + '.request')
    raw = station_read(path, billing.REVIEW_LIMIT, uid=profile['courier_uid'], gid=profile['gid'])
    p.require(p.sha256(raw) == name and now - path.lstat().st_mtime < RETENTION, 'The recorded billing request expired or differs.')
    return raw, read_request(raw, profile)


def current_response(profile, name, request, now):
    path = mailbox(profile, 'reviewer') / (name + '.response')
    if not os.path.lexists(path):
        return None
    raw = station_read(path, billing.BUNDLE_LIMIT, uid=profile['reviewer_uid'], gid=profile['gid'])
    bundle = billing.json_bundle(raw)
    review = bundle.get('review') if type(bundle) is dict else None
    if type(review) is dict and type(review.get('expires_unix')) is int and review['expires_unix'] <= now:
        return None
    verify_reply(profile, raw, request, now)
    return raw


def receive(profile, command, incoming, outgoing, now):
    p.require(os.getuid() == os.geteuid() == profile['courier_uid'], 'Use the dedicated billing SSH courier account.')
    selected = re.fullmatch(COMMAND + r' ([0-9a-f]{64})', command)
    p.require(selected, 'The dedicated billing account accepts only its fixed request protocol.')
    raw = incoming.read(billing.REVIEW_LIMIT + 1)
    request = read_request(raw, profile)
    name = p.sha256(raw)
    p.require(name == selected[1], 'Billing request transport digest differs.')
    folder = mailbox(profile, 'courier')
    with mailbox_lock(folder):
        active = set(leaves(folder, 'request', now, prune=True))
        leaf = folder / (name + '.request')
        if leaf not in active:
            p.require(len(active) < MAX_REQUESTS, 'Billing station mailbox is full.')
            store(leaf, raw, profile, 'courier')
        else:
            p.require(exact_request(profile, name, now)[0] == raw, 'Retained billing request differs.')
        response = current_response(profile, name, request, now)
    if response is not None:
        outgoing.write(response)


def verify_reply(profile, raw, request, now):
    review, signature = read_response(raw, request, now)
    with tempfile.TemporaryDirectory(prefix='billing-station-review-') as directory_name:
        directory_path = Path(directory_name)
        signers, signed = directory_path / 'allowed_signers', directory_path / 'review.sig'
        write_private(signers, f'{billing.PRINCIPAL} namespaces="{billing.NAMESPACE}" {profile["reviewer_key"]}\n'.encode())
        write_private(signed, signature.encode('ascii'))
        billing.openssh('verify', '-f', str(signers), '-I', billing.PRINCIPAL, '-n', billing.NAMESPACE,
                        '-s', str(signed), data=billing.canonical(review))


def publish(profile, name, raw, now):
    _, request = exact_request(profile, name, now)
    verify_reply(profile, raw, request, now)
    folder = mailbox(profile, 'reviewer')
    with mailbox_lock(folder):
        active = set(leaves(folder, 'response', now, prune=True))
        existing = current_response(profile, name, request, now)
        p.require(existing in (None, raw), 'An unexpired signed bundle already exists for this request.')
        leaf = folder / (name + '.response')
        if existing is None:
            p.require(leaf in active or len(active) < MAX_REQUESTS, 'Billing station response mailbox is full.')
            store(leaf, raw, profile, 'reviewer')


def verified_station_command(sha):
    from day0_access_station import protected

    p.digest(sha, 40)
    script = Path(__file__).resolve()
    root = script.parents[1]
    for path in (root, root / 'tools', root / '.git'):
        protected(path, directory=True)
    for parent in script.parents:
        p.require(parent.stat().st_mode & 0o001, 'The exact station checkout must be traversable by both billing accounts.')
    command = ['/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
               *candidate.GIT, '-C', str(root)]
    end = time.monotonic() + 20
    p.require(candidate.invoke([*command, 'rev-parse', '--verify', 'HEAD'], end, cap=128).strip() == sha.encode() and
              not candidate.invoke([*command, 'status', '--porcelain=v1', '--untracked-files=all'], end, cap=8192),
              'The station checkout differs from the exact reviewed source.')
    inventory = candidate.invoke([*command, 'ls-tree', '-r', '--full-tree', '-z', sha, '--', 'tools/'],
                                 end, cap=131072)
    tracked = set()
    for row in inventory.rstrip(b'\0').split(b'\0'):
        info, _, name = row.partition(b'\t')
        tracked.add(name.decode('ascii'))
        path = root / name.decode('ascii')
        p.require(info.startswith((b'100644 blob ', b'100755 blob ')) and protected(path).stat().st_mode & 0o004,
                  'The station checkout has a linked or unreadable tool.')
    p.require(all(path.relative_to(root).as_posix() in tracked for path in (root / 'tools').glob('*.py')),
              'The station checkout includes an untracked importable tool.')
    p.require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(script)), 'The protected station path cannot enter the fixed SSH command.')
    return f'/usr/bin/python3 -IB {script}'


def make_station_directory(path, uid, gid, mode):
    if not os.path.lexists(path):
        path.mkdir(mode=0o700)
    info = path.lstat()
    if stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700):
        p.require(not any(path.iterdir()), 'Existing root-held billing mailbox needs station administrator reconciliation.')
        os.chown(path, uid, gid)
        path.chmod(mode)
        sync_directory(path.parent)
    return directory(path, uid, gid, mode)


def station_init(args, app):
    from day0_access_station import (account, courier_authorization, protected, public_key, ssh_profile,
                                    station_location)

    p.digest(args.machine_sha256)
    p.digest(args.reviewer_epoch, 32)
    p.require(args.machine_sha256 != billing.machine_binding(), 'The billing station must be distinct from the selected VPS.')
    command = verified_station_command(args.source_sha)
    courier, reviewer = account(args.courier_user), account(args.reviewer_user)
    group = grp.getgrnam(args.group)
    members = set(group.gr_mem) | {row.pw_name for row in pwd.getpwall() if row.pw_gid == group.gr_gid}
    p.require(courier.pw_uid != reviewer.pw_uid and group.gr_gid > 0 and members == {courier.pw_name, reviewer.pw_name},
              'The billing mailbox group must contain only the separate courier and billing reviewer accounts.')
    p.require(set(os.getgrouplist(courier.pw_name, courier.pw_gid)) <= {courier.pw_gid, group.gr_gid},
              'The billing SSH courier must be a dedicated unprivileged account.')
    host, _ = contact(args.station_address, courier.pw_name)
    source, _ = contact(args.vps_address, courier.pw_name)
    p.require(ipaddress.ip_address(host).version == ipaddress.ip_address(source).version and host != source,
              'The billing courier requires a distinct approved VPS in the station’s address family.')
    station_location(host, args.tailnet, app)
    wire_key, wire_fingerprint = billing.reviewer_key(args.courier_key)
    review_key, review_fingerprint = billing.reviewer_key(args.reviewer_key)
    host_key = public_key(args.station_ssh_host_key)
    p.require(len({wire_key, review_key, host_key}) == 3 and wire_fingerprint == args.courier_fingerprint and
              review_fingerprint == args.reviewer_fingerprint and billing.reviewer_key(host_key)[1] == args.host_fingerprint,
              'The billing station, courier and reviewer require separate independently authenticated public keys.')
    native_access = Path('/etc/dev-pair/destination-observer/access-station.json')
    if os.path.lexists(native_access):
        prior = billing.json_bundle(billing.bounded_file(protected(native_access), 8192, owner=0))
        p.require(not {courier.pw_name, reviewer.pw_name} & {prior.get('courier_user'), prior.get('reviewer_user')} and
                  not {wire_key, review_key, host_key} & {prior.get('host_key'), prior.get('review_key')},
                  'The billing station requires separate accounts and keys from the access station.')
    home = Path(courier.pw_dir)
    p.require(home == Path('/var/lib') / courier.pw_name, 'Use a dedicated station-managed billing courier home under /var/lib.')
    protected(home.parent, directory=True)
    if not os.path.lexists(home):
        home.mkdir(mode=0o755)
        home.chmod(0o755)
    auth = courier_authorization(courier)
    ssh_profile(courier.pw_name, host, source, args.station_ssh_host_key, app)
    profile = {'schema': 1, 'source_sha': args.source_sha, 'machine_sha256': args.machine_sha256,
               'reviewer_epoch': args.reviewer_epoch, 'reviewer_key': review_key,
               'courier_uid': courier.pw_uid, 'reviewer_uid': reviewer.pw_uid, 'gid': group.gr_gid}
    scope = p.identity(binding(profile))
    line = f'restrict,from="{source}",command="{command} --scope {scope} receive" {wire_key}\n'
    old = None
    if os.path.lexists(auth):
        old = billing.bounded_file(protected(auth), 4096, owner=0, mode=0o644).decode('ascii')
        if old != line:
            retained = re.fullmatch(r'restrict,from="[a-fA-F0-9:.]+",command="' + re.escape(command) +
                                    r' --scope [0-9a-f]{64} receive" (ssh-ed25519 [A-Za-z0-9+/=]+)\n', old)
            p.require(retained and billing.reviewer_key(retained[1])[1] == args.replace_courier_fingerprint,
                      'Replacing a courier requires its exact independently confirmed old fingerprint.')
    protected(STATION.parent, directory=True)
    if not os.path.lexists(STATION):
        STATION.mkdir(mode=0o755)
        STATION.chmod(0o755)
    protected(STATION, directory=True)
    root = make_station_directory(STATION / scope, 0, group.gr_gid, 0o750)
    stored = root / 'profile.json'
    if os.path.lexists(stored):
        data = station_read(stored, 4096, uid=0, gid=group.gr_gid)
        p.require(data == billing.canonical(profile), 'Existing station scope belongs to different authority.')
    else:
        with tempfile.TemporaryDirectory(prefix='.profile-', dir=root) as temporary:
            staged = Path(temporary) / 'profile'
            write_private(staged, billing.canonical(profile))
            with staged.open('rb') as file:
                os.fchown(file.fileno(), 0, group.gr_gid)
                os.fchmod(file.fileno(), 0o640)
                os.fsync(file.fileno())
            staged.rename(stored)
        sync_directory(root)
    for name, user in (('requests', courier), ('responses', reviewer)):
        make_station_directory(root / name, user.pw_uid, group.gr_gid, 0o2750)
    if not os.path.lexists(auth.parent):
        auth.parent.mkdir(mode=0o755)
        auth.parent.chmod(0o755)
    app.atomic(str(auth), line, mode=0o644, expected=old)
    return scope


def setup_route(reference, ask, say):
    """Return (use an explicit offline path, signed response or None)."""
    profile = current_client()
    if profile is None:
        choice = ask('Independent billing handoff [station/offline/Enter to defer].').lower()
        p.require(choice in ('', 'station', 'offline'), 'Choose the dedicated billing station, offline handoff or defer.')
        if choice != 'station':
            return choice == 'offline', None
        profile = configure_client(ask, say)
        if profile is None:
            return False, None
    try:
        response = exchange(reference, profile)
    except Unavailable as pause:
        say(str(pause))
        show_enrollment(profile, say)
    else:
        if response is not None:
            return False, response
        say('The exact request is at the independent billing station.')
    return ask('Use the protected offline billing handoff now? [y/N]').lower() in ('y', 'yes'), None


def reviewer_action(profile, args, now):
    p.require(os.getuid() == os.geteuid() == profile['reviewer_uid'], 'Use the separately designated ordinary billing reviewer account.')
    if args.command == 'pending':
        for leaf in sorted(leaves(mailbox(profile, 'courier'), 'request', now)):
            raw, entry = exact_request(profile, leaf.stem, now)
            if current_response(profile, p.sha256(raw), entry, now) is None:
                print(leaf.stem)
        return
    if args.command == 'retrieve':
        raw, _ = exact_request(profile, args.request, now)
        write_private(args.output, raw)
        sync_directory(args.output.parent)
        return
    p.require(not sys.stdin.isatty(), 'Read the reviewed signed billing bundle from protected storage.')
    publish(profile, args.request, sys.stdin.buffer.read(billing.BUNDLE_LIMIT + 1), now)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope')
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('station-init')
    for field in ('source-sha', 'machine-sha256', 'reviewer-epoch', 'station-address', 'vps-address', 'tailnet',
                  'courier-user', 'reviewer-user', 'group', 'courier-key', 'courier-fingerprint', 'reviewer-key',
                  'reviewer-fingerprint', 'host-fingerprint'):
        setup.add_argument('--' + field, required=True)
    setup.add_argument('--station-ssh-host-key', type=Path, default=HOST_PUBLIC_KEY)
    setup.add_argument('--replace-courier-fingerprint')
    commands.add_parser('enroll')
    commands.add_parser('identity')
    commands.add_parser('receive')
    commands.add_parser('pending')
    retrieve = commands.add_parser('retrieve')
    retrieve.add_argument('request')
    retrieve.add_argument('--output', type=Path, required=True)
    send = commands.add_parser('publish')
    send.add_argument('request')
    return parser.parse_args()


def main():
    global STATION

    os.umask(0o077)
    args = cli()
    try:
        if args.command in ('station-init', 'enroll', 'identity'):
            p.require(os.getuid() == os.geteuid() == 0 and not os.environ.get('SUDO_USER') and args.scope is None,
                      'Use the dedicated protected commissioning terminal.')
            if args.command == 'station-init':
                with mailbox_lock(Path('/run'), 'dev-pair-billing-station.lock'):
                    print('Approved billing station scope ' + station_init(args, Bootstrap()))
            elif args.command == 'identity':
                profile = current_client()
                p.require(profile is not None, 'No current dedicated billing transport.')
                show_enrollment(profile, print)
            else:
                with open('/dev/tty', encoding='utf-8') as incoming, open('/dev/tty', 'w', encoding='utf-8') as outgoing:
                    def ask(prompt):
                        outgoing.write(prompt + ' ')
                        outgoing.flush()
                        answer = incoming.readline(1025)
                        p.require(len(answer) <= 1024 and answer.endswith('\n'), 'Billing enrollment answer was interrupted.')
                        return answer.strip()
                    configure_client(ask, lambda message: print(message, file=outgoing, flush=True))
            return 0
        p.digest(args.scope)
        STATION = STATION / args.scope
        profile = station_profile()
        p.require(p.identity(binding(profile)) == args.scope, 'Billing station scope differs from its approved binding.')
        if args.command == 'receive':
            signal.alarm(30)
            receive(profile, os.environ.get('SSH_ORIGINAL_COMMAND', ''), sys.stdin.buffer, sys.stdout.buffer, time.time())
        else:
            signal.alarm(120)
            reviewer_action(profile, args, time.time())
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        message = str(error) if type(error) in (ValueError, Blocked, Unavailable) else 'Verify the protected billing transport.'
        print(message, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
