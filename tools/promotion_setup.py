#!/usr/bin/python3
"""Commission the optional protected checklist promotion on one owner site."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import warnings

from bootstrap import Blocked, Commands
import checklist_proposal as proposal
import commission_host as commission
from destination_release import Destination
import job_protocol as p
from ledger_recovery import read_private, sync_directory, trusted_directory
from owner_intake import CHECKLIST, Intake
import product_release as release
from release_trust import ReleaseTrust
from renewal import replace_json

FEATURE = 'checklist-promotion'
ACCOUNT = 'account.json'
ENROLLMENT = 'enrollment.json'
WINDOW = 31 * 86400
EXTERNAL_ERRORS = (Blocked, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError)


def installed():
    return Path(__file__).absolute() == Path(commission.INSTALL) / 'tools/promotion_setup.py'


def exact_node(path, uid, gid, mode, *, directory=False):
    node = path.lstat()
    p.require((stat.S_ISDIR(node.st_mode) if directory else stat.S_ISREG(node.st_mode) and node.st_nlink == 1)
              and (node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)) == (uid, gid, mode),
              'protected promotion custody differs')
    return node


def directory(path, gid=0, mode=0o700, *, ancestry=0):
    commission.protected(path.parent, ancestry, directory=True)
    if not os.path.lexists(path):
        path.mkdir(mode=0o700)
    node = path.lstat()
    if stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and node.st_gid in (0, gid) and stat.S_IMODE(node.st_mode) == 0o700:
        os.chown(path, 0, gid)
        path.chmod(mode)
        sync_directory(path.parent)
    exact_node(path, 0, gid, mode, directory=True)
    return path


def write_once(path, raw, gid=None):
    mode = 0o600 if gid is None else 0o440
    gid = 0 if gid is None else gid
    commission.protected(path.parent, gid, directory=True)
    if not os.path.lexists(path):
        commission.Commission.publish_file(path, raw, mode)
    node = path.lstat()
    p.require(node.st_gid in (0, gid), 'retained promotion credential group differs')
    exact_node(path, 0, node.st_gid, mode)
    p.require(p.read_data(path, 4096) == raw, 'retained promotion custody differs from enrollment')
    if node.st_gid != gid:
        # An interrupted publication leaves group read restricted to root until the next enrollment finishes.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            node = os.fstat(stream.fileno())
            p.require((node.st_uid, node.st_gid, node.st_nlink) == (0, 0, 1) and
                      stream.read(len(raw) + 1) == raw, 'retained promotion credential changed')
            os.fchown(stream.fileno(), 0, gid)
            os.fsync(stream.fileno())
    exact_node(path, 0, gid, mode)


@contextmanager
def lock(name, *, shared=False):
    trusted_directory(release.SITE)
    path = release.SITE / name
    flags = os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o600), 'rb') as stream:
        exact_node(path, 0, 0, 0o600)
        fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        yield


def find_account(lookup, name):
    try:
        return lookup(name)
    except KeyError:
        return None


def account_record():
    record = p.loads(read_private(release.SITE / ACCOUNT, 1024))
    p.fields(record, 'version uid')
    p.number(record['version'], 1, 1)
    return p.number(record['uid'], 2500, 2599)


def account(uid):
    user = pwd.getpwnam(proposal.DEVELOPER)
    group = grp.getgrnam(proposal.DEVELOPER)
    p.require((user.pw_uid, user.pw_gid, group.gr_gid) == (uid, uid, uid) and not group.gr_mem and
              Path(user.pw_dir) == proposal.HOME and user.pw_shell == '/usr/sbin/nologin' and
              os.getgrouplist(proposal.DEVELOPER, uid) == [uid], 'dedicated nonlogin proposal account required')


def provision_account(run):
    name = proposal.DEVELOPER
    existing_user = find_account(pwd.getpwnam, name)
    existing_group = find_account(grp.getgrnam, name)
    selected = release.SITE / ACCOUNT
    if not os.path.lexists(selected):
        p.require(existing_user is None and existing_group is None and not os.path.lexists(proposal.ROOT),
                  'the existing proposal account or path is outside this enrollment')
        uid = next((value for value in range(2500, 2600)
                    if find_account(pwd.getpwuid, value) is None and find_account(grp.getgrgid, value) is None), None)
        p.require(uid is not None, 'no available isolated proposal account ID')
        write_once(selected, commission.encoded({'version': 1, 'uid': uid}))
    uid = account_record()
    if existing_group is None:
        run('/usr/sbin/groupadd', '--system', '--gid', str(uid), name, timeout=15)
    p.require(grp.getgrnam(name).gr_gid == uid, 'proposal group differs from its recorded allocation')
    if existing_user is None:
        run('/usr/sbin/useradd', '--system', '--no-user-group', '--no-create-home', '--no-log-init', '--uid', str(uid),
            '--gid', str(uid), '--home-dir', str(proposal.HOME), '--shell', '/usr/sbin/nologin', name, timeout=15)
    account(uid)
    p.require(run('/usr/bin/passwd', '--status', name, timeout=10).split()[1] in {'L', 'LK'},
              'the dedicated proposal password must remain locked')
    directory(proposal.ROOT, gid=uid, mode=0o750)
    directory(proposal.INBOX, gid=uid, mode=0o750, ancestry=uid)
    directory(proposal.CREDENTIALS, gid=uid, mode=0o750, ancestry=uid)
    if not os.path.ismount(proposal.HOME):
        directory(proposal.HOME, ancestry=uid)
    directory(release.EVIDENCE)
    run('/usr/sbin/restorecon', '-F', str(proposal.ROOT), str(proposal.INBOX), str(proposal.CREDENTIALS),
        str(release.EVIDENCE), timeout=15)
    return uid


def files(site, fork, upstream, observer, registry):
    values = {release.SITE / 'policy.json': commission.encoded(site), release.SITE / 'read.token': observer.encode() + b'\n',
              proposal.CREDENTIALS / 'fork.token': fork.encode() + b'\n',
              proposal.CREDENTIALS / 'upstream-pr.token': upstream.encode() + b'\n'}
    if registry is not None:
        values[release.SITE / 'registry/config.json'] = registry
    return values


def trust_identity():
    rules = ReleaseTrust().policy('checklist')
    return p.identity({'reviewer_ids': sorted(rules['reviewer_ids']), 'check': rules['check'],
                       'publisher': rules['components']['checklist'], 'writer_app_id': rules['writer_app_id']})


def enrollment():
    result = p.loads(read_private(release.SITE / ENROLLMENT, 4096))
    p.fields(result, 'version state dns_name expires_unix trust_sha256 files')
    p.number(result['version'], 1, 1)
    p.require(result['state'] in ('staging', 'active', 'withdrawing', 'withdrawn'), 'promotion enrollment state differs')
    release.dns_name(result['dns_name'])
    p.number(result['expires_unix'], 1, 2**63 - 1)
    p.digest(result['trust_sha256'])
    keys = set(map(str, files({}, '', '', '', None)))
    p.require(set(result['files']) in (keys, keys | {str(release.SITE / 'registry/config.json')}),
              'promotion enrollment file set differs')
    for value in result['files'].values():
        p.digest(value)
    return result


def custody_reason(policy_path):
    try:
        saved = enrollment()
    except FileNotFoundError:
        if not installed() and policy_path.is_file():
            return None  # Keep the separately commissioned standalone controller readable.
        return 'protected-promotion-custody-missing'
    except (OSError, ValueError, KeyError, TypeError):
        return 'protected-promotion-custody-unavailable'
    if saved['state'] in ('withdrawing', 'withdrawn'):
        return 'protected-promotion-withdrawn'
    if saved['state'] == 'staging':
        return 'protected-promotion-enrollment-incomplete'
    if saved['expires_unix'] <= time.time():
        return 'scoped-release-grant-expired'
    return None if policy_path.is_file() else 'protected-promotion-custody-missing'


def file_bytes(path, uid, expected, *, withdrawing=False):
    role = path.parent == proposal.CREDENTIALS
    p.require(not role or uid is not None, 'proposal credential lacks its enrolled account')
    group, mode = (uid, 0o440) if role else (0, 0o600)
    commission.protected(path.parent, group, directory=True)
    if withdrawing and path.lstat().st_gid == 0:
        group = 0
    exact_node(path, 0, group, mode)
    raw = p.read_data(path, 4096)
    p.require(p.sha256(raw) == expected, 'a protected promotion enrollment file changed')
    return raw


def runtime_grant(selected):
    saved = enrollment()
    p.require(saved['state'] == 'active' and 0 < saved['expires_unix'] - time.time() <= WINDOW and
              saved['trust_sha256'] == trust_identity() and catalogue_dns() == saved['dns_name'],
              'current attended promotion enrollment is unavailable')
    uid = account_record()
    account(uid)
    release.root_directory(proposal.ROOT, uid, 0o750)
    release.root_directory(proposal.INBOX, uid, 0o750)
    exact_node(proposal.CREDENTIALS, 0, uid, 0o750, directory=True)
    for name, expected in saved['files'].items():
        file_bytes(Path(name), uid, expected)
    optional_registry = release.SITE / 'registry/config.json'
    p.require(os.path.lexists(optional_registry) == (str(optional_registry) in saved['files']),
              'registry credential is outside promotion enrollment')
    return {'subject': FEATURE, 'expires_unix': saved['expires_unix'], 'sha256': p.identity([selected, saved])}


def catalogue_dns():
    rows, _ = Intake().catalogue_settings()
    site = rows[proposal.REPOSITORY]
    p.require(CHECKLIST in site.get('workloads', [CHECKLIST]), 'owner catalogue lacks the approved checklist')
    return release.dns_name(site['destination'])


def destination_preflight(name):
    with Destination().release_gate() as (_, _, observed):
        p.require(observed == name, 'the protected destination differs from the owner checklist catalogue')


def observed_policy(approval, fork, upstream, observer, end):
    p.require(len({fork, upstream, observer}) == 3, 'fork write, upstream pull request and observer credentials must be separate')
    fork_hub, upstream_hub, observer_hub = (proposal.Hub(secret, end) for secret in (fork, upstream, observer))
    developer, reader = fork_hub.get('user'), observer_hub.get('user')
    p.require(developer['login'] == approval['developer_login'] and reader['login'] == approval['observer_login'],
              'the enrolled GitHub identities differ from the approved logins')
    proposal.scoped_permissions(fork_hub, upstream_hub, approval['fork'], developer['id'])
    actor_id = approval['merge_actor_id']
    actor = observer_hub.get('user/' + str(actor_id))
    p.require(actor['id'] == actor_id, 'the separate upstream merge identity is unavailable')
    site = {key: approval[key] for key in ('developer_login', 'fork', 'merge_actor_id', 'merge_gate_app_id',
                                           'merge_workflow_sha256', 'dns_name', 'expires_unix')}
    return release.policy(commission.encoded(dict(site, version=1, repository=proposal.REPOSITORY,
                                                  developer_id=developer['id'], observer_id=reader['id'])))


def remote_preflight(site, observer, end):
    hub = proposal.Hub(observer, end)
    trust, rules = release.trusted_release(site, hub)
    p.require(hub.get('repos/' + proposal.REPOSITORY)['allow_merge_commit'] is True,
              'the upstream repository must allow the independently gated merge commit')
    base = trust.api('branches/main')['commit']['sha']
    p.digest(base, 40)
    release.protected_upstream(trust, site, rules, base)
    publisher = rules['components']['checklist']
    trust.workflow(publisher['workflow'], base, publisher['sha256'])


def verify_tools():
    for binary in (proposal.GIT, proposal.GH, '/usr/bin/skopeo', '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/findmnt'):
        path = Path(binary).resolve(strict=True)
        commission.protected(path, 0)
        p.require(os.access(path, os.X_OK), 'a required signed host promotion tool is unavailable')
    end = time.monotonic() + 20
    flags = proposal.capture([proposal.GH, 'attestation', 'verify', '--help'], end)
    p.require(all(flag in flags for flag in (b'--source-digest', b'--signer-digest', b'--deny-self-hosted-runners')) and
              b'--slurp' in proposal.capture([proposal.GH, 'api', '--help'], end),
              'the host GitHub CLI lacks exact attestation or paginated read support')


def install_registry_tool(run):
    if not os.path.lexists('/usr/bin/skopeo'):
        run('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--setopt=install_weak_deps=False', '--disablerepo=*',
            '--enablerepo=fedora', '--enablerepo=updates', 'install', 'skopeo', timeout=240)


def verify_scratch_mount(run, uid):
    mount = run('/usr/bin/findmnt', '-n', '-o', 'SOURCE,FSTYPE', '--mountpoint', str(proposal.HOME), timeout=10).split()
    p.require(mount == ['dev-pair-release-scratch', 'tmpfs'], 'the proposal scratch mount is outside this enrollment')
    exact_node(proposal.HOME, uid, uid, 0o700, directory=True)


@contextmanager
def scratch(run, uid):
    with lock('.scratch.lock'):
        home = proposal.HOME
        if not os.path.ismount(home):
            exact_node(home, 0, 0, 0o700, directory=True)
            p.require(not any(home.iterdir()), 'the underlying proposal scratch path is not empty')
            run('/usr/bin/mount', '-t', 'tmpfs', '-o', f'nodev,nosuid,noexec,size=256M,nr_inodes=8192,mode=0700,uid={uid},gid={uid}',
                'dev-pair-release-scratch', str(home), timeout=15)
        verify_scratch_mount(run, uid)
        try:
            run('/usr/sbin/restorecon', '-F', str(home), timeout=15)
            from checklist_candidate import as_role
            argv = as_role(proposal.DEVELOPER, proposal.PYTHON, '-EBs', '-c',
                           'import sys; sys.path.insert(0, sys.argv[1]); import checklist_proposal as p; p.scratch_directory()',
                           str(Path(__file__).parent))
            proposal.capture(argv, time.monotonic() + 15)
            yield
        finally:
            run('/usr/bin/umount', str(home), timeout=15)


@contextmanager
def installed_scratch():
    if installed():
        with scratch(Commands(), account_record()):
            yield
    else:
        yield


@contextmanager
def execution():
    if installed():
        with lock('.custody.lock', shared=True):
            commission.require_installed_workload(FEATURE)
            yield
    else:
        yield


def enroll(site, fork, upstream, observer, registry, run):
    p.require(0 < site['expires_unix'] - time.time() <= WINDOW, 'the approved release grant expired during enrollment')
    commission.protected(release.SITE.parent, 0, directory=True)
    directory(release.SITE)
    with lock('.custody.lock'):
        record = release.SITE / ENROLLMENT
        values = files(site, fork, upstream, observer, registry)
        intent = {'version': 1, 'state': 'staging', 'dns_name': site['dns_name'], 'expires_unix': site['expires_unix'],
                  'trust_sha256': trust_identity(), 'files': {str(path): p.sha256(raw) for path, raw in values.items()}}
        if os.path.lexists(record):
            prior = enrollment()
            p.require(prior['state'] == 'withdrawn' or prior == intent or prior == {**intent, 'state': 'active'},
                      'withdraw the previous promotion enrollment before replacing its authority')
            if prior == {**intent, 'state': 'active'}:
                runtime_grant('already-enrolled')
                return
            if prior['state'] == 'withdrawn':
                replace_json(record, intent)
        else:
            p.require(not any(os.path.lexists(path) for path in values) and
                      not os.path.lexists(release.SITE / 'registry/config.json'),
                      'existing manual promotion custody requires independent reconciliation')
            write_once(record, commission.encoded(intent))
        uid = provision_account(run)
        with scratch(run, uid):
            pass
        if registry is not None:
            directory(release.SITE / 'registry')
        for path, raw in values.items():
            write_once(path, raw, uid if path.parent == proposal.CREDENTIALS else None)
        run('/usr/sbin/restorecon', '-F', *map(str, values), timeout=20)
        p.require(site['expires_unix'] > time.time(), 'the approved release grant expired during enrollment')
        replace_json(record, {**intent, 'state': 'active'})
        runtime_grant('enrolled')


def withdraw():
    if not os.path.lexists(release.SITE / ENROLLMENT):
        return
    with lock('.custody.lock'):
        saved = enrollment()
        if saved['state'] == 'withdrawn':
            return
        record = release.SITE / ENROLLMENT
        replace_json(record, {**saved, 'state': 'withdrawing'})
        # The runtime lock is exclusive, and new scan and advance calls now see a held enrollment.
        uid = account_record() if os.path.lexists(release.SITE / ACCOUNT) else None
        for name, expected in saved['files'].items():
            path = Path(name)
            if os.path.lexists(path):
                file_bytes(path, uid, expected, withdrawing=True)
                path.unlink()
                sync_directory(path.parent)
        if uid is not None and os.path.ismount(proposal.HOME):
            with lock('.scratch.lock'):
                run = Commands()
                verify_scratch_mount(run, uid)
                run('/usr/bin/umount', str(proposal.HOME), timeout=15)
        replace_json(record, {**saved, 'state': 'withdrawn'})
    # Commission's existing owned-timer withdrawal handles the signed unit on the next normal apply.


def answer(tty, label, *, secret=False):
    if secret:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass(label + ' ', stream=tty.outgoing)
        p.require(len(value) <= 512, 'promotion credential exceeds its bound')
        return value
    tty.outgoing.write(label + ' ')
    tty.outgoing.flush()
    value = tty.incoming.readline(1025)
    p.require(value.endswith('\n') and len(value) <= 1024, 'promotion answer was interrupted or too long')
    return value.strip()


def expiry(value):
    p.require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z', value), 'enter the exact UTC grant expiry')
    stamp = int(datetime.strptime(value, '%Y-%m-%dT%H:%MZ').replace(tzinfo=timezone.utc).timestamp())
    p.require(0 < stamp - time.time() <= WINDOW, 'the approved release grant must expire within 31 days')
    return stamp


def registry_config(login, secret):
    p.require(re.fullmatch(proposal.LOGIN, login) and re.fullmatch(r'(?:ghp_|github_pat_)[A-Za-z0-9_]{30,250}', secret),
              'use a separate scoped GHCR pull credential')
    return commission.encoded({'auths': {'ghcr.io': {'auth': base64.b64encode((login + ':' + secret).encode()).decode()}}})


def attended():
    run = Commands()
    with (open('/dev/tty', 'r', encoding='utf-8') as incoming,
          open('/dev/tty', 'w', encoding='utf-8', buffering=1) as outgoing):
        tty = SimpleNamespace(incoming=incoming, outgoing=outgoing)
        if answer(tty, 'Enroll optional protected checklist promotion? Type yes or press Enter to defer.').lower() != 'yes':
            return False
        install_registry_tool(run)
        verify_tools()
        dns = catalogue_dns()
        destination_preflight(dns)
        approval = {'dns_name': dns, 'fork': answer(tty, 'Independently approved fork (owner/dev-pair):'),
                    'developer_login': answer(tty, 'Approved GitHub proposer login:'),
                    'observer_login': answer(tty, 'Approved read-only GitHub observer login:'),
                    'merge_actor_id': int(answer(tty, 'Approved separate GitHub merge actor numeric ID:')),
                    'merge_gate_app_id': int(answer(tty, 'Approved merge-protection App numeric ID:')),
                    'merge_workflow_sha256': answer(tty, 'Approved checklist merge workflow SHA-256:'),
                    'expires_unix': expiry(answer(tty, 'Approved grant expiry (YYYY-MM-DDTHH:MMZ):'))}
        proposal.developer_scope(approval['developer_login'], approval['fork'])
        p.require(re.fullmatch(proposal.LOGIN, approval['observer_login']), 'exact GitHub observer login required')
        p.number(approval['merge_actor_id'], 1, 2**63 - 1)
        p.number(approval['merge_gate_app_id'], 1, 2**63 - 1)
        p.digest(approval['merge_workflow_sha256'])
        fork, upstream, observer = (proposal.token(answer(tty, label, secret=True).encode()) for label in (
            'Proposer token with write access to the approved fork:',
            'Separate same-proposer token with upstream pull request access and read-only contents:',
            'Separate upstream observer token with read permissions:'))
        login = answer(tty, 'Approved GHCR pull login, or press Enter for anonymous registry reads:')
        registry = None
        if login:
            pull = answer(tty, 'Separate GHCR pull-only token:', secret=True)
            p.require(pull not in (fork, upstream, observer), 'the private GHCR grant must be separately scoped')
            registry = registry_config(login, pull)
        end = time.monotonic() + 180
        site = observed_policy(approval, fork, upstream, observer, end)
        remote_preflight(site, observer, end)
        scope = f"Enable scoped promotion from {site['fork']} to {site['repository']} and https://{dns}/? Type yes."
        if answer(tty, scope).lower() != 'yes':
            return False
        enroll(site, fork, upstream, observer, registry, run)
        return True


def evidence_envelope(job):
    release.product.job_path(job)  # Validate the exact protected job ID before selecting a leaf.
    return release.EVIDENCE / (job + '.envelope')


@contextmanager
def proof_files(payload, signature):
    with tempfile.TemporaryDirectory(prefix='proof-', dir=trusted_directory(release.EVIDENCE)) as temporary:
        receipt = Path(temporary) / 'receipt.json'
        receipt.write_bytes(payload)
        receipt.with_suffix('.json.sig').write_bytes(signature)
        yield receipt


def import_evidence(job, stream):
    from destination_observation import access_envelope, export_release, read_access_envelope

    payload, signature = read_access_envelope(stream)
    p.require(len(signature) <= 8192, 'destination signature exceeds its protected bound')
    envelope = p.loads(access_envelope(payload, signature))
    target = evidence_envelope(job)
    root = trusted_directory(release.product.job_path(job))
    with release.job_lock(root):
        existing = p.loads(read_private(target, p.MAX_MESSAGE)) if os.path.lexists(target) else None
        replay = existing == envelope
        binding = export_release(job, confirmed_receipt=p.sha256(payload) if replay else None)
        if replay and release.record(root)['phase'] == 'confirmed':
            return  # The current settled J/D records already bind these exact independently verified bytes.
        with proof_files(payload, signature) as receipt:
            Destination().release_proof(str(receipt), binding)
        if not replay:
            replace_json(target, envelope)


def stored_proof(path):
    from io import BytesIO
    from destination_observation import read_access_envelope

    payload, signature = read_access_envelope(BytesIO(read_private(path, p.MAX_MESSAGE)))
    expiry = p.loads(payload)['expires_at']
    p.require(type(expiry) is int, 'independent destination proof expiry is invalid')
    if expiry <= time.time():
        raise release.Wait('signed-destination-evidence-expired')
    return payload, signature


def confirm_envelope(destination, path, *, job_id):
    payload, signature = stored_proof(path)
    with proof_files(payload, signature) as receipt:
        return destination.confirm(str(receipt), job_id=job_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='operation', required=True)
    actions.add_parser('enroll', help='attended setup with independently approved scoped inputs')
    actions.add_parser('withdraw', help='remove enrolled local credentials and hold future promotions')
    actions.add_parser('import-proof', help='accept the bounded, independently signed proof envelope from standard input').add_argument('job')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        p.require(installed() and os.getuid() == os.geteuid() == 0, 'use the exact installed root promotion command')
        commission.protected(Path(__file__).absolute(), 0)
        if args.operation == 'enroll':
            return 0 if attended() else 3
        if args.operation == 'withdraw':
            withdraw()
            print('Promotion custody is withdrawn. Resume Day 0 to retire the owned schedule.')
        else:
            with lock('.custody.lock', shared=True):
                p.require(enrollment()['state'] == 'active', 'the checklist promotion enrollment is held')
                import_evidence(args.job, sys.stdin.buffer)
            print('The independently signed proof was received for normal destination verification.')
    except BlockingIOError:
        print('A protected promotion operation is in progress. Retry after it settles.', file=sys.stderr)
        return 2
    except (*EXTERNAL_ERRORS, commission.Blocked, EOFError, getpass.GetPassWarning) as exc:
        print('Checklist promotion setup is held. ' + (str(exc) if type(exc) in (Blocked, commission.Blocked, ValueError)
                                                      else 'A required protected observation is unavailable.'), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
