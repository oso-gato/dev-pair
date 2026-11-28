#!/usr/bin/python3
"""Prepare and import separately approved first-host release trust."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from bootstrap import Blocked, Commands, relay
from ledger_recovery import read_private, sync_directory, write_private
from release_trust import (
    COMPONENTS, DIGEST, GITHUB, POLICY, REPOSITORY, SHA, ReleaseTrust, base_policy, canonical, protect, require,
)

FIRST_TRUST = POLICY.with_name('first-release-authority.json')
GITHUB_CONFIG = Path('/root/.config/gh')
LIMIT = 16384
GATE = '.github/workflows/release-check.yml'
PLATFORM = '.github/workflows/platform-release.yml'
CHECKLIST = '.github/workflows/checklist-release.yml'
REFRESH = '.github/workflows/agent-refresh.yml'
WORKFLOWS = (GATE, PLATFORM, CHECKLIST, REFRESH)
CHECK_NAME = 'release-source-check'
CHECKLIST_REGISTRY = 'ghcr.io/oso-gato/dev-pair/checklist'
LOGIN = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?'
MACHINE = r'[0-9a-f]{32}'
READ_SECONDS = 150


def encode(value):
    return canonical(value).encode() + b'\n'


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), 'first release authority fields differ')


def positive(value):
    return type(value) is int and 0 < value < 2**63


def match(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def identity(value):
    fields(value, 'id login')
    require(positive(value['id']) and match(LOGIN, value['login']), 'GitHub principal identity is invalid')
    return value


def scope(source, machine):
    require(match(SHA, source) and match(MACHINE, machine), 'exact reviewed source and destination machine required')


def review_record(value):
    fields(value, 'pull_request review_head reviews check_run tested_merge source_tree check_workflow_revision')
    require(all(positive(value[name]) for name in ('pull_request', 'check_run')) and
            all(match(SHA, value[name]) for name in ('review_head', 'tested_merge', 'source_tree', 'check_workflow_revision')) and
            type(value['reviews']) is list and 0 < len(value['reviews']) <= 32 and all(map(positive, value['reviews']))
            and value['reviews'] == sorted(set(value['reviews'])), 'exact independent review and trusted check evidence required')


def policy_for(hashes, reviewer_ids, check_app, writer_app, base):
    platform = {'workflow': PLATFORM, 'registry': None, 'sha256': hashes[PLATFORM]}
    checklist = {'workflow': CHECKLIST, 'registry': CHECKLIST_REGISTRY, 'sha256': hashes[CHECKLIST], 'base': base}
    refresh = {'workflow': REFRESH, 'sha256': hashes[REFRESH]}
    publishers = {role: platform for role in ('host', 'devbox')}
    publishers.update({role: {**platform, 'agent_refresh': refresh} for role in ('maintenance', 'development')})
    return {'version': 1, 'reviewer_ids': sorted(reviewer_ids), 'writer_app_id': writer_app,
            'check': {'context': CHECK_NAME, 'app_id': check_app, 'workflow': GATE, 'sha256': hashes[GATE]},
            'components': {'checklist': checklist, **publishers}}


def base_proof(value, base):
    fields(value, 'version policy invocation')
    run = r'https://github\.com/' + re.escape(base['repo']) + r'/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*'
    require(type(value['version']) is int and value['version'] == 1 and value['policy'] == base
            and match(run, value['invocation']), 'upstream checklist base verification evidence differs')
    return value


def decode(raw, source, machine):
    scope(source, machine)
    value = json.loads(raw, object_pairs_hook=relay.unique)
    fields(value, 'schema repository source_sha machine_id policy workflow_ids review base_proof read')
    require(0 < len(raw) <= LIMIT and raw == encode(value) and type(value['schema']) is int and value['schema'] == 1
            and (value['repository'], value['source_sha'], value['machine_id']) == (REPOSITORY, source, machine),
            'first release authority differs from the selected machine or source')
    policy = value['policy']
    for component in COMPONENTS:
        ReleaseTrust.validate_policy(policy, component)
    publisher = policy['components']
    hashes = {GATE: policy['check']['sha256'], PLATFORM: publisher['host']['sha256'],
              CHECKLIST: publisher['checklist']['sha256'], REFRESH: publisher['maintenance']['agent_refresh']['sha256']}
    base = publisher['checklist']['base']
    require(positive(policy['writer_app_id']) and policy == policy_for(
            hashes, policy['reviewer_ids'], policy['check']['app_id'], policy['writer_app_id'], base),
            'the authorized release gate or publisher paths differ')
    workflows = value['workflow_ids']
    require(type(workflows) is dict and set(workflows) == set(WORKFLOWS) and all(map(positive, workflows.values()))
            and len(set(workflows.values())) == len(WORKFLOWS), 'exact GitHub publisher workflow IDs required')
    review_record(value['review'])
    base_proof(value['base_proof'], base)
    read = value['read']
    fields(read, 'principal token_sha256')
    require(identity(read['principal'])['id'] not in policy['reviewer_ids'] and match(DIGEST, read['token_sha256']),
            'dedicated GitHub read custody differs from the approved release authority')
    return value


def fine_grained(raw):
    require(len(raw) <= 262, 'bounded GitHub read credential required')
    raw = raw.removesuffix(b'\n')
    require(re.fullmatch(rb'github_pat_[A-Za-z0-9_]{30,250}', raw), 'an independently issued fine-grained GitHub token is required')
    return raw


def hosts_document(principal, token):
    login = principal['login']
    secret = token.decode('ascii')
    return encode({'github.com': {'user': login, 'git_protocol': 'https', 'oauth_token': secret,
                                  'users': {login: {'oauth_token': secret}}}})


class GitHubRead:
    def __init__(self, config, end, commands=None):
        self.config, self.end = config, end
        self.commands = commands or Commands()
        self.trust = ReleaseTrust(self.run)

    def run(self, *args, timeout):
        seconds = min(timeout, self.end - time.monotonic())
        require(seconds > 0, 'first release authority observation exceeded its deadline')
        require(args[:1] == (GITHUB,) and '--hostname' in args and
                args[args.index('--hostname') + 1] == 'github.com' and
                (args[1:3] == ('attestation', 'verify') or args[1] == 'api' and '-X' in args
                 and args[args.index('-X') + 1] == 'GET' and
                 not {'-f', '-F', '--field', '--raw-field', '--input', '--method'}.intersection(args)),
                'release custody supports fixed read-only GitHub requests')
        return self.commands('/usr/bin/env', '-i', 'PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8',
                             'HOME=' + str(self.config), 'GH_CONFIG_DIR=' + str(self.config), 'GH_HOST=github.com',
                             'GH_PROMPT_DISABLED=1', 'GH_NO_UPDATE_NOTIFIER=1', *args, timeout=seconds)

    def user(self, endpoint):
        data = json.loads(self.run(GITHUB, 'api', '--hostname', 'github.com', '-X', 'GET', endpoint, timeout=15),
                          object_pairs_hook=relay.unique)
        require(data['type'] == 'User', 'release custody requires the approved dedicated GitHub identity')
        return identity({'id': data['id'], 'login': data['login']})

    def workflow_ids(self):
        result = {}
        for workflow in WORKFLOWS:
            record = self.trust.api('actions/workflows/' + Path(workflow).name)
            require(record['path'] == workflow and record['state'] == 'active' and positive(record['id']),
                    'required release workflow is unavailable')
            result[workflow] = record['id']
        return result

    def observe(self, source, policy):
        review = self.trust.review(source, policy)
        self.trust.checklist_environment(policy['writer_app_id'])
        workflow_ids = self.workflow_ids()
        artifacts = self.trust.api('actions/artifacts?per_page=1')
        require(type(artifacts['artifacts']) is list and len(artifacts['artifacts']) <= 1,
                'the approved read identity cannot observe release artifact metadata')
        publishers = policy['components']
        for publisher in (publishers['checklist'], publishers['host'], publishers['maintenance']['agent_refresh']):
            self.trust.workflow(publisher['workflow'], source, publisher['sha256'])
        self.trust.main(source)
        return review, workflow_ids


@contextmanager
def staged_read(login, token, *, root=None):
    with tempfile.TemporaryDirectory(prefix='dev-pair-release-read-', dir=root) as work:
        path = Path(work)
        write_private(path / 'hosts.yml', hosts_document({'login': login}, token))
        yield path


def prepare(source, machine, reviewer_logins, check_app, writer_app, base, login, token):
    scope(source, machine)
    require(1 <= len(reviewer_logins) <= 32 and all(match(LOGIN, entry) for entry in reviewer_logins)
            and match(LOGIN, login) and positive(check_app) and positive(writer_app),
            'independently authorized reviewer, gate and read principal inputs are required')
    base = base_policy(base)
    with staged_read(login, token) as config:
        hub = GitHubRead(config, time.monotonic() + READ_SECONDS)
        principal = hub.user('user')
        require(principal['login'] == login, 'read token belongs to a different GitHub principal')
        reviewers = [hub.user('users/' + name) for name in reviewer_logins]
        require([reviewer['login'] for reviewer in reviewers] == reviewer_logins and
                len({reviewer['id'] for reviewer in reviewers}) == len(reviewers) and
                principal['id'] not in {reviewer['id'] for reviewer in reviewers},
                'read custody and independent reviewers must identify distinct approved GitHub users')
        hashes = {workflow: hub.trust.workflow_hash(workflow, source) for workflow in WORKFLOWS}
        policy = policy_for(hashes, [reviewer['id'] for reviewer in reviewers], check_app, writer_app, base)
        review, workflow_ids = hub.observe(source, policy)
        proof = hub.trust.verify_base(base)
        hub.trust.main(source)
    raw = encode({'schema': 1, 'repository': REPOSITORY, 'source_sha': source, 'machine_id': machine,
                  'policy': policy, 'workflow_ids': workflow_ids, 'review': review, 'base_proof': proof,
                  'read': {'principal': principal, 'token_sha256': fingerprint(token)}})
    decode(raw, source, machine)
    return raw


def private_bytes(path, bound=LIMIT):
    protect(path)
    require(path.lstat().st_gid == 0, 'release custody requires root-private group ownership')
    return read_private(path, bound)


def private_publish(path, data):
    from commission_host import Commission

    protect(path.parent, directory=True)
    if not os.path.lexists(path):
        Commission.publish_file(path, data, 0o600)
    require(private_bytes(path) == data, 'existing protected release custody differs from the approved bytes')
    sync_directory(path.parent)


def installed(source, machine, *, finish=False, authority=None, policy=None):
    authority = FIRST_TRUST if authority is None else authority
    policy = POLICY if policy is None else policy
    if not os.path.lexists(authority):
        return None
    grant = decode(private_bytes(authority), source, machine)
    expected = encode(grant['policy'])
    if finish:
        private_publish(policy, expected)
    elif os.path.lexists(policy):
        require(private_bytes(policy) == expected, 'installed release trust differs from its first-host handoff')
    return grant


def install_handoff(path, digest, source, machine, *, authority=None, policy=None):
    authority = FIRST_TRUST if authority is None else authority
    policy = POLICY if policy is None else policy
    require(match(DIGEST, digest), 'supply the fingerprint obtained independently from the release custodian')
    raw = private_bytes(path)
    require(fingerprint(raw) == digest, 'release handoff differs from the independently received fingerprint')
    grant = decode(raw, source, machine)
    if os.path.lexists(policy):
        require(private_bytes(policy) == encode(grant['policy']), 'existing protected release trust conflicts with the handoff')
    private_publish(authority, raw)
    installed(source, machine, finish=True, authority=authority, policy=policy)


def registered_read(grant, credential):
    raw = private_bytes(credential)
    data = json.loads(raw, object_pairs_hook=relay.unique)['github.com']
    reader = grant['read']
    token = fine_grained(data['oauth_token'].encode('ascii'))
    require(fingerprint(token) == reader['token_sha256'] and raw == hosts_document(reader['principal'], token),
            'GitHub custody differs from the independently authorized read credential')


def github_prerequisite():
    binary = Path(GITHUB)
    if not os.path.lexists(binary):
        Commands()('/usr/bin/dnf', '-y', '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '--disablerepo=*',
                   '--enablerepo=fedora', '--enablerepo=updates', 'install', 'gh', timeout=180)
    require(os.access(protect(binary), os.X_OK), 'signed Fedora GitHub CLI is unavailable')


def register_read(source, machine, path, *, config=None):
    grant = installed(source, machine, finish=True)
    require(grant is not None, 'install the independent first release handoff before registering its read credential')
    token = fine_grained(private_bytes(path, 512))
    approved = grant['read']
    require(fingerprint(token) == approved['token_sha256'], 'GitHub credential differs from the independently authorized read token')
    github_prerequisite()
    config = GITHUB_CONFIG if config is None else config
    credential = config / 'hosts.yml'
    if os.path.lexists(credential):
        registered_read(grant, credential)
        return
    with staged_read(approved['principal']['login'], token, root='/run') as stage:
        hub = GitHubRead(stage, time.monotonic() + READ_SECONDS)
        require(hub.user('user') == approved['principal'], 'read token belongs to a different GitHub identity')
        _, workflows = hub.observe(source, grant['policy'])
        require(workflows == grant['workflow_ids'], 'GitHub release workflow identity changed after the authority handoff')
    for directory in (config.parent, config):
        protect(directory.parent, directory=True)
        if not os.path.lexists(directory):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            sync_directory(directory.parent)
        protect(directory, directory=True)
    require(config.stat().st_gid == 0 and stat.S_IMODE(config.stat().st_mode) == 0o700,
            'the GitHub read configuration requires a root-private directory')
    private_publish(credential, hosts_document(approved['principal'], token))
    registered_read(grant, credential)


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    custodian = actions.add_parser('prepare', help='independent release custodian only')
    custodian.add_argument('--source-sha', required=True)
    custodian.add_argument('--machine-id', required=True)
    custodian.add_argument('--reviewer', action='append', required=True)
    custodian.add_argument('--check-app-id', type=int, required=True)
    custodian.add_argument('--writer-app-id', type=int, required=True)
    custodian.add_argument('--read-principal', required=True)
    custodian.add_argument('--token-file', type=Path, required=True)
    for key in ('image', 'repo', 'workflow', 'source', 'ref'):
        custodian.add_argument('--base-' + key, required=True)
    custodian.add_argument('--output', type=Path, required=True)
    install = actions.add_parser('install', help='install the custodian’s handoff on the protected host')
    install.add_argument('--source-sha', required=True)
    install.add_argument('--handoff', type=Path, required=True)
    install.add_argument('--sha256', required=True)
    register = actions.add_parser('register-read', help='register the custodian’s scoped GitHub token')
    register.add_argument('--source-sha', required=True)
    register.add_argument('--token-file', type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.action == 'prepare':
            raw = prepare(args.source_sha, args.machine_id, args.reviewer, args.check_app_id, args.writer_app_id,
                          {key: getattr(args, 'base_' + key) for key in ('image', 'repo', 'workflow', 'source', 'ref')},
                          args.read_principal, fine_grained(read_private(args.token_file, 512)))
            write_private(args.output, raw)
            sync_directory(args.output.parent)
            result = {'phase': 'handoff-prepared', 'sha256': fingerprint(raw)}
        else:
            from commission_host import KIT, verify_checkout

            require(os.getuid() == os.geteuid() == 0, 'use the authorized root terminal on the selected host')
            with protect(Path('/etc/machine-id')).open('rb') as stream:
                machine = stream.read(34).decode('ascii').removesuffix('\n')
            scope(args.source_sha, machine)
            verify_checkout(KIT, args.source_sha, 0)
            if args.action == 'install':
                install_handoff(args.handoff, args.sha256, args.source_sha, machine)
                result = {'phase': 'release-trust-installed'}
            else:
                register_read(args.source_sha, machine, args.token_file)
                result = {'phase': 'release-read-registered'}
        print(canonical(result))
        return 0
    except (Blocked, OSError, ValueError, RuntimeError, TypeError, KeyError, AttributeError, IndexError,
            subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, Blocked) else 'required protected release authority is unavailable'
        print('Release setup paused. ' + detail, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
