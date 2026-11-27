#!/usr/bin/python3
"""Submit the fixed checklist candidate from a separate developer account."""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import stat
import subprocess
import tempfile
import time

import checklist_candidate as candidate
import job_protocol as p
from ledger_recovery import read_private, trusted_directory

REPOSITORY = 'oso-gato/dev-pair'
DEVELOPER = 'dp-release-dev'
ROOT = candidate.ROOT / 'release-developer'
HOME = ROOT / 'home'
INBOX = ROOT / 'inbox'
CREDENTIALS = ROOT / 'credentials'
PYTHON = '/usr/bin/python3'
GIT = '/usr/bin/git'
GH = '/usr/bin/gh'
GIT_TRANSFER = 16 * 1024 * 1024
SCRATCH_MIN = 64 * 1024**2
SCRATCH_LIMIT = 512 * 1024**2
OUTPUT_LIMIT = 1024 * 1024
CHECKLIST_FILES = frozenset('examples/checklist/' + name for name in ('checklist.py', 'test_checklist.py', 'README.md'))
FETCH = ['fetch', '--quiet', '--no-tags', '--no-auto-maintenance', '--no-recurse-submodules']
MARKER = 'dev-pair-checklist-product-v1\n'


class Unavailable(OSError):
    """A bounded external command can be retried after exact status is observed."""


def capture(args, end, *, env=None, data=None, ceiling=OUTPUT_LIMIT, timeout=30):
    end = min(end, time.monotonic() + timeout)
    p.require(time.monotonic() < end, 'protected release operation deadline expired')
    p.require(data is None or len(data) <= p.MAX_MESSAGE, 'bounded release command input required')
    clean = {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent',
             'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1', **(env or {})}
    with tempfile.TemporaryFile() as incoming, selectors.DefaultSelector() as selector:
        if data is not None:
            incoming.write(data)
            incoming.seek(0)
        with subprocess.Popen(tuple(map(str, args)), env=clean, stdin=incoming, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, start_new_session=True) as proc:
            output = bytearray()
            try:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.select(max(0, end - time.monotonic())):
                    chunk = os.read(proc.stdout.fileno(), min(8192, ceiling + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    p.require(len(output) <= ceiling, 'protected release command output exceeded its bound')
                else:
                    raise Unavailable('protected release transport timed out')
                code = proc.wait(timeout=max(0, end - time.monotonic()))
            except BaseException as exc:
                terminate(proc)
                if isinstance(exc, subprocess.TimeoutExpired):
                    raise Unavailable('protected release transport timed out') from exc
                raise
        if code != 0:
            raise Unavailable('protected release transport did not complete')
        return bytes(output)


def terminate(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=2)


def token(raw):
    p.require(re.fullmatch(rb'github_pat_[A-Za-z0-9_]{30,250}', raw.removesuffix(b'\n')),
              'a separately provisioned fine-grained token is required')
    return raw.removesuffix(b'\n').decode('ascii')


def json_data(raw, limit=OUTPUT_LIMIT):
    def unique(items):
        result = {}
        for key, value in items:
            p.require(key not in result, 'duplicate release response field')
            result[key] = value
        return result

    p.require(len(raw) <= limit, 'bounded release response required')
    return json.loads(raw, object_pairs_hook=unique)


class Hub:
    def __init__(self, secret, end, *, registry_auth=None):
        self.secret = secret
        self.end = end
        self.registry_auth = registry_auth

    def gh(self, *args, timeout=20):
        p.require(len(args) >= 5 and args[0] == GH and args.count('--hostname') == 1 and
                  args[args.index('--hostname') + 1] == 'github.com', 'unsupported GitHub authority')
        api_read = (args[1] == 'api' and args.count('-X') == 1 and args[args.index('-X') + 1] == 'GET' and
                    all(item not in args for item in ('--method', '-f', '-F', '--field', '--raw-field', '--input')))
        p.require(api_read or args[1:3] == ('attestation', 'verify'), 'unsupported GitHub observer command')
        env = {'GH_TOKEN': self.secret}
        if self.registry_auth is not None and args[1] == 'attestation':
            env.update(DOCKER_CONFIG=str(self.registry_auth.parent), REGISTRY_AUTH_FILE=str(self.registry_auth))
        return capture(args, self.end, timeout=timeout, env=env)

    def get(self, endpoint):
        p.require(endpoint == 'user' or re.fullmatch(r'repos/[A-Za-z0-9_./?=&:%+\-]+', endpoint),
                  'unsupported scoped GitHub read')
        return json_data(self.gh(GH, 'api', '--hostname', 'github.com', '-X', 'GET', endpoint))

    def post_pull(self, request):
        data = {'title': 'Checklist product job ' + request['job_id'], 'body': pull_body(request),
                'head': request['fork'].split('/')[0] + ':' + request['branch'], 'base': 'main',
                'draft': False, 'maintainer_can_modify': False}
        return json_data(capture([GH, 'api', '--hostname', 'github.com', '-X', 'POST',
                                  'repos/' + REPOSITORY + '/pulls', '--input', '-'], self.end,
                                  env={'GH_TOKEN': self.secret}, data=p.canonical(data).encode()))


def branch(job, sha):
    p.token(job)
    p.digest(sha, 40)
    return 'dev-pair-products/' + job + '-' + sha[:12]


def request_shape(request):
    p.fields(request, 'version job_id agreement_sha256 repository base_sha candidate_sha tree_sha bundle_sha256 '
                      'release_binding_sha256 review_policy_sha256 developer_id developer_login fork branch')
    p.number(request['version'], 1, 1)
    p.number(request['developer_id'], 1, 2**63 - 1)
    for name in ('base_sha', 'candidate_sha', 'tree_sha'):
        p.digest(request[name], 40)
    for name in ('agreement_sha256', 'bundle_sha256', 'release_binding_sha256', 'review_policy_sha256'):
        p.digest(request[name])
    p.require(request['repository'] == REPOSITORY and request['base_sha'] != request['candidate_sha'] and
              re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', request['developer_login']) and
              re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/dev-pair', request['fork']) and
              request['fork'].lower() != REPOSITORY.lower() and
              request['branch'] == branch(request['job_id'], request['candidate_sha']),
              'proposal lacks the exact checklist repository, fork or branch')
    return request


def pull_body(request):
    return MARKER + p.canonical(request)


def match_pull(row, request):
    number = row['number']
    p.number(number, 1, 2**31 - 1)
    head, base = row['head'], row['base']
    p.require(head['repo']['full_name'] == request['fork'] and head['ref'] == request['branch'] and
              head['sha'] == request['candidate_sha'] and row['user']['id'] == request['developer_id'] and
              row['user']['login'] == request['developer_login'] and
              base['repo']['full_name'] == REPOSITORY and base['ref'] == 'main' and
              row['html_url'] == f'https://github.com/{REPOSITORY}/pull/{number}' and row['body'] == pull_body(request),
              'existing proposal has a different actor, head or base')
    return row


def find_pull(hub, request):
    prefix = 'repos/' + REPOSITORY + '/pulls'
    needle = request['fork'].split('/')[0] + '%3A' + request['branch'].replace('/', '%2F')
    rows = hub.get(prefix + '?state=all&base=main&head=' + needle + '&per_page=20')
    p.require(type(rows) is list and len(rows) <= 1, 'ambiguous existing checklist proposals')
    if not rows:
        return None
    p.number(rows[0]['number'], 1, 2**31 - 1)
    return match_pull(hub.get(prefix + '/' + str(rows[0]['number'])), request)


def permissions(hub, repository, actor, *, push):
    p.require(hub.get('user')['id'] == actor, 'separate GitHub custody identity changed')
    row = hub.get('repos/' + repository)
    access = row['permissions']
    p.require(row['full_name'] == repository and access['admin'] is False and access['maintain'] is False and
              access['push'] is push and access['pull'] is True, 'GitHub custody exceeds the scoped repository grant')
    return row


def scoped_diff(raw):
    fields = raw.split(b'\0')
    p.require(fields[-1] == b'' and 2 <= len(fields) - 1 <= len(CHECKLIST_FILES) * 2
              and (len(fields) - 1) % 2 == 0, 'checklist Git delta must make a bounded existing-file change')
    paths = []
    for header, path in zip(fields[:-1:2], fields[1:-1:2]):
        p.require(re.fullmatch(rb':100644 100644 [0-9a-f]{40} [0-9a-f]{40} M', header),
                  'promotion requires a regular nonexecutable checklist modification')
        name = path.decode('utf-8')
        p.require(name in CHECKLIST_FILES and name not in paths, 'candidate changes files outside the approved checklist scope')
        paths.append(name)
    return sorted(paths)


def git_call(repository, end, *args, secret=None, login=None, bundle=False):
    options = ('--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch', '-c', 'core.hooksPath=/dev/null',
               '-c', 'protocol.allow=never', '-c', 'http.followRedirects=false')
    env = {'HOME': str(HOME), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_LAZY_FETCH': '1'}
    if secret is not None:
        p.require(type(login) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', login),
                  'exact GitHub developer login required')
        credentials = base64.b64encode((login + ':' + secret).encode()).decode()
        options += ('-c', 'protocol.https.allow=always')
        env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraHeader',
                   GIT_CONFIG_VALUE_0='Authorization: Basic ' + credentials)
    if bundle:
        options += ('-c', 'protocol.file.allow=always')
    return capture([GIT, *options, '-C', str(repository), *args], end, env=env)


def propose(request, staged, fork_secret, pull_secret, end):
    request_shape(request)
    forks, pulls = Hub(fork_secret, end), Hub(pull_secret, end)
    fork = permissions(forks, request['fork'], request['developer_id'], push=True)
    permissions(pulls, REPOSITORY, request['developer_id'], push=False)
    p.require(fork['fork'] is True and fork['parent']['full_name'] == REPOSITORY,
              'developer write grant does not target the separately scoped fork')
    existing = find_pull(pulls, request)
    if existing is not None:
        p.require(existing['state'] == 'open' or existing['merged'] is True, 'the bound proposal was closed without merging')
        return {'pull_request': existing['number'], 'head': request['candidate_sha']}
    base, revision = request['base_sha'], request['candidate_sha']
    fork_url = 'https://github.com/' + request['fork'] + '.git'
    upstream = 'https://github.com/' + REPOSITORY + '.git'
    ref = 'refs/heads/' + request['branch']
    witness = git_call(HOME, end, 'ls-remote', '--refs', fork_url, ref, secret=fork_secret, login=request['developer_login'])
    if witness:
        p.require(witness == (revision + '\t' + ref + '\n').encode(), 'existing developer branch has a different head')
    with tempfile.TemporaryDirectory(prefix='proposal-', dir=HOME) as root:
        repository = Path(root)
        git_call(repository, end, 'init', '--bare', '--template=')
        git_call(repository, end, *FETCH, upstream, 'refs/heads/main', secret=pull_secret, login=request['developer_login'])
        fetched = git_call(repository, end, 'rev-parse', '--verify', 'FETCH_HEAD').decode().strip()
        p.require(fetched == base, 'main advanced before the authorized proposal')
        git_call(repository, end, *FETCH, str(staged), 'refs/heads/materialized:refs/heads/proposal-input', bundle=True)
        obj = git_call(repository, end, 'show', '-s', '--format=%H%n%T%n%P', 'refs/heads/proposal-input')
        p.require(obj.decode().splitlines() == [revision, request['tree_sha'], base],
                  'incoming bundle is not the one reviewed candidate commit')
        scoped_diff(git_call(repository, end, 'diff', '--raw', '-z', '--no-abbrev', '--no-renames', base, revision, '--'))
        if not witness:
            # An empty prior value permits creating this ref once. It cannot replace or advance a retained head.
            git_call(repository, end, 'push', '--quiet', '--force-with-lease=' + ref + ':', fork_url,
                     revision + ':' + ref, secret=fork_secret, login=request['developer_login'])
    pull = match_pull(pulls.post_pull(request), request)
    p.require(pull['state'] == 'open', 'the scoped developer proposal did not open')
    return {'pull_request': pull['number'], 'head': revision}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('job')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        p.token(args.job)
        account = pwd.getpwnam(DEVELOPER)
        p.require(os.getuid() == os.geteuid() == account.pw_uid >= 1000 and
                  os.getgid() == os.getegid() == account.pw_gid and Path(account.pw_dir) == HOME,
                  'scoped proposal account required')
        directory = trusted_directory(HOME)
        capacity = os.statvfs(directory)
        mount_flags = os.ST_NODEV | os.ST_NOSUID | os.ST_NOEXEC
        p.require(os.path.ismount(directory) and directory.stat().st_dev != ROOT.stat().st_dev and
                  capacity.f_flag & mount_flags == mount_flags and
                  SCRATCH_MIN <= capacity.f_blocks * capacity.f_frsize <= SCRATCH_LIMIT and
                  capacity.f_bavail * capacity.f_frsize >= SCRATCH_MIN and 64 <= capacity.f_files <= 65536,
                  'proposal staging needs a bounded dedicated build filesystem')
        resource.setrlimit(resource.RLIMIT_FSIZE, (SCRATCH_LIMIT, SCRATCH_LIMIT))
        input_dir = INBOX / args.job
        for path in (input_dir, INBOX, ROOT, ROOT.parent, *ROOT.parent.parents):
            node = path.lstat()
            p.require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022,
                      'proposal input ancestry is outside protected custody')
        request_path = input_dir / 'request.json'
        bundle_path = input_dir / 'candidate.bundle'
        for path in (request_path, bundle_path):
            node = path.lstat()
            p.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
                      node.st_gid == account.pw_gid and stat.S_IMODE(node.st_mode) == 0o440,
                      'proposal inputs require immutable root custody')
        request = request_shape(p.loads(p.read_data(request_path, 4096)))
        p.require(request['job_id'] == args.job and p.sha256(p.read_data(bundle_path, GIT_TRANSFER)) ==
                  request['bundle_sha256'], 'proposal input job or Git transport changed')
        credentials = trusted_directory(CREDENTIALS)
        p.require(credentials.stat().st_dev == ROOT.stat().st_dev, 'proposal credentials require persistent separate custody')
        result = propose(request, bundle_path, token(read_private(credentials / 'fork.token', 512)),
                         token(read_private(credentials / 'upstream-pr.token', 512)), time.monotonic() + 110)
        print(p.canonical(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(2, 'Scoped checklist proposal withheld (' + type(exc).__name__ + ').\n')


if __name__ == '__main__':
    raise SystemExit(main())
