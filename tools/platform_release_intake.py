#!/usr/bin/python3
"""Read and stage one exact, independently attested platform package."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

import platform_release as release
from storage import GUEST_RESERVE
from platform_release_protocol import (
    ARCHIVE_LIMIT, CONTROL_LIMIT, ROLES, COMPONENT,
    Blocked, file_hash, hex_id, json_bytes, require, seconds, stream_exact, portable_index, portable_roles,
)

GITHUB = '/usr/bin/gh'
ROOT = Path('/var/lib/dev-pair/platform-releases')
TRUST = Path('/usr/libexec/dev-pair/tools/release_trust.py')
API = 'repos/' + release.REPOSITORY + '/'
CONTROL_SECONDS = 900
MAX_LOCAL_RELEASES = 3
ZIP_OVERHEAD = 1024 * 1024
META_LIMIT = 256 * 1024
ENV = {'PATH': '/usr/bin:/usr/sbin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
       'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1', 'GH_HOST': 'github.com'}


def native_env():
    env = dict(ENV)
    for key in ('GH_CONFIG_DIR',):
        if key in os.environ:
            env[key] = str(protected(Path(os.environ[key]), directory=True))
    return env


def protected(path, *, directory=False):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'release intake requires canonical protected paths')
    for node in (path, *path.parents):
        info = node.lstat()
        wanted = stat.S_ISDIR(info.st_mode) if node != path or directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        require(info.st_uid == 0 and not info.st_mode & 0o022 and wanted, 'release intake path is not root protected')
    return path


def read_api(endpoint, end, *, limit=META_LIMIT, output=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    command = [GITHUB, 'api', '--hostname', 'github.com', '--method', 'GET',
               '-H', 'Accept: application/vnd.github+json', API + endpoint]

    def transfer(target):
        subprocess.run(command, env=native_env(), stdin=subprocess.DEVNULL, stdout=target, stderr=subprocess.DEVNULL,
                       timeout=seconds(end, 300), check=True, preexec_fn=limits)
        size = target.tell()
        require(0 < size <= limit, 'GitHub response exceeded the exact release transfer bound')

    if output is None:
        with tempfile.TemporaryFile(dir=ROOT) as target:
            transfer(target)
            target.seek(0)
            return json_bytes(target.read(limit + 1))
    with output.open('xb') as target:
        transfer(target)


def intake_limit(directory, files, headroom=0):
    demand = sum(files) + headroom + GUEST_RESERVE
    require(shutil.disk_usage(directory).free >= demand, 'release intake capacity and recovery reserve are insufficient')


def checked_run(value, source, run, agent):
    event = ('schedule', 'workflow_dispatch') if agent else ('push',)
    path = '.github/workflows/agent-refresh.yml' if agent else '.github/workflows/platform-release.yml'
    require(value.get('id') == run and value.get('run_attempt') == 1 and value.get('event') in event and
            value.get('status') == 'completed' and value.get('conclusion') == 'success' and
            value.get('path') == path and value.get('head_sha') == source and
            value.get('head_branch') == 'main' and value.get('repository', {}).get('full_name') == release.REPOSITORY and
            value.get('head_repository', {}).get('full_name') == release.REPOSITORY, 'protected platform publisher run unavailable')


def artifacts(raw, source, agent):
    values = raw.get('artifacts')
    roles = (*ROLES, 'host') if not agent else ROLES[:2]
    names = {release.artifact_name(part, source) for part in (*roles, 'subjects')}
    if agent:
        names.add(f'agent-tooling-{source}')
    require(raw.get('total_count') == len(names) and type(values) is list and len(values) == len(names),
            'publisher artifact inventory differs from the closed release package')
    result = {}
    for row in values:
        name, identifier = row.get('name'), row.get('id')
        require(name in names and name not in result and type(identifier) is int and identifier > 0 and
                row.get('expired') is False and type(row.get('digest')) is str and
                re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']) and
                type(row.get('size_in_bytes')) is int and row['size_in_bytes'] > 0, 'publisher artifact is expired or ambiguous')
        result[name] = row
    require(len({row['id'] for row in result.values()}) == len(result), 'duplicate artifact ID')
    return result


def extract_zip(zip_path, destination, wanted, end):
    with zip_path.open('rb') as source:
        # Bound the central directory before zipfile reads or allocates it.
        end_record = zipfile._EndRecData(source)
        require(end_record is not None and end_record[zipfile._ECD_DISK_NUMBER] == 0 and
                end_record[zipfile._ECD_DISK_START] == 0 and
                end_record[zipfile._ECD_ENTRIES_THIS_DISK] == end_record[zipfile._ECD_ENTRIES_TOTAL] == len(wanted) and
                0 < end_record[zipfile._ECD_SIZE] <= CONTROL_LIMIT,
                'Actions ZIP central directory exceeds its closed two-file bound')
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            require(len(members) == len(wanted) and {item.filename for item in members} == set(wanted),
                    'Actions ZIP content differs from its exact component')
            for item in members:
                mode = item.external_attr >> 16
                require(not item.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG) and not item.flag_bits & 1 and
                        item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                        'Actions ZIP contains a link, special file or unsupported member')
                expected, maximum = wanted[item.filename]
                require(0 < item.file_size <= maximum and (expected is None or item.file_size == maximum),
                        'Actions ZIP member byte limit or exact length differs')
                with archive.open(item) as content, (destination / item.filename).open('xb') as target:
                    actual = stream_exact(content, item.file_size, end, target)
                    require(not content.read(1) and (expected is None or actual == expected),
                            'Actions ZIP member failed its verified digest')
                    os.fsync(target.fileno())


def fetch_artifact(rows, name, destination, wanted, end):
    row = rows[name]
    maximum = ZIP_OVERHEAD + sum(value[1] for value in wanted.values())
    require(row['size_in_bytes'] <= maximum, 'Actions ZIP transport exceeds the approved byte bound')
    intake_limit(ROOT, [row['size_in_bytes'], sum(value[1] for value in wanted.values())])
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='.download-') as temporary:
        path = Path(temporary) / 'transport.zip'
        read_api(f'actions/artifacts/{row["id"]}/zip', end, limit=row['size_in_bytes'], output=path)
        sha, length = file_hash(path, maximum, end, owner=0)
        require(length == row['size_in_bytes'] and row['digest'] == 'sha256:' + sha,
                'Actions ZIP differs from its exact transport identity')
        extract_zip(path, destination, wanted, end)


def verify_subject(path, identity, source, run, role, end):
    verify = protected(TRUST)
    subprocess.run(['/usr/bin/python3', '-B', str(verify), 'verify', '--component', role, '--source-sha', source,
                    '--subject', str(protected(path)), '--sha256', identity, '--run-id', str(run)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=native_env(), timeout=seconds(end, 120), check=True)


def verify_local_parts(directory, value, end):
    for part, transfer in value['transports'].items():
        local = protected(directory / part, directory=True)
        require({item.name for item in local.iterdir()} == set(transfer['files']), 'local release component inventory changed')
        for name, row in transfer['files'].items():
            require(file_hash(protected(local / name), row['bytes'], end, owner=0) == (row['sha256'], row['bytes']),
                    'local release component no longer matches its digest')
        source = value['source_sha']
        if part == 'host':
            require(release.validate_host(local, source, end) == value['components']['host']['bundle_manifest_sha256'],
                    'portable host bundle identity differs')
        else:
            component = value['components'][COMPONENT[part]]
            checked, _ = release.validate_image_part(local, part, source, end, component if part != 'devbox' else None)
            require(release.portable_image(checked, component) == component, 'portable image identity differs from exact archive')


def retained_index(identity):
    previous = protected(ROOT / identity, directory=True)
    raw, value = release.readonly_json(protected(previous / 'platform.json'), 0)
    require(raw == canonical(value) and hashlib.sha256(raw).hexdigest() == identity,
            'retained previous platform manifest changed')
    portable_index(value, value['source_sha'], value['publisher_run'])
    path = protected(previous / 'intake.json')
    receipt_raw, receipt = release.readonly_json(path, 0)
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and receipt_raw == canonical(receipt) and
            type(receipt['schema']) is int and receipt == {'schema': 2, 'platform_sha256': identity,
            'source_sha': value['source_sha'], 'publisher_run': value['publisher_run'], 'kind': value['kind']},
            'retained previous platform lacks exact prior trust receipt')
    return previous, value, hashlib.sha256(receipt_raw).hexdigest()


def previous_release(identity, end):
    previous, value, _ = retained_index(identity)
    verify_local_parts(previous, value, end)
    return value


@contextmanager
def intake_lock():
    protected(ROOT, directory=True)
    lock = ROOT / '.intake.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1 and
                stat.S_IMODE(node.st_mode) == 0o600, 'release intake lock is not protected')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def acquire(source, run, expected, previous, end, *, agent=False):
    hex_id(source, 40)
    hex_id(expected)
    require(type(run) is int and 0 < run < 2 ** 63 and os.getuid() == os.geteuid() == 0,
            'protected release operator and exact publisher run required')
    protected(ROOT, directory=True)
    require(Path(GITHUB).is_file(), 'protected read-only GitHub CLI unavailable')
    require(not os.path.lexists(ROOT / expected), 'platform package already staged at its exact digest')
    entries = [item for item in ROOT.iterdir() if item.name != '.intake.lock']
    require(len(entries) < MAX_LOCAL_RELEASES and all(re.fullmatch('[0-9a-f]{64}', item.name) and
                                                   protected(item, directory=True) for item in entries),
            'retained platform store is full or requires scoped reconciliation')
    require(previous is not None or not entries, 'initial release intake requires an empty platform store')
    if previous is not None:
        hex_id(previous)
        require(previous != expected, 'platform release cannot reference itself for recovery')
    # Capacity is established before contacting the transport. One additional
    # ZIP may coexist with the complete set of retained release files.
    intake_limit(ROOT, [release.AGENT_BUDGET if agent else release.FILE_BUDGET], ARCHIVE_LIMIT + ZIP_OVERHEAD)
    checked_run(read_api(f'actions/runs/{run}', end), source, run, agent)
    rows = artifacts(read_api(f'actions/runs/{run}/artifacts?per_page=100', end), source, agent)
    with release.output_directory(ROOT / expected) as stage:
        names = {name: (None, CONTROL_LIMIT) for name in release.SUBJECTS}
        fetch_artifact(rows, release.artifact_name('subjects', source), stage, names, end)
        raw, value = release.readonly_json(stage / 'platform.json', 0)
        require(hashlib.sha256(raw).hexdigest() == expected, 'platform subject differs from independently selected digest')
        value = portable_index(value, source, run)
        kind = 'dev-pair-agent-release' if agent else 'dev-pair-platform-release'
        require(value['kind'] == kind and value['previous_platform_sha256'] == previous,
                'protected recovery version or release kind differs')
        roles = portable_roles(kind)
        for role in roles if agent else (*roles, 'host'):
            verify_subject(stage / 'platform.json', expected, source, run, role, end)
        if previous is not None:
            prior = previous_release(previous, end)
            if agent:
                base = prior['base_platform_sha256'] or previous
                require(value['base_platform_sha256'] == base, 'agent refresh changes the retained host and DevBox base')
                if base != previous:
                    retained = previous_release(base, end)
                    require(retained['kind'] == 'dev-pair-platform-release', 'retained stable base is incomplete')
        else:
            require(not agent, 'agent refresh requires the previous verified platform')
        for part, transport in value['transports'].items():
            target = stage / part
            target.mkdir(mode=0o700)
            wanted = {name: (item['sha256'], item['bytes']) for name, item in transport['files'].items()}
            fetch_artifact(rows, transport['name'], target, wanted, end)
        verify_local_parts(stage, value, end)
        branch = read_api('branches/main', end)
        require(branch.get('protected') is True and branch.get('commit', {}).get('sha') == source,
                'protected main changed before release staging')
        receipt = {'schema': 2, 'platform_sha256': expected, 'source_sha': source,
                   'publisher_run': run, 'kind': value['kind']}
        release.write_json(stage / 'intake.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--platform-sha256', required=True)
    parser.add_argument('--agent-only', action='store_true')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--previous')
    mode.add_argument('--initial', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    require(os.getuid() == os.geteuid() == 0, 'protected release operator required')
    with intake_lock():
        result = acquire(args.source, args.run_id, args.platform_sha256, args.previous,
                         time.monotonic() + CONTROL_SECONDS, agent=args.agent_only)
    print(release.canonical(result).decode(), end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print('platform intake blocked: ' + str(exc)[:800], file=sys.stderr)
        sys.exit(2)
