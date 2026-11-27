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
    ARCHIVE_LIMIT, CONTROL_LIMIT, HOST_LIMIT, ROLES, STANDARDS, COMPONENT,
    Blocked, fields, file_hash, hex_id, json_bytes, require, seconds, stream_exact,
)

GITHUB = '/usr/bin/gh'
ROOT = Path('/var/lib/dev-pair/platform-releases')
U_ROOT = Path('/var/lib/dev-pair/renewal')
HOST_CONFIG = Path('/etc/dev-pair/host-releases')
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


def checked_run(value, source, run):
    require(value.get('id') == run and value.get('run_attempt') == 1 and value.get('event') == 'push' and
            value.get('status') == 'completed' and value.get('conclusion') == 'success' and
            value.get('path') == '.github/workflows/platform-release.yml' and value.get('head_sha') == source and
            value.get('head_branch') == 'main' and value.get('repository', {}).get('full_name') == release.REPOSITORY and
            value.get('head_repository', {}).get('full_name') == release.REPOSITORY, 'protected platform publisher run unavailable')


def artifacts(raw, source):
    values = raw.get('artifacts')
    names = {release.artifact_name(part, source) for part in (*ROLES, 'host', 'subjects')}
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


def validate_subject(value, source, run):
    fields(value, 'schema kind repository source_sha publisher_run standards_sha previous_platform_sha256 release_sha256 transports')
    require(type(value['schema']) is int and value['schema'] == 1 and value['kind'] == 'dev-pair-platform-release' and
            value['repository'] == release.REPOSITORY and value['source_sha'] == source and
            type(value['publisher_run']) is int and value['publisher_run'] == run and value['standards_sha'] == STANDARDS,
            'attested platform subject does not identify the exact candidate and publisher')
    hex_id(value['release_sha256'])
    if value['previous_platform_sha256'] is not None:
        hex_id(value['previous_platform_sha256'])
    transports = value['transports']
    require(type(transports) is dict and set(transports) == set((*ROLES, 'host')), 'platform transport inventory is incomplete')
    for part, transport in transports.items():
        fields(transport, 'name files')
        require(transport['name'] == release.artifact_name(part, source), 'attested Actions artifact name differs')
        names = release.HOST_PAYLOADS if part == 'host' else (release.archive_name(part), release.PART_FILE)
        require(type(transport['files']) is dict and set(transport['files']) == set(names), 'platform artifact file inventory changed')
        for name, row in transport['files'].items():
            fields(row, 'sha256 bytes')
            hex_id(row['sha256'])
            cap = (HOST_LIMIT if part == 'host' else ARCHIVE_LIMIT) if name.endswith('.tar') else CONTROL_LIMIT
            require(type(row['bytes']) is int and 0 < row['bytes'] <= cap, 'attested component file bound invalid')
    return value


def verify_subject(path, identity, source, run, role, end):
    verify = protected(TRUST)
    subprocess.run(['/usr/bin/python3', '-B', str(verify), 'verify', '--component', role, '--source-sha', source,
                    '--subject', str(protected(path)), '--sha256', identity, '--run-id', str(run)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=native_env(), timeout=seconds(end, 120), check=True)


def runtime_manifest(path, expected):
    digest, value = release.readonly_json(path, 0)
    require(hashlib.sha256(digest).hexdigest() == expected, 'renewal subject digest differs from attested platform record')
    fields(value, 'schema source_revision config_sha256 plan_sha256 ledger_contract state_contract components')
    require(all(type(value[key]) is int and value[key] == 1 for key in ('schema', 'ledger_contract', 'state_contract')),
            'platform and prior release state contracts differ')
    hex_id(value['source_revision'], 40)
    for value_sha in (value['config_sha256'], value['plan_sha256']):
        hex_id(value_sha)
    components = value['components']
    require(type(components) is dict and set(components) == {'host', *COMPONENT.values()}, 'platform runtime components are incomplete')
    for name, item in components.items():
        agent = name.endswith('-agent')
        fields(item, 'source_revision config_sha256 artifact_sha256' + (' codex_version' if agent else ''))
        hex_id(item['source_revision'], 40)
        hex_id(item['config_sha256'])
        hex_id(item['artifact_sha256'])
        if agent:
            require(type(item['codex_version']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', item['codex_version']),
                    'release agent lacks a stable tooling version')
    require(components['host']['config_sha256'] == value['config_sha256'], 'platform host configuration changed')
    return value


def check_site(runtime, end):
    config = protected(HOST_CONFIG / (runtime['config_sha256'] + '.json'))
    plan = protected(U_ROOT / 'plans' / (runtime['plan_sha256'] + '.json'))
    for path, identity, limit in ((config, runtime['config_sha256'], 4096), (plan, runtime['plan_sha256'], CONTROL_LIMIT)):
        require(file_hash(path, limit, end, owner=0)[0] == identity, 'independently selected site configuration or launch plan changed')


def verify_local_parts(directory, value, runtime, end):
    for part, transfer in value['transports'].items():
        local = protected(directory / part, directory=True)
        require({item.name for item in local.iterdir()} == set(transfer['files']), 'local release component inventory changed')
        for name, row in transfer['files'].items():
            require(file_hash(protected(local / name), row['bytes'], end, owner=0) == (row['sha256'], row['bytes']),
                    'local release component no longer matches its digest')
        source = value['source_sha']
        if part == 'host':
            require(release.validate_host(local, source, end) == runtime['components']['host']['artifact_sha256'],
                    'platform host bundle identity differs from renewal subject')
        else:
            checked, _ = release.validate_image_part(local, part, source, end)
            runtime_row = runtime['components'][COMPONENT[part]]
            fixed = {'source_revision': source, 'artifact_sha256': checked['image']['image_id'],
                     'config_sha256': checked['image']['context_sha256']}
            if part != 'devbox':
                fixed['codex_version'] = release.CODEX_VERSION
            require(runtime_row == fixed, 'platform runtime image differs from exact archive')


def previous_release(identity, end):
    if identity is None:
        return
    previous = protected(ROOT / identity, directory=True)
    raw, value = release.readonly_json(protected(previous / 'platform.json'), 0)
    require(hashlib.sha256(raw).hexdigest() == identity, 'retained previous platform manifest changed')
    validate_subject(value, value['source_sha'], value['publisher_run'])
    raw, receipt = release.readonly_json(protected(previous / 'intake.json'), 0)
    require(receipt == {'schema': 1, 'platform_sha256': identity, 'source_sha': value['source_sha'],
                        'publisher_run': value['publisher_run'], 'release_sha256': value['release_sha256']},
            'retained previous platform lacks exact prior trust receipt')
    runtime = runtime_manifest(protected(previous / 'release.json'), value['release_sha256'])
    check_site(runtime, end)
    verify_local_parts(previous, value, runtime, end)


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


def acquire(source, run, expected, previous, end):
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
    intake_limit(ROOT, [release.FILE_BUDGET], ARCHIVE_LIMIT + ZIP_OVERHEAD)
    checked_run(read_api(f'actions/runs/{run}', end), source, run)
    rows = artifacts(read_api(f'actions/runs/{run}/artifacts?per_page=100', end), source)
    with release.output_directory(ROOT / expected) as stage:
        names = {name: (None, CONTROL_LIMIT) for name in release.SUBJECTS}
        fetch_artifact(rows, release.artifact_name('subjects', source), stage, names, end)
        raw, value = release.readonly_json(stage / 'platform.json', 0)
        require(hashlib.sha256(raw).hexdigest() == expected, 'platform subject differs from independently selected digest')
        value = validate_subject(value, source, run)
        require(value['previous_platform_sha256'] == previous, 'protected recovery version differs from the release request')
        verify_subject(stage / 'platform.json', expected, source, run, 'host', end)
        runtime = runtime_manifest(stage / 'release.json', value['release_sha256'])
        require(runtime['source_revision'] == source, 'renewal subject source differs')
        for role in ROLES:
            verify_subject(stage / 'release.json', value['release_sha256'], source, run, role, end)
        check_site(runtime, end)
        previous_release(previous, end)
        for part, transport in value['transports'].items():
            target = stage / part
            target.mkdir(mode=0o700)
            wanted = {name: (item['sha256'], item['bytes']) for name, item in transport['files'].items()}
            fetch_artifact(rows, transport['name'], target, wanted, end)
        verify_local_parts(stage, value, runtime, end)
        branch = read_api('branches/main', end)
        require(branch.get('protected') is True and branch.get('commit', {}).get('sha') == source,
                'protected main changed before release staging')
        receipt = {'schema': 1, 'platform_sha256': expected, 'source_sha': source,
                   'publisher_run': run, 'release_sha256': value['release_sha256']}
        release.write_json(stage / 'intake.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--platform-sha256', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--previous')
    mode.add_argument('--initial', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    require(os.getuid() == os.geteuid() == 0, 'protected release operator required')
    with intake_lock():
        result = acquire(args.source, args.run_id, args.platform_sha256, args.previous, time.monotonic() + CONTROL_SECONDS)
    print(release.canonical(result).decode(), end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print('platform intake blocked: ' + str(exc)[:800], file=sys.stderr)
        sys.exit(2)
