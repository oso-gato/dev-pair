#!/usr/bin/python3
"""Package exact protected platform release subjects and verify their portable bytes."""

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

import fedora_oci
import public_inputs
from devbox import db
from platform_release_protocol import (
    ARCHIVE_LIMIT, CONTROL_LIMIT, EXPANSION_LIMIT, HOST_LIMIT, ROLES, STANDARDS,
    COMPONENT, Blocked, canonical, fields, file_hash, hex_id, image_record, json_bytes,
    regular, require, seconds, stream_exact, portable_index, portable_roles,
    UPSTREAM_RELEASE_LIMIT, upstream_release_json,
)

REPOSITORY = 'oso-gato/dev-pair'
CODEX_VERSION = '0.169.0'
SOURCE = Path(__file__).resolve().parent.parent
HOST_FILES = 256
ASSEMBLY_SECONDS = 720
HOST_PAYLOADS = ('host.tar', 'host-manifest.json')
PART_FILE = 'part.json'
SUBJECTS = ('platform.json',)
FILE_BUDGET = len(ROLES) * (ARCHIVE_LIMIT + CONTROL_LIMIT) + HOST_LIMIT + 3 * CONTROL_LIMIT
TRANSPORT_BUDGET = FILE_BUDGET + 5 * 1024 ** 2
AGENT_BUDGET = 2 * (ARCHIVE_LIMIT + CONTROL_LIMIT) + 4 * 1024 ** 2
LATEST = 'https://api.github.com/repos/openai/codex/releases/latest'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def readonly_json(path, owner=None):
    stream, node = regular(path, CONTROL_LIMIT, owner)
    with stream:
        data = stream.read(CONTROL_LIMIT + 1)
        require(len(data) == node.st_size, 'release metadata changed during read')
    return data, json_bytes(data)


def write_json(path, value):
    data = canonical(value)
    require(len(data) <= CONTROL_LIMIT, 'release metadata exceeds its bound')
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(data)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def output_directory(destination):
    require(destination.is_absolute() and destination.parent.resolve(strict=True) == destination.parent and
            not os.path.lexists(destination), 'release output requires one new directory below its owned parent')
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.platform-') as temporary:
        stage = Path(temporary) / 'content'
        stage.mkdir(mode=0o700)
        yield stage
        sync_directory(stage)
        require(not os.path.lexists(destination), 'release output destination appeared')
        stage.rename(destination)
        sync_directory(destination.parent)


def archive_name(role):
    require(role in ROLES, 'unknown protected image role')
    return role + '.oci.tar'


def artifact_name(part, source):
    require(part in (*ROLES, 'host', 'subjects'), 'invalid platform transport component')
    return f'platform-{part}-{hex_id(source, 40)}'


def source_git(source, *args):
    cmd = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
           '-C', str(source), *args]
    value = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                           env={'PATH': '/usr/bin:/usr/sbin', 'GIT_CONFIG_NOSYSTEM': '1',
                                'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                                'GIT_OPTIONAL_LOCKS': '0'}, check=True, timeout=15).stdout
    require(len(value) <= HOST_LIMIT, 'reviewed Git content exceeds the release bound')
    return value


def source_checkout(source, revision):
    require(source_git(source, 'rev-parse', 'HEAD').decode().strip() == hex_id(revision, 40) and
            not source_git(source, 'status', '--porcelain'), 'protected release source checkout is not the exact clean commit')


def stable_version(raw):
    row = upstream_release_json(raw)
    tag = row.get('tag_name', '')
    match = re.fullmatch(r'rust-v([0-9]+\.[0-9]+\.[0-9]+)', tag)
    require(match is not None and row.get('draft') is False and row.get('prerelease') is False and
            row.get('html_url') == 'https://github.com/openai/codex/releases/tag/' + tag,
            'official stable Codex version unavailable')
    return match[1]


def official_version():
    request = urllib.request.Request(LATEST, headers={'Accept': 'application/vnd.github+json',
                                                    'User-Agent': 'dev-pair-platform-release/1'})
    with urllib.request.urlopen(request, timeout=8) as response:
        require(response.status == 200 and response.geturl() == LATEST, 'official stable Codex endpoint changed')
        raw = response.read(UPSTREAM_RELEASE_LIMIT + 1)
    return stable_version(raw)


def admit(source):
    from platform_release_ci import admitted_push

    admitted_push(source, os.environ)
    source_checkout(SOURCE, source)
    for requirement in ('tools/native_placements.py', 'tools/release_trust.py', 'tools/renewal.py',
                        'tools/renewal_site.py', 'tools/platform_release_protocol.py', 'tools/platform_release_install.py',
                        'runtime/renewal/driver', 'runtime/renewal/host-release'):
        require((SOURCE / requirement).is_file(), 'protected platform integration lacks ' + requirement)
    previous = os.environ.get('PREVIOUS')
    if previous != 'initial':
        hex_id(previous)
    try:
        quota = int(os.environ.get('ARTIFACT_BYTES', ''))
    except ValueError:
        raise Blocked('protected Actions artifact quota approval is unavailable') from None
    require(TRANSPORT_BUDGET <= quota, 'protected Actions artifact quota does not cover bounded one-day retention')
    require(official_version() == CODEX_VERSION,
            'official stable Codex advanced; review the signed build-input pins before building')
    output = Path(os.environ['GITHUB_OUTPUT'])
    require(output.is_absolute() and output.resolve(strict=True) == output, 'Actions approval output unavailable')
    with output.open('a') as stream:
        stream.write(f'previous={previous}\nartifact-bytes={quota}\n')


def host_member(name):
    require(type(name) is str and re.fullmatch(r'(?:tools|runtime)/[A-Za-z0-9_./@-]{1,160}', name)
            and all(item not in ('', '.', '..') for item in name.split('/')), 'unsafe host bundle member')
    return name


def host_sources(source, revision, end):
    source_checkout(source, revision)
    rows = source_git(source, 'ls-tree', '-r', '-z', revision, '--', 'tools', 'runtime').rstrip(b'\0').split(b'\0')
    require(0 < len(rows) <= HOST_FILES, 'host bundle file-count limit exceeded')
    for row in rows:
        seconds(end, 120)
        metadata, path = row.split(b'\t', 1)
        mode, kind, object_id = metadata.split()
        name = host_member(path.decode())
        require(kind == b'blob' and mode in (b'100644', b'100755'), 'host bundle contains nonregular Git content')
        data = source_git(source, 'cat-file', 'blob', object_id.decode())
        require(data and len(data) <= 4 * 1024 ** 2, 'host bundle source file is empty or oversized')
        yield name, data, 0o555 if mode == b'100755' else 0o444


def build_host(source, revision, output):
    end = time.monotonic() + 120
    with output_directory(output) as stage:
        files = {}
        path = stage / HOST_PAYLOADS[0]
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            total = 0
            for name, data, mode in host_sources(source, revision, end):
                total += len(data)
                require(total <= HOST_LIMIT - CONTROL_LIMIT, 'host bundle source byte limit exceeded')
                member = tarfile.TarInfo(name)
                member.mode, member.size = mode, len(data)
                archive.addfile(member, io.BytesIO(data))
                files[name] = digest(data)
        require(path.stat().st_size <= HOST_LIMIT, 'host bundle archive exceeds the transport bound')
        identity = write_json(stage / HOST_PAYLOADS[1],
                              {'schema': 1, 'source_revision': revision, 'state_contract': 1, 'files': files})
        return identity


def validate_host(directory, revision, end, destination=None):
    raw, manifest = readonly_json(directory / HOST_PAYLOADS[1])
    fields(manifest, 'schema source_revision state_contract files')
    require(type(manifest['schema']) is type(manifest['state_contract']) is int and
            manifest['schema'] == manifest['state_contract'] == 1 and manifest['source_revision'] == revision,
            'host bundle source or state contract mismatch')
    expected = manifest['files']
    require(type(expected) is dict and 0 < len(expected) <= HOST_FILES, 'host bundle file inventory is invalid')
    for name, value in expected.items():
        host_member(name)
        hex_id(value)
    seen = set()
    stream, node = regular(directory / HOST_PAYLOADS[0], HOST_LIMIT)
    with stream, tarfile.open(fileobj=stream, mode='r:') as archive:
        for member in archive:
            name = host_member(member.name)
            require(name in expected and name not in seen and member.type == tarfile.REGTYPE and
                    not member.pax_headers and member.mode in (0o444, 0o555) and
                    member.uid == member.gid == member.mtime == 0 and 0 < member.size <= node.st_size,
                    'host bundle contains unexpected, duplicate or unsafe content')
            with archive.extractfile(member) as source:
                if destination is None:
                    actual = stream_exact(source, member.size, end)
                else:
                    path = destination / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('xb') as output:
                        actual = stream_exact(source, member.size, end, output)
                        os.fchmod(output.fileno(), member.mode)
                        os.fsync(output.fileno())
            require(actual == expected[name], 'host bundle file digest mismatch')
            seen.add(name)
        require(seen == set(expected), 'host bundle file inventory is incomplete')
        stream.seek(archive.offset)
        require(all(not any(data) for data in iter(lambda: stream.read(65536), b'')), 'host bundle has trailing data')
    if destination is not None:
        with (destination / 'manifest.json').open('xb') as output:
            output.write(raw)
            os.fchmod(output.fileno(), 0o444)
            os.fsync(output.fileno())
    return digest(raw)


def publication_evidence(image, proof):
    role = image['role']
    if role == 'maintenance':
        fields(proof, 'result result_sha256')
        row = fields(proof['result'], 'kind source_sha context_sha256 distrobox_sha fedora_base assembled_image_id '
                     'runtime_container_id boundary_and_version_cycles runtime_container_removed job_admission '
                     'authentication model_access nested_placement note')
        exact = {'kind': 'maintenance-gptbox-probe-candidate', 'source_sha': image['source_sha'],
                 'context_sha256': image['context_sha256'], 'distrobox_sha': public_inputs.DBX_SOURCE,
                 'assembled_image_id': image['image_id'], 'boundary_and_version_cycles': 2,
                 'authentication': 'not verified', 'model_access': 'not verified', 'nested_placement': 'not verified',
                 'note': 'Probe-only candidate; no Codex job, credential or model request is admitted.'}
        require(all(row[key] == value for key, value in exact.items()) and type(row['boundary_and_version_cycles']) is int
                and row['runtime_container_removed'] is True and row['job_admission'] is False and
                proof['result_sha256'] == digest(json.dumps(row, sort_keys=True).encode() + b'\n'),
                'maintenance release lacks its exact verified assembly')
        hex_id(row['runtime_container_id'])
        fedora_oci.validate_import_proof(row['fedora_base'])
    elif role == 'development':
        fields(proof, 'source_sha context_sha256 image_id archive_sha256 archive_bytes diff_ids inputs_sha256 sealed_sha256')
        require(all(proof[key] == image[key] for key in image if key != 'role') and
                type(proof['archive_bytes']) is int, 'development export differs from its protected inner record')
        hex_id(proof['inputs_sha256'])
        hex_id(proof['sealed_sha256'])
    else:
        fields(proof, 'tooling_image_id tooling_diff_ids tooling_recipe_sha256 signed_base')
        hex_id(proof['tooling_image_id'])
        hex_id(proof['tooling_recipe_sha256'])
        fedora_oci.validate_import_proof(proof['signed_base'])
        diffs = proof['tooling_diff_ids']
        require(type(diffs) is list and 0 < len(diffs) < len(image['diff_ids']) and image['diff_ids'][:len(diffs)] == diffs,
                'DevBox layers do not extend its verified tooling')


def image_archive(path, image, end, tooling=None):
    image_record(image)
    require(file_hash(path, ARCHIVE_LIMIT, end) == (image['archive_sha256'], image['archive_bytes']),
            'exact OCI archive digest or size mismatch')
    require(image['diff_ids'][0] == 'sha256:' + fedora_oci.DIFF, 'OCI image lacks the signed Fedora root layer')
    try:
        db.check_archive_image(path, image, EXPANSION_LIMIT, end)
    except db.Blocked as error:
        raise Blocked('platform OCI graph verification failed: ' + str(error)) from None
    with tarfile.open(path, 'r:') as archive:
        entries = {db.archive_path(row.name): row for row in archive if row.isreg()}
        with archive.extractfile(entries['index.json']) as stream:
            manifest = db.json_data(stream.read(db.OCI_METADATA_LIMIT + 1))['manifests'][0]['digest']
        with archive.extractfile(entries['blobs/sha256/' + image['image_id']]) as stream:
            labels = db.json_data(stream.read(db.OCI_METADATA_LIMIT + 1))['config']['Labels']
    expected = {'org.opencontainers.image.revision': image['source_sha'], 'dev-pair.role': image['role'],
                'dev-pair.standards': STANDARDS, 'dev-pair.distrobox': public_inputs.DBX_SOURCE}
    if image['role'] != 'devbox':
        version, binary = ((CODEX_VERSION, public_inputs.CODEX_SHA) if tooling is None
                           else (tooling['codex_version'], tooling['codex_sha256']))
        expected.update({'dev-pair.context': image['context_sha256'], 'dev-pair.codex.version': version,
                         'dev-pair.codex.sha256': binary})
    require(type(labels) is dict and all(labels.get(key) == value for key, value in expected.items()),
            'archived image labels differ from the fixed Fedora/platform/source target')
    return hex_id(manifest.removeprefix('sha256:'))


def tooling_row(tooling):
    if tooling is None:
        return None
    return {'codex_version': tooling['version'], 'codex_source_sha': tooling['source_sha'],
            'codex_sha256': tooling['binary']['sha256']}


def write_image_part(directory, image, proof, end, tooling=None):
    image_record(image)
    publication_evidence(image, proof)
    manifest = image_archive(directory / archive_name(image['role']), image, end, tooling)
    data = {'schema': 1, 'image': image, 'oci_manifest_sha256': manifest, 'producer': proof}
    write_json(directory / PART_FILE, data)
    return data


def validate_image_part(directory, role, source, end, tooling=None):
    raw, part = readonly_json(directory / PART_FILE)
    fields(part, 'schema image oci_manifest_sha256 producer')
    image = image_record(part['image'])
    require(type(part['schema']) is int and part['schema'] == 1 and image['role'] == role and image['source_sha'] == source,
            'platform image part source or role differs')
    publication_evidence(image, part['producer'])
    require(image_archive(directory / archive_name(role), image, end, tooling) == part['oci_manifest_sha256'],
            'platform image manifest digest changed')
    return part, digest(raw)


def transport_record(directory, names, maximum, end):
    require({item.name for item in directory.iterdir()} == set(names), 'unexpected platform artifact files')
    result = {}
    for name in names:
        identity, size = file_hash(directory / name, maximum if name.endswith('.tar') else CONTROL_LIMIT, end)
        result[name] = {'sha256': identity, 'bytes': size}
    return result


def portable_image(part, tooling=None):
    image = part['image']
    item = {key: image[key] for key in ('source_sha', 'context_sha256', 'archive_sha256', 'archive_bytes')}
    item.update(oci_config_sha256=image['image_id'], oci_manifest_sha256=part['oci_manifest_sha256'])
    if image['role'] != 'devbox':
        values = tooling or {'codex_version': CODEX_VERSION, 'codex_source_sha': public_inputs.CODEX_SOURCE,
                             'codex_sha256': public_inputs.CODEX_SHA}
        item.update({key: values[key] for key in ('codex_version', 'codex_source_sha', 'codex_sha256')})
    return item


def assemble(inputs, output, source, run_id, previous, quota, *, agent=False, base=None, site_chain=False, tooling=None):
    hex_id(source, 40)
    limit = AGENT_BUDGET if agent else TRANSPORT_BUDGET
    require(type(run_id) is int and run_id > 0 and type(quota) is int and limit <= quota,
            'protected Actions artifact quota approval is missing')
    require(site_chain == (tooling is not None), 'site-chained assembly requires selected release tooling')
    if site_chain:
        require(agent and previous is None, 'site-chained assembly only accepts an agent pair without a CI predecessor')
    else:
        if previous != 'initial' or agent:
            hex_id(previous)
    if agent:
        hex_id(base)
    end = time.monotonic() + ASSEMBLY_SECONDS
    kind = 'dev-pair-agent-release' if agent else 'dev-pair-platform-release'
    transports = {}
    components = {}
    for role in portable_roles(kind):
        name = artifact_name(role, source)
        directory = inputs / name
        part, _ = validate_image_part(directory, role, source, end, tooling)
        components[COMPONENT[role]] = portable_image(part, tooling)
        transports[role] = {'name': name, 'files': transport_record(directory, (archive_name(role), PART_FILE), ARCHIVE_LIMIT, end)}
    if not agent:
        name = artifact_name('host', source)
        directory = inputs / name
        host = validate_host(directory, source, end)
        transports['host'] = {'name': name, 'files': transport_record(directory, HOST_PAYLOADS, HOST_LIMIT, end)}
        components['host'] = {'source_sha': source, 'bundle_manifest_sha256': host}
    combined = {'schema': 3 if site_chain else 2, 'kind': kind, 'repository': REPOSITORY, 'source_sha': source, 'publisher_run': run_id,
                'standards_sha': STANDARDS, 'contracts': {'ledger': 1, 'state': 1, 'release_policy': 1},
                'previous_platform_sha256': None if previous == 'initial' else previous, 'base_platform_sha256': base,
                'components': components, 'transports': transports}
    portable_index(combined, source, run_id)
    with output_directory(output) as stage:
        return write_json(stage / 'platform.json', combined)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest='operation', required=True)
    approval = operations.add_parser('admit')
    approval.add_argument('--source', required=True)
    host = operations.add_parser('host')
    host.add_argument('--source', required=True)
    host.add_argument('--output', required=True, type=Path)
    build = operations.add_parser('assemble')
    build.add_argument('--source', required=True)
    build.add_argument('--input', required=True, type=Path)
    build.add_argument('--output', required=True, type=Path)
    build.add_argument('--run-id', required=True, type=int)
    build.add_argument('--agent-only', action='store_true')
    build.add_argument('--base-platform')
    build.add_argument('--previous')
    build.add_argument('--site-chain', action='store_true')
    build.add_argument('--refresh-tooling', type=Path)
    build.add_argument('--approved-artifact-bytes', required=True, type=int)
    args = parser.parse_args()
    if args.operation == 'admit':
        admit(args.source)
    elif args.operation == 'host':
        print(build_host(SOURCE, args.source, args.output))
    else:
        require(args.site_chain == (args.refresh_tooling is not None), 'site-chained assembly requires verified refresh tooling')
        tooling = None
        if args.site_chain:
            from platform_release_ci import admitted_refresh
            admitted_refresh(args.source, os.environ)
            source_checkout(SOURCE, args.source)
            tooling = tooling_row(public_inputs.read_tooling(args.refresh_tooling, args.source))
        identity = assemble(args.input, args.output, args.source, args.run_id, args.previous, args.approved_artifact_bytes,
                            agent=args.agent_only, base=args.base_platform, site_chain=args.site_chain, tooling=tooling)
        print(identity)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, db.Blocked, OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        print('platform release blocked: ' + str(exc)[:800], file=sys.stderr)
        sys.exit(2)
