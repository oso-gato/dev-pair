#!/usr/bin/python3
"""Resolve and verify the exact official stable Codex inputs for protected refresh."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

import fedora_ci as ci
import fedora_oci
import platform_release as release
import public_inputs as public
from platform_release_protocol import (
    Blocked, file_hash, hex_id, require, seconds, UPSTREAM_RELEASE_LIMIT, upstream_release_json,
)

API = 'https://api.github.com/repos/openai/codex'
TAG = r'rust-v([0-9]+\.[0-9]+\.[0-9]+)'
ASSETS = {'archive': 'codex-x86_64-unknown-linux-musl.tar.gz',
          'bundle': 'codex-x86_64-unknown-linux-musl.sigstore'}
METADATA_LIMIT = 256 * 1024
BUNDLE_LIMIT = 256 * 1024
RESOLVER_SECONDS = 360
TOOLING_CACHE_BUDGET = 512 * public.MIB
ASSET_HOSTS = {'github.com', 'api.github.com', 'objects.githubusercontent.com',
               'release-assets.githubusercontent.com', 'github-releases.githubusercontent.com'}


class OfficialHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, url):
        target = urllib.parse.urlsplit(url)
        require(target.scheme == 'https' and target.hostname in ASSET_HOSTS and target.port is None and
                target.username is None and target.password is None, 'unexpected official tooling redirect')
        return super().redirect_request(req, fp, code, msg, headers, url)


def api(opener, tail, end):
    url = API + tail
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                                    'User-Agent': 'dev-pair-platform-tooling/1'})
    release_reply = tail == '/releases/latest'
    limit = UPSTREAM_RELEASE_LIMIT if release_reply else METADATA_LIMIT
    with opener.open(request, timeout=seconds(end, 10)) as response:
        require(response.geturl() == url and response.status == 200, 'official tooling metadata endpoint changed')
        raw = response.read(limit + 1)
    if release_reply:
        return upstream_release_json(raw)
    require(0 < len(raw) <= METADATA_LIMIT, 'official tooling metadata exceeds its bound')
    return json.loads(raw, object_pairs_hook=ci.unique_object)


def latest(opener, end):
    row = api(opener, '/releases/latest', end)
    tag = row.get('tag_name', '')
    version = re.fullmatch(TAG, tag)
    require(version is not None and row.get('draft') is False and row.get('prerelease') is False and
            row.get('html_url') == 'https://github.com/openai/codex/releases/tag/' + tag and
            type(row.get('id')) is int and row['id'] > 0, 'official latest stable release is unavailable')
    return row, tag, version[1]


def commit_for_tag(opener, tag, end):
    found = api(opener, '/git/ref/tags/' + tag, end)
    require(found.get('ref') == 'refs/tags/' + tag, 'official tooling ref identity mismatch')
    value = found.get('object')
    for _ in range(3):
        identity = hex_id(value.get('sha'), 40)
        if value.get('type') == 'commit':
            require(value.get('url') == API + '/git/commits/' + identity, 'official tooling commit URL changed')
            return identity
        require(value.get('type') == 'tag' and value.get('url') == API + '/git/tags/' + identity,
                'official tooling tag does not resolve to a commit')
        record = api(opener, '/git/tags/' + identity, end)
        require(record.get('sha') == identity, 'official tooling tag object differs')
        value = record.get('object')
    raise Blocked('official tooling tag exceeds its object resolution bound')


def selected_asset(row, tag, part):
    name = ASSETS[part]
    base = 'https://github.com/openai/codex/releases/download/' + tag
    matches = [item for item in row['assets'] if item.get('name') == name]
    require(len(matches) == 1, 'exact signed tooling asset is absent or ambiguous')
    selected = matches[0]
    maximum = BUNDLE_LIMIT if part == 'bundle' else public.PAYLOAD_LIMIT - fedora_oci.ARCHIVE_BYTES - 2 * public.MIB
    require(selected.get('state') == 'uploaded' and selected.get('browser_download_url') == f'{base}/{name}' and
            type(selected.get('size')) is int and 0 < selected['size'] <= maximum,
            'official tooling asset identity or role-bundle capacity is unsupported')
    digest = selected.get('digest')
    if digest is not None:
        require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}', digest), 'official asset digest has invalid format')
    return selected['browser_download_url'], selected['size'], digest.removeprefix('sha256:') if digest else None


def acquire(opener, destination, identity, end, cache=None):
    url, size, trusted = identity
    if trusted is not None and cache is not None:
        source = cache / (trusted + '.blob')
        if os.path.lexists(source):
            with destination.open('xb') as output:
                actual = file_hash(source, size, end, owner=os.getuid(), output=output)
            require(actual == (trusted, size), 'approved public tooling cache entry changed')
            return {'sha256': trusted, 'bytes': size, 'reused': True}
    digest = hashlib.sha256()
    with opener.open(url, timeout=seconds(end, 20)) as response, destination.open('xb') as output:
        require(response.status == 200, 'official tooling asset request failed')
        pending = size
        while pending:
            seconds(end, 20)
            value = response.read(min(public.MIB, pending))
            require(bool(value), 'official tooling download truncated')
            digest.update(value)
            output.write(value)
            pending -= len(value)
        require(not response.read(1), 'official tooling download exceeds observed length')
    sha = digest.hexdigest()
    require(trusted is None or sha == trusted, 'official tooling download digest differs')
    return {'sha256': sha, 'bytes': size, 'reused': False}


def extract_binary(archive, binary, end):
    with tarfile.open(archive, 'r|gz') as source:
        item = source.next()
        require(item is not None and item.type == tarfile.REGTYPE and not item.pax_headers and not item.issparse() and
                item.name == 'codex-x86_64-unknown-linux-musl' and
                0 < item.size <= public.EXPANSION_LIMIT - fedora_oci.ARCHIVE_BYTES - 4 * public.MIB,
                'official tooling binary has an unsupported archive member or expansion size')
        from platform_release_protocol import stream_exact
        with source.extractfile(item) as data, binary.open('xb') as output:
            identity = stream_exact(data, item.size, end, output)
        require(source.next() is None, 'official tooling archive has extra members')
    return identity, item.size


def verify_signature(work, verifier, bundle, binary, tag, source, end):
    command = [str(verifier), 'verify-blob', '--bundle', str(bundle),
               '--certificate-identity', 'https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/' + tag,
               '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
               '--certificate-github-workflow-repository', 'openai/codex',
               '--certificate-github-workflow-ref', 'refs/tags/' + tag,
               '--certificate-github-workflow-sha', source, str(binary)]
    stdout, stderr = public.command(command, work, timeout=seconds(end, 60), network=True)
    proof = stdout + stderr
    require(b'Verified OK' in proof, 'official tooling Sigstore verification failed')
    return hashlib.sha256(proof).hexdigest()


def matches_pins(value):
    wanted = {'archive': public.ARTIFACTS['codex.tar.gz'], 'bundle': public.ARTIFACTS['codex.sigstore']}
    return (value['version'] == release.CODEX_VERSION and value['source_sha'] == public.CODEX_SOURCE and
            value['binary'] == {'sha256': public.CODEX_SHA, 'bytes': public.CODEX_BYTES} and
            all((value['assets'][name]['bytes'], value['assets'][name]['sha256']) == item[1:]
                for name, item in wanted.items()))


def resolve(output, approved_source, cache=None):
    release.source_checkout(release.SOURCE, hex_id(approved_source, 40))
    require(shutil.disk_usage(output.parent).free >= ci.HOST_RESERVE + public.WORK_LIMIT,
            'official tooling resolver allocation is below its workspace reserve')
    if cache is not None:
        node = cache.lstat()
        require(cache.is_absolute() and cache.resolve(strict=True) == cache and node.st_uid == os.getuid() and
                stat.S_ISDIR(node.st_mode) and not node.st_mode & 0o022, 'public tooling cache must be owned and protected')
    opener = urllib.request.build_opener(OfficialHTTPS())
    end = time.monotonic() + RESOLVER_SECONDS
    with ci.deadline(RESOLVER_SECONDS), release.output_directory(output) as stage:
        work = stage / 'verify'
        work.mkdir()
        (work / 'home').mkdir()
        row, tag, version = latest(opener, end)
        source = commit_for_tag(opener, tag, end)
        assets = {name: acquire(opener, work / name, selected_asset(row, tag, name), end, cache) for name in ASSETS}
        verifier = work / 'cosign'
        acquire(opener, verifier, public.ARTIFACTS['cosign'], end, cache)
        verifier.chmod(0o500)
        digest, size = extract_binary(work / 'archive', work / 'binary', end)
        evidence = verify_signature(work, verifier, work / 'bundle', work / 'binary', tag, source, end)
        recheck, next_tag, _ = latest(opener, end)
        require(recheck['id'] == row['id'] and next_tag == tag and commit_for_tag(opener, tag, end) == source and
                all(selected_asset(recheck, tag, name) == selected_asset(row, tag, name) for name in ASSETS),
                'official tooling release changed during verification')
        value = {'schema': 1, 'kind': 'dev-pair-verified-codex-pin-proposal', 'reviewed_source_sha': approved_source,
                 'source_sha': source, 'tag': tag, 'version': version, 'release_id': row['id'],
                 'assets': {name: {key: info[key] for key in ('sha256', 'bytes')} for name, info in assets.items()},
                 'binary': {'sha256': digest, 'bytes': size}, 'verification_sha256': evidence}
        exact = matches_pins(value)
        numeric = tuple(int(part) for part in version.split('.'))
        shipped = tuple(int(part) for part in release.CODEX_VERSION.split('.'))
        require(numeric > shipped or exact, 'official tooling is older than the pinned baseline or changed at its pinned version')
        record = {**value, 'approved_pins_match': exact, 'cached_assets': sorted(name for name, row in assets.items() if row['reused'])}
        release.write_json(stage / 'tooling.json', public.tooling_record(record, approved_source))
        for key, name in (('archive', 'codex.tar.gz'), ('bundle', 'codex.sigstore'), ('cosign', 'cosign')):
            (work / key).rename(stage / name)
        shutil.rmtree(work)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--actions', action='store_true')
    args = parser.parse_args()
    metadata = {}
    if args.actions:
        from platform_release_ci import admitted_refresh
        admitted_refresh(args.source, os.environ)
        base = hex_id(os.environ.get('BASE_PLATFORM'))
        try:
            quota = int(os.environ.get('ARTIFACT_BYTES', ''))
        except ValueError:
            raise Blocked('agent artifact quota approval is missing') from None
        require(quota >= release.AGENT_BUDGET + TOOLING_CACHE_BUDGET, 'agent artifact quota cannot cover bounded release and cache')
        metadata = {'base': base, 'artifact-bytes': quota}
    record = resolve(args.output, args.source, args.cache)
    if filepath := os.environ.get('GITHUB_OUTPUT'):
        with Path(filepath).open('a') as stream:
            for name, value in metadata.items():
                stream.write(f'{name}={value}\n')
            stream.write('tooling-verified=true\n')
    print('Verified official stable Codex ' + record['version'])


if __name__ == '__main__':
    try:
        main()
    except (Blocked, ci.Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        ci.emit_text('TOOLING_REFRESH_BLOCKED ', str(exc), 1000)
        sys.exit(2)
