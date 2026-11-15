"""Pinned Fedora signed OCI input; local verification is not runtime admission."""
import contextlib
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import time

MIB = 1024 ** 2
NAME = 'Fedora-Container-Base-Generic-44-1.7.x86_64.oci.tar.xz'
URL = 'https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Container/x86_64/images/'
ARCHIVE_BYTES = 70170200
ARCHIVE_SHA = '75200f5752a74a21a616ca9a75e25beb594e2e117a0195c54f87c0b3e3974d1b'
CHECKSUM_SHA = '80b508bc3341680b09a4299a11d6f776fdf7d6a8b55f027e2db3130d81f11d0b'
KEY_SHA = '93642aec521a1e5e96dd715f7ae0ec0850ebc9de09a94ce03cae5263f26cc18a'
FINGERPRINT = '36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6'
MANIFEST = 'f1e66cdd6eff2c9ccad192f8865af9be6d69b46b3f13329d2975a2d61a1296c5'
CONFIG = '9eaa56a730854ae53f57e58c16179d09c2fa1f4157a5d69ccb39647e33c6464d'
LAYER = 'd93cacdefe7f7526297a08879cb444d1eeb526adf9cb7e34ab1f0609759a3044'
DIFF = 'fc2b4c6a945ce8413b6308454d39c096225d1a1a7488b4c8a250cde006225e4a'
IMAGE = 'sha256:' + CONFIG  # local immutable config ID, never a registry reference
FILES = ('fedora.oci.tar.xz', 'fedora-CHECKSUM', 'fedora-key')
ARTIFACTS = {
    FILES[0]: (URL + NAME, ARCHIVE_BYTES, ARCHIVE_SHA),
    FILES[1]: (URL + 'Fedora-Container-44-1.7-x86_64-CHECKSUM', 1841, CHECKSUM_SHA),
    FILES[2]: ('https://src.fedoraproject.org/rpms/fedora-repos/raw/f44/f/RPM-GPG-KEY-fedora-44-primary', 1672, KEY_SHA),
}
PROVENANCE = {'image': IMAGE, 'verification': 'Fedora44 signed release CHECKSUM; exact archive and OCI graph verified',
              'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST, 'config_sha256': CONFIG,
              'layer_sha256': LAYER, 'diff_id_sha256': DIFF, 'signer': FINGERPRINT,
              'checksum_sha256': CHECKSUM_SHA, 'key_sha256': KEY_SHA}
PLAIN_LIMIT = 80 * MIB
DIFF_LIMIT = 192 * MIB
DIFF_BYTES = 188336128


def require(ok, reason):
    if not ok: raise ValueError(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate OCI JSON field')
        result[key] = value
    return result


def _json(data):
    require(len(data) <= 256 * 1024, 'OCI JSON size exceeded')
    return json.loads(data, object_pairs_hook=unique)


def _tick(end):
    require(time.monotonic() < end, 'Fedora OCI verification deadline exceeded')


def _hash(stream, maximum, end, output=None):
    digest = hashlib.sha256(); total = 0
    while True:
        _tick(end)
        block = stream.read(min(MIB, maximum - total + 1))
        if not block: break
        total += len(block); require(total <= maximum, 'OCI expansion/byte budget exceeded')
        digest.update(block)
        if output is not None: output.write(block)
    return total, digest.hexdigest()


def _signature(work, end):
    from public_inputs import command
    home = work / 'gpg'; home.mkdir(mode=0o700)
    gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart', '--no-auto-key-retrieve', '--homedir', str(home)]
    command(gpg + ['--import', str(work / FILES[2])], work, timeout=max(.001, end-time.monotonic()))
    status, _ = command(gpg + ['--status-fd=1', '--verify', str(work / FILES[1])], work,
                        timeout=max(.001, end-time.monotonic()))
    require(re.findall(rb'^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ', status, re.M) == [FINGERPRINT.encode()],
            'Fedora OCI signer mismatch')
    data = (work / FILES[1]).read_bytes()
    require(hashlib.sha256(data).hexdigest() == CHECKSUM_SHA, 'Fedora signed checksum identity mismatch')
    text = data.decode('ascii')
    require(re.findall(r'^SHA256 \(' + re.escape(NAME) + r'\) = ([a-f0-9]{64})$', text, re.M) == [ARCHIVE_SHA]
            and re.findall(r'^# ' + re.escape(NAME) + r': ([0-9]+) bytes$', text, re.M) == [str(ARCHIVE_BYTES)],
            'Fedora signed archive declaration mismatch')
    return status.decode('ascii')


def parse_oci(plain, end):
    """Inspect an outer OCI transport; never extract or follow rootfs members."""
    blobs = {}; metadata = {}; seen = set(); count = 0
    with tarfile.open(plain, 'r:') as archive:
        for member in archive:
            _tick(end); count += 1; require(count <= 16, 'OCI entry count exceeded')
            name = member.name
            require(name not in seen and name in ('blobs', 'blobs/sha256', 'index.json', 'oci-layout',
                    *('blobs/sha256/' + value for value in (MANIFEST, CONFIG, LAYER))), 'unknown/duplicate OCI path')
            seen.add(name)
            require(not member.pax_headers and not member.issparse(), 'OCI extended/sparse header denied')
            if name in ('blobs', 'blobs/sha256'):
                require(member.isdir() and member.size == 0, 'OCI directory type mismatch'); continue
            require(member.isreg() and 0 < member.size <= PLAIN_LIMIT, 'OCI nonregular/oversized member denied')
            with archive.extractfile(member) as stream:
                size, value = _hash(stream, member.size, end)
            require(size == member.size, 'truncated OCI member')
            if name.startswith('blobs/'):
                require(name.rsplit('/', 1)[1] == value, 'OCI blob hash mismatch')
                blobs['sha256:' + value] = (member, size)
            if name != 'blobs/sha256/' + LAYER:
                require(size <= 256 * 1024, 'OCI metadata size exceeded')
                with archive.extractfile(member) as stream: metadata[name] = _json(stream.read())
        require(seen == {'blobs', 'blobs/sha256', 'index.json', 'oci-layout',
                        *('blobs/sha256/' + value for value in (MANIFEST, CONFIG, LAYER))}, 'missing OCI descriptor/blob')
        require(metadata['oci-layout'] == {'imageLayoutVersion':'1.0.0'}, 'unsupported OCI layout')
        index = metadata['index.json']; require(set(index) == {'schemaVersion','mediaType','manifests'} and index['schemaVersion'] == 2
                and index['mediaType'] == 'application/vnd.oci.image.index.v1+json'
                and len(index['manifests']) == 1, 'unsupported OCI index')
        def descriptor(item, digest, media):
            require(type(item) is dict and set(item) <= {'mediaType','digest','size','annotations'}
                    and item.get('digest') == 'sha256:' + digest and item.get('mediaType') == media
                    and type(item.get('size')) is int and item['size'] == blobs['sha256:' + digest][1], 'OCI descriptor mismatch')
        descriptor(index['manifests'][0], MANIFEST, 'application/vnd.oci.image.manifest.v1+json')
        manifest = metadata['blobs/sha256/' + MANIFEST]
        require(set(manifest) <= {'schemaVersion','mediaType','config','layers','annotations'} and manifest['schemaVersion'] == 2
                and manifest['mediaType'] == 'application/vnd.oci.image.manifest.v1+json'
                and len(manifest['layers']) == 1, 'unsupported OCI manifest')
        descriptor(manifest['config'], CONFIG, 'application/vnd.oci.image.config.v1+json')
        descriptor(manifest['layers'][0], LAYER, 'application/vnd.oci.image.layer.v1.tar+gzip')
        config = metadata['blobs/sha256/' + CONFIG]
        require(config['os'] == 'linux' and config['architecture'] == 'amd64'
                and config['rootfs'] == {'type':'layers','diff_ids':['sha256:' + DIFF]}, 'OCI platform/rootfs mismatch')
        with archive.extractfile(blobs['sha256:' + LAYER][0]) as stream, gzip.GzipFile(fileobj=stream) as expanded:
            size, value = _hash(expanded, DIFF_LIMIT, end)
        require(size == DIFF_BYTES and value == DIFF, 'OCI rootfs diff identity mismatch')
        with open(plain, 'rb') as tail:
            tail.seek(archive.offset)
            while True:
                _tick(end); data = tail.read(MIB)
                if not data: break
                require(not any(data), 'nonzero OCI trailing bytes')
    return dict(PROVENANCE)


@contextlib.contextmanager
def verified(source, *, seconds=120):
    """Private captured bytes, fixed pin first, signature before decoding; owned cleanup."""
    from public_inputs import capture_regular
    end = time.monotonic() + seconds
    with tempfile.TemporaryDirectory(prefix='dev-pair-fedora-') as temporary:
        work = Path(temporary); (work/'home').mkdir()
        for name, (_, size, expected) in ARTIFACTS.items():
            _tick(end)
            _, actual = capture_regular(Path(source)/name, size, exact_size=size, destination=work/name)
            require(actual == expected, 'Fedora public input identity mismatch')
        status = _signature(work, end)
        plain = work / 'base.oci.tar'
        with lzma.open(work/FILES[0], 'rb') as src, open(plain, 'xb') as out:
            _hash(src, PLAIN_LIMIT, end, out)
        proof = parse_oci(plain, end)
        proof.update(signature_status=status, plain_bytes=plain.stat().st_size)
        _tick(end)
        plain.chmod(0o444); work.chmod(0o755)  # exact public image, readable by dp-maint only after verification
        yield plain, proof


def imported(rows):
    """No conversion is presumed: immutable config, manifest and layer diff must match."""
    require(type(rows) is list and len(rows) == 1, 'ambiguous imported Fedora image')
    item = rows[0]
    require(item.get('Id','').removeprefix('sha256:') == CONFIG
            and item.get('Digest') == 'sha256:' + MANIFEST
            and item.get('ManifestType') == 'application/vnd.oci.image.manifest.v1+json'
            and item.get('Os') == 'linux' and item.get('Architecture') == 'amd64'
            and item.get('RootFS',{}).get('Layers') == ['sha256:' + DIFF], 'imported Fedora identity/format mismatch')
    return {'source':PROVENANCE, 'imported_config':'sha256:'+CONFIG,
            'imported_manifest':'sha256:'+MANIFEST, 'conversion':'none; exact digest equality required'}


def import_image(engine, plain, uid=None, seconds=120):
    """Local-only import and save-back proof; failed imports may retain store data."""
    from public_inputs import capture_regular
    end = time.monotonic() + seconds
    def call(*args):
        _tick(end)
        return engine(*args, timeout=max(.001, end-time.monotonic()))
    call('load', '--input', str(plain))
    record = imported(json.loads(call('image', 'inspect', IMAGE)))
    export = plain.parent / 'imported.oci.tar'
    fd = os.open(export, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        if uid is not None: os.fchown(fd, uid, -1)
    finally: os.close(fd)
    call('save', '--format=oci-archive', '--output', str(export), IMAGE)
    captured = plain.parent / 'captured-import.oci.tar'
    capture_regular(export, PLAIN_LIMIT, destination=captured)
    parse_oci(captured, end)
    record['verification'] = 'Save-back OCI graph manifest/config/compressed-layer/diff_id equality; no format conversion accepted'
    record['failure_recovery'] = 'Import is nontransactional; unreferenced store layers may remain, no broad prune/removal'
    return record
