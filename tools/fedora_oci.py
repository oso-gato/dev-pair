"""Pinned Fedora signed OCI input; local verification is not runtime admission."""
import contextlib
import gzip
import hashlib
import json
import lzma
import math
import os
import sys
from pathlib import Path
import re
import shutil
import signal
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
SAVE_FILE_LIMIT = 192 * MIB
UNLINKED_RESERVE = 192 * MIB
IMPORT_PEAK_RESERVE = 768 * MIB
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


def _public_inputs():
    try:
        import public_inputs
    except ModuleNotFoundError:
        import importlib.util
        spec = importlib.util.spec_from_file_location('public_inputs', Path(__file__).with_name('public_inputs.py'))
        public_inputs = importlib.util.module_from_spec(spec)
        sys.modules['public_inputs'] = public_inputs
        spec.loader.exec_module(public_inputs)
    return public_inputs


def _signature(work, end):
    command = _public_inputs().command
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


def _headers(plain, end):
    # tarfile silently consumes GNU/PAX pseudo-members before returning a member.
    # Validate every raw header first, within the same finite transport bound.
    with open(plain, 'rb') as source:
        length = os.fstat(source.fileno()).st_size
        require(0 < length <= PLAIN_LIMIT and length % 512 == 0, 'invalid OCI tar length')
        count = 0
        while source.tell() < length:
            _tick(end)
            block = source.read(512)
            require(len(block) == 512, 'truncated OCI header')
            if block == bytes(512):
                zeros = 512
                while True:
                    _tick(end); tail = source.read(MIB)
                    if not tail: break
                    zeros += len(tail); require(not any(tail), 'nonzero OCI trailing bytes')
                require(zeros >= 1024, 'missing OCI tar terminator')
                return
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
            count += 1
            require(count <= 16 and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                    'OCI unsupported extended/nonregular header or entry count')
            require(0 <= member.size <= PLAIN_LIMIT, 'OCI raw member size exceeded')
            target = source.tell() + ((member.size + 511) // 512) * 512
            require(target <= length, 'truncated OCI raw member')
            source.seek(target)
        raise ValueError('missing OCI tar terminator')


def parse_oci(plain, end, *, derived=False):
    """Inspect an outer OCI transport; never extract or follow rootfs members."""
    _headers(plain, end)
    blobs = {}; metadata = {}; seen = set(); count = 0
    with tarfile.open(plain, 'r:') as archive:
        for member in archive:
            _tick(end); count += 1; require(count <= 16, 'OCI entry count exceeded')
            name = member.name
            if name == '.':
                require(member.isdir() and member.size == 0 and name not in seen, 'invalid OCI root directory')
                seen.add(name); continue
            if name.startswith('./'): name = name[2:]
            known = name in ('blobs', 'blobs/sha256', 'index.json', 'oci-layout')
            blob = re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name)
            require(name not in seen and (known or blob and (derived or name.rsplit('/', 1)[1] in (MANIFEST, CONFIG, LAYER))),
                    'unknown/duplicate OCI path')
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
            if size <= 256 * 1024:
                with archive.extractfile(member) as stream: metadata[name] = stream.read()
        require({'index.json','oci-layout'} <= seen and len(blobs) == 3, 'missing OCI descriptor/blob')
        require(_json(metadata['oci-layout']) == {'imageLayoutVersion':'1.0.0'}, 'unsupported OCI layout')
        index = _json(metadata['index.json'])
        require(set(index) == {'schemaVersion','mediaType','manifests'} and index['schemaVersion'] == 2
                and index['mediaType'] == 'application/vnd.oci.image.index.v1+json'
                and type(index['manifests']) is list and len(index['manifests']) == 1, 'unsupported OCI index')
        def descriptor(item, media, wanted=None):
            require(type(item) is dict and set(item) <= {'mediaType','digest','size','annotations'}
                    and type(item.get('digest')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',item['digest'])
                    and item['digest'] in blobs and item.get('mediaType') == media
                    and type(item.get('size')) is int and item['size'] == blobs[item['digest']][1]
                    and (wanted is None or item['digest'] == 'sha256:'+wanted), 'OCI descriptor mismatch')
            return item['digest'].removeprefix('sha256:')
        manifest_id = descriptor(index['manifests'][0], 'application/vnd.oci.image.manifest.v1+json', None if derived else MANIFEST)
        manifest = _json(metadata['blobs/sha256/' + manifest_id])
        require(set(manifest) <= {'schemaVersion','mediaType','config','layers','annotations'} and manifest['schemaVersion'] == 2
                and manifest['mediaType'] == 'application/vnd.oci.image.manifest.v1+json'
                and type(manifest['layers']) is list and len(manifest['layers']) == 1, 'unsupported OCI manifest')
        descriptor(manifest['config'], 'application/vnd.oci.image.config.v1+json', CONFIG)
        layer_id = descriptor(manifest['layers'][0], 'application/vnd.oci.image.layer.v1.tar+gzip', None if derived else LAYER)
        require(set(blobs) == {'sha256:'+manifest_id,'sha256:'+CONFIG,'sha256:'+layer_id}, 'unreferenced OCI blob')
        config = _json(metadata['blobs/sha256/' + CONFIG])
        require(config['os'] == 'linux' and config['architecture'] == 'amd64'
                and config['rootfs'] == {'type':'layers','diff_ids':['sha256:' + DIFF]}, 'OCI platform/rootfs mismatch')
        with archive.extractfile(blobs['sha256:' + layer_id][0]) as stream, gzip.GzipFile(fileobj=stream) as expanded:
            size, value = _hash(expanded, DIFF_LIMIT, end)
        require(size == DIFF_BYTES and value == DIFF, 'OCI rootfs diff identity mismatch')
        with open(plain, 'rb') as tail:
            tail.seek(archive.offset)
            while True:
                _tick(end); data = tail.read(MIB)
                if not data: break
                require(not any(data), 'nonzero OCI trailing bytes')
    return (dict(PROVENANCE) if not derived else {'manifest_sha256':manifest_id, 'config_sha256':CONFIG,
            'compressed_layer_sha256':layer_id, 'diff_id_sha256':DIFF,
            'derivation':'storage export gzip recompression allowed; exact source config bytes and rootfs diff stream required'})


@contextlib.contextmanager
def _wall_deadline(end):
    now = time.monotonic()
    previous = signal.getitimer(signal.ITIMER_REAL)
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_end = now + previous[0] if previous[0] else None
    if previous_end is not None: end = min(end, previous_end)
    def expired(signum, frame):
        raise ValueError('Fedora OCI verification deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(.000001, end-now))
    try:
        yield
        _tick(end)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_end is not None:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, previous_end-time.monotonic()), previous[1])


@contextlib.contextmanager
def verified(source, *, seconds=120, temporary_parent=None):
    """Private captured bytes, fixed pin first, signature before decoding; owned cleanup."""
    capture_regular = _public_inputs().capture_regular
    require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 120, 'invalid Fedora verification budget')
    end = time.monotonic() + seconds
    with tempfile.TemporaryDirectory(prefix='dev-pair-fedora-', dir=temporary_parent or source) as temporary:
        work = Path(temporary); (work/'home').mkdir()
        with _wall_deadline(end):
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
    require(type(item) is dict and type(item.get('Id')) is str and type(item.get('RootFS')) is dict, 'malformed imported Fedora inspection')
    require(item.get('Id','').removeprefix('sha256:') == CONFIG
            and item.get('Digest') == 'sha256:' + MANIFEST
            and item.get('ManifestType') == 'application/vnd.oci.image.manifest.v1+json'
            and item.get('Os') == 'linux' and item.get('Architecture') == 'amd64'
            and item.get('RootFS',{}).get('Layers') == ['sha256:' + DIFF], 'imported Fedora identity/format mismatch')
    return {'source':PROVENANCE, 'imported_config':'sha256:'+CONFIG,
            'imported_manifest':'sha256:'+MANIFEST, 'conversion':'none; exact digest equality required'}


def import_image(engine, plain, uid=None, seconds=120):
    """Local-only import and save-back proof; failed imports may retain store data."""
    capture_regular = _public_inputs().capture_regular
    require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 120, 'invalid Fedora import budget')
    end = time.monotonic() + seconds
    parse_oci(plain, end)  # Invalid local sources never reach even the first engine call.
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
    record['saveback'] = parse_oci(captured, end, derived=True)
    record['conversion'] = 'source manifest/config retained on load; storage save gzip representation derived and fully rehashed'
    record['verification'] = 'Source archive chain plus exported config-byte/rootfs-diff equality and full derived descriptor/blob graph'
    record['failure_recovery'] = 'Import is nontransactional; unreferenced store layers may remain, no broad prune/removal'
    return record


@contextlib.contextmanager
def copy_workspace(parent, *, uid=None, reconcile, remove=None, reserve=0):
    parent = Path(parent).absolute()
    require(parent.resolve() == parent, 'image copy parent symlink denied')
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
            'image copy parent must be controller owned')
    require(shutil.disk_usage(parent).free >= reserve + IMPORT_PEAK_RESERVE, 'image copy peak/reserve capacity blocked')
    path, record = parent/'image-copy', parent/'image-copy-owner.json'
    actor = os.getuid() if uid is None else uid
    for ancestor in (parent, *parent.parents):
        node = ancestor.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_mode & (0o100 if node.st_uid==actor else 0o001),
                'image copy actor cannot traverse intended parent')
    def identity(target):
        value = target.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == actor and stat.S_IMODE(value.st_mode) == 0o700,
                'image copy directory ownership changed')
        return [value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode]
    def recorded():
        fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            node=os.fstat(stream.fileno())
            require(stat.S_ISREG(node.st_mode) and node.st_uid==os.getuid() and node.st_nlink==1
                    and stat.S_IMODE(node.st_mode)==0o600 and node.st_size<=2048,'image copy proof invalid')
            return json.loads(stream.read(2049),object_pairs_hook=unique)
    def cleanup():
        require(recorded()==proof and identity(path)==proof['identity'],'image copy ownership proof changed')
        reconcile()  # Must establish the exact executor stopped; failure preserves the leaf.
        require(identity(path)==proof['identity'],'image copy directory replaced during reconciliation')
        (remove or shutil.rmtree)(path)
        record.unlink()
    if path.exists() or path.is_symlink() or record.exists() or record.is_symlink():
        require(path.exists() and record.exists(),'unproven image copy allocation preserved')
        proof=recorded()
        require(type(proof) is dict and set(proof)=={'version','parent','identity'} and proof['version']==1
                and proof['parent']==[info.st_dev,info.st_ino] and proof['identity']==identity(path), 'foreign image copy proof')
        cleanup()
    path.mkdir(mode=0o700);path.chmod(0o700)
    if uid is not None:os.chown(path,uid,-1)
    proof={'version':1,'parent':[info.st_dev,info.st_ino],'identity':identity(path)}
    fd=os.open(record,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(json.dumps(proof,sort_keys=True).encode()+b'\n');stream.flush();os.fsync(stream.fileno())
    try:yield path
    finally:cleanup()
