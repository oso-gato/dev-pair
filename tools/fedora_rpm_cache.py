#!/usr/bin/python3
"""Bounded, authenticated stock Fedora DNF construction cache."""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import time
import xml.etree.ElementTree as ET

import fedora_oci


LIMIT = 384 * 1024 ** 2
CONTROL_LIMIT = 256 * 1024
FILES_LIMIT = 512
METADATA_LIMIT = 2 * 1024 ** 2
PRIMARY_LIMIT = 256 * 1024 ** 2
PRIMARY_WINDOW_LIMIT = 16 * 1024 ** 2
PRIMARY_NAMESPACE = b'http://linux.duke.edu/metadata/common'
WORK_PEAK = 2 * LIMIT + PRIMARY_LIMIT
REPOSITORIES = {'fedora-cff72538bc9825a4': {'primary', 'primary_zck', 'group'},
                'updates-3cc07c89a20302f2': {'primary', 'primary_zck', 'group', 'updateinfo_zck'}}
ROOT = '/var/cache/libdnf5'
DROPIN_NAME = '99-dev-pair-construction-cache.conf'
DROPIN_PATH = '/etc/dnf/libdnf5.conf.d/' + DROPIN_NAME
DROPIN = b'[main]\ncacheonly=all\n'
HEX = re.compile(r'[0-9a-f]{64}')
GIT = re.compile(r'[0-9a-f]{40}')
RPM = re.compile(r'[0-9A-Za-z][0-9A-Za-z_.+~^%-]{0,239}\.rpm')
REPODATA = re.compile(r'repodata/[0-9a-f]{64}-[A-Za-z0-9_.-]+')
SIGNER = fedora_oci.FINGERPRINT.lower()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def binding(source, standards, recipe, *, outer_recipe=None):
    require(GIT.fullmatch(source) and GIT.fullmatch(standards) and HEX.fullmatch(recipe),
            'invalid RPM cache source or recipe identity')
    pinned = {'schema': 1, 'kind': 'fedora44-stock-dnf-cache', 'source_sha': source, 'standards_sha': standards,
              'recipe_sha256': recipe, 'base_image': fedora_oci.IMAGE}
    if outer_recipe is not None:
        require(HEX.fullmatch(outer_recipe), 'invalid outer RPM cache recipe identity')
        pinned['outer_recipe_sha256'] = outer_recipe
    return pinned


def member_name(name):
    repo, sep, leaf = name.partition('/')
    require(sep and repo in REPOSITORIES and (leaf in {'metalink.xml', 'repodata/repomd.xml'}
            or REPODATA.fullmatch(leaf) or (leaf.startswith('packages/') and RPM.fullmatch(leaf[9:]))),
            'RPM cache contains an unexpected path')
    return repo, leaf


def remaining(end):
    seconds = end - time.monotonic()
    require(seconds > 0, 'RPM cache verification deadline exceeded')
    return seconds


def digest(path, end):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            remaining(end)
            value.update(block)
    return value.hexdigest()


def validate_manifest(raw, expected_sha, wanted):
    require(HEX.fullmatch(expected_sha) and hashlib.sha256(raw).hexdigest() == expected_sha,
            'RPM cache manifest differs from separately supplied digest')
    manifest = json.loads(raw, object_pairs_hook=fedora_oci.unique)
    keys = set(wanted) | {'files'}
    require(type(manifest) is dict and keys <= set(manifest) <= keys | {'outer_recipe_sha256'} and raw == canonical(manifest)
            and type(manifest['schema']) is int and all(manifest[key] == value for key, value in wanted.items()),
            'RPM cache manifest differs from source, recipe or Fedora base')
    if 'outer_recipe_sha256' in manifest:
        require(type(manifest['outer_recipe_sha256']) is str and HEX.fullmatch(manifest['outer_recipe_sha256']),
                'invalid RPM cache outer recipe binding')
    files = manifest['files']
    require(type(files) is dict and 0 < len(files) <= FILES_LIMIT, 'invalid RPM cache inventory')
    total = 0
    for name, item in files.items():
        member_name(name)
        require(type(item) is dict and set(item) == {'bytes', 'sha256'} and type(item['bytes']) is int
                and 0 < item['bytes'] <= LIMIT and type(item['sha256']) is str and HEX.fullmatch(item['sha256']),
                'invalid RPM cache file descriptor')
        total += item['bytes']
    require(total < LIMIT, 'RPM cache inventory exceeds the transport limit')
    return files


def read_header(stream):
    block = stream.read(512)
    if block == bytes(512):
        return None
    require(len(block) == 512 and block[257:263] == b'ustar\x00', 'RPM cache requires bounded USTAR')
    item = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
    require(item.type == tarfile.REGTYPE and item.uid == item.gid == item.mtime == 0 and item.mode == 0o444
            and item.size > 0 and not item.linkname, 'RPM cache contains a noncanonical file header')
    return item


def unpack(archive, expected_sha, wanted, destination, key, end, *, signature_check=None):
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and not info.st_mode & 0o022 and 0 < info.st_size <= LIMIT, 'unsafe RPM cache transport')
        item = read_header(stream)
        require(item and item.name == 'manifest.json' and item.size <= CONTROL_LIMIT, 'RPM cache manifest must be first')
        raw = stream.read(item.size)
        files = validate_manifest(raw, expected_sha, wanted)
        require(stream.read(-item.size % 512) == bytes(-item.size % 512), 'invalid RPM cache manifest padding')
        seen = set()
        while item := read_header(stream):
            remaining(end)
            entry = files.get(item.name)
            require(entry is not None and item.name not in seen and entry['bytes'] == item.size
                    and stream.tell() + item.size <= info.st_size, 'missing, duplicate or changed RPM cache file')
            seen.add(item.name)
            path = destination / item.name
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            checksum = hashlib.sha256()
            left = item.size
            with path.open('xb') as output:
                while left:
                    remaining(end)
                    data = stream.read(min(left, 1024 * 1024))
                    require(data, 'truncated RPM cache file')
                    output.write(data)
                    checksum.update(data)
                    left -= len(data)
                os.fchmod(output.fileno(), 0o444)
            require(checksum.hexdigest() == entry['sha256'], 'RPM cache file digest mismatch')
            require(stream.read(-item.size % 512) == bytes(-item.size % 512), 'invalid RPM cache padding')
        padding = stream.read(tarfile.RECORDSIZE + 1)
        require(seen == set(files) and 512 <= len(padding) <= tarfile.RECORDSIZE and padding == bytes(len(padding))
                and stream.tell() == info.st_size, 'RPM cache transport is incomplete or has trailing data')
    if signature_check is None:
        validate_repositories(destination, files, key, end)
    else:
        validate_repositories(destination, files, key, end, signature_check=signature_check)
    return destination


def xml_document(path):
    with path.open('rb') as stream:
        data = stream.read(METADATA_LIMIT + 1)
    require(0 < len(data) <= METADATA_LIMIT and b'<!DOCTYPE' not in data, 'unsupported Fedora metadata document')
    try:
        return data, ET.fromstring(data)
    except ET.ParseError:
        raise ValueError('malformed Fedora metadata document') from None


def xml_child(parent, name):
    child = parent.find('{*}' + name)
    require(child is not None, 'required Fedora metadata element missing')
    return child


def command(args, work, end, *, output=None):
    result = subprocess.run(args, cwd=work, timeout=remaining(end), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if output is None else output, stderr=subprocess.PIPE,
                            env={'PATH': '/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'Fedora metadata or RPM signature verification failed')
    return result.stdout


def primary_packages(stream, packages, end):
    """Check the complete primary XML with the stock libxml2 streaming reader."""
    library = ctypes.CDLL('libxml2.so.2')
    integer, pointer, string = ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p
    input_reader = ctypes.CFUNCTYPE(integer, pointer, pointer, integer)
    error_handler = ctypes.CFUNCTYPE(None, pointer, pointer, integer, pointer)

    def api(name, result, *arguments):
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
        return function

    create = api('xmlReaderForIO', pointer, input_reader, pointer, pointer, string, string, integer)
    set_error_handler = api('xmlTextReaderSetErrorHandler', None, pointer, error_handler, pointer)
    read = api('xmlTextReaderRead', integer, pointer)
    next_sibling = api('xmlTextReaderNext', integer, pointer)
    kind = api('xmlTextReaderNodeType', integer, pointer)
    depth = api('xmlTextReaderDepth', integer, pointer)
    name = api('xmlTextReaderConstLocalName', string, pointer)
    namespace = api('xmlTextReaderConstNamespaceUri', string, pointer)
    expand = api('xmlTextReaderExpand', pointer, pointer)
    document = api('xmlTextReaderCurrentDoc', pointer, pointer)
    free_reader = api('xmlFreeTextReader', None, pointer)
    free_document = api('xmlFreeDoc', None, pointer)
    xpath_context = api('xmlXPathNewContext', pointer, pointer)
    set_context = api('xmlXPathSetContextNode', integer, pointer, pointer)
    register = api('xmlXPathRegisterNs', integer, pointer, string, string)
    compile_xpath = api('xmlXPathCompile', pointer, string)
    evaluate = api('xmlXPathCompiledEval', pointer, pointer, pointer)
    as_string = api('xmlXPathCastToString', pointer, pointer)
    free_value = api('xmlXPathFreeObject', None, pointer)
    free_xpath = api('xmlXPathFreeCompExpr', None, pointer)
    free_context = api('xmlXPathFreeContext', None, pointer)
    free_string = ctypes.CFUNCTYPE(None, pointer).in_dll(library, 'xmlFree')

    window = 0
    input_error = None

    @input_reader
    def read_data(_context, buffer, length):
        nonlocal window, input_error
        if time.monotonic() >= end:
            input_error = 'RPM cache verification deadline exceeded'
            return -1
        try:
            data = stream.read(length)
        except OSError:
            input_error = 'cannot read expanded Fedora primary metadata'
            return -1
        window += len(data)
        if window > PRIMARY_WINDOW_LIMIT:
            input_error = 'oversized Fedora primary metadata record'
            return -1
        ctypes.memmove(buffer, data, len(data))
        return len(data)

    @error_handler
    def malformed(_context, _message, _severity, _locator):
        nonlocal input_error
        if input_error is None:
            input_error = 'malformed Fedora primary metadata'

    def advance(operation):
        result = operation(reader)
        require(input_error is None, input_error)
        return result

    def field(index):
        result = evaluate(expressions[index], context)
        require(result, 'cannot read Fedora primary metadata field')
        try:
            value = as_string(result)
            require(value, 'cannot read Fedora primary metadata field')
            try:
                return ctypes.string_at(value)
            finally:
                free_string(value)
        finally:
            free_value(result)

    # NONET, NOBLANKS and COMPACT. Keep DTD loading, entity substitution
    # and HUGE disabled, and reject any DOCTYPE node.
    options = 2048 | 256 | 65536
    reader = create(read_data, None, None, None, b'UTF-8', options)
    require(reader, input_error or 'cannot open Fedora primary metadata reader')
    set_error_handler(reader, malformed, None)
    context = doc = None
    expressions = []
    element, end_element = 1, 15
    ignorable = (7, 8, 13, 14)  # Processing instruction, comment and whitespace.
    expected = {key.encode('ascii'): value for key, value in packages.items()}
    found = set()
    try:
        status = advance(read)
        while status == 1 and kind(reader) in ignorable:
            status = advance(read)
        require(status == 1 and kind(reader) == element and depth(reader) == 0
                and name(reader) == b'metadata' and namespace(reader) == PRIMARY_NAMESPACE,
                'malformed Fedora primary metadata')
        doc = document(reader)
        require(doc, 'cannot open Fedora primary metadata document')
        context = xpath_context(doc)
        require(context and register(context, b'c', PRIMARY_NAMESPACE) == 0,
                'cannot open Fedora primary metadata query')
        for query in (
            b"string(c:location[count(../*[local-name()='location'])=1 and not(*)"
            b" and not(../descendant::*[local-name()='package'])]/@href)",
            b"string(c:size[count(../*[local-name()='size'])=1 and not(*)]/@package)",
            b"string(c:checksum[count(../*[local-name()='checksum'])=1 and not(*)]/@type)",
            b'string(c:checksum)',
        ):
            expression = compile_xpath(query)
            require(expression, 'cannot compile Fedora primary metadata query')
            expressions.append(expression)

        status = advance(read)
        while status == 1 and kind(reader) != end_element:
            remaining(end)
            if kind(reader) in ignorable:
                status = advance(read)
                continue
            require(kind(reader) == element and depth(reader) == 1 and name(reader) == b'package'
                    and namespace(reader) == PRIMARY_NAMESPACE, 'malformed Fedora primary metadata package')
            package = advance(expand)
            require(package and set_context(package, context) == 0, 'malformed Fedora primary metadata package')
            location = field(0)
            require(location, 'invalid or duplicate Fedora primary package location')
            basename = location.rsplit(b'/', 1)[-1]
            if basename in expected:
                length, algorithm, checksum = field(1), field(2), field(3)
                require(re.fullmatch(rb'Packages/[0-9a-z]/' + re.escape(basename), location)
                        and algorithm == b'sha256' and basename not in found
                        and length.isdigit() and len(length) <= len(str(LIMIT))
                        and expected[basename]['bytes'] == int(length)
                        and expected[basename]['sha256'].encode('ascii') == checksum,
                        'RPM bytes differ from Fedora primary metadata')
                found.add(basename)
            window = 0
            status = advance(next_sibling)
        require(status == 1 and depth(reader) == 0, 'malformed Fedora primary metadata')
        while (status := advance(read)) == 1:
            require(kind(reader) in ignorable, 'malformed Fedora primary metadata trailer')
        require(status == 0, 'malformed Fedora primary metadata trailer')
        remaining(end)
        require(found == set(expected), 'RPM missing from Fedora primary metadata')
    finally:
        for expression in expressions:
            free_xpath(expression)
        if context:
            free_context(context)
        free_reader(reader)
        if doc:
            free_document(doc)


def validate_primary(path, sizes, packages, end):
    with path.with_name('primary.xml').open('x+b') as stream:
        try:
            size = sizes[0]
            require(0 < size <= PRIMARY_LIMIT and HEX.fullmatch(sizes[1]), 'invalid expanded primary metadata identity')
            command(['/usr/bin/prlimit', f'--fsize={size}:{size}', '--core=0:0', '--', '/usr/bin/zstd', '-dc', '--', str(path)],
                    path.parent, end, output=stream)
            stream.seek(0)
            value = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(stream.tell() == size and value == sizes[1], 'expanded primary metadata differs from Fedora repomd')
            stream.seek(0)
            primary_packages(stream, packages, end)
        finally:
            Path(stream.name).unlink()


def validate_repositories(destination, files, key, end, *, signature_check=None):
    all_rpms = []
    for repo, kinds in REPOSITORIES.items():
        root = destination / repo
        nodes = {name.split('/', 1)[1]: entry for name, entry in files.items() if name.startswith(repo + '/')}
        require({'metalink.xml', 'repodata/repomd.xml'} <= nodes.keys(), 'Fedora metalink or repomd missing')
        _, metalink = xml_document(root / 'metalink.xml')
        raw, index = xml_document(root / 'repodata/repomd.xml')
        metalink_files = metalink.findall('./{*}files/{*}file')
        require(len(metalink_files) == 1 and metalink_files[0].get('name') == 'repomd.xml', 'invalid Fedora metalink index')
        hashes = metalink_files[0].findall('./{*}verification/{*}hash')
        for name in ('sha256', 'sha512'):
            require([item.text for item in hashes if item.get('type') == name] == [hashlib.new(name, raw).hexdigest()],
                    'Fedora repomd differs from the verified metalink hashes')
        selected = {}
        for entry in index.findall('./{*}data'):
            kind = entry.get('type')
            if kind not in kinds:
                continue
            name = xml_child(entry, 'location').get('href', '')
            checksum = xml_child(entry, 'checksum')
            require(kind not in selected and REPODATA.fullmatch(name) and checksum.get('type') == 'sha256'
                    and nodes.get(name) == {'bytes': int(entry.findtext('{*}size')), 'sha256': checksum.text},
                    'RPM cache repodata differs from Fedora repomd')
            selected[kind] = name
            if kind == 'primary':
                expanded = xml_child(entry, 'open-checksum')
                require(expanded.get('type') == 'sha256', 'unsupported expanded Fedora primary hash')
                primary = (int(entry.findtext('{*}open-size')), expanded.text)
        packages = {name[9:]: entry for name, entry in nodes.items() if name.startswith('packages/')}
        require(set(selected) == kinds and packages and set(nodes) == {'metalink.xml', 'repodata/repomd.xml'}
                | set(selected.values()) | {'packages/' + name for name in packages},
                'incomplete or unexpected Fedora cache metadata')
        validate_primary(root / selected['primary'], primary, packages, end)
        all_rpms.extend(root / 'packages' / name for name in sorted(packages))
    require(digest(key, end) == fedora_oci.KEY_SHA, 'Fedora RPM signing key differs from the pinned key')
    (signature_check or verify_signatures)(destination, key, all_rpms, end)


def verify_signatures(destination, key, packages, end):
    database = destination.parent / 'rpm-signature-db'
    database.mkdir(mode=0o700)
    argv = ['/usr/bin/rpmkeys', '--dbpath', str(database), '--define', f'_keyringpath {database}/keys']
    command([*argv, '--import', str(key)], database, end)
    keys = command([*argv, '--list'], database, end).decode().splitlines()
    require(len(keys) == 1 and keys[0].partition(' ')[0] == SIGNER, 'unexpected RPM signature keyring')
    for start in range(0, len(packages), 32):
        batch = packages[start:start + 32]
        rows = command([*argv, '--checksig', '--verbose', *map(str, batch)], database, end).decode().splitlines()
        verify_signature_output(batch, rows)


def verify_signature_output(packages, rows):
    expected = set(map(str, packages))
    verified = {}
    current = None
    for row in rows:
        if not row.startswith(' '):
            current = row.removesuffix(':')
            require(current in expected and current not in verified, 'unexpected RPM signature output')
            verified[current] = []
        elif 'signature, key fingerprint:' in row:
            require(current in verified, 'RPM signature output lacks its package')
            verified[current].append(row.split('signature, key fingerprint: ', 1)[-1])
    require(set(verified) == expected and all(items == [SIGNER + ': OK'] for items in verified.values()),
            'missing or unexpected Fedora RPM signature')


def mount_args(work):
    return ('--volume', f'{work / "rpm-cache"}:{ROOT}:rw,Z,nodev,nosuid,noexec',
            '--volume', f'{work / DROPIN_NAME}:{DROPIN_PATH}:ro,Z,nodev,nosuid,noexec')


def build_mounts(work, canonical_cache, uid, gid):
    require(work.resolve(strict=True) == work and work.stat().st_uid == os.getuid()
            and not work.stat().st_mode & 0o022, 'RPM build copy requires a protected staging directory')
    cache = work / 'rpm-cache'
    shutil.copytree(canonical_cache, cache)
    dropin = work / DROPIN_NAME
    with dropin.open('xb') as stream:
        stream.write(DROPIN)
        os.fchmod(stream.fileno(), 0o444)
    # Release ownership only after each subtree has been populated. The bound
    # mount leaves remain anchored in the controller-owned staging directory.
    paths = sorted(cache.rglob('*'), key=lambda path: len(path.parts), reverse=True)
    for path in [*paths, cache, dropin]:
        if path.is_dir():
            path.chmod(0o755)
        os.chown(path, uid, gid)
    return mount_args(work)


def assembly_handoff(work, canonical_cache, gid):
    work.mkdir(mode=0o700)
    cache = work / 'rpm-cache'
    shutil.copytree(canonical_cache, cache)
    dropin = work / DROPIN_NAME
    dropin.write_bytes(DROPIN)
    for path in [cache, *cache.rglob('*'), dropin, work]:
        os.chown(path, -1, gid)
        path.chmod(0o750 if path.is_dir() else 0o440)
    return cache, dropin


def cache_member(name):
    path = PurePosixPath(posixpath.normpath('/' + name.lstrip('/')).lstrip('/'))
    cache = PurePosixPath(ROOT.lstrip('/'))
    return (path.name == DROPIN_NAME or path.suffix == '.rpm'
            or path == cache or cache in path.parents)


def audit_layer(stream, maximum, end):
    checksum = hashlib.sha256()
    expanded = 0

    def read(size, exact=True):
        nonlocal expanded
        remaining(end)
        data = stream.read(min(size, maximum - expanded + 1))
        expanded += len(data)
        require(expanded <= maximum and (not exact or len(data) == size),
                'OCI cache history layer truncated or above its expansion limit')
        checksum.update(data)
        return data

    zero = bytes(512)
    extensions = {}
    for _ in range(150000):
        header = read(512)
        if header == zero:
            require(not extensions and read(512) == zero, 'malformed OCI cache history terminator')
            while trailer := read(1024 * 1024, exact=False):
                require(not any(trailer), 'nonzero data trails the OCI cache history layer')
            return 'sha256:' + checksum.hexdigest(), expanded
        entry = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        if entry.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            require(0 < entry.size <= 65536 and len(extensions) <= 3, 'oversized OCI archive metadata')
            body = read(entry.size)
            if entry.type in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                key = 'path' if entry.type == tarfile.GNUTYPE_LONGNAME else 'linkpath'
                require(key not in extensions and b'\0' in body, 'invalid OCI archive long path')
                name, padding = body.split(b'\0', 1)
                require(not any(padding), 'invalid OCI archive long path padding')
                extensions[key] = name.decode('utf-8')
            else:
                selected = pax_identity(body)
                require(not selected if entry.type == tarfile.XGLTYPE else not selected.keys() & extensions.keys(),
                        'ambiguous OCI archive extended identity')
                extensions.update(selected)
            require(read(-entry.size % 512) == bytes(-entry.size % 512), 'invalid OCI archive metadata padding')
            continue
        require(entry.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE,
                               tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE),
                'unsupported OCI archive layer member')
        name = extensions.get('path', entry.name)
        require(name and '\0' not in name and '..' not in PurePosixPath(name).parts,
                'unsafe OCI archive layer path')
        require(not cache_member(name) or entry.isdir(), 'construction RPM cache entered OCI history')
        if entry.islnk() or entry.issym():
            link = extensions.get('linkpath', entry.linkname)
            target = link if entry.islnk() else posixpath.join(posixpath.dirname(name), link)
            require(not cache_member(target), 'construction RPM cache link entered OCI history')
        size = int(extensions.get('size', entry.size))
        extensions.clear()
        require(0 <= size <= maximum - expanded and (entry.isreg() or size == 0), 'invalid OCI layer member size')
        for offset in range(0, size, 1024 * 1024):
            read(min(size - offset, 1024 * 1024))
        require(read(-size % 512) == bytes(-size % 512), 'invalid OCI archive file padding')
    raise ValueError('OCI cache history layer entry limit exceeded')


def pax_identity(body):
    selected = {}
    offset = 0
    for _ in range(128):
        if offset == len(body):
            return selected
        separator = body.find(b' ', offset, offset + 8)
        require(separator >= 0 and body[offset:separator].isdigit(), 'invalid OCI PAX record size')
        finish = offset + int(body[offset:separator])
        require(separator + 2 < finish <= len(body) and body[finish - 1] == 10, 'invalid OCI PAX record')
        key, sep, value = body[separator + 1:finish - 1].partition(b'=')
        require(key and sep and not key.startswith(b'GNU.sparse'), 'unsupported OCI PAX record')
        if key in (b'path', b'linkpath', b'size'):
            key = key.decode('ascii')
            require(key not in selected and value and b'\0' not in value
                    and (key != 'size' or len(value) <= 16 and value.isdigit()),
                    'invalid OCI PAX member identity')
            selected[key] = value.decode('utf-8')
        offset = finish
    raise ValueError('OCI PAX record limit exceeded')


def build_transport(source, output, wanted):
    end = time.monotonic() + 120
    files = {}
    paths = {}
    for directory, dirs, names in os.walk(source):
        for name in dirs + names:
            require(not (Path(directory) / name).is_symlink(), 'RPM cache source symlink denied')
        for name in names:
            path = Path(directory) / name
            info = path.lstat()
            member = path.relative_to(source).as_posix()
            member_name(member)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= LIMIT and len(files) < FILES_LIMIT,
                    'invalid RPM cache input file')
            paths[member] = path
            files[member] = {'bytes': info.st_size, 'sha256': digest(path, end)}
    raw = canonical({**wanted, 'files': files})
    manifest_sha = hashlib.sha256(raw).hexdigest()
    require(len(raw) <= CONTROL_LIMIT, 'RPM cache manifest exceeds the control limit')
    validate_manifest(raw, manifest_sha, wanted)
    require(sum((item['bytes'] + 511) // 512 * 512 + 512 for item in files.values()) + len(raw)
            + 1024 + tarfile.RECORDSIZE <= LIMIT, 'RPM cache transport exceeds its limit')
    with output.open('xb') as stream:
        try:
            os.fchmod(stream.fileno(), 0o444)
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                def add(name, handle, size):
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = size, 0o444
                    archive.addfile(member, handle)
                add('manifest.json', io.BytesIO(raw), len(raw))
                for name in sorted(paths):
                    remaining(end)
                    with paths[name].open('rb') as handle:
                        add(name, handle, files[name]['bytes'])
        except BaseException:
            output.unlink()
            raise
    return manifest_sha


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--standards-sha', required=True)
    parser.add_argument('--recipe-sha256', required=True)
    parser.add_argument('--outer-recipe-sha256')
    args = parser.parse_args()
    exact = binding(args.source_sha, args.standards_sha, args.recipe_sha256, outer_recipe=args.outer_recipe_sha256)
    print(build_transport(args.cache, args.output, exact))
