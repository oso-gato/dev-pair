#!/usr/bin/env python3
"""Verified public gptbox inputs; no agent, VM, account or host admission."""
import argparse
import contextlib
import gzip
import hashlib
import json
import os
import pathlib
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
try:
    import fedora_oci
except ModuleNotFoundError:
    # -I excludes scriptdir; load only this source-bound immutable sibling.
    import importlib.util
    _fedora_spec = importlib.util.spec_from_file_location('fedora_oci', pathlib.Path(__file__).with_name('fedora_oci.py'))
    fedora_oci = importlib.util.module_from_spec(_fedora_spec)
    sys.modules['fedora_oci'] = fedora_oci
    _fedora_spec.loader.exec_module(fedora_oci)

MIB = 1024 ** 2
STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
CODEX_SOURCE = 'd32063f96c2dff1dc96af839b3952abb6acfeda4'
DBX_SOURCE = '40c3cd724faa434aeb0a23e28776665b92de68bd'
FEDORA = fedora_oci.IMAGE
RELEASE = 'https://github.com/openai/codex/releases/download/rust-v0.169.0/'
ARTIFACTS = {
    'codex.tar.gz': (RELEASE + 'codex-x86_64-unknown-linux-musl.tar.gz', 117805733,
                     '9af4d751fce183faedea629437d5252dbf458eeb04130cf4f97be844621ea985'),
    'codex.sigstore': (RELEASE + 'codex-x86_64-unknown-linux-musl.sigstore', 8489,
                       '3146e0f44e249125606667091d5de4cdc04abb8089ae329546c5d870ad822c91'),
    'cosign': ('https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64', 145688404,
               '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa'),
}
ARTIFACTS.update(fedora_oci.ARTIFACTS)
CODEX_BYTES = 294277432
CODEX_SHA = 'b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b'
SOURCE_LIMIT = 32 * MIB
PAYLOAD_LIMIT = 192 * MIB
EXPANSION_LIMIT = 384 * MIB
WORK_LIMIT = 1536 * MIB
FILE_LIMIT = 2048
MANIFEST_LIMIT = 256 * 1024
EXTRACTION_SECONDS = 120
VERIFICATION = 'strict-cosign-keyless; Fedora signed-CHECKSUM/OCI verification is separately required; Cosign bootstrap is official HTTPS plus pinned digest; no runtime/model admission'
ROLES = ('maintenance', 'development')
PUBLIC_INPUT_KINDS = tuple(f'verified-public-{role}-inputs' for role in ROLES)
PROXY_ENV = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy',
             'all_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            value.update(block)
    return value.hexdigest()


def tooling_record(value, revision=None):
    names = ('schema kind reviewed_source_sha source_sha tag version release_id assets binary verification_sha256 '
             'approved_pins_match cached_assets')
    require(type(value) is dict and set(value) == set(names.split()) and type(value['schema']) is int and
            value['schema'] == 1 and value['kind'] == 'dev-pair-verified-codex-pin-proposal',
            'verified refresh tooling record shape differs')
    require(all(type(value[key]) is str and re.fullmatch('[0-9a-f]{40}', value[key])
                for key in ('reviewed_source_sha', 'source_sha')) and
            (revision is None or revision == value['reviewed_source_sha']), 'refresh tooling source differs')
    require(type(value['version']) is str and re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})', value['version'])
            and value['tag'] == 'rust-v' + value['version'] and type(value['release_id']) is int and value['release_id'] > 0,
            'invalid official stable tooling release identity')
    require(type(value['verification_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['verification_sha256']) and
            type(value['approved_pins_match']) is bool and type(value['cached_assets']) is list and
            value['cached_assets'] == sorted(set(value['cached_assets'])) and set(value['cached_assets']) <= {'archive', 'bundle'},
            'invalid tooling signature or cache evidence')
    assets = value['assets']
    require(type(assets) is dict and set(assets) == {'archive', 'bundle'}, 'refresh asset evidence differs')
    limits = (PAYLOAD_LIMIT - fedora_oci.ARCHIVE_BYTES - 2 * MIB, 256 * 1024,
              EXPANSION_LIMIT - fedora_oci.ARCHIVE_BYTES - 4 * MIB)
    for item, limit in zip((assets['archive'], assets['bundle'], value['binary']), limits):
        require(type(item) is dict and set(item) == {'sha256', 'bytes'} and type(item['bytes']) is int and
                0 < item['bytes'] <= limit and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
                'verified refresh tooling bytes exceed the approved bound')
    return value


def read_tooling(path, revision=None):
    raw, _ = capture_regular(path, 64 * 1024)
    value = tooling_record(json.loads(raw), revision)
    require(raw == canonical(value), 'refresh tooling evidence must be canonical')
    return value


def selected_tooling(tooling=None):
    if tooling is None:
        return ARTIFACTS, '0.169.0', CODEX_SOURCE, CODEX_SHA, CODEX_BYTES
    tag = tooling['tag']
    assets = dict(ARTIFACTS)
    for part, local, suffix in (('archive', 'codex.tar.gz', 'tar.gz'), ('bundle', 'codex.sigstore', 'sigstore')):
        item = tooling['assets'][part]
        url = f'https://github.com/openai/codex/releases/download/{tag}/codex-x86_64-unknown-linux-musl.{suffix}'
        assets[local] = url, item['bytes'], item['sha256']
    binary = tooling['binary']
    return assets, tooling['version'], tooling['source_sha'], binary['sha256'], binary['bytes']


def artifact_receipt(artifacts):
    return {name: {'bytes': size, 'sha256': sha} for name, (_, size, sha) in artifacts.items()}


def safe_path(name):
    require(type(name) is str and 0 < len(name.encode()) <= 240 and
            all(32 <= ord(c) < 127 for c in name), 'invalid archive path')
    path = pathlib.PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and not any(p in ('.', '..') for p in path.parts),
            'unsafe archive path')
    return path


def private_directory(path):
    path = pathlib.Path(path).absolute()
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'symlink output ancestor denied')
        if item != path and item.exists():
            info = item.stat()
            require(info.st_uid in (0, os.getuid()) and
                    (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                    'output ancestors must be controlled by the operator')
    path.mkdir(mode=0o700)
    return path


@contextlib.contextmanager
def wall_limit(seconds):
    def expired(signum, frame):
        raise ValueError('public input wall-time limit exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def environment(home, network=False):
    result = {'HOME': str(home), 'TMPDIR': str(home.parent), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
              'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    if network:
        result.update({key: os.environ[key] for key in PROXY_ENV if key in os.environ})
    return result


def workspace_bytes(root):
    total = 0
    def walk_error(error):
        if not isinstance(error, FileNotFoundError):
            raise error
    for directory, _, files in os.walk(root, onerror=walk_error):
        for name in files:
            try:
                info = pathlib.Path(directory, name).lstat()
            except FileNotFoundError:
                continue  # owned command may atomically replace its temp file
            require(stat.S_ISREG(info.st_mode), 'nonregular workspace file denied')
            total += info.st_size
    return total


def command(argv, work, *, timeout=120, network=False, input_file=None, output_file=None, file_limit=SOURCE_LIMIT, workspace_reserve=0):
    """Fixed-controller argv only; no shell, inherited credentials or loaders."""
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(open(input_file, 'rb')) if input_file else subprocess.DEVNULL
        target = stack.enter_context(open(output_file, 'xb')) if output_file else subprocess.PIPE
        process = subprocess.Popen(argv, stdin=source, stdout=target, stderr=subprocess.PIPE,
                                   env=environment(work / 'home', network), start_new_session=True, preexec_fn=limits)
        selector = selectors.DefaultSelector()
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        if not output_file:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        started = time.monotonic()
        try:
            while selector.get_map():
                require(time.monotonic() - started < timeout, 'public input command deadline exceeded')
                require(workspace_bytes(work) + workspace_reserve <= WORK_LIMIT, 'public input workspace budget exceeded')
                for key, _ in selector.select(timeout=.1):
                    data = os.read(key.fileobj.fileno(), 16384)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(data)
                    require(sum(map(len, buffers.values())) <= MIB, 'public input command output limit exceeded')
            require(process.wait(timeout=5) == 0, 'public input command failed; bounded output retained only by caller')
            require(workspace_bytes(work) + workspace_reserve <= WORK_LIMIT, 'public input workspace budget exceeded')
            return bytes(buffers['stdout']), bytes(buffers['stderr'])
        finally:
            selector.close()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            process.stderr.close()
            if not output_file:
                process.stdout.close()


def git(repo, *args):
    return ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', str(repo), *args]


def snapshot(source, destination, expected_bytes, expected_sha):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as src, open(destination, 'xb') as dst:
        require(stat.S_ISREG(os.fstat(src.fileno()).st_mode), 'input must be a regular public artifact')
        require(os.fstat(src.fileno()).st_size == expected_bytes, 'public artifact length mismatch')
        copied = 0
        while True:
            block = src.read(MIB)
            if not block:
                break
            copied += len(block)
            require(copied <= expected_bytes, 'public artifact grew while staging')
            dst.write(block)
    require(copied == expected_bytes and digest(destination) == expected_sha, 'public artifact SHA256 mismatch')


def capture_regular(path, maximum, *, exact_size=None, destination=None):
    """Capture an untrusted input once; callers consume these exact bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), 'admission input must be a regular file')
        require(0 < info.st_size <= maximum, 'admission input size limit exceeded')
        require(exact_size is None or info.st_size == exact_size, 'admission input exact size mismatch')
        output = stack.enter_context(open(destination, 'xb')) if destination else None
        data = bytearray() if output is None else None
        value, copied = hashlib.sha256(), 0
        while True:
            block = os.read(fd, min(MIB, maximum - copied + 1))
            if not block:
                break
            copied += len(block)
            require(copied <= maximum and (exact_size is None or copied <= exact_size), 'admission input grew past size limit')
            value.update(block)
            output.write(block) if output is not None else data.extend(block)
        require(copied == info.st_size and (exact_size is None or copied == exact_size), 'admission input changed size during capture')
        return bytes(data) if data is not None else None, value.hexdigest()


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(newurl.startswith('https://'), 'non-HTTPS public artifact redirect denied')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(output, fedora_cache=None, *, codex_cache=None, tooling=None):
    with wall_limit(600):
        return fetch_within_limit(output, fedora_cache, codex_cache=codex_cache, tooling=tooling)


def fetch_within_limit(output, fedora_cache=None, *, codex_cache=None, tooling=None):
    require(tooling is None or codex_cache is not None, 'refresh requires the exact signed in-run public cache')
    artifacts, _, _, _, _ = selected_tooling(tooling)
    output = private_directory(output)
    try:
        opener = urllib.request.build_opener(HTTPSOnly())
        for name, (url, size, expected) in artifacts.items():
            if fedora_cache is not None and name in fedora_oci.ARTIFACTS:
                snapshot(pathlib.Path(fedora_cache)/name,output/name,size,expected)
                continue
            if codex_cache is not None and name in ('codex.tar.gz', 'codex.sigstore', 'cosign'):
                snapshot(pathlib.Path(codex_cache) / name, output / name, size, expected)
                continue
            started = time.monotonic()
            copied = 0
            with opener.open(url, timeout=20) as response, open(output / name, 'xb') as dst:
                while True:
                    require(time.monotonic() - started < 300, 'public artifact download deadline exceeded')
                    block = response.read(min(MIB, size - copied + 1))
                    if not block:
                        break
                    copied += len(block)
                    require(copied <= size, 'public artifact download byte limit exceeded')
                    dst.write(block)
            require(copied == size and digest(output / name) == expected, 'downloaded public artifact identity mismatch')
        (output / 'home').mkdir()
        repo = output / 'distrobox'
        repo.mkdir()
        command(git(repo, 'init', '--bare', '--template='), output)
        command(git(repo, 'fetch', '--depth=1', '--no-tags', 'https://github.com/89luca89/distrobox.git', DBX_SOURCE), output, network=True)
        command(git(repo, 'update-ref', 'refs/heads/public-input', DBX_SOURCE), output)
        command(git(repo, 'symbolic-ref', 'HEAD', 'refs/heads/public-input'), output)
        return {'cache': str(output), 'downloaded_artifacts': list(artifacts), 'distrobox_sha': DBX_SOURCE,
                'signature_verification': 'not yet performed; build must verify'}
    except BaseException:
        shutil.rmtree(output)
        raise


def extract_codex(archive, destination, tooling=None):
    artifacts, _, _, binary, size = selected_tooling(tooling)
    _, archive_bytes, archive_sha = artifacts['codex.tar.gz']
    require(archive.stat().st_size == archive_bytes and digest(archive) == archive_sha,
            'official Codex archive identity mismatch before expansion')
    return _parse_codex_archive(archive, destination, size, binary)


def _parse_codex_archive(archive, destination, expected_bytes, expected_sha):
    """Internal parser; production calls only with the fixed verified identities."""
    with tarfile.open(archive, 'r|gz') as source:
        item = source.next()
        require(item is not None and item.name == 'codex-x86_64-unknown-linux-musl' and
                item.type == tarfile.REGTYPE and not item.pax_headers and not item.issparse() and item.size == expected_bytes,
                'unexpected Codex archive member/type/expansion')
        with source.extractfile(item) as src, open(destination, 'xb') as dst:
            shutil.copyfileobj(src, dst, length=MIB)
        require(source.next() is None, 'Codex archive must contain exactly its official binary')
    require(destination.stat().st_size == expected_bytes and digest(destination) == expected_sha, 'extracted Codex digest mismatch')


def signature_args(verifier, bundle, binary, tooling=None):
    _, version, source, _, _ = selected_tooling(tooling)
    tag = 'refs/tags/rust-v' + version
    return [str(verifier), 'verify-blob', '--bundle', str(bundle),
            '--certificate-identity', 'https://github.com/openai/codex/.github/workflows/rust-release.yml@' + tag,
            '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
            '--certificate-github-workflow-repository', 'openai/codex',
            '--certificate-github-workflow-ref', tag,
            '--certificate-github-workflow-sha', source, str(binary)]


def clean_checkout(source, revision, destination, work):
    require(re.fullmatch('[0-9a-f]{40}', revision), 'full source revision required')
    head = command(git(source, 'rev-parse', 'HEAD'), work)[0].decode().strip()
    require(head == revision, 'public source HEAD mismatch')
    tree = command(git(source, 'ls-tree', '-r', '-z', revision), work)[0]
    entries = tree.rstrip(b'\0').split(b'\0')
    require(len(entries) <= FILE_LIMIT, 'public source file-count limit exceeded')
    for entry in entries:
        meta, name = entry.split(b'\t', 1)
        require(meta.split()[0] in (b'100644', b'100755'), 'source symlink/submodule/special entry denied')
        path = safe_path(name.decode())
        require('.git' not in (part.lower() for part in path.parts), 'tracked Git metadata path denied')
    objects = command(git(source, 'rev-list', '--objects', '--no-walk', revision), work)[0]
    object_list = work / ('objects-' + destination.name)
    ids = [line.split(b' ', 1)[0] for line in objects.splitlines()]
    require(all(re.fullmatch(b'[0-9a-f]{40}', item) for item in ids), 'invalid public Git object inventory')
    object_list.write_bytes(b'\n'.join(ids) + b'\n')
    pack = work / ('pack-' + destination.name)
    command(git(source, 'pack-objects', '--stdout'), work, input_file=object_list, output_file=pack)
    destination.mkdir()
    command(git(destination, 'init', '--template='), work)
    command(git(destination, 'index-pack', '--stdin'), work, input_file=pack)
    metadata = destination / '.git'
    (metadata / 'config').write_text('[core]\nrepositoryformatversion=0\nbare=false\nfilemode=true\n')
    (metadata / 'HEAD').write_text('ref: refs/heads/public-input\n')
    (metadata / 'refs/heads/public-input').write_text(revision + '\n')
    (metadata / 'shallow').write_text(revision + '\n')
    command(git(destination, 'read-tree', revision), work)
    command(git(destination, 'checkout-index', '--all'), work)
    (metadata / 'index').unlink()
    command(git(destination, 'fsck', '--full', '--strict'), work)
    require(workspace_bytes(destination) <= SOURCE_LIMIT, 'clean public checkout exceeds source limit')
    return destination


def inventory(root, binary_limit=CODEX_BYTES):
    result = []
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'payload must contain regular files/directories only')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            safe_path(name)
            require(info.st_size <= binary_limit, 'payload file exceeds individual byte limit')
            result.append({'path': name, 'bytes': info.st_size, 'sha256': digest(path)})
    require(len(result) <= FILE_LIMIT and sum(item['bytes'] for item in result) <= EXPANSION_LIMIT, 'payload expansion/file budget exceeded')
    return result


def write_payload(root, files, destination):
    with open(destination, 'xb') as output, gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
            for item in files:
                header = tarfile.TarInfo(item['path'])
                header.size, header.mode, header.mtime = item['bytes'], 0o444, 0
                with open(root / item['path'], 'rb') as stream:
                    archive.addfile(header, stream)
                require(output.tell() <= PAYLOAD_LIMIT, 'compressed payload byte limit exceeded')
    require(destination.stat().st_size <= PAYLOAD_LIMIT, 'compressed payload byte limit exceeded')


def build(cache, distrobox, output, *, role='maintenance', tooling=None):
    with wall_limit(600):
        return build_within_limit(cache, distrobox, output, role=role, tooling=tooling)


def build_within_limit(cache, distrobox, output, *, role='maintenance', tooling=None):
    require(role in ROLES, 'unsupported public-input role')
    repo = pathlib.Path(__file__).resolve().parents[1]
    output = private_directory(output)
    try:
        with tempfile.TemporaryDirectory(prefix='public-inputs-', dir=output) as temporary:
            work = pathlib.Path(temporary)
            (work / 'home').mkdir()
            revision = command(git(repo, 'rev-parse', 'HEAD'), work)[0].decode().strip()
            require(not command(git(repo, 'status', '--porcelain'), work)[0], 'public source must be committed and clean')
            require(command(git(repo, 'show', revision + ':tools/public_inputs.py'), work)[0] == pathlib.Path(__file__).read_bytes(),
                    'executing input helper differs from exact public HEAD')
            if tooling is not None:
                tooling_record(tooling, revision)
            artifacts, version, codex_source, codex_sha, codex_bytes = selected_tooling(tooling)
            for name, (_, size, expected) in artifacts.items():
                snapshot(pathlib.Path(cache) / name, work / name, size, expected)
            binary = work / 'codex'
            extract_codex(work / 'codex.tar.gz', binary, tooling)
            (work / 'cosign').chmod(0o500)
            proof = command(signature_args(work / 'cosign', work / 'codex.sigstore', binary, tooling), work, network=True)
            require(b'Verified OK' in proof[0] + proof[1], 'strict Cosign success evidence missing')
            retained = output / 'verification'
            retained.mkdir(mode=0o700)
            shutil.copyfile(work / 'codex.sigstore', retained / 'codex.sigstore')
            (retained / 'cosign-verification.txt').write_bytes(proof[0] + proof[1])
            receipt = {'version': 1, 'kind': 'public-codex-verification-receipt', 'helper_source_sha': revision,
                       'exit_status': 0, 'result': 'Verified OK', 'codex_source_sha': codex_source,
                       'codex_binary_sha256': codex_sha, 'codex_binary_bytes': codex_bytes,
                       'artifacts': artifact_receipt(artifacts),
                       'verification_output_sha256': hashlib.sha256(proof[0] + proof[1]).hexdigest(),
                       'note': VERIFICATION}
            (retained / 'receipt.json').write_bytes(canonical(receipt))
            require(workspace_bytes(work) + 160 * MIB <= WORK_LIMIT, 'Fedora verification workspace reserve unavailable')
            with fedora_oci.verified(work) as (plain, fedora_proof):
                (retained / 'fedora-verification.json').write_bytes(canonical(fedora_proof))
            tree = work / 'payload'
            tree.mkdir()
            clean_checkout(repo, revision, tree / 'dev-pair', work)
            clean_checkout(pathlib.Path(distrobox), DBX_SOURCE, tree / 'distrobox', work)
            # The context schema models placement only. These fixed descriptors
            # are never used to allocate a target job or mount credentials.
            leaf = 'bootstrap-probe' if role == 'maintenance' else 'development-image-probe'
            role_root = f'/var/lib/dev-pair/{role}'
            manifest = {'kind': 'operator-verified-inputs', 'source_sha': revision, 'standards_sha': STANDARDS,
                        'fedora': dict(fedora_oci.PROVENANCE),
                        'codex': {'version': version, 'source': artifacts['codex.tar.gz'][0], 'sha256': codex_sha,
                                  'verification': 'Strict Cosign3.1.4 identity/issuer/workflow/repository/ref/source verification passed; evidence in payload'},
                        'role': role, 'provider': 'gptbox', 'model': 'gpt-6.2-sol', 'effort': 'high',
                        'mounts': {'workspace': f'{role_root}/workspaces/{leaf}',
                                   'state': f'{role_root}/state/{leaf}',
                                   'cache': f'{role_root}/cache/{leaf}',
                                   'credentials': f'/var/lib/dev-pair/credentials/{role}/{leaf}'}}
            inputs = work / 'inputs.json'
            inputs.write_text(json.dumps(manifest))
            preparation = command([sys.executable, '-I', str(tree / 'dev-pair/tools/candidate.py'), 'prepare',
                                   '--manifest', str(inputs), '--binary', str(binary), '--fedora-inputs', str(work), '--output', str(tree / 'context')],
                                  work, file_limit=codex_bytes + MIB, workspace_reserve=160*MIB)[0]
            context = json.loads(preparation)
            evidence = tree / 'evidence'
            evidence.mkdir()
            shutil.copyfile(retained / 'codex.sigstore', evidence / 'codex.sigstore')
            shutil.copyfile(retained / 'cosign-verification.txt', evidence / 'cosign-verification.txt')
            shutil.copyfile(retained / 'receipt.json', evidence / 'verification-receipt.json')
            shutil.copyfile(retained / 'fedora-verification.json', evidence / 'fedora-verification.json')
            if tooling is not None:
                (evidence / 'tooling.json').write_bytes(canonical(tooling))
            files = inventory(tree, codex_bytes)
            payload = output / f'{role}-inputs.tar.gz'
            write_payload(tree, files, payload)
            record = {'version': 2, 'kind': f'verified-public-{role}-inputs', 'fedora': dict(fedora_oci.PROVENANCE), 'source_sha': revision,
                      'standards_sha': STANDARDS, 'distrobox_sha': DBX_SOURCE, 'context_sha256': context['context_sha256'],
                      'artifacts': {name: {'url': url, 'bytes': size, 'sha256': sha} for name, (url, size, sha) in artifacts.items()},
                      'payload': {'sha256': digest(payload), 'bytes': payload.stat().st_size}, 'files': files,
                      'verification': VERIFICATION}
            if tooling is not None:
                record.update(version=3, tooling=tooling)
            validate_manifest(record)
            (output / 'manifest.json').write_bytes(canonical(record))
            return {'manifest_sha256': digest(output / 'manifest.json'), 'payload_sha256': digest(payload),
                    'context_sha256': context['context_sha256'], 'source_sha': revision, 'output': str(output)}
    except BaseException:
        cleanup_failed_build(output)
        raise


def cleanup_failed_build(output):
    # Successful cryptographic evidence survives an unrelated packaging failure;
    # it cannot authorize a retry: build always verifies again into a new output.
    if (output / 'verification/receipt.json').is_file():
        for path in output.iterdir():
            if path.name != 'verification':
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        (output / 'failure.json').write_bytes(canonical({'status': 'payload-not-published',
                                                        'verified_input_evidence': 'verification/receipt.json'}))
    else:
        shutil.rmtree(output)


def validate_manifest(obj):
    def keys(value, names):
        require(type(value) is dict and set(value) == set(names.split()), 'missing or unknown manifest fields')
    refreshed = type(obj) is dict and obj.get('version') == 3
    keys(obj, 'version kind source_sha standards_sha distrobox_sha context_sha256 artifacts payload files verification fedora'
         + (' tooling' if refreshed else ''))
    require(type(obj['version']) is int and obj['version'] in (2, 3) and obj['kind'] in PUBLIC_INPUT_KINDS,
            'unsupported public-input manifest version/kind')
    require(obj['fedora'] == fedora_oci.PROVENANCE, 'signed Fedora provenance mismatch')
    require(re.fullmatch('[0-9a-f]{40}', obj['source_sha']) and obj['standards_sha'] == STANDARDS and
            obj['distrobox_sha'] == DBX_SOURCE and re.fullmatch('[0-9a-f]{64}', obj['context_sha256']), 'manifest identity mismatch')
    tooling = tooling_record(obj['tooling'], obj['source_sha']) if refreshed else None
    artifacts, _, _, _, binary_limit = selected_tooling(tooling)
    require(canonical(obj['artifacts']) == canonical({name: {'url': url, 'bytes': size, 'sha256': sha}
                                for name, (url, size, sha) in artifacts.items()}) and obj['verification'] == VERIFICATION,
            'public artifact verification contract mismatch')
    keys(obj['payload'], 'sha256 bytes')
    require(re.fullmatch('[0-9a-f]{64}', obj['payload']['sha256']) and type(obj['payload']['bytes']) is int and
            0 < obj['payload']['bytes'] <= PAYLOAD_LIMIT, 'invalid payload identity/size')
    require(type(obj['files']) is list and 1 <= len(obj['files']) <= FILE_LIMIT, 'invalid payload inventory')
    names = []
    total = 0
    for item in obj['files']:
        keys(item, 'path bytes sha256')
        path = safe_path(item['path'])
        require(path.parts[0] in ('dev-pair', 'distrobox', 'context', 'evidence'), 'unexpected payload root')
        if '.git' in (part.lower() for part in path.parts):
            require(re.fullmatch(r'(dev-pair|distrobox)/\.git/(HEAD|config|shallow|refs/heads/public-input|objects/pack/pack-[0-9a-f]{40}\.(pack|idx|rev))', item['path']),
                    'undeclared Git metadata denied')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= binary_limit and
                re.fullmatch('[0-9a-f]{64}', item['sha256']), 'invalid file identity/size')
        names.append(item['path'])
        total += item['bytes']
    require(names == sorted(set(names)) and total <= EXPANSION_LIMIT, 'duplicate/unsorted/oversized payload inventory')
    required = {'context/' + name for name in ('inputs.json', 'codex', 'candidate.json', 'Containerfile', *fedora_oci.FILES)}
    required |= {'evidence/codex.sigstore', 'evidence/cosign-verification.txt', 'evidence/verification-receipt.json', 'evidence/fedora-verification.json'}
    if refreshed:
        required.add('evidence/tooling.json')
    for repo in ('dev-pair', 'distrobox'):
        required |= {repo + '/.git/' + name for name in ('HEAD', 'config', 'shallow', 'refs/heads/public-input')}
    require(required <= set(names), 'incomplete public-input payload')
    return obj


def parse_manifest(data, actual_sha, expected_sha):
    require(re.fullmatch('[0-9a-f]{64}', expected_sha), 'separately trusted manifest digest required')
    require(actual_sha == expected_sha, 'manifest integrity/size mismatch')
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate manifest field')
            result[key] = value
        return result
    return validate_manifest(json.loads(data, object_pairs_hook=unique))


def read_manifest(path, expected_sha):
    with wall_limit(EXTRACTION_SECONDS):
        data, actual_sha = capture_regular(path, MANIFEST_LIMIT)
        return parse_manifest(data, actual_sha, expected_sha)


def extract(payload, manifest_path, expected_manifest_sha, destination, *, role='maintenance'):
    # Admission (including open/fstat/hash/JSON) is inside the same deadline as
    # expansion. Neither untrusted path is ever reopened for consumption.
    with wall_limit(EXTRACTION_SECONDS):
        data, actual_sha = capture_regular(manifest_path, MANIFEST_LIMIT)
        record = parse_manifest(data, actual_sha, expected_manifest_sha)
        require(role in ROLES and record['kind'] == f'verified-public-{role}-inputs',
                'public input payload role mismatch')
        return _extract_captured(payload, record, destination)


def _extract_captured(payload, record, destination):
    destination = private_directory(destination)
    try:
        with tempfile.TemporaryDirectory(prefix='expand-', dir=destination) as temporary:
            compressed = pathlib.Path(temporary) / 'payload.gz'
            _, actual_sha = capture_regular(payload, PAYLOAD_LIMIT, exact_size=record['payload']['bytes'], destination=compressed)
            require(actual_sha == record['payload']['sha256'], 'payload identity mismatch')
            raw = pathlib.Path(temporary) / 'payload.tar'
            count = 0
            with gzip.open(compressed, 'rb') as src, open(raw, 'xb') as dst:
                while True:
                    block = src.read(MIB)
                    if not block:
                        break
                    count += len(block)
                    require(count <= EXPANSION_LIMIT + 4 * MIB, 'compressed payload expansion limit exceeded')
                    dst.write(block)
            expected = {item['path']: item for item in record['files']}
            seen = set()
            with tarfile.open(raw, 'r:') as archive:
                for member in archive:
                    safe_path(member.name)
                    require(member.name in expected and member.name not in seen and member.type == tarfile.REGTYPE and
                            not member.pax_headers and not member.issparse(), 'unexpected/duplicate/nonregular archive member')
                    item = expected[member.name]
                    require(member.size == item['bytes'], 'archive member byte length mismatch')
                    target = destination / member.name
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with archive.extractfile(member) as src, open(target, 'xb') as dst:
                        shutil.copyfileobj(src, dst, length=MIB)
                    require(digest(target) == item['sha256'], 'archive member digest mismatch')
                    target.chmod(0o444)
                    seen.add(member.name)
                require(seen == set(expected), 'missing payload member')
                with open(raw, 'rb') as tail:
                    tail.seek(archive.offset)
                    require(all(not any(block) for block in iter(lambda: tail.read(MIB), b'')), 'trailing nonzero tar data denied')
            config = '[core]\nrepositoryformatversion=0\nbare=false\nfilemode=true\n'
            for repo, revision in (('dev-pair', record['source_sha']), ('distrobox', DBX_SOURCE)):
                metadata = destination / repo / '.git'
                require((metadata / 'config').read_text() == config and
                        (metadata / 'HEAD').read_text() == 'ref: refs/heads/public-input\n' and
                        (metadata / 'refs/heads/public-input').read_text() == revision + '\n' and
                        (metadata / 'shallow').read_text() == revision + '\n', 'unsafe Git metadata contents')
        return {'source_sha': record['source_sha'], 'context_sha256': record['context_sha256'],
                'files': len(record['files']), 'extracted': str(destination),
                'verification': 'trusted-manifest transport integrity; no remote authentication or runtime admission'}
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    fetch_parser = sub.add_parser('fetch')
    fetch_parser.add_argument('--fedora-cache', type=pathlib.Path)
    fetch_parser.add_argument('--codex-cache', type=pathlib.Path)
    fetch_parser.add_argument('--refresh-tooling', type=pathlib.Path)
    fetch_parser.add_argument('--output', required=True, type=pathlib.Path)
    build_parser = sub.add_parser('build')
    build_parser.add_argument('--cache', required=True, type=pathlib.Path)
    build_parser.add_argument('--refresh-tooling', type=pathlib.Path)
    build_parser.add_argument('--distrobox-source', required=True, type=pathlib.Path)
    build_parser.add_argument('--output', required=True, type=pathlib.Path)
    build_parser.add_argument('--role', choices=ROLES, default='maintenance')
    consumer = sub.add_parser('extract')
    consumer.add_argument('--payload', required=True, type=pathlib.Path)
    consumer.add_argument('--manifest', required=True, type=pathlib.Path)
    consumer.add_argument('--expected-manifest-sha256', required=True)
    consumer.add_argument('--output', required=True, type=pathlib.Path)
    consumer.add_argument('--role', choices=ROLES, default='maintenance')
    args = parser.parse_args()
    tooling = read_tooling(args.refresh_tooling) if getattr(args, 'refresh_tooling', None) else None
    if args.command == 'fetch':
        result = fetch(args.output, args.fedora_cache, codex_cache=args.codex_cache, tooling=tooling)
    elif args.command == 'build':
        result = build(args.cache, args.distrobox_source, args.output, role=args.role, tooling=tooling)
    else:
        result = extract(args.payload, args.manifest, args.expected_manifest_sha256, args.output, role=args.role)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, OSError, subprocess.SubprocessError, tarfile.TarError):
        print('Public inputs blocked; no runtime or agent admission', file=sys.stderr)
        sys.exit(2)
