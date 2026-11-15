#!/usr/bin/env python3
"""Offline candidate preparation; deliberately has no execution adapter."""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import uuid
import fedora_oci

STANDARDS = 'b9d4da5d442ac48dba2e8be62d81b5bdc83690b8'
DESTINATIONS = {'workspace': '/work/job', 'state': '/state/codex',
                'cache': '/cache/job', 'credentials': '/run/secrets/codex'}
BLOCKER = ('No validated Fedora 44 Distrobox confinement adapter exists. '
           'Normal Distrobox home/host integration is not an isolation boundary; execution denied.')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(obj, expected, name):
    require(isinstance(obj, dict) and set(obj) == set(expected.split()),
            f'{name}: missing or unknown fields')


def token(value, pattern, name):
    require(isinstance(value, str) and re.fullmatch(pattern, value), f'invalid {name}')


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(m, fixture=False):
    keys(m, 'kind source_sha standards_sha fedora codex role provider model effort mounts', 'manifest')
    require(m['kind'] == ('fixture' if fixture else 'operator-verified-inputs'),
            'fixture needs --fixture; production requires operator-verified-inputs')
    token(m['source_sha'], r'[0-9a-f]{40}', 'source SHA')
    require(m['standards_sha'] == STANDARDS, 'standards pin mismatch')
    if fixture:
        keys(m['fedora'], 'image verification', 'fedora')
        token(m['fedora']['image'], r'registry\.fedoraproject\.org/fedora:44@sha256:[0-9a-f]{64}', 'fixture image reference')
    else:
        require(m['fedora'] == fedora_oci.PROVENANCE, 'exact signed Fedora OCI provenance required')
    keys(m['codex'], 'version source sha256 verification', 'codex')
    token(m['codex']['version'], r'[0-9]+\.[0-9]+\.[0-9]+', 'stable Codex version')
    token(m['codex']['sha256'], r'[0-9a-f]{64}', 'Codex binary SHA256')
    expected = ('https://github.com/openai/codex/releases/download/rust-v' +
                m['codex']['version'] + '/codex-x86_64-unknown-linux-musl.tar.gz')
    require(m['codex']['source'] == expected, 'unsupported official Codex source/architecture')
    if not fixture:
        require(len(set(m['fedora']['image'].split(':')[-1])) > 1,
                'placeholder image digest denied')
        require(m['codex']['version'] != '0.0.0', 'fixture version denied')
    for obj in (m['fedora'], m['codex']):
        token(obj['verification'], r'[^\x00-\x1f]{10,1000}', 'operator verification evidence reference')
    require(m['role'] in ('maintenance', 'development'), 'unsupported role')
    require(m['provider'] == 'gptbox', 'unsupported provider; no fallback')
    token(m['model'], r'gpt-[a-z0-9]+(?:[.-][a-z0-9]+)+', 'explicit model identity')
    require(m['model'] not in ('gpt-latest', 'gpt-default', 'gpt-auto'), 'floating model')
    require(m['effort'] in ('low', 'medium', 'high', 'xhigh'), 'explicit supported effort required')
    keys(m['mounts'], 'workspace state cache credentials', 'mounts')
    roots = []
    for name, raw in m['mounts'].items():
        token(raw, r'/[a-zA-Z0-9_./-]+', f'{name} path')
        path = pathlib.Path(raw)
        require(str(path) == raw and '..' not in path.parts, 'noncanonical path')
        # Match A4.3's separate role-owned classes; credentials stay outside agent data.
        directory = {'workspace': 'workspaces', 'state': 'state', 'cache': 'cache'}
        prefix = (f'/var/lib/dev-pair/credentials/{m["role"]}/' if name == 'credentials'
                  else f'/var/lib/dev-pair/{m["role"]}/{directory[name]}/')
        require(raw.startswith(prefix) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', raw[len(prefix):]),
                'mount source must be one dedicated job leaf in its approved role/storage class')
        # Even nonexistent paths must not resolve through existing symlink parents.
        require(path.resolve() == path, 'symlink mount source denied')
        for other in roots:
            require(not (path == other or path in other.parents or other in path.parents),
                    'overlapping mount sources')
        roots.append(path)
    return m


def recipe(m):
    # No package downloads, writable-home code, unpinned RUN installation or live patching.
    return (f"FROM {m['fedora']['image']}\n"
            + ('' if m['kind'] == 'fixture' else 'RUN /usr/bin/timeout --signal=TERM --kill-after=10s 540s /bin/sh -ec \'dnf -y --refresh --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --disablerepo=\"*\" --enablerepo=fedora --enablerepo=updates upgrade; mkdir -p /usr/lib/dev-pair; rpm -qa --qf \"%{NEVRA}\\n\" | sort > /usr/lib/dev-pair/base-rpms.txt; dnf clean all\'\n')
            +
            f"LABEL org.opencontainers.image.revision={m['source_sha']}\n"
            f"LABEL dev-pair.standards={STANDARDS}\n"
            f"LABEL dev-pair.role={m['role']}\n"
            f"LABEL dev-pair.codex.version={m['codex']['version']}\n"
            'COPY --chmod=0555 codex /opt/dev-pair/bin/codex\n'
            'ENV PATH=/opt/dev-pair/bin:/usr/bin:/bin\n'
            'WORKDIR /work/job\n'
            'ENTRYPOINT ["/opt/dev-pair/bin/codex"]\n').encode()


def check_binary(m, data, fixture):
    require(digest(data) == m['codex']['sha256'], 'Codex binary integrity mismatch')
    require(fixture or (len(data) > 20 and data[:6] == b'\x7fELF\x02\x01' and
                        data[18:20] == b'\x3e\x00'), 'expected extracted x86_64 ELF binary')


def check_source(m, fixture):
    if not fixture:
        repo = pathlib.Path(__file__).resolve().parents[1]
        for name, path in (('candidate.py', pathlib.Path(__file__)),
                           ('fedora_oci.py', pathlib.Path(fedora_oci.__file__))):
            tracked = subprocess.run(
                ['/usr/bin/git', '-C', str(repo), 'show', m['source_sha'] + ':tools/' + name],
                check=True, capture_output=True, timeout=10,
                env={'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'LC_ALL': 'C'}).stdout
            require(tracked == path.read_bytes(), 'source SHA does not identify this preparation implementation')


def check_binary_and_source(m, data, fixture):
    check_binary(m, data, fixture)
    check_source(m, fixture)


def context_record(files, fixture):
    identity = {name: digest(value) for name, value in files.items()}
    return {'kind': 'fixture-not-admissible' if fixture else 'prepared-not-runtime-validated',
            'files_sha256': identity, 'context_sha256': digest(canonical(identity)),
            'provenance': 'Operator supplies upstream verification; only local binary hash checked here.',
            'runtime': 'blocked', 'reason': BLOCKER}


def prepare(manifest, binary, output, fixture=False, fedora_inputs=None):
    m = validate(manifest, fixture)
    data = pathlib.Path(binary).read_bytes()
    check_binary_and_source(m, data, fixture)
    files = {'inputs.json': canonical(m), 'codex': data, 'Containerfile': recipe(m)}
    if not fixture:
        require(fedora_inputs is not None, 'verified Fedora input directory required')
        with fedora_oci.verified(fedora_inputs) as (plain, _):
            for name in fedora_oci.FILES:
                files[name] = (plain.parent / name).read_bytes()
    result = context_record(files, fixture)
    target = pathlib.Path(output).absolute()
    require(target.parent.resolve() == target.parent, 'symlink output parent denied')
    require(not target.exists() and not target.is_symlink(), 'output must be new; refusing overwrite')
    target.mkdir(parents=False, mode=0o700)
    try:
        for name, value in files.items():
            (target / name).write_bytes(value)
        (target / 'codex').chmod(0o555)
        (target / 'candidate.json').write_bytes(canonical(result))
    except BaseException:
        shutil.rmtree(target)
        raise
    return result


def _verify_content(context, expected_context_sha256, fixture=False):
    """Python-only integrity stage, never source/release admission; internal bootstrap prerequisite check."""
    token(expected_context_sha256, r'[0-9a-f]{64}', 'expected context SHA256')
    root = pathlib.Path(context).absolute()
    require(root.resolve() == root and root.is_dir(), 'context must be a nonsymlink directory')
    names = {'inputs.json', 'codex', 'Containerfile', 'candidate.json'}
    if not fixture: names.update(fedora_oci.FILES)
    require({p.name for p in root.iterdir()} == names, 'context record: missing or extra files')
    files = {}
    for name in names:
        path = root / name
        require(stat.S_ISREG(path.lstat().st_mode), 'context: only regular files permitted')
        if name in fedora_oci.ARTIFACTS and not fixture:
            from public_inputs import capture_regular
            _, size, expected = fedora_oci.ARTIFACTS[name]
            data, actual = capture_regular(path, size, exact_size=size)
            require(actual == expected, 'context Fedora signed artifact identity mismatch')
            files[name] = data
        else:
            files[name] = path.read_bytes()
    recorded = json.loads(files.pop('candidate.json'))
    result = context_record(files, fixture)
    require(result['context_sha256'] == expected_context_sha256,
            'context identity does not match handoff')
    require(recorded == result, 'candidate record does not match context bytes')
    m = validate(json.loads(files['inputs.json']), fixture)
    require(files['inputs.json'] == canonical(m), 'noncanonical input manifest')
    require(files['Containerfile'] == recipe(m), 'recipe does not match recorded inputs')
    check_binary(m, files['codex'], fixture)
    if not fixture:
        # The producer verifies signatures/OCI graph. Admission binds these very
        # captured bytes to the reviewed signed-artifact pins without requiring
        # GPG before initial host provisioning. Import verifies the chain afresh.
        for name, (_, size, expected) in fedora_oci.ARTIFACTS.items():
            require(len(files[name]) == size and digest(files[name]) == expected,
                    'context Fedora signed artifact identity mismatch')
    return result, m


def verify(context, expected_context_sha256, fixture=False):
    """Always check both content and Git source; no CLI source-check bypass exists."""
    result, manifest = _verify_content(context, expected_context_sha256, fixture)
    check_source(manifest, fixture)
    return {**result, 'verification': 'local-context-integrity-only'}


def plan(m, selector, model, effort, resume=None, fixture=False):
    validate(m, fixture)
    selected = m['provider'] if selector == 'agentbox' else selector
    require(selected == m['provider'] == 'gptbox', 'unavailable provider; no fallback')
    require(model == m['model'] and effort == m['effort'], 'recorded model/effort mismatch; migration required')
    if resume is not None:
        require(str(uuid.UUID(resume)) == resume, 'resume requires explicit canonical UUID; never --last')
    argv = ['/opt/dev-pair/bin/codex', 'exec']
    if resume:
        argv += ['resume']
    argv += ['--model', model, '-c', f'model_reasoning_effort="{effort}"',
             '-c', 'model_provider="openai"']
    if resume:
        argv += [resume]
    argv += ['-']
    return {'runtime': 'blocked', 'reason': BLOCKER,
            'kind': 'fixture-not-admissible' if fixture else 'unvalidated-invocation-plan',
            'role': m['role'], 'provider': selected,
            'placement': ('host -> maintenance gptbox' if m['role'] == 'maintenance'
                          else 'host -> DevBox -> development gptbox'),
            'cwd': '/work/job', 'codex_argv_proposal': argv,
            'environment_proposal': {'HOME': '/state/home', 'CODEX_HOME': '/state/codex',
                                     'PATH': '/opt/dev-pair/bin:/usr/bin:/bin'},
            'storage_proposal': [{'source': m['mounts'][name], 'destination': dest,
                                 'mode': 'ro' if name == 'credentials' else 'rw'}
                                for name, dest in DESTINATIONS.items()],
            'immutable_code': ['/usr', '/etc', '/opt/dev-pair', '/bin', '/lib', '/lib64'],
            'required_not_enforced': ['read-only root; non-root user; no privilege escalation',
                                      'SELinux enforcing; no outer engine socket or host-exec bridge',
                                      'isolated home; no writable config/hooks/plugins shadowing code',
                                      'private tmpfs /tmp and /run; bounded storage and resources',
                                      'authorized Tailscale-only workload ingress; denial and fail-closed recovery verified',
                                      'credential auth adapter and CLI flags verified for pinned stable version']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--binary', required=True)
    prep.add_argument('--output', required=True)
    prep.add_argument('--fedora-inputs')
    check = sub.add_parser('verify')
    check.add_argument('--context', required=True)
    check.add_argument('--expected-context-sha256', required=True)
    check.add_argument('--fixture', action='store_true')
    pl = sub.add_parser('plan')
    pl.add_argument('--selector', choices=('agentbox', 'gptbox', 'claudebox'), default='agentbox')
    pl.add_argument('--model', required=True)
    pl.add_argument('--effort', required=True)
    pl.add_argument('--resume')
    for p in (prep, pl):
        p.add_argument('--manifest', required=True)
        p.add_argument('--fixture', action='store_true')
    sub.add_parser('launch')
    args = parser.parse_args()
    try:
        require(args.command != 'launch', BLOCKER)
        if args.command == 'verify':
            result = verify(args.context, args.expected_context_sha256, args.fixture)
        else:
            m = json.loads(pathlib.Path(args.manifest).read_text())
            if args.command == 'prepare':
                result = prepare(m, args.binary, args.output, args.fixture, args.fedora_inputs)
            else:
                result = plan(m, args.selector, args.model, args.effort, args.resume, args.fixture)
        sys.stdout.buffer.write(canonical(result))
    except (ValueError, OSError, TypeError, subprocess.SubprocessError) as error:
        print(f'blocked: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
