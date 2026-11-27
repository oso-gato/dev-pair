#!/usr/bin/python3
"""Build one exact Fedora platform image from a protected main push."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import time

import fedora_ci as ci
import fedora_ci_guest as guest
import fedora_ci_storage as kernel
import fedora_oci
import platform_release as release
from platform_release_protocol import ARCHIVE_LIMIT, GIB, ROLES, Blocked, canonical, file_hash, hex_id, require, seconds, receive_frame

REPO = Path(__file__).resolve().parent.parent
RUN_ENV = (*ci.RUNNER_ENV, 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_REF_PROTECTED', 'GITHUB_WORKFLOW_REF')
EXPORT_VOLUME = 3 * GIB
OUTER_SECONDS = 1200
EVENT_LIMIT = 25 * 1024 ** 2
PLATFORM_WORKFLOW = '.github/workflows/platform-release.yml'
AGENT_WORKFLOW = '.github/workflows/agent-refresh.yml'
AGENT_SCHEDULE = '0 19 * * *'


def admitted_push(source, env):
    hex_id(source, 40)
    require(all(env.get(key) == value for key, value in {
        'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
        'GITHUB_REF': 'refs/heads/main', 'GITHUB_REF_PROTECTED': 'true', 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_SHA': source, 'GITHUB_WORKFLOW_REF': release.REPOSITORY + '/' + PLATFORM_WORKFLOW + '@refs/heads/main',
    }.items()), 'platform production requires the first exact protected main push')
    require(re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')), 'missing exact platform publisher run ID')
    path = Path(env.get('GITHUB_EVENT_PATH', ''))
    require(path.is_absolute() and path.resolve(strict=True) == path, 'protected push event path unavailable')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as event:
        node = os.fstat(event.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_uid in (0, os.getuid()) and not node.st_mode & 0o022 and node.st_nlink == 1 and
                0 < node.st_size <= EVENT_LIMIT, 'protected push event ownership or size is invalid')
        raw = event.read(EVENT_LIMIT + 1)
    require(len(raw) <= EVENT_LIMIT, 'protected push event exceeds its byte bound')
    value = json.loads(raw, object_pairs_hook=guest.unique_object)
    require(value.get('ref') == 'refs/heads/main' and value.get('after') == source and value.get('deleted') is False and
            value.get('repository', {}).get('full_name') == release.REPOSITORY, 'protected push event source mismatch')


def admitted_refresh(source, env):
    hex_id(source, 40)
    event_name = env.get('GITHUB_EVENT_NAME')
    require(event_name in ('schedule', 'workflow_dispatch') and all(env.get(key) == value for key, value in {
        'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_REF_PROTECTED': 'true', 'GITHUB_SHA': source, 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_WORKFLOW_REF': release.REPOSITORY + '/' + AGENT_WORKFLOW + '@refs/heads/main',
    }.items()) and re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')),
            'agent refresh requires the exact protected refresh workflow and main run')
    path = Path(env.get('GITHUB_EVENT_PATH', ''))
    require(path.is_absolute() and path.resolve(strict=True) == path, 'agent refresh event path differs')
    from platform_release_protocol import regular
    incoming, node = regular(path, EVENT_LIMIT)
    with incoming:
        require(node.st_uid in (0, os.getuid()), 'agent refresh event ownership differs')
        event = json.loads(incoming.read(EVENT_LIMIT + 1), object_pairs_hook=guest.unique_object)
    if event_name == 'schedule':
        require(event.get('schedule') == AGENT_SCHEDULE, 'unapproved agent refresh schedule')
    else:
        require(event.get('ref') in ('main', 'refs/heads/main') and event.get('inputs') in (None, {}),
                'on-demand refresh only accepts the fixed operation')


def admitted_source(source, role, env):
    if env.get('GITHUB_EVENT_NAME') == 'push':
        admitted_push(source, env)
        return False
    admitted_refresh(source, env)
    require(role in ci.SCENARIOS, 'agent refresh publishes only maintenance and development images')
    return True


class Export:
    def __init__(self, scenario, final, tooling_cache=None):
        self.scenario = scenario
        self.tooling_cache = tooling_cache
        self.final = final
        self.nonce = secrets.token_hex(16)
        self.volume = None

    def report_identity(self):
        event = os.environ.get('GITHUB_EVENT_NAME')
        workflow = PLATFORM_WORKFLOW if event == 'push' else AGENT_WORKFLOW
        require(event in ('push', 'schedule', 'workflow_dispatch') and
                os.environ.get('GITHUB_WORKFLOW_REF') == release.REPOSITORY + '/' + workflow + '@refs/heads/main',
                'platform report lacks its exact workflow identity')
        trigger = {'event': event, 'ref': os.environ.get('GITHUB_REF'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                   'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'role': self.scenario}
        if event == 'schedule':
            trigger['schedule'] = AGENT_SCHEDULE
        return workflow, trigger

    def report_profile(self, probe):
        probe.report['scenario'] = self.scenario
        probe.report['artifact_transport'] = {'upload': 'after successful role and teardown',
                                              'attestation': 'separate publish job', 'retention_days': 1}
        limits = probe.report['limits']
        limits.update(release_storage_bytes=EXPORT_VOLUME, release_inodes=3072, archive_bytes=ARCHIVE_LIMIT,
                      post_build_verify_seconds=guest.PLATFORM_VERIFY_SECONDS)
        if self.scenario == 'devbox':
            for key in ('overlay_bytes', 'overlay_inodes', 'guest_virtual_bytes', 'vm_seconds',
                        'vm_container_seconds', 'guest_cpus', 'guest_memory_bytes', 'public_seconds'):
                del limits[key]
            limits.update(outer_build_seconds=OUTER_SECONDS, build_memory_bytes=2 * GIB, build_cpus=2)
            probe.report['executor'] = 'public-standard-ubuntu-24.04/DevBox-OCI'
            probe.report['phases'] = {name: {'status': 'blocked', 'detail': 'Not reached'}
                                      for name in ('runner-preflight', 'outer-devbox', 'cleanup')}
        else:
            limits.update(vm_seconds=ci.VM_SECONDS - guest.PLATFORM_VERIFY_SECONDS,
                          guest_work_seconds=guest.INITIALIZE_SECONDS - guest.PLATFORM_EXPORT_SECONDS - guest.PLATFORM_VERIFY_SECONDS,
                          guest_export_seconds=guest.PLATFORM_EXPORT_SECONDS)

    def preflight(self, probe):
        require(self.final.parent.is_dir() and self.final.parent.resolve(strict=True) == self.final.parent and
                self.final.parent.stat().st_uid == os.getuid() and not self.final.parent.stat().st_mode & 0o022 and
                not os.path.lexists(self.final), 'release artifact destination is unavailable')
        planned = sum(volume.size for volume in probe.storage.volumes)
        device = self.final.parent.stat().st_dev
        if device != probe.lease.stat().st_dev:
            require(shutil.disk_usage(self.final.parent).free >= ci.HOST_RESERVE + ARCHIVE_LIMIT,
                    'artifact output filesystem lacks export overlap and host reserve')
        overlap = ARCHIVE_LIMIT if device == probe.lease.stat().st_dev else 0
        probe.storage.parent_free(planned + EXPORT_VOLUME + overlap + kernel.PARENT_HEADROOM)

    def allocate(self, probe):
        self.volume = kernel.Volume(probe.lease, 'release', EXPORT_VOLUME, 3072, probe.privileged)
        self.volume.configure()
        probe.report['release_storage'] = self.volume.observe(kernel.mount_table())
        probe.storage.parent_free(ARCHIVE_LIMIT if self.final.parent.stat().st_dev == probe.lease.stat().st_dev else 0)

    def input_cache(self):
        if self.tooling_cache is None:
            return []
        return ['--codex-cache', str(self.tooling_cache)]

    def request(self, probe):
        writer = REPO / 'tools/platform_release_guest.py'
        return {'nonce': self.nonce, 'writer_sha256': ci.file_hash(writer)}

    def vm_arguments(self, args, image):
        position = args.index(image)
        args[position:position] = [f'--volume={self.volume.path}:/release:rw']
        args.extend(('-chardev', 'file,id=platform,path=/release/export.bin,append=off',
                     '-device', 'virtio-serial-pci', '-device', 'virtserialport,chardev=platform,name=dev-pair-platform'))
        return args, ci.VM_SECONDS - guest.PLATFORM_VERIFY_SECONDS

    def capture(self, probe):
        native = probe.report['guest']
        require(all(row['status'] == 'pass' for row in native['phases'].values()), 'native producer did not pass its release phases')
        if self.scenario == 'maintenance':
            observed = native['initialization']
            identity = observed['assembled_image_id']
            proof = {key: observed[key] for key in ('source_sha', 'context_sha256', 'distrobox_sha', 'assembled_image_id',
                      'boundary_and_version_cycles', 'runtime_container_removed', 'job_admission')}
        else:
            proof = native['development']['receipt']['inner']
            identity = proof['image_id']
        target = {'nonce': self.nonce, 'source_sha': probe.source, 'role': self.scenario,
                  'context_sha256': probe.handoff['context_sha256'], 'image_id': identity}
        end = min(probe.phase_end, time.monotonic() + guest.PLATFORM_VERIFY_SECONDS)
        with release.output_directory(self.final) as stage:
            archive = stage / release.archive_name(self.scenario)
            frame = receive_frame(self.volume.path / 'export.bin', archive, target, end)
            if self.scenario == 'maintenance':
                require(all(frame['receipt']['result'][key] == value for key, value in proof.items()),
                        'transferred maintenance result differs from verified serial evidence')
            else:
                require(frame['receipt'] == proof, 'transferred inner record differs from verified serial evidence')
            release.write_image_part(stage, frame['image'], frame['receipt'], end)
        probe.storage.parent_free()
        probe.report['platform_export'] = frame['image']

    def close(self):
        if self.volume is not None:
            self.volume.release()


class OuterStorage(kernel.KernelStorage):
    def __init__(self, lease, privileged):
        super().__init__(lease, privileged)
        self.volumes = (self.overhead,)

    def configure(self):
        initial = self.parent_free(self.overhead.size + kernel.PARENT_HEADROOM)
        self.started = True
        self.overhead.configure()
        return {**self.observe(), 'initial_parent_free_bytes': initial}


def engine_copy(probe, temporary, *args, timeout):
    probe.engine_activity = True
    probe.image_copy_active = True
    reserve = probe.phase_end - time.monotonic()
    timeout = min(timeout, reserve)
    require(timeout > 3, 'outer tooling copy cannot fit its bounded build window')
    limits = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', f'{timeout - 2:.6f}s']
    if args[0] == 'save':
        limits += ['/usr/bin/prlimit', f'--fsize={ARCHIVE_LIMIT}:{ARCHIVE_LIMIT}']
    output = probe.bounded(probe.engine_command(copy_tmp=temporary, limits=limits) + list(args), timeout,
                           'scoped DevBox OCI operation')
    probe.image_copy_active = False
    return output


def build_devbox(probe):
    import native_placements as native

    cache = probe.root / 'public-cache'
    helper = REPO / 'tools/public_inputs.py'
    probe.bounded([sys.executable, '-B', str(helper), 'fetch', '--output', str(cache)],
                  300, 'fixed DevBox signed input fetch')
    row = probe.release
    temporary = probe.root / 'tmp'
    with fedora_oci.verified(cache, temporary_parent=temporary) as (plain, _):
        proof = fedora_oci.import_image(lambda *args, timeout: engine_copy(probe, temporary, *args, timeout=timeout), plain)
    distrobox = cache / 'distrobox'
    source = ci.run_small(['/usr/bin/git', '-C', str(distrobox), 'rev-parse', 'HEAD'], timeout=5).decode().strip()
    require(source == native.db.DISTROBOX, 'DevBox Distrobox source differs from reviewed pinned upstream')
    enter = ci.run_small(['/usr/bin/git', '-C', str(distrobox), 'show', source + ':distrobox-enter'], timeout=5)
    require(hashlib.sha256(enter).hexdigest() == native.db.ENTER_SHA256, 'DevBox entry differs from reviewed upstream bytes')
    tooling, context = probe.root / 'tooling', probe.root / 'devbox'
    tooling.mkdir()
    context.mkdir()
    (tooling / 'Containerfile').write_bytes(native.TOOLING_RECIPE)
    (context / 'distrobox-enter').write_bytes(enter)
    for name in native.OUTER_FILES:
        shutil.copyfile(REPO / 'runtime/devbox' / name, context / name)
    context_sha = hashlib.sha256(canonical({p.name: ci.file_hash(p) for p in sorted(context.iterdir())})).hexdigest()
    common = ('build', '--quiet', '--pull=never', '--http-proxy=false', '--format=oci', '--force-rm',
              '--memory=2g', '--cpu-quota=200000', '--ulimit=fsize=2147483648:2147483648')
    tool_id = native.db.engine_id(engine_copy(probe, temporary, *common, '--network=slirp4netns:allow_host_loopback=false',
                                              '--file', str(tooling / 'Containerfile'), str(tooling), timeout=600).decode().strip())
    outer_id = native.db.engine_id(engine_copy(probe, temporary, *common, '--network=none',
                                               '--build-arg', 'TOOLING_IMAGE=sha256:' + tool_id,
                                               '--build-arg', 'SOURCE_SHA=' + probe.source,
                                               '--file', str(context / 'Containerfile'), str(context), timeout=600).decode().strip())
    tool, = json.loads(engine_copy(probe, temporary, 'image', 'inspect', tool_id, timeout=20))
    outer, = json.loads(engine_copy(probe, temporary, 'image', 'inspect', outer_id, timeout=20))
    tool_shape, shape = map(native.image_shape, (tool, outer))
    require(tool_shape['config_id'] == tool_id and shape['config_id'] == outer_id and
            shape['diff_ids'][:len(tool_shape['diff_ids'])] == tool_shape['diff_ids'] and
            len(shape['diff_ids']) > len(tool_shape['diff_ids']), 'DevBox image does not extend its exact tooling image')
    archive = row.volume.path / release.archive_name('devbox')
    engine_copy(probe, temporary, 'save', '--format=oci-archive', '--output', str(archive), 'sha256:' + outer_id, timeout=240)
    probe.privileged('/usr/bin/chown', f'{os.getuid()}:{os.getgid()}', '--', str(archive))
    end = min(probe.phase_end, time.monotonic() + guest.PLATFORM_VERIFY_SECONDS)
    with release.output_directory(row.final) as stage:
        with (stage / archive.name).open('xb') as output:
            digest, size = file_hash(archive, ARCHIVE_LIMIT, end, owner=os.getuid(), output=output)
        image = {'role': 'devbox', 'source_sha': probe.source, 'context_sha256': context_sha,
                 'image_id': outer_id, 'archive_sha256': digest, 'archive_bytes': size, 'diff_ids': shape['diff_ids']}
        part = release.write_image_part(stage, image,
                                        {'tooling_image_id': tool_id, 'tooling_diff_ids': tool_shape['diff_ids'],
                                         'tooling_recipe_sha256': ci.file_hash(tooling / 'Containerfile'), 'signed_base': proof}, end)
    probe.storage.parent_free()
    probe.report['platform_export'] = {**image, 'oci_manifest_sha256': part['oci_manifest_sha256']}


def execute_devbox(probe):
    start = time.monotonic()
    phase = 'runner-preflight'
    try:
        require((REPO / 'tools/native_placements.py').is_file(), 'reviewed G DevBox tooling recipe is missing from the integrated commit')
        probe.phase_end = start + OUTER_SECONDS
        with ci.deadline(OUTER_SECONDS):
            probe.preflight()
            phase = 'outer-devbox'
            build_devbox(probe)
            probe.phase(phase, 'pass', 'Signed Fedora tooling and exact outer OCI export verified')
    except (Blocked, ci.Blocked, OSError, ValueError, ImportError, subprocess.SubprocessError) as error:
        probe.phase(phase, 'blocked', str(error))
    finally:
        probe.phase_end = None
        try:
            with ci.deadline(ci.CLEANUP_SECONDS):
                probe.cleanup()
        except (Blocked, ci.Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
            probe.phase('cleanup', 'fail', str(error))
        probe.finish_report()
    return 0 if all(row['status'] == 'pass' for row in probe.report['phases'].values()) else 2


def namespace(source, role):
    for tool in ci.NAMESPACE_TOOLS:
        require(Path(tool).is_file(), f'required preinstalled production namespace tool unavailable: {tool}')
    ancestor = os.readlink('/proc/self/ns/mnt')
    values = {**ci.SAFE_ENV, **{key: os.environ[key] for key in RUN_ENV if key in os.environ}}
    args = ['/usr/bin/sudo', '-n', '/usr/bin/timeout', '--kill-after=1s', f'{ci.CONTROLLER_SECONDS}s',
            '/usr/bin/unshare', '--mount', '--propagation', 'private', '--pid', '--mount-proc', '--kill-child=SIGKILL',
            '/usr/bin/setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()), '--init-groups', '--pdeathsig=keep',
            '/usr/bin/env', '-i', *(f'{k}={v}' for k, v in values.items()), '/usr/bin/python3', '-B', str(REPO / 'tools/fedora_ci.py'),
            '--expected-source', source, '--platform-release-role', role, '--namespace-parent', ancestor]
    return subprocess.run(args, env=ci.SAFE_ENV, timeout=ci.CONTROLLER_SECONDS + 5).returncode


def entered(source, role, parent):
    refresh = admitted_source(source, role, os.environ)
    require(parent is not None and os.getuid() != 0 and os.getpid() == 1 and
            re.fullmatch(r'mnt:\[\d+\]', parent) and os.readlink('/proc/self/ns/mnt') != parent,
            'private production mount and PID namespaces not established')
    require(os.uname().machine == 'x86_64', 'x86_64 standard runner required for this platform release')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    runner = Path(os.environ['RUNNER_TEMP'])
    require(runner.is_absolute(), 'standard runner temporary directory unavailable')
    final = runner / ('platform-' + role + '-' + source)
    root = ci.scratch_root(str(runner))
    export = Export(role, final, runner / 'agent-tooling' if refresh else None)
    probe = ci.Probe(source, root, role if role in ci.SCENARIOS else 'maintenance', release=export)
    if role == 'devbox':
        probe.storage = OuterStorage(root, probe.privileged)
        return execute_devbox(probe)
    return probe.execute()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=ROLES)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    admitted_source(args.source, args.role, os.environ)
    return namespace(args.source, args.role)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, ci.Blocked, OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as exc:
        ci.emit_text('PLATFORM_RELEASE_BLOCKED ', str(exc), 1500)
        sys.exit(2)
