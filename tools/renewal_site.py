"""Derive the site plan from protected portable intake and installed readback."""
import argparse
import base64
import io
import os
from pathlib import Path
import socket
import stat
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import renewal as r
from renewal import protocol as p
from gptbox import image_inputs_bytes
from public_inputs import DBX_SOURCE

ROOT = r.DEFAULT_ROOT
PORTABLE = ROOT / 'platform-releases'
CONFIG = Path('/etc/dev-pair/renewal/site-configs')
HOSTS = Path('/usr/libexec/dev-pair/host-releases')
HOST_CONFIGS = Path('/etc/dev-pair/host-releases')
INDEX_NAME = 'platform.json'
FULL = 'dev-pair-platform-release'
AGENT = 'dev-pair-agent-release'
MAX_SITE_JOBS = 32
GIB = 1024**3


def protected_bytes(path, limit=r.MAX_CONTROL):
    """Read bounded installed metadata through locally protected paths."""
    r.require(path.is_absolute() and path.resolve(strict=True) == path, 'site release path is not canonical')
    for parent in path.parents:
        node = parent.lstat()
        sticky = node.st_uid == 0 and node.st_mode & stat.S_ISVTX
        r.require(stat.S_ISDIR(node.st_mode) and node.st_uid in (0, os.getuid()) and
                  (not node.st_mode & 0o022 or sticky), 'site release ancestry is not protected')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        node = os.fstat(stream.fileno())
        r.require(stat.S_ISREG(node.st_mode) and node.st_uid == os.getuid() and node.st_nlink == 1 and
                  not node.st_mode & 0o022 and 0 < node.st_size <= limit, 'unsafe or oversized site release metadata')
        raw = stream.read(limit + 1)
    r.require(len(raw) == node.st_size, 'site release metadata changed during read')
    return raw


def closed_site(raw):
    site = r.loads(raw)
    p.fields(site, 'schema hostname host_config_sha256 jobs')
    p.number(site['schema'], 1, 1)
    p.token(site['hostname'])
    r.require(len(site['hostname']) <= 63, 'invalid approved site hostname length')
    p.digest(site['host_config_sha256'])
    jobs = site['jobs']
    r.require(type(jobs) is dict and 0 < len(jobs) <= MAX_SITE_JOBS, 'site job geometry is missing')
    reserved = set()
    for job, geometry in jobs.items():
        p.token(job)
        r.require(len(job) <= 48, 'site job is unsupported by the live role executors')
        p.fields(geometry, 'storage_bytes categories')
        p.number(geometry['storage_bytes'], 8 * GIB, 16 * GIB)
        r.require(geometry['storage_bytes'] % GIB == 0, 'approved site storage must use whole GiB')
        categories = geometry['categories']
        p.fields(categories, 'outer inner')
        outer, inner = categories['outer'], categories['inner']
        r.require(type(outer) is list and type(inner) is list and len(outer) == 3 and len(inner) == 2 and
                  all(type(category) is int and 0 <= category <= 1023 for category in [*outer, *inner]),
                  'invalid approved site SELinux category geometry')
        r.require(outer == sorted(set(outer)) and inner == sorted(set(inner)) and set(inner) < set(outer) and
                  not reserved.intersection(outer), 'site jobs have incompatible SELinux categories')
        reserved.update(outer)
    return site


def offer_record(value, scope):
    p.fields(value, 'schema scope operation platform_sha256 previous_release_sha256 site_config_sha256 affected_jobs reason')
    p.number(value['schema'], 2, 2)
    r.require(value['scope'] == scope and scope in ('initial', 'agent', 'stable'), 'unsupported portable site selection')
    p.token(value['operation'])
    p.digest(value['platform_sha256'])
    p.digest(value['site_config_sha256'])
    if scope == 'initial':
        r.require(value['previous_release_sha256'] is None, 'initial site selection has a predecessor')
    else:
        p.digest(value['previous_release_sha256'])
    jobs = value['affected_jobs']
    r.require(type(jobs) is list and len(jobs) <= r.MAX_JOBS, 'invalid affected jobs')
    for job in jobs:
        p.token(job)
    r.require(jobs == sorted(set(jobs)), 'ambiguous affected jobs')
    p.text(value['reason'], 512)
    return value


def installed_row(receipt, *, index_sha, index, base, site_sha, boot):
    p.fields(receipt, 'schema platform_sha256 base_platform_sha256 site_config_sha256 boot_id source_sha components')
    p.number(receipt['schema'], 1, 1)
    r.require(receipt['platform_sha256'] == index_sha and receipt['base_platform_sha256'] == base and
              receipt['site_config_sha256'] == site_sha and receipt['boot_id'] == boot and
              receipt['source_sha'] == index['source_sha'], 'installed proof is for a different target, site or boot')
    fields = {'host': 'manifest_sha256', 'maintenance': 'context_sha256 oci_config_sha256 oci_manifest_sha256 result_sha256',
              'devbox': 'oci_config_sha256 oci_manifest_sha256',
              'development': 'context_sha256 oci_config_sha256 oci_manifest_sha256 inner_sha256 jobs'}
    entries = receipt['components']
    p.fields(entries, 'host maintenance devbox development')
    for role, names in fields.items():
        p.fields(entries[role], names)
        for key in entries[role].keys() - {'jobs'}:
            p.digest(entries[role][key])
    return entries


def artifact_rows(index, base):
    return {**base['components'], **index['components']}


def check_component(receipt, component):
    for key in ('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256'):
        if key in receipt:
            r.require(receipt[key] == component[key], 'installed role differs from the verified portable image')


def bound_part(directory, index, role):
    raw = protected_bytes(directory / role / 'part.json', 65536)
    expected = index['transports'][role]['files']['part.json']
    r.require((r.sha(raw), len(raw)) == (expected['sha256'], expected['bytes']),
              'producer evidence differs from the attested portable part')
    return r.loads(raw)


def maintenance_claim(directory, index):
    component = index['components']['maintenance-agent']
    producer = bound_part(directory, index, 'maintenance')['producer']['result_sha256']
    p.digest(producer)
    return {'schema': 1, 'kind': 'maintenance-imported-release-admission', 'platform_sha256': directory.name,
            'source_sha': component['source_sha'], 'context_sha256': component['context_sha256'],
            'image_id': component['oci_config_sha256'], 'oci_manifest_sha256': component['oci_manifest_sha256'],
            'distrobox_sha': DBX_SOURCE, 'boundary_and_version_cycles': 2, 'runtime_container_removed': True,
            'job_admission': False, 'producer_result_sha256': producer}


def maintenance_path(root, claim, boot):
    r.session(boot)
    for key in ('platform_sha256', 'context_sha256', 'image_id'):
        r.digest(claim[key])
    return (root / 'bootstrap/gptbox-adapter' / claim['context_sha256'] / 'imported-releases' /
            claim['platform_sha256'] / claim['image_id'] / (boot + '.json'))


def maintenance_readback(root, claim, boot):
    path = maintenance_path(root, claim, boot)
    raw = protected_bytes(path, 65536)
    r.require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and raw == image_inputs_bytes({**claim, 'boot_id': boot}),
              'maintenance lacks exact typed local import and boundary admission')
    return r.sha(raw)


def retained_maintenance(controller, component, context):
    """Read the exact per-image import proof already held for this local selection."""
    root = controller.root
    platform = component.get('platform_sha256')
    if platform is None:
        return None
    directory, index, _ = Resolver(controller, portable=root / 'platform-releases').index(platform)
    claim = maintenance_claim(directory, index)
    r.require((claim['context_sha256'], claim['source_sha'], claim['image_id']) ==
              (context, component['source_revision'], component['artifact_sha256']),
              'retained maintenance admission differs from selected launch plan')
    installed = r.loads(protected_bytes(directory / 'installed.json', 65536))
    site = installed['site_config_sha256']
    p.digest(site)
    base = index['base_platform_sha256'] if index['kind'] == AGENT else directory.name
    installed_boot = r.session(installed['boot_id'])
    components = installed_row(installed, index_sha=directory.name, index=index, base=base, site_sha=site,
                               boot=installed_boot)
    check_component(components['maintenance'], index['components']['maintenance-agent'])
    r.require(maintenance_readback(root, claim, installed_boot) == components['maintenance']['result_sha256'],
              'retained maintenance admission differs from the installed release receipt')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if boot != installed_boot and os.path.lexists(maintenance_path(root, claim, boot)):
        maintenance_readback(root, claim, boot)
        return claim, boot, site
    return claim, installed_boot, site


def observe_development_files(native, parent, lease, reference, manifest, parsed, *, owner=(0, 0)):
    record = lease['manifests'][reference]
    volume = lease['volumes']['build']
    label = native.db.file_label(parsed, 'outer')
    device = os.fstat(parent).st_dev
    r.require(record['inner_sha256'] == r.sha(image_inputs_bytes(parsed['inner'])), 'installed inner lease digest changed')
    with native.private_child(parent, 'inputs', *owner, mode=0o755, create=False, label=label) as (inputs, _):
        r.require(native.volume_inode(os.fstat(inputs)) == volume['inputs'] and os.fstat(inputs).st_dev == device,
                  'DevBox inputs differ from protected mounted lease')
        with native.private_child(inputs, reference, *owner, mode=0o755, create=False, label=label) as (folder, _):
            r.require(native.volume_inode(os.fstat(folder)) == record['directory'] and os.fstat(folder).st_dev == device,
                      'DevBox release input directory differs from its protected lease')
            for name, size in (('manifest.json', len(manifest)), ('development.oci.tar', parsed['inner']['archive_bytes'])):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                with os.fdopen(os.open(name, flags, dir_fd=folder), 'rb') as stream:
                    fd = stream.fileno()
                    node = os.fstat(fd)
                    r.require(stat.S_ISREG(node.st_mode) and (node.st_uid, node.st_gid) == owner and
                              stat.S_IMODE(node.st_mode) == 0o444 and node.st_nlink == 1 and
                              node.st_size == size and node.st_dev == device and
                              native.db.same_label(os.getxattr(fd, 'security.selinux').decode('ascii'), label),
                              'DevBox installed input ownership, label or length differs')
                    if name == 'manifest.json':
                        r.require(stream.read(size + 1) == manifest and r.sha(manifest) == reference,
                                  'installed local DevBox manifest bytes differ')
                    current = os.stat(name, dir_fd=folder, follow_symlinks=False)
                    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                    r.require(all(getattr(current, key) == getattr(node, key) for key in fields),
                              'DevBox input changed during readback')
            r.require(native.volume_inode(os.stat(reference, dir_fd=inputs, follow_symlinks=False)) == record['directory'],
                      'DevBox release folder changed during readback')
        r.require(native.volume_inode(os.stat('inputs', dir_fd=parent, follow_symlinks=False)) == volume['inputs'],
                  'DevBox mounted inputs changed during readback')


def observe_development(root, manifests, site):
    import native_placements as n

    lease_path = root / 'native-placements/release/records/placement.json'
    producer = n.DevelopmentGptbox()
    with producer.lock():
        record = r.read_json(lease_path)
        p.fields(record, 'schema owner activity volumes jobs outer_copy legacy last_failure')
        p.number(record['schema'], 1, 1)
        r.require(record['activity'] is None and set(manifests) <= set(record['jobs']), 'DevBox release placement is unsettled')
        account = r.pwd.getpwnam('dp-dev')
        for job, (reference, manifest) in manifests.items():
            lease = record['jobs'][job]
            geometry = site['jobs'][job]
            r.require(all(lease[key] == part for key, part in geometry.items()), 'DevBox local lease geometry differs')
            build = root / 'development/builds' / job
            proof = SimpleNamespace(account=account, backings=root / 'native-placements/backings' / job,
                                    record=lease_path.with_name(job + '.json'), state=lease)
            volume = n.Volume(proof, 'build', build, geometry['storage_bytes'])
            volume.staging = lease_path.with_name(job + '-build.mount')
            r.require(volume.verify_existing(n.mount_rows()) == {build}, 'DevBox lease has no verified mounted build filesystem')
            before = n.devbox.private_dir(build, account)
            with n.directory_fd(build) as descriptor:
                node = os.fstat(descriptor)
                r.require(n.identity(before) == n.identity(node) and node.st_dev == volume.device.stat().st_rdev,
                          'DevBox role mount descriptor differs from its protected lease')
                observe_development_files(n, descriptor, lease, reference, manifest, r.loads(manifest))
                r.require(n.identity(build.lstat()) == n.identity(node), 'DevBox build mount changed during readback')


def build_selection(index, base, site, installed, inner, platform, previous=None):
    """Pure derivation whose outputs are independently compared with installed leaves."""
    rows = artifact_rows(index, base)
    host, outer = rows['host'], rows['devbox']
    r.require(installed['host']['manifest_sha256'] == host['bundle_manifest_sha256'], 'installed host differs from its portable bundle')
    for role, name in (('maintenance', 'maintenance-agent'), ('development', 'development-agent'), ('devbox', 'devbox')):
        check_component(installed[role], rows[name])
    agent = rows['development-agent']
    p.fields(inner, 'source_sha context_sha256 image_id archive_sha256 archive_bytes diff_ids inputs_sha256 sealed_sha256')
    expected = {key: agent[key] for key in ('source_sha', 'context_sha256', 'archive_sha256', 'archive_bytes')}
    r.require({key: inner[key] for key in expected} == expected and inner['image_id'] == agent['oci_config_sha256'],
              'installed inner configuration differs from attested package')
    for key in ('inputs_sha256', 'sealed_sha256'):
        p.digest(inner[key])
    r.require(type(inner['diff_ids']) is list and 0 < len(inner['diff_ids']) <= 128 and
              all(type(item) is str and item.startswith('sha256:') and len(item) == 71 for item in inner['diff_ids']),
              'invalid selected inner image layer set')
    for item in inner['diff_ids']:
        p.digest(item[7:])
    selected = {}
    for name, value in rows.items():
        if name == 'host':
            selected[name] = {'source_revision': value['source_sha'], 'config_sha256': site['host_config_sha256'],
                              'artifact_sha256': value['bundle_manifest_sha256']}
        else:
            selected[name] = {'source_revision': value['source_sha'], 'config_sha256': value['context_sha256'],
                              'artifact_sha256': value['oci_config_sha256']}
            if name in r.SCOPE_COMPONENTS['agent']:
                selected[name]['codex_version'] = value['codex_version']
            if name == 'maintenance-agent':
                selected[name]['platform_sha256'] = platform
    if previous is not None:
        r.require(all(selected[name] == previous['components'][name] for name in ('host', 'devbox')) and
                  previous['config_sha256'] == site['host_config_sha256'], 'agent selection changes the retained host or DevBox')
    jobs = installed['development']['jobs']
    r.require(type(jobs) is dict and set(jobs) == set(site['jobs']), 'installed job map differs from the independently approved site geometry')
    manifests = {}
    for job, geometry in site['jobs'].items():
        p.fields(jobs[job], 'manifest_sha256')
        local = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': r.STANDARDS, 'job': job,
                 'storage_bytes': geometry['storage_bytes'], 'categories': geometry['categories'],
                 'outer': {'source_sha': outer['source_sha'], 'image_id': outer['oci_config_sha256']}, 'inner': inner}
        data = r.json_bytes(local) + b'\n'
        reference = r.sha(data)
        r.require(jobs[job]['manifest_sha256'] == reference, 'installed manifest differs from the deterministic local job plan')
        manifests[job] = (reference, data)
    plan = {'schema': 1, 'maintenance_context_sha256': rows['maintenance-agent']['context_sha256'],
            'development_manifests': {job: item[0] for job, item in manifests.items()}}
    selection = {'schema': 1, 'source_revision': index['source_sha'], 'config_sha256': site['host_config_sha256'],
                 'plan_sha256': r.identity(plan), 'ledger_contract': p.VERSION, 'state_contract': 1, 'components': selected}
    return r.checked_release(selection), plan, manifests


class Resolver:
    def __init__(self, controller, portable=PORTABLE, configs=CONFIG, hosts=HOSTS, host_configs=HOST_CONFIGS,
                 development_reader=observe_development):
        self.controller = controller
        self.control = controller.control
        self.root = controller.root
        self.portable = portable
        self.configs = configs
        self.hosts = hosts
        self.host_configs = host_configs
        self.development_reader = development_reader

    def index(self, reference):
        from platform_release_protocol import canonical, portable_index
        p.digest(reference)
        directory = self.portable / reference
        raw = protected_bytes(directory / INDEX_NAME, 65536)
        r.require(r.sha(raw) == reference, 'portable index digest mismatch')
        value = r.loads(raw)
        portable_index(value, value['source_sha'], value['publisher_run'])
        r.require(raw == canonical(value), 'portable release index has noncanonical bytes')
        admission = protected_bytes(directory / 'intake.json', 65536)
        r.require(r.loads(admission) == {'schema': 2, 'platform_sha256': reference, 'source_sha': value['source_sha'],
                                        'publisher_run': value['publisher_run'], 'kind': value['kind']},
                  'missing exact protected F/D intake result')
        if value['schema'] == 3:
            _, local = self.site_predecessor(directory, reference, value)
            admission += local
        return directory, value, r.sha(admission)

    def site_predecessor(self, directory, reference, value):
        from platform_release_protocol import canonical, site_predecessor

        raw = protected_bytes(directory / 'site-predecessor.json', 4096)
        binding = r.loads(raw)
        r.require(raw == canonical(binding), 'local portable predecessor proof is noncanonical')
        return site_predecessor(binding, reference, value['base_platform_sha256']), raw

    def store(self, path, value):
        if os.path.lexists(path):
            r.require(r.read_private(path, r.MAX_CONTROL) == r.json_bytes(value), 'site release publication would change protected bytes')
        else:
            r.replace_json(path, value)

    def resolve(self, offer, *, boot=None, hostname=None):
        scope = offer['scope']
        offer_record(offer, scope)
        if boot is None:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        r.session(boot)
        platform = offer['platform_sha256']
        site_hash = offer['site_config_sha256']
        site_bytes = protected_bytes(self.configs / (site_hash + '.json'), 65536)
        r.require(r.sha(site_bytes) == site_hash, 'approved site configuration digest changed')
        site = closed_site(site_bytes)
        r.require(site['hostname'] == (hostname or socket.gethostname()), 'approved site configuration is for another host')
        r.require(set(offer['affected_jobs']) <= set(site['jobs']), 'site update names a foreign product job')
        directory, index, intake_sha = self.index(platform)
        predecessor, previous = None, None
        stable_admission = None
        if scope == 'initial':
            r.require(index['kind'] == FULL and index['previous_platform_sha256'] is None and
                      not os.path.lexists(self.control / 'current.json') and not os.path.lexists(self.control / 'site-current.json'),
                      'initial site selection requires a fresh full portable release')
            base_sha, stable = platform, index
        elif scope == 'stable':
            import stable_renewal

            prior = stable_renewal.settled(self, site_hash)
            r.require(offer['previous_release_sha256'] == prior['release_sha256']
                      and offer['affected_jobs'] == sorted(site['jobs']),
                      'stable offer does not cover the exact live predecessor and all affected jobs')
            stable_admission = prior, stable_renewal.validate_successor(self, prior, index, platform, site)
            base_sha, stable = platform, index
        else:
            r.require(index['kind'] == AGENT, 'agent site selection requires a distinct portable agent package')
            current = self.controller.live_release()
            published = r.read_json(self.control / 'platform-bindings' / (current + '.json'))
            r.require(published['release_sha256'] == current and published['site_config_sha256'] == site_hash,
                      'active selection and approved site configuration differ')
            _, _, prior_intake = self.index(published['platform_sha256'])
            r.require(prior_intake == published['intake_sha256'], 'active portable intake evidence changed')
            predecessor = offer['previous_release_sha256']
            if current != predecessor:
                r.require(published['platform_sha256'] == platform, 'agent offer has a stale local predecessor')
            if index['schema'] == 3:
                r.require(r.read_json(self.control / 'site-current.json') == current,
                          'site and admitted release selectors differ')
                local_prior = published if predecessor == current else r.read_json(
                    self.control / 'platform-bindings' / (predecessor + '.json'))
                portable_prior, _ = self.site_predecessor(directory, platform, index)
                r.require(local_prior['release_sha256'] == predecessor and
                          local_prior['site_config_sha256'] == site_hash and
                          local_prior['base_platform_sha256'] == published['base_platform_sha256'] and
                          local_prior['platform_sha256'] == portable_prior,
                          'site-chained offer changes independently staged predecessor evidence')
                if predecessor != current:
                    _, _, local_intake = self.index(portable_prior)
                    r.require(local_prior['intake_sha256'] == local_intake,
                              'retained local predecessor intake evidence changed')
            elif current == predecessor:
                r.require(index['previous_platform_sha256'] == published['platform_sha256'], 'agent offer changes its portable predecessor')
            base_sha = index['base_platform_sha256']
            r.require(base_sha == published['base_platform_sha256'], 'agent offer changes its retained portable base')
            _, stable, _ = self.index(base_sha)
            r.require(stable['kind'] == FULL, 'retained host/DevBox portable base is incomplete')
            previous = self.controller.release(current)
        receipt = protected_bytes(directory / 'installed.json', 65536)
        installed = installed_row(r.loads(receipt), index_sha=platform, index=index, base=base_sha, site_sha=site_hash, boot=boot)
        inner = bound_part(directory, index, 'development')['producer']
        r.require(r.sha(image_inputs_bytes(inner)) == installed['development']['inner_sha256'],
                  'installed inner receipt identifies different producer evidence')
        selection, plan, manifests = build_selection(index, stable, site, installed, inner, platform, previous)
        reference = r.identity(selection)
        if previous is not None and current != predecessor:
            r.require(reference == current, 'already selected agent package derives different local bytes')
        host = selection['components']['host']
        r.require(r.sha(protected_bytes(self.hosts / host['artifact_sha256'] / 'manifest.json', 1 << 20)) == host['artifact_sha256'],
                  'portable host manifest has not been installed')
        r.require(r.sha(protected_bytes(self.host_configs / (site['host_config_sha256'] + '.json'), 4096)) == site['host_config_sha256'],
                  'approved host configuration has not been installed')
        claim = maintenance_claim(directory, index)
        r.require(maintenance_readback(self.root, claim, boot) == installed['maintenance']['result_sha256'],
                  'installed maintenance observation identifies different local admission bytes')
        self.development_reader(self.root, manifests, site)
        self.store(self.control / 'plans' / (selection['plan_sha256'] + '.json'), plan)
        self.store(self.control / 'releases' / (reference + '.json'), selection)
        binding = {'schema': 1, 'release_sha256': reference, 'platform_sha256': platform, 'base_platform_sha256': base_sha,
                   'site_config_sha256': site_hash, 'plan_sha256': selection['plan_sha256'], 'intake_sha256': intake_sha}
        self.store(self.control / 'platform-bindings' / (reference + '.json'), binding)
        if stable_admission is not None:
            stable_renewal.store(self, offer, binding, *stable_admission)
        # The observation can refresh on another boot. It cannot change the immutable selection binding.
        observation = {'schema': 1, **binding, 'boot_id': boot, 'installed_sha256': r.sha(receipt)}
        r.replace_json(self.control / 'platform-observations' / (reference + '.json'), observation)
        return binding


def role_artifacts(controller, reference):
    release = controller.release(reference)
    raw = r.read_private(controller.control / 'plans' / (release['plan_sha256'] + '.json'), r.MAX_CONTROL)
    r.require(r.sha(raw) == release['plan_sha256'], 'private role launch plan digest differs')
    plan = r.loads(raw)['development_manifests']
    r.require(type(plan) is dict and plan, 'private role placement has no approved development manifest')
    job = sorted(plan)[0]
    r.token(job)
    r.digest(plan[job])
    return {'release_sha256': reference, 'job': job, 'development_manifest': plan[job],
            **{role + '_image': release['components'][component]['artifact_sha256'] for role, component in
               (('maintenance', 'maintenance-agent'), ('development', 'development-agent'), ('devbox', 'devbox'))}}


class CandidateAccess:
    """Exchange independent access evidence for one staged exact placement."""

    def __init__(self, controller, host, *, kind=None):
        from destination_observation import AGENT_CANDIDATE, STABLE_CANDIDATE

        self.controller, self.host = controller, host
        self.control = controller.control
        self.kind = AGENT_CANDIDATE if kind is None else kind
        r.require(self.kind in (AGENT_CANDIDATE, STABLE_CANDIDATE), 'unknown prospective placement authority')
        self.scope = 'stable' if self.kind == STABLE_CANDIDATE else 'agent'
        self.pending = self.control / (self.scope + '-observation-pending.json')

    def selection(self, reference, previous, operation):
        r.digest(reference)
        r.digest(previous)
        r.token(operation)
        target = self.controller.release(reference)
        retained = self.controller.release(previous)
        changed = {key for key in r.COMPONENTS if target['components'][key] != retained['components'][key]}
        if self.scope == 'stable':
            from stable_renewal import for_release

            approval = for_release(self.controller, reference)
            r.require(changed == r.COMPONENTS and target['config_sha256'] == retained['config_sha256'] and
                      approval['previous_release_sha256'] == previous and approval['operation'] == operation,
                      'prospective stable observation differs from the authorized complete successor')
            return r.read_json(self.control / 'platform-bindings' / (reference + '.json'))
        r.require(changed and changed <= r.SCOPE_COMPONENTS['agent'] and
                  target['config_sha256'] == retained['config_sha256'],
                  'prospective observation requires an agent-only replacement')
        binding = r.read_json(self.control / 'platform-bindings' / (reference + '.json'))
        prior = r.read_json(self.control / 'platform-bindings' / (previous + '.json'))
        r.require(binding['release_sha256'] == reference and prior['release_sha256'] == previous and
                  all(binding[key] == prior[key] for key in ('base_platform_sha256', 'site_config_sha256')) and
                  binding['plan_sha256'] == target['plan_sha256'] and
                  target['components']['maintenance-agent']['platform_sha256'] == binding['platform_sha256'],
                  'prospective observation differs from the protected portable pair')
        r.digest(binding['platform_sha256'])
        return binding

    def binding(self, reference, previous, operation, requested_at, *, recovery=None):
        from destination_observation import validate_candidate

        binding = self.selection(reference, previous, operation)
        identity = self.host.destination_identity()
        observed = r.read_json(self.control / 'platform-observations' / (reference + '.json'))
        if recovery is None:
            r.require(all(observed.get(key) == value for key, value in binding.items()) and
                      observed['boot_id'] == identity['boot_id'], 'candidate needs installed observation on the current boot')
            _, state = self.controller.transition()
            r.require(self.controller.live_release() == previous == r.read_json(self.control / 'site-current.json') and
                      (state is None or state['phase'] in r.TERMINAL) and
                      not os.path.lexists(self.controller.root / 'renewal-fence/frozen'),
                      'the candidate predecessor is no longer settled')
            guard = self.host.verify_workload_access()
        else:
            request = recovery[1]['request']
            r.require((reference, previous, operation) == tuple(request[key] for key in
                      ('target_sha256', 'previous_sha256', 'operation')),
                      'recovery observation differs from the exact forward-only attempt')
            guard = self.host.verify_final_guard()
        self.host.verify_final_ssh()
        live, dns = self.host.tailscale_state()
        tailnet, node = self.host.identity_fields(live)
        keys_sha = self.host.access_keys_digest()
        r.require(all(guard['target'][key] == val for key, val in
                      (('dns_name', dns), ('tailnet', tailnet), ('node_id', node))) and
                  guard['core_keys_sha256'] == keys_sha, 'the current private route differs from its admitted ingress')
        candidate = {'previous_release_sha256': previous, 'platform_sha256': binding['platform_sha256'],
                     'operation': operation, 'guard_sha256': guard['guard_sha256'], 'requested_at': requested_at,
                     'acl_sha256': guard['acl_sha256'],
                     'host_artifact_sha256': self.controller.release(reference)['components']['host']['artifact_sha256']}
        validate_candidate(candidate, kind=self.kind)
        return {'version': 1, 'kind': self.kind, 'job_id': 'host-access',
                'source_sha': guard['target']['source_sha'], **identity, 'dns_name': dns,
                'tailnet': tailnet, 'node_id': node, 'tailnet_addresses': self.host.access_addresses(live),
                'keys_sha256': keys_sha, 'role_artifacts': role_artifacts(self.controller, reference),
                'candidate': candidate}

    def request(self, reference=None):
        recovery = self.recovery_context()
        path = self.pending if recovery is None else recovery[0] / 'stable-recovery-request.json'
        saved = r.read_json(path)
        expected = saved['role_artifacts']['release_sha256']
        r.require(reference is None or reference == expected, 'request does not select the pending candidate')
        scope = saved['candidate']
        measured = self.binding(expected, scope['previous_release_sha256'], scope['operation'], scope['requested_at'],
                                recovery=recovery)
        within_window = 0 <= time.time() - scope['requested_at'] < 3600
        if recovery is not None and not within_window:
            proof_path = self.recovery_proof_path(recovery)
            within_window = os.path.lexists(proof_path) and r.read_json(proof_path)['accepted_at'] is not None
        r.require(saved == measured and within_window,
                  'candidate observation request expired or its exact selection changed')
        return saved

    def prepare(self, offer, reference):
        previous, operation = offer['previous_release_sha256'], offer['operation']
        if os.path.lexists(self.pending):
            saved = r.read_json(self.pending)
            requested = saved['candidate']['requested_at']
        else:
            saved, requested = None, 0
        now = int(time.time())
        stamp = requested if 0 <= now - requested < 3600 else now
        binding = self.binding(reference, previous, operation, stamp)
        if binding != saved:
            binding['candidate']['requested_at'] = now
            r.replace_json(self.pending, binding)
        return binding

    def recovery_context(self):
        """Permit fresh observations only after this exact stable effect was committed."""
        if self.scope != 'stable':
            return None
        from stable_renewal import forward_started, frozen_request

        attempt, state = self.controller.transition()
        if state is None or state['request']['scope'] != 'stable' or state['phase'] not in ('applying', 'verifying', 'accepted'):
            return None
        request = state['request']
        if not forward_started(self.controller, request):
            return None
        reference = request['target_sha256']
        original = r.read_json(self.proof_path(reference))
        p.fields(original, 'envelope accepted_at')
        r.require(type(original['accepted_at']) is int, 'stable recovery needs the independently admitted original access proof')
        original_data, _ = self.verify(original['envelope'], reference, self.host.verify_final_guard(),
                                       checked_at=original['accepted_at'], historical=True)
        now_boot = self.host.destination_identity()['boot_id']
        if original_data['boot_id'] == now_boot:
            return None
        reference_scope = original_data['candidate']
        r.require((reference_scope['previous_release_sha256'], reference_scope['operation']) ==
                  (request['previous_sha256'], request['operation']),
                  'original independent access proof belongs to another stable attempt')
        frozen_request(self.controller, attempt, state, original_data['boot_id'], now_boot)
        return attempt, state, original_data

    def recovery_proof_path(self, recovery):
        from destination_observation import canonical_uuid

        boot = self.host.destination_identity()['boot_id']
        r.require(canonical_uuid(boot), 'the stable recovery boot identity is invalid')
        return recovery[0] / ('stable-recovery-access-' + boot + '.json')

    def recover_request(self):
        """Create or reuse the distinct boot-bound request handed to the independent station."""
        recovery = self.recovery_context()
        if recovery is None:
            return None
        attempt, state, _ = recovery
        request = state['request']
        path = attempt / 'stable-recovery-request.json'
        saved = r.read_json(path) if os.path.lexists(path) else None
        now = int(time.time())
        identity = self.host.destination_identity()
        stamp = saved['candidate']['requested_at'] if saved and saved['boot_id'] == identity['boot_id'] else now
        proof_path = self.recovery_proof_path(recovery)
        proof = r.read_json(proof_path) if os.path.lexists(proof_path) else None
        if not 0 <= now - stamp < 3600 and not (proof and proof['accepted_at'] is not None):
            stamp = now
        binding = self.binding(request['target_sha256'], request['previous_sha256'], request['operation'], stamp,
                               recovery=recovery)
        if binding != saved:
            r.require(proof is None or proof['accepted_at'] is None, 'the admitted stable recovery request changed')
            r.replace_json(path, binding)
        return binding

    def proof_path(self, reference):
        r.digest(reference)
        suffix = '.stable-access.json' if self.scope == 'stable' else '.access.json'
        return self.control / 'platform-observations' / (reference + suffix)

    def verify(self, envelope, reference, guard, *, expected=None, checked_at=None, historical=False):
        from bootstrap import TRUST_SIGNERS, checked_file
        from destination_observation import (ACCESS, CORE_BINDING, FINAL_NAMESPACE,
                                             checked_candidate_readings, encoding, read_access_envelope,
                                             stable_approval, stable_host_trust, validate_candidate,
                                             verify_agent_observer, verify_bytes)

        payload, signature = read_access_envelope(io.BytesIO(envelope.encode('ascii')))
        signers = checked_file(self.host.path(TRUST_SIGNERS))
        data, proof_sha = verify_bytes(payload, signature, 'dev-pair-access-review', signers, FINAL_NAMESPACE)
        r.require(type(data) is dict, 'signed candidate observation must contain a protected JSON object')
        observed = data.get('observation')
        attended = observed == 'named-stable-challenges'
        r.require((self.scope == 'agent' and not attended) or
                  (self.scope == 'stable' and (attended or historical and observed is None)),
                  'stable maintenance requires distinct attended independent authorization')
        automatic = observed in ('named-candidate-challenges', 'named-stable-challenges')
        p.fields(data, 'version kind machine_id boot_id dns_name source_sha tailnet_addresses role_artifacts candidate '
                 'issued_at expires_at probes provider_recovery public_addresses ' + ' '.join(sorted(ACCESS)) +
                 (' observation collector_signature policy_measurement' if automatic else '') +
                 (' stable_approval' if attended else ''))
        p.number(data['version'], 1, 1)
        scope = data['candidate']
        validate_candidate(scope, kind=self.kind)
        binding = self.selection(reference, scope['previous_release_sha256'], scope['operation'])
        identity = self.host.destination_identity()
        live, dns = self.host.tailscale_state()
        tailnet, node = self.host.identity_fields(live)
        r.require(data['kind'] == self.kind and data['machine_id'] == identity['machine_id'] and
                  data['source_sha'] == guard['target']['source_sha'] and data['dns_name'] == dns and
                  (data['tailnet'], data['node_id']) == (tailnet, node) and
                  data['tailnet_addresses'] == self.host.access_addresses(live) and
                  data['keys_sha256'] == self.host.access_keys_digest() and
                  all(data[key] == guard[key] for key in ('provider_recovery', 'public_addresses', 'acl_sha256')) and
                  data['execution_route'] == 'tailnet-core' and scope['guard_sha256'] == guard['guard_sha256'] and
                  scope['acl_sha256'] == guard['acl_sha256'] and scope['host_artifact_sha256'] ==
                  self.controller.release(reference)['components']['host']['artifact_sha256'] and
                  scope['platform_sha256'] == binding['platform_sha256'] and
                  data['role_artifacts'] == role_artifacts(self.controller, reference),
                  'signed prospective observation differs from the live site or exact candidate')
        if expected is not None:
            r.require(all(data[key] == value for key, value in expected.items() if key != 'job_id') and
                      data['boot_id'] == identity['boot_id'], 'signed candidate observation belongs to a different request or boot')
        now = int(time.time()) if checked_at is None else checked_at
        r.require(type(now) is int and type(data['issued_at']) is int and type(data['expires_at']) is int and
                  scope['requested_at'] <= data['issued_at'] <= now < data['expires_at'] <= data['issued_at'] + 1800,
                  'signed candidate observation is outside its verified acceptance window')
        if automatic:
            r.require(data['keys_sha256'] == guard['core_keys_sha256'] and
                      all(data[key] == guard['target'][key] for key in ('tailnet', 'node_id', 'dns_name')) and
                      data['issued_at'] - scope['requested_at'] < 3600,
                      'automatic candidate reviews require the original admitted route controls')
            checked_candidate_readings(data, data['probes'], data['issued_at'])
            request = {key: data[key] for key in (CORE_BINDING | {'role_artifacts', 'candidate'}) - {'job_id'}}
            request['job_id'] = 'host-access'
            request_sha = r.sha(encoding(request))
            if attended:
                stable_approval(base64.b64decode(data['stable_approval'], validate=True), request,
                                stable_host_trust(self.host), data['issued_at'])
            policy = data['policy_measurement']
            p.fields(policy, 'method sha256 request_sha256 boot_id observed_at')
            r.require(policy['method'] == 'tailscale-policy-api-v2' and policy['sha256'] == guard['acl_sha256'] and
                      (policy['request_sha256'], policy['boot_id']) == (request_sha, data['boot_id']) and
                      type(policy['observed_at']) is int and
                      max(row['observed_at'] for row in data['probes']) <= policy['observed_at'] == data['issued_at'],
                      'independent Tailscale policy measurement is stale or for a different candidate')
            collection = {'request_sha256': request_sha, 'readings': data['probes']}
            collector_signature = base64.b64decode(data['collector_signature'], validate=True)
            measured, _ = verify_agent_observer(encoding(collection), collector_signature, self.host)
            r.require(measured == collection, 'independent collector signature differs from final candidate observations')
        else:
            plan = self.host.access_probe_plan(dns, data['provider_recovery'], data['public_addresses'])
            self.host.verify_access_probes(data, plan)
        r.require(all(row['observed_at'] >= scope['requested_at'] for row in data['probes']),
                  'candidate observations predate the exact protected request')
        return data, proof_sha

    def receive(self, envelope, expected):
        reference = expected['role_artifacts']['release_sha256']
        r.require(self.request(reference) == expected, 'candidate request changed during independent transport')
        wire = envelope.decode('ascii')
        self.verify(wire, reference, self.host.verify_final_guard(), expected=expected)
        recovery = self.recovery_context()
        path = self.proof_path(reference) if recovery is None else self.recovery_proof_path(recovery)
        prior = r.read_json(path) if os.path.lexists(path) else None
        if recovery is not None and prior is None:
            r.require(sum(1 for _ in recovery[0].glob('stable-recovery-access-*.json')) < r.MAX_ATTEMPTS,
                      'the bounded stable recovery proof inventory is full')
        r.require(prior is None or prior['accepted_at'] is None or prior['envelope'] == wire,
                  'a new observation cannot replace admitted rollback evidence')
        if prior is None or prior['envelope'] != wire:
            r.replace_json(path, {'envelope': wire, 'accepted_at': None})

    def fresh(self, reference, previous, operation, *, expected=None, guard=None, checked_at=None):
        recovery = self.recovery_context()
        path = self.proof_path(reference) if recovery is None else self.recovery_proof_path(recovery)
        proof = r.read_json(path)
        p.fields(proof, 'envelope accepted_at')
        if recovery is not None:
            r.require(recovery[1]['request']['target_sha256'] == reference,
                      'stable recovery proof is for a different protected target')
            if proof['accepted_at'] is not None:
                checked_at = proof['accepted_at']
        data, _ = self.verify(proof['envelope'], reference, guard or self.host.verify_final_guard(),
                              expected=expected, checked_at=checked_at,
                              historical=self.scope == 'stable' and proof['accepted_at'] is not None)
        r.require(data['boot_id'] == self.host.destination_identity()['boot_id'] and
                  (data['candidate']['previous_release_sha256'], data['candidate']['operation']) == (previous, operation),
                  'signed candidate observation does not authorize this renewal attempt on this boot')
        return proof

    def accept(self, reference, operation):
        from bootstrap import SIGNER_TRUST_LOCK

        attempt, state = self.controller.transition()
        r.require(state is not None and state['phase'] == 'applying' and state['request']['scope'] == self.scope and
                  state['request']['target_sha256'] == reference and state['request']['operation'] == operation and
                  r.read_json(self.controller.root / 'renewal-fence/frozen') == attempt.name,
                  'candidate admission requires the exact fenced activation')
        previous = state['request']['previous_sha256']
        guard = self.host.verify_final_guard()
        self.host.verify_final_ssh()
        now = int(time.time())
        with self.host.lock(SIGNER_TRUST_LOCK):
            original = self.proof_path(reference)
            approved = r.read_json(original) if self.scope == 'stable' else None
            recovery = self.recovery_context()
            path = original if recovery is None else self.recovery_proof_path(recovery)
            stamp = approved['accepted_at'] if approved and approved['accepted_at'] is not None else now
            actual = {self.controller.live_release(), r.read_json(self.control / 'site-current.json')}
            allowed = {previous, reference} if approved and approved['accepted_at'] is not None else {previous}
            r.require(actual <= allowed, 'candidate activation changed its retained predecessor')
            proof = self.fresh(reference, previous, operation, guard=guard,
                               checked_at=stamp if recovery is None else None)
            if proof['accepted_at'] is None:
                r.replace_json(path, {**proof, 'accepted_at': now})

    def admitted(self, reference, guard):
        path = self.proof_path(reference)
        if not os.path.lexists(path):
            return None
        proof = r.read_json(path)
        p.fields(proof, 'envelope accepted_at')
        if proof['accepted_at'] is None:
            return None
        data, proof_sha = self.verify(proof['envelope'], reference, guard, checked_at=proof['accepted_at'],
                                      historical=self.scope == 'stable')
        return {'role_artifacts': data['role_artifacts'], 'access_receipt_sha256': proof_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scope', choices=('initial',))
    args = parser.parse_args()
    r.require(os.getuid() == os.geteuid() == 0, 'protected site resolver required')
    controller = r.Renewal(ROOT, None)
    with controller.lock():
        offer = r.read_json(controller.control / 'offers' / (args.scope + '.json'))
        offer_record(offer, args.scope)
        print(r.canonical(Resolver(controller).resolve(offer)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
