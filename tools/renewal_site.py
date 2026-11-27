"""Derive the site plan from protected portable intake and installed readback."""
import argparse
import os
from pathlib import Path
import socket
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import renewal as r
from renewal import protocol as p

ROOT = r.DEFAULT_ROOT
PORTABLE = ROOT / 'platform-releases'
CONFIG = Path('/etc/dev-pair/renewal/site-configs')
HOSTS = Path('/usr/libexec/dev-pair/host-releases')
HOST_CONFIGS = Path('/etc/dev-pair/host-releases')
INDEX_NAME = 'platform.json'
FULL = 'dev-pair-platform-release'
AGENT = 'dev-pair-agent-release'


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
    p.digest(site['host_config_sha256'])
    jobs = site['jobs']
    r.require(type(jobs) is dict and 0 < len(jobs) <= r.MAX_JOBS, 'site job geometry is missing')
    reserved = set()
    for job, geometry in jobs.items():
        p.token(job)
        r.require(len(job) <= 48, 'site job is unsupported by the live role executors')
        p.fields(geometry, 'storage_bytes categories')
        p.number(geometry['storage_bytes'], 256 * 1024**2, 20 * 1024**3)
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
    r.require(value['scope'] == scope and scope in ('initial', 'agent'), 'unsupported portable site selection')
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


def build_selection(index, base, site, installed, inner, previous=None):
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
    def __init__(self, controller, portable=PORTABLE, configs=CONFIG, hosts=HOSTS, host_configs=HOST_CONFIGS):
        self.controller = controller
        self.control = controller.control
        self.root = controller.root
        self.portable = portable
        self.configs = configs
        self.hosts = hosts
        self.host_configs = host_configs

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
        return directory, value, r.sha(admission)

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
        if scope == 'initial':
            r.require(index['kind'] == FULL and index['previous_platform_sha256'] is None and
                      not os.path.lexists(self.control / 'current.json') and not os.path.lexists(self.control / 'site-current.json'),
                      'initial site selection requires a fresh full portable release')
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
            else:
                r.require(index['previous_platform_sha256'] == published['platform_sha256'], 'agent offer changes its portable predecessor')
            base_sha = index['base_platform_sha256']
            r.require(base_sha == published['base_platform_sha256'], 'agent offer changes its retained portable base')
            _, stable, _ = self.index(base_sha)
            r.require(stable['kind'] == FULL, 'retained host/DevBox portable base is incomplete')
            previous = self.controller.release(current)
        receipt = protected_bytes(directory / 'installed.json', 65536)
        installed = installed_row(r.loads(receipt), index_sha=platform, index=index, base=base_sha, site_sha=site_hash, boot=boot)
        inner_bytes = protected_bytes(directory / 'development' / 'part.json', 65536)
        inner_transport = index['transports']['development']['files']['part.json']
        r.require((r.sha(inner_bytes), len(inner_bytes)) == (inner_transport['sha256'], inner_transport['bytes']),
                  'inner producer evidence differs from the attested portable part')
        inner = r.loads(inner_bytes)['producer']
        r.require(r.sha(r.json_bytes(inner) + b'\n') == installed['development']['inner_sha256'],
                  'installed inner receipt identifies different producer evidence')
        selection, plan, manifests = build_selection(index, stable, site, installed, inner, previous)
        reference = r.identity(selection)
        if previous is not None and current != predecessor:
            r.require(reference == current, 'already selected agent package derives different local bytes')
        host = selection['components']['host']
        r.require(r.sha(protected_bytes(self.hosts / host['artifact_sha256'] / 'manifest.json', 1 << 20)) == host['artifact_sha256'],
                  'portable host manifest has not been installed')
        r.require(r.sha(protected_bytes(self.host_configs / (site['host_config_sha256'] + '.json'), 4096)) == site['host_config_sha256'],
                  'approved host configuration has not been installed')
        maint = selection['components']['maintenance-agent']
        result = self.root / 'bootstrap' / 'gptbox-adapter' / plan['maintenance_context_sha256'] / 'result.json'
        result_bytes = protected_bytes(result, 1 << 20)
        facts = r.loads(result_bytes)
        r.require(r.sha(result_bytes) == installed['maintenance']['result_sha256'] and
                  facts.get('context_sha256') == plan['maintenance_context_sha256'] and
                  facts.get('source_sha') == maint['source_revision'] and facts.get('assembled_image_id') == maint['artifact_sha256'] and
                  facts.get('runtime_container_removed') is True and facts.get('boundary_and_version_cycles') == 2 and
                  facts.get('job_admission') is False, 'maintenance has no exact installed assembly admission')
        for job, (item, manifest) in manifests.items():
            path = self.root / 'development' / 'builds' / job / 'inputs' / item
            r.require(protected_bytes(path / 'manifest.json', 65536) == manifest, 'installed local DevBox manifest bytes differ')
            archive = path / 'development.oci.tar'
            node = archive.lstat()
            r.require(archive.resolve(strict=True) == archive and stat.S_ISREG(node.st_mode) and node.st_uid == os.getuid() and
                      not node.st_mode & 0o222 and node.st_nlink == 1 and node.st_size == inner['archive_bytes'],
                      'exact local development archive is not installed')
        self.store(self.control / 'plans' / (selection['plan_sha256'] + '.json'), plan)
        self.store(self.control / 'releases' / (reference + '.json'), selection)
        binding = {'schema': 1, 'release_sha256': reference, 'platform_sha256': platform, 'base_platform_sha256': base_sha,
                   'site_config_sha256': site_hash, 'plan_sha256': selection['plan_sha256'], 'intake_sha256': intake_sha}
        self.store(self.control / 'platform-bindings' / (reference + '.json'), binding)
        # The observation can refresh on another boot. It cannot change the immutable selection binding.
        observation = {'schema': 1, **binding, 'boot_id': boot, 'installed_sha256': r.sha(receipt)}
        r.replace_json(self.control / 'platform-observations' / (reference + '.json'), observation)
        return binding


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
