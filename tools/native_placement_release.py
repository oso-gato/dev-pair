"""Install the verified nested placement from a protected, already acquired release."""

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

import native_placements as n

db = n.db
RELEASES = Path('/var/lib/dev-pair/platform-releases')
SITE_CONFIGS = Path('/etc/dev-pair/renewal/site-configs')
RENEWAL = Path('/var/lib/dev-pair/renewal')
RELEASE_TIMEOUT = 280
OUTER_BYTES = 4 * db.GIB
STAGE_HEADROOM = 64 * 1024 ** 2
MAX_JOBS = 32
MAX_RETAINED_MANIFESTS = 3
INNER_FILES = ('usr/lib/dev-pair/gptbox/inputs.json', 'usr/lib/dev-pair/gptbox/sealed.json',
               'usr/lib/dev-pair/gptbox/packages.txt')
INNER_LIMITS = dict(zip(INNER_FILES, (16384, 16384, 128 * 1024)))
INNER_KEYS = ('source_sha', 'context_sha256', 'image_id', 'inputs_sha256', 'sealed_sha256',
              'archive_sha256', 'archive_bytes', 'diff_ids')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(producer, path, expected=None, *, mode=None):
    raw = producer.protected_bytes(path, db.MANIFEST_LIMIT, mode)
    n.require(expected is None or digest(raw) == expected, 'protected metadata digest changed')
    value = db.json_data(raw)
    n.require(type(value) is dict and raw == n.json_bytes(value), 'protected release metadata is not canonical')
    return value


def read_index(producer, platform_sha):
    from platform_release_protocol import portable_index

    root = RELEASES / db.hex_id(platform_sha)
    index = metadata(producer, root / 'platform.json', platform_sha)
    portable_index(index, index['source_sha'], index['publisher_run'])
    receipt = metadata(producer, root / 'intake.json')
    n.require(receipt == {'schema': 2, 'platform_sha256': platform_sha, 'source_sha': index['source_sha'],
                          'publisher_run': index['publisher_run'], 'kind': index['kind']},
              'release lacks the exact protected intake receipt')
    return root, index


def read_part(producer, root, index, role):
    from platform_release import portable_image, publication_evidence
    from platform_release_protocol import COMPONENT, image_record

    transfer = index['transports'][role]['files']['part.json']
    path = root / role / 'part.json'
    part = metadata(producer, path, transfer['sha256'])
    n.require(path.stat().st_size == transfer['bytes'], 'release part metadata length changed')
    db.fields(part, 'schema image oci_manifest_sha256 producer', 'platform image part')
    image = image_record(part['image'])
    n.require(type(part['schema']) is int and part['schema'] == 1 and image['role'] == role,
              'release part role or schema differs')
    publication_evidence(image, part['producer'])
    component = index['components'][COMPONENT[role]]
    n.require(portable_image(part, component if role != 'devbox' else None) == component,
              'protected image part differs from the portable release')
    return part


def stage_source(producer, base_root, base_index):
    host = metadata(producer, base_root / 'host/host-manifest.json',
                    base_index['components']['host']['bundle_manifest_sha256'])
    db.fields(host, 'schema source_revision state_contract files', 'protected base host manifest')
    n.require(type(host['schema']) is type(host['state_contract']) is int
              and host['schema'] == host['state_contract'] == 1
              and host['source_revision'] == base_index['source_sha'], 'base host code binding differs')
    files = host['files']
    required = ('tools/native_placements.py', 'tools/native_placement_release.py', 'tools/platform_release.py',
                'tools/platform_release_protocol.py', 'tools/platform_release_install.py', 'tools/bootstrap.py',
                'tools/gptbox.py', 'tools/fedora_oci.py', 'tools/native_io.py', 'tools/storage.py', *n.ENTRY_FILES)
    staged = {}
    for name in required:
        raw = producer.protected_bytes(n.SOURCE / name, 4 * 1024 ** 2)
        n.require(digest(raw) == files[name], 'executing host placement code differs from the enrolled base')
        if name in n.ENTRY_FILES:
            staged[name] = raw
    return staged


@dataclass(frozen=True)
class Candidate:
    identity: str
    base: str
    site: str
    source: str
    job: str
    previous: str | None
    root: Path
    boot: str
    outer: dict
    outer_path: Path
    inner: dict
    inner_path: Path
    inner_manifest: str
    inner_record_sha: str
    tooling: dict
    entry: dict
    geometry: dict


def candidate(producer, identity, job):
    from platform_release_install import machine, site_configuration

    root, index = read_index(producer, identity)
    supplied = metadata(producer, root / 'development-placement.json', mode=0o600)
    db.fields(supplied, 'schema platform_sha256 base_platform_sha256 site_config_sha256 source_sha outer inner '
              'inner_oci_manifest_sha256', 'development placement handoff')
    base = index['base_platform_sha256'] or identity
    base_root, base_index = (root, index) if base == identity else read_index(producer, base)
    n.require(base_index['kind'] == 'dev-pair-platform-release', 'development requires a complete stable DevBox base')
    outer_part = read_part(producer, base_root, base_index, 'devbox')
    inner_part = read_part(producer, root, index, 'development')
    outer_image = outer_part['image']
    inner = inner_part['producer']
    db.fields(inner, ' '.join(INNER_KEYS), 'protected development producer record')
    outer = {'source_sha': outer_image['source_sha'], 'oci_config_sha256': outer_image['image_id'],
             'oci_manifest_sha256': outer_part['oci_manifest_sha256']}
    site = db.hex_id(supplied['site_config_sha256'])
    n.require(type(supplied['schema']) is int and supplied == {'schema': 1, 'platform_sha256': identity,
              'base_platform_sha256': base, 'site_config_sha256': site, 'source_sha': index['source_sha'],
              'outer': outer, 'inner': inner, 'inner_oci_manifest_sha256': inner_part['oci_manifest_sha256']},
              'development-placement handoff differs from independently pinned release subjects')
    settings = site_configuration(SITE_CONFIGS / (site + '.json'), site)
    jobs = settings['jobs']
    n.require(settings['hostname'] == os.uname().nodename and type(jobs) is dict
              and 0 < len(jobs) <= MAX_JOBS and job in jobs,
              'selected job is outside the protected site inventory')
    outer_path = producer.protected(base_root / 'devbox/devbox.oci.tar')
    inner_path = producer.protected(root / 'development/development.oci.tar')
    previous = index['previous_platform_sha256']
    boot = machine(settings, time.monotonic() + 30)
    return Candidate(identity, base, site, index['source_sha'], job, previous, root, boot,
                     outer_part, outer_path, inner, inner_path, inner_part['oci_manifest_sha256'],
                     digest(n.image_inputs_bytes(inner)), index['components']['development-agent'],
                     stage_source(producer, base_root, base_index), jobs[job])


def rootfs_evidence(archive, blobs, layers, end):
    """Read only the effective protected release files, without extraction or an engine."""
    ancestors = set()
    for target in INNER_FILES:
        ancestors.update(str(parent) for parent in PurePosixPath(target).parents if str(parent) != '.')
    watched = set(INNER_FILES) | ancestors
    resolved = {}
    count = 0

    def under(name, parent):
        return not parent or name == parent or name.startswith(parent + '/')

    for layer in layers:
        changes = {}
        removed = set()
        with archive.extractfile(blobs['blobs/sha256/' + layer['digest'].removeprefix('sha256:')]) as stream, \
                tarfile.open(fileobj=stream, mode='r|*') as tree:
            for item in tree:
                count += 1
                n.require(count <= 1000000 and time.monotonic() < end, 'inner seal layer inventory exceeded its bound')
                name = item.name.removeprefix('./').rstrip('/')
                if name in ('', '.'):
                    continue
                path = PurePosixPath(name)
                n.require(not path.is_absolute() and str(path) == name and '..' not in path.parts,
                          'unsafe path in verified image layer')
                parent = '' if str(path.parent) == '.' else str(path.parent)
                if path.name.startswith('.wh.'):
                    hidden = parent if path.name == '.wh..wh..opq' else (parent + '/' + path.name[4:]).lstrip('/')
                    if any(under(target, hidden) for target in watched):
                        n.require(item.isreg() and item.size == 0, 'unknown whiteout in protected inner path')
                        removed.add((hidden, path.name == '.wh..wh..opq'))
                    continue
                if name not in watched:
                    continue
                n.require(name not in changes, 'duplicate protected member in image layer')
                if name in ancestors:
                    changes[name] = item.isdir()
                    continue
                maximum = INNER_LIMITS[name]
                n.require(item.isreg() and item.uid == item.gid == 0 and item.mode == 0o444
                          and 0 < item.size <= maximum, 'immutable development seal member is invalid')
                with tree.extractfile(item) as data:
                    raw = data.read(maximum + 1)
                n.require(len(raw) == item.size, 'immutable development seal member is truncated')
                changes[name] = raw
        n.require(not any(value is False and any(name != parent and under(name, parent) for name in changes)
                          for parent, value in changes.items()), 'conflicting protected ancestor in image layer')
        for name in list(resolved):
            if any(under(name, hidden) and (not opaque or name != hidden) for hidden, opaque in removed):
                del resolved[name]
            elif any(value is False and name != parent and under(name, parent) for parent, value in changes.items()):
                del resolved[name]
        resolved.update(changes)
    n.require(all(resolved.get(name) is True for name in ancestors)
              and all(type(resolved.get(name)) is bytes for name in INNER_FILES),
              'verified image does not contain the effective immutable development seal')
    return tuple(resolved[name] for name in INNER_FILES)


def verify_inner(item, end):
    import platform_release

    image = {'role': 'development', **{key: value for key, value in item.inner.items()
                                      if key not in ('inputs_sha256', 'sealed_sha256')}}
    n.require(platform_release.image_archive(item.inner_path, image, end, item.tooling) == item.inner_manifest,
              'verified development OCI manifest changed')
    with tarfile.open(item.inner_path, 'r:') as archive:
        blobs = {db.archive_path(row.name): row for row in archive if row.isreg()}
        manifest_path = 'blobs/sha256/' + item.inner_manifest
        with archive.extractfile(blobs[manifest_path]) as data:
            layers = db.json_data(data.read(db.OCI_METADATA_LIMIT + 1))['layers']
        with archive.extractfile(blobs['blobs/sha256/' + item.inner['image_id']]) as data:
            labels = db.json_data(data.read(db.OCI_METADATA_LIMIT + 1))['config']['Labels']
        inputs, sealed, packages = rootfs_evidence(archive, blobs, layers, end)
    n.require(digest(inputs) == item.inner['inputs_sha256'] == labels.get('dev-pair.inputs')
              and digest(sealed) == item.inner['sealed_sha256'], 'immutable development input or seal digest differs')
    evidence = db.json_data(sealed)
    db.fields(evidence, 'kind inputs_sha256 source_sha uid gid packages_sha256', 'immutable development seal')
    n.require(evidence == {'kind': 'genuine-distrobox-assembled', 'inputs_sha256': digest(inputs),
                           'source_sha': item.source, 'uid': 1000, 'gid': 1000, 'packages_sha256': digest(packages)},
              'immutable development seal does not bind its source and package inventory')
    inputs = db.json_data(inputs)
    n.require(inputs['role'] == 'development' and inputs['source_sha'] == item.source
              and inputs['context_sha256'] == item.inner['context_sha256'] and inputs['distrobox_sha'] == db.DISTROBOX
              and inputs['files']['/opt/dev-pair/bin/codex'] == item.tooling['codex_sha256'],
              'immutable development inputs do not bind protected role and tooling')


def previous_installed(producer, item):
    if item.previous is None:
        return None
    root, previous = read_index(producer, item.previous)
    value = metadata(producer, root / 'installed.json', mode=0o600)
    db.fields(value, 'schema platform_sha256 base_platform_sha256 site_config_sha256 boot_id source_sha components',
              'previous native installation')
    n.require(type(value['schema']) is int and value['schema'] == 1
              and value['platform_sha256'] == item.previous and value['source_sha'] == previous['source_sha']
              and value['base_platform_sha256'] == (previous['base_platform_sha256'] or item.previous)
              and value['site_config_sha256'] == item.site
              and re.fullmatch(r'[0-9a-f-]{36}', value['boot_id']),
              'previous installation does not bind compatible site, source and platform')
    db.fields(value['components'], 'host maintenance devbox development', 'previous installed components')
    inner = value['components']['development']
    db.fields(inner, 'context_sha256 oci_config_sha256 oci_manifest_sha256 inner_sha256 jobs',
              'previous installed development component')
    selected = previous['components']['development-agent']
    previous_part = read_part(producer, root, previous, 'development')
    n.require(all(selected[key] == inner[key] for key in ('context_sha256', 'oci_config_sha256', 'oci_manifest_sha256')),
              'previous installed development component differs from the trusted subject')
    n.require(inner['inner_sha256'] == digest(n.image_inputs_bytes(previous_part['producer'])),
              'previous installed seal differs from its exact protected producer record')
    job = inner['jobs'][item.job]
    db.fields(job, 'manifest_sha256', 'previous installed job placement')
    db.hex_id(job['manifest_sha256'])
    outer = value['components']['devbox']
    db.fields(outer, 'oci_config_sha256 oci_manifest_sha256', 'previous installed outer component')
    for key in outer:
        db.hex_id(outer[key])
    if previous['kind'] == 'dev-pair-agent-release':
        _, base = read_index(producer, value['base_platform_sha256'])
    else:
        base = previous
    component = base['components']['devbox']
    n.require(all(component[key] == outer[key] for key in outer), 'previous installed outer differs from its stable base')
    if item.base != item.identity:
        n.require(item.base == value['base_platform_sha256']
                  and item.outer['image']['image_id'] == outer['oci_config_sha256']
                  and item.outer['image']['source_sha'] == component['source_sha']
                  and item.outer['oci_manifest_sha256'] == outer['oci_manifest_sha256'],
                  'agent-only refresh changes its stable outer')
    return value


def current_selection(producer, item):
    def read(path):
        return db.json_data(producer.protected_bytes(path, db.MANIFEST_LIMIT))

    current = RENEWAL / 'current.json'
    active = RENEWAL / 'site-current.json'
    if not n.present(current) and not n.present(active):
        n.require(item.previous is None, 'declared previous platform is not selected on this host')
        return None
    reference = db.hex_id(read(current))
    n.require(read(active) == reference, 'host and site release selectors disagree')
    binding = read(RENEWAL / 'platform-bindings' / (reference + '.json'))
    db.fields(binding, 'schema release_sha256 platform_sha256 base_platform_sha256 site_config_sha256 '
              'plan_sha256 intake_sha256', 'selected portable platform binding')
    n.require(type(binding['schema']) is int and binding['schema'] == 1
              and binding['release_sha256'] == reference and binding['site_config_sha256'] == item.site
              and binding['platform_sha256'] in (item.previous, item.identity),
              'currently selected platform is outside the approved install or restore lineage')
    for key in ('platform_sha256', 'base_platform_sha256', 'plan_sha256', 'intake_sha256'):
        db.hex_id(binding[key])
    if binding['platform_sha256'] == item.identity or item.base != item.identity:
        n.require(binding['base_platform_sha256'] == item.base, 'selected stable base differs')
    return reference


def admitted_checklist_mounts(producer, rows):
    fixed = (Path('/var/lib/dev-pair/checklist-validation'), Path('/var/lib/dev-pair/checklist-live'))
    selected = {name: path for name, path in zip(('validation', 'live'), fixed) if n.by_target(rows, path)}
    if not selected:
        return set()
    from destination_release import Destination

    receipt = db.json_data(producer.protected_bytes(Path('/var/lib/dev-pair/checklist-release/provision.json'),
                                                   db.MANIFEST_LIMIT, 0o600))
    destination = Destination()
    for name, path in selected.items():
        spec = receipt['mounts'][name]
        backing = Path('/var/lib/dev-pair/checklist-storage') / (name + '.img')
        n.require(spec['image'] == str(backing)
                  and backing.stat().st_dev == devbox_root().stat().st_dev,
                  'checklist data mount is not backed by the enrolled managed filesystem')
        destination.mount_observation(str(path), spec)
    return set(selected.values())


def devbox_root():
    return n.devbox.ROOT.parent


class ReleasePlacement(n.Placement):
    """Separate released storage ledger; reuse the native kernel/role primitives."""

    def __init__(self, producer, account, item, previous):
        self.producer, self.account, self.item, self.previous = producer, account, item, previous
        self.job, self.entry_files = item.job, item.entry
        self.boot, self.stage = n.current_boot(), 'release storage admission'
        n.require(self.boot == item.boot, 'verified site boot changed before placement preparation')
        root = n.ROOT / 'release'
        self.record = root / 'records' / 'placement.json'
        self.backings = root / 'backings'
        self.scratch_path = root / 'scratch'
        self.outer_path = Path(account.pw_dir) / '.local/share/containers/storage'
        self.build_path = n.devbox.ROOT / 'builds' / self.job
        self.inputs_path = self.build_path / 'inputs'
        self.recipes = root / 'recipes' / item.base
        self.entry = self.recipes / 'entry'
        n.protected_directories(producer, n.ROOT, root, root / 'recipes', self.recipes)
        n.protected_directories(producer, self.record.parent, mode=0o700)
        n.protected_directories(producer, self.backings, n.ROOT / 'backings',
                                n.ROOT / 'backings' / self.job, mode=0o711)
        if n.present(self.record):
            self.state = metadata(producer, self.record, mode=0o600)
            db.fields(self.state, 'schema owner activity volumes jobs outer_copy legacy last_failure',
                      'released placement lease')
            n.require(type(self.state['schema']) is int and self.state['schema'] == 1,
                      'unknown released placement lease schema')
            db.hex_id(self.state['owner'])
        else:
            self.state = {'schema': 1, 'owner': os.urandom(32).hex(), 'activity': None,
                          'volumes': {}, 'jobs': {}, 'outer_copy': None, 'legacy': None, 'last_failure': None}
            self.state['legacy'] = self.legacy_record()
            self.save()
        legacy = self.state['legacy']
        store_lease = self
        if legacy is not None:
            legacy_job = job_token(legacy)
            n.require(legacy_job != self.job, 'released job identity conflicts with the ordinary probe leaf')
            record = n.ROOT / 'records' / legacy_job / 'placement.json'
            ordinary = self.read_record(record)
            n.require(ordinary['request']['job'] == legacy and ordinary['activity'] is None
                      and ordinary['verification'] is None
                      and all(ordinary['volumes'][key]['prepared'] for key in ('outer', 'scratch')),
                      'ordinary probe storage owner is unresolved')
            self.scratch_path = n.ROOT / 'scratch' / legacy
            store_lease = SimpleNamespace(producer=producer, account=account, record=record,
                                          backings=n.ROOT / 'backings' / legacy, state=ordinary,
                                          save=lambda: n.write_atomic(record, n.json_bytes(ordinary)))
        self.store_lease = store_lease
        self.copy_path = self.scratch_path / 'image-copy'
        self.outer_volume = n.Volume(store_lease, 'outer', self.outer_path,
                                     OUTER_BYTES if legacy is None else store_lease.state['request']['outer_bytes'])
        self.scratch_volume = n.Volume(store_lease, 'scratch', self.scratch_path, n.SCRATCH_BYTES)
        self.select_job()
        self.build_volume = self.job_volume(self.job)
        self.outer_label = db.file_label(self.job_state, 'outer')
        self.inner_label = db.file_label(self.job_state, 'inner')

    def legacy_record(self):
        parent = n.ROOT / 'records'
        if not n.present(parent):
            return None
        self.producer.protected(parent)
        entries = list(parent.iterdir())
        n.require(len(entries) <= 1 and (not entries or entries[0].is_dir()),
                  'ordinary probe has ambiguous persistent ownership')
        return job_token(entries[0].name) if entries else None

    def select_job(self):
        jobs = self.state['jobs']
        n.require(type(jobs) is dict and len(jobs) <= MAX_JOBS, 'released storage job inventory exceeded')
        if self.job in jobs:
            self.job_state = jobs[self.job]
            n.require(self.item.geometry == {name: self.job_state[name] for name in ('storage_bytes', 'categories')},
                      'released job has different owned storage geometry or labels')
            return
        n.require(len(jobs) < MAX_JOBS and not any(n.present(n.devbox.ROOT / root / self.job)
                   for root in ('builds', 'evidence', *db.JOB_TARGETS)),
                   'released job would cover an unowned data leaf')
        n.require(self.previous is None, 'previous installed job is missing its persistent storage lease')
        occupied = n.used_categories()
        if self.state['legacy'] is not None:
            occupied.update(self.store_lease.state['categories']['outer'])
        for record in jobs.values():
            occupied.update(record['categories']['outer'])
        n.require(not occupied.intersection(self.item.geometry['categories']['outer']),
                  'approved job categories overlap a live or retained placement')
        self.job_state = {**self.item.geometry, 'volumes': {}, 'leaves': {}, 'manifests': {}, 'preflight': None}
        jobs[self.job] = self.job_state
        self.save()

    def job_volume(self, job):
        job_token(job)
        lease = SimpleNamespace(producer=self.producer, account=self.account, state=self.state['jobs'][job],
                                backings=n.ROOT / 'backings' / job, record=self.record.parent / (job + '.json'),
                                save=self.save)
        volume = n.Volume(lease, 'build', n.devbox.ROOT / 'builds' / job, lease.state['storage_bytes'])
        volume.staging = self.record.parent / (job + '-build.mount')
        return volume

    def existing_volume(self, name, target):
        known = {'build': self.build_volume, 'outer': self.outer_volume, 'scratch': self.scratch_volume}[name]
        n.require(target == known.target and known.verify_existing(n.mount_rows()) == {target},
                  'released owned volume is not attached at its declared target')
        return known

    def initialize_build(self, fd):
        uid, gid = self.account.pw_uid, self.account.pw_gid
        for name in ('graph', 'image-copy', 'work'):
            with n.private_child(fd, name, uid, gid, label=self.inner_label if name == 'work' else self.outer_label):
                pass
        with n.private_child(fd, 'inputs', 0, 0, mode=0o755, label=self.outer_label) as (inputs, _):
            self.build_volume.info['inputs'] = n.volume_inode(os.fstat(inputs))
        self.root_mode(fd)

    def initialize_scratch(self, fd):
        self.default_label(fd, self.scratch_path)
        with n.private_child(fd, 'image-copy', self.account.pw_uid, self.account.pw_gid) as (copy, _):
            self.scratch_volume.info['image_copy'] = n.volume_inode(os.fstat(copy))
        os.fchmod(fd, 0o755)

    def leaves(self):
        uid, gid = self.account.pw_uid, self.account.pw_gid
        for key in db.JOB_TARGETS:
            recorded = self.job_state['leaves'].get(key)
            with n.directory_fd(n.devbox.ROOT / key) as parent:
                with n.private_child(parent, self.job, uid, gid, create=recorded is None,
                                     label=self.inner_label) as (fd, created):
                    node = n.volume_inode(os.fstat(fd))
                    n.require(created if recorded is None else node == recorded,
                              'released job leaf is foreign or exchanged')
                    if created:
                        self.job_state['leaves'][key] = node
                        self.save()
        with n.directory_fd(self.build_path) as parent:
            for key in ('graph', 'image-copy', 'work'):
                with n.private_child(parent, key, uid, gid, create=False,
                          label=self.inner_label if key == 'work' else self.outer_label) as (fd, _):
                    n.require(os.fstat(fd).st_dev == os.fstat(parent).st_dev, 'released job storage crosses a mount')

    def establish(self):
        self.reconcile(interrupted=True)
        observed = n.managed_snapshot()
        maint = pwd.getpwnam('dp-maint')
        n.require_idle_roles(self.account, maint)
        self.check_job_categories()
        n.verify_role_home(self.account, self.outer_path)
        n.verify_role_home(maint)
        uid, gid = self.account.pw_uid, self.account.pw_gid
        for parent in reversed(self.outer_path.parents[:3]):
            with n.directory_fd(parent.parent) as parent_fd:
                with n.private_child(parent_fd, parent.name, uid, gid):
                    pass
        active = (self.outer_volume, self.scratch_volume, self.build_volume)
        known = list(active) + [self.job_volume(key) for key in self.state['jobs'] if key != self.job]
        legacy = self.state['legacy']
        if legacy is not None:
            known.append(n.Volume(self.store_lease, 'build', n.devbox.ROOT / 'builds' / legacy,
                                  self.store_lease.state['request']['build_bytes']))
        rows = n.mount_rows()
        allowed = set().union(*(volume.verify_existing(rows) for volume in known))
        allowed.update(admitted_checklist_mounts(self.producer, rows))
        n.verify_enrollment(rows, allowed, (devbox_root(), Path(self.account.pw_dir), Path(maint.pw_dir)))
        for volume in active:
            if volume.info is None and n.present(volume.target):
                with n.directory_fd(volume.target) as descriptor:
                    n.require(not os.listdir(descriptor), 'foreign occupied released mount target preserved')
        n.verify_managed_classes(observed['device'], [self.item.root, self.backings, self.build_volume.backing.parent,
                               self.outer_volume.backing.parent, self.scratch_volume.backing.parent,
                               n.devbox.ROOT, *(n.devbox.ROOT / key for key in ('builds', *db.JOB_TARGETS))])
        prior_allocations = sum(volume.allocated() for volume in active)
        additional = sum(volume.capacity for volume in active) - prior_allocations
        n.reserve_managed(self.backings, max(0, additional))
        self.outer_volume.mount(self.initialize_outer)
        self.scratch_volume.mount(self.initialize_scratch)
        storage = self.build_volume.mount(self.initialize_build)
        self.leaves()
        self.stage_entry()
        self.verify_mount_access(storage)
        self.check_predecessor()
        self.cleanup_outer()
        return self.engine_store()

    def check_job_categories(self):
        n.require(not n.used_categories().intersection(self.job_state['categories']['outer']),
                  'live host container overlaps the released job category reservation')

    def verify_mount_access(self, storage):
        _, output = self.managed('/usr/bin/python3', '-I', '-B', self.entry / 'tools/placement_check.py',
                                 self.build_path, self.build_volume.backing, str(self.build_volume.capacity), seconds=25)
        n.require(output.decode('ascii').strip() == storage['device'], 'released rootless backing proof differs')

    def check_predecessor(self):
        if self.previous is None:
            return
        previous = self.previous['components']['development']
        admission = previous['jobs'][self.job]['manifest_sha256']
        record = self.job_state['manifests'].get(admission)
        n.require(record is not None and record['inner_sha256'] == previous['inner_sha256'],
                  'previous installed placement lacks its exact persistent ownership')
        with self.build_inputs() as parent:
            with n.private_child(parent, admission, 0, 0, mode=0o755, create=False, label=self.outer_label) as (fd, _):
                n.require(n.volume_inode(os.fstat(fd)) == record['directory'],
                          'previous released placement input directory was exchanged')
                root = Path(f'/proc/self/fd/{fd}')
                manifest = db.read_manifest(root / 'manifest.json', admission, time.monotonic() + 5)
                n.require(manifest['job'] == self.job and manifest['categories'] == self.job_state['categories']
                          and manifest['outer']['image_id'] == self.previous['components']['devbox']['oci_config_sha256']
                          and manifest['inner']['image_id'] == previous['oci_config_sha256']
                          and digest(n.image_inputs_bytes(manifest['inner'])) == previous['inner_sha256']
                          and db.file_hash(root / n.RELEASE_ARCHIVE, manifest['inner']['archive_bytes'],
                                           time.monotonic() + 120)[:2] ==
                          (manifest['inner']['archive_sha256'], manifest['inner']['archive_bytes']),
                          'previous exact archive or job placement changed')

    def copy_verified(self, source, expected, size, output):
        proof = n.capture_release_file(self.producer.protected(source), size, 0, output=output)
        n.require(proof[:2] == (expected, size), 'protected release bytes changed while copying')

    def cleanup_outer(self):
        pending = self.state['outer_copy']
        if pending is None:
            return
        n.require(self.state['activity'] is None and re.fullmatch(r'outer-[0-9a-f]{64}\.oci\.tar', pending),
                  'uncertain released image import preserved')
        self.validate_scratch()
        with n.directory_fd(self.scratch_path) as parent:
            for name in (pending, pending + '.new'):
                try:
                    node = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                n.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1
                          and stat.S_IMODE(node.st_mode) in (0o444, 0o600),
                          'foreign outer image scratch retained')
                os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        self.state['outer_copy'] = None
        self.save()

    def load_outer(self):
        self.check_previous_outer()
        image = self.item.outer['image']
        manifest = self.item.outer['oci_manifest_sha256']
        observed = 'sha256:' + image['image_id']
        status, _ = self.managed(*n.PODMAN, 'image', 'exists', observed, seconds=10, copy=True, allowed=(0, 1))
        if status == 1:
            self.validate_scratch()
            space = os.statvfs(self.scratch_path)
            n.require(space.f_bavail * space.f_frsize >= image['archive_bytes'] + STAGE_HEADROOM
                      and space.f_favail >= 4, 'the bounded outer copy volume has insufficient space or inodes')
            name = 'outer-' + image['image_id'] + '.oci.tar'
            with n.directory_fd(self.scratch_path) as parent:
                n.require(not n.present(self.scratch_path / name) and not n.present(self.scratch_path / (name + '.new')),
                          'foreign outer image scratch retained')
                self.state['outer_copy'] = name
                self.save()
                n.stable_file(parent, name, lambda output: self.copy_verified(self.item.outer_path,
                              image['archive_sha256'], image['archive_bytes'], output), self.outer_label)
            self.engine('load', '--input', str(self.scratch_path / name), timeout=180)
            self.cleanup_outer()
        actual = n.image_shape(self.inspect('image', observed))
        n.require(actual == {'config_id': image['image_id'], 'oci_manifest_digest': 'sha256:' + manifest,
                            'diff_ids': image['diff_ids']}, 'live outer config, manifest or layer identity differs')
        db.immutable_image(self, {'outer': {'image_id': image['image_id'],
                                           'source_sha': image['source_sha']}}, 'outer')
        self.check_previous_outer()

    def check_previous_outer(self):
        if self.previous is not None:
            prior = self.previous['components']['devbox']
            old = n.image_shape(self.inspect('image', 'sha256:' + prior['oci_config_sha256']))
            n.require(old['config_id'] == prior['oci_config_sha256']
                      and old['oci_manifest_digest'] == 'sha256:' + prior['oci_manifest_sha256'],
                      'previous outer image is unavailable for exact restore')

    def publish(self):
        image = self.item.outer['image']
        manifest = {'kind': 'dev-pair-development-nested-v1', 'standards_sha': db.STANDARDS, 'job': self.job,
                    'storage_bytes': self.build_volume.capacity, 'outer': {'source_sha': image['source_sha'],
                    'image_id': image['image_id']}, 'inner': self.item.inner, 'categories': self.job_state['categories']}
        raw = n.json_bytes(manifest)
        admission = digest(raw)
        with self.build_inputs() as parent:
            record = self.job_state['manifests'].get(admission)
            n.require(record is not None or len(self.job_state['manifests']) < MAX_RETAINED_MANIFESTS,
                      'released placement retention is full and needs scoped reconciliation')
            with n.private_child(parent, admission, 0, 0, mode=0o755, label=self.outer_label,
                                 create=record is None) as (fd, created):
                identity = n.volume_inode(os.fstat(fd))
                binding = {'directory': identity, 'inner_sha256': self.item.inner_record_sha}
                n.require(created if record is None else record == binding, 'released manifest input ownership differs')
                if created:
                    self.job_state['manifests'][admission] = binding
                    self.save()
                root = Path(f'/proc/self/fd/{fd}')
                archive = root / n.RELEASE_ARCHIVE
                if not n.present(archive):
                    space = os.fstatvfs(fd)
                    n.require(space.f_bavail * space.f_frsize >= self.item.inner['archive_bytes'] + STAGE_HEADROOM
                              and space.f_favail >= 4, 'nested placement lacks free rollback overlap capacity')
                n.stable_file(fd, n.RELEASE_ARCHIVE, lambda output: self.copy_verified(self.item.inner_path,
                              self.item.inner['archive_sha256'], self.item.inner['archive_bytes'], output),
                              self.outer_label)
                n.require(db.file_hash(archive, self.item.inner['archive_bytes'], time.monotonic() + 120)[:2] ==
                          (self.item.inner['archive_sha256'], self.item.inner['archive_bytes']),
                          'published released inner archive changed')
                n.stable_file(fd, 'manifest.json', lambda output: output.write(raw), self.outer_label)
                n.require(db.read_manifest(root / 'manifest.json', admission, time.monotonic() + 5) == manifest,
                          'released nested manifest readback differs')
        return admission

    def admission_binding(self):
        item = self.item

        def source(path, size):
            node = self.producer.protected(path).lstat()
            n.require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1
                      and node.st_size == size, 'protected OCI archive ownership or byte bound changed')
            return n.identity(node) + [node.st_size, node.st_mtime_ns, node.st_ctime_ns]

        return {'platform_sha256': item.identity, 'base_platform_sha256': item.base,
                'site_config_sha256': item.site, 'boot_id': self.boot,
                'outer': source(item.outer_path, item.outer['image']['archive_bytes']),
                'inner': source(item.inner_path, item.inner['archive_bytes'])}

    def preflight(self, binding):
        import platform_release

        if self.job_state['preflight'] == binding:
            return
        image = self.item.outer['image']
        self.stage = 'protected OCI validation and immutable seal'
        end = time.monotonic() + 240
        n.require(platform_release.image_archive(self.item.outer_path, image, end) ==
                  self.item.outer['oci_manifest_sha256'], 'the protected outer OCI graph differs from its attested subject')
        verify_inner(self.item, end)
        n.require(self.admission_binding() == binding, 'container inputs changed during release preflight')

    def install(self, phase):
        admission = None
        binding = self.admission_binding()
        if phase == 'preflight':
            self.preflight(binding)
            self.stage = 'release storage admission'
            self.establish()
            n.require(self.admission_binding() == binding and n.current_boot() == self.boot,
                      'released inputs or host boot changed during placement preflight')
            self.job_state['preflight'] = binding
            self.save()
        else:
            n.require(self.job_state['preflight'] == binding,
                      'released placement requires matching current-boot preflight evidence')
            self.establish()
            self.stage = 'protected outer image and inner archive'
            self.load_outer()
            self.stage = 'digest-addressed deployment inputs'
            admission = self.publish()
            n.require(self.admission_binding() == binding and n.current_boot() == self.boot,
                      'released inputs or host boot changed during installation')
        return {'schema': 1, 'phase': phase, 'platform_sha256': self.item.identity,
                'base_platform_sha256': self.item.base, 'site_config_sha256': self.item.site,
                'boot_id': self.boot, 'job': self.item.job,
                'outer': {'oci_config_sha256': self.item.outer['image']['image_id'],
                          'oci_manifest_sha256': self.item.outer['oci_manifest_sha256']},
                'manifest_sha256': admission}


def job_token(value):
    n.require(type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', value),
              'invalid released job leaf')
    return value


def install_cli(argv):
    parser = argparse.ArgumentParser(prog='native_placements.py install-release', description=__doc__)
    parser.add_argument('--phase', choices=('preflight', 'stage'), required=True)
    parser.add_argument('--platform-sha256', required=True)
    parser.add_argument('--job', required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, db.interrupt)
    signal.setitimer(signal.ITIMER_REAL, RELEASE_TIMEOUT)
    expected_errors = (n.BootstrapBlocked, db.Blocked, OSError, ValueError, TypeError, KeyError, IndexError,
                       subprocess.SubprocessError, tarfile.TarError, EOFError, ImportError)
    try:
        n.require(os.geteuid() == os.getuid() == 0 and platform.machine() == 'x86_64',
                  'authorized root release installer on Fedora 44 x86_64 required')
        producer = n.DevelopmentGptbox()
        # The protected site check verifies the deployed Fedora host and current
        # boot. The virgin bootstrap's listener/ingress rules do not apply here.
        item = candidate(producer, db.hex_id(args.platform_sha256), job_token(args.job))
        n.managed_snapshot()
        with producer.lock():
            n.managed_snapshot()
            account = n.role_account(producer)
            previous = previous_installed(producer, item)
            selected = current_selection(producer, item)
            placement = ReleasePlacement(producer, account, item, previous)
            try:
                result = placement.install(args.phase)
                n.require(current_selection(producer, item) == selected,
                          'the active platform changed during released placement preparation')
            except expected_errors as error:
                placement.fail(error)
                raise
        print(n.json_bytes(result).decode(), end='')
        return 0
    except expected_errors as error:
        print(f'Native release placement blocked: {str(error)[:2048]}', file=sys.stderr)
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
