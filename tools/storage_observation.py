"""Closed maintenance point-sample projection; no quota, fit or admission decision."""
import copy
import json
import re

STAGES=('prepared-image','assembled-postcleanup')
ROOT='/var/lib/dev-pair/maintenance'
OUTSIDE='artifacts-and-image-copy-workspaces-not-sampled'
SEMANTICS='st_blocks*512 per unique device/inode; shared extents/compression/open-unlinked data not inferred'
REASONS=('no-budget','bounded-runner-unavailable','collector-lifecycle-failure','collector-unavailable','invalid-collector-output')


def require(value):
    if not value:raise ValueError('invalid-storage-observation')


def integer(value):return type(value) is int and 0<=value<2**63


def identity(value,length):return type(value) is str and re.fullmatch('[0-9a-f]{%d}'%length,value) is not None


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result);result[key]=value
    return result


def sample(value):
    keys=set(('sample capacity_known blockers quiescence_proven enforces_capacity device root_inode mount_id filesystem_type entries '
              'unique_inodes hardlink_references files_with_possible_external_links allocated_bytes regular_apparent_bytes inode_types filesystem bounds allocation_semantics').split())
    require(type(value) is dict and set(value)==keys)
    require(value['sample']=='two-matching-bounded-scans' and value['quiescence_proven'] is False and value['enforces_capacity'] is False and
            type(value['capacity_known']) is bool and value['allocation_semantics']==SEMANTICS)
    for key in ('device','root_inode','mount_id','entries','unique_inodes','hardlink_references','files_with_possible_external_links','allocated_bytes','regular_apparent_bytes'):
        require(integer(value[key]))
    require(value['root_inode']>0 and value['mount_id']>0 and 0<value['unique_inodes']<=value['entries']<=100000 and
            value['hardlink_references']==value['entries']-value['unique_inodes'])
    require(value['filesystem_type'] in ('ext4','xfs','btrfs','tmpfs','overlay'))
    counts=value['inode_types'];require(type(counts) is dict and set(counts)=={'directories','regular_files','symlinks','special'} and
        all(integer(v) for v in counts.values()) and sum(counts.values())==value['unique_inodes'] and counts['directories']>=1 and
        value['files_with_possible_external_links']<=counts['regular_files'])
    fs=value['filesystem'];require(type(fs) is dict and set(fs)=={'total_bytes','available_bytes','total_inodes','available_inodes'})
    blockers=[]
    for kind in ('bytes','inodes'):
        total,available=fs['total_'+kind],fs['available_'+kind]
        if total is None and available is None:blockers.append('filesystem-'+('byte' if kind=='bytes' else 'inode')+'-capacity-unknown')
        else:require(integer(total) and integer(available) and 0<=available<=total and total>0)
    require(value['blockers']==blockers and value['capacity_known']==(not blockers))
    bounds=value['bounds'];require(type(bounds) is dict and set(bounds)=={'entries','depth','seconds','name_bytes'} and
        type(bounds['entries']) is int and bounds['entries']==100000 and type(bounds['depth']) is int and bounds['depth']==64 and
        type(bounds['name_bytes']) is int and bounds['name_bytes']==8*1024**2 and
        type(bounds['seconds']) in (int,float) and 0<bounds['seconds']<=10)
    return copy.deepcopy(value)


def record(stage,source,context,prepared,sealed=None,cleanup=False):
    require(stage in STAGES and identity(source,40) and identity(context,64) and identity(prepared,64) and
            (sealed is None or identity(sealed,64)) and type(cleanup) is bool)
    require((stage=='prepared-image' and sealed is None and cleanup is False) or
            (stage=='assembled-postcleanup' and sealed is not None and cleanup is True))
    return {'schema':1,'stage':stage,'source_sha':source,'context_sha256':context,'prepared_image_id':prepared,
        'assembled_image_id':sealed,'cleanup_verified':cleanup,'sample_root':'maintenance-role-total',
        'graphroot':'included-overlapping-subset-not-added','outside_sample':OUTSIDE,
        'quiescence_proven':False,'enforces_capacity':False,'runtime_admitted':False,
        'status':'unavailable','reason':'collector-unavailable','inventory':None}


def validate(value,stage,source,context,prepared,sealed=None):
    expected=record(stage,source,context,prepared,sealed,cleanup=stage=='assembled-postcleanup')
    require(type(value) is dict and set(value)==set(expected))
    for key in set(expected)-{'status','reason','inventory'}:require(type(value[key]) is type(expected[key]) and value[key]==expected[key])
    if value['status']=='observed':require(value['reason']=='none');sample(value['inventory'])
    else:require(value['status']=='unavailable' and value['reason'] in REASONS and value['inventory'] is None)
    require(len(json.dumps(value))<=16384)
    return copy.deepcopy(value)


def decode(text):
    require(type(text) is str and len(text.encode())<=16384)
    value=json.loads(text,object_pairs_hook=unique)
    if type(value) is dict and set(value)=={'sample','reason','enforces_capacity'} and value['sample']=='blocked' and value['enforces_capacity'] is False:
        # Scanner's private fixed reason is not promoted into the public schema.
        require(type(value['reason']) is str and re.fullmatch('[a-z-]{1,80}',value['reason']))
        return None
    return sample(value)


def logical(row):
    """Selected descriptors from an already identity-verified inspect row."""
    size=row.get('Size');size=size if integer(size) else None
    layers=row.get('RootFS',{});layers=layers.get('Layers') if type(layers) is dict else None
    if not (type(layers) is list and len(layers)<=128 and all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for v in layers)):
        layers=None
    return {'logical_size_bytes':size,'layer_count':len(layers) if layers is not None else None,
        'layer_digests':copy.deepcopy(layers),'semantics':'logical-descriptors-not-unique-physical-usage'}
