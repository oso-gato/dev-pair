# Storage samples and peak-capacity arithmetic

`tools/storage.py` is a read-only observation and pure planning component. It
creates no allocation, quota, mount, loop device, deletion policy, reservation
ledger or job admission. Existing aggregate20GiB, guest8GiB reserve and independent
CI16GiB overlay/4GiB overhead/3GiB runner reserve remain unchanged.

```
python3 tools/storage.py /absolute/declared/root --seconds 10
```

The Linux observer opens every component through dirfds with no-follow flags.
O_PATH snapshots inspect symlinks, FIFOs and devices without following/opening
contents. A readable directory fd is opened only for a verified directory.
Per-fd `/proc/self/fdinfo` mount IDs detect nested mounts, including bind mounts
on the same device; missing mount identity blocks. Ancestor symlinks and nested
mounts are rejected. Selected local filesystems are ext4, XFS, Btrfs, tmpfs and
overlay; other backends block instead of attempting remote/FUSE traversal.

Two bounded scans compare inode/dentry metadata and recheck the root identity.
Observed changes block rather than producing an admission sample. Matching scans
are still **not proof that writers stopped**: `quiescence_proven=false` always.
The external owner must serialize reservation decisions, verify writers/pins and
remeasure before effects. Deadline checks bound iteration on supported local
filesystems; the existing external native timeout is still required for
pathological kernel/filesystem stalls.

Defaults are100000 entries, depth64,10s and8MiB aggregate private name bytes per
scan. Configurable hard maxima are1000000 entries, depth128,30s and32MiB names.
Both scans share the deadline. Results contain aggregate counters and filesystem
identity only; filenames, contents, symlink targets and private paths/hashes are
never reported. Inaccessible entries, entry/depth/name/deadline excess, unknown
allocation data and races block. No incomplete count becomes zero.

Allocated bytes sum `st_blocks*512` once per device/inode, including directories
and links. Regular apparent bytes are separate. Hardlink aliases are deduplicated;
possible additional external links are counted. Distinct-inode reflinks/shared
extents, compression, filesystem metadata and open-unlinked files cannot be
inferred as exclusive physical ownership or reclamation. Do not add overlapping
root inventories or Podman logical image Size values as unique physical usage.

Known byte/inode counts remain useful when filesystem capacity counters are
unsupported. Unknown total/available capacities are JSON null, `capacity_known`
is false, blockers are explicit and CLI exit2 is returned. Zero available space
with a known total instead means measured exhaustion. In particular Btrfs may
report no finite inode capacity; this remains unknown. Run14 observed Btrfs with
no selected quota-option flags; that proves neither enabled enforcement nor its
absence. This component does not inspect or claim Btrfs quota enforcement.

The Python `admit(...)` function requires `Space` measurements and every named
peak input explicitly. Missing/null/mistyped/negative metrics block. Existing
materialized reservations are included in the single20GiB aggregate but are not
subtracted again from current guest free space. New and outstanding unmaterialized
reservations, remaining unreserved growth, platform writes and metadata margin
are charged to the guest peak; planned inode growth must also fit.

Overlay current bytes must conservatively cover both observed file length and
allocated bytes. Its supplied growth upper bound must cover both length and
physical growth, including metadata, overwrite/COW clusters and overlapping
prepare/builder/sealed/rollback/export/import copies. It cannot be below the
additional guest charge. This is an explicit caller-proven bound, not an inference
from virtual free space, sparse length or compressed archive size. Overlay and
non-overlay peaks independently remain within16/4GiB; their additional growth is
charged against runner free space while retaining3GiB. Guest space retains8GiB.
Inode headroom is checked independently for both filesystems. All pending overlap
must already be included; there is no scheduler or concurrency lease here.

`fits_capacity_plan=true` means only these supplied numbers fit the arithmetic.
Every result still has `runtime_admitted=false` and `enforces_capacity=false`.
Samples are not quotas or reservations, and no data is reclaimed. Actual backing
allocation/geometry, independent lower thin-layer bounds, hard byte/inode denial,
protected recovery capacity and crash-safe lifecycle remain separate required
implementation/runtime gates.

Run `python3 -m unittest discover -s tests -p test_storage.py -v`. Real filesystem
tests cover hardlinks, sparse allocation, symlinks/FIFOs, permission failure,
mutation races and work bounds. Same-device mount-ID changes and unavailable
capacity are explicitly injected, without making mounts or claiming backend
acceptance. Counterexamples test reserve edges, unknown metrics, outstanding
commitments, preallocation non-double-counting and independent CI limits.
