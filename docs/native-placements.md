# Prove both offline placements on one Fedora host

Use the authorized continuing Fedora Cloud 44 x86_64 host, an enforcing SELinux
policy, and the exact independently reviewed source. The offline proof runs the
existing pinned Distrobox entry points. It reports two starts in each placement
and preserves the existing closed job admission.

## Prepare the same-host releases

Prepare the maintenance and development input bundles at the same reviewed
commit. Keep their separately trusted manifest and context hashes. Extract the
bundles into two new root-owned protected directories on the Fedora host, as
described in the [maintenance input guide](public-maintenance-inputs.md) and
[development image guide](development-image.md). In the commands below,
`MAINT` and `DEV` are those absolute extraction paths. The signed Fedora input
files required for the DevBox tooling build are in `$DEV/context`.

Run maintenance initialization from the authorized root console using the
approved bootstrap access mode for the target. For a deployment that authorizes
temporary SSH, the existing entry is:

```sh
/usr/bin/python3 -B "$MAINT/dev-pair/tools/bootstrap.py" initialize --apply \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --gptbox-context "$MAINT/context" --expected-context-sha256 "$MAINT_CONTEXT_SHA256" \
  --distrobox-source "$MAINT/distrobox" \
  --bootstrap-source "$AUTHORIZED_BOOTSTRAP_CIDR" --password-file "$CORE_PASSWORD_FILE"
```

Verify the [maintenance assembly result](confined-gptbox.md) includes the exact
source, context, sealed image and both launch/probe cycles. On an already
initialized host, the same exact command revalidates the candidate. The
authorized first-bootstrap password remains external to the input bundles and
receipts. The commands below need the prepared host and require no additional
credential input.

Build the development gptbox with the signed development context on that same
host. Leave the published release and its protected producer receipt in place.

```sh
/usr/bin/python3 -B "$DEV/dev-pair/tools/gptbox.py" build-development --apply \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --context "$DEV/context" --expected-context-sha256 "$DEV_CONTEXT_SHA256" \
  --distrobox-source "$DEV/distrobox"
```

The development release path includes the exact archive and the eight-field
inner record. The protected producer evidence also binds the attempt and
published directory identity. A temporary CI guest's release path is usable
only while that guest exists.

## Prepare and exercise the nested placement

The root console needs the already provisioned, locked `dp-dev` account with
its private group, subordinate ranges, sudo denial and linger-enabled user
manager. The host requires `losetup`, `blkid`, and `mkfs.ext4` from its trusted
Fedora packages. Allow exclusive use of the placement and declared MCS pool
during this operation. Finish the maintenance proof first and keep unrelated
container starts outside the scoped window. The placement excludes live
container categories and durable bridge reservations. The operator must
coordinate separate Podman stores and other allocators on the host.

```sh
/usr/bin/env -i PATH=/usr/sbin:/usr/bin /usr/bin/python3 -B \
  "$DEV/dev-pair/tools/native_placements.py" run \
  --source-sha "$REVIEWED_SOURCE_SHA" --context-sha256 "$DEV_CONTEXT_SHA256" \
  --distrobox-source "$DEV/distrobox" --fedora-cache "$DEV/context" \
  --job nested-probe --storage-gib 8 --outer-storage-gib 4
```

The command takes the bootstrap lock, verifies the protected development
publication, and checks for idle managed roles. It charges allocated blocks
in the maintenance and development stores, producer artifacts and durable
role data before allocating more space. The three loop-backed ext4 filesystems
default to 8 GiB for the nested graph, archive and copy scratch, 4 GiB for the
outer image graph, and 1 GiB for protected verification and outer copy scratch.
All have finite inode tables. Existing data and the full reservations,
including 256 MiB of host metadata headroom, must fit within the existing
20 GiB managed ceiling. At least eight GiB remains available and finite host
inode counters must leave headroom. The outer graph target is
`/home/dp-dev/.local/share/containers/storage`. An existing populated or
foreign graph blocks before volume creation. The kernel mounts retain their
separate identities. For the runtime's remaining paths, the Podman runroot
uses the managed user's tmpfs, and the empty offline workspace, state and
cache leaves remain under their managed role roots.

The tool verifies Fedora's official signed archive, imports it by config ID,
and checks the save-back graph. The root-owned scratch mount prevents the role
from exchanging the verification or image-copy directories. The tool removes
its exact verification spool after the managed import stops and preserves it
when the result remains uncertain. A disposable rootless builder uses a separate
capability profile for signed Fedora package setup, removes inherited sudo,
and sets the two namespace helper file capabilities in the exact outer recipe.
Package setup needs public access through the isolated builder network. The outer
DevBox build uses the exact verified tooling image and pinned Distrobox entry,
with networking disabled and local images only. The receipt retains the
base, tooling and outer image identities and distinguishes the outer OCI image
manifest digest from its config ID, the inner archive digest and the nested
placement manifest SHA-256.

The bridge stages the exact launcher source and host configuration in a
root-owned directory readable by `dp-dev`. As `dp-dev` it verifies that the
launcher loads the reduced runtime capability profile and can inspect the
allocated loop backing. The backing bytes stay private to root. It writes the
read-only placement manifest from a verified input directory, supplies its
separately retained SHA-256, and runs the normal
`devbox.py run` under a finite `dp-dev` systemd service. The successful receipt
requires both nested start identities, the consumer's confinement checks, exact
container removal and `job_admission: false`. First execution has a
2,280-second wall ceiling. The existing consumer controls its own 600-second
outer and 180-second inner lifetimes.

## Reapply and inspect

Record the JSON output. The root-only record at
`/var/lib/dev-pair/native-placements/records/nested-probe/placement.json` holds
the same proof and the most recent failure stage. A completed identical call
on the same boot rechecks the storage, image and release bindings and returns
the recorded proof with `reused: true`. An authorized reboot followed by the
same command reattaches the recorded volumes and runs a new probe for that boot.
It checks the backing identity and filesystem UUID before admitting an inode
on the current loop device. The backing files and verified images persist
across host reboot. The command does the reattachment when invoked.

After a failed image setup or nested probe, use `--retry` only for the same
authorized input. Image setup permits two attempts total and the probe permits
two attempts per boot. A prior uncertain launch must reconcile its exact
systemd identity and cgroup, or reach its recorded deadline, before retry.
Foreign mounts, changed backing, nonempty job leaves and ambiguous ownership
block while preserving the data. The bridge retains its exact volumes, images,
MCS reservation and any failed evidence for operator inspection. Any later
placement replacement or reclamation requires separate ownership and lifecycle
verification.

The focused local tests exercise release custody, filesystem identity and the
managed launch/retry contract. An actual enforcing Fedora run establishes
kernel mounts, native rootless image builds and Distrobox confinement.
