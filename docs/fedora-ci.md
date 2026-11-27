# Secret-free Fedora 44 CI execution route

[The PR workflow](../.github/workflows/fedora-vm.yml),
[controller](../tools/fedora_ci.py) and [guest](../tools/fedora_ci_guest.py)
implement a disposable Fedora execution route for one exact public candidate.
The reviewed baseline reached a real TCG Fedora44 boot, Enforcing SELinux,
systemd PID1, cgroupv2 and a complete dedicated serial report. Run7 identified
stock systemd-resolved LLMNR as the inspection blocker. The shared bootstrap now
contains the separately reviewed service-bound discovery mitigation.
**The preparation/maintenance integration described here has not run on Fedora.**
Local process/crypto/parser tests do not establish installation or confinement.

A successful new run must perform actual preparation and genuine maintenance
Distrobox initialization, seal an image, complete two frozen boundary/version
cycles and clean up. A green job establishes those components on this disposable
VM and exact source; it does not establish designated Hostinger or pair acceptance.

## Workflow and authority

Only same-repository PRs in `oso-gato/dev-pair` run on free standard
`ubuntu-24.04`. Opened, synchronize and reopened events select maintenance.
Adding the fixed `fedora-development-producer` label selects development for
that event's exact PR head. Other label events are ignored. The workflow checks
out the exact event head and uses official actions/checkout v4.3.1 commit
`34e114876b0b11c390a56381ad16ebd13914f8d5`, with persisted credentials disabled.
The controller requires exact clean HEAD. Token permissions are contents read;
there are no secrets, OIDC, private repository/standards retrieval, registry push,
cache/artifact uploads or purchased resources. Only sanitized bounded public logs
and the job summary are retained. No runner OS packages or firewall rules change.

The controller's owned filesystem, exact checkout and read-only VM payload are
the trust boundary. JSON source/role/executor claims are identities, not remote
authentication. No external transport/admission, agent job, account/model request,
Tailscale enrollment, SSH cutover or nested placement is enabled. Public source
contains adopted standards identities, never private standards text.

## Development image producer

Both scenarios use the same per-PR concurrency group and preserve its active
run. GitHub can supersede an older pending run with a newer pending run. Treat
a superseded run as blocked and keep the next dispatch under the existing
reviewed authority. Apply the development label only when the applicable
maintenance work is terminal and the exact head has been authorized. Keep one
active scope per PR and avoid label or head changes while a run is active.

The controller's `--scenario` accepts `maintenance` (the default) or
`development`. Development admission requires the Actions pull request event
from the runner's `GITHUB_EVENT_PATH` in `oso-gato/dev-pair`. A supplied event
path must match that path. The controller checks the fixed label and exact
event head before creating scratch or entering the probe. Development builds and ships one
authenticated development bundle. The manifest kind must match at build and
extraction. The scenario and a per-run nonce bind the NoCloud request, the
effective native service and the dedicated serial report. The development
report omits raw console/command output, paths and diagnostic ciphertext.

After admission on enforcing Fedora 44, the guest runs
`prepare-development-host --apply` once and deletes the disposable operator
password file before it can run `build-development --apply`. The guest checks
the original held parent and observes the file absent after the owned unlink.
It repeats the check before reporting completion. Both commands
share one absolute 2280-second work deadline. Preparation's 600 seconds and
the producer's 120-second preflight plus 2040-second build are upper bounds
clipped to the same deadline. The guest accepts each result before its stage
cutoff. The cleanup allowance cannot extend that cutoff. Native launch
startup/runtime and in-unit relay execution inherit the remaining budget.
The development Buildah package command and Distrobox assembly also check an
absolute cutoff at workload entry. Assembly and the never-started readback
snapshot retain inspected positive Podman lifetimes within their 900-second
and 180-second ceilings. Assembly checks that the created container still fits
the remaining time before starting. A failed command blocks its stage and
does not automatically retry. The 45-second cleanup allowance, 60-second final
report allowance, 2640-second VM cap and existing storage reserves remain.

Success requires protected development host readiness and its exact intent,
the first protected producer attempt, a ready publication and a readback of
the actual `inner.json` and OCI archive against the sealed image identity and
recorded digests and byte count. The guest reports password-file absence and
requires controller teardown for remaining guest resources. The controller
checks outer cleanup independently before the job can pass. This scenario
reports producer evidence with jobs disabled. Nested DevBox placement and
durable release delivery remain separate checks. The following maintenance
protocol retains its existing preparation, assembly and report evidence.

## Authenticated public inputs and actual guest path

1. Require preinstalled Podman, Git, GPG, sudo, coreutils and working
   slirp4netns; record the actual versions/kernel/runner image. Require >=10GiB
   runner RAM, two CPUs and >=23GiB free on the actual owned scratch filesystem.
2. Verify the official final Fedora44 Cloud checksum signature using fingerprint
   `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. Require exact checksum-file SHA256
   `a436186ff0e930d77637d03e6f357206b686c4ef3fcde234b6f1da63041d4b32`,
   image length583729152 and image SHA256
   `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`.
3. Build QEMU/ISO tooling inside disposable Podman storage from the pinned Fedora44
   [signed official OCI archive](signed-fedora-base.md), using only its verified
   immutable local config ID after load/save-back verification (`--pull=never`).
   RPM GPG checking, actual NEVRAs/RPM hashes and immutable image identity remain
   mandatory. The exact signed April release archive replaces the unsigned-provenance
   November registry selection; signed package refresh runs only during disposable
   candidate construction. Live RPM repositories remain a reproducibility limit. Empty auth/hooks prevent credential inheritance.
4. Invoke the current [public input helper](public-maintenance-inputs.md) `fetch`
   and `build` as bounded children. Build must perform actual strict Cosign3.1.4
   verification of pinned Codex0.169.0 and use exact Distrobox1.8.2.5 Git objects.
   An earlier receipt cannot replace this producer verification. Original public
   bundle/receipt and bounded verification output are retained in the controller
   report even if later packaging fails; counts/hash/truncation are explicit. Source/context,
   original signature bundle/output/receipt and sanitized shallow public Git
   objects enter the compressed payload. No runner Git configuration/hooks or
   inherited account credentials enter it.
5. Independently bind source, guest/helper/controller/workflow hashes, manifest
   hash, payload hash/length, context, Distrobox, standards and Codex/source hashes.
   Copy only guest/extractor code, manifest and compressed inputs to a read-only
   noexec/nosuid/nodev ISO. The guest hashes the extractor before invoking it and
   authenticates the manifest and bounded payload before staging protected code.
   The 192MiB compressed, 384MiB expansion, 2048-file and 32MiB per-public-source
   limits remain. Original cryptographic evidence is retained, not regenerated.
6. Boot the signed base with one owned writable overlay. Prefer KVM only after
   actual bounded initialization succeeds; otherwise record TCG fallback. Keep
   QEMU's existing scoped disks/public payload, no monitor/listener/engine socket,
   no host PID/network namespace or broad mounts, cap-drop ALL and NNP.
7. Cloud-init stages an exact controller-bound script under `/usr/local/libexec/dev-pair-ci`,
   a protected target record under `/var/lib/dev-pair/ci-executor` and a deterministic
   `dev-pair-ci-provision.service`. Standard `restorecon` contexts apply; no process
   label, policy or container confinement override is installed. The Type=exec root
   service has null standard streams, a clean environment, control-group termination,
   RuntimeMaxSec2445 and stop grace5s. Staging, selected startup acknowledgement and
   input admission share60s. No cloud-final ordering wait or cloud-init pipe forwarding
   occurs. The guest stages an exclusive root-owned0644 zero-byte
   `/etc/systemd/system/dev-pair-ci-provision.service.d/10-timeout-abort.conf`,
   restoring standard contexts on that directory and file. On systemd v259 this
   per-service same-basename empty regular file suppresses the stock generic
   timeout-abort drop-in; the owned empty path remains in DropInPaths. It never
   changes or accepts the global vendor file. This service explicitly selects
   TimeoutStopFailureMode=kill, SendSIGKILL=yes and FinalKillSignal=SIGKILL;
   effective values must be kill/yes/9, retaining2445s runtime and5s stop grace.
   Only the exact owned DropInPaths value is admitted; missing, vendor, substituted
   or additional paths block. Request version2 and native evidence bind the
   protected mask path, empty-content digest, device and inode. Native admission
   independently rejects symlinks/nonregular files, non-root or writable parents,
   changed mode, nonempty/multiply-linked files and inode/path replacement.
   Selected manager fields, exact loaded fragment/owned drop-in, effective limits,
   actual root UID/MainPID/cgroup/SELinux context and script/unit/controller hashes must
   match before any phase can pass. The unit contains public targets and its separate
   protected record contains the unit hash, avoiding a hash cycle. Failed startup emits
   only a bounded console diagnostic and requests shutdown; it cannot replace a report.
   Staged files persist only inside the disposable VM. Observation files are bounded
   anonymous owned regular files and close on every query exit.
   Staging failure diagnostics identify a fixed operation (root/source/context checks,
   each file installation, restorecon, reload, start or observation), numeric errno,
   actual control/query exit status or timeout, real/effective UID and elapsed time. A rejected parent
   exports only its component index and UID/GID/mode/type/size; no raw path, exception,
   argv or environment is exported. Only the three exact pre-credential public
   restorecon/reload/start operations may retain stderr, in an owned anonymous
   regular file with a native4096-byte file ceiling; stdout remains null and no
   stream is forwarded. Failure evidence exports a768-character tail, captured
   byte count/hash and explicit capture-ceiling/tail-truncation flags; it does not
   claim bytes beyond the ceiling were observed. Other commands remain withheld.
   Exact `systemctl daemon-reload` has a30s maximum, clipped to the same original
   shared60s admission deadline. Run11 observed this fixed operation time out after
   5235ms with empty stderr on TCG; that identifies a deadline failure, not a policy
   or D-Bus cause. Restore/start control caps remain5s and startup observation5s;
   no caller-selected timeout or additional VM/service time is introduced. Reload
   remains explicit so changed unit installation is not dependent on manager cache
   state. No journal is queried. Manager property values retain
   per-key bounded tails within the unchanged4096-byte console witness cap.
   Exact known public unit/mask paths are retained completely; scalar properties
   have smaller fixed caps. Unknown path values retain explicit truncation markers.
   The controller scans its already bounded console before tail truncation, verifies
   the witness schema and exact source/controller/script/unit targets, and retains
   the complete validated failure bytes and hash. Missing/partial/ambiguous witnesses
   remain unavailable diagnostics. This path never supplies phase or native executor
   acceptance and does not replace the dedicated report. Run10's generic staging
   failure does not establish a package, permission, label or drop-in cause.
   Observe actual Fedora44, Enforcing policy, systemd/cgroupv2 and >=8GiB free.
   Admit the public inputs and run actual pre-initialization inspect/status.
   Generate a disposable password only inside the root guest in a private0700
   directory and O_EXCL0600 file. Its value never enters seed, argv, environment,
   command diagnostics, journal collection or serial output.
8. Call the real shared `bootstrap.py initialize --apply` with exact source,
   context and Distrobox inputs and documentation-only SSH CIDR192.0.2.9/32.
   There is one attempt and no automatic retry. This genuinely runs signed Git
   prerequisite/normal preparation and then the maintenance adapter. Remove the
   password at an exact matching prepare-complete boundary and on every exit,
   including write/fsync failure before yielding its pathname, before reporting.
9. Read only target-bound protected phase/result records. Independently inspect
   prerequisite/sealed image IDs, architecture and source/context/upstream labels;
   verify desired/context/bootstrap hash and actual package inventory. Complete
   adapter evidence requires exit0, both phases complete, two boundary/version
   cycles and recorded removed runtime. Inspect/status also run after the attempt.
   Missing, stale, partial or nonmatching evidence remains blocked. A preparation
   pass survives a later assembly failure when its own evidence is verified.

## Provisioning network

Only the VM invocation uses outer
`slirp4netns:allow_host_loopback=false`, with QEMU IPv4 user networking and a
virtio NIC. No hostfwd/guestfwd, published ports, TAP, runner bridge, host networking,
engine sockets, privileges or extra capabilities are added. Other tooling runs
remain network-none. Actual owned-container network mode/no published ports and a different
network namespace from the runner are inspected and reported. The requested
loopback-denial option is recorded separately from normalized engine mode.

This permits fixed public artifacts/keys, Sigstore metadata, signed Fedora and
Tailscale packages and the signed official Fedora Container archive. It is **not a destination
ACL** or proof that all private/routable runner addresses are unreachable.
No proxy/account credentials are passed. Missing networking support blocks;
there is no runner package/firewall installation or host-network fallback.
Final maintenance probe runtimes retain network-none.

## Fixed resources and deadlines

| Resource | Bound |
| --- | --- |
| Guest virtual disk |32GiB |
| Writable qcow2 hard file ceiling |16GiB |
| Measured non-overlay overhead |4GiB |
| Host free reserve |3GiB |
| Initial required free storage |23GiB |
| Guest / outer resources |6GiB2CPU /8GiB3CPU1024PIDs |
| Captured console and report aggregate |8MiB |
| Dedicated JSON / write deadline |64KiB /30s |
| Controller / public setup / VM / cleanup |3300s /540s /2640s /120s |
| Native VM container lifetime |2670s |
| Guest admission and pre-observation |60s |
| Shared initialize execution / stop grace |2280s /45s |
| Guest final evidence, report and shutdown |60s |

The 60-minute standard job leaves time outside the controller for checkout/tests.
Setup shares one absolute deadline; each child is clipped to remaining time.
The VM envelope reserves boot180+admission60+initialize2280+cleanup45+final60
(2625s), with15s margin; the external VM deadline is authoritative. Missing time
blocks rather than borrowing cleanup reserve. Native staging900s and runtime180s
remain unchanged; image import/build share600s. The fixed staging dependency/locale
RUN has its own native540s timeout and10s forced termination. This bounds that
work when a build helper escapes its client unit; it does not prove every engine
helper stopped, or extend an already shorter remaining image/VM budget.

Virtual capacity is not physical allocation. QEMU RLIMIT_FSIZE enforces16GiB;
capacity/overhead monitoring preserves host reserve. Guest free space is measured
before preparation, before assembly in shared code, and finally. No reserve is
lowered. Repository/cache/temporary expansion/ISO duplication count toward4GiB.
Measured insufficiency, ENOSPC, timeout and capability failures remain blockers.

The source-bound storage worker measures allocated blocks with descriptor-relative
traversal, hardlink deduplication and the existing `guest.qcow2` basename
exclusion. It skips other devices without enumerating them. Same-device bind
mounts are traversed only after the worker verifies their source inside owned
scratch, with GNU `du --one-file-system` accounting for aliases and cycles.
If a strict source lookup crosses a mount at the final directory component on
ext4 or tmpfs, the worker checks that the visible mount is a canonical self-bind
and that the entry beneath it has the expected inode. It repeats the proof
after traversal, keeps the scanned and canonical source mounts pinned, and
charges the extra directory entries to the same scan limits.
If the source's strict parent lookup also returns EXDEV, a bounded child in a
private mount namespace can pass a read-only nonrecursive bind of the owned
scratch root back as a metadata descriptor. The worker checks each live source
component against that backing view and verifies the canonical mount source of
every crossed prefix. It holds live mount identities through the post-scan
check. All block accounting and enumeration still use the live filesystem.
Unavailable proof or a changed identity blocks the sample.
When the strict canonical source lookup returns EXDEV, fixed reason codes
identify a regular file, another nondirectory, or an empty canonical name.
Directory fallback codes identify the parent open, parent identity, unsupported
filesystem, visible leaf open, or a leaf still on the scratch mount. Overlay
has its own filesystem code. Other EXDEV errors within the fallback use
`bind-source-before-exdev`.
Unverified same-device mounts block. A descendant disappearance can yield a
provisional sample or trigger another attempt without contributing a total.
Across at most three attempts, the largest usable sample counts against the
same overhead and active-copy reserve. Final measurements require a complete
scan. Identity, permission, I/O, traversal-limit and timeout failures block.
The 64 KiB capture limit and root-side 5-second timeout with a 1-second kill
grace remain in effect. Worker evidence reports typed results and output counts
and hashes. An unresolved image-copy worker still prevents scratch cleanup.

## Reports, secrecy and cleanup

Dedicated ttyS1 retains the owned0600 FIFO pair, raw115200 terminal, bounded
write/drain and exact frame protocol. Normal poweroff requires successful report
delivery; no console salvage is accepted. JSON envelope version4 requires strict
public-input identities and selected initialization evidence. Producer/consumer
share fields/limits. Wrong/unknown versions, duplicate fields, unknown identity
or initialization fields and unmatched hashes reject. Executor exit0 plus exactly
one complete frame is required; EOF or a visible frame alone is insufficient.

Public diagnostics select fixed RPM/socket/service-result fields, strict structural AVC/USER_AVC
security fields and at most two public failure records per preparation/adapter, with
bounded1500-character stream tails, original counts and truncation flags. Fixed
operation/prepare-step IDs distinguish accepted nonzero exits from rejected
commands; recent metadata remains available when a later Python source gate fails.
Source metadata uses a separate observer, preserving the original1MiB Commands
dispatch, deadlines and cleanup. Source/context/upstream verification exports
fixed stage/outcome only, never raw
Git paths/configuration/output. Failed owned native commands additionally query
only bounded unit state/result/exit fields; a collected or unstarted unit is
explicitly unavailable, never inferred successful. SELinux enforcement is a
fixed public read operation; password/stdin output remains withheld. No
post-password arbitrary journal, shadow, environment, auth state, password file,
complete native history or filesystem is exported. Modern `::command::` and
legacy `##[command]` forms are neutralized by central emitters; structured JSON
preserves decoded evidence. The bounded raw-report hash/hex/base64 witness remains.

The password's absence and initialization cleanup state are reported explicitly.
Only exact owned guest units/recorded resources are reconciled by shared code;
uncertain cleanup stays unverified. Whole-VM shutdown/forced native teardown is
the final guest boundary. Outer cleanup uses only its unique Podman root and
short `/tmp/dpvm-*` scratch. It requires successful removal, empty inventory
including external build containers and no mounts before deletion. Unknown
active state preserves scratch and reports failure. No shared prune/reset or
runner-wide deletion occurs. Cancellation/SIGKILL supplies no completed cleanup
claim; native/job limits and the disposable runner remain the outer bound.

Run `python3 -m unittest discover -s tests -q`. Local checks cover actual process
limits/descendants, authenticated cached payload extraction, public GPG metadata,
FIFO/PTY framing, secret-sentinel failure paths, phase/identity rejection and fixed
profile/network construction. Engine/service responses injected in tests remain
explicit synthetic contracts, not Fedora execution. Actual Fedora owned-mask selection/effective kill profile/native context admission, current-source public
fetch/Cosign, package timing/capacity, rootless SELinux confinement and genuine
Distrobox initialization require a separately reviewed hosted run. No local
VM, authentication/model, VPS or complete-pair acceptance is claimed.

The [native stream transport](native-command-io.md) also covers the final dp-maint
image observation. Same-run security diagnostics retain bounded structured
no-comm USER_AVC records without exporting audit paths/proctitles/arguments.
Root filesystem type and selected quota flags are diagnostic-only observations.

Report version5 additionally binds the public Fedora verifier dependency hash;
public-input manifest version2 carries exact signed Fedora source provenance.
Older report/input contracts are rejected. No console fallback or guest phase
acceptance is added. Native import/refresh under existing budgets remains unproved.

The single tooling package RUN now emits a finite `DP_TOOL_STAGE` trace: outer
shell entry, timeout launch, inner entry, upgrade, install, RPM hashing, cache
cleanup, payload completion and the timeout's numeric exit status. Marker writes
cannot replace the payload/timeout status. The controller projects only complete
exact whole lines in order from its existing bounded capture; quoted Containerfile
RUN text, missing stages, partial lines and truncated capture do not establish
execution success or identify a cause. The540-second/10-second timeout settings,
package signature checks, environment, network and resource profile are unchanged.

The optional pre-build owned-engine runtime-info query is omitted. OCI runtime
metadata remains explicitly `unavailable` with reason `not-collected`; no previous
sample or Podman version substitutes for current runtime identity. There is no
replacement probe, retry, or transfer of its former five-second budget. Required
signed load/inspect/save-back, build and tooling run keep their original flags,
time/resource/capture limits and failure-output accounting. A failed necessary
engine operation still preserves its primary failure, sticky active latch and
owned scratch when complete worker termination is unresolved. Omitting future
diagnostic work neither reclaims run26 resources nor proves a particular helper
caused exit124, native runtime support, or failed-helper cleanup.



The runtime-account sudo probe exports only closed typed negative evidence and
bounded guest package metadata. Successful listing status zero is distinct from
permission: both fixed roles must return the exact hostname-bound C-locale denial
with empty stderr and verified complete relay transport on native execution.
Standalone trusted-root preparation retains its existing fixed direct subprocess
with actual waited status and complete bounded pipes, explicitly typed as direct
without a relay or native-exit claim. A failed native operation cannot select it
as a fallback. Public reports retain
the two stable role receipts even after ordinary recent records rotate; raw sudo
policy output remains withheld on success and rejection. Guest package provenance
is explicitly package-only, with loaded-policy-plugin verification false. Unknown
versions/backends/grammar block. No extra privileges, package workaround, changed
native executor semantics or larger resource/deadline/capture/report limits are
introduced; local parser/process tests are not Fedora policy acceptance.


Preparation now records a source/context-bound timing witness before later
adapter or cleanup phases can overwrite runner state. It reports the unchanged
configured budget, effective clipped budget, finite elapsed seconds,
`deadline_reached_at_exit`, and `timer_fired`. Only the existing actual SIGALRM
handler sets the last bit. Elapsed time or deadline crossing alone is not a
primary-cause diagnosis: cleanup after another failure may cross the deadline.
Missing, malformed, nonfinite, oversized or wrong-target witnesses remain
unavailable. Private preparation elapsed time is projected only after the same
strict checks. Bounded per-role directory counts and fixed lookup/substep IDs
identify progress without exporting argv, raw ID output or exception strings.
No time/resource/admission/cleanup ceiling is raised or reset.


### Disposable selected-load diagnostic

The native34 follow-up introduced a fixed public diagnostic recipient on the
authenticated public payload ISO. The recipient rotated on November 27, 2026.
Its SHA256 is `3a0f32ce78af805d4662d5eaaebeca79b39c2ef5d63e485838491f967336dfe5`
and its 40-hex primary fingerprint is
`968C5A2925FBCDBEEEA6B11FF8A623703EFDDB03`. Its one-day validity ends at
07:55:01 UTC on November 28, 2026. Its use is limited to disposable CI
diagnostics. The private key stays outside source, CI, images, reports and
artifacts. Public ISO entries have explicit root UID/GID metadata.

Only the existing exact signed-load selector, observed owned launch, complete
verified relay, matching maintenance UID and nonzero payload status can seal a
capsule. A canonical in-memory envelope includes source/context, unique attempt,
executor unit/UID, status and complete stdout/stderr counts, hashes and lossless
base64 bytes. Its maximum is 8 KiB; stock GPG encrypts through private pipes with
the fixed empty read-only payload ISO home and sole pinned public recipient directly.
It creates no runtime home, key copy, keyring, trustdb or random-seed file. No
plaintext file, argv, environment, public tail or fallback is written. The existing `/usr/bin/prlimit --core=0:0 -- /usr/bin/gpg` chain replaces a Python
preexec callback. No added blocked mask remains during Popen/exec or reaches the child. GPG's
maximum five seconds is clipped to the original command/phase deadline and
includes a reserved reap interval; ciphertext is capped at 16 KiB. A cleanup
uncertainty has its own closed unavailable reason and cannot replace the engine's
primary failure or existing cleanup result.

A single capsule is retained separately from repeated command records. Guest and
controller validate its source/context, attempt, recipient, digest/size and
independently validated selected-load UID/status/control evidence. Actual guest
serialization still enforces 64 KiB; optional ciphertext is replaced by a typed
report-budget reason before exceeding that bound. Other limits are unchanged.
Absent or untrusted recipient, incomplete/oversized payload, no remaining budget
or encryption failure produces typed unavailable evidence only.

Local synthetic-key roundtrips and fixed-envelope verification do not establish
Fedora behavior or native34's cause. Before diagnosis, the operator must verify
the source-bound public capsule and digest, require successful authenticated GPG
decryption privately, and validate the complete canonical envelope and stream
hashes/counts against independent selected-load evidence. `verify_plaintext`
checks these fixed operands in memory and returns only a boolean; it neither
decrypts nor authorizes a cause claim. Native35 requires fresh source review and
separate authorization. Production runtime/jobs, authentication, nested placement,
hard quota, renewal, tailnet and release/deployment gates remain unclosed.


The independent f451b33 review found lost cleanup uncertainty. The subsequent
65bd26b repair passed 669 local tests but fresh review found a launch/publication
signal gap, replacement-path deletion, swallowed cancellation and unreconcilable
post-removal descriptor release. Those failures remain evidence; its full pass
does not close them.

The replacement removes runtime writable home/key-copy/deletion and directory-FD
reconciliation entirely. The controller stages one fixed empty public directory
on the existing authenticated payload ISO, with deterministic root UID/GID
metadata. The helper admits that exact directory only when root-owned,
nonwritable, empty and on a read-only filesystem; it validates the existing exact
recipient independently. Actual mounted Fedora behavior remains unproved locally.
Stock GPG uses no-options/no-autostart/no-auto-key-retrieve/no-default-keyring/
no-keyring/no-auto-check-trustdb/no-random-seed-file. Owned synthetic-key roundtrips
use an unchanged empty 0500 home with actual UID1000 DAC write denial, not an
immutable-mount or hostile-owner proof. The earlier research's failed bwrap setup
is preserved separately; no confinement workaround is used in the product.

Only the fixed main-thread handlers are deferred across Popen return and exact
owner publication. The e7689ba review found partial handler installation and
interrupted restoration could orphan the phase handler. The repair snapshots all
original handlers and obtains the prior mask with a non-mutating query first.
Mask changes occur only inside protected handler-transition cleanup; restoration
knowledge remains live until each setter takes effect, with one bounded
restoration retry for an interrupted setter/mask operation. This is not a child,
engine or workload retry and grants no additional time. All handlers and the prior
mask are restored on exit; a failed restore cannot silently swallow later phase
signals. Known pending setup cancellation invokes its original handler before any
child launch. Pending publication/cancellation and failed-launch semantics remain.
No handled signal stays newly blocked over Popen/exec, no Python preexec callback
is used, and no timer or original deadline is reset. This is
operational ownership protection, not a hostile-kernel hard-wall guarantee.
One actual Popen owner remains only while reap/pipe cleanup is unconfirmed;
subsequent collection is blocked, and reconciliation uses the original end time.
Direct KeyboardInterrupt/SystemExit and phase cancellation propagate. Bootstrap
keeps an already-known engine primary/native cleanup result over a secondary
diagnostic cancellation; absent an original primary, cancellation propagates.
No runtime filesystem deletion or path reclamation remains. Fresh exact review,
a later combined full and a separately scoped native35 run are still required.
