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
`ubuntu-24.04`. The workflow supports opened/synchronize/reopened events, checks
out exact PR head and uses official actions/checkout v4.3.1 commit
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

Storage measurement keeps its proven one-filesystem traversal, 64KiB streaming
capture and root-side5s+1s deadline. Only exact owned-path ENOENT forms are eligible
for three retries. Missing totals are never zero; maxima remain enforced and
completion needs a stable error-free total. Permission/I/O/foreign/unknown errors
block, retaining bounded diagnostic counts/tails and truncation classifications.

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

A fixed owned-engine `info --format={{json .Host.OCIRuntime}}` query records only
validated bounded runtime name/path/version metadata. It has at most five seconds
inside the original phase deadline, uses the existing cleared environment/TMPDIR
and never executes the reported path. Valid package metadata is discarded;
null, malformed or oversized completed output is explicitly unavailable. A failed
launched query retains the existing primary failure and unresolved-worker cleanup
behavior; its raw failure capture is suppressed so package/malformed fields cannot
bypass projection through the ordinary error log. Bytes still count against the
same aggregate capture ceiling. Other command failure logs remain unchanged.
These diagnostics do not prove native runtime support, explain the
prior exit125, or establish failed-helper termination/cleanup.
