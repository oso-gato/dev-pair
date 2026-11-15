# Secret-free Fedora 44 CI execution route

[The pull-request workflow](../.github/workflows/fedora-vm.yml) and
[controller](../tools/fedora_ci.py) implement an initial real-VM execution route
for an exact public candidate. [Run 5](https://github.com/oso-gato/dev-pair/actions/runs/43731901140)
passed all 148 tests, runner preflight, signed Fedora download verification,
tooling image construction and source transfer. The Fedora VM actually booted
and powered off under TCG in approximately 95 seconds. The controller rejected
the guest report framing; the retained tail contains only partial preflight/status
results, which cannot satisfy the complete candidate-bound report contract.
Cleanup passed. Stable tooling/source overhead was 1029046272 bytes. A dedicated
second-serial report transport is now implemented and locally tested; it still
requires independent review and a fresh Fedora run. Historical console fragments
are not upgraded into complete phase results.

This checkpoint intentionally stops after boot, enforcing-Fedora/systemd/source
preflight and actual read-only `bootstrap inspect`/`status`. Preparation and
maintenance-gptbox assembly produce explicit **blocked** phases, so the job exits
`2` even if baseline phases pass. The blocked phases remain required work. After
review and the first CI evidence, transfer and independently reverify the exact
recorded Codex0.169.0/Cosign and Distrobox1.8.2.5 inputs, then implement bounded
prepare/assembly in this route. Do not replace their provenance with fixture
responses or treat this initial checkpoint as the complete CI deliverable.

## Workflow boundary

Only same-repository pull requests in `oso-gato/dev-pair` run, on standard public
`ubuntu-24.04`. Opened/synchronize/reopened events are supported; no default-branch
merge or workflow-dispatch route is required. Checkout uses exact PR head SHA,
disables persisted credentials, and is pinned to official actions/checkout
v4.3.1 commit `34e114876b0b11c390a56381ad16ebd13914f8d5`, independently resolved
through upstream Git's official HTTPS endpoint. The controller verifies HEAD and
a clean worktree, and records source, workflow/controller hashes and merge SHA.
The token has read-only contents permission; other permissions, including OIDC,
are absent. Superseded PR runs cancel, with no automatic retries.

Standard public runners are the authorized free test environment. This workflow
uses no larger runners, purchases, secrets, private repositories/standards,
registry publication, cache or artifact upload. Public job logs and a bounded job
summary are the only retained CI evidence. Workflow publication and standard-runner execution were confirmed by the first
run; later dependency/build/guest capabilities remain unverified.
CI executes reviewed public test code; it does not start an autonomous agent that
would require private standards retrieval or credentials.

## Actual execution path and identities

1. Require the actual Ubuntu24.04 runner, >=10GiB RAM, two CPUs, existing Podman,
   Git, GPG and noninteractive sudo. Record actual kernel/ImageVersion/Podman.
   Nothing installs into or deletes software from the runner's OS.
2. Download official Fedora key metadata and the final clear-signed Cloud checksum
   over HTTPS, rejecting non-HTTPS redirects. Isolated GPG verification exports
   and trusts only Fedora44 fingerprint
   `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. Require the exact checksum bytes
   SHA256 `a436186ff0e930d77637d03e6f357206b686c4ef3fcde234b6f1da63041d4b32`,
   exact named `Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2`, length
   `583729152` and SHA256
   `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`.
   The image itself is downloaded with that hard byte cap, then hashed.
3. Build QEMU/genisoimage tooling using preinstalled Podman, in a unique disposable
   graph/runroot/tmp root. Use exact official Fedora44 OCI base
   `sha256:48f4a2b507ad36a6a8bb83646ee81164aff80a62be06d03b143b80594d2b558e`.
   Mandatory RPM GPG checking verifies installed tooling; cached RPM SHA256 values,
   installed NEVRAs and the resulting immutable image ID are recorded. The OCI
   base signature is not verified here. Live Fedora RPM repositories and the
   runner remain reproducibility limits; no fully locked tooling build is claimed.
   Empty explicit registry auth and hooks directories prevent credential/hook
   inheritance. Tool construction occurs inside disposable image roots.
4. Produce a bounded public Git bundle and source archive from exact HEAD, retaining
   Git objects without runner `.git/config`, environment or credentials. Verify
   the bundle on the controller. Hash archive/bundle and guest script separately.
   Create read-only NoCloud and public-payload ISOs; the guest verifies transferred
   bytes and stages regular source files and Git objects beneath root-owned private
   `/root/dev-pair-ci-staging`. Guest Git-object validation is deferred until its
   signed Git prerequisite exists; transferred byte verification is explicit.
5. Validate qcow2 format/virtual size/no external backing, then create one 12GiB
   virtual overlay over the read-only signed base. Prefer KVM only after an actual
   bounded QEMU initialization/quit succeeds with the caller's existing device
   access; otherwise record bounded TCG fallback. Merely finding `/dev/kvm` is
   insufficient, and no host device permissions are changed.
6. Run QEMU as the runner's unprivileged UID inside a read-only, capability-free,
   no-new-privileges tooling container with only scoped public payload and owned
   disks mounted. It receives no host engine socket, privilege flag, host PID or
   network namespace, broad host mount, listener forwarding or NIC. The first
   guest has no network access and no credentials. It boots the actual signed
   Fedora kernel, systemd and SELinux policy; stock non-Enforcing state blocks
   rather than silently invoking the separate SELinux transition matrix.
7. Collect a single versioned, candidate/script-bound result on dedicated ttyS1.
   ttyS0 remains diagnostic console only; no console substring can satisfy report
   admission. Guest checks
   Fedora44/x86_64, systemd PID1, Enforcing SELinux, active policy, cgroup v2 and
   >=8GiB guest free space. Run genuine read-only bootstrap inspect/status, with
   actual command errors, startup journal/AVCs and baseline RPM identities.
   Report each phase pass/fail/blocked, then power off. No password is generated
   because no preparation occurs; future preparation must generate its disposable
   console password inside the guest and never emit it to cloud-init/serial logs.

## Limits, evidence and cleanup

The workflow has a 60-minute hard job limit. Downloads share a 600-second wall
deadline and exact byte caps (key bundle <=1MiB, checksum <=64KiB, image exact
583729152 bytes). Tool build is capped at 600 seconds with its DNF process natively
limited to 540+10 seconds. Public bundle/archive each have a native 32MiB file
limit. Tooling/source/base overhead is measured, including root-owned storage,
against a 2GiB ceiling. If the real runner cannot fit, record capacity blocked;
never remove preinstalled software or enlarge bounds to force a pass.
Measurements use one-filesystem traversal to avoid counting overlay merged mounts
again. During live package/storage churn, only exact owned-path ENOENT diagnostics
are eligible for three bounded retries; both proven `cannot access` and
`cannot read directory` ENOENT forms are covered. The largest observed size remains subject
to the overhead cap; an incomplete live sample is explicitly provisional. Every
completed command must obtain a stable error-free measurement before advancing.
Permission, I/O, invalid summaries and unrecognized errors block immediately;
the independent host-free-space reserve watchdog remains active.
Storage output is streamed under the unchanged 64KiB capture cap and a fixed
root-side five-second timeout with one-second forced termination. A rejected
measurement retains byte counts, retained-line classifications, explicit
partial/truncated flags and bounded stdout/stderr tails in `DP_REPORT`.
Truncated counts describe only the retained prefix; they do not establish the
cause of omitted diagnostics. The observed CI cap failure remains unclassified
until an actual run returns this evidence; no capture-budget increase is implied.
The separately observed fatal `fts_read failed` owned-path ENOENT can omit the
summary entirely. Only that exact scoped error permits retry without a total;
the sample is explicitly missing, never zero. The same three-attempt bound
applies, preserving the maximum usable count. All-missing attempts block even
during live monitoring, and completion still requires an error-free total.

Before VM boot, free host disk must cover the complete 8GiB overlay maximum plus
3GiB host reserve. The guest's 12GiB virtual disk is thin provisioned, not a
12GiB physical allocation. A fixed QEMU entrypoint applies native
`RLIMIT_FSIZE=8GiB` to the writable overlay. A live watchdog enforces host reserve,
overhead and aggregate 8MiB captured-log limits. KVM boot/result timeout is 300
seconds, TCG 900 seconds; native tooling-container lifetime is 1050 seconds.
QEMU gets two CPUs/6GiB RAM within three CPUs/8GiB/1024 PIDs. A full overlay,
ENOSPC, timeout or missing capability stays failed/blocked with sanitized bounded
diagnostics. The existing gptbox >=8GiB reserve, 900-second assembly and
180-second runtime limits are unchanged and are not bypassed by this probe.

On normal error/completion, remove only containers from this unique isolated
Podman root and its unique scratch directory/disks. No shared prune, cache reset,
loop mount or runner-wide cleanup occurs. SIGKILL/job cancellation can prevent
cleanup reporting; the finite container/job lifetime and disposable runner remain
the outer bound. Such a cancelled run supplies no completed cleanup evidence.
Public serial output is treated as untrusted candidate evidence: terminal and
workflow-command controls are escaped, tails are bounded, and truncation is
explicit. No qcow2, complete filesystem, environment or credential directory is
uploaded. `DP_PHASE`, `DP_SERIAL_TAIL`, `DP_REPORT` and the job summary distinguish
the exact attempted phases; fixture/local-test results never become Fedora passes.

## Dedicated report channel

Before starting QEMU, the controller creates an owned protected `result.in` and
`result.out` FIFO pair (`0600`) under the already scoped disks mount. It checks
type, ownership, mode and opened inode identity, and requires the fallback base
`result` to remain absent. QEMU receives a second `-serial pipe:/disks/result`;
no listener, broader mount, privilege or network change is added. A nonblocking
reader and controller-held writer prevent misleading startup EOF.

The guest writes directly to `/dev/ttyS1`, configured raw at115200 baud with
hardware flow control disabled. One frame contains `DP_FEDORA_REPORT_V1` plus LF,
at most65536 JSON bytes, and the fixed LF/`DP_FEDORA_REPORT_END`/LF footer. The
producer and consumer use the same constants from the hash-bound guest source.
Short writes and EAGAIN are handled; queue draining and native `tcdrain` share a
finite30-second write deadline before poweroff is requested. Normal poweroff is
requested only after successful write/drain return. A late drain failure may
leave complete bytes visible, so it propagates without normal shutdown; the
unchanged controller/native timeout then blocks executor success. Failure never
falls back to cloud-init stdout, and partial output cannot pass framing validation.

The controller concurrently drains console and result streams under the unchanged
aggregate8MiB limit. The report has its own JSON-plus-fixed-framing cap; reads
take at most the remaining allowance plus one overflow-detection byte. A result
requires executor exit0 and exactly one complete frame with the existing schema,
duplicate-key, source/script and phase checks. Extra bytes, duplicate frames,
partial records and legacy console markers are rejected. EOF alone never decides
completion. After executor exit, a one-second bounded drain handles buffered data
and held-open writers; local descendant groups and controller descriptors are
closed, while native container timeout/removal still bounds root conmon scopes.

`DP_REPORT` retains a safe structured witness on success/failure: retained byte
count/hash, cap/overflow flags, marker counts, exact head/tail hex and base64 for
the entire bounded report capture. CR/LF and malformed bytes therefore survive
console-tail truncation without emitting workflow commands. No unbounded console
dump is retained, and no truncated frame is accepted. FIFO/PTY/process tests prove
local transport behavior, not actual Fedora UART or hosted-runtime acceptance.

Podman4.9 requires its runroot path to fit within 50 characters. All probe state,
graph/runroot/tmp paths and disks therefore share one uniquely owned short
`/tmp/dpvm-*` leaf; capacity/accounting inspect that actual filesystem. The normal
long `RUNNER_TEMP` path remains an environment precondition, not the storage root.
Preflight/version-only failure deletes the verified owned scratch without needing
a functioning engine. After engine activity, deletion requires successful removal,
an empty inventory including external build containers, and no remaining mount
under scratch. Any uncertainty preserves scratch and reports cleanup failure.
UID, device/inode and nonsymlink identity are checked before deletion; unrelated
or replaced paths are never cleanup targets.
All controller log output uses central safe emitters covering both modern
`::command::` and legacy `##[command]` syntax. Structured JSON escapes introducer
characters inside strings, preserving valid JSON and exact decoded evidence,
including nested diagnostic fields and RPM manifests. Text tails visibly separate
command introducers; the structured report retains their original strings.

Run `python3 -m unittest discover -s tests -p test_fedora_ci.py -v` locally. The
committed checksum/key inputs are public official Fedora metadata used for real
isolated GPG verification and tamper/wrong-key rejection. Process tests actually
exercise file-size limits, killed descendant cleanup and output/time caps. Serial
and archive tests validate parsing and unsafe-member rejection only. This workspace
has no installed Podman/QEMU, so no image build or VM boot is claimed locally.

An eventual successful VM run can establish this Fedora VM's measured behavior.
It cannot prove designated Hostinger image/boot/recovery, Tailscale/SSH cutover,
authenticated/model calls, nested development placement, nightly renewal,
durable pair/session restoration, deployment or complete first-pair acceptance.
