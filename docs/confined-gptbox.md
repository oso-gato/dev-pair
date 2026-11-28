# Confined maintenance gptbox assembly and probes

[tools/gptbox.py](../tools/gptbox.py) now executes a genuine upstream Distrobox
assembly, seals its stopped image, creates a separate immutable runtime, enters
it through pinned upstream `distrobox-enter`, probes boundaries and Codex version,
and repeats entry after stop/restart. This is executable source with synthetic
engine tests only. **No Fedora/Podman assembly, confinement, authenticated agent,
model request or VPS operation has run here.** A passing local suite is not
runtime acceptance or completion of first bootstrap.

The shared [first-bootstrap initialize entry](fedora-bootstrap.md#shared-first-bootstrap-entry)
actually runs preparation then this adapter, retaining separate phase outcomes.
After authorized SELinux convergence and preparation, an authorized executor
can also run the standalone bounded adapter path:

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/gptbox.py assemble \
  --context /root/maintenance-context --expected-context-sha256 TRUSTED_CONTEXT_SHA256 \
  --distrobox-source /root/distrobox-1.8.2.5 --source-sha REVIEWED_FULL_SOURCE_COMMIT
# Same command plus --apply performs actual build/assembly/probe/cleanup.
# An incomplete unchanged target requires --apply --retry; at most two attempts.
```

Preview validates the Fedora host and reviewed inputs without changes. Apply
requires completed host preparation, enforcing SELinux, at least 8GiB free,
restricted `dp-maint`, its subordinate mappings and signed prerequisites,
including `slirp4netns`. It rejects fixtures. Contexts must be regenerated after
candidate source changes: manifests now use the approved per-role workspace,
state/cache classes and a separate protected credential namespace.

The first implementation accepts exactly the inspected amd64 Fedora44 manifest
`sha256:f1e66cdd6eff2c9ccad192f8865af9be6d69b46b3f13329d2975a2d61a1296c5`,
Codex0.169.0 binary SHA256
`b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b`,
and upstream Distrobox1.8.2.5 commit
`40c3cd724faa434aeb0a23e28776665b92de68bd`. The coordination handoff verified
that Codex binary using strict Cosign3.1.4 issuer/workflow/repository/tag/source
constraints and transparency checks; its official source is
`d32063f96c2dff1dc96af839b3952abb6acfeda4`. The [official signed release archive](signed-fedora-base.md) now authenticates
the Fedora base; exact import/save-back identity and actual signed package refresh
remain native execution gates. The old registry image signature was not established.
This adapter checks those exact reviewed byte identities, existing candidate
integrity/Git provenance and exact upstream Git objects; it does not fabricate
new upstream verification or silently accept another release. Transfer the
reviewed checkout, Git objects, upstream checkout and original evidence through
the authorized handoff, outside any mutable agent mounts.

The constructor deliberately replaces unsafe stock `distrobox-create`; no
upstream fork or plain-Codex-container substitution is claimed. It copies the
actual pinned init into the image and runs its real final hook after upstream
package/account/profile setup. The disposable staging recipe resolves the pinned
upstream setup_dnf architecture-specific dependency list from signed Fedora
metadata, installs available names with GPG/local-package checks, restores
required docs/locales/charmaps/UTC content and records exact RPM NEVRAs. It does
not create a fake setup marker or skip upstream init/finalization. Image pull and
build share a 600-second ceiling; the eight GiB reserve is measured again after
image construction before actual assembly. Repository resolution, TCG timing and
SELinux/rootless compatibility remain runtime gates. Assembly is a separate writable staging container
with private PID/IPC/UTS/user/network namespaces, no host bind mounts, bounded
CPU/memory/PIDs, default seccomp and retained SELinux `container_engine_t`.
Only this staging container receives mapped `SYS_ADMIN`; no privileged or
label-disable mode is used. Its private slirp network disables host loopback and
permits signed Fedora package setup. Failure/AVCs remain blockers, never grounds
to weaken confinement.

The immutable finalizer locks accounts, removes generated host bridges and
passwordless sudo, replaces host-derived startup code, inventories packages and
writes a content-bound assembly attestation. The controller requires that exact
attestation and stopped successful exit before committing the image. A new
runtime uses the real upstream init's fixed pre-init hook to enter immutable
frozen startup without repeating package/user/mount setup.

Runtime uses nonroot UID/GID1000, keep-id mapping to the restricted service user,
read-only image/home/CODEX_HOME, no capabilities, NNP, default seccomp, private
namespaces, no network and exact writable probe leaves under the maintenance
workspace/state/cache classes. Controller code/configuration, engine storage and
admission records remain outside those mounts. The offline profile uses
`--network=none`, `--no-hosts`, and `--no-hostname`. On Fedora Cloud 44, Podman
suppresses its generated resolver in this network mode. Live `/proc` checks
require loopback as the only interface and reject separate mounts for the
resolver, hosts and hostname files. The controller
inspects exact IDs, capabilities, labels, mappings, mounts, namespaces and
2GiB/256PID/one-CPU limits before entering. The image probe tests effective
UID/caps/NNP/seccomp/SELinux, rejected code/config writes, legitimate data writes
and absent host bridges. These checks need actual Fedora execution to establish
whether the proposed assembly domain/nesting interfaces work.

Entry uses the pinned real `distrobox-enter`, clean environment, supported
`DBX_CONTAINER_MANAGER=podman`, a protected PATH wrapper and immutable controller
HOME. The exact existing running target is checked before and after entry;
unsafe fallback creation has no installed create helper. Readiness requires a
new inspected `State.StartedAt` on each cycle, unchanged during the wait, and logs
scoped with `--since` to that actual start; a previous marker cannot pass restart.
Before maintenance entry, the current host controller also verifies the
running kernel view through the exact inspected PID and rechecks the start
identity. Retained signed images with older probes must pass this same check
before an import receipt is issued or a job starts.
Exact inspected `HostConfig.Tmpfs` paths/options are restricted to `/run` and
`/tmp`, separately from bind-mount inspection. Both assembly and runtime
explicitly request `notmpcopyup` so scratch mounts do not copy image contents.
Upstream Podman consumes that option before OCI generation, suppresses its
usual `tmpcopyup` default and adds `rprivate`; the guard accepts the resulting
inspected options while retaining the exact path/security/ownership policy.
Native OCI lifetime limits are
900seconds for staging and180seconds per probe start, with automatic restart
disabled and `Config.Timeout` inspected. They bound orphan candidates even if
Podman/conmon moves them outside the transient client's cgroup.
Stable context-scoped transient units prevent overlapping operations, with
per-operation runtime limits, control-group stop and longer client deadlines.
Explicit retry first stops/rechecks an owned busy executor and reconciles only
recorded context/image-matching container resources. Context bytes/cache are
reused; conflicting targets or exhausted build attempts block another build.
After two failed builds, up to two explicit cleanup-only reconciliations can
still remove exact owned resources, even below the free-space build threshold.
Neither cleanup allowance resets the execution budget.

Before image work, Podman must report the managed builder's full UID and GID
maps. If the installer reports cached single-ID maps during initial setup,
keep the provider recovery console available and reboot the host when
authorized. Reopen the recovery route and run `./day0.sh resume` from the same
verified checkout. The pause preserves the existing setup journal and does not
consume another build attempt.

Protected root records live under `/var/lib/dev-pair/bootstrap/gptbox-adapter`;
public immutable build bytes live separately under `/var/lib/dev-pair/artifacts`
so the rootless engine can read them without access to control state. Diagnostics
are restricted to credential-free assembly/probe commands: at most4MiB captured
per command, four recent and four failing records, each with16KiB stdout/stderr
tails in a protected0600 file. No credential/prompt stdin is accepted by that
logging path. Containers are removed after two successful probe/version cycles;
the sealed candidate and evidence remain. Reapply verifies the recorded image
before reusing completion evidence. This is recorded probe evidence, not a live
agent endpoint. Cleanup failures leave an incomplete target for bounded retry.

Only `probe` and `version` entry are allowed. No credentials are mounted and no
Codex job or model call can be launched. CODEX_HOME remains immutable until a
separately tested durable auth/session adapter and loader policy exist. Actual
unattended authentication, immutable project/plugin/skill/MCP rejection,
recorded model access, durable jobs/session restoration, nested development
placement, nightly renewal, full disk-quota enforcement, Tailscale endpoint
acceptance and first-bootstrap integration remain required and unverified.

Inspect schema/option references were upstream Podman commit
`a6a942f2ae0fc8ea001af86c2fd6322299c5a66c`,
`libpod/define/container_inspect.go` (`IDMappings.UidMap/GidMap` string triples,
`Memory`, `PidsLimit`, `NanoCpus`, `EffectiveCaps`, `BoundingCaps`, namespace
fields, `Config.Timeout` and `HostConfig.Tmpfs`) and the documented
no-hosts/no-hostname/dns/timeout options. The actual inspector maps native
container timeout into `Config.Timeout` and joins tmpfs option arrays into the
`HostConfig.Tmpfs` destination-to-options map; tmpfs entries are omitted from the
separate `Mounts` array. Fields missing on
the actual target block admission; synthetic schema fixtures do not establish
real Fedora compatibility. Fresh exact-candidate review and authorized host
failure/repair/retest evidence remain necessary before promotion.

Native execution now shares the [manager-opened stream transport](native-command-io.md).
Diagnostic-enabled probes retain4MiB aggregate capture; the ordinary/source-check
path stays1MiB. Private FIFO/stdin ownership and actual Fedora access remain
required runtime checks; no payload file-size restriction is introduced.


### One full image for fresh initialization

Fresh initialization now passes an internal freshly verified host-ready handoff
into the locked adapter transaction. The full existing adapter recipe is built
once; it is not relabelled as the original minimal Containerfile. Signed local
Fedora import/save-back verification, pinned inputs and expanded recipe hashes,
immutable image/platform and labels are checked before the closed versioned
candidate record and prepared storage observation/marker are published. Genuine
upstream initialization, finalizer attestation, sealing and both frozen
boundary/version cycles consume that same immutable base ID and keep their
existing security, ownership, retry and timeout limits. Public assembly after
legacy standalone preparation still preserves the original minimal record.

The selected full-image executor alone exposes closed bounded launcher summary,
constructed timing and load/save/build/inspect identity; its required non-quiet
launcher does not relax relay/profile/status admission. Image-stage records are
fixed typed evidence, not a payload-execution or cleanup claim. Raw image
launcher/payload diagnostic tails are withheld. No full native image, storage
quota, timing fit, authenticated runtime or renewal acceptance follows from local
source tests.


The adapter's rootless engine now receives a fixed `XDG_CONFIG_HOME` pointing to
an empty, protected root-owned `CONTROL/xdg-config` directory. HOME remains the
empty protected controller home, and `CONTAINERS_CONF` stays immutable. Existing
symlink/ownership/mode/content conflicts reject; no agent-writable mount includes
this directory. This bypasses a source-proven Podman 5.8.1 default that attempts
`HOME/.config` initialization. It does not prove the historical signed-load cause
or successful behavior of the Fedora downstream engine.

Only the exact source/context/UID-bound signed-load diagnostic scope retains
per-stream captured byte counts, SHA256 and completion/control flags before
image tails are suppressed. Missing/unverified capture is not published as a
complete empty stream. Complete verified exit-1 payloads can match only the exact
bare single-line reported stat ENOENT/EACCES or ownership forms at the fixed old
HOME config path. These are reported-message classifications, not causal facts.
Other paths, errno text, ANSI/multiline/truncated text and later Error-prefixed
wrappers remain unknown and hash-only. No raw text/environment/config is added.

The typed payload field is separately bounded to 1 KiB and validated again by
the guest public projection and controller report consumer. Existing native
failure/launcher, command capture, report, timeout/resource/security and cleanup
bounds stay unchanged. Matching native Podman/Fedora and distinct-owner DAC
acceptance remain required; local synthetic-engine and real-pipe tests do not
establish them. Standalone minimal preparation is unchanged.

## Install protected CI maintenance releases

Use the host-only route when protected CI supplies the maintenance image.
Prepare the host from the verified public-input extraction of the reviewed
checkout, maintenance context and pinned Distrobox checkout. Mount the
dedicated, fully allocated managed ext4 and leave the required physical host
reserve before applying this command.

```sh
/usr/bin/python3 /root/dev-pair-bootstrap-source/tools/gptbox.py prepare-maintenance-host \
  --context "$MAINTENANCE_CONTEXT" --expected-context-sha256 "$MAINTENANCE_CONTEXT_SHA" \
  --distrobox-source "$VERIFIED_DISTROBOX_CHECKOUT" --source-sha "$HOST_PREPARATION_SOURCE_SHA" \
  --bootstrap-source "$AUTHORIZED_BOOTSTRAP_CIDR" --password-file "$CORE_PASSWORD_FILE" --apply
```

The source, context and access checks also run in preview mode. Use
`--provider-ssh` on the CIDR route when the approved provider console uses an
SSH-backed transport. For the independently verified out-of-band transport,
use the signed `--console-receipt` instead of a bootstrap CIDR. The existing
bootstrap authority validates the actual transport. The host-only command
prepares host prerequisites, restricted service accounts, private roots and
the fixed maintenance gateway. It publishes the protected host prepared
marker after verification. An interrupted preparation retains its exact
target, with one explicit same-target retry. The local build route remains
available through `initialize` and `assemble`.

The release installer runs this pair of checks against the exact accepted
role artifact. It runs `preflight` before rootless OCI load, then `verify`
after measuring the imported image and writing the protected, boot-bound
`maintenance-import.json` in the release intake directory.

```sh
/usr/bin/python3 -B "$VERIFIED_HOST_DRIVER/tools/gptbox.py" verify-installed-maintenance \
  --phase preflight --platform-sha256 "$PLATFORM_SHA" --context-sha256 "$MAINTENANCE_CONTEXT_SHA" \
  --source-sha "$RELEASE_SOURCE_SHA" --image "$MAINTENANCE_IMAGE_ID" \
  --oci-manifest-sha256 "$MAINTENANCE_MANIFEST_SHA"
```

Use the same exact arguments with `--phase verify` for the post-import check.
The driver reads the signed portable index, protected intake receipt and
producer metadata bound to the index. It independently inspects the intended
rootless VFS store and selected OCI manifest, config, layers and labels. The
imported image then completes two credential-free, confined Distrobox
probe/version cycles. Each cycle also reads and checks the image-owned input
and Distrobox seal. Probe cleanup verifies the exact owned container is gone
and removes its empty temporary leaves.

The protected local admission lives at
`/var/lib/dev-pair/bootstrap/gptbox-adapter/<context>/imported-releases/<platform>/<image>/<boot>.json`.
Each immutable receipt binds the current boot, signed platform and producer
record to the selected image. Releases that reuse the same artifact each keep
their own proof, so rollback retains the original release's evidence.
Re-observe the installed image through the installer after reboot to publish
the new boot-specific proof. The original CI producer result stays in the
portable artifact. The locally assembled route checks the protected candidate,
bounded assembly attempt and resource inventory, Distrobox attestation and
completion that bind the selected sealed image.
The normal [maintenance role entry](role-entry.md) accepts the exact local
admission and still applies its separate job and provider gates.

The source-level fixture exercises the CLI, protected records, ordering,
two simulated native cycles and cleanup. The release installer and image
need verification together on the designated enforcing Fedora host.
