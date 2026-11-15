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
`sha256:48f4a2b507ad36a6a8bb83646ee81164aff80a62be06d03b143b80594d2b558e`,
Codex0.169.0 binary SHA256
`b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b`,
and upstream Distrobox1.8.2.5 commit
`40c3cd724faa434aeb0a23e28776665b92de68bd`. The coordination handoff verified
that Codex binary using strict Cosign3.1.4 issuer/workflow/repository/tag/source
constraints and transparency checks; its official source is
`d32063f96c2dff1dc96af839b3952abb6acfeda4`. Fedora registry/config digest and
architecture were inspected; a Fedora image signature was not established.
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
admission records remain outside those mounts. Host integration files are kept
image-owned using `--no-hosts`, `--no-hostname`, `--dns=none`. The controller
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
