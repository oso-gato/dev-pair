# Fedora Cloud 44 bootstrap

This is executable host preparation, implemented in [tools/bootstrap.py](../tools/bootstrap.py).
Initialization has been attempted in disposable Fedora CI, but **preparation and
maintenance assembly have not completed**. No designated VPS execution has
occurred. See [the work record](dr10-work-record.md) for candidate-bound results.
Local fixtures test control flow and filesystem transactions; they are not
installation, firewall, SSH, reboot or Tailscale evidence. Use only an authorized fresh Fedora
Cloud 44 target after exact-candidate independent review and host inspection.
The shared `initialize` entry runs host preparation followed by genuine confined maintenance Distrobox assembly and probe-only entry. This is source capability, not first-bootstrap runtime acceptance. No job, authentication, enrollment or model request is admitted.

The scope is initial provisioning under R7.1/R7.18, A1/A7.5/A8.4. This does not
complete R7.16–R7.18 or A12.12(1). The deployed pair, confined Distrobox placements,
immutable runtime enforcement, workload tailnet routes, CI, renewal and session
restoration remain separate work. The bootstrap installs Podman and Distrobox
prerequisites without using privileged containers, SELinux exceptions, host
sockets or historical live-clone installers. The A11 agent lifecycle code is
not adapted or executed here.

## Shared first-bootstrap entry

Use the exact reviewed source and independently verified public maintenance inputs.
The mandatory source SHA must identify the executing checkout HEAD and context;
the upstream checkout HEAD/scripts must identify pinned Distrobox1.8.2.5.

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py initialize \
  --gptbox-context /root/maintenance-context --expected-context-sha256 TRUSTED_CONTEXT_SHA256 \
  --source-sha REVIEWED_FULL_SOURCE_COMMIT --distrobox-source /root/distrobox-1.8.2.5 \
  --password-file /root/core-password --bootstrap-source 192.0.2.9/32
# Add --apply only on an authorized target after preview/review.
```

This thin entry shares the existing real prepare/adapter implementations. It
releases the prepare lock before assembly takes it, while a separate initializer
lock prevents another initializer. `initialize.json` records the exact target,
separate pending/complete/blocked prepare and maintenance phases, elapsed times,
and a result only after genuine assembly,
sealing and two frozen runtime probe/version cycles. `status` exposes this record;
`prepared` alone remains prerequisite evidence. A partial unchanged target needs
explicit `--apply --retry`; a changed target is rejected. Adapter limits remain
two build attempts and two cleanup-only attempts. Reapply revalidates the actual
prerequisite image and the sealed image's ID/source/context/upstream labels,
plus the protected complete result. It cannot promote a stale completion file.

If Git is initially absent, Python-only context/pin/protection checks precede the
signed minimal `git-core` prerequisite. Complete context/source/upstream Git
verification then runs before desired binding or ordinary host changes. No
submitted recipe or arbitrary command is executed. The filesystem/controller
must remain trusted; Git/SHA metadata is identity, not remote authentication.

Initialization has a 2280-second execution ceiling, a 600-second prepare phase
(including public key fetching), a 1620-second adapter phase and at most a
45-second exact-resource cleanup attempt after adapter failure, all clipped to
remaining execution time. Separate command runners inherit the earliest enclosing
absolute deadline for timers, native limits and successful boundary checks.
An interrupted capture kills its owned process group and reconciles its exact
native unit even when the direct launcher already exited. An interrupted command has at most45seconds of
additional process/native-stop cleanup grace; this does not enlarge any native
component lifetime. Adapter image pull/build share 600 seconds. Existing
900-second assembly and 180-second runtime native OCI lifetimes stay unchanged.
Normal host commands use finite owned transient cgroups; root unit names are
persisted before launch, and retries verify their descriptions/owners before
stopping them. User executor units use the exact context identity and the same
ownership check. Native `RuntimeMaxSec` never grows beyond its component or
remaining phase ceiling. CLI process-group termination is not proof that an
escaped engine process stopped: only recorded candidate resources are reconciled;
uncertain cleanup is recorded as blocked, with native lifetimes retained.
Actual Fedora systemd/Podman cleanup remains an acceptance gate.

Commands capture at most 1MiB combined output; preparation keeps four recent and
four failed protected diagnostic records. Only fixed public signed-package and
candidate-image operations retain 8KiB stream tails, with truncation/byte metadata.
All stdin-bearing operations discard child output and never record stdin,
argv or environment. Environments are fixed and credential-free. Standalone
`prepare` is the prerequisite operation; it does not claim complete initialization.

## Preconditions and preview

Run the separate [initial SELinux convergence](selinux-bootstrap.md) first when
the provider image is Disabled or Permissive. It stages a checked full relabel
and automatically finalizes across explicitly authorized setup reboots. Existing
Enforcing hosts are preserved; permissive mode alone is insufficient. Normal
prepare refuses an incomplete recorded transition even if live enforcement has
already been enabled. These are source capabilities with no Fedora runtime
acceptance yet.

The authorized executor verifies the designated host SSH fingerprint through an
independent trusted channel, inventories disks/data/services and confirms a usable
provider-console recovery route. Keep the original session open throughout.
Select the exact reviewed Git commit and record its SHA and bootstrap file hash
outside the target. Transfer the exact reviewed repository checkout, including Git objects for the manifest source revision and `tools/candidate.py`, as root-owned code under `/root/dev-pair-bootstrap-source`; do not execute a
moving branch, a submitted candidate manifest or an arbitrary download script.
The following commands are for that executor on the designated **Fedora host**,
not the development machine. Examples use reserved documentation CIDRs; replace
them with explicitly authorized executor source CIDRs before execution.

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py inspect
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py prepare \
  --operator core --password-file /root/core-password \
  --gptbox-context /root/maintenance-context --expected-context-sha256 TRUSTED_CONTEXT_SHA256 \
  --bootstrap-source 192.0.2.9/32 --bootstrap-source 2001:db8::9/128
```

`prepare` and `enroll` default to read-only inspection. Only `--apply` performs
changes. First preparation requires an external root-owned 0600 password file,
with no symlinks or group/world-writable path components. Supply the password
through the executor's secure secret channel, never in a command argument,
environment variable, transcript or repository. It must contain one nonempty
line (optional final LF), no colon/control characters, and at most 1024
characters. Keep it outside transferred source/context and remove it through
that channel once setup is confirmed. The tool does not delete external secrets.
Keys come only from `https://github.com/oso-gato.keys`: no local-key substitute,
redirect or proxy. Fetch uses normal TLS certificate validation, up to three
attempts, each in a disposable isolated Python child with a hard twenty-five-
second parent timeout covering DNS, TLS, headers and body. Inside it, a five-
second socket timeout, twenty-second read deadline and 256KiB body limit also
apply. At most 256 unoptioned Ed25519, RSA, ECDSA or
OpenSSH security-key entries are accepted; every entry must pass base64/type
and actual `ssh-keygen` parsing. Validation has a twenty-second deadline plus
at most five seconds for the final key check. Empty, malformed, over-limit,
redirected or failed responses leave previously admitted keys untouched.
Comments are discarded and duplicates collapse; every distinct admitted key
is imported. Key validation/fetch also occurs during read-only preview. Root, Fedora44, x86_64/aarch64,
host systemd PID1, enforcing SELinux, valid existing OpenSSH on port22, and an
otherwise vanilla listener inventory are mandatory. Competing active firewalld
or nftables services and foreign nft tables are rejected without disabling them.
Verified root-owned tailscaled PeerAPI listeners are allowed only on this node’s observed assigned Tailscale addresses, so successful enrollment does not break reapply. This deliberately reports a blocker on a provider image with existing services
or network policy; it does not guess how to preserve arbitrary configurations.
The actual stock-Fedora run7 discovery inventory is retained as a parser fixture.
Before preparation only, port5355 is recognized solely for the verified active
`systemd-resolved.service` main PID, protected official executable, service UID
and exact system cgroup. Name/port alone is insufficient. Preparation writes
`/etc/systemd/resolved.conf.d/90-dev-pair-discovery.conf` with `LLMNR=no` and
`MulticastDNS=no`, verifies the merged Resolve settings, restarts the verified
service and rejects surviving discovery listeners. It checks retained SSH and
loopback DNS endpoints. Override, restart, process/service mismatch and unrelated
listeners block completion. After `prepared`, discovery listeners are rejected
even when their service identity matches. No firewall or SELinux exception is
introduced; effective target behavior still needs the next authorized run.

The actual current SSH source must be in the declared CIDRs before apply.

## Maintenance gptbox inputs

Before any state, account, network or normal package changes, Python-only checks verify the context hash, exact file/schema/recipe/binary contents, maintenance role and x86_64 platform. An invalid input leaves no immutable desired binding; correcting the hash or inputs can be retried. First bootstrap requires `--gptbox-context` and a separately recorded trusted
`--expected-context-sha256`; there is no implicit/latest image or fixture fallback.
Use [candidate preparation](candidate-preparation.md#supply-real-inputs-without-inventing-pins)
with **role `maintenance`**, actual upstream-verified Fedora44 digest/Codex binary,
explicit model/effort, the current exact candidate-tool source revision and the
adopted standards pin. Transfer the four resulting files into a root-owned
protected context directory. Refresh contexts after the verifier source change;
prior context provenance is not silently upgraded. The current binary recipe is
x86_64-only; ARM bootstrap preparation cannot complete the host-gptbox build yet.
Official Fedora 44 manifest/configuration digests and the stable Codex 0.169.0
binary have now been inspected; Codex's official Sigstore bundle passed strict
verification. The exact identities and remaining Fedora image-signature gap are
recorded in [the work record](dr10-work-record.md#actual-upstream-inputs-and-corrected-transport-evidence).
These checks do not establish an OCI build or Fedora runtime result.
`TRUSTED_CONTEXT_SHA256` in the commands is a required
handoff value, not an executable sample pin. The CLI rejects missing inputs.

## Prepare

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py prepare --apply \
  --operator core --password-file /root/core-password \
  --gptbox-context /root/maintenance-context --expected-context-sha256 TRUSTED_CONTEXT_SHA256 \
  --bootstrap-source 192.0.2.9/32 --bootstrap-source 2001:db8::9/128
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py status
```

Preparation installs signed RPMs using Fedora's `fedora`/`updates` repositories
with GPG checking, and the official Tailscale stable Fedora repository with
package and repository signature checking. It does not run a remote installer.
The exact installed package versions are retained in
`/var/lib/dev-pair/bootstrap/packages.txt`; upstream versions are resolved by the
signed repositories at execution time rather than reproducibly pinned RPMs.
Network/package failure may leave installed prerequisites; reapply reconciles
that partial state. This is authorized initial platform provisioning, not
permission for product jobs to install into a running host.

The fixed human operator `core` gets a private group and password-gated sudo;
its password also supports authorized provider-console login. Before unlocking
the new account, preparation installs, validates and reloads the effective
key-only SSH policy. A later password/marker failure retains that restriction,
so the initial global SSH password setting cannot expose the newly set password. `chpasswd` receives
the password only on stdin, with child output withheld. Neither plaintext nor
password hash is recorded in state, argv or images. The protected completion
marker is written only after `passwd -S` reports a usable password. Before that
marker, a failed/interrupted attempt may retry the externally supplied input.
After the marker exists, `--password-file` is optional and rerunning prepare
never resets or relocks `core`; any supplied password is ignored. An unexpectedly
locked/unusable account blocks for separately scoped recovery. Password rotation
is an explicit operator action, not an implicit consequence of prepare.

The imported keys remain root-owned under `/etc/ssh/dev-pair-keys/core`, outside
`core`'s writable home. A protected hash intent permits atomic key rotation and
retry on either side of an interrupted rename; conflicting unmanaged changes
block. Password and initial SSH stay available if fetching/validation fails.
The named-user Match block requires public-key authentication and denies
password/keyboard-interactive SSH even though the local password is usable.
`sshd -t` and effective `sshd -T -C` settings must pass before reload. Full sudo
syntax and effective core policy are checked for password bypass. Existing
root/global authentication policy is retained pending verified cutover. The new
SSH fragment is removed on initial validation failure; an admitted fragment is
preserved on retry. No existing unmanaged account is automatically adopted.

Signed Fedora `mosh`, `tmux` and `chrony` packages are installed. Interactive
`core` Bash sessions with terminal input/output attach the durable
`dev-pair-core` tmux session; reconnect returns to that session. Remote commands,
scp/sftp and mosh's noninteractive SSH startup retain their normal protocol.
Use `mosh core@TAILSCALE_IP` from an authorized tailnet client; plain SSH remains
supported. The guard allows mosh UDP60000–61000 only through `tailscale0` and
explicitly drops that range on other interfaces before established-state
acceptance. A managed sysctl reserves those ports from outbound ephemeral
allocation, preserving/merging existing reserved ranges; drift that conflicts
with its root-owned configuration blocks rather than overwriting foreign state.
Only an actual managed-core `/usr/bin/mosh-server` listener in that range is
accepted on reapply. This terminal continuity does not prove agent job recovery,
container replacement or restart acceptance.

`hostnamectl` sets and observes the persistent lowercase `erebus` hostname;
a cloud-init `preserve_hostname: true` drop-in prevents normal provider-name
replacement. Chronyd is enabled/started and queried. Configuration/daemon
observation is not evidence that synchronization or reboot persistence passed.
These mechanisms were informed by A11's pinned host reference; historical
bootstrap code/policy was not copied or executed.

`dp-maint` and `dp-dev` are separate locked, nologin runtime accounts with private
groups, no sudo grants (checked using `sudo -l`) and explicit SSH denial. Each receives 65536
nonoverlapping subordinate UIDs/GIDs, beginning at 1000000 and 1065536; overlap or
existing conflicting users/configuration fails. Linger permits future systemd
user supervision. User-slice limits are 2GiB memory, 512 tasks and 100% CPU per
role. Durable 0700 role directories live under `/var/lib/dev-pair/{maintenance,development}`:
workspaces, checkpoints, evidence, deliverables, builds, cache and state.
Directory creation/ownership changes use nonfollowing directory descriptors, so mutable runtime-owned parents cannot redirect root writes. No recursive ownership change, cleanup, data deletion or automatic account
adoption occurs. Existing storage is preserved. Runtime jobs remain disabled:
the 20GiB storage budget, 8GiB reserve and seven-day inactive retention are
recorded defaults, **not enforced quotas or an implemented cleanup policy**.
Those controls must be implemented before jobs start.

An atomic nftables batch owns only `inet dev_pair_bootstrap`, with default-drop
input and forwarding. It permits established connections, loopback, SSH22 from
the explicit bootstrap CIDRs and `tailscale0`, tailnet-only mosh, Tailscale UDP41641, ICMP and DHCP.
It neither flushes other tables nor launches applications. A root-owned systemd
unit reapplies the guard at boot and is required before tailscaled starts.
The forward drop intentionally prevents bridge/subnet forwarding; a later
reviewed deployment must define tested workload routes. No claim is made that
this unit alone establishes fail-closed boot behavior for future applications.
Initial public SSH/root remains a **temporary, source-scoped bootstrap route**.
This is not final private administration or completed root retirement.

## First-bootstrap image build and its limit

Prepare and its read-only preview check the real context using `candidate.py`, reconstruct the only permitted Containerfile, and reject fixtures, changed bytes, unsupported architecture and development-role contexts **before host mutation**. With Git available, full source-object verification also occurs before mutation. On a vanilla host without Git, only a minimal signature-checked Fedora `git-core` prerequisite is installed; full source verification must then pass before immutable desired binding, normal packages, accounts or ingress changes. That prerequisite may remain if source verification fails, with no admitted desired target. Preview reports source verification pending instead of admitting the candidate. There is no verifier CLI bypass for source checks. The context is checked again before staging and the protected staged bytes receive full verification before any engine call. Verification checks source Git bytes using a fixed Git executable
and clean environment. It does not independently authenticate upstream operator
evidence. Root-owned 0444 snapshots under
`/var/lib/dev-pair/artifacts/gptbox/<context-sha256>` prevent runtime-user changes
to the bytes used by the builder; interrupted file staging is reconciled safely.
These files contain only public build inputs, never authentication credentials.

The executor starts the `dp-maint` user manager, then fixed transient systemd
services run Podman as `dp-maint`, with a clean environment, separate vfs storage
under `/var/lib/dev-pair/maintenance/images`, a 600-second runtime bound, 2GiB RAM,
512 tasks and 100% CPU. The context-specific service identity prevents another
operation starting while a timed-out client leaves an engine command running;
systemd kills the operation's complete cgroup on its own time limit. Reattempts
while that unit still exists fail rather than duplicate the build. These actual
systemd/Podman semantics still require Fedora validation.

Podman pulls the manifest's exact official Fedora digest, then builds the verified
recipe with networking disabled and pulling disabled. The recipe has no `RUN`,
installer, Distrobox invocation, secret mount or submitted command. There is an
8GiB free-space admission reserve; the build timeout and official fixed inputs
bound this one operation, but vfs storage quotas/cleanup remain unimplemented.
The build's returned immutable image ID is inspected directly. Public labels and
local tags alone never authorize artifact reuse: a retry requires the prior
root-protected completion record and matching image ID/context. Without that
completion record an interrupted build is rebuilt from the same verified inputs.

`status` returns the root-protected result from
`/var/lib/dev-pair/bootstrap/gptbox-image.json`: actual image ID, context/source/base
identities, Codex hash and runtime account. The candidate tag is
`localhost/dev-pair/maintenance-gptbox:<context-sha256>`. It is a local OCI candidate,
not a registry release digest, running agent, verified CLI/auth adapter or
Distrobox-assembled image. The existing source-only recipe does not preassemble
Distrobox dependencies/user/init, and the bootstrap never calls stock Distrobox
create/assemble/enter. No development-role gptbox is built in this bootstrap step.

This preserves the intended host → Distrobox maintenance gptbox architecture
without silently weakening isolation. Official Distrobox1.8.2.5 source at
[`40c3cd724faa434aeb0a23e28776665b92de68bd`](https://github.com/89luca89/distrobox/blob/40c3cd724faa434aeb0a23e28776665b92de68bd/distrobox-create#L689)
unconditionally adds `--privileged`, `label=disable`, root user and broad host/home
mounts. `--unshare-all` does not remove those options. Its
[init integration](https://github.com/89luca89/distrobox/blob/40c3cd724faa434aeb0a23e28776665b92de68bd/distrobox-init#L1962)
links host sockets. These concrete conflicts with A1.2/A2.4/A10.5 block stock launch.
A confined immutable Distrobox assembly/adapter must be implemented and tested as
a new candidate before any maintenance agent starts; plain Podman launch is not
substituted for the required Distrobox layer.

## Enroll and enter

Place a minimally scoped, short-lived enrollment key in an external root-owned
0600 file (no symlinks or group/world writable path). Do not put its value in an
argument, environment variable, source, transcript or image. The tool passes
only Tailscale's documented `--auth-key=file:/path` reference and withholds all
command output on errors and timeouts. Remove the external file after confirmed
enrollment and revoke the enrollment credential when appropriate; the bootstrap
does not delete externally managed secrets.

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py enroll --apply \
  --auth-key-file /root/tailscale-enrollment.key --tailnet example.ts.net
sudo tailscale ip -4
# From a separately authorized tailnet client, using its private SSH key:
ssh core@TAILSCALE_IP
# In that core session: clear cached sudo credentials, then verify a password is required.
sudo -k
sudo -n true  # must fail
sudo -v       # enter the external core password through the terminal
sudo true
```

`--tailnet` must equal the intended tailnet's exact `CurrentTailnet.Name`.
The [official Tailscale status schema](https://github.com/tailscale/tailscale/blob/v1.82.5/ipn/ipnstate/ipnstate.go#L66-L68)
permits `CurrentTailnet: null` while disconnected. Nullable `CurrentTailnet` and
`Self` identity fields are normalized as absent; this permits a normal initial
NeedsLogin enrollment or eligible stopped retry. A Running node still needs both
the expected non-null tailnet name and actual node ID before acceptance. Intent
reconciliation/persistence for a resumed unverified Running node remains inside
the disconnect-on-failure transaction.
The node ID is recorded and must remain consistent on retry. An unrelated
already-running node is never adopted. A successful-but-wrong tailnet is taken
down before reporting failure; the initial SSH route stays in place and external
credential revocation may still be needed. A failed/timeout enrollment command, post-enrollment status observation/JSON decode, node validation, persistence or completion-journal write takes the new unverified node down because the daemon may already have enrolled. Disconnect does not depend on a working journal. A partially visible new node-completion marker is removed after disconnect. Previously accepted unchanged nodes are not disconnected merely because a retry cannot observe their status. A failed disconnect is reported as a
failure, not a claim of isolation. Existing accepted nodes are not automatically
reauthenticated or reset after losing enrollment. A crash after daemon enrollment
but before `node.json` creates an **unverified** running attempt; same-intent
retry validates/persists that node inside the same disconnect-on-failure
transaction, without repeating `tailscale up`. An explicit `enroll --apply` may
retry a stopped **unverified** attempt only when the protected intent matches,
no accepted node record exists, and the observed tailnet is the expected one or
absent. It uses the supplied external auth-file reference with the normal fixed
flags, never reset/force-reauth. An accepted stopped node always requires separate
controlled recovery. A previously observed wrong tailnet creates a root-protected
recovery-required record, remains down, and cannot be retried merely because a
later daemon response omits that identity. Such mismatches need a separately
scoped operator recovery with credentials checked/revoked/replaced as appropriate;
this tool provides no override or generic state deletion command.

Enrollment disables Tailscale SSH, DNS/route acceptance, exit-node advertising
and Tailscale-managed netfilter rules. Ordinary key-authenticated OpenSSH runs
over Tailscale; tailnet ACLs/grants must independently restrict authorized clients.
Node `Running`, a local status record or a listener is not proof of remote access.
The recorded enrollment retry still requires the external secret file to exist,
but does not consume its contents or re-enroll a running accepted node.

## Interruption and recovery

A nonblocking exclusive lock serializes mutations. Root-private desired state
binds operator/key hash, source CIDRs, source baseline, standards pin and exact
bootstrap file hash. Journal entries are flushed before each stage and after
completion/failure. Re-run the **same exact file and inputs** after a package,
command or connection failure; it rechecks actual configuration rather than
trusting a completed marker. Changes to admitted inputs/configuration are rejected
and require a separately reviewed maintenance operation. Atomic file writes and
nft transactions avoid partially written configurations. The first invocation
never disables root SSH or removes the initial SSH route.

Use the retained initial source-scoped SSH session or independently verified
provider console to diagnose failure. Read the root-private journal and command
state locally; do not publish enrollment output or secrets. Do not remove the
ingress guard as a generic fix. Do not delete account homes, state directories,
subordinate mappings or package data to force a rerun. Taking Tailscale down does
not remove the initial SSH route or guard. An operator can recover via the
provider console even with the pair/tailnet absent; this must be exercised live.
There is no automatic destructive uninstall or automatic SSH cutover in this slice.

`finalize` always exits2 with an explicit blocker. It accepts no fake evidence
flags/files. Before a subsequent cutover implementation can disable direct root
and public SSH, the authorized executor must return candidate-bound evidence:

1. Actual new named-admin SSH login from a separate authorized tailnet client,
   using only the admitted key; working sudo and password/root rejection tests.
2. Actual provider-console recovery login and named-admin recovery while the
   tailnet and pair are unavailable, under scoped authority with no app ingress.
3. Full effective SSH configuration for applicable Match cases, authorized and
   unauthorized/public connection tests, route/listener/firewall inventory and
   tailnet-loss denial. Include IPv4 and IPv6.
4. A staged, timed automatic rollback tested through failed validation, interrupted
   cutover and reboot, preserving the independent recovery route; only then commit
   final root/public-SSH retirement.

These are executor tasks owned by the development workflow, not owner code-review
or worker-coordination tasks. No live evidence or production readiness is claimed.

## Local verification and official references

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m py_compile tools/bootstrap.py
python3 tools/bootstrap.py --help
```

Tests use isolated temporary roots and fake system commands. They cover replay,
interruption, locks, state/configuration conflicts, subordinate overlap, SSH
validation failure without reload, bootstrap-source lockout prevention, secret
redaction, wrong-tailnet disconnect including command failure after daemon side effects, authenticated PeerAPI classification, directory symlink-race rejection, verified rootless build handoff, image-ID reuse, recipe/fixture/role rejection, engine failure and cutover refusal. They cannot validate
RPM/repository installation, actual SSH authentication, nft syntax/kernel behavior,
SELinux, systemd/resource limits or external reachability.

Official sources checked in this development task:
[Fedora Podman](https://packages.fedoraproject.org/pkgs/podman/podman/fedora-44.html),
[Distrobox](https://packages.fedoraproject.org/pkgs/distrobox/distrobox/fedora-44.html),
[Tailscale Fedora repo](https://pkgs.tailscale.com/stable/fedora/tailscale.repo),
[Tailscale up flags/file auth key](https://tailscale.com/kb/1241/tailscale-up),
[Tailscale SSH authentication](https://tailscale.com/kb/1193/tailscale-ssh),
[nftables base-chain semantics](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
Package-page existence is not a verified installation on the target.

## Required host acceptance for operator access

Independent review and an authorized designated Fedora target must still prove:
all owner account keys can authenticate, password/keyboard-interactive SSH is
rejected, `core` console password works, sudo refuses without a password and
succeeds with it, both runtime accounts remain locked/nologin without sudo,
noninteractive SSH/scp/sftp and mosh negotiation are intact, reconnect over mosh
and SSH resumes the same tmux work, public/unauthorized UDP is rejected even
with prior conntrack state, and tailnet loss exposes no fallback. Reboot must
retain `erebus`, the guard, reservation and tmux configuration; chronyd must
actually synchronize. Existing final root retirement/recovery evidence remains
required. A previously prepared candidate from the former arbitrary-operator/
NOPASSWD schema is not migrated automatically; protected desired/configuration
conflicts require a separately reviewed migration. No deployed host exists in
the local evidence for either schema.

A separate [confined maintenance gptbox assembly/probe path](confined-gptbox.md)
now implements an owned constructor with genuine upstream init/entry. It is not
called automatically by prepare and has no real Fedora/OCI acceptance yet.
Stock unsafe Distrobox creation remains blocked; authenticated agent, model,
nested placement and complete first-bootstrap acceptance remain pending.
