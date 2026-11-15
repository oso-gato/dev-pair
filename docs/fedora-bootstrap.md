# Fedora Cloud 44 bootstrap

This is executable host preparation, implemented in [tools/bootstrap.py](../tools/bootstrap.py).
It has **not been run on Fedora or the designated VPS**. Local fixtures test the
control flow and filesystem transactions; they are not installation, firewall,
SSH, SELinux, reboot or Tailscale evidence. Use only an authorized fresh Fedora
Cloud 44 target after exact-candidate independent review and host inspection.
The first bootstrap now builds a Fedora/Codex OCI candidate for the host maintenance gptbox. No application or agent is launched; Distrobox assembly/admission remains blocked for the concrete isolation reasons below.

The scope is initial provisioning under R7.1/R7.18, A1/A7.5/A8.4. This does not
complete R7.16–R7.18 or A12.12(1). The deployed pair, confined Distrobox placements,
immutable runtime enforcement, workload tailnet routes, CI, renewal and session
restoration remain separate work. The bootstrap installs Podman and Distrobox
prerequisites without using privileged containers, SELinux exceptions, host
sockets or historical live-clone installers. The A11 agent lifecycle code is
not adapted or executed here.

## Preconditions and preview

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
  --operator devpair-admin --public-key-file /root/operator.pub \
  --gptbox-context /root/maintenance-context --expected-context-sha256 TRUSTED_CONTEXT_SHA256 \
  --bootstrap-source 192.0.2.9/32 --bootstrap-source 2001:db8::9/128
```

`prepare` and `enroll` default to read-only inspection. Only `--apply` performs
changes. Public keys must be one valid unoptioned Ed25519 key in a root-owned
file with no writable or symlink path components. Root, Fedora44, x86_64/aarch64,
host systemd PID1, enforcing SELinux, valid existing OpenSSH on port22, and an
otherwise vanilla listener inventory are mandatory. Competing active firewalld
or nftables services and foreign nft tables are rejected without disabling them.
Verified root-owned tailscaled PeerAPI listeners are allowed only on this node’s observed assigned Tailscale addresses, so successful enrollment does not break reapply. This deliberately reports a blocker on a provider image with existing services
or network policy; it does not guess how to preserve arbitrary configurations.
The actual current SSH source must be in the declared CIDRs before apply.

## Maintenance gptbox inputs

First bootstrap requires `--gptbox-context` and a separately recorded trusted
`--expected-context-sha256`; there is no implicit/latest image or fixture fallback.
Use [candidate preparation](candidate-preparation.md#supply-real-inputs-without-inventing-pins)
with **role `maintenance`**, actual upstream-verified Fedora44 digest/Codex binary,
explicit model/effort, the current exact candidate-tool source revision and the
adopted standards pin. Transfer the four resulting files into a root-owned
protected context directory. Refresh contexts after the verifier source change;
prior context provenance is not silently upgraded. The current binary recipe is
x86_64-only; ARM bootstrap preparation cannot complete the host-gptbox build yet.
No real upstream digests or Codex release inputs have been invented or acquired
by this source-only task. `TRUSTED_CONTEXT_SHA256` in the commands is a required
handoff value, not an executable sample pin. The CLI rejects missing inputs.

## Prepare

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/bootstrap.py prepare --apply \
  --operator devpair-admin --public-key-file /root/operator.pub \
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

The named operator gets a private group, locked password and explicit
passwordless sudo administration. This is the human/operator recovery identity,
never the maintenance agent's identity. Its admitted public key is root-owned
under `/etc/ssh/dev-pair-keys`, readable for OpenSSH authentication and outside
the user's writable home. A named-user Match block requires public-key auth;
`sshd -t` and effective `sshd -T -C` settings must pass before reload. Existing
root/global authentication policy is retained. The new fragment is removed on
initial validation failure; an already admitted fragment is preserved on retry.

`dp-maint` and `dp-dev` are separate locked, nologin runtime accounts with private
groups, no sudo membership and explicit SSH denial. Each receives 65536
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
the explicit bootstrap CIDRs and `tailscale0`, Tailscale UDP41641, ICMP and DHCP.
It neither flushes other tables nor launches applications. A root-owned systemd
unit reapplies the guard at boot and is required before tailscaled starts.
The forward drop intentionally prevents bridge/subnet forwarding; a later
reviewed deployment must define tested workload routes. No claim is made that
this unit alone establishes fail-closed boot behavior for future applications.
Initial public SSH/root remains a **temporary, source-scoped bootstrap route**.
This is not final private administration or completed root retirement.

## First-bootstrap image build and its limit

After the signed prerequisites and isolated accounts exist, prepare verifies the
real context using `candidate.py`, reconstructs the only permitted Containerfile,
and rejects fixtures, changed bytes and development-role contexts **before any
engine call**. Verification checks source Git bytes using a fixed Git executable
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
ssh devpair-admin@TAILSCALE_IP
sudo -n true
```

`--tailnet` must equal the intended tailnet's exact `CurrentTailnet.Name`.
The node ID is recorded and must remain consistent on retry. An unrelated
already-running node is never adopted. A successful-but-wrong tailnet is taken
down before reporting failure; the initial SSH route stays in place and external
credential revocation may still be needed. A failed/timeout enrollment command also takes Tailscale down because the daemon may have enrolled before the CLI failed. A failed disconnect is reported as a
failure, not a claim of isolation. Existing accepted nodes are not automatically
reauthenticated or reset after losing enrollment.

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
