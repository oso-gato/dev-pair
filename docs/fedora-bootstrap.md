# Fedora Cloud 44 bootstrap

This is executable host preparation, implemented in [tools/bootstrap.py](../tools/bootstrap.py).
It has **not been run on Fedora or the designated VPS**. Local fixtures test the
control flow and filesystem transactions; they are not installation, firewall,
SSH, SELinux, reboot or Tailscale evidence. Use only an authorized fresh Fedora
Cloud 44 target after exact-candidate independent review and host inspection.
No application or agent is installed or launched by this slice.

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
outside the target. Transfer that file as root-owned code; do not execute a
moving branch, a submitted candidate manifest or an arbitrary download script.
The following commands are for that executor on the designated **Fedora host**,
not the development machine. Examples use reserved documentation CIDRs; replace
them with explicitly authorized executor source CIDRs before execution.

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap.py inspect
sudo /usr/bin/python3 /root/dev-pair-bootstrap.py prepare \
  --operator devpair-admin --public-key-file /root/operator.pub \
  --bootstrap-source 192.0.2.9/32 --bootstrap-source 2001:db8::9/128
```

`prepare` and `enroll` default to read-only inspection. Only `--apply` performs
changes. Public keys must be one valid unoptioned Ed25519 key in a root-owned
file with no writable or symlink path components. Root, Fedora44, x86_64/aarch64,
host systemd PID1, enforcing SELinux, valid existing OpenSSH on port22, and an
otherwise vanilla listener inventory are mandatory. Competing active firewalld
or nftables services and foreign nft tables are rejected without disabling them.
This deliberately reports a blocker on a provider image with existing services
or network policy; it does not guess how to preserve arbitrary configurations.
The actual current SSH source must be in the declared CIDRs before apply.

## Prepare

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap.py prepare --apply \
  --operator devpair-admin --public-key-file /root/operator.pub \
  --bootstrap-source 192.0.2.9/32 --bootstrap-source 2001:db8::9/128
sudo /usr/bin/python3 /root/dev-pair-bootstrap.py status
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
No recursive ownership change, cleanup, data deletion or automatic account
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

## Enroll and enter

Place a minimally scoped, short-lived enrollment key in an external root-owned
0600 file (no symlinks or group/world writable path). Do not put its value in an
argument, environment variable, source, transcript or image. The tool passes
only Tailscale's documented `--auth-key=file:/path` reference and withholds all
command output on errors and timeouts. Remove the external file after confirmed
enrollment and revoke the enrollment credential when appropriate; the bootstrap
does not delete externally managed secrets.

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap.py enroll --apply \
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
credential revocation may still be needed. A failed disconnect is reported as a
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
redaction, wrong-tailnet disconnect and cutover refusal. They cannot validate
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
