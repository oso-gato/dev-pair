# Changelog

Incident narrative and activation-proofs live here — memoir is not specification (P9).
Newest first.

## 2026-08-03 — Increment 3: dev-container/ image + harness

Build-order step 3 landed: the dev-container image (`Containerfile` + `install.sh` +
`entrypoint.sh`), the harness (`dp-session`, `dp-bus`, `dp-validate`, `gh-app-auth.sh`),
and the host-side Quadlet. Mined from the fleet's fedora-dev and pruned under P3: the
poller/deadman/dev-loop services, the fitness-token ferry, and the live-spec clone all
dropped — the loop services return as increments 5–6 by design, and the harness is
image-baked and versioned (no live-clone duality to skew). The tailscale.repo pin was
independently live re-checked (P2): content unchanged since the fleet's pin; the pin now
lives in the Containerfile ARG, bumped there only. `dp-session new` takes an optional
clone source — a genuine local-mirror feature that also lets the suite drive real git
without network (the test caught the hardcoded GitHub URL on its first run; fixed in the
tool, not the test).

**Activation-proof (P3/P8):** `test_session.sh` — 11 rows pass with real git in
throwaway tmpdirs: namespaced tree creation on `session/<session>/main`, the
fail-closed `verify` guard accepting own-tree/own-branch and refusing non-namespaced
branches, out-of-namespace paths, another session's tree, and traversal-shaped session
names. `dp-validate` exercised both directions against the vendored contracts (accepts
conforming, refuses with named violations, exit 1). The image built for real
(`podman build`, genuine 121-ish package install) and its contents verified: all 10
harness/tools present, 4 contracts vendored, sshd drop-in live, `core` user, uid-map
caps, jsonschema importable. An unplanned live boot of the entrypoint (invoked by a
mis-formed verify command — kept, it's honest evidence) generated persistent host keys
and synced the 3 real trust-root keys from GitHub. Not yet proven (recorded): the
tailnet join and the published-port door activate on first host run; the Quadlet's
Secret/env wiring activates with the refresh verb (increment 6).

## 2026-08-03 — Increment 2: host/ Fedora core + cloud adapter

Build-order step 2 landed: `host/core/converge.sh` (the CONVERGE verb — root idempotent
applier), `converge-user.sh` (rootless layer), `validate.sh` (the VALIDATE verb v1, the
G2 host seam), `lib.sh` (pure functions, one home), the two installed helpers, and
`host/cloud/genesis.sh` (cloud adapter). Rebuilt from the fleet's setup-host.sh under
P1–P11: the tailscale.repo fetch is now structurally verified against the live vendor
file (fact-checked 2026-08-03: `gpgcheck=1` AND `repo_gpgcheck=1`, vendor key on the
vendor host); the footprint is pruned (flatpak-session-helper, fastfetch,
cockpit-networkmanager/selinux dropped — recorded trade-offs); the scoped agent sudoers
defers to increment 6 with the verb that needs it (P3: no unproven gating); fail2ban
stays out (key-only door). One production hardening added by the test: the converger
generates sshd host keys on demand and creates `/etc/sysctl.d` when missing — a minimal
image must never wedge it.

**Activation-proof (P3/P8):** `test_lib.sh` — 25 rows pass (vendor-repo accept +
mutation-refuse rows; mutation-proven in fact: dropping the `repo_gpgcheck` requirement
turned exactly its row red). `test_converge_container.sh` — the REAL converger ran twice
in a real Fedora 44 systemd container (121 genuine packages, genuine units, genuine
`sshd -t`): first run applied, second run was a safe no-op, and the REAL validate passed
all 19 live read-back checks (2 warnings naming legitimate states: tailnet join pending
genesis, no SELinux in a container). The authorized-keys trust root synced 3 real keys
from the maintainer's GitHub account inside the test. Container-inherent chown/socket
warnings degraded exactly as designed (fail-LOUD, never fatal). Remaining for first VPS
genesis (recorded, not hidden): the tailnet join, the SELinux relabel path, and
multi-client tmux geometry activate there.

## 2026-08-03 — Increment 1: shared/ grammars v1

Build-order step 1 of `DESIGN.md` Part C landed: the four bus grammars —
ticket-envelope, verdict, refresh-manifest, lineage-manifest — defined once,
versioned v1, in `shared/contracts/`, with seven valid example instances.

**Activation-proof (P3):** `shared/contracts/test_contracts.py` — 43 rows
(7 accept, 36 refuse) against the real JSON Schema validator, all passing.
Mutation-proven in fact (P8): removing `sha` from the verdict schema's required
set turned exactly the matching refuse-row red (`verdict unbound from sha
refused: instance was accepted`); the restored schema is green. Two lineage
manifests recorded against the P11 admission contract: claudebox (admitted, L2),
kimibox (admitted, L3 c2); one example non-admission recorded with its reason.

## 2026-08-02 — Repository founded

`00-OBJECTIVES.md` and `00-BUILDPRINCIPLE.md` committed as the governing pair;
layout law (`host/` · `dev-container/` · `shared/`) established with scoping
READMEs. Loop steps (a) and (b) landed as `DESIGN.md` (dev-owned): functional
requirements traced per objective clause, the zero-base architecture (one loop,
two empirical gates, three host verbs, one watcher per clock, one versioned
bus), and the nine-increment build order.
