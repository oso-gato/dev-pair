# dev-container/

Everything that builds or operates the dev container: the working half of the
dev pair, where the agent layer (claudebox, kimibox) runs and where project
repos are worked. Highly stable by design: it changes only through this
repository's merge-and-deploy path; durable state lives on the two volumes,
never in the image.

- `Containerfile` — Fedora 44 base; provenance L1 (Fedora) + L2 (Tailscale,
  .repo pinned by sha256 — the pin lives in the ARG and is bumped there only,
  after a live re-check).
- `install.sh` — the image install: minimal-leaf package set, nested rootless
  podman config, key-only sshd drop-in (host keys on the root-owned state
  volume, generated at runtime), the tmux session-group persistence mechanism.
- `entrypoint.sh` — PID 1 bring-up: home volume, runtime dir, uid-map caps,
  host keys, authorized-keys trust-root sync (cached), sshd, tailscaled + join
  (secret-file authkey, never argv/env), standing GitHub App credential
  (40-min refresh), rootless podman socket, then the watchdog.
- `bin/` — the harness:
  - `dp-session` — session isolation, code-enforced (P6): namespaced trees,
    `session/<session>/*` branch namespace, fail-closed pre-commit/pre-push
    `verify` guard.
  - `dp-bus` — the ticket-bus client: `list` / `claim` / `report`, every
    payload validated against the vendored grammar before it posts (fail-closed).
  - `dp-validate` — grammar validation against the vendored contracts.
  - `gh-app-auth.sh` — the standing, auto-rotating App credential minter.
- `dev-container.container` — the Quadlet the host runs (public key-only
  ssh/mosh published; tailnet for everything else; the pair's own App identity
  via env; secrets mounted, never layered).
- `test_session.sh` — the isolation suite: real git, namespaced trees,
  mutation-refuse rows.

The shared bus grammars are vendored into the image at build time from their
one home (`shared/contracts/`, P9) — same repository, same change, never
hand-copied.
