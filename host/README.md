# host/

Everything that provisions, converges, or operates the Fedora host.

The host is one half of the dev pair and, secondarily, the mother platform that
runs other containers as apps and services. Structured as **Fedora core + adapters**
(FR-PROV-3): onboarding a new environment is an adapter addition, never a fork.

- `core/` — the converger and its verbs, environment-agnostic:
  - `converge.sh` — the CONVERGE verb: the root idempotent applier. Every host
    mutation is declared here and flows the merge-and-deploy path; re-run-safe
    from any historical version.
  - `converge-user.sh` — the rootless layer (authorized-keys trust root, rootless
    podman socket), run as the operating user via converge.sh's hand-off.
  - `validate.sh` — the VALIDATE verb (v1): live acceptance read-back — effective
    daemon config, listening sockets, unit state — never config-file testimony.
    This is the G2 seam for host refreshes.
  - `lib.sh` — pure decision functions (one home, sourced by converge + tests).
  - `selinux-enforce-once.sh`, `cockpit-tailnet-serve.sh` — installed helpers.
  - `test_lib.sh` — unit suite (accept + mutation-refuse rows).
  - `test_converge_container.sh` + `test/Containerfile.systemd` — the live test:
    the real converger, twice, in a real Fedora 44 systemd container, then the
    real validate. No mocks.
- `cloud/` — the cloud adapter: `genesis.sh` turns a stock Fedora cloud image on
  any provider into a converged host (remote, channel-proof, no local act).
- `local/` — the local adapter (bootc image + installer + rebase). Build-order
  step 9; lineage: `oso-gato/strix-ms-s1-bootc`.

Tests: `bash host/core/test_lib.sh` and `bash host/core/test_converge_container.sh`
(needs podman). Genesis: run `host/cloud/genesis.sh` as root on the fresh machine.
