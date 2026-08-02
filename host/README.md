# host/

Everything that provisions, converges, or operates the Fedora host.

The host is one half of the dev pair and, secondarily, the mother platform that
runs other containers as apps and services. Two genesis paths exist:

- **VPS track** — a stock Fedora Cloud image converged in place by the idempotent converger.
- **Bare-metal track** — a custom bootc image (lineage: `oso-gato/strix-ms-s1-bootc`).

Host files live here and nowhere else. Contracts exchanged with the dev
container live in `shared/`.
