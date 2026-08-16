# dev-pair

The autonomous dev pair: a Fedora host and a dev container, built and run as one system.

Three documents govern everything in this repository:

- [OBJECTIVE.md](OBJECTIVE.md) — why the pair exists and what it must achieve.
- [constitution.md](constitution.md) — the estate's universal build principles, applied by reference.
- [BYLAW.md](BYLAW.md) — this repository's own build principles, subordinate to the constitution.

Agents start at [AGENTS.md](AGENTS.md) — the session-loaded operating manual. The working map from spec to code is [ARCHITECTURE.md](ARCHITECTURE.md) — agent-owned, mutable-on-fact, never a conformance target. Decisions are recorded in [decisions/](decisions/); notable changes in [CHANGELOG.md](CHANGELOG.md).

If code and these documents disagree, the documents win — or the documents are changed deliberately, in the open, never silently.

## Layout law

The standing skeleton is law — universal constitution P2, instantiated for this repository's shape in [BYLAW.md](BYLAW.md). This repository is the host + container shape:

- `host/` — everything that provisions, converges, or operates the Fedora host (VPS or bare metal).
- `dev-container/` — everything that builds or operates the dev container.
- `shared/` — versioned atomic contracts and anything both artifacts genuinely share. Nothing lands here to escape a boundary.

There is no fourth place. A file that fits nowhere is an architecture smell; fix the architecture, not the filing.
