# dev-pair

The autonomous dev pair: a Fedora host and a dev container, built and run as one system.

Two documents govern everything in this repository:

- [spec.md](spec.md) — why the pair exists and what it must achieve.
- [constitution.md](constitution.md) — how anything in this repository may be built.

Agents start at [AGENTS.md](AGENTS.md) — the session-loaded operating manual. The working map from spec to code is [ARCHITECTURE.md](ARCHITECTURE.md) — agent-owned, mutable-on-fact, never a conformance target. Decisions are recorded in [decisions/](decisions/); notable changes in [CHANGELOG.md](CHANGELOG.md).

If code and these documents disagree, the documents win — or the documents are changed deliberately, in the open, never silently.

## Layout law

Ruthless path-level modularity. Every file belongs unambiguously to exactly one artifact:

- `host/` — everything that provisions, converges, or operates the Fedora host (VPS or bare metal).
- `dev-container/` — everything that builds or operates the dev container.
- `shared/` — versioned atomic contracts and anything both artifacts genuinely share. Nothing lands here to escape a boundary.

There is no fourth place. A file that fits nowhere is a design smell; fix the design, not the filing.
