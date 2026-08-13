# dev-pair

The autonomous dev pair: a Fedora host and a dev container, built and run as one system.

Two documents govern everything in this repository:

- [00-OBJECTIVE.md](00-OBJECTIVE.md) — why the pair exists and what it must achieve.
- [00-OBJECTIVE.md](00-OBJECTIVE.md) — how anything in this repository may be built.

The working map from those two to the code is [DESIGN.md](DESIGN.md) — dev-owned,
mutable-on-fact, never a conformance target.

If code and these documents disagree, the documents win — or the documents are changed deliberately, in the open, never silently.

## Layout law

Ruthless path-level modularity. Every file belongs unambiguously to exactly one artifact:

- `host/` — everything that provisions, converges, or operates the Fedora host (VPS or bare metal).
- `dev-container/` — everything that builds or operates the dev container.
- `shared/` — versioned atomic contracts and anything both artifacts genuinely share. Nothing lands here to escape a boundary.

There is no fourth place. A file that fits nowhere is a design smell; fix the design, not the filing.
