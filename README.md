# dev-pair

The autonomous dev pair takes a product brief and delivers a tested, ready-to-use product. The product owner supplies the requirements; code review and routine development are the pair's responsibility.

The required platform is a Fedora host with a Podman development container, both operated by Codex by default. [00-OBJECTIVE.md](00-OBJECTIVE.md) defines the roles and delivery outcomes; [00-BYLAW.md](00-BYLAW.md) B5 defines the agent mapping: `gptbox` runs Codex, `claudebox` runs Claude Code, and `agentbox` selects the default, currently `gptbox`.

## Implementation status

The 2026-11-10 requirements revision records the agreed direction. The existing implementation still uses Claude Code and nested Distrobox under Podman. The `gptbox` runtime scripts and `agentbox` default launcher still need to be developed and tested; setting their names in the requirements does not install Codex or enable switching. Existing code and historical decisions are retained while the replacement is developed. [ARCHITECTURE.md](ARCHITECTURE.md) remains the map of the actual source, and [decision 000034](docs/decisions/000034-codex-on-podman.md) records the transition.

## Setup and migration

The commands in [AGENTS.md](AGENTS.md) describe the retained Claude setup. There is no working `gptbox` setup command in this revision. Implementation must admit and pin Codex, provide its authentication and agent-specific adapter, wire the B5 default selection into shared lifecycle scripts, and prove launch, resume and recovery before documenting a ready-to-use setup path. [Decision 000035](docs/decisions/000035-agentbox-name.md) records the naming and switching contract.

## The charter — governing documents

The following three governing documents are collectively called **the charter**. They define the product's purpose, requirements and governing rules, and are maintainer-merge-only:

- [00-OBJECTIVE.md](00-OBJECTIVE.md) — why the pair exists and what it must achieve.
- [00-BYLAW.md](00-BYLAW.md) — this repository's own build principles, subordinate to the constitution.
- [CONSTITUTION.md](CONSTITUTION.md) — the estate's universal build principles, applied by reference, with the scoped maintainer direction recorded for this revision.

The charter is part of the **project documentation**. The setup guidance, operating manual, architecture map, decision records and changelog support it; they are not additional charter documents.

Agents start at [AGENTS.md](AGENTS.md) — the session-loaded operating manual. The working map from spec to code is [ARCHITECTURE.md](ARCHITECTURE.md) — agent-owned, mutable-on-fact, never a conformance target. Decisions are recorded in [docs/decisions/](docs/decisions/); notable changes in [CHANGELOG.md](CHANGELOG.md).

If code and these documents disagree, the documents win — or the documents are changed deliberately, in the open, never silently.

## Layout law

The standing skeleton is law — universal constitution C2, instantiated for this repository's shape in [00-BYLAW.md](00-BYLAW.md). This repository is the host + container shape:

- `host/` — everything that provisions, converges, or operates the Fedora host (VPS or bare metal).
- `dev-container/` — everything that builds or operates the dev container.
- `shared/` — versioned atomic contracts and anything both artifacts genuinely share. Nothing lands here to escape a boundary.

There is no fourth place. A file that fits nowhere is an architecture smell; fix the architecture, not the filing.
