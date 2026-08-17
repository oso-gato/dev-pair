# AGENTS.md — operating manual for agents in this repository

Read this first, every session.

## Load the law

Fetch the universal constitution at session start — the fetch line is in [CONSTITUTION.md](CONSTITUTION.md). For structural work, also read the charter: [00-OBJECTIVE.md](00-OBJECTIVE.md), the WHY, and [00-BYLAW.md](00-BYLAW.md), this repository's own law. All three are locked, maintainer-merge-only. Bare C-numbers mean the universal constitution; B-numbers mean the bylaw.

The pair's identities — GitHub App, tailnet, `core` — rest in the estate vault at homelab-root `identity/`; [ARCHITECTURE.md](ARCHITECTURE.md) § Pairs carries the exact pointers. The vault discipline in homelab-root's AGENTS.md binds here too: credential files are never read, operations on them are content-blind.

## What this repository is

The dev pair: three parts, always. The **GitHub ticket bus** — issues and PRs — carries every hand-off; nothing durable lives only in a container or a layer. The **host** operates the platform and validates what the container cannot (tier-2); it opens PRs and never merges. The **dev-container** develops, validates (tier-1), and holds sole merge authority — except the locked documents above.

## Working method

Per ticket, the loop runs **specify → plan → tasks → analyze → implement**:

1. `docs/specs/<NNNNNN-slug>/spec.md` — what this ticket must do; NNNNNN is the issue number, zero-padded to six digits.
2. `docs/specs/<NNNNNN-slug>/plan.md` — the design that serves it.
3. `docs/specs/<NNNNNN-slug>/tasks.md` — the decomposition to iterate through.
4. Analyze — a read-only consistency check across the three before implementing.
5. Implement, validate, iterate — two tiers, per the objective.

Clarification happens once, at initiation — never a mid-loop human summons (C11). Where the charter is silent, decide with the smallest footprint, record the decision, and report it at delivery — the objective's silence policy. Spec folders merge to main and freeze at ship; a change is a new ticket. A decision stays in `plan.md` while it binds one ticket; it graduates to [docs/decisions/](docs/decisions/) when it binds future ones.

Execution is parallel where independent and sequential only where dependent: `tasks.md` marks which tasks depend on which, independent tasks fan out concurrently, and dependencies alone impose order. Parallelism never trades away quality or accuracy — every parallel result passes the same gates as if it had run alone (C12).

## Ticket routing

Every ticket carries two stamps: its **pair** (the lineage: `erebus`, `strix`) and its **agent** (`claudebox` = Claude Code, `kimibox` = Kimi Code). Pick up a ticket only when both stamps match your box (C8).

## Self-renewal — never forget this

A maintainer-instructed improvement merges → the host brings itself to the merged state → the host rebuilds and relaunches the dev-container from outside → every session is restored. The dev-container never rebuilds itself — it requests renewal, its own or the host's, through the ticket bus (B4).

## Chartering a new repository

After its initiation session, fetch the genesis kit fresh from `oso-gato/homelab-root` → `genesis/` into a throwaway tree, instantiate from its `skeleton/` per its manual, and tear the tree down. Never keep a committed copy of the kit.

## Records

[ARCHITECTURE.md](ARCHITECTURE.md) is the current-state map — update it in the same change that alters a fact; a stale map is a blocking finding (C1). [docs/decisions/](docs/decisions/) holds the ADRs — problem, options, choice, fate; reverse by superseding record, never by edit. [CHANGELOG.md](CHANGELOG.md) carries notable changes and incidents.

A surface improvement that is universal rather than pair-specific updates the surface's genesis template (homelab-root `genesis/`) in the same change, or records why it is pair-only — facts (lineage names, expiry-dated filenames) never mirror.

## Writing style

Every document here is written one way, for humans and agents alike. Full prose sentences that happen to be short — one subject per sentence, one line per paragraph, no hard wraps. State the rule, then the reason. Name a thing once and reuse the name; coin a new term with a plain gloss at first use; bold only load-bearing anchors. The label-colon register ("Status: X. Fixed: Y.") never appears in prose — it belongs only to functional forms. Functional forms keep their native shape: task lists stay checklists, registries stay fact lists, ADR metadata stays a header, tables stay tables — prose never invades them either. Frozen records are never restyled.

## Session conduct

- Author and build only in your session's isolated, namespaced worktree; re-verify branch ownership before every commit and push (B2).
- Builds are throwaways cut from throwaway trees — never from a live tree (B1).
- No mutable out-of-band change to any deployed artifact (C7).
- No mechanism without an outcome it changes; no test asserting a mock; no gate without recovery (C3, C9, C11).
- The confirmed baseline is the protected tag `chartered`, with timestamped epochs `chartered-YYYY-MM-DD-HHMM` beneath it. Never move or delete an epoch tag. After a bad run, restore by reverting main to `chartered` — a recorded act; reset is maintainer-only (C11).

## Build & test

While `host/` and `dev-container/` are absent, building them is the whole of the work: day zero, the idempotent converger, the `nox` image, and an agent box on each side. Nothing else is on the critical path.

The change that lands a component replaces its line above with that component's real commands, in the same change — this section is mutable-on-fact like the map, and retires the paragraph above itself once both components run. The rule that outlives it: a mechanism that observes, gates, or validates is built only after the thing it serves runs, and only when an observed failure demands it — the estate's measured failure mode is scaffolding that arrives first and then outgrows the product (C3).
