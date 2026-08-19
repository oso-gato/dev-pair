# AGENTS.md — operating manual for agents in this repository

Read this first, every session.

## Load the law

The charter is loaded, not consulted. This repository's two law files are imported immediately below, so both stand in context before the session's first tool call and are re-injected after every compaction.

@00-OBJECTIVE.md
@00-BYLAW.md

They are read end to end and never in excerpt. An agent working from a quoted fragment contradicts the clause the fragment came from while believing it obeys it, and this repository has done exactly that — the dev-container was once built with no public door at all, citing the outcome that requires one.

The universal constitution is the charter's third file and it cannot be imported, because its text lives at its one home in another repository and a copy here would be the fork it forbids. Fetch it at session start; the line is in [CONSTITUTION.md](CONSTITUTION.md). Fetch it again after a compaction, because an imported file survives one and a fetched document does not.

Cite no C-number a session has not loaded. A rule recalled from memory and a citation attached to a rule that does not contain it are the same defect, and this estate has already built a merge gate citing a C9 requirement C9 does not contain ([000018](docs/decisions/000018-no-sieves-and-product-before-mechanism.md)).

`/context` lists what a session actually holds. Read it rather than assume the load worked.

The charter is locked, maintainer-merge-only. Bare C-numbers mean the universal constitution; B-numbers mean the bylaw.

The pair's identities — GitHub App, tailnet, `core` — rest in the estate vault at homelab-root `identity/`; [ARCHITECTURE.md](ARCHITECTURE.md) § Pairs carries the exact pointers. The vault discipline in homelab-root's AGENTS.md binds here too: credential files are never read, operations on them are content-blind.

## Working method

Per ticket, the loop runs **specify → plan → tasks → analyze → implement**:

1. `docs/specs/<NNNNNN-slug>/spec.md` — what this ticket must do; NNNNNN is the issue number, zero-padded to six digits.
2. `docs/specs/<NNNNNN-slug>/plan.md` — the design that serves it.
3. `docs/specs/<NNNNNN-slug>/tasks.md` — the decomposition to iterate through.
4. Analyze — a read-only consistency check across the three before implementing.
5. Implement, validate, iterate — two tiers, per the objective.

Spec folders merge to main and freeze at ship; a change is a new ticket. A decision stays in `plan.md` while it binds one ticket; it graduates to [docs/decisions/](docs/decisions/) when it binds future ones.

Execution is parallel where independent and sequential only where dependent: `tasks.md` marks which tasks depend on which, independent tasks fan out concurrently, and dependencies alone impose order. Parallelism never trades away quality or accuracy — every parallel result passes the same gates as if it had run alone (C12).

## Decide, or halt

The pair answers the questions its own work raises. A session reaches the maintainer three ways and no others.

**Delivery**, where the objective is shipped and the outcome is handed over with an account of what was decided along the way. Delivery is a report and asks for no approval.

**A halt**, where the objective cannot be met within its boundaries. The session names the contradiction and proposes an amendment, rather than looping indefinitely or quietly shipping a compromise.

**A scope change**, where a ticket would exceed the objective or the bylaw. The charter is amended first, and only then does the work proceed.

Everything else is decided here. Where the charter is silent, take the smallest footprint that serves the objective, record the decision, and report it at delivery; a wrong choice is amended afterwards and that costs less than a summons. Where the charter speaks, it has already decided, and asking is evidence it was not read.

These never reach the maintainer: which of two designs to take, whether a reading is right, confirmation that a step is correct, a status check, or permission to continue. Build the candidates, test them, discard what fails, and record why — the objective counts one human interaction per project, and an unnecessary escalation is the human summons C11 forbids.

## Ticket routing

Every ticket carries two stamps: its **pair** (the lineage: `erebus`, `strix`) and its **agent** (`claudebox` = Claude Code, `kimibox` = Kimi Code). Pick up a ticket only when both stamps match your box (C8).

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

The erebus lineage's genesis path is built and unapplied; `moros` and the strix pair's activation are the remaining build. What runs today:

- `bash host/converge/selftest.sh` — everything the container can prove without a host: every delivered script parses, shellcheck is clean at style level, the idempotence primitives are exercised against a real filesystem and mutation-checked, and the tree carries no credential, no forbidden channel, and no installation missing `install_weak_deps=False`. This is the tier-1 gate and it must be green before a ticket is offered as done.
- `sudo host/converge/converge.sh --env <name>` — converge a host. `--list` shows the units, `--only <unit>` runs one. Re-running is the normal case, and a converged host reports zero changes.
- `bash dev-container/build.sh` — a throwaway validation candidate of the `nox` image, torn down with its tree on every exit path (B1). Never a production image: CI builds those.

Tier 2 is the maintainer's apply. A full converge on a live Fedora Cloud host, and the second apply that proves the converger re-run-safe end to end, need a host and are never simulated here (C9).

The change that lands a component replaces its line above with that component's real commands, in the same change — this section is mutable-on-fact like the map, and retires the paragraph above itself once both components run. The rule that outlives it: a mechanism that observes, gates, or validates is built only after the thing it serves runs, and only when an observed failure demands it — the estate's measured failure mode is scaffolding that arrives first and then outgrows the product (C3).
