# 0004 — Building the method in: five bindings, vendored templates, repo genesis

- status: accepted
- date: 2026-08-16

## Problem

The working method (specify → plan → tasks → analyze → implement) existed only as AGENTS.md prose — informative, not enforced. The platform's measured failure mode is agents forgetting undocumented mechanism; an unenforced method is the same failure waiting.

## Decision

1. Five bindings give the method mechanical existence: AGENTS.md (session knowledge) · pinned templates shaping every artifact · ticket-envelope stamps carrying pair, agent, and stage (P7) · analyze as an in-session proceed/revise gate, with adversarial checking staying at the ship gate · a CI merge gate failing any PR that implements without a complete `specs/<NNN-slug>/`, edits a frozen specs folder, or adds a root surface outside P13.
2. Tooling: Spec Kit's templates vendored verbatim and pinned (v0.16.4, sha `bf88c9f9`), not its CLI — the pair needs artifacts and gates, not interactive scaffolding (P3). The CLI stays admissible later inside an agent box (P11) after a P2 scratch-test. Cost accepted: vendored templates drift unless re-verified on the P2 cadence.
3. Repo genesis: every new repository starts from `shared/templates/repo-genesis/` after its one initiation session — skeleton by declared shape (single artifact · host + container · swarm), objective locked verbatim, principles by reference, first ticket opens `specs/`.

## Options considered

- Adopt the `specify` CLI now — rejected: human-interactive scaffolding, more moving parts, provenance surface for no artifact the templates don't already give.
- Home the templates in homelab-root — rejected: genesis is the pair's own function; the universal principles will be *linked from* the constitution template, not co-located with it.

## Consequences

Ticket #6 shipped the template set. Remaining tickets: the ticket-envelope stamps (P7 contracts) and the CI merge gate (P8) — until the gate exists, the method binds by discipline only.
