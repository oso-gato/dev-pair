# 000034 — Codex operates the Fedora and Podman pair

- status: accepted direction; charter revision pending maintainer merge
- date: 2026-11-10
- supersedes: 000029's decision to require a nested agent box for the replacement runtime; its historical findings remain intact

## Problem

The maintainer wants to state a product outcome and receive a tested, ready-to-use product. He does not review code. The current implementation uses Claude Code, and its nested Distrobox design adds runtime complexity without being a requirement of that product outcome.

The earlier assessment described Docker workers after taking an initial mention of Docker literally. The maintainer corrected the runtime to Podman. The requested repository update follows the clarified design: Fedora and Podman remain, Codex operates both roles, and development Codex runs directly in the dev-container.

## Decision

[00-OBJECTIVE.md](../../00-OBJECTIVE.md) is the authority for the product outcomes. [00-BYLAW.md](../../00-BYLAW.md) B5 and B6 define the runtime and evidence requirements. The five-stage development method remains; its implementation stage ends only after the delivery criteria are satisfied.

The dev-container itself supplies the disposable development-agent boundary. The maintenance agent has a separate host-side Podman container and a controlled operation interface. This removes the requirement for an inner Distrobox agent container and its independent refresh clock, while keeping persistent work and verified recovery.

This requirement is pair-specific. The estate's genesis templates and universal constitution have not been changed, because this decision does not select a runtime for every other repository. [CONSTITUTION.md](../../CONSTITUTION.md) explicitly records the maintainer-directed departure from universal C8; it does not silently claim conformance to the old placement rule. Official Codex package admission remains subject to C4 and C5 and is an implementation prerequisite.

## Options considered

- Keep Claude Code and rename the operator-facing command. Rejected because it does not replace the primary agent or satisfy the requested Codex roles.
- Replace Podman with Docker. Rejected by the maintainer; Podman is the required runtime.
- Put Codex inside the existing nested Distrobox structure. Rejected for the replacement design because the development container already supplies the disposable boundary, and the nested layer carries costs documented in 000029.
- Delete the existing source immediately. Rejected for this documentation change because the replacement has not been implemented or validated. History, existing adapters and reusable components remain available.

## Transition and acceptance

The requirements change does not alter scripts, images, workflows, deployed hosts, GitHub Apps or credential filenames. `CLAUDE.md` remains a compatibility loader and does not designate Claude as the target primary agent. Frozen specs and prior decisions remain historical records.

Implementation starts with a single Fedora VPS and a demonstrator product. Before claiming the migration complete, prove Codex admission and authentication, host maintenance through the constrained interface, development under rootless Podman, independent review, deployment verification, interrupted-job recovery and rollback against real artifacts. Concurrency and bare-metal expansion follow the first complete product delivery.

The documentation change is checked for consistent requirements, working local links and a clear separation between target behaviour and current source. Runtime acceptance remains unperformed. This record carries the rationale and acceptance criteria for the requirements revision; implementation work needs new tickets rather than reopening frozen genesis specs.

The charter remains maintainer-merge-only. Existing `chartered` and epoch tags are not moved by this change; the next epoch belongs to the maintainer's charter-merge process.
