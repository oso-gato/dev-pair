# 0012 — GitHub App identity model: actor, not subject

- status: accepted
- date: 2026-08-17

## Problem

Three apps existed (`oso-gato-erebus-claudebox`, `oso-gato-nox-claudebox`, `oso-gato-fitness-claudebox`) with no stated model: whether apps name agents or a generic agentbox, whether pairs or projects own apps, and how many a new pair needs.

## Decision

Apps are **actor identities, never subjects**. One App per pair-component per agent — `oso-gato-<component>-<agent>` — installed onto the repositories the pair works. The agent stays in the name because the App is the agent's identity on the bus: P10's non-author review and P8's routing both need Claude's actions distinguishable from Kimi's. The component split is kept because it makes authority mechanical: the host's App carries no merge permission, the container's does, and "the host never merges" becomes a GitHub-enforced impossibility rather than discipline. Projects never get apps — the pair's apps visit them by installation, and the ticket stamps already carry the subject.

## Options considered

- A generic `-agentbox` app — rejected: collapses the agent identity that multi-agent review and routing depend on.
- Per-project apps (the `fitness` pattern) — rejected: identity must answer who acted, not what was acted on; `oso-gato-fitness-claudebox` predates the architecture and retires once nothing depends on it.
- One app per pair spanning both components — rejected: forfeits permission-level enforcement of the host-never-merges boundary.

## Consequences

The erebus pair is correctly served by its existing two apps; the kimibox's admission adds two more; each new pair adds components × agents. App IDs and PEMs land in the vault (0011); private-visibility apps are not API-fetchable, so IDs come from the maintainer's settings page.
