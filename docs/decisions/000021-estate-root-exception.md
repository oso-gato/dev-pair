# 000021 — The estate root is C2's sole exception, recorded

- status: accepted
- date: 2026-08-17

## Problem

Universal C2 opened with *"Every repository carries the same skeleton"* and C11 with *"Every repository locks the confirmed state of its charter"*, while `oso-gato/homelab-root` carries neither. It has no charter, no standing surface set of its own and no epoch tag, and its `main` is unprotected. The maintainer had ruled on this — 000014 declined to tag the estate root — but the ruling lived in that record's Options section, in a subordinate repository, invisible from inside the repository it exempts.

An unwritten exception is not a quiet one. An agent reading the law natively in the estate root has three moves available and two of them are bad. It can file a blocking non-conformance under C1's UNTRUE rule and burn a maintainer interaction the objective forbids. It can instantiate C2's skeleton there. Or it can plant an epoch on the credential vault — and the epoch mechanism wraps each tag in a Release under a ruleset making epochs immutable to everyone, which would make a rotated credential permanently retrievable against C6's git-never-forgets-doubly clause and 000011's finding that rotation is the only recovery. The 2026-08-17 pre-retake audit had already reached into the estate root to enforce one C2 clause and reported "Verified clean", which is what an unnoticed gap looks like rather than an accepted one.

## Decision

Maintainer-ruled. The estate root is C2's sole exception, and the reason is stated rather than asserted: it holds the skeleton's **master** in `genesis/skeleton/` — the `docs/` template tree included — rather than an instance of it. Instantiating the skeleton there would put a second copy of it in the one repository that owns the first, which C1 forbids. It carries the law, the kit, the environment registry and the vault, and it builds nothing.

C11's epoch does not reach it, because a repository with no charter has nothing to lock — the obligation's object is absent and its trigger never fires. The repository stays private, unprotected and untagged, reached by the maintainer's credentials and each pair's GitHub App. Its own decisions are recorded in this trail, which the constitution's Authority section already cites.

The record lands as one clause in C2 and one paragraph in `homelab-root/AGENTS.md`, so the ruling is visible from inside the repository it governs. C11 is untouched: C2 states that the estate root has no charter, and a rule with no object needs no second carve-out.

## Options considered

- **Leave it to 000014's Options section** — rejected. It is a ruling recorded where the governed repository cannot see it, and the failure it permits is not untidiness but a permanent credential-exposure surface.
- **Give the estate root a charter and an epoch** — rejected; 000014 already declined it, and reopening a settled ruling takes a new maintainer confirmation rather than an agent's finding. The tag is not neutral: an immutable Release over the vault is a security regression.
- **Make homelab-root public to unlock branch protection** — rejected on the record. Rulesets and branch protection both return 403 on the current plan ("Upgrade to GitHub Pro or make this repository public"), and C6 states the vault may never become public. Protection is therefore unavailable by construction, and the maintainer ruled that it is also unnecessary: access is by his credentials and the pairs' Apps, not by branch rules.
- **A new paragraph in C11 as well as C2** — rejected under 000018's standard that the charter gets shorter rather than longer. One clause carries it.

## Consequences

C2 gains the exception with its reason; the constitution's Authority trail records this. `homelab-root/AGENTS.md` gains a paragraph telling the next agent not to fix the shape of that repository and never to plant a tag or Release on it. Nothing in the genesis kit changes: the exception is the estate root's alone, and a chartered repository inherits the rule, not the carve-out.
