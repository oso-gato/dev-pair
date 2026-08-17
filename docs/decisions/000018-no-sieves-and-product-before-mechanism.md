# 000018 — No sieves, product before mechanism, and the ladder rehomed to C4

- status: accepted
- date: 2026-08-17

## Problem

This repository's first ticket built a conformance gate — mechanical scans plus a CI merge job — before either component of the pair existed. The maintainer refused it as theatre and reverted to `chartered`. The refusal was correct, and the reason it happened is not agent carelessness alone.

Three causes were found, and the third is the one that binds the future.

`ARCHITECTURE.md` carried a section titled *"Promised by law, not yet built"* listing three unbuilt mechanisms, each with a citation. The product got one parenthetical with nothing actionable in it. That section was the only thing in the current-state map shaped like a queue, so it was read as one. Its lead item cited C9 for a CI merge gate; C9 contains no such requirement. The citation was invented.

The rule against building it was already present and already read. `AGENTS.md` says *"No mechanism without an outcome it changes"*; the constitution's preamble names this estate's measured failure mode as *"gates with nothing to gate, watchdogs watching each other, dead-man switches nobody would miss"*; C3 adds that *"a check that changes no outcome is telemetry."* The rule was in the session path in three places and the gate was built anyway. **An actionable list beats an evaluative rule, because a list says what to do and a rule only says how to judge.** Removing the lure is therefore the operative fix, and relocating rules is not.

`00-BYLAW.md` commissioned the worst part of it. Its provenance ladder ended *"Forbidden outright, enforced by mechanical scan,"* and the constitution's C4 said the same. So the forbidden-channel scanner was not an agent's invention — the charter ordered it.

## Evidence — the prior fleet, audited

`oso-gato/fedora-dev` and `oso-gato/fedora-bootstrap` were the previous pair, and both are dead. They were read in full before this decision (C5).

- fedora-dev: 134 files, 34,112 lines. 51 test files carrying 11,239 lines — a third of the repository.
- The watchers: `pr-poller` 2,503 lines, `apparatus-deadman` 1,074, `immutability-probe` 793, `fleet-guard-parity` 670, `bandwidth-probe` 621, `residue-witness` 503 — **6,164 lines**.
- The loop they watch: `dev-loop.sh`, **641 lines**. A ratio of 9.6 to 1.
- `CLAUDE.md`: 41,528 words, one line of 29,037 characters. The governance corpus loaded every session: 61,110 words.
- Roughly 700 tickets across the two repositories.

Every watcher's header cites a real incident, and each was locally rational. The chain ran: the loop stalls silently, so build a poller; the poller cannot report its own death, so build an independent deadman; the interactive agent stops mid-objective, so build a stop hook; the hook guarded the shape of a sentence and the model wrote a factual status report carrying no check-in signature and stopped anyway, so escalate to an oracle consulted on every stop; a teardown trap cannot witness itself, so build a witness; the witness might be blind, so give it a negative control; guards duplicated across three repositories drifted, so build a parity checker over the guards.

Two commits are the record. fedora-dev's last is document surgery on its governing set. fedora-bootstrap's last is *"host-code-refresh: a FAILED apply reported GREEN — name every failure path."* After 700 tickets and 6,164 lines of watchers, the final recorded defect is the converger reporting success while failing. The machinery watched itself and no one watched whether the thing worked.

fedora-dev had also already learned the specific lesson and written it down: *a static script-scan for bad fetch or install patterns is not a valid backstop; detecting bad patterns in arbitrary shell is a sieve, a seventh evasion always exists, and a guard that implies coverage it cannot deliver is worse than none — a host static fetch-guard was built and closed for exactly this reason.* That doctrine did not carry into this repository's charter, and the charter then commissioned the scan it forbids.

## Options

**Add a precedence rule to the bylaw or the constitution.** Rejected. The rule exists twice already, and responding to an incident with another paragraph is the mechanism by which the prior fleet reached 41,528 words of session-loaded doctrine. It would have treated a lure problem as a law problem.

**Strike mechanical enforcement entirely.** Rejected as an overcorrection. A sieve hunts arbitrary behaviour in open-ended input and is always evadable; a total check reads a bounded declared artifact and answers a closed question, and has nothing to evade. This pair runs without a human in the loop, so removing all autonomous refusal would leave it merging unchecked work. The rule is no sieves, not no checks.

**Impose a word budget on governance documents.** Rejected. A budget is a check over documents, which needs a checker, which is a gate — the thing under judgment here.

**Remove the lure, remove the disproven mandate, and rehome the ladder.** Adopted.

## Decision

Seven changes, and the charter gets shorter rather than longer.

`ARCHITECTURE.md` loses the promised-not-built section entirely, and its header now states that the map records only what exists, because a list of absent mechanisms in the current-state map reads as a build queue. Unbuilt work lives in issues.

`AGENTS.md`'s build section names the product as the standing objective while the product is absent, and retires itself: the change that lands a component replaces its line with that component's real commands. The durable rule survives the retirement — a mechanism that observes, gates, or validates is built only after the thing it serves runs, and only when an observed failure demands it.

The universal constitution's Conformance paragraph now makes adversarial review the default check at full strength, and admits a mechanical check only where it reads a bounded declared artifact, answers a closed question, and is wired to an outcome it can change. A principle whose only available check would be a pattern-scan over open-ended input is checked by review, and building the scan is the defect.

C3 gains two sentences: no mechanism precedes the thing it serves, and no guard is a sieve — the boundary is the artifact's own fail-closed verification plus its disclosure, never the scan.

C3's activation-proof clause changes *built* to *called done*, and now separates the two cases that were being conflated. Product code awaiting the maintainer's first apply is the deliverable; a mechanism whose proof its author could have taken and did not is the defect. The prior reading was used in this session to argue that `host/` should not be authored because its proof lives on the maintainer's VPS, which inverted the rule into a licence to build only self-provable things — that is, only scaffolding.

C4 absorbs the provenance ladder's shape, its c1/c2/c3 grading, and the estate-wide forbidden categories, and states that admission is enforced at the fetch by the installer's own fail-closed verification. `00-BYLAW.md` keeps only the Fedora naming. Four fifths of that ladder was universal law living in a repository, and the next repository the pair charters would have copied it — which is precisely the shape that produced `fleet-guard-parity.sh`, 670 lines and a CI workflow built because one guard payload lived in three repositories and one silently missed a fix. One home ends that before it starts.

The genesis kit carries all of it forward: the map template gains the same guard, the manual's build section ships in the self-retiring shape, and the procedure gains a step — a newly chartered repository's first ticket builds the product it exists for, never the scaffolding around it.

## Consequences

The gate this repository built is gone and is not to be rebuilt from these rules. Of its ten checks, only the forbidden-channel scanner was a genuine sieve; the rest were total checks over bounded structure. Recording that distinction matters, because "it was theatre because it was a sieve" is the wrong lesson and would licence rebuilding it with better rules. It was theatre because it changed no outcome — `main` carries no protection, so nothing it decided could stop a merge — and because it preceded the product it would check.

Mechanical checks remain admissible. When one is proposed, it must read a declared artifact, answer a closed question, be wired to a decision it can change, and arrive after the thing it serves runs.

This is the last doctrine change before the pair is built. The next commit that is not this record is `host/day-zero.sh`.

One product decision falls out of the audit and is noted for that build rather than settled here: fedora-dev admitted `claude-code` from Anthropic's own dnf repository as a vendor-level source, so the agent box needs no language package manager at all, and the tension between C8's disposable agent layer and C4's forbidden channels dissolves at L2.
