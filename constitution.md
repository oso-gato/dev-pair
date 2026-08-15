# The Dev Pair — CONSTITUTION (the build principles)

> **THE HOW WE BUILD** — how every artifact is constructed, whatever it does.
>
> **Status: DRAFT — pending maintainer confirmation.** Confirmed with the objective
> (`OBJECTIVE.md`) and sharing its authority: fixed thereafter, amendment is a new
> maintainer confirmation, MAINTAINER-MERGE-ONLY. These principles serve the twofold
> objective — the autonomous dev-pair loop workflow first, the mother platform second —
> and must never contradict it. They are **capabilities, not implementations**: a
> functional requirement says what a thing must *do*; a build principle says how anything
> the platform builds must be *made*.
>
> **Scope.** In: uniform construction constraints binding **every artifact the platform
> builds** — the host configuration, the dev-container image, workload images, and every
> throwaway build and throwaway tree alike — whatever the artifact does. Out: intent and
> outcomes (the objective's), per-project requirements (each project's own locked spec),
> and the system's arrangement (the design's).
>
> **The aim:** that anything built under these principles is built the one proven way —
> minimal, provenanced, disposable, verified — without construction law being re-decided
> per artifact or per session.
>
> **Success and acceptance:** a change conforms when it passes every principle that
> applies to it — by mechanical scan where a scan exists, by adversarial review where
> judgment is required. A principle that cannot be checked cannot bind: each must be
> enforceable in fact, or it is defective.
>
> **No theatrical machinery — the standing rationale.** The platform's measured failure mode is scaffolding that looks like rigour: gates with nothing to gate, hooks and watchdogs watching each other, dead-man switches nobody would miss, tests asserting what a mock was told. Three principles are one immune response to it: a gate must be wired to a decision it can change (P3), a test must drive the real execution boundary (P8), and detection may only exist together with recovery (P10). The test for any new mechanism is always the same: name the outcome it changes, or don't build it.
>
> Consolidated from the fleet's `fedora-dev/00-BUILDPRINCIPLE.md` (BP1–BP9), the host-side
> instantiation drafted for `fedora-bootstrap`, the zero-base architectural review of the
> pair, and the twofold-objective restatement (2026-08-02). A mapping note closes this
> document.

## P1 — PROVENANCE

Every artifact entering any tree the platform builds — host, dev-container, workload, and every throwaway alike — is admitted **fail-closed and version-pinned at the strongest provenance its source admits**. Settling for a lower level when a higher one is available is a defect. Disposability grants no exemption.

**One pinned-fetch contract serves the whole platform.** Host and dev-container fetch pinned artifacts through the same mechanism at the same strength. Provenance is a platform constant, never a per-component achievement — a repo definition fetched unverified on the most privileged component while pinned on another is the canonical violation.

The OS-level instantiation is a three-level ladder: **L1** Fedora's own dnf repos; **L2** the vendor's own RPM or dnf `.repo` with `gpgcheck=1`, plus repo-metadata signatures where the vendor publishes them; **L3** last-resort official-upstream binary, provenance-graded — **c1** GPG signature over **c2** published checksum over **c3** resolve-log — and disclosed per artifact.

Forbidden outright, enforced by mechanical scan: COPR and third-party repos, language package managers onto PATH, tarballs onto PATH, curl-pipe-sh, mirror and aggregator binaries, flatpak, snap.

## P2 — VERIFY-BEFORE-ADOPT

Before any source, version, or artifact is adopted or bumped, its existence and identity are **fact-checked against the live upstream** — never asserted from memory or a stale pin. A risky install — a version-mismatched vendor RPM, a new `.repo`, an L3 binary — is **exercised in a scratch throwaway before it is wired into a real build file**.

Every adoption leaves a **recorded trail**: artifact, level and grade, pin, adoption date, last live-check date. The vendoring trail in the repo-genesis template set is the standing exemplar.

**Environment facts expire.** Provider console behaviour, cloud-image vintage, hardware, virtualization capability, GPU availability, network shape, package splits — all are re-verified against the live environment, per environment and per Fedora release. Their one home is the estate's environment registry. A new environment is onboarded by **verifying its facts, never by assuming them** — and never by forking the platform.

A source adopted without a live fact-check, or a risky install wired in unproven, is a reviewable defect.

## P3 — CAPABILITY-RELATIVE MINIMALISM

Every package and artifact enters at the **minimal leaf footprint for its decided capability**, and nothing enters any built tree without a **recorded justification**. The most specific leaf package wins over any convenience metapackage. The irreducible hard-dependency closure of a chosen capability is accepted and disclosed, not fought. (OS instantiation: `install_weak_deps=False` on every package installation, bootstrap paths included.)

Minimality is **capability-relative**. Between equal-capability options, prefer the smaller, higher-provenance one. **Dropping a capability to shrink the footprint is a recorded capability trade-off, never a minimalism win.**

**Gates are features.** Every gate, check, watcher, and probe is bound by the same justification — security machinery is not exempt. A mechanism is warranted only if it guards a real trust boundary, reads an artifact rather than an opinion, and is wired to a decision it can change. A check that can change no outcome is telemetry; it lives in the log, not in a gate. Machinery exists to move the objective's artifacts, **never to manage other machinery** — a component whose only consumer is another component's failure mode is the same component.

**Activation-proof.** No actuator is declared built until its first measured live success is recorded — a merged, unproven mechanism is scaffolding. A permanently red probe is deleted or fixed, never tolerated: a standing red trains the loop to ignore alarms, which is worse than no alarm.

## P4 — IMMUTABLE HOST / CONTAINERISE-EVERYTHING

The platform is container-first and Fedora CoreOS-style throughout. The host is immutable. Every application runs in a container. A virtual machine is allowed only where a workload genuinely requires one — a recorded capability decision per the objective.

Containers are immutable the same way. The **image is the artifact**; the running container is disposable. Durable state lives only in declared volumes. Change is rebuild-and-redeploy, never a live patch.

One invariant binds host and containers alike: **no mutable out-of-band change to any deployed artifact**. Every change is reproducible from its owning repository and flows the merge-and-deploy path. A mechanical check fails any change that violates this.

The host has two lineages, each with one sanctioned deploy mechanism:

- **VPS (cloud genesis).** A virtualised remote host running stock Fedora Cloud. Not a true CoreOS environment, but held to the same standard: host-immutable, everything in containers. Deployed by the **idempotent converger** — a re-run-safe converge script, run by the self-refresh actuators or the operator. Every mutation is declared in the repository. Any historical version re-runs safely. Ad-hoc drift vanishes on the next apply.
- **Bare metal (local genesis).** A local machine — currently the Minisforum MS-01 — running a custom **bootc image** built, with its installer media, from this repository. Kept current by **image rebase with atomic rollback**. Permanent data survives reinstalls.

Onboarding a new environment is an **adapter addition, never a fork**: a small per-environment piece added to this repository, never a copy of it. Moving an environment from converger to image-rebase is a design decision, not a conformance gap.

## P5 — THE THROWAWAY PRINCIPLE & CHURN

This is the pair's build-and-validation mechanism. Every build is a throwaway. The tree it builds from is a throwaway with it. Nothing ever builds from the host's live tree or the container's live tree — a throwaway tree is cut first, used, and torn down. This is what keeps both components immutable (P4) while the pair builds and validates work for any repository.

Scope. The throwaway principle governs build state on the pair's components — trees, images, run containers, caches. It never governs repository content: what lands on main through the merge path is the durable record, governed by P9 and P13. A shipped ticket's `specs/` folder accumulating on main is record, not drift.

Validation follows the objective's two tiers. A build validates inside the dev-container where possible. Only what the container cannot validate — PID 1 and boot-level behaviour, for example — runs on the host.

Teardown is total. An EXIT-trap, covering signal paths, removes every throwaway tree, image, and run container. An orphan sweeper reaps crash and kill leaks; the sweeper itself is scheduled and proven.

The only durable inputs are caches: a small, declared registry holding re-downloadable inputs only — never build output, never an image layer. The standard: anything cached re-downloads at zero bytes on the next iteration. Every cache is bounded by a hard ceiling under a scheduled, self-verifying actuator, so storage can never grow without limit. Eviction policy and numeric ceilings are architecture facts; they live in `ARCHITECTURE.md`, not here.

Churn discipline for images: heavy, stable layers early; churning layers late. Iterative rebuilds ride the layer cache. A full clean rebuild is a periodic, deliberate event — never part of churn.

## P6 — ISOLATED WORKING TREE

P5 governs what builds; this governs who works where. Every authoring or build action runs in a fresh working tree, namespaced to its session. No action mutates the live tree, a shared clone, or another session's tree. All mutable local state — worktree roots, locks, markers, scratch — is namespaced per session too.

Before every commit and every push, the checked-out branch is re-verified to belong to the session's own namespace. This holds at the authoring sites and at the harness's own commit and push sites alike — the harness being the most important case.

The `cd` into an isolated tree is a fail-closed guard, never a prefix. If the enter fails, no mutating step runs in the caller's directory.

A mutating action outside an isolated tree, or a commit or push without branch re-verification, is UNSAFE.

## P7 — ATOMIC CONTRACTS / RUNTIME COMPATIBILITY

This governs the pair's own protocol — the ticket bus, the verdict formats, and the refresh manifests the two components use to talk to each other. Every contract has one home: defined once in `shared/`, versioned, both sides reading the same definition. A contract change lands atomically — producer and consumer updated in the same merge, never separately.

The repository guarantees the source; the runtime still staggers. The two components upgrade at different moments, so for a window one side runs old code. Two rules cover that window. A consumer that receives a shape it does not recognise refuses it safely — it never guesses. A producer does not emit a new shape until the consumer that understands it is confirmed live.

A producer-first emission that can strand or wedge a not-yet-upgraded counterpart is UNSAFE.

## P8 — TEST-QUALITY / MUTATION-PROVEN

Every behavioural change ships a test, and the test drives the real execution boundary — the actual engine, git, kernel, or process semantics under test. A stub asserting what a mock was told proves nothing.

Every test is proven to fail against the pre-change code. A test that passes against the unfixed code is a defect, not a test. Guards are mutation-checked in-suite: the pre-fix behaviour is mechanically restored on a copy, and the guard's test must fail.

Production-only lines — the paths no test seam substitutes — are covered by a real-body test or by the live acceptance gate. The suite contains no line whose production invocation has never been executed; the measured lesson is that an untested production invocation fails silently at scale.

Validation that needs full virtualization or a GPU runs on the bare-metal track; the VPS track never simulates what it cannot run.

Tests gate the merge, bound to the exact head sha — the objective's distrust-made-structural, applied at the merge boundary. A test culture that cannot stop a merge is decoration. A permanently failing test or probe is fixed or removed, never tolerated (P3: no standing red).

## P9 — ONE HOME, DECISIONS ON RECORD

One authoritative home per concept; every other mention is a one-line pointer or deleted. The repository's documentation surfaces are exactly: the README, the objective (`OBJECTIVE.md`), this constitution, `AGENTS.md` (the session-loaded operating manual), `ARCHITECTURE.md` (the current-state map, agent-owned, mutable-on-fact, never a conformance target), the decision record (`decisions/`), the per-ticket work record (`specs/<NNN-slug>/` — Spec Kit verbatim, frozen at ship), and the changelog — nothing else accretes. A document asserting behaviour the code does not have is UNTRUE and a blocking finding.

The decision record is the loop's memory of its own reasoning. Every non-obvious decision is recorded as it is made: the problem, the options considered, the choice and why, and its fate — adopted, discarded, reversed, superseded. The road not travelled and the reversal are recorded with the same care as the road taken. Records are append-only: a reversed decision is closed by a superseding record, never erased. (This is the industry's Architecture Decision Record practice, adopted as standing law.)

Evidence and benchmarks live in the principle they prove. Incident narrative belongs to the changelog; reasoning belongs to the decision record. Memoir is not specification.

## P10 — RECOVERY-BEFORE-POWER

No mechanism may block the loop without carrying a bounded, automatic recovery. A gate that is unavailable, stalled, or erroring retries, fails over, or degrades under a recorded policy — and surfaces to the maintainer only after its bounded attempts fail.

Detection is only added together with recovery. A blocking gate with no self-heal path is UNSAFE: a fail-closed gate with no recovery is a human summons, and the objective's single-interaction law forbids those.

Every autonomous mutation is reversible — merge by revert, deploy by rollback, refresh by re-converge, closure by reopen. Each recovery path is proven by a test (P8), never by a standing drill framework that itself needs managing.

## P11 — DISPOSABLE AGENT LAYER (REBUILD, NEVER UPDATE)

The agent is a special class. Everything else is stable and immutable (P4); agent tooling moves too fast for that. So agents always run inside an **agent box** — a disposable distrobox layer on top of the immutable component — and the box absorbs the churn the component refuses.

Each box runs **one agent**: the **claudebox** runs Claude Code, the **kimibox** runs Kimi Code. A component may run **several boxes in parallel, one per agent**, because the agent landscape shifts faster than pairs can be provisioned. Boxes pair by agent across the two components: an agent present on the dev-container is present on its host. Every ticket is **stamped with its pair and its agent** — the strix pair's claudebox work is picked up only by the strix host's claudebox: never by another pair's claudebox (erebus), never by another agent on the same pair (the kimibox). Agents meet only at the ship gate's adversarial review, where reviewer and author are different agents — which running several agents on one pair is precisely what makes possible.

An agent box is pinned to the latest official release of its agent and **rebuilt nightly, never updated in place**; an on-demand rebuild is always available. The agent's own self-update is disabled by construction — a self-installed binary would shadow the managed one, survive the rebuild, and strand the layer stale while appearing current. Everything durable — credentials, transcripts, configuration — lives outside the layer, so a rebuild loses nothing.

Two rebuild modes exist. The **automatic nightly rebuild never interrupts a live session** — where it cannot yet resume reliably, live sessions block it until they quit; deferral is the fallback, never the steady state. The **maintainer's manual rebuild may interrupt**: on command it rebuilds, ends the running sessions, and restores the full multi-tenant session set. In both modes the standing rule is interrupt → rebuild → restart → resume: the live session set is captured before teardown — for a layer rebuild or a component refresh alike — and every session is restored to active work, working again, not merely present, and verified. Resume is possible by construction because the work's durable state is the ticket bus — sessions re-derive from what is co-written to GitHub, never from layer state.

Admission is a contract, not a name. Any agent — DeepSeek, Codex, Gemini, GPT, their successors — is admitted as a new box when it meets the contract: official provenance at the strongest level the vendor admits (P1), headless autonomous operation, self-update disabled, state outside the layer, and the loop's policy interface. Each admitted agent is recorded as an **admission manifest**; a failed one is a recorded non-admission.

## P12 — SELF-RENEWAL

The pair is three parts, always: **the GitHub ticket bus, the host, and the dev-container**. Self-renewal is those three making the pair's own improvement live with no human step.

The chain: a maintainer-instructed improvement merges; the host brings itself to the merged state via its deploy mechanism (P4); the host rebuilds and relaunches the dev-container from outside; the full multi-tenant session set is restored (P11). The dev-container never rebuilds itself — it requests its own renewal, and the host's, through the ticket bus. Each link is verified by reading the live artifact back, fail-closed.

Neither component rebuilds the agent doing the work. A renewal that cannot restore its sessions does not fire. A failed link recovers under P10 and surfaces to the maintainer only after bounded attempts fail.

## P13 — STANDING REPO STRUCTURE

Every repository the platform builds carries the same skeleton, known before the first line of code:

```
<repo>/
├── OBJECTIVE.md      the locked objective — WHY (maintainer-merge-only)
├── constitution.md   the build principles — HOW (maintainer-merge-only)
├── AGENTS.md         session-loaded operating manual for agents
├── ARCHITECTURE.md   current-state map — agent-owned, mutable-on-fact, never a conformance target
├── CHANGELOG.md      curated notable changes + incident narrative
├── README.md         human orientation
├── decisions/        ADRs — 0001-<slug>.md, append-only, status-tracked
├── specs/            per-ticket work record — <NNN-slug>/spec.md, plan.md, tasks.md (Spec Kit verbatim; NNN = issue number; frozen at ship)
└── <component tree — by runtime shape>
```

Filenames are contracts. Where a tool consumes the file, the name and case are the tool's: `constitution.md` and the per-ticket `spec.md` / `plan.md` / `tasks.md` per GitHub Spec Kit, `AGENTS.md` per the agents.md standard — the hosts' filesystems are case-sensitive, so a wrong-case name is an undiscovered file. Where no tool consumes the file (OBJECTIVE, README, ARCHITECTURE, CHANGELOG), the classic uppercase root convention holds. "Spec" means only what the kit means by it: a per-ticket specification; the repo-level lock is the objective.

The component tree adapts to the runtime shape — and only to the runtime shape:

- **Single artifact** (one container, one program): one source tree at root; no component split.
- **Host + container** (a dev pair): `host/`, `dev-container/`, `shared/`.
- **Container swarm** (containers working together): one folder per container, plus `shared/`.

`shared/` exists only where two or more components genuinely share code — nothing lands there to escape a boundary. Every file belongs unambiguously to exactly one component; there is no fourth place. A file that fits nowhere is an architecture smell: fix the architecture, not the filing.

---

## Mapping to the fleet's BP1–BP9 (provenance note)

P1=BP1 (strengthened: one fetch contract; repo-metadata signatures) · P2=BP2 (strengthened: environment/release re-verification; adoption trail) · P3=BP3 (extended: gates-are-features, activation-proof, no-standing-red) · P4=BP4 (amended 2026-08-15: container immutability made explicit; two host lineages named) · P5=BP5 (recast as the pair's build-and-validation mechanism) · P6=BP6 (strengthened: harness sites named) · P7=BP7 (rescoped as the pair's own protocol) · P8=BP8 (extended: mutation-proven; merge gate anchored to the objective) · P9=BP9 (recast: one home + decision record; vendoring clause re-homed to the layout law) · P10=new (codified from the measured gate-without-recovery incidents) · P11=new (agent layer: one agent per box, many boxes per pair, two rebuild modes, admission contract) · P12=new (self-renewal, codified from the measured forgetting failures) · P13=new (standing repo structure and filename contracts).
