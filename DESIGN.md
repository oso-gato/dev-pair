# The Dev Pair — DESIGN (dev-owned, mutable-on-fact)

> **THE ARRANGEMENT** — the functional requirements derived from the objective, and the
> architecture that serves them.
>
> **Status: dev-owned, mutable-on-fact.** This document serves `00-OBJECTIVES.md` and is
> built under `00-BUILDPRINCIPLE.md`. It is **never a conformance target**: it changes when
> facts change, by the loop's own merge path, without maintainer re-confirmation. It is not
> part of the authoritative document spine (objective, principles, runtime law, changelog);
> it is the working map from one to the other. If this document and the objective disagree,
> this document is defective.
>
> Part A is step **(a)** of the loop — the functional requirements. Part B is step **(b)** —
> the design that serves them. Part C is the build order for step **(c)**.

---

# Part A — Functional requirements

Every requirement is traced to the objective clause that demands it. A requirement with no
trace is scope creep; an objective clause with no requirement is a gap. Both are defects.

## A.1 The loop (objective §1 — the autonomous dev-pair loop)

- **FR-LOOP-1 — One-session initiation capture.** The platform must be able to take a
  maintainer's initiation session — objective, intended outcome, scope, boundaries — and
  lock the co-created result as `00-OBJECTIVE.md` at the root of the worked repository,
  with the governing build principles captured explicitly by reference in the same session.
  *Trace: §1 Initiation, Confirmation.*
- **FR-LOOP-2 — Objective-to-ship execution.** From a locked `00-OBJECTIVE.md`, the pair
  must autonomously derive requirements, architect, build, validate, and iterate in a live
  environment until the objective ships — with no human act after the one confirmation.
  *Trace: §1 Execution.*
- **FR-LOOP-3 — Automatic recovery.** Every autonomous mutation the loop performs must be
  reversible, and every blocking mechanism must carry a bounded automatic recovery that
  surfaces to the maintainer only after its bounded attempts fail. *Trace: §1 Execution
  ("recovering automatically from failure"); built per P10.*
- **FR-LOOP-4 — The ship gate.** Before a product ships, an independent adversarial review
  must verify it against the confirmed spec — objective first, then requirements, then
  principles — with reviewer and author from different agent lineages where the platform's
  lineages allow. A failed review returns the product to the loop. *Trace: Mechanics, "The
  ship gate."*

## A.2 Provisioning and convergence (objective §Platform, §Roles)

- **FR-PROV-1 — Cloud genesis.** Given nothing but a stock Fedora cloud image on any
  provider and remote access to it, the platform must turn it into a converged host with
  no local act, re-run-safe, idempotent, and fail-loud. *Trace: Platform, "cloud genesis
  (remote, channel-proof, no local act)"; Roles, host genesis.*
- **FR-PROV-2 — Local genesis.** The repository must build a custom bootc image
  (container-first, CoreOS-style, layered) and its installer media; installing a bare-metal
  machine from it and keeping it current by image rebase with atomic rollback, permanent
  data preserved across reinstalls. *Trace: Platform, "local genesis"; P4.*
- **FR-PROV-3 — Environment adapters.** The genesis path must be structured as a Fedora
  core plus a per-environment provisioning adapter, so onboarding a new provider or machine
  is an adapter addition, never a fork. Environment facts are verified inputs (P2), never
  baked-in assumptions. *Trace: Platform, "environment-agnostic by construction"; P4.*
- **FR-PROV-4 — Convergence from the repository only.** Every host change must be
  reproducible from this repository and flow the merge-and-deploy path; re-running the
  converger from any historical repository version must be safe, and ad-hoc drift must
  vanish on the next apply. *Trace: Boundaries, "No unmerged change is ever applied"; P4.*

## A.3 Refresh and resume (objective §Platform agent layer, §Mechanics "Merged is not live")

- **FR-REF-1 — Self-arming refresh.** A merge to this repository must arm the matching
  component refresh with no human step. *Trace: Mechanics, "self-arms the matching
  refresh."*
- **FR-REF-2 — Staggered outside-in refresh.** Each component must be refreshed from
  outside — the host refreshes the dev-container to the latest merged image; the
  dev-container instructs the host's agent to re-converge the host — so neither rebuilds
  the agent doing the work. *Trace: Mechanics; Roles ("refreshed from outside, by the
  host").*
- **FR-REF-3 — Read-back verification, fail-closed.** No refresh is done until the live
  artifact on the target is read back against merged source. Testimony is not acceptance.
  *Trace: Mechanics, "confirmed by reading the live artifact back against merged source,
  fail-closed."*
- **FR-REF-4 — Resume to active work, verified.** Before any refresh or agent-box rebuild
  tears anything down, it must capture the live session set; afterwards it must restore
  **every** session — all tenants — **to active work**: each session kick-started and
  working again, verified against work, never merely present. A refresh that cannot resume
  its sessions does not fire; where a refresh class cannot yet resume reliably, live
  sessions block it until they quit. *Trace: Platform agent layer; P11.*
- **FR-REF-5 — Three decoupled clocks.** Host OS, dev-container image, and each agent box
  advance on independent cadences; none forces a rebuild of the others. *Trace: Mechanics,
  "Three decoupled clocks."*

## A.4 The agent layer (objective §Platform agent layer; P11)

- **FR-BOX-1 — Two built lineages.** The platform must build and operate two agent-box
  lineages — claudebox (Claude Code) and kimibox (Kimi Code) — as disposable Distrobox
  layers on **both** the host and the dev-container. *Trace: Platform, "Two lineages are
  built now."*
- **FR-BOX-2 — Lineage as a provisioning parameter.** One box instance runs exactly one
  lineage, chosen at provisioning (default claudebox). Lineage must never fork the
  platform. *Trace: Platform; P11.*
- **FR-BOX-3 — Lineage admission contract.** Any further lineage (DeepSeek, Codex, Gemini,
  GLM, successors) is admitted when — and only when — it satisfies the contract: official
  provenance at the strongest admitted level, headless autonomous operation, self-update
  disabled by construction, state outside the layer, the loop's policy/permissions
  interface. Each admission or non-admission is recorded as a lineage manifest.
  *Trace: Platform; P11.*
- **FR-BOX-4 — Daily rebuild, never in-place update.** Each box tracks its vendor's
  releases on a daily rebuild cycle from the official channel; the tool's own self-update
  is disabled by construction; credentials, transcripts, and configuration live on
  persistent volumes outside the layer. *Trace: Platform, "daily refresh cycle"; P11.*

## A.5 Multi-tenant work and validation (objective §Mechanics)

- **FR-WORK-1 — Scope-enforced session isolation.** The dev-container must run an
  undefined number of agent sessions concurrently, each on its own declared repository
  set, isolated by scope and enforced in code: no session can read, touch, or iterate
  another session's work. *Trace: Mechanics, "Multi-tenant development"; P6.*
- **FR-WORK-2 — The ticket bus.** GitHub issues and pull requests are the first-class
  ticket bus; the dev-container never touches the host directly — it instructs the host's
  agent through the bus. *Trace: Mechanics, "first-class ticket bus."*
- **FR-WORK-3 — Two-tier validation.** A session must prove whatever it can inside the
  dev-container and engage the host only for the live validation the container cannot
  perform — iterating on the host's verdict until GREEN. Validation requiring full
  virtualization or a GPU routes to the bare-metal track; the VPS track never simulates
  what it cannot run. *Trace: Mechanics, "Two-tier validation"; Tracks.*
- **FR-WORK-4 — Sole merge authority under empirical gates.** The dev-container is the
  platform's only merger, and only under gates proven against the live artifact at
  check-time, by a non-author, bound to the exact head sha; the test suite must be able to
  stop a merge. The host never merges; the confirmed spec is maintainer-merge-only.
  *Trace: Roles; Mechanics, "Distrust, made structural"; Boundaries; P8.*
- **FR-WORK-5 — CI builds production images.** Production images are built by CI, never by
  either component; the host builds only throwaway validation candidates. No unmerged
  change is ever applied. *Trace: Boundaries.*
- **FR-WORK-6 — Per-pair authority and identity.** Each pair merges its own work and
  validates its own sessions under its own dedicated GitHub App identities, never shared
  across pairs; the platform operates only on repositories its App is installed on and
  never widens its own reach. *Trace: Platform, "Authority is per-pair"; Boundaries.*

## A.6 Mother platform (objective §2)

- **FR-APP-1 — Apps and services as containers.** The host must be able to spin up, run,
  and remove containers as apps and services pulled from a registry, each app its own
  container — without disturbing the pair, which always comes up foremost and first.
  *Trace: §2.*
- **FR-APP-2 — GPU as shared substrate.** On the bare-metal track, the host's GPU must be
  shareable to containers and virtual machines, never monopolised away from the host.
  *Trace: Tracks, "GPU acceleration."*

## A.7 Access and security (objective §Access and security objectives)

- **FR-SEC-1 — Minimal public surface.** The only public-internet doors on either
  component are hardened secure-shell access (SSH/MOSH-type); every other service is
  reachable only from private networks (tailnet everywhere, LAN on a local pair), bounded
  at the network layer. *Trace: Access §1.*
- **FR-SEC-2 — Key-only shell authentication.** Every shell path on both components,
  public or private, authenticates by SSH keys only; the maintainer's published key set is
  the single trust root. *Trace: Access §2.*
- **FR-SEC-3 — Session persistence as an outcome.** Interactive sessions must survive
  frequent disconnections and persist long-term, resumable exactly where they were from
  any authorized device with no loss of running state, transcript, or work context. The
  mechanism is the design's choice against current best practice. *Trace: Access §3.*

## A.8 Coverage check

Every objective clause traces to at least one requirement: twofold objective → A.1, A.6;
platform and provisioning → A.2, A.4; tracks → A.5 (FR-WORK-3), A.6 (FR-APP-2); roles →
A.2, A.3, A.5; mechanics → A.1, A.3, A.5; access → A.7; boundaries → A.2 (FR-PROV-4), A.5
(FR-WORK-4..6). Every requirement above carries its trace. No orphans, no gaps — and any
future amendment to the objective re-runs this check.

---

# Part B — The architecture

Zero-base doctrine, stated once: **one loop, two empirical gates, three host verbs, one
watcher per clock, one versioned bus, four authoritative documents. Machinery touches
artifacts, never other machinery.** Everything below is an instance of that doctrine or it
does not belong here.

## B.1 The one loop

A single cycle drives all work, on both tracks:

1. A ticket exists on the bus (opened by the maintainer's initiation, by a session, or by
   the ship gate's verdict).
2. A session claims it, authors in an isolated tree (P6), proves what it can in-container
   (tier-1), and requests host verdicts through the bus for what it cannot (tier-2).
3. The merge authority merges only when the empirical gates pass against the exact head
   sha (FR-WORK-4).
4. The merge self-arms the refresh (FR-REF-1); the stagger applies it outside-in
   (FR-REF-2); read-back confirms it (FR-REF-3); sessions resume to active work
   (FR-REF-4).
5. Shipping a product adds the ship gate (FR-LOOP-4) before the door.

There is no second loop, no supervisory loop, no meta-loop. Recovery is a property of each
step (P10), not a parallel apparatus.

## B.2 The two empirical gates

Only two mechanisms may stop work, each passing the gates-are-features warrant (real trust
boundary, reads an artifact, wired to a decision it can change):

- **G1 — the merge gate.** Runs the suite bound to the exact head sha, in the
  dev-container, executed by a non-author. Boundary: unmerged → merged. Artifact: the tree
  at that sha. Decision: merge or not.
- **G2 — the live gate.** Reads the live artifact back against merged source after a
  refresh, per artifact (`host/` changes gate the host, `dev-container/` changes gate the
  dev-container, `shared/` gates both). Boundary: merged → live. Artifact: the running
  system. Decision: confirm or roll back.

The ship gate (FR-LOOP-4) is a review, not a standing mechanism: it convenes per product,
adversarial and cross-lineage, and dissolves. Everything else that smells like a check is
telemetry and lives in the log (P3).

## B.3 The three host verbs

The host exposes exactly three operations to the bus; there is no fourth:

- **converge** — apply the repository's declared host state (FR-PROV-1, FR-PROV-4),
  idempotent, re-run-safe, fail-loud.
- **refresh** — replace the dev-container (or an app container) with a newer merged image
  (FR-REF-2), bounded, health-gated, rolled back on failure.
- **validate** — execute a tier-2 verdict request against the live host and return the
  artifact of the result (FR-WORK-3): it runs the check and hands back evidence, never an
  opinion.

The host's claudebox serves these verbs and nothing else; proposing changes (live-diagnose,
develop fixes, open PRs) is ordinary session work that ends on the bus, never in an apply.

## B.4 The one watcher per clock

Three clocks (FR-REF-5), one watcher each, no more:

- **repo clock** — a merged commit to this repository arms the staggered refresh. This is
  the platform's single self-arm watcher.
- **image clock** — a newer merged dev-container image arms the host's `refresh` verb on
  the dev-container.
- **box clock** — the daily timer arms each agent box's rebuild (FR-BOX-4).

Every watcher carries the same standing rule: capture the session set, act, resume every
session to active work, verify — or, for an unproven resume class, defer until live
sessions quit (FR-REF-4, P11). A watcher that cannot resume does not fire; a permanently
red watcher is fixed or deleted, never tolerated (P3).

## B.5 The one versioned bus

GitHub issues and pull requests are the only channel between components and between
sessions (FR-WORK-2). All machine-readable grammars on the bus — ticket envelopes, verdict
formats, refresh manifests, lineage manifests — are defined once, versioned, in `shared/`
(P7). Consumers fail-safe refuse shapes they do not recognize; new producer emissions stay
gated off until the consuming side is confirmed live (G2).

## B.6 The component arrangement

- **`host/`** — structured as **Fedora core + adapters** (FR-PROV-3). The core is the
  converger: a declared, idempotent host-state applier owning the three verbs. The **cloud
  adapter** turns a stock Fedora cloud image into a converged host (FR-PROV-1). The
  **local adapter** builds the bootc image and installer media and keeps the machine
  current by rebase with atomic rollback (FR-PROV-2). Onboarding an environment is an
  adapter addition, never a fork.
- **`dev-container/`** — the image and its operating harness: session isolation by scope
  in code (FR-WORK-1), the merge authority under G1 (FR-WORK-4), tier-1 validation, and
  the bus client. Highly stable by design: it changes only through the merge-and-deploy
  path.
- **The agent layer** — a Distrobox layer on each component, one lineage per box instance
  chosen at provisioning (FR-BOX-2), rebuilt daily from the official channel with
  self-update disabled (FR-BOX-4), all durable state on persistent volumes outside the
  layer. Two lineage manifests ship now — claudebox, kimibox — each recorded against the
  admission contract (FR-BOX-3).
- **`shared/`** — the versioned grammars of B.5 and nothing else. If only one side uses
  it, it belongs to that side.

## B.7 Session persistence and resume — mechanism choice (FR-SEC-3, FR-REF-4)

The objective names the outcome; the design picks the current best practice, changeable
without amending the objective:

- **Persistence:** interactive shells run inside a terminal multiplexer on the component
  they belong to, so client disconnects, roams, and sleeps cost nothing — the session
  lives server-side and is re-attached from any authorized device. Long-term persistence
  is the default state, not a feature: nothing reaps idle sessions.
- **Roaming access:** the public door pairs hardened SSH with a roaming-capable shell
  transport so network changes do not drop the connection at all.
- **Resume-to-active-work:** a session's durable state is the bus and its repositories —
  work is co-written to GitHub, never held only in a layer. Resume therefore means:
  re-attach the multiplexer session, re-derive the work context from the bus and the
  repo, and **kick the session back into motion** — a resumed session that sits idle is a
  stalled session and the refresh is not done (P11). The verification reads the session's
  first post-resume action against the artifact, not its presence.

## B.8 Access arrangement (A.7)

Both components run a hardened SSH service as the only public door, key-only, with the
maintainer's published key set as the single trust root; the roaming transport rides the
same door. Everything else — dashboards, consoles, app interfaces — binds to private
networks only: the tailnet on every pair, the LAN additionally on a local pair, enforced
at the firewall, not by application config. Per-service authentication on private services
is hardened and per-service, never shared, never default.

## B.9 What is deliberately not built

Recorded per P3 — each exclusion is a decision, revisitable on new facts:

- **No supervisory orchestrator.** No component whose only consumer is another
  component's failure mode. Recovery lives inside each mechanism (P10).
- **No LLM-as-gate.** Judgment may propose; only artifact-reading mechanisms decide
  (the fleet's injectable reviewer-gate is the canonical anti-pattern).
- **No standing drill framework.** Recovery paths are proven by tests (P8), not by a
  drilled apparatus that itself needs managing.
- **No per-component provenance machinery.** One pinned-fetch contract serves host,
  dev-container, and boxes alike (P1).
- **No parity checkers between documents.** De-duplication is the fix; the spine stays
  four documents (P9).
- **No standing human tap anywhere.** Any mechanism that can only stall is a defect by
  definition (P10; objective §Mechanics).

## B.10 Trade-off register

Conflicts between objective clauses, evaluated and recorded as they arise (Mechanics,
"Minimal machinery"). Initial entries:

- **T1 — Daily box rebuild vs. uninterrupted sessions.** Resolved by the standing rule:
  interrupt → rebuild → restart → resume-to-active-work, with deferral only as the
  fallback for unproven resume classes. Currency wins by default; continuity is preserved
  by resume, not by skipping rebuilds. *Recorded 2026-08-02.*
- **T2 — Merge authority concentrated in the dev-container vs. host independence.** The
  host never merges, so the pair has exactly one authority to reason about; the cost is
  that a dead dev-container pauses merges while a dead host pauses nothing but tier-2 and
  refresh. Accepted: one authority, per pair, is the minimal trustworthy arrangement.
  *Recorded 2026-08-02.*

---

# Part C — Build order

Step **(c)** builds in dependency order, each increment landing through the loop's own
path as soon as that path exists, earliest artifacts hand-verified until the gates stand:

1. **`shared/` grammars v1** — ticket envelope, verdict format, refresh manifest, lineage
   manifest. Everything else speaks these; they change only atomically (P7).
2. **`host/` Fedora core + cloud adapter** — the converger and the three verbs, proven on
   a live VPS (the fleet's proven path, rebuilt under P1–P11: pinned fetch, FETCH_HEAD
   race closed, no bare-curl repo fetches).
3. **`dev-container/` image + harness skeleton** — session isolation and the bus client.
4. **The agent layer** — Distrobox layer + claudebox lineage manifest, daily rebuild with
   resume verified against work; kimibox immediately after, identical contract.
5. **G1 + merge authority** — the suite gating merges at the exact head sha; from this
   increment on, everything lands through the loop (dogfooding begins).
6. **Self-arm + stagger + G2** — the repo watcher, the image watcher, read-back
   verification, rollback.
7. **Resume-to-active-work for component refreshes** — session-set capture, restore,
   kick-start, work-verified.
8. **FR-APP-1** — the mother-platform app primitive on host `box`, the genesis agent.
9. **The local adapter** — bootc image build + installer + rebase, drawing on the
   `strix-ms-s1-bootc` lineage; brings the bare-metal track and full-virt/GPU validation
   online.

Each increment ships with its tests (P8), its recovery (P10), and its activation-proof
(P3): nothing is declared built until its first measured live success is recorded in the
changelog.
