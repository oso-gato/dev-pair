# The Dev Pair — BYLAW (repo-specific build principles)

## Authority

Confirmed 2026-08-16 with the objective, sharing its authority, and fixed: amendment is a new maintainer confirmation, never a silent edit, and only the maintainer merges it. This is one of the two initiation artifacts (C2) — with the objective and, by reference, the constitution, the charter — co-created with the maintainer in the initiation session. It is subordinate to the universal constitution ([CONSTITUTION.md](CONSTITUTION.md)) — valid only where it does not conflict — and bare C-numbers below refer to it.

The 2026-11-10 revision records the requested Codex and Podman design and awaits the charter merge. [CONSTITUTION.md](CONSTITUTION.md) records the maintainer-directed departure from C8's runtime placement; all other universal principles continue to apply.

## B1 — THE THROWAWAY PRINCIPLE & CHURN

This is the pair's build-and-validation mechanism. Every build is a throwaway. The tree it builds from is a throwaway with it. Nothing ever builds from the host's live tree or the container's live tree — a throwaway tree is cut first, used, and torn down. This is what keeps both components immutable (C7) while the pair builds and validates work for any repository.

Scope. The throwaway principle governs build state on the pair's components — trees, images, run containers, caches. It never governs repository content: what lands on main through the merge path is the durable record, governed by C1 and C2. A shipped ticket's `docs/specs/` folder accumulating on main is record, not drift.

Validation follows the objective's two tiers. A build validates inside the dev-container where possible. Only what the container cannot validate — PID 1 and boot-level behaviour, for example — runs on the host.

Teardown is total. An EXIT-trap, covering signal paths, removes every throwaway tree, image, and run container. An orphan sweeper reaps crash and kill leaks; the sweeper itself is scheduled and proven.

The only durable inputs are caches: a small, declared registry holding re-downloadable inputs only — never build output, never an image layer. The standard: anything cached re-downloads at zero bytes on the next iteration. Every cache is bounded by a hard ceiling under a scheduled, self-verifying actuator, so storage can never grow without limit. Eviction policy and numeric ceilings are architecture facts; they live in `ARCHITECTURE.md`, not here.

Churn discipline for images: heavy, stable layers early; churning layers late. Iterative rebuilds ride the layer cache. A full clean rebuild is a periodic, deliberate event — never part of churn.

## B2 — ISOLATED WORKING TREE

B1 governs what builds; this governs who works where. Every authoring or build action runs in a fresh working tree, namespaced to its session. No action mutates the live tree, a shared clone, or another session's tree. All mutable local state — worktree roots, locks, markers, scratch — is namespaced per session too.

Before every commit and every push, the checked-out branch is re-verified to belong to the session's own namespace. This holds at the authoring sites and at the harness's own commit and push sites alike — the harness being the most important case.

The `cd` into an isolated tree is a fail-closed guard, never a prefix. If the enter fails, no mutating step runs in the caller's directory.

A mutating action outside an isolated tree, or a commit or push without branch re-verification, is UNSAFE.

## B3 — ATOMIC CONTRACTS / RUNTIME COMPATIBILITY

This governs the pair's own protocol — the ticket bus, the verdict formats, and the refresh manifests the two components use to talk to each other. Every contract has one home: defined once in `shared/`, versioned, both sides reading the same definition. A contract change lands atomically — producer and consumer updated in the same merge, never separately.

The repository guarantees the source; the runtime still staggers. The two components upgrade at different moments, so for a window one side runs old code. Two rules cover that window. A consumer that receives a shape it does not recognise refuses it safely — it never guesses. A producer does not emit a new shape until the consumer that understands it is confirmed live.

A producer-first emission that can strand or wedge a not-yet-upgraded counterpart is UNSAFE.

## B4 — SELF-RENEWAL

Self-renewal is the pair's three parts — **the GitHub ticket bus, the host, and the dev-container** (the objective's definition) — making the pair's own improvement live with no human step.

The chain: a maintainer-instructed improvement merges; CI builds the required production images; the host brings itself to the merged state via its deploy mechanism (C7, instantiated below); the host pulls the verified image and relaunches the dev-container from outside; the active job set resumes from durable checkpoints. The dev-container never replaces itself — it requests its own renewal, and the host's, through the ticket bus. Each link is verified by reading the live artifact back, fail-closed.

Neither component rebuilds the agent doing the work. A renewal that cannot restore its sessions does not fire. A failed link recovers under C11 and surfaces to the maintainer only after bounded attempts fail.

## B5 — PODMAN AND CODEX RUNTIME

Podman is the pair's container runtime. Rootless containers are managed through Quadlet and systemd; Docker Engine and a Docker daemon are not platform dependencies.

The development worker is the dev-container itself: Codex, project tools and tests run directly in that container, with a persistent project workspace. No nested Distrobox or second agent container is required inside it. The maintenance Codex runs in a separate Podman container on the Fedora host.

Development containers receive no host Podman socket, host administration credentials or unrestricted host execution bridge. They request host operations through the ticket bus. The maintenance role reaches only declared operations through a controlled host interface; it does not gain unrestricted passwordless sudo merely because it is autonomous.

Concurrent jobs use separate rootless container instances with separate workspace, Codex state and credential mounts. A Git worktree separates edits but does not by itself enforce access isolation. Host administration and development workloads use distinct service identities and permissions; `core` remains the human administrative identity. Resource ceilings and bounded cleanup apply to every job.

The new runtime retains SELinux confinement and default capability restrictions unless a specific required operation has a measured, recorded exception. The nesting exception in ADR 000029 is not inherited automatically by the replacement.

Codex versions and containing images are pinned and admitted under C4 and C5. Updates rebuild images, preserve external state and pass validation before rollout. The migration must verify an official installation route and record its provenance before adopting it; this requirements change does not waive installation restrictions or declare a Codex package admitted.

## B6 — DELIVERY EVIDENCE

The five-stage working method remains, with records proportional to the change. Acceptance criteria are written before implementation, and execution continues through tests, independent review, deployment and live verification before delivery.

The reviewer runs in a separate Codex session with the confirmed requirements and the exact candidate available for inspection. It cannot alter the candidate to make its review pass. A release binds its source revision, image digest or artifact checksum, test results and review result together; a new candidate invalidates the previous release verdict.

The development side retains the existing merge role, but release checks are enforced outside the author session. A product job cannot weaken its own required checks or substitute an author statement for independent evidence. Platform policy changes follow their own reviewed change path.

Recovery is demonstrated at the real boundary: interrupt a job and resume its work, reject an unhealthy deployment and recover, and restore durable data into a clean destination. Failures consume bounded attempts and produce a blocker report when recovery is exhausted. Numeric limits belong in the project's confirmed requirements and runtime configuration.

## Instantiations of universal law

This repository declares one platform and the required deploy mechanisms below. [ARCHITECTURE.md](ARCHITECTURE.md) records which parts exist and have been applied; a requirement here is not evidence of live implementation.

**Platform (declares under C4).** This repository builds on Fedora. C4 carries both platforms' ladder names, their minimalism flags and their forbidden instances; none of it is restated here.

**Host tracks and deploy mechanisms (instantiates C7).** A host belongs to one of two tracks, each with one sanctioned deploy mechanism:

- **VPS (cloud genesis).** A virtualised remote host running stock Fedora Cloud. Not a true CoreOS environment, but held to the same standard: host-immutable, everything in containers. Deployed by the **idempotent converger** — a re-run-safe converge script, run by the self-refresh actuators or the operator. Every mutation is declared in the repository. Any historical version re-runs safely. Ad-hoc drift vanishes on the next apply. Day zero is one pasted script: the host begins from the provider's stock Fedora Cloud image, reset from the console, and the maintainer pastes a single script into the root terminal — root's only act, ever. It creates `core`, joins the tailnet, activates the pair's GitHub App, hands off to the converger, and retires root. Everything after day zero flows the merge-and-deploy path.
- **Bare metal (local genesis).** A local machine — currently the Minisforum MS-S1 MAX — running a custom **bootc image** built, with its installer media, from this repository. Kept current by **image rebase with atomic rollback**. Permanent data survives reinstalls. Day zero here installs nothing: the image already carries every capability (C7), and identity — `core`, its keys, its sudo hash — is baked from the trust root at build, because declarations are records (C6). The maintainer's one act supplies only what an image may never hold: the live credentials — the tailnet join and the pair's GitHub App activation. Then root retires, and everything flows the merge-and-deploy path.

Onboarding a new environment is an **adapter addition, never a fork**: a small per-environment piece added to this repository, never a copy of it. Moving an environment from converger to image-rebase is an architecture decision, not a conformance gap. Environment facts live in the estate's environment registry (C5).
