# The Dev Pair — BYLAW (repo-specific build principles)

## Authority

Confirmed 2026-08-16 with the objective, sharing its authority, and fixed: amendment is a new maintainer confirmation, never a silent edit, and only the maintainer merges it. This is one of the two initiation artifacts (C2) — with the objective and, by reference, the constitution, the charter — co-created with the maintainer in the initiation session. It is subordinate to the universal constitution ([CONSTITUTION.md](CONSTITUTION.md)) — valid only where it does not conflict — and bare C-numbers below refer to it.

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

The chain: a maintainer-instructed improvement merges; the host brings itself to the merged state via its deploy mechanism (C7, instantiated below); the host rebuilds and relaunches the dev-container from outside; the full multi-tenant session set is restored (C8). The dev-container never rebuilds itself — it requests its own renewal, and the host's, through the ticket bus. Each link is verified by reading the live artifact back, fail-closed.

Neither component rebuilds the agent doing the work. A renewal that cannot restore its sessions does not fire. A failed link recovers under C11 and surfaces to the maintainer only after bounded attempts fail.

## Instantiations of universal law

This repository owns three instantiations — the estate's live implementations of universal principles, recorded here as fact.

**Provenance ladder — Fedora naming (instantiates C4).** C4 owns the ladder's shape, its grading, and the estate-wide forbidden categories; this repository names only the Fedora instances, so a repository on another platform inherits the law and writes only its own names. **L1** is Fedora's own dnf repositories. **L2** is the vendor's own RPM or dnf `.repo` with `gpgcheck=1`, and `repo_gpgcheck=1` where the vendor signs its metadata. **L3** is an official-upstream binary, graded and disclosed per C4. C4's forbidden categories take these local instances: COPR for community rebuild repositories; pip, npm, cargo, gem and brew for language package managers onto PATH; flatpak and snap for self-bundling formats.

**Minimalism flag (instantiates C3).** `install_weak_deps=False` on every package installation, bootstrap paths included.

**Host tracks and deploy mechanisms (instantiates C7).** A host belongs to one of two tracks, each with one sanctioned deploy mechanism:

- **VPS (cloud genesis).** A virtualised remote host running stock Fedora Cloud. Not a true CoreOS environment, but held to the same standard: host-immutable, everything in containers. Deployed by the **idempotent converger** — a re-run-safe converge script, run by the self-refresh actuators or the operator. Every mutation is declared in the repository. Any historical version re-runs safely. Ad-hoc drift vanishes on the next apply. Day zero is one pasted script: the host begins from the provider's stock Fedora Cloud image, reset from the console, and the maintainer pastes a single script into the root terminal — root's only act, ever. It creates `core`, joins the tailnet, activates the pair's GitHub App, hands off to the converger, and retires root. Everything after day zero flows the merge-and-deploy path.
- **Bare metal (local genesis).** A local machine — currently the Minisforum MS-S1 MAX — running a custom **bootc image** built, with its installer media, from this repository. Kept current by **image rebase with atomic rollback**. Permanent data survives reinstalls. Day zero here installs nothing: the image already carries every capability (C7), and identity — `core`, its keys, its sudo hash — is baked from the trust root at build, because declarations are records (C6). The maintainer's one act supplies only what an image may never hold: the live credentials — the tailnet join and the pair's GitHub App activation. Then root retires, and everything flows the merge-and-deploy path.

Onboarding a new environment is an **adapter addition, never a fork**: a small per-environment piece added to this repository, never a copy of it. Moving an environment from converger to image-rebase is an architecture decision, not a conformance gap. Environment facts live in the estate's environment registry (C5).
