# The Dev Pair — CONSTITUTION (repo-specific build principles)

> **Status: DRAFT — pending maintainer confirmation.** Confirmed with the objective (`OBJECTIVE.md`) and sharing its authority: fixed thereafter, amendment is a new maintainer confirmation, MAINTAINER-MERGE-ONLY.
>
> **Universal law, applied by reference.** The estate's universal constitution — `principles/constitution.md` in the estate's root repository (private; resolvable by the pair's agents), P1–P11 — governs all work here. It is never re-dictated; a re-dictation is a fork. Bare P-numbers below refer to it. This document adds only what is this repository's own: four repo-specific principles (R1–R4) and the instantiations of universal law this repository owns.

## R1 — THE THROWAWAY PRINCIPLE & CHURN

This is the pair's build-and-validation mechanism. Every build is a throwaway. The tree it builds from is a throwaway with it. Nothing ever builds from the host's live tree or the container's live tree — a throwaway tree is cut first, used, and torn down. This is what keeps both components immutable (P7) while the pair builds and validates work for any repository.

Scope. The throwaway principle governs build state on the pair's components — trees, images, run containers, caches. It never governs repository content: what lands on main through the merge path is the durable record, governed by P1 and P2. A shipped ticket's `specs/` folder accumulating on main is record, not drift.

Validation follows the objective's two tiers. A build validates inside the dev-container where possible. Only what the container cannot validate — PID 1 and boot-level behaviour, for example — runs on the host.

Teardown is total. An EXIT-trap, covering signal paths, removes every throwaway tree, image, and run container. An orphan sweeper reaps crash and kill leaks; the sweeper itself is scheduled and proven.

The only durable inputs are caches: a small, declared registry holding re-downloadable inputs only — never build output, never an image layer. The standard: anything cached re-downloads at zero bytes on the next iteration. Every cache is bounded by a hard ceiling under a scheduled, self-verifying actuator, so storage can never grow without limit. Eviction policy and numeric ceilings are architecture facts; they live in `ARCHITECTURE.md`, not here.

Churn discipline for images: heavy, stable layers early; churning layers late. Iterative rebuilds ride the layer cache. A full clean rebuild is a periodic, deliberate event — never part of churn.

## R2 — ISOLATED WORKING TREE

R1 governs what builds; this governs who works where. Every authoring or build action runs in a fresh working tree, namespaced to its session. No action mutates the live tree, a shared clone, or another session's tree. All mutable local state — worktree roots, locks, markers, scratch — is namespaced per session too.

Before every commit and every push, the checked-out branch is re-verified to belong to the session's own namespace. This holds at the authoring sites and at the harness's own commit and push sites alike — the harness being the most important case.

The `cd` into an isolated tree is a fail-closed guard, never a prefix. If the enter fails, no mutating step runs in the caller's directory.

A mutating action outside an isolated tree, or a commit or push without branch re-verification, is UNSAFE.

## R3 — ATOMIC CONTRACTS / RUNTIME COMPATIBILITY

This governs the pair's own protocol — the ticket bus, the verdict formats, and the refresh manifests the two components use to talk to each other. Every contract has one home: defined once in `shared/`, versioned, both sides reading the same definition. A contract change lands atomically — producer and consumer updated in the same merge, never separately.

The repository guarantees the source; the runtime still staggers. The two components upgrade at different moments, so for a window one side runs old code. Two rules cover that window. A consumer that receives a shape it does not recognise refuses it safely — it never guesses. A producer does not emit a new shape until the consumer that understands it is confirmed live.

A producer-first emission that can strand or wedge a not-yet-upgraded counterpart is UNSAFE.

## R4 — SELF-RENEWAL

The pair is three parts, always: **the GitHub ticket bus, the host, and the dev-container**. Self-renewal is those three making the pair's own improvement live with no human step.

The chain: a maintainer-instructed improvement merges; the host brings itself to the merged state via its deploy mechanism (P7, instantiated below); the host rebuilds and relaunches the dev-container from outside; the full multi-tenant session set is restored (P8). The dev-container never rebuilds itself — it requests its own renewal, and the host's, through the ticket bus. Each link is verified by reading the live artifact back, fail-closed.

Neither component rebuilds the agent doing the work. A renewal that cannot restore its sessions does not fire. A failed link recovers under P11 and surfaces to the maintainer only after bounded attempts fail.

## Instantiations of universal law

This repository owns three instantiations — the estate's live implementations of universal principles, recorded here as fact.

**Provenance ladder (instantiates P4).** The OS-level hierarchy: **L1** Fedora's own dnf repos; **L2** the vendor's own RPM or dnf `.repo` with `gpgcheck=1`, plus repo-metadata signatures where the vendor publishes them; **L3** last-resort official-upstream binary, provenance-graded — **c1** GPG signature over **c2** published checksum over **c3** resolve-log — and disclosed per artifact. Forbidden outright, enforced by mechanical scan: COPR and third-party repos, language package managers onto PATH, tarballs onto PATH, curl-pipe-sh, mirror and aggregator binaries, flatpak, snap.

**Minimalism flag (instantiates P3).** `install_weak_deps=False` on every package installation, bootstrap paths included.

**Host lineages and deploy mechanisms (instantiates P7).** The host has two lineages, each with one sanctioned deploy mechanism:

- **VPS (cloud genesis).** A virtualised remote host running stock Fedora Cloud. Not a true CoreOS environment, but held to the same standard: host-immutable, everything in containers. Deployed by the **idempotent converger** — a re-run-safe converge script, run by the self-refresh actuators or the operator. Every mutation is declared in the repository. Any historical version re-runs safely. Ad-hoc drift vanishes on the next apply.
- **Bare metal (local genesis).** A local machine — currently the Minisforum MS-S1 MAX — running a custom **bootc image** built, with its installer media, from this repository. Kept current by **image rebase with atomic rollback**. Permanent data survives reinstalls.

Onboarding a new environment is an **adapter addition, never a fork**: a small per-environment piece added to this repository, never a copy of it. Moving an environment from converger to image-rebase is an architecture decision, not a conformance gap. Environment facts live in the estate's environment registry (P5).
