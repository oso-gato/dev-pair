# Dev-pair architecture

This document describes the intended architecture. It has not yet been implemented or verified on a live host. Shared governance and engineering standards are pinned in [STANDARDS.md](STANDARDS.md); product acceptance criteria live in [REQUIREMENTS.md](REQUIREMENTS.md). This file records the project-specific design and operating choices.

## Platform

Use Fedora Cloud 45 for the first VPS and versioned Fedora 45 base images for the agent environments. Verify the provider image, architecture, runtime capabilities and official image identities before adoption. Pin deployed images by digest and record their source revisions. Apply tested maintenance updates; a major Fedora upgrade is a deliberate platform change, never an automatic consequence of a floating `latest` tag.

Use rootless Podman with Quadlet and systemd. Docker Engine is not a dependency. Keep SELinux enforcing and retain container confinement; an exception requires a demonstrated need and a recorded scope.

## Roles and isolation

The maintenance agent runs in its own Podman container and uses a controlled host-operation interface for deployment, health checks and recovery. It does not receive unrestricted passwordless administration. Keep a documented operator recovery path that works when the agent is unavailable.

DevBox is the development-role container, distinct from the `agentbox` provider selector. Its Codex agent runs directly inside the development container alongside project tools and tests. No additional Distrobox agent layer is required. Give it its own workspace and runtime state, without the host Podman socket, host administration credentials or unrestricted host execution bridge.

Use separate service permissions for the two roles and separate credentials and state for each job. Durable work lives in declared volumes or external storage, not only in disposable image layers. Apply resource limits and bounded cleanup. Add concurrent workers only after their access isolation and resource handling have been tested.

## Development and host validation protocol

DevBox owns clarification, implementation, local unit/integration testing and consumption of host-test results. GitHub issues and PRs provide the durable request and evidence references. The maintenance agent owns the controlled host executor; it never treats a ticket or repository script as authority to run arbitrary host commands.

| Message | Required information |
|---|---|
| Test request | Job/request ID; source revision and artifact digest when applicable; test revision and recipe; reason DevBox is insufficient; required host capabilities; permitted effects; workspace/data fixtures; expected outcomes; time/resource limits; cleanup plan |
| Test result | Request and candidate IDs; executor/environment identity; pass/fail/blocked per check; expected versus actual behaviour; exit status and diagnostic/evidence locations; side effects and cleanup status |

The maintenance side checks capabilities, allowed operations, candidate identity and resource limits before executing. Untrusted candidate code runs with confined job permissions; the controlled host interface exposes only declared operations. The request path never exposes the host Podman socket or host administration credentials to DevBox. Passing results are evidence for their exact candidate and environment, not permission to broaden the next request.

Run each check in the least-privileged environment that can prove it. Local function/unit and suitable integration checks run in DevBox. Host checks can exercise a disposable candidate under the actual host service manager, network or confinement boundary using job-owned resources. Boot changes, destructive system tests, or checks requiring writes to the live OS need a designated disposable VM/VPS or equivalent real target. If unavailable, return blocked; do not claim nested execution proves that behaviour. Preserve the live pair for ongoing development.

DevBox reads returned diagnostics, repairs the candidate and repeats affected local and host checks. Persist request state and results so interruptions can resume or reconcile a request without repeating a destructive action. Duplicate requests reuse a matching completed result or reconcile the previous attempt; they do not blindly replay it. Reject a result whose candidate/test identity no longer matches the required check.

Define each message schema once, version it, and update producer and consumer definitions together. During staggered runtime renewal, reject unknown versions safely and do not emit a new schema until the receiving side supports it. This is a protocol compatibility requirement, not a reason to introduce a separate orchestration framework.

## Protected Fedora roots and writable work areas

Protect the running host and agent-container Fedora OS trees from product build and test writes. Configure DevBox and the maintenance container with read-only image roots and explicit writable mounts for job work, agent state and necessary temporary/runtime data. Run build code without privileges that can remount or alter protected roots. On the host, confined job execution may write only its declared data/test resources, not system package paths or configuration. A build directory alone does not enforce this boundary.

Install baseline tools when constructing a new candidate image. Per-project dependencies belong in a job dependency environment, isolated build root or disposable builder image, never in the running host or DevBox OS. Any image-building backend must preserve the same boundaries; do not grant the worker a host socket simply to build images. Platform updates use the separate approved provisioning/replacement path.

The runtime must declare the following storage classes and ownership:

| Storage | Lifetime and handling |
|---|---|
| Source workspaces, uncommitted edits, checkpoints, evidence, deliverables | Durable per project/job; protected from build cleanup and container replacement |
| Build trees, fetched source copies, generated outputs, test fixtures and candidates | Job-owned and disposable; reusable while active; removed at safe lifecycle boundaries |
| Verified downloads, dependency/compiler caches and reusable image layers | Bounded by compatibility, trust scope and resource budgets; no secrets; safe reuse and selective invalidation |
| Agent credentials/state and temporary runtime data | Explicit mounts with minimal scope; retention appropriate to recovery and confidentiality |

A job owns its source worktree, branch, locks and build paths. Verify workspace and branch identity before mutations, commits and pushes; a failed workspace entry stops the action rather than falling back to the caller's directory. Neither cleanup nor a test may modify another job's workspace.

Record source/dependency identities, toolchain/base image, target and build options for compatibility checks. Retain valid build directories and caches across the active loop; invalidate affected outputs when those inputs change. Verify a clean candidate in a separate output root when needed. Keep stable image inputs reusable and changing inputs separate so a source edit does not force every dependency to download again.

Before runtime use, configure disk ceilings, active-use protection, idle retention and cleanup events. Reclaim completed/abandoned or expired inactive trees after preserving durable outputs. Reconcile orphaned resources after crashes, but never identify an active workspace as garbage merely because a worker restarted. At capacity, evict eligible inactive data and checkpoint/pause if insufficient; do not purge in-use caches mid-build. Report cache hits, actual downloads and space reclaimed as evidence for the reuse and cleanup acceptance criteria.

Podman provides [read-only container roots and explicit writable mounts](https://docs.podman.io/en/latest/markdown/podman-run.1.html); [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) integrates containers with systemd. These are design inputs, not proof that the proposed enforcement or host-testing route works; verify the selected Fedora/Podman versions during implementation.

## Agent selection

- `gptbox` identifies OpenAI Codex.
- `claudebox` identifies Claude Code.
- `agentbox` resolves to the configured default, initially `gptbox` for both roles.

Explicit selection overrides the default for a new session. Resolve and record the concrete agent, role, runtime version and selected model when a job starts. Existing and resumed jobs keep that selection when the default changes. The agent default does not prescribe a particular model version.

Share lifecycle code for launch, durable state, renewal and routing. Keep installation, authentication, invocation, configuration and resume in small agent-specific adapters. An unavailable or unvalidated selection fails clearly; it never silently switches provider. Build and validate the Codex adapter first. Reserving the Claude name does not require implementing its adapter for the first milestone.

## Development and release

Apply the adopted engineering standards to the product acceptance criteria in [REQUIREMENTS.md](REQUIREMENTS.md). The following rules specialize the pair’s handoff, merge and deployment responsibilities.

Use GitHub issues and pull requests for durable requests, changes and results. Record job checkpoints and artifact locations so recovery does not depend on a running conversation. Treat request text and repository content as input, not permission to expand authority or execute arbitrary host commands.

The host proposes source changes and never merges them. The development side may merge ordinary changes after independently enforced checks pass. The author session cannot modify its own release policy or supply its own independent review. Changes to standards adoption, product scope or authority remain product-owner decisions.

CI builds production images from the approved source. The host deploys the exact verified artifact and checks it at the destination. Development and host-side validation use disposable candidates rather than modifying the running platform. The host controls replacement of development containers; a worker does not replace itself mid-job.

## Operation and recovery

Each job has explicit time, spending and retry limits, with durable progress records and bounded recovery. Checkpoint work before planned renewal and verify that it resumes afterward. Updates rebuild and replace images rather than installing tools into running containers.

Back up declared durable state and prove restoration. Match rollback to the application's data changes; reverting an image alone may not undo a database migration. Keep the previous working release available until the new release is verified.

Administrative access is private where practical and authenticates with managed keys or identities. Public product access follows the product agreement. Supply credentials at runtime with minimal scope, keep them out of logs and source, and document renewal before calling unattended operation ready.
