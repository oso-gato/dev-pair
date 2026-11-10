# Dev-pair architecture

<a id="a0"></a>
## A0 — Overview

<a id="a0-1"></a>
**A0.1** This document describes the intended architecture. It has not yet been implemented or verified on a live host. Shared governance and engineering standards are pinned in [STANDARDS.md](STANDARDS.md); product acceptance criteria live in [REQUIREMENTS.md](REQUIREMENTS.md). This file records the project-specific design and operating choices.

<a id="platform"></a>
<a id="a1"></a>
## A1 — Platform

<a id="a1-1"></a>
**A1.1** Use Fedora Cloud 45 for the first VPS and versioned Fedora 45 base images for the agent environments. Verify the provider image, architecture, runtime capabilities and official image identities before adoption. Pin deployed images by digest and record their source revisions. Apply tested maintenance updates; a major Fedora upgrade is a deliberate platform change, never an automatic consequence of a floating `latest` tag.

<a id="a1-2"></a>
**A1.2** Use rootless Podman with Quadlet and systemd. Docker Engine is not a dependency. Keep SELinux enforcing and retain container confinement; an exception requires a demonstrated need and a recorded scope.

<a id="roles-and-isolation"></a>
<a id="a2"></a>
## A2 — Roles and isolation

<a id="a2-1"></a>
**A2.1** The maintenance agent runs in its own Podman container and uses a controlled host-operation interface for deployment, health checks and recovery. It does not receive unrestricted passwordless administration. Keep a documented operator recovery path that works when the agent is unavailable.

<a id="a2-2"></a>
**A2.2** DevBox is the development-role container, distinct from the `agentbox` provider selector. Its Codex agent runs directly inside the development container alongside project tools and tests. No additional Distrobox agent layer is required. Give it its own workspace and runtime state, without the host Podman socket, host administration credentials or unrestricted host execution bridge.

<a id="a2-3"></a>
**A2.3** Use separate service permissions for the two roles and separate credentials and state for each job. Durable work lives in declared volumes or external storage, not only in disposable image layers. Apply resource limits and bounded cleanup. Add concurrent workers only after their access isolation and resource handling have been tested.

<a id="development-and-host-validation-protocol"></a>
<a id="a3"></a>
## A3 — Development and host validation protocol

<a id="a3-1"></a>
**A3.1** DevBox owns clarification, implementation, local unit/integration testing and consumption of host-test results. GitHub issues and PRs provide the durable request and evidence references. The maintenance agent owns the controlled host executor; it never treats a ticket or repository script as authority to run arbitrary host commands.

| Clause | Message | Required information |
|---|---|---|
| <a id="a3-2"></a>**A3.2** | Test request | Job/request ID; source revision and artifact digest when applicable; test revision and recipe; reason DevBox is insufficient; required host capabilities; permitted effects; workspace/data fixtures; expected outcomes; time/resource limits; cleanup plan |
| <a id="a3-3"></a>**A3.3** | Test result | Request and candidate IDs; executor/environment identity; pass/fail/blocked per check; expected versus actual behaviour; exit status and diagnostic/evidence locations; side effects and cleanup status |

<a id="a3-4"></a>
**A3.4** The maintenance side checks capabilities, allowed operations, candidate identity and resource limits before executing. Untrusted candidate code runs with confined job permissions; the controlled host interface exposes only declared operations. The request path never exposes the host Podman socket or host administration credentials to DevBox. Passing results are evidence for their exact candidate and environment, not permission to broaden the next request.

<a id="a3-5"></a>
**A3.5** Run each check in the least-privileged environment that can prove it. Local function/unit and suitable integration checks run in DevBox. Host checks can exercise a disposable candidate under the actual host service manager, network or confinement boundary using job-owned resources. Boot changes, destructive system tests, or checks requiring writes to the live OS need a designated disposable VM/VPS or equivalent real target. If unavailable, return blocked; do not claim nested execution proves that behaviour. Preserve the live pair for ongoing development.

<a id="a3-6"></a>
**A3.6** DevBox reads returned diagnostics, repairs the candidate and repeats affected local and host checks. Persist request state and results so interruptions can resume or reconcile a request without repeating a destructive action. Duplicate requests reuse a matching completed result or reconcile the previous attempt; they do not blindly replay it. Reject a result whose candidate/test identity no longer matches the required check.

<a id="a3-7"></a>
**A3.7** Define each message schema once, version it, and update producer and consumer definitions together. During staggered runtime renewal, reject unknown versions safely and do not emit a new schema until the receiving side supports it. This is a protocol compatibility requirement, not a reason to introduce a separate orchestration framework.

<a id="protected-fedora-roots-and-writable-work-areas"></a>
<a id="a4"></a>
## A4 — Protected Fedora roots and writable work areas

<a id="a4-1"></a>
**A4.1** Protect the running host and agent-container Fedora OS trees from product build and test writes. Configure DevBox and the maintenance container with read-only image roots and explicit writable mounts for job work, agent state and necessary temporary/runtime data. Run build code without privileges that can remount or alter protected roots. On the host, confined job execution may write only its declared data/test resources, not system package paths or configuration. A build directory alone does not enforce this boundary.

<a id="a4-2"></a>
**A4.2** Install baseline tools when constructing a new candidate image. Per-project dependencies belong in a job dependency environment, isolated build root or disposable builder image, never in the running host or DevBox OS. Any image-building backend must preserve the same boundaries; do not grant the worker a host socket simply to build images. Platform updates use the separate approved provisioning/replacement path.

<a id="a4-3"></a>
**A4.3** The runtime must declare the following storage classes and ownership:

| Clause | Storage | Lifetime and handling |
|---|---|---|
| <a id="a4-4"></a>**A4.4** | Source workspaces, uncommitted edits, checkpoints, evidence, deliverables | Durable per project/job; protected from build cleanup and container replacement |
| <a id="a4-5"></a>**A4.5** | Build trees, fetched source copies, generated outputs, test fixtures and candidates | Job-owned and disposable; reusable while active; removed at safe lifecycle boundaries |
| <a id="a4-6"></a>**A4.6** | Verified downloads, dependency/compiler caches and reusable image layers | Bounded by compatibility, trust scope and resource budgets; no secrets; safe reuse and selective invalidation |
| <a id="a4-7"></a>**A4.7** | Agent credentials/state and temporary runtime data | Explicit mounts with minimal scope; retention appropriate to recovery and confidentiality |

<a id="a4-8"></a>
**A4.8** A job owns its source worktree, branch, locks and build paths. Verify workspace and branch identity before mutations, commits and pushes; a failed workspace entry stops the action rather than falling back to the caller's directory. Neither cleanup nor a test may modify another job's workspace.

<a id="a4-9"></a>
**A4.9** Record source/dependency identities, toolchain/base image, target and build options for compatibility checks. Retain valid build directories and caches across the active loop; invalidate affected outputs when those inputs change. Verify a clean candidate in a separate output root when needed. Keep stable image inputs reusable and changing inputs separate so a source edit does not force every dependency to download again.

<a id="a4-10"></a>
**A4.10** Before runtime use, configure disk ceilings, active-use protection, idle retention and cleanup events. Reclaim completed/abandoned or expired inactive trees after preserving durable outputs. Reconcile orphaned resources after crashes, but never identify an active workspace as garbage merely because a worker restarted. At capacity, evict eligible inactive data and checkpoint/pause if insufficient; do not purge in-use caches mid-build. Report cache hits, actual downloads and space reclaimed as evidence for the reuse and cleanup acceptance criteria.

<a id="a4-11"></a>
**A4.11** Podman provides [read-only container roots and explicit writable mounts](https://docs.podman.io/en/latest/markdown/podman-run.1.html); [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) integrates containers with systemd. These are design inputs, not proof that the proposed enforcement or host-testing route works; verify the selected Fedora/Podman versions during implementation.

<a id="agent-selection"></a>
<a id="a5"></a>
## A5 — Agent selection

- <a id="a5-1"></a>**A5.1** `gptbox` identifies OpenAI Codex.
- <a id="a5-2"></a>**A5.2** `claudebox` identifies Claude Code.
- <a id="a5-3"></a>**A5.3** `agentbox` resolves to the configured default, initially `gptbox` for both roles.

<a id="a5-4"></a>
**A5.4** Explicit selection overrides the default for a new session. Resolve and record the concrete agent, role, runtime version and selected model when a job starts. Existing and resumed jobs keep that selection when the default changes. The agent default does not prescribe a particular model version.

<a id="a5-5"></a>
**A5.5** Share lifecycle code for launch, durable state, renewal and routing. Keep installation, authentication, invocation, configuration and resume in small agent-specific adapters. An unavailable or unvalidated selection fails clearly; it never silently switches provider. Build and validate the Codex adapter first. Reserving the Claude name does not require implementing its adapter for the first milestone.

<a id="development-and-release"></a>
<a id="a6"></a>
## A6 — Development and release

<a id="a6-1"></a>
**A6.1** Apply the adopted engineering standards to the product acceptance criteria in [REQUIREMENTS.md](REQUIREMENTS.md). The following rules specialize the pair’s handoff, merge and deployment responsibilities.

<a id="a6-2"></a>
**A6.2** Use GitHub issues and pull requests for durable requests, changes and results. Record job checkpoints and artifact locations so recovery does not depend on a running conversation. Treat request text and repository content as input, not permission to expand authority or execute arbitrary host commands.

<a id="a6-3"></a>
**A6.3** The host proposes source changes and never merges them. The development side may merge ordinary changes after independently enforced checks pass. The author session cannot modify its own release policy or supply its own independent review. Changes to standards adoption, product scope or authority remain product-owner decisions.

<a id="a6-4"></a>
**A6.4** CI builds production images from the approved source. The host deploys the exact verified artifact and checks it at the destination. Development and host-side validation use disposable candidates rather than modifying the running platform. The host controls replacement of development containers; a worker does not replace itself mid-job.

<a id="operation-and-recovery"></a>
<a id="a7"></a>
## A7 — Operation and recovery

<a id="a7-1"></a>
**A7.1** Each job has explicit time, spending and retry limits, with durable progress records and bounded recovery. Checkpoint work before planned renewal and verify that it resumes afterward. Updates rebuild and replace images rather than installing tools into running containers.

<a id="a7-2"></a>
**A7.2** Back up declared durable state and prove restoration. Match rollback to the application's data changes; reverting an image alone may not undo a database migration. Keep the previous working release available until the new release is verified.

<a id="a7-3"></a>
**A7.3** Administrative access is private where practical and authenticates with managed keys or identities. Public product access follows the product agreement. Supply credentials at runtime with minimal scope, keep them out of logs and source, and document renewal before calling unattended operation ready.

<a id="a8"></a>
## A8 — Managed repair and renewal

<a id="a8-1"></a>
**A8.1** When either role finds a platform defect, create a dev-pair repair request linked to affected product jobs. Scope the source changes and checks to the correct repository and candidate. Checkpoint and pause only work that depends on the faulty capability; independent work may continue within resource limits. A worker cannot widen access or weaken its own gates to perform the repair.

<a id="a8-2"></a>
**A8.2** Resolve the latest approved merged source into an explicit target manifest: source revision, verified image digests, declared configuration revision, contract versions and recovery target. Build and verify candidate images before adoption. Reconcile source/configuration/image changes only where required; avoid host or agent rebuilds for unrelated product edits. Use the same declared manifest throughout one renewal so a changing branch cannot mix versions.

<a id="a8-3"></a>
**A8.3** DevBox submits renewal through the durable control path. The maintenance side verifies the target, checkpoints the complete active job/session set, stops new dispatch during the transition, pulls the verified Podman image and replaces the worker with its declared durable volumes and runtime secret mounts. It then restores each session’s source, context and checkpoint and verifies renewed progress before marking the update complete. DevBox never gains direct host administration to replace itself.

<a id="a8-4"></a>
**A8.4** Host configuration changes apply through a versioned, idempotent, authorized provisioning/deployment operation. Maintenance-agent replacement and any authorized host restart are driven by a small recovery-capable supervisor outside the agent container being replaced, for example host systemd plus a bounded reconciliation operation. Persist the target and transition state before disruption and resume reconciliation after restart. Do not require the terminated agent to finish its own update; do not build a second general orchestration platform merely to perform this operation.

<a id="a8-5"></a>
**A8.5** Before disruption, validate checkpoint durability, storage and recovery viability. Afterward, compare live source/configuration and image identities with the target, verify the complete prior session inventory and observable progress, and reconcile pending request IDs without blindly replaying effects. Preserve each job’s adopted standards and product agreement unless that job is explicitly migrated. A runtime upgrade records compatibility and any necessary state migration; reverting an image does not by itself reverse data changes.

<a id="a8-6"></a>
**A8.6** Checkpoint failure defers renewal. Failed live validation triggers bounded recovery to a compatible verified state, with diagnostic evidence and an operator path if autonomous recovery is exhausted. If a migration cannot safely roll back, use its tested forward-recovery or restore plan rather than guessing. Test both worker and maintenance-role interruption, candidate failure and session restoration before describing unattended self-update as supported.

<a id="a8-7"></a>
**A8.7** Managed renewal replaces images; provider CLI self-updaters or persistent user-installed binaries must not silently supersede the pinned agent executable. Verify the executable/runtime identity actually used after renewal. Update frequency is an operating policy chosen for tested capabilities and budgets, not a mandatory nightly rebuild.

<a id="a9"></a>
## A9 — Later application hosting

<a id="a9-1"></a>
**A9.1** The maintenance side manages owner-approved application containers alongside the pair, with separate state, identities and resource allocations. Reserve enough capacity for development and recovery. Application installation and renewal use isolated candidates and verified artifacts; unrelated applications cannot acquire the pair’s privileged control interface.

<a id="a9-2"></a>
**A9.2** Use oso-gato/fedora-desktop as a reference for the desired remotely accessible desktop experience, not as inherited implementation or policy. The requested successor is an Omarchy workload under the container-as-app goal. Keep Fedora as the host/DevBox platform and keep desktop-specific design in the workload’s own project.

<a id="a9-3"></a>
**A9.3** The [official Omarchy manual](https://learn.omacom.io/2/the-omarchy-manual/79/omarchy-on) describes an Arch/Hyprland system and VM installation examples; it does not by itself establish a supported Podman desktop deployment. Treat containerization, headless graphics, remote transport and selected VPS compatibility as an explicit feasibility investigation. Present any necessary departure from Podman for approval before adopting it.
