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
**A2.2** **Retired.** The direct-in-DevBox Codex placement and no-Distrobox requirement were introduced during an incorrect simplification of the original design. A2.4 and A10 restore the separate Distrobox agent layers; the worker’s host-access restrictions remain in force.

<a id="a2-3"></a>
**A2.3** Use separate service permissions for the two roles and separate credentials and state for each job. Durable work lives in declared volumes or external storage, not only in disposable image layers. Apply resource limits and bounded cleanup. Add concurrent workers only after their access isolation and resource handling have been tested.

<a id="a2-4"></a>
**A2.4** DevBox is the stable development-role Podman container, distinct from the `agentbox` selector. It hosts a nested Distrobox-based development agent environment, initially `gptbox` running Codex. The VPS host has a separate Distrobox-based maintenance agent environment, initially `gptbox`; this environment is the maintenance container, not a demand for another wrapper around it. Both use Podman. Keep development workspaces, credentials and session state separately declared, with no outer-host Podman socket, host-administration credentials or unrestricted host bridge exposed to the development role.

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
## A4 — Immutable runtime code and writable work areas

<a id="a4-1"></a>
**A4.1** Protect the running host and agent-container Fedora OS trees from product build and test writes. Configure DevBox and the maintenance container with read-only image roots and explicit writable mounts for job work, agent state and necessary temporary/runtime data. Run build code without privileges that can remount or alter protected roots. On the host, confined job execution may write only its declared data/test resources, not system package paths or configuration. A build directory alone does not enforce this boundary.

<a id="a4-1-1"></a>
**A4.1.1** Apply the immutable-code boundary to all container roles, including hosted applications and disposable test runtimes, not just the two Codex containers. Protect installed application/agent code, plugins and entrypoints as well as OS paths. Use read-only release/image code with explicit writable data mounts; no writable mount may obscure a managed code location.

<a id="a4-1-2"></a>
**A4.1.2** For the host, enforce an immutable deployed-code boundary against running jobs and workloads, and activate system/code/configuration changes only through the verified, versioned maintenance path. The selected host update mechanism must demonstrate this invariant; stock Fedora installation alone does not establish it. Controlled activation of a new desired state is distinct from ad hoc edits or package changes by a product build.

<a id="a4-1-3"></a>
**A4.1.3** Capture candidate image/code identity for validation and deployment. Build image layers and project dependencies in separate staging roots; do not mutate the installed runtime of a running container. Keep editable project source distinct from the platform code executing the agent. Revalidate affected evidence whenever test-candidate code changes.

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
**A8.7** **Retired.** Its non-nightly cadence statement incorrectly removed the original nightly agent refresh requirement; A10.2–A10.4 restore it. The replacement preserves verified runtime identity and disables in-place agent self-updates while requiring nightly agent-layer rebuilds.

<a id="a9"></a>
## A9 — Later application hosting

<a id="a9-1"></a>
**A9.1** The maintenance side manages owner-approved application containers alongside the pair, with separate state, identities and resource allocations. Reserve enough capacity for development and recovery. Application installation and renewal use isolated candidates and verified artifacts; unrelated applications cannot acquire the pair’s privileged control interface.

<a id="a9-2"></a>
**A9.2** Use oso-gato/fedora-desktop as a reference for the desired remotely accessible desktop experience, not as inherited implementation or policy. The requested successor is an Omarchy workload under the container-as-app goal. Keep Fedora as the host/DevBox platform and keep desktop-specific design in the workload’s own project.

<a id="a9-3"></a>
**A9.3** The [official Omarchy manual](https://learn.omacom.io/2/the-omarchy-manual/79/omarchy-on) describes an Arch/Hyprland system and VM installation examples; it does not by itself establish a supported Podman desktop deployment. Treat containerization, headless graphics, remote transport and selected VPS compatibility as an explicit feasibility investigation. Present any necessary departure from Podman for approval before adopting it.

<a id="a10"></a>
## A10 — Distrobox agents and release scheduling

<a id="a10-1"></a>
**A10.1** Use Podman-backed Distrobox environments for the agent runtime on each side: host → maintenance gptbox; host → DevBox → development gptbox. Keep the outer DevBox and host platform artifacts stable while the inner agent artifacts advance. `agentbox` selects the default provider environment and `gptbox` names the Codex environment; retain the machine names `erebus` and `strix`, always lowercase. Record deployment identity and role/job identity in configuration so reusable lifecycle code does not require a fork for each machine.

<a id="a10-2"></a>
**A10.2** Maintain distinct manifests and schedules for the host platform, DevBox and each admitted agent runtime. A nightly controller resolves official stable tooling, records the exact source/version and artifact, builds using approved recipes and cached inputs, runs compatibility/renewal checks, and promotes only the verified candidate. CI remains the builder of production artifacts. Record success, failure, retained version and any deferred activation so “latest” is a checked state, not a claim.

<a id="a10-3"></a>
**A10.3** Keep the replacement executor outside the agent environment it stops. The host controller owns maintenance-agent replacement and outer DevBox replacement. A constrained controller outside the inner development agent owns its replacement, with the outer host path available for recovery. Checkpoint the complete session set, stagger maintenance/development activation where necessary, restore state and verify work progress. The current worker cannot destroy its own only recovery executor.

<a id="a10-4"></a>
**A10.4** Disable in-place CLI self-update and package upgrades in running agent environments. Prepare Distrobox initialization, package installation and home integration in isolated candidate assembly, then protect installed code in the admitted runtime. Keep agent state and credentials outside the image in explicit mounts without executable shadowing. Distrobox is not an exception to E4.1.1–E4.1.4 or R5.1.1–R5.1.3.

<a id="a10-5"></a>
**A10.5** Validate the chosen nested Podman/Distrobox arrangement on the selected Fedora release before adopting it. Inspect and test user namespaces, storage/mounts, initialization, lifecycle and SELinux confinement. Distrobox’s normal parent integration, shared home and host-exec facilities must not create an unrestricted bridge to the VPS or writable parent code. Provision the necessary tooling in verified base images; never patch the live host or DevBox to make nesting work. If required permissions conflict with the agreed boundaries, present the measured blocker and a scoped design decision rather than silently granting privileged mode or mounting the outer host engine socket.

<a id="a10-6"></a>
**A10.6** Model selection is separate from tool-image versioning. Use the provider’s supported model discovery/selection mechanism for the actual authentication mode; verify access and compatibility rather than assuming every published model is available. Record the chosen model per job. Existing jobs require an explicit migration for a model change, even when a nightly CLI rebuild succeeds.

<a id="a10-7"></a>
**A10.7** Set the agent rebuild window and timezone before deployment and handle missed schedules with bounded reconciliation. Host and DevBox releases follow their own tested change/maintenance schedule and can be expedited for consequential fixes. Do not use a floating latest image at deployment: the schedule resolves an exact candidate, and promotion uses its verified identity.

<a id="a10-8"></a>
**A10.8** Upstream references: [Distrobox integration and security implications](https://distrobox.it/#security-implications), [Distrobox creation options](https://distrobox.it/usage/distrobox-create/), and [nested Podman examples](https://distrobox.it/useful_tips/#using-podman-inside-a-distrobox). These establish the need to validate integration and privileges; they do not prove that this project’s nested, confined, immutable arrangement already works.

<a id="a11"></a>
## A11 — Existing implementation references and retained identities

<a id="a11-1"></a>
**A11.1** Keep the existing machine identities `erebus` and `strix`, both lowercase. The historical architecture identifies `erebus` as the VPS lineage and `strix` as the bare-metal lineage. Preserve those identities without expanding R6's first milestone: prove the VPS pair first, with bare-metal support later. This documentation update does not rename or reconfigure either machine.

<a id="a11-2"></a>
**A11.2** The host-side implementation reference is [fedora-bootstrap at e8def268](https://github.com/oso-gato/fedora-bootstrap/tree/e8def2684e91facceb985974ac4d38d64f0be8c5): `distrobox.ini`, `setup-user.sh`, `claudebox-daily.sh`, `box-rebuild.sh`, `claudebox-init.sh` and `host-agent-watch.sh`. These contain the Claudebox manifest, a daily 04:00 timer, idle/session-lock deferral, an external systemd rebuild executor, parent integration and development-container session restoration. Inspect the code and its associated tests before replacing these mechanisms; historical comments alone are not live verification.

<a id="a11-3"></a>
**A11.3** The nested development implementation reference is [fedora-dev at 9811f351](https://github.com/oso-gato/fedora-dev/tree/9811f351a43c89e7da1aa1fa255d4711a7ab5216): `distrobox.ini`, `entrypoint.sh`, `claudebox-assemble.sh`, `claudebox-daily.sh`, `box-rebuild.sh`, `bin/claude` and `bin/rebuild-request.sh`. These contain nested Podman/Distrobox assembly, daily and on-demand rebuild triggers, serialization and busy deferral, durable-home handling, session IDs and manifests that guard against omitted sessions or ambiguous restoration by working directory. Preserve the outcomes and useful regression cases when adapting provider-specific behavior to Codex.

<a id="a11-4"></a>
**A11.4** Reuse selectively through A5.5's common lifecycle and agent adapters. Replace Claude-specific installation, authentication, invocation and resume with verified Codex equivalents. Adapt destroy-before-build replacement, live-clone script/skill loading and broad parent integration to the candidate-before-replacement, immutable-code and scoped-operation requirements. The old `fedora-dev.container` deliberately adds capabilities and disables SELinux label separation for nesting; evaluate that concrete compatibility issue under A1.2/A10.5 rather than blindly removing needed capabilities or copying the exception. Demonstrate all-session restoration, failure recovery and actual resumed work on the new runtime before claiming equivalence.

<a id="a11-5"></a>
**A11.5** These references establish that the original mechanisms have code, not that the new Codex design is already implemented or verified. The [pre-restart dev-pair architecture](https://github.com/oso-gato/dev-pair/blob/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5/ARCHITECTURE.md) also records shared disposable agent layers and the two machine lineages. Preserve that design evidence; the restart retires the implementation baseline, not agreed product behavior. Keep current authoritative requirements here and in REQUIREMENTS rather than importing historical governance.

<a id="a12"></a>
## A12 — Development workflow and separate sessions

<a id="a12-1"></a>
**A12.1** Use the following session workflow to develop this repository. It organizes work under the existing product agreement; it does not introduce new deployed container roles. The maintenance/development runtime split remains A2. Session names below are human-readable task titles, not hostnames. Verify the checkout is `oso-gato/dev-pair`, load the four project documents and all three shared documents at the STANDARDS pin, and record the source baseline before beginning. Access to private standards and the reference repos must be verified rather than assumed from the cloud environment's name.

| Clause | Separate session | Model / effort | Responsibility and completion evidence |
|---|---|---|---|
| <a id="a12-2"></a>**A12.2** | Dev-pair — architecture and coordination | `gpt-6-astra` / `high` | Reconcile the original charter, current requirements and A11 implementation references. Maintain a concise requirement-to-acceptance mapping and an ordered work queue. Preserve owner decisions; resolve material conflicts before dependent work. Hand one bounded implementation slice to a builder, then coordinate repair, review and delivery. |
| <a id="a12-3"></a>**A12.3** | Dev-pair — build — task ID | `gpt-6.1-sol` / `high` | Work in an isolated branch/worktree. Implement the slice and meaningful tests, run suitable local checks, request external checks where needed, diagnose failures and repair. Hand off an exact candidate commit and evidence, never a moving branch alone. |
| <a id="a12-4"></a>**A12.4** | Dev-pair — review — task ID | `gpt-6-astra` / `high` | A fresh session independently reads the governing documents, exact candidate and evidence. Check lost requirements, behavior, failure paths and boundaries. Report pass, changes required or blocked with clause/file references. Do not edit the candidate or accept the author's summary as proof; fixes return to the builder and receive fresh affected checks and review. |
| <a id="a12-5"></a>**A12.5** | Dev-pair — host validation — task ID | `gpt-6.1-sol` / `high` | Use only the designated authorized executor/target to perform A3 host checks and renewal tests. Return candidate-bound results to the builder. Bootstrap may use an authorized cloud/operator execution route until the pair works; record that fact and later prove the pair's own handoff loop. No deployment authority follows merely from naming this session. |
| <a id="a12-6"></a>**A12.6** | Dev-pair — focused task — task ID | `gpt-6.1-sol` / `medium` | Optional for mechanical documentation, naming or small isolated changes with settled behavior. Charter interpretation, permission changes and lifecycle/recovery work use the higher-effort roles above. |

<a id="a12-7"></a>
**A12.7** Keep model, effort and allowed escalation in runtime/session configuration, separate from `agentbox → gptbox`. The table is the initial operating recommendation, not a permanent shared-standard requirement. Use Astra High for difficult architecture or platform diagnosis and escalate a specific unresolved problem to `xhigh` only with a recorded reason and within the job's budget. Do not use maximum effort for every action. Verify model/effort availability before launch, record the actual settings, and surface unavailable selections rather than claiming the requested model ran. A prompt alone does not configure a model. Existing session model changes follow A5.4/A10.6; do not silently switch a resumed job.

<a id="a12-8"></a>
**A12.8** Use one existing issue/PR or equivalent durable job record for the handoff: task/outcome; applicable requirement IDs; source baseline and standards SHA; branch/worktree and exact candidate SHA; tests and their environment/evidence; unresolved decisions; next action; session/model/effort; and applicable authority, time, spending and retry limits. Include image digests and external request IDs when relevant. Record secret references only. This is a compact record, not a compulsory spec/plan/tasks document bundle. Persist it before changing sessions; the product owner should not shuttle context between workers.

<a id="a12-9"></a>
**A12.9** Sequence work as follows: reconcile requirements → build one slice → run local and necessary host checks → independent review of the exact candidate → repair/retest/review until acceptance or an explicit bounded blocker → merge under A6 → CI artifact and authorized deployment → verify at the destination. The development side owns permitted merge decisions; maintenance never merges. If integration or the release artifact differs from reviewed/tested inputs, rerun affected verification before promotion. A separate model/session supports review independence but does not enforce a gate by itself; validate repository/CI permissions and checks before claiming autonomous release enforcement. Until enforcement exists, report that gap and do not self-approve production promotion.

<a id="a12-10"></a>
**A12.10** Begin with one builder at a time. Create a fresh reviewer session per candidate/review cycle with direct access to authoritative sources. Independent research or tests may run concurrently when their workspaces and responsibilities do not overlap. Keep architecture coordination available without requiring a permanently running model. A blocked test does not cancel unrelated work; a failed test does not routinely send the owner back into the development loop.

<a id="a12-11"></a>
**A12.11** The first architecture session compares [the original objective](https://github.com/oso-gato/dev-pair/blob/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5/00-OBJECTIVE.md), [bylaw](https://github.com/oso-gato/dev-pair/blob/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5/00-BYLAW.md), [constitution reference](https://github.com/oso-gato/dev-pair/blob/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5/CONSTITUTION.md), the current contract and A11 source. Finish the omission review, including headless operation, client-disconnect continuity, authorized repository scope, credential/service failure recovery, installation rehearsal and efficient dependencies. Classify each material item as retained with a current clause, proposed restoration/clarification, or explicitly deferred/removed with owner authority. Do not import historical policy or silently treat pending recommendations as approved requirements. Resolve actual scope/authority decisions with the owner and otherwise continue autonomously.

<a id="a12-12"></a>
**A12.12** After that reconciliation, deliver small verified slices in dependency order: (1) reproducible candidate construction, explicit state/workspace boundaries and Codex launch in both Distrobox placements; (2) one durable product job with local tests and a failed host-test request followed by repair and successful retest; (3) nightly agent renewal plus separate host/DevBox release paths, preserving every session and testing failed/interrupted renewal; (4) the complete demonstrator delivery with independent review, deployment verification, cache reuse/cleanup and restoration. Each slice gets its relevant tests from the start. These are checkpoints within R6/R7/R9/R11, not reduced acceptance or four new products; `strix` bare-metal and unrelated app hosting remain later scope.

<a id="a12-13"></a>
**A12.13** Session creation and transfer must be confirmed by the execution service. Record the returned session identifier/link and selected environment when available. A local subagent, saved launch prompt or workflow table is not a newly created standalone Codex Cloud conversation. If the current client cannot launch it, provide the ready-to-use brief, exact repository and model/effort selection, state that limitation, and preserve the work record so a new session can continue without reconstructing this chat. Do not create scheduled automations merely to imitate an immediate development session.
