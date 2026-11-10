# Dev-pair requirements

<a id="outcome"></a>
<a id="r1"></a>
## R1 — Outcome

<a id="r1-1"></a>
**R1.1** Dev-pair is an autonomous development pair that takes a software or product brief, develops it through an initial conversation with the product owner, and delivers a tested, ready-to-use product. It must work across the authorized repositories and product briefs supported by the agreed platform, rather than being hard-coded to one demonstrator. The owner describes the desired outcome; the pair owns design, implementation, unit and integration testing, end-to-end validation, repair, independent review and delivery. The owner is not required to write or inspect code, review diffs or operate development tools.

<a id="product-agreement"></a>
<a id="r2"></a>
## R2 — Product agreement

<a id="r2-1"></a>
**R2.1** One initiation conversation may contain several rounds of questions. The pair probes material ambiguities in the initial brief until intended users, essential journeys, acceptance criteria, delivery destination, scope, data constraints, budgets and permitted autonomous actions are actionable. It reuses answers already given and proposes ordinary technical choices itself.

<a id="r2-2"></a>
**R2.2** The pair records and settles the project agreement with the owner in REQUIREMENTS and ARCHITECTURE, under the shared governance and engineering standards pinned in STANDARDS. This is what the earlier charter terminology expressed; no additional charter file is required. Then the pair proceeds through a concise plan to implementation and delivery without routine human approvals. A normal test failure leads to diagnosis and repair, not a new product-owner task.

<a id="r2-3"></a>
**R2.3** Resolve ordinary implementation choices independently and report material decisions at delivery. If the requirements conflict, necessary access is unavailable, or bounded recovery cannot make progress, stop the affected work and report the blocker and a proposed resolution. Never silently weaken acceptance criteria or keep retrying without a limit.

<a id="the-pair"></a>
<a id="r3"></a>
## R3 — The pair

<a id="r3-1"></a>
**R3.1** The **DevBox** is the stable Fedora Podman development container hosting a Distrobox-based development agentbox, initially **gptbox** running Codex. It owns the product development loop. A separate Distrobox-based maintenance agentbox runs on the Fedora VPS and provides the maintenance-container role: controlled host operations, deployment, recovery and checks that cannot be proven inside DevBox. Both roles default to `agentbox → gptbox`. [ARCHITECTURE.md](ARCHITECTURE.md) defines their boundaries and agent-selection contract.

<a id="r3-2"></a>
**R3.2** Development work must not directly administer the host. The two roles exchange durable requests and evidence so a lost terminal or restarted container does not lose the job.

<a id="r3-3"></a>
**R3.3** Retain the existing machine names `erebus` and `strix`, both lowercase. Naming is separate from deployment readiness: the first milestone remains one VPS pair; later support does not become implemented merely because its machine identity is retained.

<a id="development-validation-and-repair-loop"></a>
<a id="r4"></a>
## R4 — Development, validation and repair loop

1. <a id="r4-1"></a>**R4.1** Turn the agreed outcomes into executable acceptance checks. Define tests before or alongside implementation, then develop and test individual functions and units inside DevBox.
2. <a id="r4-2"></a>**R4.2** Build the components and test their integration in DevBox wherever that environment can establish the required behaviour. Run full product journeys there when possible. Diagnose failures, repair the code and rerun affected tests throughout development.
3. <a id="r4-3"></a>**R4.3** When a required check cannot be proven in DevBox, send a durable, scoped test request to the maintenance side. Host-only validation is a required fallback, not an optional skipped test or a reason to give DevBox direct host access.
4. <a id="r4-4"></a>**R4.4** The maintenance agent validates the request and executes the identified candidate in an isolated host-side test workspace or suitable designated disposable target. It returns the test outcome, expected and actual behaviour, logs and diagnostics to DevBox. A check of real host behaviour must actually exercise that boundary.
5. <a id="r4-5"></a>**R4.5** DevBox consumes the result, fixes failures, rebuilds as needed, reruns affected local checks and requests fresh host validation. Continue within agreed time, spending and retry limits until all required checks pass or a specific unresolved blocker is reported. Changed candidates cannot reuse affected old passing verdicts.
6. <a id="r4-6"></a>**R4.6** Obtain independent review of the exact candidate, deploy or deliver it, and verify its real end-to-end use at the agreed destination. Hand the owner the usable product and evidence without a code-review task.

<a id="r4-7"></a>
**R4.7** Host-side examples include real host systemd/Quadlet lifecycle, host networking and confinement behaviour that cannot be established inside the worker, and boot/restart behaviour when required. Capabilities determine placement; a test running inside some container is not automatically equivalent to a test of the actual VPS. Requests that need unsupported capabilities or would change protected live OS state must use an appropriately isolated disposable target or report a blocker. They cannot silently alter the running platform.

<a id="protected-operating-systems-and-disposable-build-trees"></a>
<a id="r5"></a>
## R5 — Immutable runtime code and disposable build trees

<a id="r5-1"></a>
**R5.1** Product development and testing must not install into or modify the Fedora operating-system tree on the VPS, DevBox or maintenance container. Use independent, job-owned build trees, dependency roots and fixtures, with enforced boundaries. Builds must not run from live platform trees or replace running system binaries, libraries, packages or configuration. Declared writable workspaces, caches, runtime data and test volumes are separate from the protected OS tree. Authorized platform provisioning, upgrades and deployment are separate controlled operations; a product build/test request does not authorize them.

<a id="r5-1-1"></a>
**R5.1.1** Immutability covers the host, DevBox, maintenance container and every hosted or test container: all deployed OS, application, agent, library, plugin and startup code is immutable. The rule applies during normal operation, development and testing, not only to Fedora package files.

<a id="r5-1-2"></a>
**R5.1.2** Build code changes in separate working trees or candidate images, validate them, and activate verified replacements through the controlled maintenance/deployment path. Do not patch installed code inside a running environment. Self-update means managed replacement with session preservation under R9, not in-place mutation.

<a id="r5-1-3"></a>
**R5.1.3** Declared source workspaces, build trees, caches, application data, logs, secrets and session state remain writable according to their purpose and isolation boundary. They must not shadow deployed executable paths or bypass the verified release with mutable plugins or startup scripts. Configuration changes are declared and controlled; arbitrary live edits are not a deployment mechanism.

<a id="r5-2"></a>
**R5.2** A disposable build tree can contain fetched source, dependencies, intermediate outputs and test fixtures, but it is not the only copy of valuable work. Preserve source edits, job checkpoints, evidence and deliverables in durable project storage before discarding a tree. Durable uncommitted work must survive interruption as well as committed source.

<a id="r5-3"></a>
**R5.3** Keep compatible trees and verified caches through an active edit/build/test cycle and safe job resumption. Repeated builds must reuse unchanged inputs instead of repeatedly downloading them. Reset affected outputs when inputs, toolchains or targets change, or when a clean check or contamination requires it. Clean-candidate verification must not erase the active workspace or needlessly discard verified downloads.

<a id="r5-4"></a>
**R5.4** Cleanup follows job completion or abandonment, a configured idle window, invalidation, or managed storage pressure. It must not purge active work on each iteration. Storage and retention are bounded: reclaim eligible inactive data first, preserve evidence and deliverables, and pause/report if capacity cannot be recovered safely. Numeric budgets and retention values are agreed or selected within delegated authority before jobs execute. Cleanup and cache behaviour must be demonstrated, not merely described.

<a id="initial-scope"></a>
<a id="r6"></a>
## R6 — Initial scope

<a id="r6-1"></a>
**R6.1** Build one pair on one Fedora Cloud 45 VPS with rootless Podman. Prove one small demonstrator product from brief to delivery. The demonstrator must have observable user journeys and enough persistent job or application state to prove recovery. This milestone must also exercise the host-test failure/repair/retest path and repeated-build reuse/cleanup; an application-only success inside DevBox is insufficient.

<a id="r6-2"></a>
**R6.2** Concurrency, bare-metal and GPU support, additional agent adapters, and unrelated hosted applications are later work. Keep their addition possible without implementing them before the first delivery succeeds.

<a id="acceptance-for-the-first-pair"></a>
<a id="r7"></a>
## R7 — Acceptance for the first pair

1. <a id="r7-1"></a>**R7.1** A fresh designated Fedora 45 VPS can be provisioned reproducibly. Reapplying setup preserves work and makes no unnecessary changes.
2. <a id="r7-2"></a>**R7.2** The default entry point starts Codex in each role with the intended permissions. Authentication works for unattended execution without credentials appearing in source, images or reports.
3. <a id="r7-3"></a>**R7.3** A product brief produces a working demonstrator whose agreed user journeys and relevant failure paths pass. Test evidence identifies the exact source and artifact tested.
4. <a id="r7-4"></a>**R7.4** A separate agent session reviews the candidate against the agreed requirements. Automated checks and independent evidence control release; the author cannot approve its own result or weaken its own gates.
5. <a id="r7-5"></a>**R7.5** The released product works at its agreed destination. A build, merge, image upload or successful process start alone is not delivery.
6. <a id="r7-6"></a>**R7.6** Interrupting a job and restarting its environment restores durable work and resumes from a verified checkpoint without duplicating consequential actions. A failed deployment recovers to a known working state. Backed-up durable data can be restored into a clean destination.
7. <a id="r7-7"></a>**R7.7** The product owner receives the usable address or artifact, brief instructions, acceptance evidence, remaining limitations, operating costs and recovery information in plain language.
8. <a id="r7-8"></a>**R7.8** A brief with material ambiguities is refined into the recorded product agreement before dependent implementation. After agreement, normal development and test failures are resolved without routine owner intervention; genuine scope/authority decisions and exhausted recovery are reported clearly.
9. <a id="r7-9"></a>**R7.9** A representative product has meaningful function/unit, integration and end-to-end checks. A required host-only check is handed off, fails with actionable diagnostics, drives a DevBox code repair, and passes on the corrected candidate. A stale verdict or unavailable/blocked test cannot satisfy acceptance. A repeated request after interruption does not duplicate consequential effects.
10. <a id="r7-10"></a>**R7.10** Representative build and install attempts cannot write outside authorized build/data locations into protected Fedora OS paths on either role or the host. A failed build or host-side test leaves the live platform unchanged apart from declared runtime data. Test routing does not give DevBox host credentials or unrestricted execution.

<a id="r7-10-1"></a>
**R7.10.1** Acceptance must reject attempted mutation of deployed application/agent code as well as OS files on the host and each applicable container role. Verify that writable mounts cannot shadow managed executable locations, while legitimate workspace/data writes still succeed. A verified replacement changes the recorded artifact identity without losing durable sessions or data; in-place patching cannot satisfy this test.
11. <a id="r7-11"></a>**R7.11** Consecutive compatible builds demonstrate reuse of unchanged fetched inputs, without unnecessary repeat downloads. Relevant input changes invalidate affected outputs; a clean-candidate check does not destroy the active workspace. Storage and network-use evidence shows bounded cache behaviour.
12. <a id="r7-12"></a>**R7.12** Completion/idle cleanup and interrupted-cleanup recovery reclaim eligible disposable trees and test resources without deleting another job's or an active job's data. Source changes, checkpoints, test evidence and deliverables survive. Capacity pressure cannot trigger unbounded growth or silent loss of active work.

<a id="r7-13"></a>
**R7.13** These are acceptance requirements, not claims of current capability. The README states what has actually been built and verified.

<a id="r7-14"></a>
**R7.14** The pair operates headlessly after initial provisioning: installation, authentication, agent launch, development, maintenance and recovery must not require a physical display or a local graphical seat on the host. Verify the supported remote bootstrap/authentication route and both agent roles with no graphical session or display available; a terminal-only launch alone does not prove the complete journey.

<a id="r7-15"></a>
**R7.15** Client disconnection, network changes and client-device sleep must not stop an active job or lose its session context and work. Reconnecting from an authorized client returns to the same durable job/session and shows verified progress, without a manual worker nudge or duplicated consequential actions. Exercise disconnect/reconnect while work proceeds in both roles. Host/container interruption and replacement additionally retain the recovery obligations in R7.6 and R9.4–R9.6.

<a id="r7-16"></a>
**R7.16** Administration dashboards and control services must be reachable only through authorized private access; product services may be public when their product agreement calls for it. Remote terminal access requires authorized SSH keys, and direct remote root login is disabled after initial provisioning. Verify that administration is unreachable from the public network, password-based shell authentication and direct remote root login are rejected, and an authorized named administrator retains a working controlled recovery route. The owner confirmed these access outcomes on November 10, 2026; credential products, administrator naming and transport implementation are design choices within these boundaries.

<a id="continuing-work"></a>
<a id="r8"></a>
## R8 — Continuing work

<a id="r8-1"></a>
**R8.1** An in-scope request follows the same delivery loop under the standing product agreement. Changes to outcomes, permissions, spending or scope require the product owner's direction. Routine code review and release decisions belong to the pair within those boundaries.

<a id="r9"></a>
## R9 — Platform repair and self-update

<a id="r9-1"></a>
**R9.1** Dev-pair must repair and renew its own platform, both during development of dev-pair and when work for another authorized repository exposes a platform defect. Record the platform repair separately from the product job, preserve that job’s state and requirements, and resume affected work after the repair is verified. A platform fault must not be disguised as a product defect or a successful test.

<a id="r9-2"></a>
**R9.2** DevBox must be able to request its own update from the latest approved, merged dev-pair revision. After CI produces and validates the corresponding image, the maintenance side pulls that exact image, replaces DevBox and restores every active session. This is autonomous self-update from the product owner’s perspective; the container being replaced must not be its own sole recovery mechanism.

<a id="r9-3"></a>
**R9.3** The host and its maintenance environment must likewise converge to the latest approved dev-pair source and declared configuration through the controlled deployment path. This includes replacement of the maintenance-agent image when required. Verify live configuration and artifacts against the intended revision, preserve an independent recovery path, and do not treat a successful pull or process start as a completed update.

<a id="r9-4"></a>
**R9.4** Before renewal, capture the complete active-session and job set, committed and uncommitted source, agent context/transcripts, credentials/configuration references, pending test requests and checkpoints in durable storage. After renewal, restore every session to actual work and verify progress against its checkpoint; a recreated shell or idle agent is insufficient. Preserve safe reusable build/cache state and invalidate incompatible outputs without losing durable work.

<a id="r9-5"></a>
**R9.5** Updates must remain within the product agreement, authorized repositories and permissions, independent release checks and execution limits. Do not replace an active environment unless checkpoint and recovery are viable. Defer an unsafe update, or recover to a compatible known-working state when verification fails; report an unresolved blocker after bounded recovery. A safe bootstrap/operator recovery path remains necessary when the pair cannot repair itself.

<a id="r9-6"></a>
**R9.6** Acceptance for the first pair includes a representative platform defect discovered during a product job, a separately tracked fix, DevBox image replacement and host/configuration renewal, followed by verified continuation of every active session. Exercise an interrupted or failed renewal and recovery without lost uncommitted edits, duplicate handoff/deployment effects or manual session nudging. Where the scenario needs a reboot, use an authorized disposable/designated target and demonstrate post-boot recovery; never claim an untested reboot path works.

<a id="r10"></a>
## R10 — Secondary goal: host applications

<a id="r10-1"></a>
**R10.1** Retain the host’s secondary purpose as a container-as-app platform for other owner-requested Podman workloads. Deliver the autonomous development pair first; application hosting is a later milestone and must not displace or compromise its development, validation and recovery duties.

<a id="r10-2"></a>
**R10.2** The owner’s named later workload is a remotely accessible Omarchy desktop, replacing the Fedora desktop experience represented by oso-gato/fedora-desktop. Preserve the desired remote-use outcome while developing the new workload against its own requirements. This does not change the Fedora host or DevBox OS choice and does not claim Omarchy currently works as a Podman workload.

<a id="r10-3"></a>
**R10.3** A hosted application has its own isolated runtime, declared durable data, credentials and resource limits. It must not modify the host or DevBox OS tree or inherit platform-administration authority. Define authenticated remote access and acceptance for the desktop in its product agreement, including the intended browser/native-client experience, session/data continuity and impact on pair capacity.

<a id="r10-4"></a>
**R10.4** Before committing to the desktop implementation, validate Omarchy’s current upstream installation model, graphical/remote-session requirements and feasibility on the selected VPS under Podman. If the required outcome cannot be met within that boundary, present the evidence and a scoped alternative for owner decision. Do not silently replace Omarchy, introduce a VM dependency or change the host OS. Detailed desktop implementation and acceptance remain later work.

<a id="r11"></a>
## R11 — Agent layers and separate update cycles

<a id="r11-1"></a>
**R11.1** Run an independently replaceable Distrobox-based agentbox on the VPS host for maintenance and inside DevBox for development. Initially both are gptbox with Codex. The agent tooling lives in these layers rather than being installed or updated in the stable host or DevBox code tree. This restores the original layered design lost during simplification; immutable deployed code and the controlled host-operation boundary still apply.

<a id="r11-2"></a>
**R11.2** Rebuild both active agent environments nightly from the latest official stable agent tooling available at build time. Resolve and verify the upstream version, pin the resulting candidate and artifact, test it, and promote it through the managed renewal path. Reuse valid download/build caches; nightly does not mean forced repeated downloads. Provide an on-demand rebuild for a needed fix. A failed or unavailable upstream candidate leaves the verified working environment running and produces a recorded stale/update-failure status with bounded recovery.

<a id="r11-3"></a>
**R11.3** Agent-layer renewal must preserve and restore every active session, its context, credentials/configuration references, work and pending operations. Verify actual resumed progress. Build the nightly candidate separately before replacing the active layer; defer unsafe activation when checkpoint/resume is not viable and report the reason. Nightly agent updates must not force a host or DevBox release just to refresh the agent.

<a id="r11-4"></a>
**R11.4** The host and DevBox use separate, slower, deliberate release cycles: versioned changes, relevant tests, controlled promotion, live verification and recovery. Important defects or security updates can justify an earlier release. Configure each schedule and timezone explicitly before operation; nightly agent rebuilds do not mandate nightly base-platform rebuilds.

<a id="r11-5"></a>
**R11.5** Keep access to current provider models under review alongside tooling currency. Verify the latest appropriate supported model actually available to the configured account and within agreed budget/capabilities, and make it available for new work through a recorded selection. An image rebuild updates client tooling; it does not install a remote model or grant account access. Existing/resumed jobs keep their recorded model unless an explicit compatible migration is recorded; never silently substitute a model.

<a id="r11-6"></a>
**R11.6** First-pair acceptance must prove both agent placements, a nightly-triggered rebuild path, verified runtime/version identity, restoration of active sessions on each role, failure/deferral recovery and an on-demand update. Show that an agent-only update leaves the host/DevBox release identity unchanged. Verify nested runtime capability, parent-code immutability and credential/operation boundaries before declaring the design supported; report a concrete blocker rather than quietly reverting placement or widening permissions.
