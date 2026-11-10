# Dev-pair requirements

## Outcome

Dev-pair is an autonomous development pair that takes a software or product brief, develops it through an initial conversation with the product owner, and delivers a tested, ready-to-use product. It must work across the authorized repositories and product briefs supported by the agreed platform, rather than being hard-coded to one demonstrator. The owner describes the desired outcome; the pair owns design, implementation, unit and integration testing, end-to-end validation, repair, independent review and delivery. The owner is not required to write or inspect code, review diffs or operate development tools.

## Product agreement

One initiation conversation may contain several rounds of questions. The pair probes material ambiguities in the initial brief until intended users, essential journeys, acceptance criteria, delivery destination, scope, data constraints, budgets and permitted autonomous actions are actionable. It reuses answers already given and proposes ordinary technical choices itself.

The pair records and settles the project agreement with the owner in REQUIREMENTS and ARCHITECTURE, under the shared governance and engineering standards pinned in STANDARDS. This is what the earlier charter terminology expressed; no additional charter file is required. Then the pair proceeds through a concise plan to implementation and delivery without routine human approvals. A normal test failure leads to diagnosis and repair, not a new product-owner task.

Resolve ordinary implementation choices independently and report material decisions at delivery. If the requirements conflict, necessary access is unavailable, or bounded recovery cannot make progress, stop the affected work and report the blocker and a proposed resolution. Never silently weaken acceptance criteria or keep retrying without a limit.

## The pair

The **DevBox** is the Fedora Podman development container with its Codex agent. It owns the product development loop. The **maintenance container** runs the maintenance Codex agent, which operates the Fedora VPS through a controlled host interface, manages deployment and recovery, and executes validation that cannot be proven inside DevBox. Both roles use Codex by default. [ARCHITECTURE.md](ARCHITECTURE.md) defines their boundaries and the agent-selection contract.

Development work must not directly administer the host. The two roles exchange durable requests and evidence so a lost terminal or restarted container does not lose the job.

## Development, validation and repair loop

1. Turn the agreed outcomes into executable acceptance checks. Define tests before or alongside implementation, then develop and test individual functions and units inside DevBox.
2. Build the components and test their integration in DevBox wherever that environment can establish the required behaviour. Run full product journeys there when possible. Diagnose failures, repair the code and rerun affected tests throughout development.
3. When a required check cannot be proven in DevBox, send a durable, scoped test request to the maintenance side. Host-only validation is a required fallback, not an optional skipped test or a reason to give DevBox direct host access.
4. The maintenance agent validates the request and executes the identified candidate in an isolated host-side test workspace or suitable designated disposable target. It returns the test outcome, expected and actual behaviour, logs and diagnostics to DevBox. A check of real host behaviour must actually exercise that boundary.
5. DevBox consumes the result, fixes failures, rebuilds as needed, reruns affected local checks and requests fresh host validation. Continue within agreed time, spending and retry limits until all required checks pass or a specific unresolved blocker is reported. Changed candidates cannot reuse affected old passing verdicts.
6. Obtain independent review of the exact candidate, deploy or deliver it, and verify its real end-to-end use at the agreed destination. Hand the owner the usable product and evidence without a code-review task.

Host-side examples include real host systemd/Quadlet lifecycle, host networking and confinement behaviour that cannot be established inside the worker, and boot/restart behaviour when required. Capabilities determine placement; a test running inside some container is not automatically equivalent to a test of the actual VPS. Requests that need unsupported capabilities or would change protected live OS state must use an appropriately isolated disposable target or report a blocker. They cannot silently alter the running platform.

## Protected operating systems and disposable build trees

Product development and testing must not install into or modify the Fedora operating-system tree on the VPS, DevBox or maintenance container. Use independent, job-owned build trees, dependency roots and fixtures, with enforced boundaries. Builds must not run from live platform trees or replace running system binaries, libraries, packages or configuration. Declared writable workspaces, caches, runtime data and test volumes are separate from the protected OS tree. Authorized platform provisioning, upgrades and deployment are separate controlled operations; a product build/test request does not authorize them.

A disposable build tree can contain fetched source, dependencies, intermediate outputs and test fixtures, but it is not the only copy of valuable work. Preserve source edits, job checkpoints, evidence and deliverables in durable project storage before discarding a tree. Durable uncommitted work must survive interruption as well as committed source.

Keep compatible trees and verified caches through an active edit/build/test cycle and safe job resumption. Repeated builds must reuse unchanged inputs instead of repeatedly downloading them. Reset affected outputs when inputs, toolchains or targets change, or when a clean check or contamination requires it. Clean-candidate verification must not erase the active workspace or needlessly discard verified downloads.

Cleanup follows job completion or abandonment, a configured idle window, invalidation, or managed storage pressure. It must not purge active work on each iteration. Storage and retention are bounded: reclaim eligible inactive data first, preserve evidence and deliverables, and pause/report if capacity cannot be recovered safely. Numeric budgets and retention values are agreed or selected within delegated authority before jobs execute. Cleanup and cache behaviour must be demonstrated, not merely described.

## Initial scope

Build one pair on one Fedora Cloud 45 VPS with rootless Podman. Prove one small demonstrator product from brief to delivery. The demonstrator must have observable user journeys and enough persistent job or application state to prove recovery. This milestone must also exercise the host-test failure/repair/retest path and repeated-build reuse/cleanup; an application-only success inside DevBox is insufficient.

Concurrency, bare-metal and GPU support, additional agent adapters, and unrelated hosted applications are later work. Keep their addition possible without implementing them before the first delivery succeeds.

## Acceptance for the first pair

1. A fresh designated Fedora 45 VPS can be provisioned reproducibly. Reapplying setup preserves work and makes no unnecessary changes.
2. The default entry point starts Codex in each role with the intended permissions. Authentication works for unattended execution without credentials appearing in source, images or reports.
3. A product brief produces a working demonstrator whose agreed user journeys and relevant failure paths pass. Test evidence identifies the exact source and artifact tested.
4. A separate agent session reviews the candidate against the agreed requirements. Automated checks and independent evidence control release; the author cannot approve its own result or weaken its own gates.
5. The released product works at its agreed destination. A build, merge, image upload or successful process start alone is not delivery.
6. Interrupting a job and restarting its environment restores durable work and resumes from a verified checkpoint without duplicating consequential actions. A failed deployment recovers to a known working state. Backed-up durable data can be restored into a clean destination.
7. The product owner receives the usable address or artifact, brief instructions, acceptance evidence, remaining limitations, operating costs and recovery information in plain language.
8. A brief with material ambiguities is refined into the recorded product agreement before dependent implementation. After agreement, normal development and test failures are resolved without routine owner intervention; genuine scope/authority decisions and exhausted recovery are reported clearly.
9. A representative product has meaningful function/unit, integration and end-to-end checks. A required host-only check is handed off, fails with actionable diagnostics, drives a DevBox code repair, and passes on the corrected candidate. A stale verdict or unavailable/blocked test cannot satisfy acceptance. A repeated request after interruption does not duplicate consequential effects.
10. Representative build and install attempts cannot write outside authorized build/data locations into protected Fedora OS paths on either role or the host. A failed build or host-side test leaves the live platform unchanged apart from declared runtime data. Test routing does not give DevBox host credentials or unrestricted execution.
11. Consecutive compatible builds demonstrate reuse of unchanged fetched inputs, without unnecessary repeat downloads. Relevant input changes invalidate affected outputs; a clean-candidate check does not destroy the active workspace. Storage and network-use evidence shows bounded cache behaviour.
12. Completion/idle cleanup and interrupted-cleanup recovery reclaim eligible disposable trees and test resources without deleting another job's or an active job's data. Source changes, checkpoints, test evidence and deliverables survive. Capacity pressure cannot trigger unbounded growth or silent loss of active work.

These are acceptance requirements, not claims of current capability. The README states what has actually been built and verified.

## Continuing work

An in-scope request follows the same delivery loop under the standing product agreement. Changes to outcomes, permissions, spending or scope require the product owner's direction. Routine code review and release decisions belong to the pair within those boundaries.
