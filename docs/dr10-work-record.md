# DR10 launch reconciliation and work record

## Latest continuation checkpoint

Updated November 16, 2026, 05:46 HKT. This section summarizes the current state;
chronological records below retain earlier evidence and owner decisions.

- Continue draft [PR13](https://github.com/oso-gato/dev-pair/pull/13), requested
  branch `codex/dr10-reconciliation-review`, coordination tree
  `/workspace/dev-pair`. PR source remains
  `8bdd19d050dc2fe6012b19052f2af538b77d5705`. Reviewed additional storage
  source is durably published at supplemental checkpoint
  `f15c11efbc7213f2d96f9133edf16a530601a05c`; it has no execution trigger.
  Standards remain `b9d4da5d442ac48dba2e8be62d81b5bdc83690b8`.
- [Fedora run14](https://github.com/oso-gato/dev-pair/actions/runs/43758085093)
  passed 254 tests and native service admission, Enforcing Fedora, authenticated
  inputs, pre/post inspection, complete report framing and outer cleanup.
  Initialize blocked after 16.811 seconds: status209, with actual init_t write
  denial on a var_run_t FIFO. No preparation/assembly acceptance. Its single-run
  scope is closed; there is no active CI run or permission for an unchanged retry.
- Reviewed offline stock-Codex state and managed-child component is included on
  the PR. Actual no-network checks passed; independent review verified cleanup
  failures cannot return success. Authentication, complete tool-path enforcement,
  Fedora ownership/nesting and session renewal remain separate runtime gates.
- Storage observation/capacity source `2944ac6`, repaired by `63ed903`, passed
  fresh Astra High review: 265 tests, independent filesystem and arithmetic checks.
  Source and tests match the reviewed checkpoint. It provides no hard quota,
  reservation, deletion or job admission. Unknown Btrfs inode capacity stays
  unknown. Native hard storage enforcement and safe cleanup remain required.
- Native relay `da2ebf5` and deadline/signal repair `afac296` are integrated
  locally through `9a97b81`. Fresh independent review passed the narrow repair
  with 275 tests and five adversarial checks, but native admission remains
  blocked by an inherited systemd timeout-abort drop-in. Sole Sol High builder
  `/root/durable_job_build` is implementing exact-unit owned masks, prelaunch
  configuration checks and an in-relay effective-profile gate in
  `/workspace/dev-pair-transient-profile`. Fresh Astra High
  `/root/transient_profile_review` is prepared for the immutable candidate.
  No policy grants, forced contexts or budget increases are included.
- Source handoffs are `/workspace/scratch/native-fifo-label-design.md`,
  `/workspace/scratch/nested-profile-source-research.md` and
  `/workspace/scratch/storage-admission-design.md`. They are source research,
  not native acceptance. Installed DNF/script domains, real nested engine/helper
  mapping and confined child transitions require actual verification.
- Subagent model/effort choices are accepted API settings: Sol High builder and
  fresh Astra High review. Backend attestation and coordinator model metadata
  are unavailable. Each implementation/review/retest slice retains its finite
  scope and evidence; current profile source slice is 35 minutes before checkpoint.
- VPS remains untouched; root credential availability was checked without
  exposing or sending it. This cloud has no verified supported VPS SSH route.
  Local managed Docker works but lacks the cgroup enforcement needed to replace
  the bounded Fedora VM runner. No credentials are copied into CI or source.
- Actual preparation/assembly, both gptbox placements, hard storage/cleanup,
  authenticated jobs, durable host-test repair, tailnet cutover/recovery,
  all-session renewal, independent release enforcement and demonstrator delivery
  remain incomplete. Main branch enforcement is unverified; PR stays draft and
  unmerged. Continue source repair and real validation within the existing scope;
  the owner does not coordinate workers or review code.

## Recorded baseline and authority

- Job: DR10 / A12.11 original-charter reconciliation, followed by the first bounded part of A12.12(1).
- Repository: `oso-gato/dev-pair`; fetched `main` and verified it equals `f2e829b0bcaa1fb5d22cf9b12261a122a607d25c` on 2026-11-10.
- Starting checkout: branch `work`, clean, at that same commit. Isolated coordination worktree: `/workspace/dev-pair-dr10`, branch `codex/dr10-reconciliation`, created from `origin/main`.
- Standards: `oso-gato/standards@08fc080dc8463a16e7ef753eefdefd98463b76b9`; all three adopted documents loaded from the matching local Git objects. Their private text is not copied into this record.
- Historical comparison: `90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`, `00-OBJECTIVE.md`, `00-BYLAW.md`, `CONSTITUTION.md`, and historical `ARCHITECTURE.md`. These are evidence, not current authority. In particular, this snapshot contains the subsequently corrected direct-in-DevBox interpretation.
- A11 references fetched and checked out at exact revisions: `oso-gato/fedora-bootstrap@e8def2684e91facceb985974ac4d38d64f0be8c5` and `oso-gato/fedora-dev@9811f351a43c89e7da1aa1fa255d4711a7ab5216`.
- The owner requested autonomous coordination and is not the code reviewer. On 2026-11-10 the owner explicitly authorized **model-configured local subagents for this run** after being told they are not standalone Codex Cloud conversations. This is a run-specific execution choice, not a permanent amendment of A12.
- Current scope: repository inspection, isolated source changes, local tests, durable draft handoff. The owner has identified an existing Hostinger VPS, but its secure endpoint and suitability for disposable testing remain unverified. No infrastructure purchase is authorized, and no deployment or credential migration has occurred. Reference repositories are read-only inputs.
- Coordinator-selected local limits: no new paid infrastructure/API purchases; one builder at a time; each delegated task bounded to 10 minutes, at most two repair cycles before checkpoint/reassessment. These are conservative limits for this run, not approved operating budgets for the deployed pair. Host spending, disk/retention, execution limits and nightly timezone remain unresolved before dependent execution.

## Owner correction: Fedora Cloud 44 target

On November 10, 2026, the owner reported that the existing Hostinger VPS runs
**Fedora Cloud 44 (F44)** and directed correction of the earlier Fedora 45 target.
Fedora Cloud 44 is now the target for the VPS, agent base inputs and validation
handoff (DR3.1/DR6.1, R6.1/R7.1, A1.1). This is owner-reported OS information,
not live host verification: no host has been contacted, inspected or changed.
The exact provider image, architecture, runtime capabilities and digest-pinned
official Fedora 44 base still require verification before adoption. Historical
commits and the explicitly historical Fedora 45 blocked-check entry below retain
the earlier record; no earlier test result is upgraded by this correction.

## Session and environment evidence

The managed executor is Debian 13, not the currently required Fedora Cloud 44 VPS. The environment status reported current observations, connected/running state, and an enforced unrestricted network policy. Its configuration reports no secret bindings or outbound identities. Git fetches and the GitHub connector nevertheless independently establish the repository access used here; absence of configured bindings is not proof that every service lacks credentials.

`codex` is installed (`0.167.0-alpha.4`); `podman` and `distrobox` are absent from PATH. No host runtime, SELinux, nested-container, unattended Codex authentication or model-entitlement acceptance has been established.

No standalone chat-creation tool is exposed in this client. The installed CLI offers `codex cloud exec`, but its read-only access probe, `codex cloud list --limit 1 --json`, returned HTTP 401 (authentication token could not be parsed). No Cloud task was submitted. Local CLI model flags would not by themselves prove Cloud execution settings.

The coordinator chat is `6af394d3-26e0-8191-8818-43e6027740db`, titled “Dev-pair — architecture and coordination”. Reading its service metadata confirmed the chat identity and workspace but did not expose model/effort; those settings remain **unverified**. The local subagent API supports explicit `model` and `reasoning_effort` parameters; the launch ledger records those actual requests and the service-returned identifiers. An accepted launch is configuration evidence, not a separate provider-side model attestation. No prompt text is used as proof of model selection.

| Role | Requested through execution API | Returned identifier | State |
|---|---|---|---|
| Architecture reconciliation check | `gpt-6-astra` / `high`, fresh context | `/root/charter_check` (child chat `6af39609-ea78-8191-a036-8140b6f990f9`) | Completed read-only reconciliation; no independent provider attestation |
| Builder | `gpt-6.1-sol` / `high`, fresh context | `/root/build_candidate_prep` (child chat `6af396e8-e3a4-8191-9560-749bb5dab0c5`) | Completed in `/workspace/dev-pair-build`, branch `codex/dr10-candidate-preparation`, from record commit `33e08e5`; returned `cdcd4a300494783c7e5b6290ed83e77b2cd891ad`, integrated as `a28330a` |
| Candidate reviewer | `gpt-6-astra` / `high`, fresh context | See accompanying PR handoff | Launch against the exact committed integration candidate; service identifier and verdict recorded in PR |

The GitHub connector reported push/admin permissions for dev-pair. The shell identity received HTTP 403 when reading main branch protection. A subsequent ruleset listing succeeded and returned two active **tag** rulesets, not a demonstrated branch release gate. These observations do not establish independently enforced release checks; A6.3/A12.9 promotion remains blocked until enforcement is verified. No bypass or ruleset change is authorized by this record.

## Original-charter reconciliation

“Retained” means a current contractual home exists, not that the feature is implemented. “Proposed clarification” is not an approved amendment. Historical mechanisms and historical policy references do not supersede the adopted documents.

| Material original item and source | Classification and current home | Acceptance or next action |
|---|---|---|
| Outcome → clarification/agreement → autonomous delivery; owner never reviews code (objective: workflow) | Retained: R1.1, R2.1–R2.3, R4, R7.7–R7.8 | Demonstrator journey, failure/repair and plain-language delivery; no routine owner approval loop. |
| Independent exact-candidate review, destination verification, recovery (objective: delivered; B6) | Retained: R4.6, R7.3–R7.6, A6, A12.4/A12.9 | Separate reviewer; source/artifact-bound tests; real destination and restore checks. Enforcement is presently unverified. |
| Ticket bus, host/development split, host never merges, CI builds production images (objective: pair/boundaries; B4) | Retained: R3, R4.3–R4.5, R9.2, A2/A3/A6 | Scope-denial and host-test repair round trip; verified CI artifact and controlled replacement. |
| Headless operation, no display/local seat after genesis (objective: pair/boundaries) | **Restored with owner approval, 2026-11-10**: R7.14 and A7.4 | Make install, authentication, launch and recovery work with no graphical seat; test with display variables absent. Remote browser-based authorization, if needed, must have a documented bootstrap route. No GUI dependency should enter slice 1. |
| Client disconnect, network roam and device sleep preserve work (objective: security outcome 3) | **Restored with owner approval, 2026-11-10**: R7.15 and A7.4; complements R3.2/R7.6/R9.4 | Detach/reconnect while work proceeds, retain same job/session identity and observable progress, with no manual worker nudge. |
| Authorized repositories only; GitHub App installation bounds reach; dedicated identities (objective: pair/boundaries) | Retained: R1.1/R9.5/A2.3 require authorized scope and isolated credentials. The owner clarified that dedicated per-pair GitHub Apps are a design choice to explain, not a product requirement to approve. | Enforce declared job scope within actual credential grants; revoked/out-of-scope access fails closed. Explain the selected credential design before provisioning; do not infer expanded repository authority from its mechanism or from this run's admin connector. |
| Credential/service failure recovery (A12.11; objective: bounded recovery; reference token refresh) | **Proposed acceptance clarification** under R2.3/R7.6/R9.5/R11.2 and A7.3 | Expired/revoked credentials, unavailable model/GitHub/registry, rate limits and interrupted replies preserve checkpoints, bound retry, avoid duplicate effects, and report blocked/stale truthfully. Never silently switch account/model. |
| Reproducible, re-run-safe installation; fresh target rehearsal (B4 and host-track instantiation) | Retained: R7.1, DR6.1, A1/A8.4 | Rehearse twice on a designated disposable Fedora 44 target, inject interruption, demonstrate state preservation. One pasted root script, exact admin username and registry/vault choices are historical mechanisms; they are not automatically adopted. |
| Immutable runtime code and isolated author/build trees (B1/B2) | Retained and strengthened: R5.1–R5.2/R7.10, A4 | Reject writes and executable shadowing across host/all roles; job-owned writable paths succeed; verify branch before mutations. |
| Efficient dependencies, heavy stable layers, no repeated downloads (B1) | Retained: R5.3/R7.11, A4.9 | Same-input reuse and measured downloads; changed-input invalidation; clean check preserves active tree/cache. Dependency minimization is an ordinary engineering choice; the retired package-admission ladder is not imported. |
| Immediate total teardown/only input caches (B1) | Explicitly superseded by current R5.3–R5.4 and A4.5–A4.10 | Reusable active build trees and image layers; bounded lifecycle cleanup, not per-iteration deletion. Preserve evidence/uncommitted work. |
| One contract home, atomic producer/consumer change and safe staggered rollout (B3) | Retained: A3.7 | Reject unknown versions; withhold new producer shape until consumer supports it. Historical `shared/` layout is not compulsory. |
| Complete session inventory, external replacement executor, actual resumed work (B4/B6 and A11 implementation) | Retained: R9.2–R9.6/R11.3, A8/A10.3 | Missing/ambiguous session, checkpoint failure and interrupted replacement tests; restore every session by identity, not just cwd or process presence. |
| Separate host/DevBox and agent lifecycles; original disposable inner layers | Corrected/restored by owner-directed S1.7, R11, A2.4/A10; direct-in-DevBox snapshot language is superseded | Codex in both Distrobox placements; agent-only update leaves parent identities unchanged; nightly + on-demand triggers and failed candidate retention. |
| `agentbox → gptbox`, explicit override, recorded model on resumed jobs (B5) | Retained: A5, A10.6, R11.5 | Unavailable choice fails; provider environment and model are separate; no silent default migration. Claude adapter later under R6.2. |
| `erebus` / `strix`, reusable instance configuration (objective: lineages) | Retained: R3.3/A10.1/A11.1 | Lowercase names; one VPS now. `nox`/`moros` runtime naming is not reinstated by inference. |
| Bare-metal, GPU/virtualization, concurrent jobs (objective: tracks) | Explicitly later scope: R6.2, A11.1 | No bare-metal dependency for the first VPS pair; preserve extensibility without implementing it now. |
| Mother platform and remote desktop | Retained as later owner-directed scope: R10/A9 | Deliver pair first; Omarchy feasibility and its own agreement before implementation. No imported desktop or VM exception. |
| Private-by-default network, SSH/MOSH only, key-only shell, `core`, root retirement, trust-root/vault policy (objective: security; bylaw: genesis) | **Restored with owner approval, 2026-11-10**: R7.16 and A7.3 require private administrative services, key-only remote shells and no direct remote root after bootstrap. Other historical identity/transport/vault mechanisms are engineering choices, not imported policy. | Test public-network administration denial, password-shell/root-login rejection and successful authorized recovery. Explain credential/transport design without requiring the owner to select ordinary mechanisms; never widen authorized repository scope. |
| Historical human-only charter merge and live homelab-root constitution reference | Explicitly replaced by S1/S4.2 and R2/A6.3 | Pinned standards govern; owner decides product/authority changes, pair owns permitted ordinary review/merge. Do not load/import historical universal law as current authority. |
| Dogfooding every change through the pair | Bootstrap route explicitly allowed by A12.5; own loop remains required by R7.9/R9.6 | Label cloud bootstrap evidence; later prove the pair's actual handoff loop. |

The reconciliation is an evidence-backed proposal with outstanding decisions, not a claim that omissions are resolved or all historical security requirements were intentionally removed. Existing issue #10 and #11 descriptions predate the restart (Fedora 44/Claude/historical governance) and are background evidence, not current implementation instructions.

## A11 mechanism findings

- Host reference: `setup-user.sh:277–287` wires a 04:00 persistent timer; `claudebox-daily.sh` uses a shared/exclusive session lock and pending marker. `box-rebuild.sh:40–53` stops watchers, removes the old box and reassembles. Retain external ownership and busy deferral; replace destroy-before-build with candidate-before-activation.
- Host integration: `claudebox-init.sh` exports the parent Podman socket and writes post-assembly code. This is reference behavior, not permission to expose an outer host socket or mutate admitted code under A2.4/A10.4–A10.5.
- Nested reference: `entrypoint.sh:335–355` actually schedules the next local 04:00 (despite the stale “sleep 86400” comment in `claudebox-daily.sh`). `box-rebuild.sh:25–48` serializes and closes lock fd 9 before assembly to avoid a child retaining the rebuild lock. Preserve that regression case and explicit timezone/missed-run handling.
- `claudebox-assemble.sh` detects failed/stale assembly and verifies policy readability as the actual session user. It executes scripts from a writable live clone and destroys before assembly. Adapt the failure/readability checks to identified immutable candidates; do not copy the live-clone mechanism or historical policy.
- `bin/claude` retains explicit session IDs and a shared session lock, but launches a floating model default and copies skills from writable home. Codex needs its own supported identity/resume/model selection path; do not transliterate Claude flags or carry over mutable executable extensions.
- `bin/rebuild-request.sh` deduplicates by session ID and refuses omitted live IDs or ambiguous same-cwd sessions; `host-agent-watch.sh` uses verified container identity and progress handshakes, not merely a recreated shell. The pinned producer still contains approval-label wording while the pinned host explicitly retires that tap. Do not reintroduce manual coordination from those historical strings.
- `fedora-dev/fedora-dev.container:60,71` adds `NET_ADMIN SYS_ADMIN` and disables SELinux label separation. This is a concrete feasibility risk under A1.2/A10.5, not an authorized exception for dev-pair.

## Evidence and boundaries

| Check | Result | What it establishes |
|---|---|---|
| Fetch dev-pair main, standards Git objects, both A11 pinned revisions | Pass | Source identity/read access; no runtime claim |
| `fedora-dev`: `timeout 45 bash rebuild-request.test.sh` | Exit 0, ALL PASS | Historical manifest producer fixtures/consumer grammar checks; includes omission, ambiguous cwd and failed filing retention cases; engines/network stubbed |
| `fedora-dev`: `timeout 45 bash claudebox-assemble.sh --selftest` | Exit 0, five decision cases PASS | Historical assembly decision behavior only; unreadable image ID currently skips, which must not become provenance approval |
| Cloud session listing | Blocked, HTTP 401 | Standalone CLI launch route not authenticated |
| Branch protection inspection | Blocked, HTTP 403 | Current shell cannot verify this release gate |
| Ruleset listing | Pass on second attempt after HTTP 503 | Two tag rulesets visible; no branch enforcement proven |
| Historical Fedora 45 target, nested Podman/Distrobox, SELinux, headless/auth/host renewal | Not run / blocked | Earlier target before the owner correction; no designated authorized target, runtime tooling or operational budgets at that check |
| Current Fedora 44 target and both Distrobox placements | Not run / blocked | Owner-reported OS only; no live OS inspection, secure host connection, runtime validation or operational budgets |

Raw local reference-test logs: `/workspace/scratch/dr10-rebuild-request.log` and `/workspace/scratch/dr10-assemble-selftest.log`. They are local evidence, not portable runtime acceptance. No reference repo changes or historical installer execution occurred.

The independent Astra reconciliation check agreed that local preparation may proceed while host/security decisions remain unresolved. It identified headless operation and client disconnect continuity as missing explicit outcomes; installation rehearsal and dependency reuse already have current acceptance. Its recommendation is a small candidate recipe, explicit path layout and fail-closed invocation preparation, not a general orchestration framework. The owner approved restoration of headless operation and client disconnect/network-change/device-sleep continuity on 2026-11-10; R7.14–R7.15 and A7.4 record the decision. After examples, the owner clarified that dedicated GitHub Apps are an engineering design choice to explain, not a requirement requiring product approval. The remaining product questions concern private administration, key-only remote shell/no direct root after bootstrap, and whether an existing test server is available. The owner approved private administration and key-only remote shells with no direct remote root after bootstrap; R7.16 and A7.3 record them. The owner identified an existing Hostinger VPS plan 4 and offered access for deployment. The owner subsequently reported its OS as Fedora Cloud 44 and corrected the target as recorded above. Its address, verified live OS/data/services inventory and secure connection remain unknown; inspection must precede any decision about disposable testing or deployment. No host has been contacted or changed. The host request was clarified as permission to use a spare/test server, not a request for the owner to execute tests or review code.

## Implemented local preparation

The Sol builder returned `cdcd4a300494783c7e5b6290ed83e77b2cd891ad`, integrated as `a28330a`. It adds `tools/candidate.py`, offline fixture generation, eight tests, and a candidate-bound Fedora handoff in `docs/candidate-preparation.md`. Local validation checks binary integrity, explicit identities, deterministic context output, source identity, unsafe path proposals, immutable recorded model/effort, fixture separation and execution refusal. A fixture CLI exercise succeeded; `launch` refused with exit 2 as required. No actual Fedora/Codex upstream identity was invented, no image was built, and no Distrobox execution adapter exists yet. This is preparation within slice 1, not completion of slice 1 or the product.

Fresh Astra reviewer `/root/review_candidate_1` reviewed `3b57e6cc5c3937f8f13cf92585f1d1e78e5bbaeb` and returned changes required: the initial host-build handoff circularly required an already-built image, and committed tests did not exercise non-fixture validation. Sol repaired both in `f035e917fd0370f094591bdc241b7a7974da886c`, integrated as `5d9d05b`. The handoff now separates context-bound build from image-bound runtime checks; five additional offline tests exercise actual isolated Git lookup, source mismatch/missing objects, ELF/architecture and placeholder rejection. All 13 tests pass in the integration tree. Synthetic non-fixture test assertions remain explicitly untrusted and do not establish upstream provenance. Runtime code is unchanged by the repair.

Fresh Astra reviewer `/root/review_candidate_2` reviewed published `b22c72c5e8af101b4de8fa88eb3c322c8a33318a` and confirmed both earlier repairs, but reproduced a test fixture error with `PYTHONDONTWRITEBYTECODE=1`: removing the final tracked file also removed its parent directory. Sol repair `1163a503b16dbe616590dd1347ea64ece531eee2` explicitly recreates that directory. All 13 tests then passed in fresh scratch roots both with normal bytecode behavior and with bytecode disabled. This exhausts the run's two planned repair cycles; further substantive findings require a checkpoint and explicit bounded reassessment. No runtime implementation changed in either repair. A fresh affected review of the final published candidate is recorded in the PR.

The integration candidate includes the owner-approved R7.14–R7.16/A7.3–A7.4 additions and a README link to this record. The local commit IDs above are the audit trail in the execution workspace. Shell Git push lacked write credentials, so publication uses the GitHub connector with a separately identified commit and verified identical Git tree. The final published SHA, fresh reviewer service identity, review verdict, any repair candidates and final test evidence are recorded in the accompanying PR, avoiding a self-referential commit hash or an author-supplied release approval.

## Work queue and durable handoffs

1. Complete reconciliation check; resolve only material product/authority choices before dependent work. Keep proposed additions distinct from current clauses.
2. One bounded A12.12(1) builder: reproducible candidate inputs/construction and explicit workspace/state boundaries first, with meaningful failure tests. Both real Distrobox placements remain acceptance requirements. Report a partial implementation if host execution is blocked; never substitute a mock launch for success.
3. Run affected local checks and submit an A3 host request for exact candidate/artifacts once an authorized Fedora target exists. Required host checks: both placements, rootless nesting/SELinux, code-write rejection and writable-state success, no outer-host socket/host-exec bridge, unattended authentication and recorded model/effort, actual launch and checkpoint recovery.
4. Fresh Astra High reviewer reads authoritative sources and exact committed candidate without editing. Repair through Sol, retest and start fresh affected review. No author self-approval; no merge/promotion while required gates/host evidence remain unavailable.
5. Continue A12.12(2) durable job + failed host-test repair/retest, (3) nightly and separate platform renewal with failure recovery, then (4) complete demonstrator delivery, cache cleanup and restoration. No later slice is claimed complete here.

Builder launch brief: Work on `oso-gato/dev-pair`, starting from recorded main `f2e829b0bcaa1fb5d22cf9b12261a122a607d25c`, in your assigned isolated worktree. Configure `gpt-6.1-sol` / `high` through the execution service. Read DR10, STANDARDS and all three exact pinned sources, REQUIREMENTS, ARCHITECTURE A12 and this work record. Implement only the bounded first slice assigned by coordination; preserve A2/A4/A5/A10/A11. Define meaningful tests, run local checks, and return an exact commit plus remaining A3 requests. Do not expand permissions, deploy, purchase infrastructure, silently change models or claim absent host checks passed. Record actual session/configuration evidence, limits and next action.

Reviewer launch brief: Configure a fresh `gpt-6-astra` / `high` session through the execution service. Independently read the same authoritative sources and the exact candidate SHA provided by coordination. Inspect the diff and run appropriate safe tests. Check omitted requirements, provenance, write/credential boundaries, failure/retry behavior and evidence truthfulness. Do not edit the candidate. Return pass, changes required or blocked with precise references, distinguish code-review verdict from full milestone acceptance, and never treat the author summary as proof.

## Continuation checkpoint — 2026-11-11

This entry supersedes earlier unknown-endpoint/credential/target-authorization
statements; historical observations above remain historical.

- Resumed PR #13 at `512cf6aa3afc41d1db128e82221a9caf9a84ca2b`, branch
  `codex/dr10-reconciliation-review`, initially clean. Loaded README DR10,
  STANDARDS, all three Git-object documents at the unchanged standards pin,
  REQUIREMENTS, ARCHITECTURE A12 and this record.
- The owner designated the existing Hostinger VPS as clean/disposable and
  authorized initial root access and wiping if needed. Fedora Cloud 44 remains
  owner-reported, not inspected. Host address and credential values are not
  published here. The credential reference is environment variable
  `hostinger_root`; a boolean-only process check confirmed it was nonempty.
  Environment status independently reported this runtime variable `ready`,
  current observations and enforced network policy. No credential was printed,
  written to source or supplied to a remote endpoint.
- Supported SSH transport is **blocked before authentication**. The managed
  executor startup policy reports `vpn_configured: false`,
  `automatic_tailscale_access: false`, and empty TCP domain/IP grants. The
  cloud-environment runtime networking/VPN reference specifies that raw TCP
  CONNECT uses Tailscale transport; unrestricted HTTP is not public SSH access.
  No supported route to the designated host is established. No SSH retry,
  authentication, host command, wipe or deployment occurred in this continuation.
  Diagnostic metadata returned `history_status: not_found`, no captures.
- No runtime environment-change tool is exposed. To unblock host work, provide
  an execution environment with a supported authenticated SSH route to the
  designated VPS (or configure the managed Tailscale route and eligible target).
  A public-IP TCP grant alone is not established as sufficient by the runtime
  documentation. Do not bypass the proxy or weaken host-key verification.
  After connectivity is available, first inspect OS, architecture, disks,
  services, network exposure, SELinux, users and recovery access read-only;
  only then plan authorized provisioning. Preserve R7.16 key-only/private
  administration and root retirement after bootstrap with verified recovery.
- Local source work may continue under A12.10. This run renews a bounded
  assessment: one Sol High builder, 10 minutes per task before checkpoint,
  at most two repair cycles, no new paid infrastructure/API purchases.
  Deployed runtime budgets/scheduling remain unset until dependent execution.
- Builder execution API accepted `gpt-6.1-sol` / `high` with fresh context and
  returned `/root/build_dr10_continue`, using `/workspace/dev-pair-sol`.
  These are actual API settings, not prompt-only selection. Independent
  provider-side model attestation and this coordinator's model/effort metadata
  are unavailable. Local agents are explicitly owner-authorized; no standalone
  Codex Cloud conversation is claimed. Fresh Astra High review will bind to the
  exact integrated candidate; its returned identifier/verdict belongs in PR #13.
- PR #13 remains draft. A historical bot comment offers a `live-validate` loop;
  that comment is not proof of this restart's required boundary checks or release
  enforcement and is not authority to enroll this candidate for automatic merge.
  Required Fedora/Distrobox evidence and independently enforced release checks
  remain outstanding; no merge or production promotion is claimed.

Release-gate recheck in this continuation: the GitHub connector again returned
HTTP 403 (`Resource not accessible by integration`) for main branch protection;
the ruleset list again showed two active tag rulesets only. Enforcement remains
unverified. Shell Git push dry-run now succeeds, so the reviewed continuation
can be published as its exact local commit rather than recreating its Git tree
through the connector. This does not establish merge/promotion readiness.


## Owner correction and explicit tailnet migration — November 10, 2026 (America/New_York)

This current requirement correction supersedes the earlier administrative-only
access interpretation and public-product allowance; previous observations and
review verdicts above remain evidence only for their identified candidates.
The owner explicitly directed a cross-repository standard for executing VPS
container/VM-like development environments and applications, not merely control
panels. It does not mandate Podman for all repositories or affect source storage.

- Shared draft baseline: `oso-gato/standards@08fc080dc8463a16e7ef753eefdefd98463b76b9`.
  Prepared and committed first as
  `oso-gato/standards@b9d4da5d442ac48dba2e8be62d81b5bdc83690b8`, still
  pre-1.0 unreleased, no tag. Applicable citations: E12.1–E12.4, G1.4,
  RS5.10 and SR7.3. No private shared rule text is copied into this project.
- The owner approved this adoption and explicitly migrated the current
  DR10 / PR #13 job from the old pin. S1.3–S1.7 and all three links now identify
  that exact new draft. Other repositories and jobs retain their own pins until
  separately migrated; central publication is not runtime enforcement.
- R7.16 retains key-only shells, root retirement and controlled recovery while
  tracing its superseded network scope to new R7.17. R7.17 applies authorized
  Tailscale-only access to DevBox, both roles, demonstrator and later hosted
  workloads; no public-ingress exception is approved here. R7.18 and A7.5 keep
  authorized fresh-host SSH/provider-console bootstrap separate, avoid enrollment
  circularity and require proven tailnet entry plus independent recovery before
  temporary access is retired. A7.3 records topology choices within confinement;
  R10.3/A9.1 and the Fedora handoff carry these outcomes forward.
- `tools/candidate.py`, fixture generation and documented inputs use the new
  exact pin. A regression verifies adoption/fixture agreement and rejects the
  prior pin before output writes or invocation planning. Generated contexts
  must be regenerated and re-reviewed under the new source and standards pin;
  previous reviewed contexts/results are not upgraded to the new obligations.
- Builder API configuration: `gpt-6.1-sol` / `high`, returned identifier
  `/root/tailscale_standard_build`; independent provider attestation unavailable.
  Isolated worktrees: `/workspace/standards-tailscale` and
  `/workspace/dev-pair-tailscale`, starting from the shared baseline above and
  dev-pair `fc39196c1532c3f9253b9e82eaf132fa6d8ae839`. Scope is source/docs,
  local validation and committed handoff only, bounded to 10 minutes before
  checkpoint and at most two repair cycles. No host or network changes,
  enrollment, credential use, push, merge or release tag occurred in this task.
- Local validation: all 18 offline tests pass, including the old-pin denial
  regression and fixture/non-fixture context checks. Document checks cover
  whitespace, unique anchors, local links and matching resolvable adoption pins.
  Tailscale/host runtime tests remain unrun/blocked. A fresh Astra review must
  independently assess the two exact commits before publication; its identifier
  and verdict belong in PR #13. This builder supplies no release approval.

Next host handoff must bind to the new source/standards pin and include authorized
and unauthorized/public access tests, tailnet-loss denial without fallback,
bootstrap cutover and recovery under explicit effects/limits. The previously
reported executor transport blocker is distinct from this product requirement:
an authorized public SSH/provider-console bootstrap path can precede enrollment,
but this task has established no usable executor-to-host route.

## Fedora 44 bootstrap implementation — 2026-11-15

The owner explicitly redirected continuation to real bootstrap source for the
vanilla Fedora Cloud host rather than waiting for SSH connectivity. This slice
starts from `4dcf92e256a49770ddd89e4420b105319885910f`, in isolated worktree
`/workspace/dev-pair-bootstrap`, branch `codex/fedora44-bootstrap`. README DR10,
STANDARDS, all three shared Git-object documents at
`b9d4da5d442ac48dba2e8be62d81b5bdc83690b8`, REQUIREMENTS, ARCHITECTURE/A12 and this
record were loaded. No A11 code was copied or executed: agent lifecycle adaptation
is outside this prerequisite-only scope.

The actual executable `tools/bootstrap.py` and [guide](fedora-bootstrap.md) provide
inspect, default-preview prepare/enroll, explicit `--apply`, status, and a
fail-closed finalization refusal. Implemented effects: official signature-checked
RPM prerequisites, isolated operator/runtime identities, nonoverlapping subids,
durable directories and bounded cgroup defaults, operator effective SSH checks,
source-CIDR bootstrap guard, external-file Tailscale enrollment and node/tailnet
identity reconciliation. Desired state records the script SHA256, baseline,
standards pin and public configuration; journaled stage boundaries permit retry.
Applications are never started. Runtime storage/cleanup enforcement remains absent
and jobs are disabled. Temporary root/public SSH is retained deliberately, with
explicit source restriction; R7.16–R7.18 final cutover is **not complete**. No
provider credential was read, target contacted, host mutated, image built or
application launched. No push, merge or release tag is authorized by this task.

Coordinator launched the builder as `/root/fedora_bootstrap_build` with accepted
API configuration `gpt-6.1-sol` / `high`; independent provider attestation is
unavailable. A separate research session checked official Fedora package and
Tailscale repo/flag sources. Execution is source development and local tests only,
with a 15-minute checkpoint and at most two review/repair cycles before bounded
reassessment. The first checkpoint reported source/compile completion; continuation
covered tests/docs. This builder supplies no independent release approval. Fresh
Astra High review must bind to the exact returned commit.

Local validation uses synthetic command responses and temporary filesystem roots,
clearly separated from Fedora evidence. Required real checks remain: signed RPM
install/second apply, actual operator key login and sudo, rejected runtime logins,
SELinux labels and confinement, rootless Podman/subid behavior, cgroup ceilings,
nft syntax and ingress on IPv4/IPv6, enrollment failure/mismatch/retry, restart and
reboot persistence, tailnet ACL authorization, independent console recovery and
later timed-rollback SSH cutover. No local success upgrades those checks to pass.
Exact commit, local results and fresh review verdict belong in the PR handoff.

Coordinator additionally generated the operator Match fragment through the fake
command fixture, made an ephemeral host key in scratch storage and parsed it with
real Debian OpenSSH `sshd -T -f ... -C ...`. Exit 0 and expected key-only effective
settings establish Debian parser/precedence behavior only, not Fedora login or
SELinux acceptance. The temporary material was removed; no host SSH configuration
was changed. Builder local suite: 35 tests passed (17 bootstrap and 18 candidate),
Python compilation and CLI help passed, and `git diff --check` passed. Test-owned
command substitutions do not execute package managers or provisioning on Debian.

### Owner addition: host maintenance gptbox in first bootstrap

The owner subsequently directed: “also build the gptbox for the host in first
bootstrap.” Source continuation starts from builder commit
`6ce6adae37db4d951a31c4a6f31091a098273baf`. The prepare CLI now requires a real
maintenance-role prepared context and separately trusted expected context hash.
The implementation stages public inputs root-owned/read-only, uses the actual
candidate verifier (fixed recipe, source, binary and standards checks), builds
with rootless Podman as `dp-maint`, and records the immutable ID returned by the
builder plus context/source/base/Codex identities. Separate vfs storage and fixed
bounded transient systemd operations keep it outside root/system package paths.
Existing labels/tags are insufficient provenance: reuse requires a root-protected
completed record matching actual image ID/context; an unrecorded interrupted
build is rebuilt from its verified inputs. No fixtures, arbitrary submitted
Containerfiles, development-role context, live package install into agent code,
engine socket, host bridge or secret-bearing build input is accepted.

This produces a **Fedora/Codex OCI candidate for host maintenance gptbox**, not a
Distrobox-assembled/admitted runtime. Independent official-source research pinned
Distrobox1.8.2.5 to `40c3cd724faa434aeb0a23e28776665b92de68bd`: its create path
unconditionally grants privileged/SELinux-disable/root configuration and host/home
mounts; init discovers/links host sockets. The concrete A1.2/A2.4/A10.5 conflict
blocks stock Distrobox execution. The required Distrobox layer remains in the
design; no plain Podman agent launch substitutes for it. Full assembly/confinement,
authentication/model access and actual host-image build remain live validation
requirements. This source task neither resolves actual upstream pins nor builds
an image on the current development machine.

Fresh review of `6ce6ada` returned three changes required. This first combined
repair cycle fixes: (1) enrollment CLI failure/timeout after daemon-side commit
now explicitly disconnects the unverified node, (2) known root-owned tailscaled
PeerAPI listeners on observed node addresses no longer cause false non-vanilla
rejections on reapply, and (3) runtime-owned directory traversal now uses dirfds,
`O_NOFOLLOW`, `mkdirat` and fd-only chmod/chown to prevent symlink redirection of
root writes. Tests reproduce the enrollment side-effect case, enrolled PeerAPI
reapply and an injected directory symlink swap, checking preservation of the
victim and bootstrap recovery route. Candidate Git verification also uses a
fixed executable and clean environment; contexts must be regenerated against
this changed verifier revision.

Continuation remains `/root/fedora_bootstrap_build`, API-configured Sol High,
source/local tests only. A 15-minute checkpoint recorded code and initial tests;
continuation completed documentation and affected checks. All **41 local tests**
pass (23 bootstrap, 18 candidate), compilation and whitespace checks pass. Real
Git verification is exercised in isolated synthetic repositories; every engine,
systemd, Tailscale and account command in build/bootstrap tests is fake. No
Podman/image, SSH, provider credential or live target operation occurred. Fresh
Astra review must assess the exact combined candidate; this author record grants
no release approval or completed Fedora/runtime acceptance.

### Second scoped repair — post-enrollment failures and upfront input checks

Fresh combined review of `777fc5e417c02079caff24291df012b5007aeb97` found that
successful `tailscale up` followed by status/JSON/persistence failure could leave
a new unverified node running. The complete new-enrollment transaction now shares
fail-closed cleanup: up, observed status, JSON, identity, node persistence and
completion journal. Disconnect is attempted even with broken journaling. A
partially visible new completion record is removed after disconnect. The already
accepted unchanged-node retry remains separate, so an observation failure does
not unnecessarily disconnect that established node. Initial source-scoped SSH and
independent recovery remain intact.

The same repair moves context/hash/schema/role/recipe/binary/platform checks ahead
of state/package/account/network mutation. These checks are Python-only and do
not admit source/runtime. If Git exists, full source-object verification also
precedes mutation. A vanilla host lacking Git installs only the declared signed
Fedora `git-core` prerequisite, then must pass full source verification before
immutable desired binding or normal provisioning. That prerequisite can remain
if source verification fails; no failed desired target traps the corrected retry.
Public candidate verification always includes Git source checking; no CLI bypass
or `source_verified=false` admission was added. Read-only preview validates
available inputs and explicitly reports pending source verification when Git is
absent. Full context and protected-stage verification still precede engine use.

All 46 local tests pass, including post-up command/JSON/node-persistence failure
(before and after a visible write), accepted-node observation failure preservation,
upfront invalid-context no-mutation, corrected-hash retry and minimal-Git/source
failure boundaries. Compilation and whitespace checks pass. Source, model/API
settings, host restrictions and absence of live Podman/Fedora evidence remain as
recorded above. This is the second scoped repair cycle; further substantive
findings require the bounded reassessment rather than silent repeated repair.

### Bounded final enrollment-state repair

After the two scoped repair cycles, the coordinator explicitly authorized one
final ten-minute repair/review for another reproduction of the same enrollment
state defect: a crash after `up` leaves Running plus matching intent but no
accepted node record, and the old retry treated that as established before
persistence succeeded. The resumed unverified Running state now enters the same
full validation/persistence/disconnect transaction as a new enrollment, without
repeating `up`. Initial status failure on a matching unverified intent also
attempts disconnect; accepted unchanged-node observation failures retain their
established route.

Explicit `enroll --apply` now permits a narrow same-intent retry of an unverified
Stopped state only with no accepted node record and expected/absent observed
tailnet identity. Accepted stopped nodes are never automatically reactivated.
Observed wrong-tailnet states create a protected recovery-required record and
remain blocked even if later status omits the identity; scoped operator recovery
and checked/replaced credentials remain necessary. No reset, forced reauth,
secret logging or broader access path was added.

All **50 local tests** pass, with new regressions for resumed-Running persistence
failure, same-intent unverified-Stopped retry, accepted-Stopped refusal and
wrong-tailnet-Stopped refusal/latching. Compilation and whitespace checks pass.
These are synthetic state/command fixtures, not live Tailscale/Fedora evidence.
No host, provider credential, image build, push or deployment occurred. This
bounded repair needs fresh affected independent review of its exact commit;
further substantive work requires a new bounded assessment.

### Narrow official-schema correction

The final affected review reproduced normal disconnected status with
`CurrentTailnet: null`, defined by the official Tailscale schema at
[`v1.82.5/ipn/ipnstate/ipnstate.go#L66-L68`](https://github.com/tailscale/tailscale/blob/v1.82.5/ipn/ipnstate/ipnstate.go#L66-L68).
The coordinator authorized one further ten-minute bounded correction of that
actual upstream-data mismatch. Nullable CurrentTailnet and Self are now
normalized as absent identity fields. Fresh NeedsLogin and eligible same-intent
Stopped attempts can enroll with those null fields; Running nodes without the
expected tailnet name or actual node ID still fail closed. No source/runtime
admission or schema CLI bypass was added.

Resumed unverified Running intent normalization and persistence now sit inside
the existing full cleanup transaction. A failed actual intent write therefore
disconnects the unverified node, just like a failed node-completion write. Tests
cover legitimate nullable disconnected states, Running null tailnet/Self denial
and an injected fsync failure after an actual reconciled intent write. All **53
local tests** pass, along with compilation and whitespace checks. No host,
Tailscale, Podman, secret, push or deployment operation occurred. The schema
citation supports fixture accuracy; it does not establish live Fedora behavior.
This narrow correction still requires fresh affected independent review of the
exact returned commit before publication.

### Owner direction: directory layout and reference learning (2026-11-15)

The owner confirmed retaining the new `/var/lib/dev-pair/{maintenance,development}`
directory design provided it satisfies the requirements. Its `workspaces`,
`checkpoints`, `evidence`, `deliverables`, `builds`, `cache` and `state` classes
remain subject to A4.3–A4.7: separate role ownership, durable work protected from
cleanup, bounded disposable storage, and scoped credentials/state outside
immutable code. This approves the layout direction, not proof of enforcement or
the provisional numerical resource budgets. Credential delivery, disk quota and
cleanup implementation remain incomplete.

Use the exact A11 references as prior learning, selecting useful lifecycle,
recovery and regression-test ideas without copying their code or inheriting
their directory conventions, governance or security exceptions. In particular,
retain lessons about external replacement executors, complete session inventory,
verified resumed work, persistent state, cache reuse and interrupted operations.

Related owner clarifications to carry into the next bootstrap slice: provision
`core` with a securely supplied password, Tailscale login, mosh/tmux, and GitHub
public-key import. Remote SSH remains key-only; core is the operator, separate
from restricted agent identities. SELinux must reach enforcing with container
confinement retained. The reference's disabled-to-permissive relabel/reboot flow
is relevant to fresh-host setup; inspect live state and boot arguments, verify
labeling and successful enforcement, and gate workloads on completion. Do not
copy its suppressed `setenforce` failure or disabled container labeling. Current
bootstrap instead requires enforcing at entry and needs an enablement stage.

This is a durable decision/handoff note against source baseline
`9d86e325c13241ef6e93dbe72269af261126f925` and the unchanged STANDARDS pin
`b9d4da5d442ac48dba2e8be62d81b5bdc83690b8`, not a runtime implementation or
deployment claim. No host changes were made for this clarification.

### Implementation continuation and current execution boundary

On November 15 the owner instructed continuation through the dev-pair build.
R7.19 and A7.6–A7.7 now record the agreed first-bootstrap operator and SELinux
outcomes; A4.3 records the retained directory design. Coordinate one Sol High
builder at a time, followed by a fresh Astra High exact-candidate review. For
this continuation, each implementation slice is bounded to 25 minutes and
research/review to 15 minutes, with at most two repair cycles before explicit
checkpoint/reassessment. These local coordination bounds replace the earlier
ten-minute slice default for this continuation, not deployed job budgets. No
new paid infrastructure/API purchases are authorized or needed for source work.

The agent API accepted `/root/bootstrap_owner_requirements_build` configured
`gpt-6.1-sol` / `high` in an isolated worktree, and fresh architecture research
`/root/confined_distrobox_design` configured `gpt-6-astra` / `high`. These are
local subagents, not standalone Cloud conversations; independent provider
attestation is unavailable. The coordinator's model/effort cannot be independently
verified from available runtime metadata.

Current environment status reports ready `hostinger_root` and enforced
unrestricted networking. Credential presence was checked without reading it
into output. An actual OpenSSH connection to `31.97.145.144:22` returned
`Connection refused` before authentication; no password was sent. This is an
observed transport failure, not proof that missing Tailscale or a specific host
configuration caused it. No host inspection, wipe, deployment or reboot occurred.
The local executor has PID 1 `tail`, no SELinux filesystem or KVM device, and no
installed Podman/Distrobox; user-namespace creation succeeds. Local source tests
cannot establish Fedora systemd, reboot or SELinux acceptance. The unchanged
baseline's 53 local tests passed before implementation.

Reference history also records an enforcement regression from a shared dnf
cache retaining `user_home_t` (fedora-bootstrap commit
`8a39c70894808d43b001d84649c673aed18c8573`); its scoped shared-label fix explains why
actual confined mount/cache checks are required, not just `getenforce` output.
Choose labels according to role/trust sharing; do not indiscriminately share
private-role storage or disable labeling to make tests pass.

### Core access implementation and independent findings

Sol High returned `8f4771751954184f672b09683997dd668526d2a2`, integrated with the
owner-documentation commit as `e788373db27b8900556c8906caedfe2cfa87553f`. This
implements core password-gated administration, GitHub public-key import,
interactive-only tmux attachment, tailnet-only mosh with reserved ephemeral
ports, persistent erebus hostname and clock-service setup. Both builder and
coordinator ran 66 passing local tests, including real key parsing, stdin
handling and Bash PTY/noninteractive behavior; these are not Fedora acceptance.

Fresh API-configured Astra High `/root/core_access_review` independently ran
the 66 tests and reviewed exact candidate e788373. Verdict: changes required.
It reproduced (1) a failed password-marker write after unlocking core but before
installing its key-only SSH fragment, leaving password SSH possible under a
permissive provider default, and (2) blocking DNS outside the urllib socket/read
deadline. Repair must establish and verify SSH restrictions while the account
is locked, before setting its password, and impose a process-level fetch
deadline covering DNS/TLS/headers. These findings return to the Sol builder;
the passing tests alone do not approve the candidate. Fresh affected review is
required after repair.

The cloud desktop fallback also failed to start with
`the gaas-browser node_repl sandbox cannot be disabled`; no provider-console
session could be inspected. No credentials were entered and no host action
occurred. Source work continues independently of that unavailable route.

### Confined Distrobox implementation direction

Fresh Astra High research inspected Distrobox 1.8.2.5 at
`40c3cd724faa434aeb0a23e28776665b92de68bd`. Ordinary init rewrites configuration
and mounts devpts even after `/.containersetupdone`; preassembly alone cannot
make normal restarts compatible with an immutable root. Its documented hooks
offer a narrow downstream integration: actual upstream init in isolated
candidate assembly, fixed finalizer hook that seals/exits, then a new confined
nonroot read-only container using upstream pre-init to exec a fixed frozen
startup verifier. Controlled entry uses actual upstream distrobox-enter with
`--no-tty --no-workdir --clean-path`, an explicit command, clean environment and
protected parent configuration. Verify the exact existing container before
entry so upstream's absent-container auto-create never invokes unsafe defaults.
The constructor replaces unsafe stock creation explicitly; this is not an
upstream-certified confined mode or runtime acceptance. Actual Fedora assembly,
effective labels, mounts, code-write rejection and restart tests remain required.

Nested DevBox still needs measured namespace/storage/seccomp/SELinux validation.
`container_engine_t` and `label=nested` are research candidates, not permissions
to enable global booleans, disable labels or widen agent authority. No runtime
admission follows from source research. The detailed scratch handoff is
`/workspace/scratch/confined-distrobox-handoff.md`; the durable constraints and
next slice are captured here so its loss does not erase the design decision.

### Checked SELinux slice and review-driven corrections

Sol returned `835acc7f0f69b0e4f20e3b618be3a9e34086e3f4`, integrated as
`0ee5f8bc8b322a258a19f592eb4eaa196755abdd`: a protected, resumable SELinux setup
helper and temporary autorelabel override, explicit setup-reboot authorization,
boot identity records, normal-boot finalizer and 16 new local tests (82 total).
Fresh Astra High `/root/selinux_convergence_review` independently passed the
tests but returned changes required: Fedora policycoreutils 3.11's `fixfiles`
can itself hide underlying `setfiles` failure, and a persistent kernel
`autorelabel` trigger could repeatedly enter the relabel target despite marker
removal and evade per-boot reboot limits. The reviewer reproduced both. Direct
native labeling with preserved filesystem/exclusion semantics, bounded total
transition history and checked interrupted-marker recovery are being repaired;
neither source completion nor the original 82 passing tests establish a safe
Fedora transition. Recovery entry also needs bounded process containment.

The earlier core-access corrections returned as
`14d467e9b00ef974f669a4175f8b247183175868`, integrated as
`aa853c44cc01ee92007a882cd467d2372b88893a`. Fresh Astra High
`/root/core_access_repair_review` reported scoped PASS: all 86 tests passed,
eight additional interruption probes resumed safely, unlocked core retained
key-only policy, and a real blocked DNS child was killed by the unchanged
25-second production deadline in 25.027 seconds. Child environment isolation
was independently tested. This verdict excludes the separate SELinux findings
and does not establish Fedora authentication acceptance.

### Actual upstream inputs and corrected transport evidence

Read-only official release inspection resolved stable Codex 0.169.0 to source
`d32063f96c2dff1dc96af839b3952abb6acfeda4` (distinct from its annotated tag object).
The official musl archive SHA256 is
`9af4d751fce183faedea629437d5252dbf458eeb04130cf4f97be844621ea985`; its extracted
binary SHA256 is `b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b`.
Fresh Astra High research verified version/help interfaces in an empty scratch
home, then verified the binary's official Sigstore bundle using Cosign 3.1.4
with exact issuer/workflow/repository/tag/source-SHA constraints: `Verified OK`,
exit 0. Cosign itself was obtained over official HTTPS and matched the GitHub
asset digest; its own signature was not independently verified. No model call,
credential inspection or runtime admission occurred. The detailed handoff is
`/workspace/scratch/codex-stable-adapter-handoff.md`.

An initial signature-verification network failure was caused by clearing the
required HTTP proxy environment. It was corrected by retaining only inherited
proxy/CA settings with an empty scratch home, without disabling verification.
Do not carry that superseded failure forward as an endpoint access blocker.
Separately, the live cloud proxy status confirms TCP forwarding is disabled
with empty destination grants and Tailscale unconfigured. This explains the
lack of a supported SSH executor route here; the observed direct refusal does
not prove the VPS SSH service is closed. No transport bypass was attempted.

Official Fedora registry HTTPS inspection verified the manifest/config digests
and linux/amd64 identity for
`registry.fedoraproject.org/fedora:44@sha256:48f4a2b507ad36a6a8bb83646ee81164aff80a62be06d03b143b80594d2b558e`.
Image signature verification is not established. These are real inspected
inputs, not fixture digests or a built/validated gptbox. Stable Codex adds
strict configuration and exact thread-UUID resume interfaces, but writable
CODEX_HOME also contains extension/configuration inputs; hooks/plugins default
enabled. The adapter must enforce immutable managed configuration and loader
boundaries, preserve refreshable credentials separately, and verify actual
auth/model/session behavior before claiming usable runtime admission.

### SELinux second repair and bounded reassessment

The first native-labeling correction returned as
`d09910006c6fa5ce2dbe19babcb330d832a1b897`, integrated as
`e777992641d3f265b887d58b8b5559a92f842747` (96 local tests).
Fresh Astra High `/root/selinux_repair_review` reproduced Fedora 44's merged
`/usr/sbin -> bin` layout rejecting the protected setfiles path, and a read-only
ancestor exclusion silently suppressing a writable child mount. Its additional
interruption probes passed; actual Fedora execution remained unavailable.

Sol corrected canonical native-tool/RPM paths, exclusion overlap and subprocess
group timeout cleanup in `579f97e0e02ef4f91a6eead18302fcd01a8ce4d8`, integrated as
`47acb75392c6e2a18968899d476e8889ee66c83b` (99 tests).
Fresh Astra High `/root/selinux_final_source_review` independently passed the
tests and those affected fixes, but found one remaining variant: native
non-seclabel exclusions also recursively suppress admitted writable child
mounts. Its `/mnt` vfat plus `/mnt/data` labeled ext4 reproduction showed false
completion; upstream SELinux 3.11 source confirms the implicit exclusion.

After the two repair cycles, the coordinator explicitly reassessed and authorized
one additional ten-minute correction/review of this same exclusion defect:
reject admitted writable mounts below any native implicit exclusion, preserving
ordinary nonoverlapping pseudo mounts and EFI handling. No permissions or
runtime scope expand. Further material findings require another explicit
checkpoint rather than an unbounded repair loop. No source PASS or Fedora
readiness is claimed for 47acb75 while this finding remains open.

### Reviewed bootstrap checkpoint

The bounded native-exclusion correction returned as
`061137eb4d8e18567ae21f44ee0f72fb3869d8ad`, integrated as
`dc735ef6259b00e5fd01aa2e089094931bc885f6`. Fresh Astra High
`/root/selinux_exclusion_review` returned scoped source PASS against 47acb75:
all 100 tests passed independently; native 3.11 behavior and additional
read-only/non-seclabel ancestor, EFI and adjacent-path probes agree with the
guard. Rejection preserves the relabel marker, produces no completion evidence
and invokes no labeling command. Earlier canonical-path, timeout and access
repairs retain their recorded independent evidence. No actual Fedora labeling,
reboot, SSH login or container confinement has been exercised.

Publish this reviewed source checkpoint to draft PR #13 without merging or
claiming runtime approval. A separate Sol High gptbox assembly/probe adapter
slice continues in an isolated worktree and is not part of this checkpoint.
Its runtime constructor must preserve genuine upstream Distrobox initialization
and entry, controlled source/artifact identities and enforced boundaries; it
cannot substitute a successful version probe for authenticated job admission.

### Confined gptbox source candidate and review handoff

Sol High `/root/bootstrap_owner_requirements_build` returned
`588ecab96d005eb6ff75ff5677abce8be869395a`, integrated without source changes as
`8362a39` on the PR branch. It adds executable maintenance Distrobox assembly,
an image-owned finalizer, sealed readonly nonroot startup, controlled upstream
entry, two boundary/version cycles, bounded retry/reconciliation and protected
credential-free diagnostics. Candidate paths now match the approved role
directories; bootstrap adds the signed slirp4netns prerequisite. All 107 local
tests and compilation/whitespace checks pass on the integrated source.

Fresh `/root/gptbox_adapter_review` was launched with API-selected
`gpt-6-astra` / `high`, verified the exact standards checkout, and independently
passed 107 tests in a detached checkout of 588ecab. Interface, failure-path and
boundary review is still pending at this checkpoint. This is local-subagent
configuration evidence, not a standalone Cloud conversation or independent
provider attestation; the coordinator model/effort remains unavailable.

The adapter is deliberately a separate probe step, not yet automatically called
by first bootstrap. Its result cannot admit jobs. Authentication, model access,
immutable credential/session loaders, nested development placement, enforced
storage quotas/cleanup and real Fedora acceptance remain required. No image was
built or started here, and no host was contacted or changed. The next action is
fresh exact-candidate review, bounded Sol repairs if needed, then the authorized
Fedora assembly/failure/repair/retest gate when a supported executor route exists.
Do not promote this source checkpoint or substitute fixtures for that gate.

The exact 588ecab review returned **changes required**, despite 107 passing
tests. Production input validation unpacked the inherited helper's three-value
return into two variables; the reviewer reproduced rejection using the actual
verified Codex binary/context. Separate Podman conmon/container scopes outlive
the transient client unit, so they need native lifetime limits. A second-attempt
cleanup failure also became unrecoverable because budget rejection preceded
resource reconciliation. Podman's separate `HostConfig.Tmpfs` escaped the mount
guard, and accumulated logs could satisfy readiness using an earlier start's
marker. The adapter has not been published while these findings are open.

The existing Sol High builder owns one bounded repair batch: direct production
input regression, finite native container lifetime, cleanup-only recovery after
execution-budget exhaustion, exact tmpfs validation and current-start readiness.
No third build attempt, privilege increase or host operation is authorized by
these corrections. A new Astra High session will review the exact repaired
candidate; the earlier review cannot be reused as approval.

The repair returned as `ed9b8f3c8956589565d93a63f4a159e4815df94d`, integrated as
`d5903f2`. All 110 tests pass locally and independently. Fresh Astra High
`/root/gptbox_repair_review` confirmed production inputs using the real verified
binary/context, native timeout plumbing to conmon, two-build/two-cleanup limits,
tmpfs injection/ownership rejection and current-start log filtering. It found
one compatibility regression: Podman normally appends `tmpcopyup` to tmpfs
options, but the new allowlist rejects it before assembly. The second bounded
repair cycle addresses that normalization contract and its regression fixture;
another fresh scoped review is required before source publication.

A separate local Fedora VM feasibility check investigated software emulation,
not just KVM availability. The workspace has sufficient nominal resources
(16GiB memory ceiling, four CPU quota, approximately 59GiB free disk), but no
QEMU binaries, `sudo` executable or managed `cloud-agent-packages` helper. No
supported installation grant or existing project VM route was found; no package
installation, image download or guest boot was attempted. Thus neither a local
Fedora VM result nor VPS validation exists. Missing KVM alone was not treated as
proof that software emulation is impossible. The current environment remains
the same configured instance, with the root credential reference reported ready;
its value was neither displayed nor sent to the VPS.

### Reviewed confined-adapter checkpoint and real prepared inputs

The normalization correction returned as
`bf597cab3f2ba0d2279735f1a46bc2944bbc7c96`, integrated byte-identically as
`9001ea81203d66e37e5e922d6030a0862fd07b93`. It explicitly requests
`notmpcopyup`; the guard remains strict. Fresh Astra High
`/root/gptbox_normalization_review` returned scoped source PASS against ed9b8f3.
It independently passed all 111 tests, compilation and whitespace checks,
re-fetched seven official Podman source files to verify normalization semantics,
and used emitted arguments in an independent synthetic projection that completed
both probe cycles and rejected 32 option/ownership/mode mutations. Its Go harness
was unavailable, so native parser execution is not claimed. Together with the
prior affected review, this closes the recorded adapter source findings. It
does not establish Fedora, OCI, SELinux, authentication or model acceptance.

The coordinator also prepared and verified a real maintenance context using the
recorded Codex binary and Fedora digest, bound to source 9001ea8. It lives at
`/workspace/artifacts/dev-pair-9001ea8`, with the original input manifest, public
verification artifacts, preparation/verification results and a transfer README.
Its separately recorded context SHA256 is
`9d02dc4654bf4c8e8f7b9d070e5d5f8e8aaa1ed776a0f9c7c2738e567214f5ce`.
Its status is `prepared-not-runtime-validated` and `local-context-integrity-only`.
The manifest records maintenance/gptbox, requested Sol High and dedicated
`bootstrap-probe` leaves in the approved storage classes; it supplies no secrets
and establishes no model entitlement. The local task-owned artifact must be
transferred into protected root-owned staging before host use. If this workspace
artifact is lost, regenerate from the recorded exact verified inputs and record
the new context identity; never substitute a fixture or claim the old bytes exist.

Publish this reviewed source checkpoint to draft PR #13 without merging. The
next dependency is actual Fedora assembly and boundary/failure/restart validation,
then repair of observed runtime failures, before integrating an admitted usable
gptbox into first bootstrap and building the nested development placement.
Authenticated jobs, credential/session loader isolation, quota/cleanup admission,
tailnet endpoint/recovery acceptance, durable host-test repair, complete session
renewal and the demonstrator remain unfinished. Current tools provide neither a
supported VPS SSH route nor a local Fedora VM runtime. Do not present this
checkpoint as completion of the owner's full dev-pair build.

### Continued implementation after the reviewed checkpoint

The owner renewed the instruction to continue and complete the build. The current
checkout is clean at published `2635376af24d1c1a6acdf038484d6493b5d01214`;
environment identity/configuration is unchanged and its credential reference is
ready. The Fedora/VPS gate remains open, but A12.10 permits independent source
work to continue. No product requirement or acceptance boundary is deferred.

API-configured Sol High `/root/durable_job_build` is implementing the A3 durable
job/request/result ledger in an isolated worktree, with a twenty-minute initial
source checkpoint and at most two repair cycles before reassessment. The slice
must preserve exact candidate/test identities, transactional recovery, duplicate
request handling, interrupted-effect reconciliation and failure/repair/retest
evidence. Local protocol tests cannot authorize host execution or establish the
pair's actual host-test acceptance. No secrets, arbitrary host-command runner,
deployment or model invocation are part of this slice.

Independent Astra High `/root/fedora_ci_feasibility` is investigating a possible
Fedora VM test executor on standard GitHub Actions runners. Connected repository
metadata confirms that dev-pair is public. Research must verify current free
public-runner terms, runner capabilities, official image provenance and bounded,
secret-free test execution before a workflow is proposed. No workflow or VM has
been launched by that research, and a CI VM would not replace final acceptance
on the designated Hostinger VPS. The existing local runtime capability blocker
does not imply that every other authorized test executor is unavailable.

The ledger source returned as `111e036161cdc108805b86e36c74d7009e8f4078`,
integrated as `d55d5a1e3ad449eb4558915c9fd219045a2679df`. It adds one strict
schema library, a transactional SQLite controller, CLI and a fixed local JSON
data recipe; it accepts no arbitrary command or external unauthenticated result.
The documented journey ran in separate processes and retained failure evidence
while rejecting stale consumption after a repaired checkpoint. All 122 tests
passed. Fresh Astra High `/root/durable_job_review` also verified hot-journal
recovery after process death, sixteen duplicate submissions/executors with one
reservation/result, and 83 malformed-field rejects. It found one P2 defect:
an accepted near-limit request can overflow the result envelope and make both
execution and reconciliation fail permanently. The Sol builder is correcting
that size contract with a regression before fresh review; the ledger is not yet
published as reviewed source.

Public CI research verified that standard public-repository runners are free;
the initial workflow will use `ubuntu-24.04`, logs only, no cache/artifact upload,
paid runner or external account credentials. The official Fedora 44 Cloud
Generic 44-1.7 qcow2 checksum signature passed verification against fingerprint
`36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. Image length is 583729152 bytes and
SHA256 is `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`.
Research handoff: `/workspace/scratch/fedora-ci-feasibility.md`; official evidence
is public and does not include the private standards text.

The same Sol High builder began a separate CI worktree at
`/workspace/dev-pair-fedora-ci`, branch `codex/fedora-ci-probe`, from d55d5a1,
then paused it for the ledger repair. Its bounded thirty-minute initial task is
an executable signed-image Fedora VM boot/preflight route, followed by actual
maintenance gptbox probes where supported. KVM, available storage, tooling and
timing must be measured; capacity/time failure remains blocked evidence. No
VPS access, tailnet enrollment, authenticated model execution or release follows
from a CI VM pass. The exact workflow source requires fresh review before parent
publication and observation of the first bounded CI run.

The size repair returned as `8c27db4eebaf2d258b8af36ff9fdddaff6b552d6`,
integrated as `17ab51a595ffce7b5015cf836990ebc8aff550bb`. Requests reserve output
capacity with a 16384-byte canonical limit; reconciliation diagnostics/evidence
have an 8192-byte pretransaction limit. Fresh Astra High
`/root/durable_size_review` returned scoped PASS. All 123 tests passed
independently, along with the prior concurrency, malformed-input and hot-journal
probes. Exact-cap requests produced bounded complete results through both real
OS errors and reconciliation; one-byte-over reconciliation input changed neither
events nor state. An additional suspected Unicode filesystem-error expansion
was disproved on the actual CLI worker path, not assumed safe from fixtures.
The source findings are closed; authenticated transport, actual pair recovery
and host execution remain separate gates. Publish the reviewed local-protocol
checkpoint while the independently scoped CI harness continues.

The first CI route candidate returned as
`ddcb2b1a47e910cf10882b8a9835d8a7c9c9ee50`, integrated as `5c3ada4`.
Its exact-head PR workflow and signed-image QEMU controller perform actual
Fedora boot/preflight and read-only bootstrap inspection/status when launched;
prepare and maintenance assembly are explicitly unimplemented phases, so the
checkpoint intentionally returns exit 2 even if baseline checks pass. No CI
execution has occurred. The integrated suite passes 132 tests; the builder and
reviewer tested 131 on their branch without the separate ledger size regression.

Fresh Astra High `/root/fedora_ci_review` returned changes required for two P2
defects: ordinary concurrent file removal makes GNU du return an error that
aborts otherwise healthy tooling, and legacy GitHub `##[command]` syntax survives
the current log sanitizer, including raw structured-report fields. Both were
reproduced; signature and process-limit tests passed. The Sol builder owns one
bounded correction batch for race-aware conservative storage measurement and
safe output across every log/report path. Fresh affected review must precede
workflow publication and the first observed CI run. Neither the dormant source
nor local fixtures count as a Fedora boot result.

The first CI correction returned as
`dc595647456eb910bfe39773744fd29862ed3128`, integrated as `d68bb40`.
The integrated suite passes 135 tests. Fresh Astra High
`/root/fedora_ci_repair_review` confirmed safe lossless JSON/text output across
10000 variants, permission/error rejection, bounded maximum-sample storage
accounting, mandatory stable completion checks and child termination on reserve
failure. It reproduced one remaining normal-churn form: GNU du reports
`cannot read directory ... No such file or directory` as well as `cannot access`.
The second bounded repair cycle admits only that exact owned-path disappearance
case and extends the real directory-churn regression. Further findings require
coordinator reassessment; no workflow has been published or executed yet.

Independent Astra High `/root/codex_state_boundary_design` is investigating
stock Codex 0.169.0's credential/session/configuration paths for the next runtime
adapter. This is read-only source research, with no real auth files, login,
network/model calls or admission. In particular, writable session metadata and
mutable skill/plugin discovery must not be mistaken for inert state. Its design
handoff will be evaluated against A4/A5 before any implementation or runtime
claim. The single Sol implementation worker remains assigned to the CI repair.

The second CI correction returned as
`e25fdaaa816bf8694e9dd27de6c3b9d9d4f15e8c`, integrated as
`c3450ead41f301586e3dc25767a02330a7d6f4a2`. The integrated suite passes
136 tests and the CI files are byte-identical to the reviewed branch. Fresh
`/root/fedora_ci_final_churn_review` returned scoped PASS: all 13 CI tests,
the previous captured GNU du witness, independent malformed/foreign/error
rejections and bounded conservative accounting passed. It did not repeat the
full suite. No remaining material source finding was reported in this scope.
The review used accepted API configuration `gpt-6-astra` / `high`; an initial
claim that selection was unavailable was explicitly corrected by the reviewer.
There was no unsupported-selection error or evidence of another model. Actual
backend attestation and coordinator model metadata remain unavailable.

Publish this reviewed workflow checkpoint to the existing draft PR and observe
the first exact-head standard public-runner execution. Its explicit prepare/
assembly blockers mean exit 2 is expected even after a successful baseline;
report actual phases rather than treating that exit as either full acceptance
or proof that boot failed. The single Sol builder is preparing a bounded
read-only extension plan while baseline evidence is collected. No VPS access,
paid runner, credentials, model invocation, release or merge is authorized by
this CI probe. Existing project authority and requirements remain unchanged.

The first published workflow actually ran as GitHub run `43729422976`, job
`132858362638`, source `21397430f7f74c1f11b4a529d776d237e87ab549`.
The standard Ubuntu24.04.5 runner (image 20261111.370.1) passed all 136 tests.
Runner preflight then blocked: Podman rejected the generated runroot pathname
as longer than 50 characters. Cleanup repeated that configuration error and
did not report successful scratch removal; the disposable runner was finalized.
No dependency image was downloaded/built and no Fedora guest boot occurred.
Logs: https://github.com/oso-gato/dev-pair/actions/runs/43729422976 ; local
retention: `/workspace/artifacts/fedora-ci-run-43729422976.log`.

This is a concrete runtime integration defect, not an exhausted capability
claim. The coordinator reassessed the earlier source-review repair limit and
authorized one bounded ten-minute path/early-cleanup correction followed by
fresh affected review and a new exact-candidate CI run. The single Sol builder
paused the extension plan for this repair. Preserve unique owned storage,
resource accounting and limited cleanup; no host-wide paths or pruning.

The runtime path correction returned as
`7d130edd94905b81a68ac77c67268fbb9620b522`, integrated as
`7da3087c037e1292a7fc067a5c388f843f911274`. All 140 integrated tests pass.
Fresh Astra-configured High `/root/fedora_ci_path_review` returned scoped PASS
after all 17 affected tests plus independent path/mount boundaries. It confirmed
byte-identical integrated implementation/tests, unique short owned storage and
accounting, and cleanup refusing changed identity, uncertain engine removal,
remaining external containers or mounts. Preflight-only failure now removes its
owned scratch without depending on working engine configuration. No guest/runtime
pass follows from those local tests; publish a second exact-candidate run.

Second actual run `43729968336`, job `132860040954`, source
`d6caa4fd767436c19c915ce49e39e7487a6efd5f`, passed all 140 tests and
actual runner capability checks: Podman4.9.3, 91541061632 free bytes,
16760348672 RAM bytes, Ubuntu24.04.5/image20261111.370.1. The short-path
repair worked and owned-scratch cleanup passed. A subsequent initialization
ordering defect blocked: the version command created the configured tmp directory
before the controller's exclusive mkdir. No image/guest execution occurred.
Logs: https://github.com/oso-gato/dev-pair/actions/runs/43729968336 and
`/workspace/artifacts/fedora-ci-run-43729968336.log`. The coordinator authorized
a five-minute narrow initialization-order repair with a realistic regression,
fresh review and third exact-candidate run. Measured capacity supports later
engineering reassessment of CI sizing; no limits have been silently enlarged.

The ordering correction returned as
`79b1f984e1b3f0883964b904197e1f3e02f994cf`, integrated as
`247b0dbcd28f8ebb3eb95fd3bdc6a565bf042896`. All 142 integrated tests pass.
Fresh Astra-configured High `/root/fedora_ci_init_review` returned narrow PASS
and independently passed all 19 CI tests. Declared paths now initialize before
Podman probes, retaining owner/mode/symlink/device checks and existing cleanup.
Publish the third exact-candidate run to verify the observed real-engine case.

Third actual run `43730306931`, job `132861068210`, source
`b514e8d90c1fd8de875b23fb5cd0cf3b4a6f1a6d`, passed all 142 tests and runner
preflight. It downloaded the actual 583729152-byte Fedora44 Cloud image and
verified the pinned GPG signer, checksum and image SHA256. Tooling construction
reached signed DNF package installation/cleanup, then storage monitoring stopped
on its 65536-byte diagnostic ceiling. The underlying du diagnostic text was not
retained, so ENOENT-only churn is a hypothesis, not an established diagnosis.
Owned cleanup passed. No completed tooling-image identity, payload or Fedora
guest boot is claimed. Runner free disk was 94978641920 bytes and memory
16464302080 bytes; its image20261111.127.1/AWS kernel differs from run2.
Logs: https://github.com/oso-gato/dev-pair/actions/runs/43730306931 and
`/workspace/artifacts/fedora-ci-run-43730306931.log`.

Coordinator authorized a ten-minute evidence-driven storage-diagnostic repair
with fresh review, and at most two more runtime repair/runs in this batch before
reassessing the route. Do not silently ignore large stderr or assume permission/
I/O errors are disappearance. Preserve bounded diagnostic counts/tails, validate
every admitted diagnostic, retain maximum samples, final stable measurement,
resource limits and owned cleanup. Extension implementation remains paused.
The measured runner capacity is sufficient to consider an explicit later
16GiB physical-overlay/32GiB virtual-disk/4GiB overhead profile with unchanged
3GiB host reserve and >=23GiB initial free disk, but this profile is only a
proposal; no current limit changed. Existing 900s assembly/180s runtime bounds
remain fixed, and any longer full-test VM deadline stays inside the 60-minute
workflow with reserved cleanup time.

The bounded diagnostic candidate returned as
`397e38db12d4401a14158c3a5b56930c45042f25`, integrated as
`adff56e5087bd448fb794b1f2af42d6af9ce05c8`. All 146 integrated tests pass.
Fresh Astra-configured High `/root/fedora_ci_diag_review` returned scoped PASS
with 23 affected tests, an actual five-second quiet-child deadline/kill probe
and exact-64KiB simultaneous two-pipe capture. The diagnostic cap, strict owned
ENOENT-only acceptance, resource reserves and final stable traversal remain
unchanged. Root-side GNU timeout bounds privileged scans independently of the
controller; actual privileged behavior remains a hosted check. Bounded counters,
retained-line classes, truncation flags and tails now reach the sanitized report.
This is an evidence-producing candidate, not an assertion of a runtime fix.
A deterministic large-output test uses already-deleted argv operands; it does
not reproduce the production recursive traversal or identify run3's errors.
Publish run4 to collect actual cause, then use at most the one remaining
repair/run in this batch before coordinator reassessment.

Fourth actual run `43731292754`, job `132864071280`, source
`5a966ebdda2ff6d1e807f5998bb4272061630131`, passed all 146 tests, runner
preflight and signed-image verification. Tool construction advanced through its
image build and real RPM-manifest read; a stable overhead sample was 1025351680
bytes. The monitor then captured exit1, zero stdout and this exact 90-byte stderr:
`/usr/bin/du: fts_read failed: /tmp/dpvm-0n1yt9k2/graph/overlay: No such file or directory`.
Unlike the earlier ordinary ENOENT cases, this traversal aborted without a total.
This establishes run4's cause, not run3's discarded oversized diagnostic.
Cleanup passed. No payload or Fedora boot occurred. Logs:
https://github.com/oso-gato/dev-pair/actions/runs/43731292754 and
`/workspace/artifacts/fedora-ci-run-43731292754.log`.

The final ten-minute repair in this runtime batch retries only the captured
owned-path fatal ENOENT, retaining an explicitly absent sample instead of zero.
Three-attempt/capture/resource bounds remain; at least one usable sample is
required for any provisional result and a stable total for phase completion.
Unknown, permission, I/O and foreign-path errors remain immediate blockers.
Fresh review precedes run5. Reassess after that result rather than silently
continuing an unbounded CI repair loop. Independent source work remains possible.

The fatal-traversal correction returned as
`bf1d4a6f5ea72f0c7dac19cabf6eafce0055671b`, integrated as
`a891946e4cd3ec6470b48b82c7635d0725304108`. All 148 integrated tests pass.
Fresh Astra-configured High `/root/fedora_ci_fts_review` returned scoped PASS
after all 25 CI tests plus independent foreign-prefix/traversal/mixed-error/
permission/over-cap checks. Absent totals remain None, all-missing attempts
block, maximum usable totals remain conservative and stable completion is
required. All capture, scan, storage and component bounds are unchanged.
Publish run5 as the final runtime attempt in the current repair batch; inspect
its actual phases and explicitly reassess any further runtime work.

Fifth actual run `43731901140`, job `132865981669`, source
`d79f3a4d9a6c1e3f9e611fcaeb83ca6d5e1e2fd6`, passed all 148 tests, runner
preflight, signed-image verification, tooling construction and source-payload
creation. Tooling image was
`sha256:e498edf5aed83d47cfd0afc04bcf8fe8a13fa35ca6697edc59443ca1ca0b8533`;
actual QEMU10.2.2/RPM identities and hashes were retained. Stable overhead was
1029046272 bytes. The VM booted real Fedora Cloud and shut down under TCG in
approximately 95 seconds; this is actual guest execution, not a fixture.
The controller rejected its completed-result framing as missing/ambiguous.
The bounded 24000-character serial tail starts inside a guest JSON record and
contains preflight/status pass fragments, but cannot establish a complete
candidate-bound result. Do not promote those fragments to accepted phase passes.
Cloud-init output prefixing/interleaving is a hypothesis pending diagnosis.
Cleanup passed. Logs: https://github.com/oso-gato/dev-pair/actions/runs/43731901140
and `/workspace/artifacts/fedora-ci-run-43731901140.log`.

The runtime repair batch is complete. Coordinator reassessment: the route now
proves actual Fedora boot with capacity/time headroom, while structured result
transport remains an implementation blocker. Do not broaden parser acceptance
to partial/arbitrary console text. A separate bounded read-only Astra High
`/root/fedora_ci_serial_diagnosis` examines the transport and public cloud-init
source before any further implementation/run decision.

The single Sol High builder continues an independent 25-minute verified-public-
input helper slice in `/workspace/dev-pair-fedora-inputs`, based on d79f3a4.
Scope: bounded verified Codex/Cosign/Distrobox inputs, exact-source maintenance
context, sanitized public Git objects and compressed transfer with separate
hashes. Workflow, VM limits, guest prepare and production bootstrap integration
are unchanged in this slice. No credentials, model calls or private standards
content enter the payload. Fresh exact-candidate review follows the helper.

Read-only serial diagnosis completed: cloud-init25.3 uses journal+console and
tee output plumbing, so a dedicated bounded second serial channel is preferred
to relaxed matching on mixed console text. The exact rejected prefix is not
recoverable from run5's truncated tail. The source-backed QEMU10.2.2 FIFO plan
is retained at `/workspace/scratch/fedora-ci-serial-plan.md`; no transport code
or additional hosted execution has occurred. Complete the current input helper,
then implement/review this distinct transport correction before another run.

Connected read-only GitHub checks additionally confirm main at
`f2e829b0bcaa1fb5d22cf9b12261a122a607d25c` has `protected=false` and no required
checks in the branch response. Repository rulesets list only two historical tag
rules, not a main-branch release gate. The detailed protection endpoint returned
403 Resource not accessible by integration; that API capability is unavailable.
No settings were changed. This corroborates the previously recorded independent
release-enforcement gap; local subagent reviews and the current workflow do not
establish a separately enforced production gate. Keep draft/unmerged status.

The public-input helper returned two commits, `c7ece54` and
`db27f3a462066d2f560eca571365d9e02a7e5a6f`, integrated locally as a313332
and ce38a54; not published. Builder's 159 tests pass. A real cached-input run
repeated strict Cosign successfully through the supported proxy, then produced
and extracted a payload and passed the unchanged candidate context verifier.
Evidence: `/workspace/artifacts/public-inputs-db27f3a-jcqaoe7x`. The coordinator
read its public receipt/results and independently hashed the final files:
manifest `16d147d868e43e547ec942a9dab3d57416e8160767643d0fd29529aec19e1187`;
payload `8745b41e2f8264ff61ce50137597373d1d06926fdd0dcc6103bb0c6e70f5e274`;
context `148ea8ac35cbb5c2264de333efdb9fa128bd414f073aacfb9a8f9d2c47836834`.
Compressed size121065775 bytes, expanded300075694 bytes/257 files. Git reverse
index support was corrected after actual Git generated a .rev file. Original
signature bundle, verifier output and hash-bound receipt now survive later
packaging failures; the initial failed run's deleted receipt was not recreated.

Fresh Astra High `/root/fedora_public_inputs_review` returned changes required:
P1 manifest hashing and parsing reopen the input and can authenticate different
bytes; P2 FIFO/nonregular admission can block before the extraction deadline.
Both were reproduced. Eleven helper tests passed but did not cover these cases;
a malformed Codex-tar test also stopped before member validation. The Sol builder
owns a twelve-minute consolidated repair: capture regular bounded inputs once,
hash/parse/decompress the same private bytes, put every admission step under the
deadline, and add real replacement/FIFO/device/size/time plus parser tests.
Re-extract the existing trusted payload without repeating unchanged cryptography.
Fresh `/root/public_inputs_snapshot_review` awaits its exact fix. The retained
pre-fix payload is evidence for its recorded source only, not an admitted release
or an assertion that the new consumer boundary already passed. No CI/runtime
change or further hosted execution accompanies this helper yet.


The input-consumer repair is committed as
`62eb1f6fa884c9c902cbb226b9a9751f94858868`, integrated byte-for-byte as
`921654d`. The coordinator independently ran all 163 tests successfully. Both
transfer inputs now use one bounded regular-file capture; manifest parsing and
payload expansion consume the exact hashed capture, under a deadline beginning
before input admission. Tests reproduce replacement races and reject actual
FIFOs/devices, symlinks and oversized files, exercise a real admission timeout,
and reach Codex member validation with explicitly non-production fixtures.

The repaired consumer extracted the retained 257-file payload in 3.531 seconds
and the unchanged candidate verifier passed local context integrity. Evidence:
`/workspace/artifacts/public-inputs-db27f3a-jcqaoe7x/repaired-consumer-62eb1f6-result.json`.
This binds the consumer to 62eb1f6 and the payload to its recorded db27f3a
producer; it does not upgrade either to runtime acceptance. Original signature
receipts remain unchanged; no network cryptography was repeated. Fresh Astra
High review is in progress. Nothing in this checkpoint was pushed or deployed.


Fresh Astra High `/root/public_inputs_snapshot_review` returned PASS on exact
62eb1f6 with no new findings. Independent cross-process replacement tests,
same-inode mutation/growth rejection and a real blocking-first-open deadline
(0.150 seconds) passed, as did all 15 affected tests and retained-payload/context
verification. Evidence: `/workspace/artifacts/public-inputs-review-62eb1f6/review.json`.
This closes both prior consumer findings without changing production identities.

The sole Sol High builder now owns a separate twenty-minute dedicated report-
transport slice from c9a47ef, preserving current VM resource/phase limits and
implementing the source-backed FIFO plan. Fresh reviewer
`/root/fedora_report_transport_review` was accepted by the local agent API with
`gpt-6-astra` / `high`, fresh context. The exact candidate will receive independent
review before one reassessed hosted run; two repair cycles maximum before another
checkpoint. No private policy, credentials, model calls or host deployment enter
this test. API settings are configuration evidence, not backend attestation.


Read-only Astra High `/root/fedora_prepare_integration_design` completed the
next integration design against 8c9a41b; it did not modify source or execute a
hosted test. Handoff: `/workspace/scratch/fedora-prepare-integration-plan.md`.
Use a shared production first-bootstrap entry for real prepare followed by
confined assembly, with distinct durable phase results and exact source/context
binding; a separate CI-only adapter call is insufficient. The guest alone creates
its disposable root0600 test password, and never publishes it. Proposed finite
CI profile: 32GiB virtual disk, 16GiB physical overlay, 4GiB overhead and unchanged
3GiB host reserve, with isolated public provisioning egress and no forwarded
ports, enrollment, model calls or Hostinger route. These values are a design,
not yet implemented or tested. Preserve the adapter's 900s staging and 180s
runtime ceilings and enforce an enclosing whole-phase deadline.

Pinned Distrobox init requests additional Fedora packages absent from the
current staging recipe. The next implementation should resolve and preinstall
that actual signed dependency set, preserving genuine unchanged init and its
verification hooks. Add bounded credential-aware diagnostics to the preparation
path and truthful partial completion/reapply behavior. Actual SELinux/rootless
failures must drive scoped diagnosis; no label-disable, privileged, host-socket
or seccomp-disable fallback is authorized. Complete the report-channel review
and its exact-candidate run before enabling this new test scope.


Dedicated report transport candidate
`6988c1a2aa73ca25801bf21248d3e52112a950ae` was integrated byte-for-byte as
`fd46663`. The coordinator independently passed all 171 tests and whitespace
checks. The eight new tests exercise real FIFO/PTY/process behavior, including
fragmentation, concurrent console output, exact/overflow limits, malformed and
failed results, held writers, validated pipe ownership and bounded terminal
write/drain behavior. No actual QEMU/Fedora result is claimed for this change yet.

The guest writes one bounded raw115200 frame directly to ttyS1 under a 30-second
write/drain deadline; ttyS0 remains diagnostics. QEMU receives an owned0600 FIFO
pair, and the controller drains both streams under existing aggregate bounds,
checks the complete source/script-bound frame and retains byte-preserving bounded
failure evidence. Network, storage, component/native lifetimes and phase scope
are unchanged. Fresh Astra High `/root/fedora_report_transport_review` is reviewing
this exact source before publication; all helper and transport changes remain
local pending that verdict. The builder is reading the next integration design
without editing while review completes.


Fresh transport review found one material P2 before publication: guest main
powered off in a finally block even when the report's final drain failed. The
reviewer reproduced actual main finalization with a real PTY, a complete accepted
678-byte frame, injected tcdrain EIO and an incorrectly invoked normal poweroff.
Since QEMU then exits normally, the controller could accept failed delivery.
All 171 tests and additional framing/aggregate tests passed but missed this path.

The builder has an eight-minute repair scope: permit normal shutdown only after
successful write/drain; propagate failure and retain the existing controller/
native VM timeout as its bound. Add actual PTY/main-finalization regression and
success gating, without a new protocol or changed runtime limits. Fresh Astra
High `/root/fedora_report_shutdown_review` is API-selected and awaits the exact
fix. No hosted run or publication occurred for the defective candidate.


The shutdown-gating fix `12d73c39fd662f116e328da725fe69a5271ededa` is integrated
byte-identically as `3a49fd8`. All 174 integration tests pass. Fresh Astra High
`/root/fedora_report_shutdown_review` returned PASS with no new findings after
36 affected checks and independent real-PTY EIO/drain-timeout/success tests.
The same independent regression fails against the parent candidate, establishing
sensitivity to the actual defect. Evidence:
`/workspace/artifacts/fedora-report-shutdown-review-12d73c3/review.json`.

Coordinator reassessment authorizes one exact-candidate standard public CI run
for this reviewed dedicated transport. The previous five-run diagnostic batch
is closed; this is a distinct corrected transport checkpoint. Existing resource,
network-none and inspection-only phase scope stay unchanged. Require complete
candidate-bound baseline results and cleanup; prepare/assembly remain blocked
until their next reviewed implementation. The source and review results support
publication of the draft branch, not merge, deployment or job admission.


Published reviewed candidate `b8ac722ab8dac31543d0e258c8f5d2552135f1d3`
without merge. [CI run6](https://github.com/oso-gato/dev-pair/actions/runs/43736703953),
job132880789582, is in progress; all 174 CI tests already passed. PR13 remains
draft and its description now distinguishes implemented code, local evidence,
prior actual boot evidence and unresolved delivery requirements.

While that immutable candidate executes, the sole builder starts a separate
25-minute source-only first-bootstrap slice from b8ac722. This overlaps no runtime
mutation and cannot affect run6. Scope: shared initialize/prepare/assembly entry,
exact source/context/upstream validation with signed Git prerequisite, bounded
credential-aware command diagnostics and whole-phase/native cleanup, and pinned
upstream staging dependencies. No CI integration changes yet. Actual report
acceptance and fresh review precede enabling prepare in CI. Fresh API-configured
Astra High `/root/first_bootstrap_review` prepares against the stable baseline;
review begins only at the exact new candidate. In particular, adapter transient
systemd units are outside a parent process group: native remaining deadlines and
owned-unit reconciliation must cover them explicitly. No new privilege, auth,
job, enrollment or cutover scope is granted.


CI run6 completed at b8ac722. All 174 tests, signed Cloud image, tooling, source
payload, real TCG boot, complete dedicated report, Fedora preflight, bootstrap
status and cleanup passed. Guest: Fedora44 kernel6.19.10-300.fc44.x86_64,
SELinux Enforcing, systemd PID1, cgroupv2, cloud_init_t executor and
11590758400 free root bytes. The dedicated frame was 3905 bytes, exactly one
begin/end marker, no overflow, executor exit0, SHA256
`ff4f3a92d27c61fc12175df64221a4521f12eda23c3c42ec94b1f32d79ee6a46`.
Tool image `sha256:ae9a9405eff0fbc52ebdefb1c0763b120962c616e21e0dc41804dae399312418`;
stable non-overlay overhead1029308416 bytes. Complete logs/report are retained
under `/workspace/artifacts/fedora-ci-run-43736703953*`.

Bootstrap inspect genuinely blocked on an unexpected listener; the current report
has no socket inventory, so the exact listener remains unknown. No allowlist or
host-vanilla requirement is relaxed. Prepare and assembly remain intentionally
blocked and were not attempted. This is actual component evidence, not a working
platform or Hostinger acceptance.

Coordinator reassessment permits one narrow diagnostic follow-up: the same Sol
builder temporarily preserves its larger bootstrap WIP and adds bounded `ss -H
-lntup` guest diagnostics in an isolated candidate. Fresh Astra High
`/root/fedora_listener_diagnostic_review` checks it before one inspection-only
CI run. No network, package provisioning, listener admission or resource changes
are included; the exact inventory must precede any listener-policy repair. The
first-bootstrap source slice resumes afterward without a second builder.


Listener-only diagnostic candidate `9aae9d7a188ff82562375b49742878638e391e54`
is integrated byte-identically as `4584059`. Builder's full 175 tests pass;
coordinator and fresh Astra High `/root/fedora_listener_diagnostic_review` each
passed all 37 affected tests. Independent real-process overflow/sanitization and
report roundtrip checks also passed. Review returned PASS with no findings.
The only production-code addition is fixed `/usr/bin/ss -H -lntup` through the
existing 15s/64KiB capture and explicit bounded/truncated diagnostic path.
Publish for the one previously authorized inspection-only run7; do not infer or
admit the unknown listener before its actual evidence returns.


[Run7](https://github.com/oso-gato/dev-pair/actions/runs/43737631539),
job132883635284, completed against `76e7d61b8966f2c25420e66bed84f44f36142b2c`.
All 175 tests and prior successful baseline/report/status/cleanup phases passed.
The bounded socket inventory exited0 without truncation. The rejected listeners
are stock `systemd-resolve` PID767 on TCP/UDP IPv4/IPv6 wildcard port5355 (LLMNR).
Other observed sockets are loopback systemd-resolved DNS53, chronyd323 and sshd22.
Inspection correctly remained blocked; prepare/assembly were not attempted.
Logs/report: `/workspace/artifacts/fedora-ci-run-43737631539*`.

The actual evidence justifies a narrow ordinary first-provisioning correction,
not a security exception: recognize the verified resolved service/process during
initial inspection, persist LLMNR=no and MulticastDNS=no through owned resolved
configuration, verify merged settings and restart, then reject any remaining
discovery listener. Keep unrelated/impostor listeners rejected and ordinary DNS
and bootstrap SSH intact. The current Sol source slice includes this prerequisite
with captured-inventory, service/process mismatch, restart failure and reapply
checks; fresh first-bootstrap review is informed. No blanket port5355 allowance,
CI fixture substitution or admission bypass is authorized. No additional CI run
is started until the next reviewed integration candidate.


Shared first-bootstrap candidate `9c8c597ced106c0c5d34cff102d15a5fa5bc6782`
was integrated byte-identically as `0438afc`. Builder's 184 tests and the
coordinator's 185 integration tests (including the later diagnostic case) pass,
as do compilation/diff checks. Cached exact Distrobox source confirmed all55
staging dependency names; no DNF or init execution was performed locally.
The candidate adds shared initialize, exact target/HEAD checks, bounded secret-
aware commands, durable native-unit recovery, image reuse verification, upstream
staging prerequisites and service-bound persistent resolved discovery disabling.
Source-only until independent review and actual Fedora execution.

Fresh Astra High `/root/first_bootstrap_review` independently passed184 tests and
checked CLI exception forwarding and secret-stdin withholding, but reproduced
two material failures: an exited direct parent causes Commands to skip group/native
cleanup while a surviving child retains pipes; separate Commands instances can
replace/cancel the outer alarm, allowing an inner phase to exceed the declared
total execution deadline. The coordinator and reviewer both reproduced an outer
0.05s/inner0.2s real0.1s sleep returning success. Review is consolidating findings;
the builder awaits the complete repair batch. This candidate is not published,
executed on Fedora or approved. Preserve all existing runtime/security gates.


The first-bootstrap review finalized CHANGES REQUIRED with exactly the two
reproduced deadline/cleanup findings above. Detailed evidence:
`/workspace/artifacts/first-bootstrap-review-9c8c597/review.json`. A twelve-minute
consolidated source repair is assigned; fresh API-configured Astra High
`/root/first_bootstrap_deadline_review` reads governing sources and waits for its
immutable candidate. No further hosted run is authorized for the defective
source. The same candidate's secret withholding, script entry and cross-process
initializer lock checks passed, but do not override the failed execution bounds.


First repair `da3e4e3bb26aeb51ba0b10e3d245d10381f8e98b` is integrated
byte-identically as `68f2e11`; builder187/coordinator188 tests pass. Fresh Astra
High `/root/first_bootstrap_deadline_review` independently passed187 repository
tests and twelve targeted checks. Shared absolute deadline inheritance,
restoration, success-boundary enforcement and generic command cleanup now pass.

The review still requires one P2 repair: ProbeCommands checks a disallowed exit
after its cleanup try block. A parent exiting9 with a descendant that closes its
pipes leaves that descendant alive and skips native reconciliation. Evidence:
`/workspace/artifacts/first-bootstrap-deadline-review-da3e4e3/review.json`.
The second bounded repair cycle is eight minutes, limited to routing this failed
exit through the shared cleanup and preserving real exit diagnostics, with a
real closed-pipe orphan regression. Fresh API-configured Astra High
`/root/first_bootstrap_probe_exit_review` awaits its immutable source. No
publication or hosted execution of either first-bootstrap candidate occurred.


Second repair `8c47d2382d7488ccbcbb22b78cd64bfe470c7496` is integrated
byte-identically as `674954e`. Main's189 tests pass. Fresh Astra High
`/root/first_bootstrap_probe_exit_review` returned PASS with no new findings after
188 repository tests and21 independent process/deadline/cleanup checks. Failed
exit9 now kills the closed-pipe descendant and reconciles owned native units
while preserving its exit status; the same regression fails on the parent.
Foreign-unit protection, allowed exits and prior timing/secret boundaries pass.
Evidence: `/workspace/artifacts/first-bootstrap-probe-exit-review-8c47d23/review.json`.
This completes the two source repair cycles; no native manager/engine acceptance
is inferred from local tests.

The next bounded slice integrates the reviewed path into the actual CI guest:
current-source strict public input production/transport, real shared initialize,
scoped public package egress without listeners/forwarding, guest-only disposable
password, exact phase records/diagnostics and owned cleanup. The proposed resource
profile is32GiB virtual/16GiB physical overlay/4GiB overhead/3GiB host reserve,
with controller3300s split540s public setup +2640s VM +120s outer cleanup/report.
The guest reserves initialize2280s and its45s cleanup grace explicitly. Preserve
native900/180 component limits and no jobs, auth, enrollment or Hostinger access.
Add an in-image fixed dependency-build timeout within the600s image-work budget;
this does not establish complete detached-helper cleanup. Fresh exact-candidate
review precedes hosted execution. No source after76e7d61 has yet been published.


The CI integration builder is active in `/workspace/dev-pair-fedora-prepare`,
branch `codex/fedora-prepare-integration`, from
`8bd3f973e9821ebc71faba656fd3cee1af191698`, with a thirty-minute source budget.
The implementation now wires current-source verified compressed inputs, protected
source/Git objects, shared initialize, target-bound partial evidence and reportv2,
fixed resource/timing bounds and isolated VM provisioning egress. Post-password
arbitrary journal collection is removed; only selected service/RPM/socket fields,
filtered executor AVCs and bounded public-operation tails are proposed. A fixed
in-image dependency-build timeout supplements the reviewed initializer bounds.
Local phase/secret/failure/profile tests are being added; no hosted run, download,
password, enrollment, model call or source publication occurs in this builder.
Fresh API-configured Astra High `/root/fedora_prepare_ci_review` has loaded the
contract and waits for an immutable candidate. The latest published source is
still76e7d61 and the last actual run is7; do not confuse this WIP with runtime
acceptance or a completed platform.


CI preparation integration candidate `d76adbfcc9d3c39bd4d21b7524658c7e9797eaf1`
was integrated byte-identically as `bbd2f47`. Builder198 tests passed33.472s;
coordination198 tests passed31.688s. Fresh API-configured Astra High
`/root/fedora_prepare_ci_review` returned PASS with no material findings after
198 tests32.723s and17 additional identity/phase/duplicate, secret-stdin echo,
quiet/orphan deadline, setup-cleanup and concrete network/profile checks.
Evidence: `/workspace/artifacts/fedora-prepare-ci-review-d76adbf/review.json`.
The separate README status update was also checked. Source/configuration review
is not fresh producer cryptography or native Fedora acceptance.

The next hosted validation batch is limited to one initial preparation run and
at most two evidence-driven repair runs, each after exact-candidate independent
source review. Preserve the existing standard public runner,60-minute job,
3300s controller,540s setup,2640s VM,120s cleanup and fixed disk/memory/CPU/log
bounds. No purchases, uploaded artifacts/caches, private standards, provider
secrets, enrollment, model use or Hostinger route is added. A measured blocker
requires diagnosis; do not retry unchanged inputs indefinitely or relax security,
capacity or acceptance. After the batch, reassess the concrete outcome and
continue independent work where possible. This publication remains a draft
component test, not production promotion; release enforcement remains absent.


Published reviewed integration `f03c6db16c3a3bc6a34a0517c74bdc4e9bf0ba31`
started [run8](https://github.com/oso-gato/dev-pair/actions/runs/43743748166),
job132902382113. Runtime result is pending. The PR remains draft/unmerged, and
its metadata records198 tests plus independent review. Source stays frozen while
this exact candidate executes; do not publish documentation-only commits that
cancel/replace its run. The sole Sol builder performs a bounded read-only next-
slice plan against the nested-placement handoff while awaiting actual diagnostics.


Actual [run8](https://github.com/oso-gato/dev-pair/actions/runs/43743748166),
job132902382113, source `f03c6db16c3a3bc6a34a0517c74bdc4e9bf0ba31`, passed198
tests27.409s, standard runner checks, signed Cloud image, tooling and fresh strict
public Codex verification/packaging. Public setup completed in about55s. Complete
candidate-bound report5455 bytes SHA256
`5b0cb21eed0bb980d51ac3754b269f28ff52d2f116f6237b47fd355c4127af06` passed.
Actual Fedora44 kernel6.19.10-300.fc44.x86_64, Enforcing SELinux, systemd/cgroupv2,
guest input admission, pre/post inspect/status, distinct outer slirp network
namespace/no published ports, password absence and outer cleanup passed.

Shared initialize exited2 after12.103s in prepare; maintenance remained pending.
No packages or image completion evidence exists. One recorded non-public command
returned1 with output withheld, and guest projection omitted its operation/elapsed
metadata. Stock resolved5355 listeners remain, so persistent discovery convergence
was not reached. No selected AVC was reported. The cloud-init BrokenPipe trace is
during shutdown after the guest report, not an established cause of initialization
failure. Exact failed command/cause is not known from this evidence. Do not infer
DNF, privilege or SELinux failure or relax those policies. The builder pauses nested
planning and diagnoses early preparation/native calls; if the source cause is not
provable, add only fixed bounded command/native-result diagnostics. Fresh Astra
High `/root/fedora_prepare_failure_review` awaits that exact candidate. Two hosted
repair attempts remain in the current bounded batch.

Inputs: manifest `a12277de88121709d186111883752698ce17cc37e6b1551656d05397c28178a0`;
payload `25e46d49490c595feedf57bc34ae0d550e9f9e5d49bb4d6cfbfca7ff527a2be6`
121156034bytes; context `d65ef3e90a3d7877e5894c22a28ef16132c4f106f268755da1da1b9f07f58e4b`.
Strict Cosign output was12bytes Verified OK, original output SHA256
`80a53f76c7ed6969dade3b6ee47cdb753162db7c00be625448999d08bae77ed8`; source-bound
receipt and original bundle are retained. Tool image
`sha256:ca05392e6a31f6f03ede3d16e27197ec0472cbce867b44653bcfbd5470cc946e`;
stable overhead1655279616bytes; guest initial/final free33065336832/33024909312bytes.
Runner AWS7.0.0-1014-aws/image20261111.127.1, Podman4.9.3/slirp1.2.1,
initialfree94983139328bytes/RAM16464306176bytes. Evidence:
`/workspace/artifacts/fedora-ci-run-43743748166.log` and sibling `-report.json`.
The VPS remains untouched; no authenticated job or full bootstrap is admitted.


Diagnostic candidate `a742b98158839eb8f10be64d5c966badd069ab0e` is integrated
byte-identically as `ac29f00`. Builder201 tests passed34.584s; coordinator201 tests
passed30.983s. Five files add fixed operation/preparation-step identity,
accepted-versus-rejected exit outcomes, source-verification runner/stage evidence,
bounded native service properties with explicit missing/collected state, and
narrow public enforcement/resolved output. Arbitrary argv, Git output/config,
exceptions, environment, journals and sensitive-stdin output remain withheld.
Allowed exits, execution order, budgets and permissions are unchanged. This is a
diagnostic candidate, not a proved repair of run8's unknown cause. Fresh Astra
High `/root/fedora_prepare_failure_review` is reviewing the exact immutable
candidate; no hosted execution or publication has occurred for it.


Fresh diagnostic review reproduced a budget regression: assigning the source-
verification runner's probe diagnostic callback switches it from Commands'
1048576-byte path to ProbeCommands'4194304-byte path. A real1100000-byte child
is rejected before assignment and accepted afterward. Although201 repository
tests pass, this violates the diagnostic-only no-budget-relaxation boundary.
Candidate a742b98 is not published or executed. Review is consolidating findings;
repair must preserve the original source runner semantics while adding metadata.


The diagnostic review finalized CHANGES REQUIRED with that single P2 dispatch/
capture-budget finding; all201 repository and11 other independent checks passed.
Evidence: `/workspace/artifacts/fedora-prepare-failure-review-a742b98/review.json`.
The sole builder repaired it in `7aa5ebae9f01f6f6d849f6c0285cffb641f6259a`,
integrated byte-identically as `0dd70a5`. A separate Commands metadata hook keeps
ProbeCommands.diagnostic unchanged and preserves original source dispatch,
1048576-byte capture, timeout and cleanup semantics. A real actual-initializer
source_check regression passes32-byte normal output and rejects1100000-byte
output, preserving callbacks and withholding stream content. Builder202 tests
passed35.064s; coordinator202 tests passed32.772s. Fresh API-configured Astra High
`/root/fedora_diagnostic_budget_review` is reviewing the combined exact repair.
No diagnostic candidate has yet been published or executed on Fedora.


Fresh Astra High `/root/fedora_diagnostic_budget_review` returned PASS for exact
`7aa5ebae9f01f6f6d849f6c0285cffb641f6259a`, no material findings. All 202 tests
passed in 32.899s, with 24 independent checks. The actual source_check comparison
reproduced the parent regression and proved repaired Commands dispatch: exactly
1 MiB passes, 1 MiB+1 and 1.1 MB reject. Callback restoration, normal and failed
status, exceptions, timeout, invalid UTF-8, sensitive stdin, orphan cleanup,
native ownership/deadline and guest projection passed. Integration source bytes
match. Evidence: `/workspace/artifacts/fedora-diagnostic-budget-review-7aa5eba/review.json`.
This admits the next bounded diagnostic run only; the original Fedora preparation
cause remains unknown. The run consumes the first of two repair attempts in the
current hosted batch, with all resource/network/secrecy limits unchanged.


Published reviewed diagnostics `c5cef5fb8c2d22d35cc1bb8e945cae4aa1244f9b`.
GitHub confirms that exact open draft PR head, but after several minutes both the
commit workflow query and repository workflow-run collection report no new run.
Run8 remains the latest completed run. No diagnostic execution is yet claimed.
Allow a short bounded event-delivery interval, then if still absent use one
same-candidate PR-reopen trigger (already declared in the unchanged workflow).
Do not rerun old-source run8 or push speculative source changes to fabricate a
new result. Record actual executor identity once a new run exists.


[Run9](https://github.com/oso-gato/dev-pair/actions/runs/43746428844) subsequently
appeared for exact `c5cef5fb8c2d22d35cc1bb8e945cae4aa1244f9b` and is running.
No PR close/reopen or other retrigger was performed. This is the first diagnostic
repair run in the bounded batch; outcome remains pending. Source stays frozen.


Actual [run9](https://github.com/oso-gato/dev-pair/actions/runs/43746428844),
job132910632631, source `c5cef5fb8c2d22d35cc1bb8e945cae4aa1244f9b`, passed all
202 tests in 27.424s. Fresh strict public verification, exact guest inputs, TCG
boot, Enforcing/systemd/cgroup v2, pre/post inspection/status, isolated outer
network, password absence and outer cleanup passed. Initialization stopped after
11.905s in host-preflight, before source verification or package/assembly phases.

The first wrapped getenforce was rejected with exit1; its exact public stderr was
`Failed to start transient service unit: Connection reset by peer`. Native unit
metadata was explicitly unavailable after collection/no start. The matching AVC
shows dbus-broker in system_dbusd_t denied write to a fifo_file labelled
cloud_init_t, permissive=0. This distinguishes the observed executor/FD routing
blocker from failed SELinux enforcement; direct getenforce/inspection succeeds.
No policy relaxation or general dbus FIFO permission is justified.

The sole Sol builder has a twenty-minute source slice for a proper native CI
provisioning executor: cloud-init stages protected exact-target inputs and a
fixed owned Type=exec service, then starts it nonblocking with null standard
streams. The service uses the normal Fedora service transition and standard file
contexts, not SELinuxContext/runcon, explicit unconfined labels, policy modules,
booleans or permissive mode. It executes the same guest/initialize code and binds
actual MainPID/cgroup/root/context plus unit/script/controller/input identities.
Native lifetime/stop remain inside the existing VM and final report envelope.
Dedicated ttyS1 is the result channel; no arbitrary journal export or inherited
pipe FDs. Root provisioning is the existing authorized executor, not agent/job
admission; container profiles remain unchanged. Fresh Astra High
`/root/fedora_native_executor_review` awaits an immutable candidate. One final
hosted repair run remains before batch reassessment.

Run9 manifest `7395da7d8175af7eb5889da809084bea1f881ab5edaa4fad8f9d80d1bb24b6a4`;
payload `6af993b0bdd5fc1ce0a7273b0ab4498d47e9a5d999187bcf628d2613f2f54351`
121166827bytes; context `9f2decfbde9171afe1aaf5ed840093fb831377eb966c6c30050d5b93076f5e32`.
Complete report6599bytes SHA256
`b8cc95bc667669de295e9772d7ce3ed5cd64653c6636c53ec51e9244431b14ac`;
stable overhead1655304192bytes; tool image
`sha256:3920a0801d7aaabe86f66945d60009303bf55e466c9955502743097f2dbf37ed`.
Evidence: `/workspace/artifacts/fedora-ci-run-43746428844.log` and sibling
`-report.json`. Runner AWS7.0.0-1014-aws/image20261111.127.1, Podman4.9.3,
initialfree94983086080bytes/RAM16464306176bytes. No VPS or production mutation.


Native executor builder is active in `/workspace/dev-pair-fedora-native`, branch
`codex/fedora-native-executor`, from `6cf2bdd`. Source/test changes are in progress;
no candidate is yet admitted. The agreed design stages protected fixed inputs,
uses standard restorecon contexts, sends no cloud-init standard-stream FDs into
the service, and verifies actual root/MainPID/cgroup/context plus independently
bound unit/script/controller/input identities. Avoid circular unit/manifest
hashes and cloud-final self-waits. A bounded selected-property startup observation
should distinguish a queued request from actual execution without journal export.
Fresh `/root/fedora_native_executor_review` has the governing sources and run9 AVC;
review begins only after an immutable candidate. No policy or confinement change,
new hosted run, VPS access or production deployment has occurred in this slice.


Native executor candidate `9ca8641f3c276b5cd66c6bef24d2f1cbbad48936` is
integrated byte-identically as `ee1589a`. Builder211 tests passed34.267s;
coordinator211 tests passed31.788s. Nine focused tests cover real null-FD/clean-
environment children, protected files, failed startup without a passing frame,
target mismatch, effective profile/drop-ins and captured SELinux NUL terminators.
Reportv3 requires the actual native executor before accepting any passed guest
phase. Native runtime2445s plus stop5s and shared admission60s preserve the VM
bound. The service has no cloud-final wait and forwards no cloud-init pipe FDs.

Fresh Astra High `/root/fedora_native_executor_review` independently passed211
tests31.326s and has no material finding so far; review is not yet final. Unknown
global service drop-ins intentionally block and selected failure-witness fields
retain their paths; their presence/content on this exact Fedora guest is not yet
known. Do not assume remembered vendor defaults or blanket-allow them. Actual
unit loading/default SELinux transition/effective configuration and subsequent
preparation remain runtime gates. Local systemd-analyze verification was blocked
by /run/systemd permissions and is not claimed. No new source is published yet.


Fresh Astra High `/root/fedora_native_executor_review` returned PASS for exact
`9ca8641f3c276b5cd66c6bef24d2f1cbbad48936`, with no material findings. All 211
repository tests passed in 31.326s and 77 independent checks passed: actual local
process/FD boundaries, identity/ownership, start ordering/failures, deadlines and
report admission. Evidence:
`/workspace/artifacts/fedora-native-executor-review-9ca8641/review.json`.
Review permits the final bounded repair run in this hosted batch; native Fedora
transition/profile and preparation remain pending. No unknown global drop-in,
policy exception or confinement relaxation is accepted by this verdict. After
the actual result, close/reassess the batch against the concrete blocker or
passing evidence and continue independent authorized work where possible.


### November 16, 2026, 02:57 HKT — native staging failure and batch closure

Published reviewed source `e5e95bba9798433833c8121e4a9c072c8afa58eb` ran
[Fedora run10](https://github.com/oso-gato/dev-pair/actions/runs/43749265408),
job132919348236. All211 tests passed26.835s. Signed Cloud-image verification,
fresh strict public-input verification, tooling, observed isolated networking and
outer cleanup passed. The guest booted but native executor staging failed before
selected service properties were available. The failure-only console witness
reported native-executor-staging/blocked and availability=unavailable; the
controller's console-tail truncation cut off its beginning. Dedicated report
contained zero bytes, so no guest phase is accepted. Executor exit0 is not a pass.
The later cloud-init BrokenPipe accompanies shutdown and does not establish the
staging cause. No package preparation or maintenance assembly is established.

This closes the three-run preparation batch (runs8–10). It resolved run8's
missing command identity and diagnosed run9's cloud-init pipe denial, but the
new native executor has not passed staging. There is no evidence yet identifying
a vendor drop-in, missing executable, path ownership or SELinux cause for run10.
No unchanged retry is authorized. Sole Sol High builder `/root/durable_job_build`
is performing a bounded15-minute source/local diagnosis and narrow fixed-operation
diagnostics repair before a fresh independent review and explicit run reassessment.
Resource, security and credential boundaries remain unchanged; VPS untouched.

Run10 input manifest `5e770a077350117dbd0bb64107f7220bc24e7b6c479b9c5b84e61cc9eed0ef81`;
payload `57a35ecc0272667706de4a5c6c17744f181762c32132a0cb785e5235fbb0b3d7`,121187164bytes;
context `3f88993ac379462d05b760ca3fb9516feda4aa96baec4f2d7b4793e072951627`;
guest `95f089f6e57b460c30ace6c66fa17f48d025335bde8b42ee188f4703f9345490`.
Evidence: `/workspace/artifacts/fedora-ci-run-43749265408.log` and sibling
`-controller.json`. Stable tooling overhead1655398400bytes. No valid guest report.

Independent Astra High `/root/codex_offline_state_probe` is also testing the
stock Codex state/config boundary offline in scratch, without product edits,
credentials, login or model calls. Its15-minute/2GiB scope does not overlap the
sole builder. The API accepted the requested model/effort; backend attestation
and coordinator actual model metadata remain unavailable.


### November16, 2026, 03:03 HKT — supported local Docker capability

Cloud runtime skill guidance led to an explicit managed socket check.
`/var/run/docker.sock` resolves to `/run/codex-docker/docker.sock` and the task
user can access it. Clearing only Docker host/context/TLS endpoint overrides,
`docker --host=unix:///var/run/docker.sock info` reports29.9.2, rootless, builtin
seccomp and cgroupns,18882662400bytes RAM and5CPUs. This corrects the broader
earlier inference that missing local Podman/QEMU/sudo implies no local VM path.
No supported local Fedora execution has yet been demonstrated; the existing
Podman runner needs an explicitly verified Docker adaptation or test harness.

Fresh Astra High `/root/local_fedora_executor_feasibility` has a10-minute
read-only/source/capability scope to assess that path without product edits,
image pull/build or VM execution. Preserve signed inputs, exact source binding,
network/CPU/memory/disk/time boundaries and no container privilege exceptions.
The supported managed Docker endpoint is distinct from forbidden workload access
to a host engine socket. No socket will enter the Fedora guest or product.
Current managed status is the same instance/spec1, network unrestricted/enforced,
credential reference hostinger_root ready. This does not establish a supported
public SSH route or change the observed VPS connectivity limitation.


The local Docker feasibility check is complete: CgroupDriver=none prevents
claiming the existing aggregate CPU/memory/PID ceilings. Daemon UID2000 versus
task UID1000 also prevents copying protected bind/FIFO assumptions; shared vfs
storage needs different accounting and owned cleanup. Image/container/volume
cache is empty. No pull/build/run occurred. Evidence:
`/workspace/artifacts/local-fedora-executor-feasibility/feasibility.json`.
Continue with the existing bounded hosted executor for Fedora acceptance; local
Docker availability alone is not an equivalent replacement.


### November16, 2026, 03:08 HKT — reviewed staging diagnostic run

Sole Sol High candidate `3913dd69eb84cd2ed22593a0d21ea580dd965599` is
integrated byte-identically for tools/tests/CI documentation as `f225652`.
Builder220tests passed32.855s, coordinator220passed33.157s. It fixes two
reproduced diagnostic losses: generic staging failures and startup-witness loss
from console-tail truncation. Fixed staging step, numeric errno/exit/timeout,
UID and rejected-parent metadata identify the operation. Only exact pre-credential
restorecon/reload/start operations retain bounded public stderr through an owned
anonymous regular file,4096-byte native ceiling,768-character tail and byte/hash
metadata. Other commands still discard streams. Strict failure-only witness
extraction preserves exact bytes/hash before truncation and can never satisfy
dedicated report or guest-phase admission. No Fedora root cause is asserted.

Fresh Astra High `/root/native_staging_diagnostic_review` returned PASS with
limits for exact3913dd69:220tests33.349s,52 independent process/parser checks,
15 unchanged AST/file boundaries, no material findings.
Evidence: `/workspace/artifacts/native-staging-diagnostic-review-3913dd69eb84cd2ed22593a0d21ea580dd965599/review.json`.
Initializer, execution dispatch, unit/profile, report gates, workflow, QEMU and
resource/security bounds remain unchanged. Under existing test authority,
coordinator reassessment admits exactly one new diagnostic-only hosted run to
resolve run10's fixed failing operation. No unchanged retries; reassess its
measured result before more hosted execution. Source remains frozen during run.
This is separate from the closed runs8–10 preparation batch and is not production
or VPS authorization.

Offline stock Codex evidence is now durable in
`/workspace/artifacts/codex-offline-state-probe/REPORT.txt`, SHA256
`e82fbad4cf8b88ec8fe6690214ade49f33bfdec1ff1d928aea157f61ef22454c`.
Actual no-network app-server tests confirm untrusted-source skills discovery,
fixed-cwd exclusion, required assembly seeding of bundled skills, managed feature/
path behavior, separate SQLite lifecycle and session-index symlink replacement.
Strict-config alone accepts unknown requirement keys. Same-owner bubblewrap
fixtures cannot prove distinct root/job sticky ownership; direct binary
reinvocation remains a loader-boundary design issue. No authentication, model
call, true session resume or Fedora placement is claimed. Artifact1.4MiB,116files.


### November16, 2026, 03:13 HKT — measured daemon-reload timeout

[Run11](https://github.com/oso-gato/dev-pair/actions/runs/43750769082), job132923988447,
published7284e77, passed220tests32.832s, signed/fresh public inputs, isolated
networking and outer cleanup. The diagnostic goal succeeded: complete validated
failure witness766bytes SHA256
`df13ad6c983d4101e213d246590226716c2b4ef5b2e31ff111608d2e9e6b6732` identifies
reload-manager timeout after5235ms, UID/EUID0, zero stderr. Script/request/unit
installation and restorecon therefore completed; native service start was not
reached. Dedicated report remained zero bytes and no guest-phase pass is accepted.
Evidence: `/workspace/artifacts/fedora-ci-run-43750769082.log` and sibling
`-controller.json`. This closes the one-run diagnostic scope.

Measured failure justifies reallocating the fixed daemon-reload operation from
5seconds to at most30seconds, still clipped to the original shared60-second
admission deadline. All other caps, totalVM/service/resource budgets and security
settings remain fixed. Sole Sol builder has a10-minute source/test slice from
7284e77; fresh Astra High `/root/native_reload_budget_review` independently reviews
its immutable result before one bounded hosted retest. A timed-out manager call
does not prove a policy failure or guarantee30seconds will suffice. No policy
change or unbounded retry is authorized.

Additional offline stock Codex evidence identifies a minimal child boundary:
managed restrictive read grants, explicit product writes, disabled networking
and cleared child environment denied synthetic credential/supervisor-state reads
while allowing product writes. Symlink/proc aliases failed. Even direct child
Codex reinvocation requesting danger-full-access inherited the existing denial.
Use exact measured profile rather than blanket CODEX_HOME denial, which conflicts
with the stock helper directory. Actual agent tool-path wiring and Fedora/
Distrobox execution remain unverified. No model/auth/network calls. Evidence:
`/workspace/artifacts/codex-offline-child-boundary/REPORT.txt` and hash manifest.


Reload allocation candidate `39285a1ffa352e48414397d3a6f5f89328a87d31`
is integrated byte-identically as8951e44. Builder221tests33.336s, coordinator
221tests32.703s passed. Fresh Astra High `/root/native_reload_budget_review`
returned PASS with no findings:221tests33.331s and independent sequential real-
child deadline/cleanup checks. After one command consumed most of the shared
end, the next received only43.48ms and timed out; an expired third launched no
child. Exact argv alone gets30seconds; other control caps remain5seconds.
Evidence: `/workspace/artifacts/native-reload-budget-review-39285a1ffa352e48414397d3a6f5f89328a87d31/review.json`.

One bounded Fedora retest is admitted for this measured timeout repair under the
existing executor envelope. It must verify actual reload, subsequent native
service admission and remaining preparation; a new blocker is returned for
diagnosis rather than weakening any gate. No production or VPS action.


### November16, 2026, 03:22 HKT — native service active; vendor drop-in gate

[Run12](https://github.com/oso-gato/dev-pair/actions/runs/43751625705), job132926640810,
source88b3a6b, passed221tests37.840s, fresh verified inputs, networking and cleanup.
Reload and service start succeeded; selected observation after4659ms showed
MainPID1200, active/root, exact fragment, null streams,2445s runtime and5s stop.
Admission rejected the actual global drop-in
`/usr/lib/systemd/system/service.d/10-timeout-abort.conf`. File content was not
captured. Complete validated failure witness1086bytes SHA256
`dc5c9497066d045c99291bc995b6bef5a743ade630d3fa145f9d39f78f3f6fae`;
no dedicated report, native SELinux context or guest phase is accepted. Evidence:
`/workspace/artifacts/fedora-ci-run-43751625705.log` and sibling-controller.json.
The one-run reload retest is closed with a new measured configuration gate.

Read-only Astra architecture investigation confirmed upstream systemd v259
per-unit same-basename shadowing, including that an empty regular file REMAINS
in DropInPaths. Sources: systemd.unit.xml241–250,shared/dropin.c256–290,
basic/conf-files.c246–255/321–329,core/load-dropin.c128–146 and dbus-unit.c942.
This is source feasibility, not exact Fedora installed-byte proof.

The sole builder has a15-minute repair slice: root-owned0644exclusive empty
`/etc/systemd/system/dev-pair-ci-provision.service.d/10-timeout-abort.conf`,
protected parents, standard restorecon and native admission verification.
Require precisely this controlled path as the only drop-in; reject any other.
No unknown vendor content is accepted and no global file is changed. Declare
TimeoutStopFailureMode=kill,SendSIGKILL=yes,FinalKillSignal=SIGKILL and verify
effective kill/yes/9 to avoid abort/core-dump stop extension. All total budgets,
SELinux and container confinement remain fixed. Fresh Astra High
`/root/native_unit_mask_review` reviews the immutable candidate before a bounded
retest. Recheck4096-byte witness after adding properties.

The independent state harness WIP is parked as local incomplete commit
`efe838ada27d068242840101f9739260f82a7604` in
`/workspace/dev-pair-codex-state`, branchcodex/offline-state-policy. It is not
integrated, published or admitted. One actual no-network stock-binary run
passed seven offline checks; report `/workspace/artifacts/codex-state-first-local.json`,
SHA256`27d93d8266ef7109a8ebff144e626adb50429193c0e1ff1eab08588812c6da7a`.
Strict layout/requirements validation, unit mutation/bound checks, documentation
and review remain unfinished. Resume after the measured native blocker repair.


Scoped unit candidate `8fa968348869b66410c65ca4418eb92cd8dea33e` is
integrated byte-identically asad55ac9. Builder224tests36.082s and coordinator
224tests31.779s passed. Requestv2/reportv4 bind the empty mask's path,device,inode
and SHA; native admission reopens and checks protected ownership,0644,zero bytes,
singlelink and original identity before accepting any phase. The only permitted
DropInPaths is the controlled file. Effective stop fields must be kill/yes/9.
Per-key diagnostic caps preserve its complete73-byte path within the unchanged
4096-byte worst-case witness bound. Native2445s,stop5s,admission60s,VM2640s unchanged.

Fresh Astra High `/root/native_unit_mask_review` returned PASS for exact8fa9683,
scoped to one bounded Fedora retest:56 affected tests passed10.664s, source/diff
review found no blocking issue. Evidence:
`/workspace/artifacts/native-unit-mask-review-8fa968348869b66410c65ca4418eb92cd8dea33e/review.json`.
The coordinator admits that single unchanged-envelope test; actual Fedora
shadowing, effective kill values, native identity and preparation remain gates.
No source publication grants job, authentication, model or VPS admission.
The sole builder has resumed the isolated offline-state WIP; it cannot change
the frozen native test source or publish without its own review.


### November16, 2026, 03:35 HKT — native admission passes; command transport blocked

[Run13](https://github.com/oso-gato/dev-pair/actions/runs/43752925913), job132930653097,
source39cc4bc, passed224tests30.648s and actual native executor admission.
The protected mask, effective kill profile, root/MainPID1194/cgroup and default
SELinux transition to unconfined_service_t were verified. This is the authorized
root provisioning executor, not an agent/container relaxation. Enforcing Fedora,
authenticated inputs, pre/post inspection/status, password absence and outer
cleanup passed. Complete reportv4 frame7410bytes SHA256
`adea5fce4dcd2b6bec08f3a7e408fed3223b205ee2effce39a8cda18d3295900`.

Initialization still stopped after10.224s at first transient getenforce, with
connection-reset-by-peer from systemd-run. The native handoff alone did not
resolve command execution. The selected AVC filter retained0lines and omitted1;
it currently requires a known comm field, so the omitted record cannot be
interpreted. Recurrence of the error does not independently prove the exact
run9 denial. No packages, discovery convergence or assembly are accepted.
Evidence: `/workspace/artifacts/fedora-ci-run-43752925913.log`,
`-controller.json` and `-report.json`. The scoped mask retest is closed.

Fresh Astra High `/root/native_command_io_design` is doing bounded read-only
diagnosis/design. A documented candidate is manager-opened private FIFO paths
for stdout/stderr, avoiding systemd-run --pipe FD transfer over D-Bus while
preserving1MiB combined capture and native cgroup/deadline cleanup. Sensitive
stdin would need a separately protected bounded ephemeral file and exact crash/
retry ownership cleanup. Blanket LimitFSIZE is unsuitable: it also limits dnf/
image files, not only output. Structured AVC security-field projection can retain
USER_AVC diagnostics without arbitrary path/proctitle/argv/private payload.
No implementation or new hosted run is admitted yet; no SELinux exception.
The sole Sol builder is finishing the independent offline-state component.


Offline state candidate `112ec05bcd5d9c382fca58065b454c4f2bd9d972`
is integrated locally as942b2f2 but NOT published/admitted. Builder231tests and
coordinator combined234tests32.724s passed. Its real stock-binary run passed9
checks; report `/workspace/artifacts/codex-state-acceptance-local.json`, SHA256
`6cb985b1f36b426bda0784148792d39a158b5ced9cc0a49e7073b44d089186a4`.
Fresh Astra High `/root/codex_state_component_review` independently passed10
focused tests and all9stock checks but returned CHANGES: P2 cleanup exception
after those checks can leave status=pass/exit0. Evidence:
`/workspace/artifacts/codex-state-component-review-112ec05/review.json`, SHA256
`ab12d4f5ffa83309948dc7bc7cdf4cf0a7ffabdfeef56bfc468caa3fdf882c4a`.
The sole builder is applying a bounded narrow fix/regression before continuing
native command I/O. Fresh `/root/codex_state_cleanup_review` will independently
review the immutable repair. Successful behavior checks do not override this
failure-reporting defect or the component's runtime_admitted=false gates.

Native command transport design is complete at
`/workspace/scratch/native-command-io-design.md`. Systemd259 file: explicitly
supports FIFOs; using manager-opened private FIFO paths removes D-Bus descriptor
transfer while preserving nonseekable bounded output. Actual SELinux path access
remains unverified. IO ownership must be persisted before secret/launch, with
collision preservation and scoped crash reconciliation; Python finally cannot
claim SIGKILL cleanup. No new hosted run or global policy change is admitted yet.


### November16, 2026, 03:49 HKT — offline component reviewed and checkpointed

State repair `9e57e37aa1fb83b33b8506baddc0571c19c9e0c1` is integrated
byte-identically as03bff83. Builder232tests33.526s; coordinator combined235tests
35.809s passed. Fresh Astra High `/root/codex_state_cleanup_review` returned PASS:
11focused tests, actualstock9check success, and injected cleanup failure after
real fixture removal now returns2/blocked while preserving9passedchecks. The
review independently reproduced old112ec05 returning0/pass under the same fault.
Evidence: `/workspace/artifacts/codex-state-cleanup-review-9e57e37/review.json`, SHA256
`a65dff2617bcfe3e9f4f149981d661ccc3f6b791dd5856f425f84bd2bb7e766d`.

The offline component remains runtime_admitted=false: it is not gptbox launch,
authentication, complete tool-path enforcement, Fedora ownership/nesting or
session renewal acceptance. Real generated policy/layout/skills identities and
stock behavioral checks are reusable source capability. Sampled state storage
limits are explicitly not hard quotas.

This reviewed main-worktree checkpoint is published to the supplemental branch
`codex/dr10-reviewed-checkpoint`, with no separate PR, workflow trigger or release.
The sole workflow triggers pull_request only. PR13 stays on its last tested39cc4bc
while native Commands I/O is repaired in an isolated branch; pushing unrelated
state work to that PR now would rerun the known unchanged Fedora failure. The
next reviewed combined candidate returns to the requested PR branch.
Native I/O builder has a30-minute source/test slice from39cc4bc; fresh independent
`/root/native_command_io_review` is prepared. No new hosted run yet.

### November 16, 2026, 04:20 HKT — native stream candidate under review

Sol High candidate `ce3ecb76546debf98172a57642bfcdcf84a8c3da` is integrated
locally as `d69ad5d`, after the reviewed offline-state checkpoint. The builder's
242 tests passed in 35.983 seconds; the combined 253 tests passed in 37.212
seconds. The transport covers ordinary root commands, explicit dp-maint
commands, diagnostic probes and guest image observation. Separate capture
ceilings remain 1 MiB, 4 MiB and 256 KiB respectively. Private manager-opened
FIFOs replace D-Bus stdio descriptor forwarding; ownership records precede
sensitive input and launch. No SELinux policy exception or resource-budget
increase is included. Actual Fedora execution is still unverified.

Fresh Astra High review found a likely retry defect: explicit gptbox native
units enter the initializer's durable list, but its retry parser accepts only
initializer unit names. The sole builder is repairing this with a regression;
the immutable candidate remains under review and is not published to PR13.
No further hosted run is admitted until the repair and independent review pass.
Model and effort selections are verified at the agent API boundary only;
backend attestation and coordinator model metadata remain unavailable.

Read-only source research at
`/workspace/scratch/nested-profile-source-research.md` identifies a plausible
confined nested engine profile. Narrow mapping helpers need SETUID/SETGID
acquisition, while the inner agent retains zero capabilities and NNP1. Upstream
container_engine_t is MCS constrained, but the examined source does not establish
its required child transition. Installed Fedora policy and runtime versions must
be inspected before admitting a concrete profile; a narrowly scoped dedicated
domain remains an engineering possibility, not an accepted policy change. No
unavoidable owner exception was established. Native nesting, storage enforcement,
authentication, renewal and delivery acceptance remain outstanding.

### November 16, 2026, 04:26 HKT — reviewed transport and one Fedora retest

The original transport review returned CHANGES REQUIRED for NIO-1 only, with
242 independently passing tests. Evidence:
`/workspace/artifacts/native-command-io-review-ce3ecb7/review.json`, SHA256
`0fe957b7f97f34d21a294f8e3e072e3293cb299a8e41dc7df4a66e969a275352`.
Sol High repair `3fdaedb03f4db93f7ebca67379e0f07971b981cc` is integrated
byte-identically as `5fce36f`. Only Commands-created root wrappers enter the
initializer inventory. Explicit dp-maint transports retain protected journals
and existing exact-context, UID-bound recovery; no grammar or user check widens.
The builder passed 243 tests in 39.620 seconds; combined integration passed
254 tests in 38.210 seconds.

Fresh Astra High `/root/native_io_retry_review` returned PASS for that exact
repair, independently passing 243 tests in 41.260 seconds. Its real FIFO checks
cover interrupted integrated retry, actual SIGKILL after persisted sensitive
input but before launch for both root and dp-maint, recovery before new payload
execution, wrong-user rejection and foreign replacement preservation. Evidence:
`/workspace/artifacts/native-io-retry-review-3fdaedb03f4db93f7ebca67379e0f07971b981cc/review.json`,
SHA256 `02dc1848af4e35b7f3d363b63ba1a6ebf54f0b5675f825df747c5ab364d3eab2`.
This admits a bounded Fedora test, not production or native-runtime acceptance.

Publish the combined reviewed offline-state and transport work to the requested
PR13 branch. One changed-candidate Fedora retest is admitted under the existing
60-minute hosted job / 3300-second controller envelope (setup 540, VM 2640,
cleanup 120 seconds), guest 6 GiB/2 CPUs/32 GiB virtual disk and outer
8 GiB/3 CPUs/1024 PIDs. Existing 16 GiB overlay, 4 GiB overhead, 3 GiB host
reserve, 8 GiB guest reserve and output/report ceilings remain unchanged. The
test must establish actual manager-opened command behavior, protected recovery
and the existing preparation/assembly checks, returning exact diagnostics on
failure. No unchanged retry, policy relaxation, secret/model use, VPS mutation,
release promotion or added execution budget follows from this admission.

### November 16, 2026, 04:33 HKT — Fedora run 14 identified FIFO label denial

Published source `8bdd19d050dc2fe6012b19052f2af538b77d5705` produced
[run 14](https://github.com/oso-gato/dev-pair/actions/runs/43758085093), job
132946493509. All 254 tests passed in 41.125 seconds. Real native service
admission, Enforcing Fedora 44, authenticated inputs, pre/post inspection,
original password-file absence, complete report framing and outer cleanup passed.
The 7882-byte frame has SHA256
`b7e4b98c18c93e9bbcd9c0e90d9f6e60dcd1d00b17f04de7249ca41573a90512`.

Initialization blocked after 16.811 seconds at its first getenforce command,
with native status 209 and zero output. Structural audit projection retained
the actual denial: init_t writing fifo_file labeled var_run_t, permissive=0.
This is a concrete manager-opened FIFO labeling failure; the transport does not
yet pass Fedora. A second same-boot setfiles_t/file/var_lib_t denial was retained
without claiming it caused this command failure. RPM inventory timed out within
the diagnostic budget. Root filesystem observation is btrfs with no selected
quota flags; this does not establish quota support or enforcement.

No package preparation, image assembly or container runtime is admitted.
Artifacts: `/workspace/artifacts/fedora-ci-run-43758085093.log`,
`-controller.json`, `-report.json` and `-request.json`. The one-run retest scope
is closed. Bounded Astra High source diagnosis now checks the correct supported
manager runtime labeling path; no unchanged retry, policy bypass or SELinux-mode
change is authorized by this failure. The sole Sol builder is preparing a small
independent read-only storage measurement/admission component while diagnosis
proceeds. Hard filesystem enforcement and cleanup remain separate future gates.

### November 16, 2026, 04:49 HKT — storage source reviewed and checkpointed

Sol High storage candidate `2944ac650e9708459b7da0c6c3e4e3d1b4860a22`
adds bounded read-only inventory and pure peak-capacity arithmetic. Fresh Astra
review found one P2: unreserved existing growth was not constrained to its full
declared existing maximum. Review evidence:
`/workspace/artifacts/storage-admission-review-2944ac6/review.json`, SHA256
`277e05222c64c8e5da009b979279f14a774db749a1ad1f18d21cac09e704a8aa`.
Repair `63ed9032fa8e22c882282f127bb654b338624948` rejects contradictory
inputs and clarifies full-maximum semantics without double-charging materialized
capacity. These commits are integrated as `af46ad2` and `e012be1`; all source and
test bytes match the reviewed repair (other differences are documentation).

Fresh Astra High `/root/storage_capacity_fix_review` returned PASS, with
265 tests in 41.486 seconds, 38 independent named checks and 2000 valid-input
differential cases. The valid existing-20-GiB / remainder-1-GiB case retains
20 GiB managed maximum and charges only 1 GiB additional guest growth. Unknown
capacity differs from measured zero availability and remains blocked. Evidence:
`/workspace/artifacts/storage-capacity-fix-review-63ed9032fa8e22c882282f127bb654b338624948/review.json`,
SHA256 `3de717bd7b6461baa72306215766c1c6c8ab996a3faa8ae7f0d1043610f2c1c3`.
The actual local read-only sample is
`/workspace/artifacts/storage-observation-local.json`, SHA256
`64c7358ef5ca41156fca106680e81ae257407fd339f4830f1e9b98b319628c10`.

This is source capability only: no allocation, quota, mount, cleanup action,
reservation or job admission. Preserve the reviewed combined checkpoint on
`codex/dr10-reviewed-checkpoint`; PR13 remains on tested `8bdd19d` until the
next reviewed native correction, avoiding another unchanged Fedora failure.

The source-backed native correction design is
`/workspace/scratch/native-fifo-label-design.md`: manager-only stream objects
use the stock verified manager runtime type; an immutable in-unit relay gives
transitioned commands ordinary anonymous pipes. Journal records stay outside
the manager namespace. A path move alone is insufficient for passwd/chronyc
domains. The relay must prove completion through bounded child-stderr framing,
because a numerical exit alone could mistake failed startup for an accepted
nonzero payload result. No policy grants or forced process labels are proposed.
The sole Sol builder works from `8bdd19d` in a separate native-relay worktree;
fresh Astra High review is prepared. No new Fedora run is admitted yet.

### November 16, 2026, 05:12 HKT — relay source reviewed; deadline repair required

Sol High relay candidate `da2ebf5834fa9ae266f81fe434517eac1a3db7ec`
is integrated locally as `b88d6f1`; it is not published or admitted. Builder
269 tests passed in 42.864 seconds; combined storage/relay integration passed
280 tests in 42.445 seconds. Helper identity is SHA256
`993ad277ec4458c57c745c8f02ea6ec5dfbe83acb2ea0382cd430a2ba4f04b33`.
Fresh Astra High review independently passed 269 tests and five adversarial
stream checks, but returned CHANGES REQUIRED with two P2 findings:

- NR-1: manager FIFO opening can block before helper exec. Type=exec startup is
  not covered by RuntimeMaxSec. Set a finite remaining-budget startup timeout;
  pass the original absolute deadline to the helper so startup cannot renew it.
- NR-2: systemd-run returns 255 for signal failures and can return 0 for clean
  signal stops. The helper protocol must handle that mapping while independently
  rejecting unaccepted payload signals; accepting launcher zero alone is unsafe.

Review: `/workspace/artifacts/native-relay-review-da2ebf5/review.json`, SHA256
`e0b9e30bfde154544c06449298a4bd921b66948e798c0eb9b7f7fe8aeac196f0`.
Exact upstream v259 service/timer/exit-status sources are cached under
`/workspace/scratch/systemd-v259-start-timers`; these are source evidence, not
Fedora vendor-binary acceptance. The sole builder is making a narrow repair;
fresh `/root/native_relay_deadline_review` is prepared. No new hosted run,
policy change or deployment is admitted by the local test pass.

### November 16, 2026, 05:46 HKT — narrow repair passed; transient profile in progress

Sol High repair `afac2969e638e9c870010490267bb537f57cd323`, integrated as
`9a97b81`, bounds startup within the original command deadline and independently
rejects signaled payloads despite systemd-run's numerical exit mapping. Fresh
Astra High `/root/native_relay_deadline_review` returned scoped PASS for NR-1
and NR-2: 275 tests in 43.638 seconds and five adversarial checks in 3.044
seconds. Evidence:
`/workspace/artifacts/native-relay-deadline-review-afac2969e638e9c870010490267bb537f57cd323/review.json`,
SHA256 `162175389f0e10ec668fa44545638e95bf8fc7106c8eab0d4c054ecfd3149604`.

That verdict does not admit another native run: v259 source shows the global
service timeout-abort drop-in loads after transient properties and can override
the requested stop behavior. The next correction journals an exact-unit empty
mask, rejects unexpected applicable fragments/drop-ins/dependencies before
launch, refreshes the not-found cache through verified directory timestamp
advance, and checks the effective profile inside the relay before sensitive
input or payload execution. It retains the separate root, maintenance and
observation stop budgets. Design:
`/workspace/scratch/transient-profile-design.md`. The sole builder's source
slice started around 05:24 HKT, with a checkpoint by 05:59 HKT; no new CI run
or production change is admitted yet.

Independent read-only Codex research at
`/workspace/scratch/codex-tool-boundary-design.md` identifies actual shell,
filesystem-helper and conditional extension paths in stock 0.169.0. A finite
synthetic Responses fixture can exercise actual tool dispatch offline while
retaining the managed permission policy; endpoint/auth-mode differences must
be recorded. This is a queued validation component, not model authentication
or proof that every production tool path is covered. No real model/auth call
or additional native target was used by that research.
