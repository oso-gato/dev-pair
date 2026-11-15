# DR10 launch reconciliation and work record

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
