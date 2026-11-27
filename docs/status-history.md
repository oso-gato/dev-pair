# Earlier dev-pair validation records

These records are the original DR2 component and diagnostic history. See the current [setup entry](../README.md#set-up-the-fedora-host).

<a id="dr2-2"></a>
**DR2.2** The restart now includes an offline, Python-standard-library [candidate preparation tool and local tests](candidate-preparation.md). It validates explicit operator-supplied identities, prepares a deterministic digest-pinned Fedora/Codex build context, verifies transferred context bytes against a separately recorded handoff hash and prints blocked invocation proposals for both Distrobox placements. A disposable CI tooling image has been built and a Fedora VM has booted; no production gptbox image or authenticated agent has been admitted. Distrobox confinement, complete Fedora validation, authentication and model access remain unverified. Executable host bootstrap preparation is now available under DR6. No complete platform installation or deployment has been verified; DR2.5 records partial CI evidence. Tailscale access for the pair and all hosted applications, ingress denial and fail-closed recovery remain required and unverified (R7.17–R7.18). Operational access and budgets still need to be established before dependent execution.

<a id="dr2-3"></a>
**DR2.3** The previous source and documentation remain in Git history at commit [`90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`](https://github.com/oso-gato/dev-pair/tree/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5). They may be consulted selectively but do not govern the new implementation. No history or existing tags are rewritten.

<a id="dr2-4"></a>
**DR2.4** The local job ledger records versioned requests, transactional checkpoints, candidate-bound results and interrupted attempts. Bounded SQLite backup and clean-destination restore preserve job identity and ordered history, including completed results and in-flight attempts. See the [durable job protocol](durable-jobs.md). The local checklist handoff uses mutual TLS between separate processes. It creates and completes an item, verifies the same item after a process restart and returns the stored result when the exact completed request is replayed. Separate-UID credential custody, the handoff through rootless Podman and systemd on Fedora, and the full pair failure, repair and retest loop remain unverified. See the [local checklist restart handoff](host-handoff.md).

<a id="dr2-5"></a>
**DR2.5** The [Fedora 44 CI VM probe](fedora-ci.md) keeps signed inputs and fixed resource/time/log limits. [Run 27](https://github.com/oso-gato/dev-pair/actions/runs/45025114650), source `de85467`, passed enforcing Fedora preparation through both role batches/sudo denials and progressed Tailscale setup, then rejected the first maintenance signed-base load; its 600-second timer did not fire. The old effective-profile label and post-interrupt -9 do not identify the cause. [Run 28](https://github.com/oso-gato/dev-pair/actions/runs/45034350875), source `122688f`, passed 466 hosted tests and booted enforcing Fedora, then stopped earlier at the operator's final configuration-snapshot comparison, before its launcher existed. Preparation took 315.831 seconds with no timer firing. The changed row/actor is unknown; dp-maint and image/storage stages were not reached. Both outer cleanups passed; guest cleanup is unverified. The combined source candidate establishes newly created relay artifact directories as descriptor-bound 0755 despite service umask 0077. Its closed cache witness cancels balanced canonical alias rows and withholds ambiguous surplus pairs, preserving exact comparison and all cleanup limits. The directory defect is independently source-proven, not an attributed run27/28 cause. [Run 29](https://github.com/oso-gato/dev-pair/actions/runs/45038447317) on reviewed `048e965` stopped in hosted tests: 525 tests, two failures/four errors in relay fixtures; Fedora was skipped and no controller/guest report exists. The fixtures assumed traversable checkout ancestry outside their owned namespace; the exact failing external ancestor was not observed. A test-only portability correction now models that trusted external boundary by exact inode identity, retaining real in-fixture security checks and unchanged product bytes. [Run 30](https://github.com/oso-gato/dev-pair/actions/runs/45040232209), source `8aa45c2`, passed 526 hosted tests and enforcing Fedora preparation through both role checks and ingress, then its Tailscale signed-package launcher exited 1 before interruption with zero relay bytes. The 600-second prepare timer did not fire; service/payload result and root cause remain unknown. Outer cleanup passed; guest cleanup, prepared images and storage samples remain unverified. The next source candidate adds an exact-selector bounded launcher summary/timing witness and an ephemeral bracketed resolved-listener identity batch. Neither changes admission or establishes runtime savings; fresh exact review and separately authorized changed native evidence remain required. Earlier run25 timeout/run26 tooling failure, all receipts and unchanged limits remain in the [work record](dr10-work-record.md). Maintenance assembly, hard quotas, nested placement, authenticated jobs and designated Hostinger acceptance remain open; no deployment is verified. Native31 on `2ed389f` passed 553 hosted tests and enforcing preparation through Tailscale/package-inventory commands, then its context-owned maintenance candidate launcher exited 1 before interruption with zero relay bytes. Preparation used 598.599 seconds without its timer firing; the manager result, payload execution and cause remain unknown. Outer cleanup passed; guest cleanup and prepared/assembled images remain unverified. The current source-only diagnostic extends bounded summary/timing evidence to that exact existing executor without changing its launch flags, limits or admission. Fresh review and later combined validation remain required; no diagnostic-only native retry is scheduled here. The new source candidate factors internal host readiness from public preparation: host convergence remains inside 600 seconds, then one full adapter image is built and independently inspected inside the existing adapter 1,620/image 600 ceilings. Only a closed source/input/recipe-bound completion and storage record earn the prepared marker; genuine assembly and both frozen runtime cycles still follow. Standalone minimal preparation and legacy public assembly remain supported. This is source/local evidence only; no timing, size, quota or native success is inferred. Native32 on reviewed `498e96f` stopped before Fedora: 588 hosted tests had one timeout-fixture assertion failure because the existing deadline primary differed from the fixture’s generic-only expectation. The test-only correction checks both exact primaries and real launcher/interrupt/owned-cleanup evidence; product tools and limits are unchanged. No VM/controller/guest result or native success is inferred. Native33 on `505f591` passed 589 hosted checks and completed host prerequisites in 520.262 seconds, then signed load returned 1 after 4.236 seconds through complete verified relay; images/assembly/storage were not reached. Exact owned reconciliation and outer cleanup passed. Its suppressed payload reason remains unknown. The next source candidate adds a protected explicit XDG config path and signed-load-only typed payload hashes/counts and reported-error classes. Tagged upstream source proves the absent-XDG construction defect, without attributing run33 or proving Fedora behavior. Fresh review and changed native evidence remain required.

The next source-only diagnostic adds a disposable, fixed public CI recipient for
one encrypted capsule from the exact failed, complete, verified signed-load
payload. It preserves native34's unknown cause: enforcing Fedora host setup took
541.513 seconds, load exited 125 after 54.124 seconds, and owned/outer cleanup
passed. No image or assembly was completed. Only bounded ciphertext and typed
binding evidence may leave the guest; no plaintext fallback or runtime security,
command, resource or deadline change is introduced. Fresh review and a separately
scoped changed native run remain required; no native35 acceptance is claimed.

<a id="dr2-6"></a>
**DR2.6** The [public maintenance-input helper](public-maintenance-inputs.md) verifies pinned Codex/Cosign/Distrobox inputs and creates a compressed current-HEAD context/source handoff with sanitized Git objects and separate integrity manifests. Actual run8 completed fresh strict producer verification and admitted that exact source/context in the Fedora guest. Every changed source requires a matching new handoff and verification; historical receipts do not admit a changed candidate. This helper grants no agent/model or runtime admission.

<a id="dr2-7"></a>
**DR2.7** The [offline state component](codex-offline-state.md), [tool fixture](codex-offline-tools.md) and [two-session fixture](codex-offline-sessions.md) have finite component evidence; runtime/job admission remains false. Reviewed `82efae1` passed the existing 32 actions plus nine baseline checks. Exact `f54afb5` then passed one finite offline stock two-session experiment in 3.397 seconds: both actual UUIDs resumed in fresh processes, all four phase effects/history/helper/causal-pair checks and both final durable audits passed, SQLite integrity and the exact UUID set held, and the unknown-UUID negative returned exit 1 with zero request delta. Cleanup completed. Its receipt is `/workspace/artifacts/session-stock-f54afb5/evidence.json`, SHA256 `540cd375197172abe01308c042b236841cdb8e8f688f5302be10ab0feb00ab9e`. That proof is limited to this same-binary, synthetic, completed-turn process-resume journey. Earlier blocked attempts and unknown causes remain in the work record; authentication, real models, in-flight replay, image/version replacement, all production sessions and nightly renewal remain unverified. A new source-only fixed-turn supervisor adds a private bounded operation registry, real child ownership and read-only observer reattachment around the existing positive-turn fixture. It binds trusted ledger/current-checkpoint and immutable input references; reserved or owner-lost operations stay inventoried without adoption or replay. The unknown-UUID CLI negative, history/helper/progress and final audits remain required. Private standards are verified in the controller and represented only by hashes; model consumption is unverified. This changed fixture has local component tests only and requires fresh review and a separately authorized stock experiment; the earlier f54 result is not a pass for it. The supervisor's first independent review found unsupported SQL schema acceptance,
contradictory stored UUIDs and lease replacement ambiguity. A source repair adds
closed schema/request/state checks and persistent descriptor-bound database/lease
identities; fresh review is still required. Reviewed `e6c4cc6` subsequently passed one corrected-wrapper finite offline stock
run in 3.417 seconds with complete owned cleanup (12 requests, 390,662 captured
bytes). Its receipt is `/workspace/artifacts/session-stock-e6c4cc6-wrapper2-20261122/evidence.json`,
SHA256 `ea13108c8910bf7669e6323514218087ab9ffed285359a24d0266f4fef90d50d`.
That result retains the same synthetic/finite admission limits. The next source
candidate adds actual managed-directive and complete synthetic document delivery
through a fixed existing helper before work, with exact replay and durable audits.
Private real documents remain in the separate verified private loader, not fixture
captures. This changed fixture has no new stock pass or model-compliance claim. Independent startup review found one resumed causal-order defect: moved original
startup evidence could permit work before final audit rejection. A narrow source
repair now checks startup-before-original-work-and-current-prompt before issuing
continuation. Affected checks pass; fresh review and changed stock evidence remain
required. Reviewed `78c1355` closes startup replay ordering before continuation. Its one
changed stock attempt stopped before the CLI/listener at a missing staged
`fedora_oci.py` dependency: nine baseline checks passed, but no turn, UUID, request
or final audit was reached. A narrow source repair now adds `fedora_oci.py` to the fixed immutable snapshot,
read-only mounts and aggregate source identity. An isolated staged import regression
checks that exact dependency closure; changed stock delivery remains unproved.
The dependency repair passed 116 affected tests and fresh review. One changed
finite stock attempt on `64b74b4` then passed the synthetic startup/session oracles:
seven complete documents, two original UUID resumptions, four turns and final
history/helper/marker/SQLite/unknown-UUID audits, with owned cleanup. That is finite
delivery evidence, not model understanding or production authentication. The
report summarizes delivery without separate per-startup call/output hashes.
The prior `65bd26b` cleanup repair passed 669 local tests but fresh review found
four lifecycle defects, so that full pass is not acceptance. The replacement
source uses a fixed immutable empty ISO home and the direct pinned recipient,
removing writable-home creation/deletion. The first simplification still failed fresh review at handler install/restore
boundaries. The focused repair now captures the prior mask without changing it,
masks only fixed handler transitions, restores that mask before Popen/exec, and
retains explicit cancellation/primary arbitration. Both real-signal boundary
reproductions and later phase-ALRM delivery are checked locally.
Fresh review, a later combined full and separately authorized native validation
remain required. This is diagnostic capability, not a runtime fix or a diagnosed
native34 cause; local read-only DAC tests do not prove native ISO behavior.

Published `bf68f2f` passed fresh review and 682 local tests in 96.415 seconds.
Native35 passed hosted checks, then stopped before Fedora at a failed controller
storage measurement; no usable capacity sample or encrypted guest diagnostic was
produced, and image-copy cleanup remained unresolved with scratch preserved.
A separate native source repair is queued. The current source-only controller
adds durable format-3 freeze/drain/snapshot/abort for its existing private registry,
with new reservation and leased launch fencing. Snapshots require complete safe
inventory; exact-token abort preserves uncertainty and never replays deferred work.
This has affected local evidence only, requires fresh review, and does not provide
role-wide session inventory, authenticated renewal or production admission.

No production deployment is established.

<a id="dr2-8"></a>
**DR2.8** The [storage observation component](storage-observation.md) measures bounded filesystem usage and checks explicit peak-capacity arithmetic. Independent review verified sparse-growth accounting and reserve boundaries. Unknown measurements block; matching samples do not prove quiescence, reserve capacity or enforce quotas. Hard storage limits and safe cleanup remain required before jobs can run.

<a id="dr2-9"></a>
**DR2.9** The checklist is available as a local development specimen. Use it to add, list and complete items, reopen them after a server restart, and back up and restore the SQLite data. The pair's end-to-end build and deployment of the checklist remain pending. See [how to run the checklist locally](examples/checklist/README.md).

<a id="platform-and-agents"></a>
