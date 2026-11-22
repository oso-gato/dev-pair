# Offline two-session UUID resume fixture

`tools/codex_sessions.py` is a separate finite experiment for the pinned stock
Codex 0.169.0 binary. It reuses the existing state Harness, immutable managed
policy/skills, private synthetic Responses transport, namespace/capability/NNP
setup, output metering and owned cleanup. The existing 32-action inventory and
its verdict are unchanged. No real model, credentials or endpoint is used.

Source tests and review are distinct from actual stock validation. This source
unit has not run the stock journey; a fresh exact-candidate review must precede
one separately authorized bounded experiment. Tiny fake binaries and synthetic
history/SQLite fixtures in tests are not stock restoration evidence.

Use an already verified binary, the unchanged pinned catalog and a new report:

```sh
python3 tools/codex_sessions.py --binary /path/to/verified/codex \
  --catalog /path/to/pinned/models.json --report /path/to/new-report.json
```

The binary is privately snapshotted and verified by Harness against its exact
294277432-byte SHA256 pin. Catalog SHA256 must be
`1384625c0b6b3e67d3c60da29becea2b017f2c283fc1e2d05b8edafb4698eb10`;
the synthetic metadata model remains gpt-5.5, separate from development worker
model selection. No feature, provider or catalog mutation manufactures coverage.

Two sequential stock processes create distinct actual UUID sessions sharing
`/job` and one CODEX_HOME. Each has a distinct synthetic context and one fixed
benign command that creates a private progress marker. Actual CLI thread events,
HTTP call/result evidence, marker bytes and read-only stock database/rollout
records bind each completed first turn. A bounded private checkpoint outside the
stock child's read policy retains both identities; it is checked against the
server's independently observed first-turn evidence before every continuation.

Every completed process is terminated/reaped before starting a fresh process.
`exec resume UUID` uses each exact observed UUID; names, --last, cwd selection,
fabricated rollout/session records and fresh-thread substitutions cannot count.
Before emitting continuation work, the server requires the actual resumed request
to carry the exact complete ordered user-message sequence independently observed
in the first request, plus one exact new continuation prompt, and the exact
previously observed call/result pair in order. First-result requests must retain
the same observed context too. The expected prompt is a separate exact full-message
binding, never a substring or a substitute for observed history. No metadata
normalization is performed; any needed normalization requires pinned-source proof.
Reported context hashes derive from the observed message sequence. The other
session is excluded. Unknown/orphan/duplicate/reordered
call outputs or changed history reject without committing acceptance bookkeeping.
Then one fixed command appends the session's second distinct marker; complete
successful output and filesystem bytes must match exactly. Both first actions
remain once, unrelated uncommitted source bytes remain unchanged and the UUID set
and SQLite integrity must hold. A fixed unknown UUID additionally needs a
source-backed no-rollout error, nonzero status and no model dispatch; generic
process failure does not prove unknown-session rejection.

One reviewed-candidate stock experiment stopped at the first alpha history
metadata guard, after nine baseline checks and complete owned cleanup. No bound
turn/checkpoint/resume was accepted; actual created sessions/marker effects are
unverified, not established zero. The rejected wire shape was not retained, so
its exact keys cannot be claimed. Cached pinned source independently shows the
fixture-issued assistant function call gets `turn_id` without `create_time`;
function-call outputs additionally get creation time. This source mismatch is a
likely cause, not observed-wire attribution or proof of subsequent stages.

The repaired closed contract keeps metadata optional. When present, calls require
exactly `{turn_id}` and outputs exactly `{turn_id, create_time}`. Null/empty,
unknown/additional keys, malformed UUIDs and invalid/nonfinite/bool timestamps
reject. Both members of a pair must agree on turn ID when both contain metadata;
a fresh continuation can have a different turn ID from historical turns and the
session UUID. Original dictionaries remain intact, with exact canonical replay;
no metadata stripping or normalization is used. The existence of other upstream
metadata fields is not permission to accept them.

At most one rejected-metadata shape witness (2 KiB maximum) records fixed
stage/kind/type enums, item position, recognized-key presence/types, counts,
validity booleans and request/harness/source hashes. It never records arbitrary
unknown key names, values, transcripts, arguments or output snippets. Rejection
changes no acceptance/checkpoint state and never undoes real file effects. The
witness uses the existing request/report/capture budgets and creates no retry.

Actual repaired resume wire/metadata serialization remains unproven until a
fresh review and separately authorized changed-candidate stock validation. An unexpected shape blocks with bounded hashes/partial positive
records; there is no unchanged retry, fallback session or automatic parser
relaxation. Reports expose actual UUIDs, binding/context/marker/rollout hashes,
counts and cleanup outcomes, not transcripts. runtime_admitted, real_model,
auth_verified and replacement_verified remain false even if this finite journey
passes.

All starts share the original 180-second experiment deadline and counters,
including the nine baseline state checks and a five-second cleanup reserve.
Each action/process is clipped to 20 seconds and remaining time. Existing limits
remain 64 requests/connections, 256 KiB bodies/lines, 2 MiB aggregate capture,
4 MiB report, 32 MiB state, 384 MiB snapshot and 4096 sampled entries. Existing
per-process 2 GiB address-space/16 MiB file ceilings remain. Four progress actions
and one negative resume form a separate small journey; they are never appended
to the old inventory action ceiling. Sampled storage is not a deployed quota.
Private owned fixture cleanup is required; unresolved ownership retains state
and blocks admission. Existing reports are never overwritten.

The interruption point is after completed first-turn checkpoints, using the same
binary and state across process restart. This does not prove in-flight operation
replay safety, all production sessions, authentication, image/version migration,
replacement/rollback, Fedora/Podman/Distrobox placement, nightly scheduling,
atomic dispatch freeze, full session/platform recovery or R9/R11 acceptance.
