# Offline two-session UUID resume fixture

`tools/codex_sessions.py` is a separate finite experiment for the pinned stock
Codex 0.169.0 binary. It reuses the existing state Harness, immutable managed
policy/skills, private synthetic Responses transport, namespace/capability/NNP
setup, output metering and owned cleanup. The existing 32-action inventory and
its verdict are unchanged. No real model, credentials or endpoint is used.

Source tests and review are distinct from actual stock validation. This source
candidate has not run the stock journey; a fresh exact-candidate review must precede
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
normalization is performed on independently observed wire messages.
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

A later reviewed metadata candidate accepted both first turns with distinct actual
UUIDs, exact complete observed contexts and one verified progress marker each,
then blocked at the first durable rollout comparison. Six requests and nine
baseline checks completed; cleanup completed. No explicit UUID resume was
reached. Field-level differences were not retained, so attribution is a
source-supported likely mismatch, not a proven sole cause of that failure.

Pinned source persists per-content attribution in durable user messages, then
removes only `content_item_metadata` from the request copy for this unchanged
non-RLite catalog model. Durable validation now separately checks the exact
text-only message envelope, canonical IDs when present, UUID/time metadata and
aligned classification/attribution arrays. `user.text` must have exactly user
provenance; `environments.environment_context` must have exactly harness
provenance with `hook=false`. Unknown, missing, extra or tool-derived attribution
blocks. Only that validated attribution field is removed from a deep copy;
classification, IDs, timestamps, full content and order remain exact. Raw rollout
bytes and raw/projected/wire context hashes remain separate evidence. Base
instructions have developer role and do not justify omitting a user message.

The first rollout audit requires the entire observed first context, with no
extra user messages, before exactly one original call/result pair. Both pair
members must match the independently observed wire dictionaries completely.
The final audit additionally binds the separately retained observed continuation
context and its issued call/result after the original output. Orphan, duplicate,
reordered or altered pairs block. The original SR1 resumed-wire guard remains
unchanged; durable projection is never applied to its retained wire baseline.

The first durable mismatch records at most 2 KiB of fixed stages, counts,
recognized field/type differences and raw/projected/wire hashes linked to
harness, request and checkpoint identities. It contains no transcript, arbitrary
unknown key names/values, arguments, output or rollout path. Diagnostic recording
cannot change accepted evidence or undo actual file effects. Existing caps and
cleanup rules remain unchanged.

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

A later reviewed durable-projection candidate passed both first rollout audits,
including complete projected contexts and exact original call/result pairs. Its
first explicit alpha UUID resume then failed the unchanged ordered-wire-context
guard. No continuation action was issued; the exact old-prefix difference or
possible fresh appended fragment was not retained. That actual failure does not
prove a particular field or authorize extra context.

Diagnostic-only instrumentation now captures the first resumed-context rejection
before the same predicate rejects it. The maximum 2 KiB witness retains original,
observed and prefix counts/hashes, exact-prefix and final-prompt booleans, first
mismatching original index, and request/harness/source identity. At most four
compact summaries give fixed shapes/classification, request positions and a
canonical hash/length. Summaries are omitted as needed to preserve essential core
evidence; `truncated_summary` says when that happened. No transcript, metadata
values, arbitrary keys/classifications, call arguments or outputs are exported.

`difference_mask` bits 0 through 7 compare type, role, id, complete content,
turn_id, create_time, content_item_kinds and complete metadata respectively against
the matching independently retained entry. New suffix entries have no retained
index or difference mask. Shape masks use three bits per recognized key: zero
means absent; codes 1 through 7 mean null, boolean, integer, number, string,
array and object. Envelope key order is type, role, id, content, metadata, status,
phase, encrypted_content; metadata key order is turn_id, create_time,
content_item_kinds, content_item_metadata. Unknown keys contribute only a count.
Positions are diagnostic only and are unresolved unless the original pair is
unique, ordered and canonically exact, with no unknown call identity. The
witness never issues work or advances accepted context, progress or checkpoint
state. No normalization or optional fresh-context acceptance is added.

The next actual diagnostic attempt proved the old complete prefix and original
pair were exact, with one additional environment-classified message after the old
output and before the exact new prompt. It did not compare that new body to the
old environment. No continuation action was issued; body equality and fresh
identity/turn binding remain unknown actual facts.

The conditional repair preserves the original no-extra path. Its only additional
path requires exactly one extra closed environment message whose entire content
array is canonically equal to exactly one independently retained original
environment. That original must have a closed single-part shape and a completed
strict first-rollout audit bound to the retained entry. Missing, ambiguous or
unsupported baselines block. No XML/tag, path, date, shell, network, whitespace or
metadata normalization is used to manufacture equality.

The new environment requires the observed exact envelope and three-key metadata,
`environments.environment_context`, a unique canonical `msg_` UUIDv7 ID, valid turn
UUID and finite positive timestamp. The current physical prompt also needs its
closed `user.text` metadata and canonical `msg_input_` identity; its new turn must
match the environment and differ from the original environment turn. Timestamps
need not equal or order across these separately stamped items. They convey no
authority. Original prefix and call/result remain exact, with strict original
output < new environment < current prompt < new call < new result ordering.

Acceptance retains the entire observed continuation context, explicit zero/one
environment mode and exact environment item. The result request cannot change or
remove any of it. Final durable audit uses that retained mode, complete context
and both exact causal pairs; its existing attribution-only projection is unchanged.
Public turn records contain the fixed mode and environment hash, never its body.
Rejected extra environments extend the first 2 KiB witness with fixed baseline,
schema, body-equality, ID, turn and ordering flags plus canonical content lengths
and hashes. Unsupported baseline/content is null, not zero/equal; summaries yield
to essential evidence at the same bound. Unequal or unexplained content remains
blocked for a separately scoped diagnosis. This source candidate has not run the
stock journey; fresh review and separate experiment authorization remain required.

Fresh review of the conditional source found an ID collision gap: its initial
uniqueness set omitted assistant and other non-user items. The repair compares
each environment and current-prompt ID against every other observed input item's
present ID, excluding only that candidate's physical request position, plus the
independently retained original IDs. Equal dictionaries at another position are
not excluded. Missing/malformed inventory or a malformed present ID cannot
establish uniqueness; absent optional IDs convey no identity. The same complete
check drives the bounded witness flags. This adds no full assistant-transcript
retention, normalization or broader context acceptance. The original zero-extra,
audited whole-body, turn, causal-order and final-audit rules remain unchanged.
