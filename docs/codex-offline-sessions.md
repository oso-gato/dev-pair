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

The fixed positive turns now pass through a private local supervisor in
`tools/session_controller.py`. It reserves an operation before launching the
source-fixed CLI, binds real v1 ledger controller/job/checkpoint identities and
immutable source/runtime/binary/policy/layout/standards/agreement references, and
records only prompt hashes/lengths and a credential reference. The existing CLI
arguments, synthetic environment, helper-child attestation and history/progress
oracles remain in force. The unknown-UUID negative still reaches the original
CLI directly and is explicitly outside positive-turn inventory.

The separate mode-0700 registry uses fully synchronous SQLite transactions,
mode-0600 files, an exclusive owner lease, at most 32 operation rows and a 1 MiB
aggregate file bound. Identical operations return a typed observe-only outcome;
changed bodies collide. A newly authorized operation reads the trusted ledger's
current checkpoint; an old operation retains its original immutable checkpoint.
A known session may have only one active/uncertain turn. Reserved unbound starts,
failed operations and idle UUIDs remain in the generation-bound inventory.

Read-only observers never own the child or issue signals. They can disconnect and
reattach to the same operation/UUID/progress sequence:

```sh
python3 tools/session_controller.py --registry /private/controller/session-registry
python3 tools/session_controller.py --registry /private/controller/session-registry \
  --operation turn-alpha-first
```

Registry format 2 validates the complete supported SQLite table definitions,
columns, primary-key indexes and uniqueness before projection or mutation. It
also checks the full bounded row set, each stored request hash and the single
logical-session origin/UUID relationship. Unsupported or corrupt schemas and
contradictory resume records reject; a duplicate ID can never silently omit a
managed session. Original operation checkpoints remain immutable, while newly
authorized operations still use the trusted ledger's current checkpoint.

The registry retains descriptors for both the database and lease, persists their
device/inode identities and compares them with the current paths on reopen,
reads, mutations and owner entry/exit. Replacing, unlinking or recreating either
file is an unavailable/conflicting state, never a fresh unlocked lease. Observers
use the same verified lease inode. Existing format-1 registry files are rejected
without migration; this does not change the v1 job ledger or its backup schema.
This is a protected same-UID controller consistency boundary, not a claim against
arbitrary malicious controller code or production state replacement.

A released owner lease makes active records uncertain in both read-only views.
Owner loss permits neither automatic adoption nor replay; persisted PIDs are
only diagnostics. The original deadline and capture meter continue across reads.
Recorded cleanup distinguishes a reaped owned child from unresolved cleanup;
process-group signaling does not prove detached descendants are gone.

The outer controller reads the four repository documents and verifies the three
shared-document cache hashes at the adopted standards pin before fixture startup.
`--standards-cache` selects an authorized read-only cache; the default is
`/workspace/standards`. Only a hash receipt enters the isolated fixture. Private
standards text is never mounted into CLI-autoloaded instructions or captured
request/history, and blank AGENTS files are unchanged. Managed instruction
delivery and model consumption remain unverified. The ledger's medium effort is
an unverified fixture record; actual fixture effort remains unconfigured. Neither
that metadata nor the synthetic model label attests this development worker's
API model selection. No production job/runtime admission is enabled.

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
source-backed no-rollout error, exit exactly 1 and no model dispatch; generic
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
closed `user.text` metadata and canonical RFC4122 `msg_` UUIDv7 identity; its new turn must
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


The pinned ordinary CLI producer supplies no admitted user-item UUID and assigns
its current prompt through the owning session's normal `msg_` UUIDv7 generator.
`msg_input_` belongs to a distinct admitted-input path and is not a compatibility
alternative here. This correction changes only the fixed one-environment path's
prompt ID expectation. The original zero-extra path and all original history,
call/result, all-input-ID uniqueness, turn, audit and whole-body checks remain.

Actual stock `1df7952` retained exact old prefix/call/result and one new
source-shaped environment, but its canonical content changed from 1,169 to 1,127
bytes. The current-prompt schema failed; schema-gated false uniqueness/turn flags
did not prove collisions or unequal turn IDs. Both first-turn markers/checkpoint
and first durable audits passed; no continuation was issued or accepted. The
specific environment delta is unknown. The prompt correction does not admit
this unequal body, and this new candidate has no actual stock result yet.

The first rejection witness stays within 2 KiB. Its compact
`environment_comparison.checks` contains `[known_mask, true_mask]` using this
fixed bit order: original pair exact, causal positions, baseline audited,
baseline schema, new environment schema, current prompt schema, new ID valid,
complete input ID inventory, new ID unique, prompt ID unique, new turn valid,
new turn differs from old, new turn equals prompt turn, exact body equality.
Unknown operands have no known bit; they are not false comparisons. `body` is
`[old_canonical_bytes, new_canonical_bytes, old_sha256, new_sha256]`.

`prompt` retains only fixed envelope/metadata type masks, unknown-key count,
ID-family enum, exact expected-text boolean and failed-schema bits. Failed bits
are envelope, fixed ID family, content shape, metadata key set, turn UUID,
timestamp and classification, in that order. These checks are independent;
unrelated malformed metadata does not fabricate an ID collision or turn mismatch.
No raw key names, values, IDs, paths, timestamps or prompt text are published.

Component diagnostics use a streaming parser with a 16 KiB input sublimit,
128-element limit and depth eight. DTD/entity declarations, comments and
processing instructions are rejected before parsing; no document tree or entity expansion
is used. Only fixed source-rendered parent/child/attribute names are supported.
Malformed, duplicate, unknown and oversized shapes get fixed statuses and remain
independent of acceptance. Presence/equality masks and packed order use the
fixed component order `cwd,status,error,shell,environments,shell_version,
current_date,timezone,network,filesystem,subagents`; packed order starts at one
and appends each one-based component index in four bits. Wrapper equality is
separate. At most two changed components include
`[component_index, old_bytes, old_sha256, new_bytes, new_sha256]`, with null for
absence. These hash exact source byte spans from each opening top-level tag to
the next tag or closing wrapper, including child order, attributes, text and
following whitespace; they are not normalized XML equality. Whole canonical
content hashes remain authoritative for body equality. Unsupported parsing and
truncated changed-component detail are explicit. Entry summaries yield before
core bindings; an overflowing component projection becomes unavailable. The
same original rejection is retained, without action/state advancement. No
component, omission, XML normalization or date/path stripping affects acceptance.


Fresh review of `7298586` found two diagnostic gaps without an acceptance bypass.
The corrected parser uses an attribute allowlist for each element and a bounded
child-name set for each active parent. Repeated singleton children are marked
unsupported/duplicate immediately, including nested network and filesystem
fields. Source-supported repeated `environment`, workspace `root` and filesystem
`entry` elements remain supported; each entry has one path/glob/special choice.
Attributes recognized elsewhere are unsupported on the wrong element. The same
16 KiB/128-element/depth-eight limits apply without a document tree. Old-turn
UUID extraction now uses the unique original metadata candidate independently of
unrelated ID/timestamp/schema errors. Its comparison is known only when both
UUID operands are valid; baseline schema validity remains mandatory for
acceptance. Whole body/history/causal/result/final-audit acceptance is unchanged.
No actual stock success is established by these source diagnostic repairs.


The combined candidate closes the consolidated structural-minimum review finding.
Environment requires id; a current environment requires cwd, while a status-form
environment has no children or primary attribute. Network requires enabled;
permission_profile requires type and one file_system; file_system requires type
but may have no entries; entry requires access and exactly one path/glob/special.
Filesystem requires permission_profile. Present environments/workspace_roots
containers are nonempty, retaining repeated environment/root/entry forms. Empty
overall context and empty network/file_system remain supported. Structural
container text is XML whitespace only; leaf values remain opaque. Status forms
of shell_version/current_date are empty markers. These are bounded shape checks,
not ID/domain/permission/path/date/attribute-value validation or an acceptance
oracle. Exact-body/history/result/final-audit admission remains unchanged.


A further review-gated source branch binds the actual live owned CLI child before
any response. A published Popen/start/parent identity, anchored private helper
and lock inodes, exact executable/three aliases, closed Linux exclusive FLOCK
record and independent nonblocking lock contention are all required and rechecked.
Missing/foreign/dead/swapped/unrecognized bindings block. No environ/cmdline or
arbitrary file contents are read. First-turn evidence is retained separately from
immutable history; later requests recheck the current child, and the handle is
cleared on exit. Unsupported lock modes/formats remain unavailable.

Only this independent evidence can enable the narrow byte-derived suffix:
original managed/restricted body and exact /job/bash spans, exact globals,
source-shaped cwd/shell omission, and one original READ path target replaced by
the independently attested resumed helper path. Every other byte, historical
message, causal pair, current prompt, result replay and final durable audit stays
exact. Self-described paths/prefixes are insufficient. No static-policy change,
XML normalization, privilege or runtime admission is introduced.

The fallback inspects all bounded filesystem entries, with ordered/multiset/root
digests, fixed header/check/count fields and hashed target details. Present
filesystem changes take priority over omission details; explicit truncation and
overflow retain aggregate rejection evidence within2KiB. Prefix-based helper
roles in diagnostics do not establish ownership. This candidate has not run
stock Codex; copied-executable/process/lock tests are local source evidence only.


An unavailable live-helper observation remains the authoritative rejection. The
fixture now records diagnostic-only filesystem evidence before re-raising that
same error: an audited retained resume body can be compared with the received
new fragment even when ownership is unknown. This does not authorize equal-body
or zero-extra acceptance. First turns have no prior body and explicitly report
missing-baseline/unavailable; missing, malformed or unsupported bodies remain
unavailable. First helper/context witnesses retain their original request hashes,
knownness and at-most2KiB bounded summary; no action or accepted-state change occurs.


Unavailable-helper diagnostics reuse `environment_comparison` in an explicit
non-admitting mode. They retain top-level `body` canonical lengths/hashes,
`environment_checks` known/true masks in the existing ENV_CHECKS order,
`baseline_count`, independent prompt/prefix/pair/request/source facts and complete
filesystem aggregates. `components` retains parse status, known bits (old=1,
new=2), presence/order/equality/wrapper masks, completeness and honest detail
truncation. Unaudited/missing old body operands are null/unavailable; new-body
facts remain independent. No-added-environment operands are unavailable rather
than invented equal bodies. A single budget preserves this core first, then
trims optional per-item and filesystem target details within2048 bytes. The
non-admitting path cannot run the helper transform or authorize any action.


## Unknown-UUID terminal evidence

The pinned ordinary UUID-resume producer can wrap the fixed missing-rollout
message in `thread/resume: thread/resume failed: ... (code -32600)`, optionally
with the terminal `Error: ` prefix. Only those two complete typed forms and the
previous fixed bare forms are supported. Different UUIDs, methods, codes, data
suffixes, extra lines, ANSI/control bytes and partial stderr cannot prove the
reason. The original 4,096-byte stderr retention limit is unchanged.

The negative attempt now records a closed witness before launch and before its
compound guard: observed launcher handle, returned and independently observed
natural-exit facts, request counters/delta, bounded stderr count/hash/completeness,
fixed CLI-event counts, forbidden-event flag and exact reason families. Missing
facts remain null; a cleanup/interruption exception cannot invent a returned
status or natural exit. No raw stderr/event/exception values are included. Valid
reason text cannot override a wrong exit, request delta or forbidden thread event.
Both final database UUID-set/integrity and exact durable continuation audits still
have to succeed before overall pass.

Actual stock `1c2ede3` completed both original-UUID continuations and all four
phase effects, then blocked at the old unknown-UUID compound guard. Its negative
status/reason/request-delta facts were not retained and its final audits were not
reached. The source-proven formatter gap is not its established runtime cause.
This source repair has no stock result; fresh exact review and one separately
bounded validation remain required. Runtime/job/renewal admission stays false.


Unrecognized messages inside the closed negative `error`/`turn.failed` envelopes
now reject immediately. A first closed rejection stores only its fixed
classification/event kind/index, raw-line byte count/SHA256 and whether a valid
reason preceded it. It is retained unchanged; later good CLI/stderr reasons
cannot clear it or pass the final negative guard. This does not classify ordinary
stderr diagnostics as structured errors. The 42 reviewed mixed-stream cases and
existing exact valid/partial/failure streams are local regressions only; the
560-test full pass belongs to base `86fdc82`, not this narrow changed candidate.
