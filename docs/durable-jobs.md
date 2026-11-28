# Durable local job and test ledger

[jobs.py](../tools/jobs.py) provides executable local job checkpoints, request
production/submission, fixed data checks, durable results and recovery.
[job_protocol.py](../tools/job_protocol.py) is the single versioned schema and
controller library used by every producer and consumer. This is A3/R3.2/R4
groundwork, **not enabled pair jobs, a host executor, agent authentication,
independent release approval or first-pair acceptance**. Existing bootstrap and
gptbox admission behavior is unchanged. No Codex/model call occurs.

## Controller and storage boundary

Run this CLI only as a trusted local controller, with reviewed immutable code,
a trusted Python installation and an operator-controlled filesystem. Pass an
explicit `--state` directory. The leaf must be owned by the current UID with
mode `0700`; database and journal files must be private regular files (`0600`,
one link). Symlink path components and untrusted writable ancestors are rejected.
The root-owned sticky temporary directory is allowed for local exercises.
These checks protect against other filesystem principals; they cannot protect
against a compromised controller UID or code interpreter.

The eventual separately owned role paths remain
`/var/lib/dev-pair/maintenance/state` and
`/var/lib/dev-pair/development/state`. A maintenance controller's ledger must
**never be writable or mounted into the development role**. This slice neither
provisions nor connects those ledgers. A JSON role, executor ID, hash, evidence
reference or model name is no authentication. The persistent random controller
ID identifies this local ledger; it does not attest a machine or remote sender.
There is deliberately no external result-import command. The `finish` library
method is internal trusted-controller code, not an authenticated transport API.
External transport, sender authorization, host admission, credential isolation
and independent release enforcement remain unverified and unimplemented here.

All ledger tables, checkpoints, requests, results and ordered events are durable
data. SQLite `BEGIN IMMEDIATE`, full synchronous commits and rollback journaling
atomically reserve attempts and commit results. Do not copy an open SQLite file
as a backup: use SQLite's backup API or stop all controllers before copying the
complete state directory. No cleanup command exists: source, artifacts, evidence,
checkpoints and deliverables are never deleted by this tool. The bounded local
backup/restore path below preserves this ledger only. Role mount enforcement,
storage quotas and retention admission still need integration and real boundary
validation before jobs are enabled.

## Private ledger backup and clean-destination restoration

The trusted local controller can snapshot its ledger without copying an open
SQLite file:

```sh
python3 tools/jobs.py --state /private/controller-state backup /private/new-backup
python3 tools/jobs.py --state /private/new-restored-state restore /private/new-backup
```

Both destinations must be absent. Existing directories, files, symlinks and
foreign-owned paths are preserved and rejected; there is no replace, merge,
cleanup or retry operation. Parents must already exist under trusted nonsymlink
ancestors. This is the same trusted controller UID/operator-managed filesystem
boundary as normal ledger use, not protection against a hostile controller or
concurrent same-UID ancestor replacement. The reserved leaf is mode `0700` and
its files are owned mode `0600`, regular and single-link.

A fixed trusted child has a 10-second total operation envelope, including bounded
termination/reaping, a 16 MiB snapshot/file ceiling and a 256 MiB address-space
ceiling. SQLite backup uses finite 64-page steps with a deadline callback and a
bounded busy wait. Source transactions continue; the backup is one consistent
committed database state. These are small local component limits, not deployed
filesystem quotas. No cap increases or unbounded rescue retries are supported.
Limits also include 4,096 rows per ordinary table, 8,192 events and a 16 KiB
manifest. Limits exhausted or termination unresolved means blocked, with partial
owned state preserved.

The backup contains `snapshot.sqlite3`, a strict version-1 `manifest.json`, a
reservation identity (`RECOVERY`) and an atomic no-replace `COMPLETE` marker.
The manifest records snapshot length/SHA256, database/protocol version, backup
identity, source recovery/protocol implementation hashes, logical controller ID,
row counts and ordered table identity hashes covering checkpoints, requests,
attempts, results and events. These hashes identify data and provenance; they do
not authenticate a backup or remotely attest its controller.

Restore reserves a fresh destination, marks it incomplete, copies only the bounded
snapshot, and validates it through a read-only SQLite connection before normal
mutable Ledger construction. Validation requires SQLite integrity, the exact
supported schema/version, no extra tables, indexes, triggers or views, valid
protocol envelopes, canonical bodies and a replay of the fixed data history.
The replay checks current checkpoint references, request budgets and identities,
unique reservations, result bindings, reconciliation and consumed progress against
all stored tables. Supplied SQL, extensions, migrations, commands and referenced
paths are never executed. Unsupported versions, truncation, hash/length changes,
missing records or invalid history block admission.

Data and manifest are fsynced before atomic completion publication; the private
leaf and parent are also synced. A killed operation retains recognizable incomplete
staging. An existing empty directory is now refused by Ledger rather than silently
initialized. Ownership of a new directory comes only from successful exclusive
creation, so a concurrent restore reservation cannot be mistaken for our own
fresh directory. A partially copied ledger cannot be opened without its matching completion
identity. Do not manually remove markers to bypass failed validation. There is no
automatic reclamation of incomplete or foreign paths.

The logical controller ID, model/standards/agreement pins, exact candidates and
tests, ordered events, historical results, pending requests and in-flight attempts
remain unchanged. A separate restoration instance identifies this local copy.
Completed duplicate requests return their stored result even if an artifact is
missing. An interrupted attempt still blocks execution and checkpoint replacement
until explicit existing reconciliation; restoration never reissues it. Old pending
requests whose library recipe identity differs remain blocked until a fresh
checkpoint/request. Historical records are never rewritten to match current code.

Only the ledger and recovery manifest are backed up. Source trees, referenced
artifacts/evidence, Codex state, credentials and secret directories are not copied
or traversed. Referenced evidence availability remains a separate dependency.
Reports contain IDs, hashes and counts, not ledger payloads. Stop the original
controller before using a restored copy for continuation: this provides no
concurrent writable replica coordination, automatic failover or external host
effect reconciliation. Local SQLite/process tests verify this component; host
transport, quotas, Codex/session renewal, deployment rollback and full platform
backup/restoration remain unverified.

## Protocol and recovery

Version `1` has strict `job`, `checkpoint`, `request` and `result` envelopes.
Unknown versions, message kinds and fields, including nested fields, fail closed;
duplicate JSON keys, duplicate check IDs and oversized messages are rejected.
All envelopes are capped at 65536 canonical JSON bytes. Requests have a smaller
16384-byte cap, reserving space for every per-check result, executor identity,
diagnostics and recovery evidence. Reconciliation diagnostics plus evidence have
an 8192-byte encoded budget validated before any state change; callers must use
bounded diagnostics and durable evidence references. Budgets count JSON escaping
and UTF-8 bytes, preserving accepted identities and expectations without truncation.
The database schema version is checked independently. Job selection records the
explicit model/effort/runtime intent as `unverified-record-only`; recording it
neither invokes nor authenticates an agent. Reusing a job ID with changed
selection, standards, agreement or limits is rejected.

A request binds job/request/checkpoint IDs, exact candidate source revision and
artifact SHA256, test revision, recipe ID/digest, requested boundary, reason,
capabilities, effects, logical workspace, fixture references, expected checks,
numeric limits and preservation/cleanup plan. Source revisions and evidence
references are recorded identities; this data-only adapter does not establish
Git provenance or artifact-to-source build provenance. Its actual artifact
bytes are verified against the bound digest. The test revision and recipe
digest both identify the executing library file's SHA256: the local executor
independently compares them with its own implementation bytes before reading
the artifact. A changed implementation requires a new checkpoint/request.

Completed identical requests reuse the exact stored result even when the
artifact is later unavailable. A reused ID with changed content is rejected.
Execution first durably reserves a unique attempt. Concurrent controllers cannot
reserve that request twice. An interrupted attempt remains `in-flight`; retry
reports unresolved effects, and checkpoint replacement/new execution is blocked
until reconciliation. There is no timeout that silently makes an attempt runnable.

After inspecting the recorded attempt and the fixed read-only recipe, a trusted
controller can use `reconcile REQUEST_ID --diagnostic TEXT --evidence REF` to
close it as **blocked**, retaining the attempt and inspection references. This
does not rerun checks or manufacture a pass. The only possible non-ledger effect
in this controller is reading the explicitly supplied local data file. A future
host adapter must supply its own verified effect reconciliation before any
expanded operation is admitted; this reconciliation command cannot prove unknown
host effects safe. Create a fresh request to retry after reconciliation.

Results bind the complete request hash, candidate/test/checkpoint, attempt and
locally established controller/implementation identity. Each check preserves its
expected and actual behavior, pass/fail/blocked verdict, exit status, diagnostics
and digest evidence; results retain overall diagnostics, effects and cleanup.
`consume` only advances the **current matching checkpoint** to
`local-checks-passed`, `repair-required` or `blocked`. It rejects stale results;
replaying an old checkpoint does not restore it as current. Blocked checks never
pass. `local-checks-passed` is protocol progress, not product/host acceptance.

## Run the local failure, repair and retest journey

From the repository root, create a private durable exercise directory. Retain it
as local evidence; this example uses no host operations and no real provider:

```sh
export JOURNEY_ROOT="$(mktemp -d /tmp/dev-pair-journey.XXXXXX)"
python3 - <<'PY'
import json, os, pathlib, subprocess, sys
sys.path.insert(0, 'tools')
from job_protocol import STANDARDS, envelope, recipe_identity, sha256
root = pathlib.Path(os.environ['JOURNEY_ROOT'])
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
def save(name, value):
    (root / name).write_text(json.dumps(value, indent=2) + '\n')
job = envelope('job', job_id='local-journey', standards_sha=STANDARDS,
    agreement_sha256=sha256(b'local data contract: message must equal ready'),
    selection={'provider':'gptbox', 'model':'gpt-6.1-sol', 'effort':'high',
        'runtime_sha256':sha256(b'unverified demo runtime intent'),
        'verification':'unverified-record-only'},
    budgets={'seconds':5, 'artifact_bytes':4096, 'spend_usd':0}, max_requests=4)
save('job.json', job)
for name, message in [('failed', 'broken'), ('repaired', 'ready')]:
    save(name + '-artifact.json', {'message':message})
    save(name + '-checkpoint.json', envelope('checkpoint', job_id='local-journey',
        checkpoint_id='cp-' + name,
        candidate={'source_revision':source,
            'artifact_sha256':sha256((root / (name + '-artifact.json')).read_bytes())},
        test=recipe_identity(), summary='Local data candidate ' + name,
        evidence=['local-data:' + name]))
PY
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" job "$JOURNEY_ROOT/job.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" checkpoint "$JOURNEY_ROOT/failed-checkpoint.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" request local-journey test-failed \
  --expected-message ready --reason 'Exercise the local failure feedback protocol'
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" execute-local test-failed \
  --artifact "$JOURNEY_ROOT/failed-artifact.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" consume test-failed
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" checkpoint "$JOURNEY_ROOT/repaired-checkpoint.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" request local-journey test-repaired \
  --expected-message ready --reason 'Fresh check after changing the data candidate'
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" execute-local test-repaired \
  --artifact "$JOURNEY_ROOT/repaired-artifact.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" consume test-repaired
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" inspect local-journey > "$JOURNEY_ROOT/results.json"
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" events > "$JOURNEY_ROOT/events.json"
# This must exit 2 with stale checkpoint; repaired progress stays current:
python3 tools/jobs.py --state "$JOURNEY_ROOT/state" consume test-failed
```

The first result has one pass and one failure with repair diagnostics. The changed
artifact gets a fresh checkpoint/request, then both checks pass. Every CLI call
is a separate process reopening durable state. `submit FILE` also consumes a
fully specified version-1 request through the same validator. Status and results
are JSON; valid failed/blocked outcomes exit `0` as data, while protocol/invocation
errors exit `2`. Consumers must inspect verdicts rather than treating exit `0`
as acceptance.

## Supported execution and remaining gates

Only the fixed `local-json-message-v1` data recipe runs. It requires exactly
`local-json-read`, `read-artifact` and `write-ledger`, no fixtures, and the two
declared checks. It reads a bounded regular artifact through a non-following FD
in a fixed trusted child process with a hard read deadline, verifies its digest,
parses JSON and compares its message. It cannot import submitted code, execute
scripts, interpret shell commands, provision resources or contact a model.
Request budgets are capped at 60 seconds, 65536 artifact bytes and zero spending;
distinct requests are bounded by the immutable job limit, with one reservation
per ID. The numeric values here govern this small local recipe, not deployed
runtime resource admission. Timeout cleanup kills/reaps the fixed reader;
interruption of the controller still requires explicit reconciliation.

A `fedora-host` boundary or unsupported recipe/capability returns blocked before
reading the artifact. No local result is relabeled as Fedora evidence. Live
host/systemd/SELinux checks, actual failure-driven code repair through the pair,
authenticated role transport, isolated job execution, job/session restoration,
full platform backup restoration and quotas/cleanup remain required. Run
`python3 -m unittest discover -s tests -p test_jobs.py -v` for the local protocol
journey, killed-process recovery, real concurrent controllers, transaction
rollback, identity/collision/budget denial and filesystem boundary checks.
