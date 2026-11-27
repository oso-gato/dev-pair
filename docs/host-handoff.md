# Local checklist restart handoff

`tools/host_handoff.py` runs one `app-state-after-restart` request as a
local acceptance component for A3.2–A3.6 and A12.12(2). The development
process submits, executes and consumes through an authenticated loopback
TLS connection. The maintenance process owns the existing SQLite job ledger,
the artifact approval and the test resources. The request carries the job,
checkpoint, candidate source and content hashes, exact test implementation,
approved effects and budget. It also binds the ledger ID and both certificate
fingerprints. `jobs.py inspect` exposes retained history to the ledger owner.

## Run the local check

The focused integration test provisions disposable TLS test principals and
candidate fixtures, then runs both roles as separate processes.

```sh
python3 -m unittest discover -s tests -p test_host_handoff.py -v
```

The check requires Linux with unprivileged user, mount, PID and network
namespaces, a protected non-setuid `/usr/bin/bwrap`, `/usr/bin/python3`,
`libseccomp.so.2`, and OpenSSL to provision fixture credentials. The application
receives a sealed single-file Python artifact, an inherited loopback listener
and one writable host-backed SQLite file limited to 1 MiB. Each instance keeps
SQLite sidecars and other temporary data in a separate, 1 MiB tmpfs. Kernel
limits govern tmpfs metadata. The sandbox uses read-only system files, private
PID and network namespaces, and a seccomp filter that denies starting more
processes or threads. Only one instance runs at a time under a 128 MiB address
space limit. The test checks fork and access denial, the aggregate tmpfs data
limit and a closed app listener after a controller interruption.

For a separately provisioned local run, the controller uses `jobs.py job`
and `jobs.py checkpoint` to create the job and its current checkpoint. Obtain
the checkpoint's `test` value from `host_handoff.py recipe`. Pass the approved
job ID, source revision, artifact path and independently computed artifact
SHA‑256 to `host_handoff.py serve`, along with the private ledger and scratch
directories and its maintenance TLS profile. The first output line supplies
the ephemeral port and controller ID. The endpoint accepts only its configured
development certificate and one independently approved candidate. The two TLS
profiles each hold `cert.pem`, `peer.pem`, and `key.pem` in a mode-0700 directory
with mode-0600 files. Each profile contains its own key and its peer's exact
public certificate. Provision the controller ID and public certificate pins
through the trusted local harness.

The development process uses `host_handoff.py request` to produce the request
from the checkpoint and its own TLS profile. It uses `host_handoff.py send`
with `submit`, `execute`, and `consume` in that order, reading the same exact
request from stdin on each call. `--help` shows the full arguments. Reopen the
same maintenance ledger and TLS profile after an interruption. An exact replay
of a completed execution returns the same result. A changed body using the
same request ID, a stale checkpoint or a changed candidate is rejected.

The maintenance process records a reservation before starting the first
application instance. The check creates and completes a uniquely named item,
stops that instance, launches another instance with the same database, and
checks the same completed ID. If the controller is killed after a database
effect, the attempt stays in flight and the owned scratch remains available
for inspection. A restarted controller refuses to execute or consume that
attempt. The generic local reconciliation command also refuses this attempt
type. SQLite sidecars are disposable, so an interrupted write may require
manual inspection of the retained primary database. A normal completion
removes the disposable data after stopping both instances and keeps the result
in the ledger.

## Verification boundary

Local TLS verifies separately provisioned keys and exact peer pins. The two
role processes share a host UID in this fixture, so cross-role filesystem
credential custody remains unverified. The namespace test establishes the
application's local isolation from the controller canary. The source-to-artifact
approval comes from the trusted harness. The maintenance allowlist contains
only the local checklist check.

Fedora acceptance requires the same user journey on an authorized target,
with one job-owned rootless Podman candidate managed by systemd, read-only code
and a declared data mount. Fedora service-manager behavior, `erebus` delivery
and VPS access policy remain open. See R7.6, R7.9 and R7.17–R7.18.

## Fedora checklist Quadlet

The host adapter uses the same version 1 job messages and SQLite ledger. Its
boundary is `fedora-checklist-quadlet`. The recipe is
`checklist-quadlet-persistence-v1`. `recipe --host` prints the exact identity,
which covers the controller, protocol, ledger recovery helper, host runtime
and Quadlet template.
The candidate carries the 40-character Git revision and the raw 64-character
SHA-256 of the single-platform OCI manifest. The registry reference in the
approval includes the `@sha256:` prefix.

### Provisioning boundary

Provision a locked, nonlogin `dp-checklist` account without supplementary
groups. Choose a unique UID/GID of at least 1000. Allocate one nonoverlapping
65,536-ID block in each of `/etc/subuid` and `/etc/subgid` after checking the
host's live IDs and existing allocations. The executor checks these assignments
and its user systemd bus. Start the user manager for the authorized service
lifetime. Linger is needed for reboot delivery. Remove disposable test-host
linger when finished.

Install the protected `tools/host_handoff.py`, `tools/job_protocol.py`,
`tools/ledger_recovery.py`, `runtime/checklist/checklist_quadlet.py` and
`runtime/checklist/acceptance.container` under
`/usr/libexec/dev-pair/checklist`, preserving their relative paths. The source
files, template and ancestors need root ownership with no group or other write
permission. Install the executor service from
[`runtime/checklist/dev-pair-checklist-executor@.service`](../runtime/checklist/dev-pair-checklist-executor@.service)
through the controlled host deployment. Its instance argument is the actual
`dp-checklist` UID. Its loopback mTLS endpoint is port 19425. The development
TLS key belongs to the trusted host conductor outside both agent workspaces.
The executor profile at `/var/lib/dev-pair/checklist-executor/tls` holds the
maintenance key and pinned peer certificate. The account home and TLS
directory are mode 0700, and the TLS files are mode 0600.

Keep the job ledger, execution history and TLS outside the mounted test
data. Only protected controller processes can access them. Provision
`/var/lib/dev-pair/renewal-fence/owner.lock` as a unique root-owned mode-0644
file beneath a root-owned directory. The executor holds a shared advisory
lock through each ledger mutation and its effects. Renewal takes the exclusive
lock and uses the root-owned `frozen` marker for durable dispatch fencing.
Authenticated status remains available during the fence.

Use a dedicated non-discarding ext4 or XFS filesystem mounted at
`/var/lib/dev-pair/checklist-validation`, with up to 2 GiB and 65,536 inodes.
Fully reserve the backing file if the mount uses a loop device. Give
`dp-checklist` private mode-0700 access to its root and the `graph`,
`attempts` and `image-copy` leaves on the same filesystem. Install the
root-owned `/etc/dev-pair/checklist/validation-containers.conf` with
`engine.image_copy_tmp_dir` set to the exact `image-copy` leaf. Place the Podman run root at
`/run/user/UID/dev-pair-checklist-runroot`, private to the account. Using that
graph and run root, pre-provision the Podman bridge
`dev-pair-checklist-internal` with `--internal`. Preload the candidate by its
exact OCI reference before validation. This requires Fedora 44 with SELinux
enforcing and a user manager with cgroup v2 delegation. The container must
have its own SELinux MCS categories and the `:Z` data mount must carry the
matching file label. The executor checks both at start and restart.

On initial provisioning, run the following as `dp-checklist` after the
validation filesystem and user manager are ready and before starting the
executor. Leave the initial `ledger` and `execution-history` leaves absent.
This creates the job ledger and binds the separate execution history to its
controller, the machine ID and the mounted validation filesystem. Use
`jobs.py job` as the controller to create the first job afterward.

```sh
/usr/bin/python3 -EBs /usr/libexec/dev-pair/checklist/tools/host_handoff.py initialize-host-history
```

### Request and result

The trusted conductor records the current checkpoint with
`jobs.py checkpoint` and reads the controller ID from the executor's first
line. This example uses a private development TLS profile available to that
conductor.

```sh
handoff=/usr/libexec/dev-pair/checklist/tools/host_handoff.py
python3 -EBs "$handoff" request checkpoint.json checklist-restart-1 \
  --host --seconds 60 --artifact-bytes 8192 \
  --tls "$development_tls" --controller-id "$controller" > request.json
```

Bind the candidate to a protected build receipt from the authorized
repository and exact commit. The release builder uses an isolated worktree
and the fixed [checklist Containerfile](../examples/checklist/Containerfile).
It selects a separately verified base digest with Python 3 and SQLite,
passes `CHECKLIST_SOURCE` as the full verified Git revision, builds with no
network and records the single-platform OCI manifest digest. The host checks
the image's OCI source label, manifest digest and actual container image ID.
The independent source-to-image receipt and authorization come from the
trusted build and host intake. A label that came from the product role cannot
serve as that receipt.

The protected intake writes a root-owned receipt with this closed shape.

```json
{
  "version": 1,
  "job_id": "checklist",
  "candidate": {
    "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "image": "localhost/checklist@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

The root-owned conductor can publish the grant as part of authorized receipt
intake. The command verifies the fixed recipe and receipt, then atomically
publishes a short-lived grant at `/etc/dev-pair/checklist/approval.json`.
The grant binds the whole canonical request, the independent receipt hash
and the executor machine identity. The artifact-byte budget caps approval
metadata read from disk. The dedicated filesystem caps the preloaded image
store and application writes.

```sh
python3 -EBs "$handoff" approve-host --candidate-receipt "$protected_receipt" \
  --publish < request.json
```

Submit, execute and consume the exact same request, in order. Run the same
command with `status` to inspect a pending, in-flight or completed request
without changing it.

```sh
for operation in submit execute consume; do
  python3 -EBs "$handoff" send "$operation" --host --port 19425 \
    --tls "$development_tls" --controller-id "$controller" < request.json
done
```

The host reserves the attempt in SQLite before changing application state.
It starts the digest-pinned Quadlet, adds and completes one uniquely named
item, restarts the same service once, and verifies the same completed item
after both the container ID and systemd invocation change. The controller
bounds the wall time, command output and host effects, and reads only the
owned application's IPv4 loopback port. The container has read-only code,
a single bounded persistent data mount, bounded tmpfs and reduced
privileges. Its output is discarded. Durable evidence retains typed host
command stages and exit statuses.

A completed reply contains the request hash, candidate, expected and actual
check, diagnostics, effect identity in `attempt_id` and cleanup result.
`consume` returns `{progress,result}` with `host-checks-passed`,
`repair-required` or `blocked`. The conductor can pass that response to
DevBox in the job's `.dev-pair/host-result.json`. DevBox responds to a
persistence failure with a changed candidate and fresh checkpoint and
request. A repeated execution for the current completed request returns the
same stored result and effect ID. A historical `status` can read its exact
stored request and result after a new checkpoint.

Loss of a client connection leaves execution and the durable result under
host control. The independent host history records the reservation and
arming before the executor starts the recipe, the verdict before cleanup
and the exact result once cleanup is confirmed. The job ledger mirrors
those transitions. If the executor dies or cleanup is uncertain, status
shows the original attempt in flight. The workspace contains
`operation.json` and the executor writes
`restart-requested` before issuing that action.

The trusted conductor can use `send reconcile --host` with the same exact
request and TLS profile. The host inspects the matching systemd unit,
rootless container and workspace within the cleanup time allowance. When
all three are absent, a durable observation and matching storage and machine
identities allow the original result to be published. An unarmed reservation with
the same absence proof closes as blocked with the original attempt ID and
zero effects. That closure allows a fresh request. The command makes no
application writes and issues no lifecycle commands. If resources still
exist, storage identity changed or an armed attempt lacks a durable
observation, the attempt stays in flight for operator inspection.

### Job snapshot recovery

Retain `/var/lib/dev-pair/checklist-executor/execution-history` independently
when backing up, replacing or restoring the job ledger during recovery or
renewal. It is private to the executor and outside job snapshots. Preserve
the history across upgrades and reboot. The history database has a 16 MiB
limit and pauses new work if it cannot durably record another attempt.
Retain the records that protect outstanding jobs and recoverable snapshots.

With the original controller, machine and validation filesystem in place,
stop the executor and restore a validated job snapshot using the normal
clean-destination procedure before returning it to the fixed `ledger` path.
Restart with the retained history. Read-only status can show the stored
attempt and exact completed verdict for the matching request. The next
authenticated operation restores missing job events under the dispatch gate
when the exact job and checkpoint are present. An older ledger that omits
the authoritative checkpoint stops that job before any host effect. Recover
a job snapshot containing the matching checkpoint, then reconcile. An
already closed attempt returns its exact outcome without another restart.
An armed attempt without a verdict stays in flight.

On a different machine or validation filesystem, restore the previous job
backup into a separate destination for historical inspection. Keep the
original controller and recorded outcomes with it. Fresh host execution
requires a pristine active ledger, a new controller and new requests with
the normal approval. A host replacement that preserves the original machine
and validation filesystem identities can resume the original requests only
with the independently retained authoritative history. If that history is
unavailable or its provenance is unclear, keep the recovered job ledger
offline and surface the unresolved attempts. The initializer rejects a
restored ledger as the basis for fresh execution history.

### Tailnet release

A separate reviewed deployment can render a persistent unit from the same
confinement template. Use the approved release digest, named tailnet DNS
authority, fixed host loopback port and actual account UID.

```sh
python3 -EBs "$handoff" render-release --image "$released_image_ref" \
  --hostname "$checklist_tailnet_dns" --port 18279 --uid "$checklist_uid"
```

This only renders a unit. Version and install it separately from the test
executor. It uses `/var/lib/dev-pair/checklist-live/{data,graph}` and the
separate `dev-pair-checklist-release` internal bridge. The deployment owns
its data allocation, backup/restore, trust receipts and rollback. Configure
the host-managed Tailscale HTTPS endpoint for the exact named authority to
forward to `http://127.0.0.1:18279`, with an ACL for authorized clients and
Funnel disabled. Exercise authorized browser use, public and unauthorized
denials, tailnet loss, host reboot and recovery on the released target.
The test executor and its ephemeral application port have no Tailscale
route.

### Evidence

The local component test exercises actual checklist HTTP in subprocesses,
with a fixture manager and OCI metadata. It verifies failure and repair
feedback, no duplicate restart, credential and grant bindings, interrupted
reservation and observation recovery, and retained uncertain effects.
The fixture's induced failure is a test input. Native
Fedora validation still needs independent evidence of the real user manager,
rootless confinement, SELinux labels, application and network boundaries.
The authenticated DevBox repair, producer receipt, controlled deployment and
private access also remain separate delivery checks.

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_checklist_quadlet.py -v
```
