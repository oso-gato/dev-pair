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
