# Submit and follow a dev-pair product job

The protected product conductor records a brief, starts a detached systemd
worker and exposes the saved progress. The worker runs maintenance and DevBox
through the existing renewal registry. It builds the exact checklist candidate,
runs the approved host persistence check and sends the durable result into the
DevBox turn. A changed DevBox commit gets a new build, checkpoint and host
request. The fixed checklist adapter permits one changed retest per job.

The job and role interfaces accept an authorized repository ID and Git
revision. The first build and validation adapter expects
`examples/checklist/checklist.py` in that repository. The checklist persistence
result measures that criterion and records the two admitted role turns.
Other acceptance checks in a brief need their own agreed evidence.

## Prepare the authorized job

Provision the existing maintenance and nested DevBox placements, the
standards cache, real provider channel and reviewed release selection.
Use the existing [role entry](role-entry.md) to approve acquisition and
startup. Provision the [Fedora checklist executor](host-handoff.md#fedora-checklist-quadlet)
and compatible destination preload controller. The host conductor uses the
pinned development mTLS profile at `/etc/dev-pair/checklist-client`.

Create the root-owned mode-0700 directory
`/var/lib/dev-pair/product-jobs` with its mode-0600 `owner.lock` and mode-0700
`jobs` and `profiles` directories. Install the trusted product sources and
the reviewed runtime dependencies at `/usr/libexec/dev-pair`. Install
[`dev-pair-product@.service`](../runtime/product-job/dev-pair-product@.service).
Install the companion [tmpfiles entry](../runtime/product-job/dev-pair-product.conf)
after provisioning the checklist account. The service limits each worker to
25 minutes. A temporary fence or lost host reply is saved as a waiting state.
Automatic observations have a three-minute and 18-observation limit for
each unfinished step. If the limit is reached, the same submission can
continue when the environment is ready. Status and reattach read the protected
job record. An identical submission can also restart the worker after a host
reboot. Protected registry reservations and the host effect ledger determine
which steps can proceed.

Provision both role workspaces at the approved starting commit and canonical
repository origin. The conductor uses the ordinary `dp-dev` account for
read-only Git object capture. Give `dp-maint` a mode-0700
`/var/lib/dev-pair/maintenance/conductor-inputs` for its bounded local Git
handoff, and `dp-checklist` a mode-0700
`/var/lib/dev-pair/checklist-executor/conductor-inputs` for typed ledger inputs.
The maintenance turn uses the approved starting candidate and leaves its
worktree clean. Following a DevBox commit, the conductor imports an exact
bounded Git bundle into the maintenance checkout under its own UID and checks
the new HEAD. It preserves dirty work and stops if a checkout would overwrite
it. Synchronization and checkpoint publication hold the renewal fence.

The controlled Fedora setup provides separate `builder/graph` and
`builder/tmp` mode-0700 leaves for `dp-checklist` on the existing bounded
validation filesystem, plus its private user runtime directory. Preload the
independently verified Python and SQLite base in the builder graph. Save the
fixed reference and verification digest in the root-owned
`/etc/dev-pair/checklist/build-base.json` with fields `version` (1),
`image` (the exact OCI digest reference) and `verification_sha256`.
The issuer checks the rootless storage roots and actual base manifest. It
runs the checklist filesystem verifier as the designated checklist UID and
binds the observation to the mount seen by the conductor. It extracts one
bounded, regular Git blob and copies it with the trusted Containerfile to one
root-owned context at `/run/dev-pair/checklist-build-inputs/active`. The
checklist group can traverse the context and read both files. Only root can
modify the context. The rootless builder writes its archive to a separate
private spool on the bounded validation filesystem. The fixed build command
disables networking and pulling.
It verifies the single-platform OCI manifest and configuration digests across
archive export and load. The destination's `preload-validation --apply` checks
the same image ID, digest and source in the owned validation graph before
the conductor publishes its named root-owned receipt. The build never runs
a command supplied by the repository.

## Job and role inputs

Use a root-protected JSON plan like this one, with actual authorized values.

```json
{
  "schema": 1,
  "job_id": "checklist-first",
  "adapter": "checklist-quadlet",
  "startup_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "agreement": {
    "repository": "owner/approved-product",
    "initial_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "brief": "Repair the checklist so the same completed item survives a service restart.",
    "host_seconds": 60,
    "build_seconds": 240,
    "turn_seconds": 120
  }
}
```

Run `product_job.py agreement-id JOB_PLAN` to obtain the exact agreement ID
for `gptbox.py approve-job`. The plan's startup digest must match that
approval's captured private startup corpus. Approve acquisition and startup
under their existing protected paths before submission.

For each role, provision
`/var/lib/dev-pair/product-jobs/profiles/JOB/ROLE/profile.json` and its
`seed/` directory under root custody. The profile contains
`runtime_sha256`, `binary_sha256`, `layout_sha256`, `credential_ref`
(the protected credential's name) and `grant` (the owner-approved broker
grant fields except the generated `schema`, `request_sha256`, `peer_uid`
and `peer_gid`). The provider allowance and full input and tariff evidence
stay in the [protected role provider setup](role-entry.md#launch-a-protected-job-turn).
The scope uses GPT-6.2 Sol High for both implementation roles. Provider model
availability and actual usage come from the independent broker evidence.

The seed is the protected, MCS-labelled operation tree described under
[role entry](role-entry.md#launch-a-protected-job-turn), including the approved
startup and approval files and two readonly placeholder leaves at
`turn/request.json` and `turn/prompt.txt`. The conductor copies that tree
with the existing bounded renewal copier and replaces just those two files,
preserving their labels and permissions. It binds the actual prompt and
checkpoint to the generated provider authorization, validates the authorization
against the separately approved allowance, and launches via the normal
`Renewal.role_turn` entry. The installed driver owns the actual role runtime,
broker and cleanup. The job grant carries no raw credential.

## Submit and return

Run from the authorized operator route.

```sh
product=/usr/libexec/dev-pair/tools/product_job.py
sudo /usr/bin/python3 -EBs "$product" submit "$approved_plan"
sudo /usr/bin/python3 -EBs "$product" status checklist-first
sudo /usr/bin/python3 -EBs "$product" reattach checklist-first
```

The detached service can continue when the client leaves. Reattach streams
changed durable state for up to two minutes per connection. Its record carries
the agreement, startup, candidate, role operation and session identities, plus
both host receipts and their individual effect IDs. After a lost mutation
reply, the conductor reads the exact authenticated request status. It can
consume a completed result immediately. A bounded worker retry checks the
same stored request before acting again. The host executor can reconcile
proven interrupted effects. Unknown outcomes remain blocked. The same job ID
always retains its original brief.

The development turn receives the original brief and exact host verdict,
including failure diagnostics. It must finish with a structured candidate SHA
and summary. The issuer verifies that SHA against the actual authorized Git
checkout and acquisition ancestry before producing a fresh artifact. A job
whose starting candidate already passes can validate an unchanged candidate.
To verify the failure and repair journey, use an authorized starting commit
whose real native observation reproduces the defect.

## Evidence and deployment boundary

The implementation targets the P schema-2 stock role entry, R ordinary
registered turn and ledger access, Q version-1 authenticated host operations,
and D prior-to-cutover preload. The local tests use real Git objects and an
OCI archive metadata fixture. The conductor's local workflow check uses a
fixture role/host adapter to exercise durable resume and effects. Native
rootless build/load, enforcing SELinux labels, authorized provider turns,
a DevBox-authored repair, and actual destination delivery require live proof.

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_product_job.py -v
```
