# Offline stock Codex state and child-policy component

`tools/codex_state.py` is a standalone acceptance experiment for exact stock
Codex0.169.0. It generates a fixed managed policy and strict layout manifest,
then tests actual binary behavior in disposable bubblewrap namespaces. It does
not launch product jobs, authenticate, make model requests, update installed
runtimes or modify the Fedora CI/gptbox admission path.

Run with an already independently verified binary and a new report destination:

```
python3 tools/codex_state.py --binary /path/to/verified/codex \
  --report /path/to/new-offline-report.json
```

The binary must be a regular non-symlink file of294277432 bytes with SHA256
`b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b`.
The harness captures and hashes one private snapshot, then executes that same
read-only snapshot. It performs no download or fresh signature verification;
retain the original public-input receipt separately. The manifest records the
binary/source pin and executing harness hash. Those identities are not remote
transport authentication.

Linux, Python3.11+, `/usr/bin/bwrap`, working unprivileged namespaces and a usable
stock Codex Linux sandbox are required. An unavailable backend or failed required
check returns exit2 with `status=blocked`; no alternate unconfined backend or
silent acceptance skip exists. Ordinary repository unit tests do not replace this
explicit stock-binary command.

## Generated policy and actual checks

The generator permits one fixed policy schema, with exact keys, scalar types and
values. It does not rely on stock `--strict-config`, which can ignore unknown
managed keys. Requirements pin state/log directories, file credential storage,
managed-only hooks, provider, disabled update/login-shell/browser/remote features,
empty MCP configuration and a single named `product-child` permission profile.
Child approval escalation is `never`; networking is disabled. The child read
allowlist is minimal runtime/tool paths plus the immutable launch directory;
only source/build/tmp receive writes. Credentials, SQLite and logs are denied,
while CODEX_HOME is excluded from the read allowlist except the stock-injected
active helper. Child environment inheritance is `none` with fixed explicit values.

The fixture contains only synthetic noncredential markers. It hides ambient HOME,
`/etc/codex`, sockets, host configuration and credentials. Outer network/user/PID
namespaces and dropped capabilities isolate all subprocesses. The report records
actual UID, kernel, network namespace, capabilities and NNP. Local bwrap ownership
maps the fixture owner; it does not establish distinct root/job ownership.

The required checks use actual stock operations:

- Start app-server during disposable assembly, seed bundled `.system` skills and
  its fingerprint marker, and inventory every regular file/hash. Freeze those
  loader mounts before the acceptance startup. Reject missing skills, discovery
  errors, mutable paths or later inventory changes.
- Compare selected returned managed values exactly, read resolved configuration,
  verify specific managed-write rejection codes and check actual resolved
  `features list` values even when plugins=true is requested. Config/read alone
  is not treated as a complete runtime feature view.
- Keep CODEX_HOME and entire SQLite/log directories writable, including database
  sidecars. Reopen stock processes and check all five actual SQLite databases.
  Delete an explicitly synthetic rollout using stock thread/delete and verify
  ordinary lexical session_index.jsonl rewrite; do not redirect it through a
  per-file symlink.
- Reject config truncation/unlink, skills-root rename and HOME/launch loader
  creation while legitimate state/source/build writes succeed.
- Prove synthetic supervisor markers are readable before running the managed
  child diagnostic. Verify credential/state, symlink and proc-root alias denials,
  cleared environment and product writes. A fresh nested Codex diagnostic using
  `:danger-full-access` must actually execute its inner Python check and still
  fail the credential read. Process recreation cannot undo inherited confinement
  in this measured case. No general broker or cwd-only security claim is made.

The manifest rejects unknown fields and altered policy/layout/binary/harness or
skills identities. Its expected skills inventory comes from the independently
captured assembly filesystem; a caller must not treat two mutually supplied JSON
claims as independent proof. This component generates its own fresh fixture and
never consumes a caller-supplied manifest to grant runtime authority.

## Bounds, cleanup and interpretation

The shared experiment deadline is180s; each command/RPC is clipped to20s and
remaining time. Process groups are killed and reaped on every exit, including an
already-exited launcher whose child retains output pipes; streams close even if
cleanup fails. Each child has a2GiB address-space ceiling,16MiB file ceiling and
no core dumps. Aggregate captured output is2MiB, RPC lines256KiB and the report
4MiB. Fixture storage checks enforce a32MiB state allowance,384MiB total snapshot
allowance and4096 entries, sampled every100ms and after operations. Skills have
an additional2048-file/4MiB-per-file/512-byte-path contract.

Storage sampling is not a filesystem quota: allocation between samples remains a
limit of this local component. Production integration must supply the declared
runtime volume ceilings. Temporary roots are private and removed after owned
process termination; the report retains exact policy/skills identities, actual
RPC evidence, database integrity and bounded operation counts/hashes. Durable
product state is never used or deleted by this experiment.

Exit0 means the offline component checks passed. Every report still sets
`runtime_admitted=false` and lists required gates: actual Fedora/Podman/Distrobox
mount/SELinux/sandbox behavior and toolchain inventory; distinct root/job and
credential-link ownership; every real agent tool path using the managed child
policy; complete loader/model-catalog inventory; authentication/refresh, exact
model entitlement and full UUID/session recovery. Synthetic deletion and SQLite
integrity are not real conversation restoration or R9 acceptance. Fixed cwd
prevents automatic descendant discovery here; it does not alone forbid alternate
supervisor discovery or establish all loader boundaries.

The smallest later integration point is candidate assembly before
`gptbox_runtime.finalize` seals its input identity. Seed the matching system
skills, include generated policy/loader/skills inventory in that identity, and
rerun this component against the actual selected runtime topology. This slice
intentionally does not change that assembly or frozen runtime entry.

Local unit checks:

```
python3 -m unittest discover -s tests -p test_codex_state.py -v
```

They exercise real timeout/output/file limits, exited-parent child cleanup,
fragmented RPC, live storage failure, snapshot identity and schema mutations.
Test-only tiny binary identities exercise the snapshot function; they are never
reported as stock Codex or Fedora evidence.
