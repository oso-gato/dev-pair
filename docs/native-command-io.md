# Native provisioning command streams

`bootstrap.Commands` retains the existing finite transient services and resource
properties. Its ordinary root wrapper, explicit dp-maint preparation/maintenance
executors, diagnostic-enabled `gptbox.ProbeCommands` and guest image observation
now use [one private transport](../tools/native_io.py). No service stdio descriptor
is passed through D-Bus: systemd-run uses `--wait --collect`, with manager-opened
`StandardOutput=file:`/`StandardError=file:` FIFOs and optional `StandardInput=file:`.
There is no `--pipe`, `--pty`, policy exception, forced SELinux context, host socket
or change to container confinement. Standard restorecon labels apply. Actual
Fedora259 manager access and SELinux behavior remain runtime gates.

Only fixed controller-owned unit grammars/descriptions can allocate transport.
Root controls `/run/dev-pair-command-io`, its records directory and each unit's
0700 directory. Exclusive creation and protected/nonsymlink ancestors reject
collisions. The root-only ownership record persists before allocation; directory
and node device/inode/type/owner/mode/link proofs persist before any stdin bytes
or launch. A failure between creation and proof leaves an unproven object that
is retained. Its name alone never authorizes deletion. Existing initializer unit
registration precedes allocation and binds exact retry to the protected job target.

Each output FIFO and each launcher stdout/stderr pipe has a measured4096-byte
capacity. Thus four native output channels have16384 bytes of kernel capacity,
in addition to the retained aggregate limit and a one-byte overflow sentinel.
Two dummy writers prevent startup EOF and open races; launcher exit releases
them, then capture drains to actual EOF. A descendant retaining a writer cannot
turn launcher exit into false completion: the original deadline still applies.
Consumer death closes readers, yielding SIGPIPE/EPIPE to writers; a producer that
ignores it remains subject to its existing native lifetime.

Combined admitted child-plus-launcher output remains1MiB for Commands and
ProbeCommands with no diagnostic callback,4MiB for the diagnostic-enabled probe
path. Guest image observation retains its narrower256KiB cap. Only child stdout
is application data; launcher output joins bounded stderr diagnostics. Public
operation filtering and tail limits remain. Every stdin-bearing call, including
empty stdin, discards all output while still counting bytes. UTF-8 input is
rejected above16384 bytes before allocation or launch. Its0600 regular file is
proven/persisted before writing; neither contents, content hash, argv nor
credentials/environment enter metadata. No stdin bytes travel through launcher
pipes. No payload LimitFSIZE is installed: DNF/image writes keep their original
behavior. Fixed restorecon setup has a separate8KiB withheld capture bound within
the same deadline.

Remaining absolute phase and command time clips native RuntimeMaxSec again after
transport setup; setup cannot give the separately spawned service a fresh budget.
Memory/tasks/CPU/stop/cgroup limits and900s staging/180s runtime ceilings are
unchanged. Kill/reap and exact native reconciliation occur even after the launcher
has already exited. Loaded foreign descriptions/users block before stop; a
collected/not-started unit is not execution proof. Manager queries use a separate
bounded non-native runner to avoid recursive services.

After known inactivity/not-found and closing descriptors, cleanup verifies every
recorded identity and rejects extra/replaced entries. A persisted cleanup intent
permits resuming deletion of missing previously-proven nodes after interruption.
Foreign symlinks/inodes and uncertain records remain. Root-only stdin is removed
on normal success, failed start/status, overflow, timeout and handled interruption
when ownership/native stop are verified; unresolved cleanup blocks acceptance.
There is no global scan, reset, truncate/adopt or deletion based on a filename.

SIGKILL/power loss cannot run finally. In particular a root-only stdin file may
remain before native launch. The existing external initializer/exact adapter
retry reconciles registered units and their matching transport records before
reapplying; reboot removes volatile `/run`. Until that occurs, secret removal is
unverified. Native lifetimes alone do not delete input files. An unproven creation
or foreign collision can require explicit operator reconciliation. No immediate
all-crash cleanup or blanket active-engine cleanup is claimed. Guest
`password_absent` refers to its original disposable password pathname; the
initializer cleanup record remains authoritative about unresolved transport
copies, and whole-VM teardown is the final disposable boundary.

## Security evidence

The guest projects only structural AVC/USER_AVC security fields: type/event ID,
optional PID/known comm, SELinux contexts, class, permissions and optional
permissive flag. Numeric aliases1400/1107 and no-comm USER_AVC are accepted. Nested
USER_AVC msg is parsed separately from its audit header; quoted path/name/exe/
proctitle/argv/environment payload is never rescanned or exported. Duplicate or
malformed fields reject the record. Individual lines are4096 bytes, contexts192
characters, permission lists8 tokens of32 characters. Up to8 records and3000
serialized bytes are selected, preferring latest known domains/comm. Counts cover
only captured input and distinguish typed, malformed and omitted records.

Ausearch keeps its64KiB/15s bounds (or remaining final-evidence budget). Overflow
retains a bounded prefix for structural projection and explicitly marks it
incomplete. Unavailable/zero-selected evidence never proves absence of denials.
No arbitrary audit/journal body is exported. Root filesystem type and only selected
quota flags are a separate bounded diagnostic from the exact `/` mountinfo record;
no mount source/path/options are returned and no new admission gate is added.

Run `python3 -m unittest discover -s tests -q`. Local FIFO/process tests use real
kernel streams, capacities, subprocess output/EOF/timeouts, secret input, consumer
death, ownership journal persistence, collisions and cleanup failure recovery.
Their manager/root ownership boundary is explicitly injected; they are not native
systemd/Fedora evidence. Adversarial audit fixtures check nested/quoted fake fields,
no-comm records, size/count caps and secret-sentinel exclusion. A fresh reviewed
Fedora run must still validate manager-opened files, labels, effective identities,
all native paths and actual failed-start/timeout/secret cleanup.
