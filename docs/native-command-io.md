# Native provisioning command streams

`bootstrap.Commands` retains the existing finite transient services and resource
properties. Its ordinary root wrapper, explicit dp-maint preparation/maintenance
executors, diagnostic-enabled `gptbox.ProbeCommands` and guest image observation
now use [one private transport](../tools/native_io.py). No service stdio descriptor
is passed through D-Bus: systemd-run uses `--wait --collect`, with manager-opened
`StandardOutput=file:`/`StandardError=file:` FIFOs and optional `StandardInput=file:`.
There is no `--pipe`, `--pty`, policy exception, forced SELinux context, host socket
or change to container confinement. Standard restorecon labels apply. Run14 observed `init_t` denied writing the old
`var_run_t` FIFO before getenforce executed; this source repair is not native
Fedora evidence. Manager access, direct and multi-hop package-script transitions
and actual cleanup remain runtime gates.

Only fixed controller-owned unit grammars/descriptions can allocate transport.
Root controls `/run/dev-pair-command-io/records` for ownership journals and
`/run/systemd/dev-pair-stdio/<unit>` for each 0700 stream directory. The existing
`/run/systemd` parent is only validated; it is never relabeled, changed or cleaned.
Only the owned stream subtree and exact nodes receive restorecon. Both
matchpathcon and observed `security.selinux` must equal the standard
`system_u:object_r:init_var_run_t:s0`; an unexpected policy/label blocks.
Version3 journals bind stream and exact-unit profile ownership. Version2 records
retain stream-only cleanup authority and never acquire ownership of a discovered
mask; unexplained masks block. Version1 records and legacy app-root streams remain
preserved for deliberate reconciliation. Exclusive creation and protected/nonsymlink ancestors reject
collisions. The root-only ownership record persists before allocation; directory
and node device/inode/type/owner/mode/link proofs persist before any stdin bytes
or launch. A failure between creation and proof leaves an unproven object that
is retained. Its name alone never authorizes deletion. Initializer registration covers only the root wrappers constructed by Commands.
Explicit dp-maint context units keep their protected transport journal and are
reconciled by the existing exact-context retry path with User=dp-maint; they never
enter the root-only initializer inventory. Registration precedes node allocation
and binds exact retry to the protected job target.

A protected source-derived helper is installed at the content-addressed, root
0444 `/usr/local/libexec/dev-pair-native-io/<sha256>/relay.py`. Existing bytes,
owner, regular type, single link, mode and ancestors are verified; conflicting
artifacts are preserved. The same existing unit executes `/usr/bin/python3 -I`
with that exact helper hash, UID and remaining deadline. Before reading stdin it
sets core size0, sets/verifies nondumpable state, and checks actual UID/context
and inherited manager descriptors. No explicit process label is set.

The helper gives the admitted payload fresh anonymous pipes, closes manager
descriptors in the child and keeps the existing service UID, cgroup and limits.
Every manager FIFO, launcher pipe and child pipe has a measured4096-byte
capacity: six pipes without stdin (24576 kernel bytes), seven with stdin
(28672 bytes). Relay output queues total at most8192 bytes; optional input is
at most16384 bytes. No payload LimitFSIZE is set. The helper multiplexes
nonblocking streams with backpressure and a finite deadline, reserving100ms
inside the original remaining command budget for owned child-group cleanup
(or half the remaining budget when shorter than200ms). The controller passes
an absolute host CLOCK_MONOTONIC deadline; setup and service startup consume it.
The helper checks it before reading input, during input admission and immediately
before payload launch. It never restarts a relative time window. Its bounded
kill/reap does not replace native cgroup reconciliation or prove escaped
engine helpers stopped.

Stdout stays raw. Helper stderr uses an8-byte header plus data bodies of4096
bytes (one final partial allowed), followed by exactly one control frame of
at most256 bytes including its header. Control binds actual payload status,
observed UID/domain, helper hash and closed profile-proof version1. Parent admission requires complete framing,
no duplicate/trailing control, and exact agreement for normal nonnegative exits.
Signaled payloads are rejected independently of caller allowed statuses. Systemd
can map clean TERM/INT/HUP/PIPE to0 and other service signals to255; neither
translation may turn a signaled payload into a successful command.
Missing helper evidence rejects service startup exits even when a caller accepts
that numeric status. Exit250 is reserved for relay failure and is never accepted.
For the256KiB/1MiB/4MiB decoded limits, raw framing overhead is bounded separately
at768/2304/8448 bytes. Payload stderr that resembles control is wrapped as data.
This prevents stream impersonation by admitted payload output; it does not
isolate arbitrary malicious root code. Root payloads are fixed privileged
provisioning operations under the existing controller boundary.

Two dummy writers prevent startup EOF and open races; launcher exit releases
them, then capture drains to actual EOF. A descendant retaining a writer cannot
turn launcher exit into completion. Consumer death closes readers and yields
EPIPE/SIGPIPE; the helper kills/reaps its payload group on handled failure.
Controller interruption and exact native reconciliation remain authoritative.

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

Remaining absolute phase, command and stricter caller lifetime are checked after
transport setup. Type=exec activation has a separate TimeoutStartSec: at most5s
and half the remaining budget. Active RuntimeMaxSec receives only the rest, with
both values rounded down and required to stay positive milliseconds. Startup
plus active time stays within the original envelope; existing stop grace is
separate. Caller startup overrides are rejected. Setup cannot give the separately
spawned helper a fresh budget.
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
all native paths and actual failed-start/timeout/secret cleanup. Local relay tests
execute the real helper pump and completion parser; only Fedora manager/UID/label
admission is injected. They cannot establish SELinux transition compatibility.

## Exact transient profile before any payload

Fedora's global `service.d/10-timeout-abort.conf` is parsed after transient fields;
CLI kill-mode properties alone cannot establish an effective stop bound. The
controller exclusively creates only
`/run/systemd/system/<canonical>.service.d/10-timeout-abort.conf`, an empty root
0644 regular file in a root0755 exact-unit directory. It never changes a prefix
or global mask. Both directory and file inode/type/mode/owner/link proofs are
journaled before input or launch. A standard restorecon labels only these owned
objects; expected matchpathcon and actual labels must agree. Label queries and
restorecon are batched with the owned streams/helper to fit the existing budget.

The controller reads the manager's bounded UnitPath and accepts only the declared
system lookup locations (with the validated conventional `/lib` alias). It scans
applicable exact, dash-prefix and type-global drop-ins/dependencies in every
location. Unknown configuration, fragments/aliases, symlinks, unsafe ownership,
extra dependency entries, bounds, unreadability or observed changes block before
StartTransientUnit. Only the stock vendor basename and the exact owned empty
mask may exist. Vendor contents are never copied or treated as accepted policy;
the exact mask must shadow the complete file. This is a conservative scanner,
not a general systemd configuration interpreter. All three directory inventories
use context-managed streaming os.scandir rather than Path.iterdir/list/set
materialization. Configuration count/name-byte/deadline limits apply as entries
arrive; profile and stream verification stop at the first foreign/duplicate name.
The same command deadline, or existing bounded reconciliation deadline, applies
to owned verification. Iterators close on success, rejection and interruption.

A fresh NOT_FOUND/inactive observation is required; loaded inactive units are not
reused. After exclusive mask-directory creation, its lookup parent's identity
must be unchanged and its mtime must strictly advance at microsecond resolution.
A second NOT_FOUND observation refreshes v259's lookup map. UnitPath and applicable
snapshots are checked again immediately before launch. No per-command reload,
parent-directory touch, sleep or retry loop is used. This cache sequence is
source-backed and remains an actual Fedora runtime gate.

The fixed launch profile sets start/stop failure modes to kill, SendSIGKILL=yes,
FinalKillSignal=SIGKILL, control-group killing, Restart=no, system.slice and the
existing2GiB/512tasks/100%CPU limits. Root commands retain5s stop grace, maintenance
contexts10s, image observations1s; observation retains its10s operation and256KiB
capture path. Start plus active timers remain inside the prior absolute command,
phase and stricter caller lifetime. No container/SELinux/privilege change occurs.

Before reading stdin or starting the payload, the immutable relay uses three
fixed stock busctl --system --json=short invocations: Manager.GetUnit, seven
exact Unit Properties.Get names, then28 exact Service names. All three share
one5s deadline clipped to the original deadline and one8192-byte stdout+stderr
cap. Each uses clean environment and measured4096-byte anonymous pipes. There
is no GetAll, introspection, show fallback or caller-supplied property/interface.
The bounded typed JSON parser rejects duplicate/missing/extra records, wrong
signatures/widths, boolean/integer coercion, and method/property shape confusion.
Method replies wrap their values in an outer array; property data is direct.
SELinuxContext must be the exact (bs) value [false,""], not an empty string.

The gate verifies MainPID, canonical ID, all four kernel UID/GID values,
system.slice membership, fragment, single exact DropInPaths array, timers,
kill/resource settings, readable stdio modes and absent isolation overrides.
No Environment, ExecStart/hooks, StandardInputData or credential value is queried.
The pipes/buffer replace later payload resources. Missing busctl or read access
blocks; no policy exception or new package is introduced.

The *File names are setters without readable getters in audited v259. Instead
the controller re-verifies its existing journal and passes only bounded decimal
device:inode pairs for the two distinct output nodes and optional regular input.
The helper fstats its inherited FD0/1/2 against those exact pairs, retaining root
owner/mode/link/type/capacity checks, O_WRONLY outputs, O_RDONLY input/null and
zero regular-input offset. No-input requires kernel /dev/null. It never traverses
the root0700 stream paths or reads the journal. Swapped/replaced/duplicated
objects fail even when other metadata matches. These nonsecret expected pairs
never enter diagnostics. FD2 is verified first; when that failure channel itself
is unproven, the helper emits no F frame and cannot emit successful completion.

A rejected effective gate emits only a terminal F diagnostic frame (at most256
bytes): fixed stage/reason, whitelisted property/query group/FD and safe category.
GetUnit/UnitGet/ServiceGet distinguish failed query groups without raw output.
It cannot satisfy successful completion, including accepted numeric exits0/1/4.
Success still requires the distinct complete C frame with profile-proof version1.
Prelaunch failures retain fixed admission stage/reason and elapsed time. Probe
metadata preserves these fields alongside its existing bounded output; no raw
UnitPath tree, arbitrary exception, journal, environment or credential is emitted.

After exact owned-unit inactivity/not-found, a bounded cgroup.events observation
must establish populated=0 or absence before cleanup. A durable cleanup intent
then permits only previously proven missing nodes. The mask is unlinked using a
verified directory FD and rechecked file identity, and only its exact empty
owned directory is removed. The journal survives until profile and streams are
both removed. Unproven creation gaps, foreign replacements, extra entries and
uncertain native state remain blocked. SIGKILL tests exercise intent, unproven
mask and proven-mask recovery; no finally-after-crash cleanup is claimed.

Local tests use real filesystem/FIFO/process effects with explicitly injected
root/manager boundaries. Effective-property mutation tests include all three
families, MainPID/UID/GID/cgroup, deadlines, resources, stdio and unknown overrides;
failed gates have no payload/input effects. Native cache discovery, installed
SELinux policy, stock D-Bus reads, effective timers/cgroups and engine/package
transitions still require a separately reviewed actual Fedora run.

The parent controller's existing systemctl show operations still perform GetAll
internally, even when their printed columns are selected. This correction does
not claim a no-sensitive-property-read contract for those other paths; their
audit/migration is a declared separate limitation. The independent local private
session-bus probe used installed systemd257.13 and verified JSON shape/order only.
It did not contact a host bus and is not Fedora259, SELinux or native acceptance.

Configuration scans compare directory device/inode, type/mode, UID/GID, link
count, size and exact nanosecond mtime/ctime across enumeration. Access time is
excluded because enumeration itself may update it. This keeps security and
configuration mutations blocking without rejecting a read alone. Cache-recheck
failures retain fixed subcondition/category codes; no exception text, paths or
configuration content enter those diagnostics. A local atime regression does
not establish the cause of any prior native failure.


The native controller retains a closed failure point/category and the owned
launcher's status sampled before its existing interruption/cleanup path. A null
sample means the launcher was still running at that observation; an unavailable
sample means no status was established. The later `native_exit_status` remains
separate and may reflect cleanup. Neither status proves descendant termination.
Decoder witnesses contain only fixed reasons and bounded structural counts and
flags from the existing failing predicates. A complete control shape is not
independent acceptance: identity, helper and native status checks still apply.
The public witness is limited to 1,536 bytes and validates exact source, context
and prepare/maintenance phase binding. Invalid or missing evidence is unavailable.
There is no new prelude frame or probe: failure before the existing safe framed
channel is established can remain unavailable. These diagnostics do not change
accepted frames, native profile checks, subprocesses, deadlines or cleanup.


Relay artifact staging does not rely on the provisioning umask. It walks the
fixed artifact ancestry with no-follow directory descriptors and compares
observed path/descriptor identities. Only a successful new directory creation
authorizes fchmod0755 on that exact descriptor. Existing shared ancestors and
private transport paths are never chmodded. Every artifact ancestor must remain
root-owned, non-group/world-writable, nonsymlink and traversable by other users
at the checked mode boundary. New conventional parents at the fixed path are
supported; existing inaccessible directories fail closed. Incomplete0700 paths
left by interruption remain blocked, with no unproven generic ownership repair.
Final chain/file identity and exact immutable0444 bytes/link checks are retained.
This relies on the existing trusted-root filesystem boundary; local descriptor
checks are not a hostile-root or SELinux/ACL attestation.

A failed final configuration comparison can include a closed `cache_comparison`
inside the existing native failure witness. It compares only the two already
captured bounded tuples. Row counts, multiset/order-only equality, the first
unmatched known row's before/after index, fixed manager lookup index/path class
and changed-field bits are public. Bits are presence, device, inode, mode, UID,
mtime and size. An order-only difference has zero field bits and remains
rejected. Lookup indices use the sorted fixed allowed manager paths with the
conventional /lib alias mapped to /usr/lib. Unknown/oversized rows are explicitly
unavailable; no names or raw metadata are exported. Source/context/phase and
cache-final-comparison binding, 1,536-byte projection, primary rejection,
pre-interrupt status, exact cleanup and every deadline/output bound remain.


Canonical /lib and /usr/lib aliases can produce duplicate snapshot path rows.
The comparison witness cancels balanced row counts before choosing a same-path
surplus counterpart. Only a unique surplus field comparison with matching
multiplicity is reported; ambiguous duplicates are unavailable. Balanced alias
rows cannot conceal an inode change by becoming the replacement counterpart.
The original ordered tuple inequality still blocks, including order-only changes.
