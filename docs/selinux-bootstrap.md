# Initial Fedora 44 SELinux convergence

[tools/selinux_bootstrap.py](../tools/selinux_bootstrap.py) implements a separate
initial-provisioning transition before the normal [host preparation](fedora-bootstrap.md).
It has local filesystem/state tests and unit syntax verification only. It has
**not run on Fedora or the designated VPS**, relabeled a real filesystem,
rebooted a host, or established container confinement. No workload is admitted
by this helper. Normal preparation still requires enforcing mode and refuses
an incomplete recorded transition, including a partial finalization that has
already changed the live mode.

Use only the exact independently reviewed checkout, transferred as root-owned
code with protected nonsymlink path components. Record its full Git revision
and the two-file code digest outside the target through the authorized handoff.
The digest binds both `tools/selinux_bootstrap.py` and `tools/bootstrap.py`;
calculate it from the reviewed checkout, rather than treating a target's
self-reported hash as approval. Keep the original SSH session and independently
verified provider-console recovery available. These commands belong on the
authorized fresh Fedora host, not the development machine:

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/selinux_bootstrap.py inspect
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/selinux_bootstrap.py converge
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/selinux_bootstrap.py converge --apply \
  --expected-code-sha256 TRUSTED_TWO_FILE_DIGEST --source-sha REVIEWED_FULL_COMMIT
```

`inspect` and `converge` without `--apply` are read-only. The applying command
above stages the transition and reports a pending reboot; it does not reboot.
To authorize the setup reboots and automatic continuation, use:

```sh
sudo /usr/bin/python3 /root/dev-pair-bootstrap-source/tools/selinux_bootstrap.py converge --apply --reboot \
  --expected-code-sha256 TRUSTED_TWO_FILE_DIGEST --source-sha REVIEWED_FULL_COMMIT
```

The existing owner authorization covers scoped setup reboots, but this tool
requires the explicit flag. With it, normal operation requires no operator
coordination between phases. A staged transition can later be resumed using
`converge --apply --reboot`; its protected intent keeps the original code target.
An interrupted or failed attempt retains evidence under
`/var/lib/dev-pair/selinux-bootstrap`. Do not delete markers or edit state to
make a failed transition appear complete.

The transition follows these boundaries:

- Inspect Fedora 44, systemd, the boot ID, live mode, persistent mode, targeted
  policy and kernel arguments. Reject disabled/foreign LSM arguments,
  `enforcing=0`, any persistent `autorelabel` word trigger (including
  `autorelabel=0` and a forced autorelabel target), and arguments preventing the
  required permissive transition. Do not edit the bootloader. Preserve an already-enforcing host;
  no downgrade, relabel or setup reboot is requested for that path.
- For Disabled or Permissive, install signature-checked Fedora policy/tools,
  confirm targeted policy exists, and bind the reviewed code target. A
  permissive live mode is never accepted as evidence of completed labeling.
  Reject foreign autorelabel units/drop-ins/masks and a changed installed
  vendor unit using its `policycoreutils` RPM ownership/verification.
- Install protected 0555 copies of the two reviewed files and a narrow
  override of Fedora's autorelabel unit. Preserve unrelated SELinux config
  content while setting the transition to permissive. Reconcile an interrupted
  config/marker write before requesting reboot. Use `restorecon` on installed
  code, managed state/configuration and units; no global labeling exception or
  disabled container label separation is introduced.
- On a different permissive boot, the helper selects writable `seclabel`
  mounts from the actual mount inventory, requires writable labeled coverage of
  the root and system trees, and honors configured exclusions outside those
  required trees. Read-only mounts are explicitly excluded. Conflicting critical
  exclusions, ambiguous overmounts or unsupported paths block without rewriting
  their configuration. Excluded/read-only ancestors of an admitted writable mount block because native
  exclusions would also skip its descendants. The RPM-verified native
  `/usr/bin/setfiles` path supports Fedora 44's merged `/usr/sbin -> bin` layout
  and retains its
  physical/XDEV traversal and non-seclabel mount exclusion; no naive recursive
  host walk or `-m` override is substituted.
- The fixed native command uses `setfiles -E -C -F -I -T 1`, the targeted file
  contexts and admitted mount/exclusion arguments, with a thirty-minute limit. Command timeouts terminate the entire subprocess
  group and reap the direct child; both owned units also stop their full control
  groups with a ten-second stop limit.
  Its actual nonzero/error-count exit blocks completion. A protected plan records
  mounts, exclusions, persistent filesystem UUID/FSROOT/type identities and the
  context inputs, including local/home-directory/substitution and compiled
  companions. Successful completion binds that plan, method, code and relabel
  boot ID. Finalization rejects changed persistent identities, exclusion config
  or context inputs, while new noncritical transient tmpfs mounts such as
  `/run/user/0` do not invalidate persistent relabel evidence. No `fixfiles` shell-wrapper exit is
  accepted. Managed-path relabeling must also succeed before the helper
  removes/fsyncs its marker and requests the next authorized reboot.
- Failed or interrupted relabels retain the marker; at most two full attempts
  are allowed, with systemd restart limits. Reboot commands have at most three
  attempts per boot and six total; the incomplete transition admits at most four
  distinct boots. A crash after durable native completion but before marker
  removal can consume one protected extra-boot allowance, recorded before
  cleanup. It removes only the exact owned marker, requests at most that one
  extra boot, and then uses normal-boot finalization. The allowance cannot reset
  after another crash. Unexpected relabel-target reentry without an owned marker
  blocks. Exhaustion is a recovery blocker, never a reboot loop or an implicit
  permanent permissive configuration.
- A narrow normal-boot service automatically verifies the installed code,
  checked completion and a boot ID distinct from both the original and relabel
  boots. Only then does it call `setenforce 1`, require live Enforcing readback,
  persist/verify enforcing configuration and record completion. It removes the
  temporary override and disables itself only after that success. Failure keeps
  the transition incomplete; cleanup after recorded success can be retried.

The override deliberately replaces the vendor script and the `fixfiles restore`
wrapper: Fedora 44's upstream 3.11 wrapper can report success after a failed
`setfiles` call or an empty filesystem list. Direct checked native execution
avoids that lost status. Disappearance of `/.autorelabel` alone is never success. Reference unit
and script inspection used the Fedora `policycoreutils` f44 packaging sources:
`https://src.fedoraproject.org/rpms/policycoreutils/raw/f44/f/selinux-autorelabel`
and the corresponding `.service`, `.target`, mark-service and generator files.
Native behavior was inspected at
`https://raw.githubusercontent.com/SELinuxProject/selinux/3.11/policycoreutils/setfiles/setfiles.c`
and `libselinux/src/selinux_restorecon.c`; the wrapper defect is in
`policycoreutils/scripts/fixfiles` at that same revision. Those references describe
vendor behavior; signature-checked, RPM-verified packages supply target code. The A11 historical implementation informed the transition design only;
its suppressed enforcement failures and broader policy were not imported.

A failed early autorelabel boot may remain in the dedicated relabel target;
provider-console recovery is essential. Existing root/SSH configuration is not
retired or rewritten. Missing policy, conflicting configuration, exhausted
attempts, code drift or failed enforcement produce blocked state and local
journal evidence. The tool does not silently repair a foreign bootloader or
substitute a steady permissive fallback.

Real acceptance still requires a designated disposable/authorized Fedora target:
exercise initial Disabled and Permissive states, checked relabel failure and
interruption, both setup reboots, successful automatic normal-boot finalization,
retained recovery, persistence after another boot, managed-path labels, and
actual container confinement. Initial Enforcing must remain enforcing. An
independent exact-candidate review and those runtime results remain required
before claiming R7.19/A7.7 acceptance.
