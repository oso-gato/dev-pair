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
  `enforcing=0`, and any boot argument that prevents the required permissive
  transition. Do not edit the bootloader. Preserve an already-enforcing host;
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
- On a different permissive boot, the checked helper runs fixed
  `fixfiles -F -T 1 restore` arguments with a thirty-minute command limit.
  It records completion and the actual relabel boot ID only after success and
  managed-path relabeling. It then removes/fsyncs its marker and requests the
  next authorized reboot. Failed or interrupted relabels retain the marker;
  at most two full attempts are allowed, with systemd restart limits. Reboot
  commands have at most three attempts per boot. Exhaustion is a real recovery
  blocker, never a repeated reboot loop or an implicit permanent permissive
  configuration.
- A narrow normal-boot service automatically verifies the installed code,
  checked completion and a boot ID distinct from both the original and relabel
  boots. Only then does it call `setenforce 1`, require live Enforcing readback,
  persist/verify enforcing configuration and record completion. It removes the
  temporary override and disables itself only after that success. Failure keeps
  the transition incomplete; cleanup after recorded success can be retried.

The override deliberately replaces the vendor script's unchecked `fixfiles`
call; disappearance of `/.autorelabel` alone is never success. Reference unit
and script inspection used the Fedora `policycoreutils` f44 packaging sources:
`https://src.fedoraproject.org/rpms/policycoreutils/raw/f44/f/selinux-autorelabel`
and the corresponding `.service`, `.target` and mark-service files. Those
references describe vendor behavior; signature-checked packages supply target
code. The A11 historical implementation informed the transition design only;
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
