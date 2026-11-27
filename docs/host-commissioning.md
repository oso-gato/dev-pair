# Commission the selected Fedora host

Use the verified Hostinger recovery terminal or the named tailnet operator with
separately authorized root access. Follow the [destination inspection and
recovery procedure](destination-release.md) first. Establish the authorized
transport, enforcing Fedora 44, the managed allocation and the protected
maintenance gateway. Keep the independent recovery path available throughout
commissioning. The commissioning command reads these prerequisites through the
existing controllers.

Transfer the exact clean reviewed checkout to the protected bootstrap source
directory. Independently verify the full commit before executing it. Stage the
attested full portable release with the protected platform intake. Provision the
digest-addressed [site plan and host profile](renewal.md), checklist server TLS
profile and any protected product inputs before applying their corresponding
features. The full package must identify the same source as the transferred
checkout. The commissioning manifest fixes the installed scripts, services,
timer files and permissions. The signed host bundle binds those script and
runtime bytes. The fixed checklist recipe comes from the independently pinned
checkout.

The root-owned commissioning policy is mode 0600. Provide its exact SHA-256 from
the separately approved site plan. It has schema 1 and these fields.

| Field | Value |
| --- | --- |
| `source_sha` | Independently selected reviewed checkout commit |
| `machine_id` | The inspected target's machine ID |
| `platform_sha256` | Full attested platform index digest |
| `site_config_sha256` | Approved physical site profile digest |
| `timers` | Sorted enabled features from `agent-renewal`, `checklist-spool`, `owner-intake` |
| `checklist` | Exact D provision options `tls_profile`, `uid`, `subid_start`, `validation_mib`, `validation_inodes`, `live_mib`, `live_inodes`, `reserve_mib` and `reserve_inodes` |

Use the already admitted repository, role templates, provider custody and
allowances for `owner-intake`. The existing intake materializes the job-scoped
grants after the owner confirms an agreement. A checklist workload additionally
requires the trusted client certificate profile and independently verified
checklist builder base in the actual bounded builder store. The standard
[workload prerequisites](product-job.md) describe those inputs. Choose only
features covered by the live site policy. A site can commission the managed
checklist executor with an empty timer list.

Run the read-only inspection before applying the exact same policy.

```sh
cd /root/dev-pair-bootstrap-source
/usr/bin/python3 -IB tools/commission_host.py inspect \
  --source-sha "$source_sha" --policy "$commission_policy" --policy-sha256 "$policy_sha"
```

Compare the reported boot, hostname, transport, listeners and free capacity with
the independently opened destination. Apply after that inspection.

```sh
/usr/bin/python3 -IB tools/commission_host.py apply \
  --source-sha "$source_sha" --policy "$commission_policy" --policy-sha256 "$policy_sha"
```

The entry verifies the protected package and installs its fixed service
closure. It stages the exact platform through the native installer, publishes
the local initial release through the renewal resolver and writes both
selectors under its lock. The checklist provisioner initializes independent
history, then observes the signed service under the persistent boot fence.
Recovery verifies the selected instance and clears the fence. A pending phase
names the owned work in progress. Repeat the same command to join it. An
interrupted initial selector write can be completed only from its protected
intent. Reapplication reads a compatible live successor and retains saved work.

The ready response contains the selected local release, the admitted timer
targets and their observed next firing. The root service for an omitted timer
stays inactive. A selected timer is enabled only after the managed listener and
boot recovery pass. The entry publishes the named operator's constrained sudo
rule after these checks. On the verified tailnet route, the owner can then run
the [normal terminal command](owner-intake.md).

```sh
dev-pair start owner/approved-repository
```

Record a native reboot and verify the current release, Q loopback listener and
next timer firing with the same entry. Separate controlled product promotion
and any subsequent rollout require their approved release paths. The local
commissioning fixture exercises ordering and durable readback with isolated
files and a synthetic manager. Fedora and SELinux commissioning remain required
on the selected target.
