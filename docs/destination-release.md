# Bootstrap and release on erebus

This procedure covers the authorized Hostinger Fedora 44 destination, the checklist host executor and the production checklist. Run it from the selected VPS root terminal or named `core` administration with separately authorized sudo. Provisioning, release and independent client observations are still required on the real host.

## First inspection and access

Open an authenticated hPanel browser session and select the VPS shown as `erebus`. hPanel account authentication and the VPS root credential belong to different login boundaries. Use the protected VPS root credential only at a VPS root prompt. Before transfer or mutation, compare the hPanel VPS identity with the terminal target, independently reopen an authorized provider recovery path, and record how each session reaches the VPS. SSH metadata or ancestry establishes an SSH-backed terminal. An empty `SSH_CONNECTION` leaves the transport unresolved. Inspect current operating system, host identity, disks, mounts, CPU, memory, addresses, listeners, services and SELinux state. Use the read-only shell inventory if the staged tools or Git are unavailable.

```sh
id -u
hostname
uname -m
cat /etc/os-release /proc/1/comm
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
df -hT / /var
df -i / /var
free -m
nproc
ip -brief address
ss -lntu
getenforce
systemctl list-units --state=failed --no-legend --no-pager
```

Transfer the independently verified exact platform checkout to protected `/root/dev-pair-bootstrap-source`, with an external full commit pin. The observed planning baseline was `657eec5d0d16a56fb34360af9883777ea3e51f31`. Use the independently reviewed integrated successor for this procedure. On a minimal Fedora image, the signed `git-core` prerequisite can be installed during explicitly authorized setup after the first inspection and independent recovery verification. Verify the transfer before executing its code. Issue boot-bound evidence again after a setup reboot.

```sh
cd /root/dev-pair-bootstrap-source
/usr/bin/python3 -EBs tools/bootstrap.py console-inspect --source-sha "$platform_sha"
```

For verified out-of-band access, the authorized transport verifier records `provider: hostinger`, the selected `provider_vps_id`, `transport: out-of-band`, `reopened_root: true` and externally observed `public_ssh_denied: true`. Add `version: 1`, `source_sha`, `machine_id`, `boot_id`, and integer Unix `issued_at` and `expires_at`, within two hours. Sign the exact receipt bytes in the `dev-pair-destination` namespace using an existing authorized signer mapped to `dev-pair-provider-console` in the protected `/etc/dev-pair/trust/allowed_signers`. Place the receipt and its `.sig` sibling in a protected root directory. The inventory command needs no signing key or receipt.

Reserve the pristine managed filesystem before the SELinux transition or initialization. Select its size and inode count from the inspected capacity and agreed role and application allocations. The installer mounts a fully reserved ext4 image of at most 20 GiB from `/var/lib/dev-pair-managed.ext4` at `/var/lib/dev-pair` with a fixed enrolled loop device. It requires 8 GiB of physical free space alongside the allocation. Ext4 and XFS parents also require at least 4,096 free inodes. For a single-device Btrfs parent, the same reserve argument budgets two available metadata nodes per requested recovery inode, measured in already allocated metadata space after kernel reservations. The stock Fedora Cloud 44 node size of 16 KiB gives a 128 MiB metadata reserve for the default request. The backing uses NOCOW and verifies exclusive, uncompressed extents before and after formatting. Keep the backing outside snapshot or reflink operations that would share its reserved extents. The managed ext4 and its child filesystems retain finite inode tables.

Verify Fedora and the local ext4 tools are available. An interrupted ambiguous backing file remains preserved. On a host with a previously completed and disarmed SELinux transition, the helper accepts only that exact protected state beside the empty mount root. It durably preserves the original directory at `/var/lib/dev-pair-selinux-preserved` and copies the same verified state into the new filesystem before publishing managed readiness. Complete an already armed transition using its previously reviewed helper first. An occupied root with any other content requires its own recovery plan.

The boot mount prepares the enrolled loop slot even if Fedora starts with no loop devices. On Btrfs, the protected backing record binds the filesystem and subvolume UUIDs, subvolume ID, and the inode number and generation. These identities survive changes to the anonymous device number at reboot. Enrollment verifies that the mounted loop still points to the same complete file at offset zero. Reapply an earlier Btrfs enrollment to upgrade its backing record before relying on automatic recovery.

```sh
/usr/bin/python3 -EBs tools/destination_release.py managed-storage --apply \
  --platform-sha "$platform_sha" --managed-mib "$managed_mib" \
  --managed-inodes "$managed_inodes" --reserve-inodes "$physical_reserve_inodes" \
  --console-receipt "$console_receipt"
```

Use `--bootstrap-source "$observed_provider_cidr"` for the SSH-backed storage path. The helper requires full live SSH metadata, a socket owned by that session's daemon ancestry, a route to its peer and that peer inside the declared scope. Preserve `SSH_CONNECTION` across the root transition.

On a Disabled or Permissive host, follow the checked [SELinux transition](selinux-bootstrap.md) once the managed filesystem is ready. Leave the mounted filesystem in place through the distinct relabel and enforcing boots. The helper records the transition inside that filesystem. Reopen recovery and verify the latest console or SSH scope before resuming. On a pristine Enforcing host, retain the existing mode. Verify normal platform admission before launching any workload.

```sh
/usr/bin/python3 -EBs tools/bootstrap.py inspect
/usr/bin/python3 -EBs tools/bootstrap.py initialize --apply \
  --source-sha "$platform_sha" --distrobox-source "$distrobox_source" \
  --gptbox-context "$maintenance_context" --expected-context-sha256 "$maintenance_context_sha" \
  --password-file "$core_password_file" --console-receipt "$console_receipt"
```

For an SSH-backed hPanel terminal, pass `--provider-ssh --bootstrap-source "$observed_provider_cidr"` in place of `--console-receipt`. Restrict the provider firewall to the actual approved source and record the retirement condition. Use the current peer and route reported by the live terminal and verified provider transport. Incomplete SSH ancestry, a missing current socket, and an out-of-scope peer stop this path before changes. Preserve the admitted temporary route through enrollment and named-admin checks. `--retry` is reserved for rerunning an interrupted exact initialization. Use separate independently verified context digests for the maintenance and development placements. For a platform bundle produced by CI, the integrated `gptbox.py prepare-maintenance-host` route sets up the protected maintenance gateway and host prerequisites before F verifies or imports its candidate. Use the same verified hPanel transport and pinned role inputs. The local `initialize` route above also builds an image and belongs to a separately planned local construction or compatible pre-existing release.

Enroll with the external restricted auth-key file and the exact expected Tailscale network. Set the authorized admin policy for ordinary SSH TCP 22 and mosh UDP 60000–61000, and the authorized app policy for HTTPS TCP 443. Use the admitted node identity and scope each grant to the intended group. Keep Funnel disabled and exercise an ACL-denied client and an independent public vantage.

```sh
/usr/bin/python3 -EBs tools/bootstrap.py enroll --apply \
  --auth-key-file "$tailnet_auth_key_file" --tailnet "$tailnet_name"
```

Before cutover, exercise the GitHub-imported `core` key, invalid-key and password denial, password-gated sudo, mosh/tmux, scripted SSH and transfers, and both role connections. Exercise an authorized client, an ACL-denied client, an independent public vantage and independent provider recovery. For tailnet-loss checks keep the recovery terminal open, then restore enrollment and verify fresh connections. Test both address families and the actual provider public addresses. Record absence of a provider public address in the applicable family as null when the provider evidence establishes it. After cutover, verify direct root denial separately.

The `dev-pair-access-review` signed receipt uses the same `version`, source, machine, boot and timestamp fields within 30 minutes. Add `node_id`, `tailnet`, `dns_name`, `keys_sha256`, `acl_sha256`, `execution_route` (`tailnet-core` or `provider-recovery`), `provider_recovery` (`hostinger://<actual-vps-id>/recovery`), `public_addresses` (`ipv4` and `ipv6`), and the full `probes` list. Each probe records `test`, `family`, `endpoint`, `vantage`, `client_id`, `outcome`, `observed_at` and `evidence_sha256`. `Bootstrap.access_probe_plan` defines the entries and exact endpoint forms. Use compact JSON and retain the underlying named observations in the independently held record. The same authorized client can observe repeated success, loss and restoration. Use separate client identities for authorized, denied and public observations.

```sh
/usr/bin/python3 -EBs tools/bootstrap.py finalize --apply --evidence "$access_receipt"
```

Apply through the independently reopened non-SSH recovery terminal or through named tailnet SSH with `SSH_CONNECTION` preserved when escalating to root. Finalization records a root-owned intent and verifies effective OpenSSH settings before activating the host firewall change. The final firewall drops external SSH, HTTPS and mosh before the established-flow allowance. OpenSSH is key-only for `core` with remote root disabled. An interrupted application can be completed with fresh exact evidence through the preserved recovery path. Recovery after finalization uses the independently verified provider path. Verify the actual new logins, denied paths and reboot persistence before marking access delivered.

## Provision the closed host test

Use the exact integrated platform source containing the Fedora checklist Quadlet and its executor. Inspect actual free bytes, inodes, CPU, memory, live users/groups, subordinate mappings and existing mounts before choosing the sizing variables. The helper creates two distinct, fully allocated non-discarding ext4 loop filesystems for validation and live storage, each up to 2 GiB and 65,536 inodes. The two backing files sit inside the already reserved aggregate ext4 and leave the selected internal reserve, with at least 1 GiB. The host retains the separately checked 8 GiB physical reserve. Executor history, ledger, private graph and image-copy writes are inside these bounded allocations. Podman run roots use the verified finite user-manager tmpfs. Provide the externally protected mTLS server profile containing `cert.pem`, `peer.pem` and `key.pem`. Keep the separately provisioned conductor key outside both agent workspaces.

```sh
/usr/bin/python3 -EBs tools/destination_release.py provision --apply \
  --platform-sha "$platform_sha" --tls-profile "$executor_tls_profile" \
  --uid "$checklist_uid" --subid-start "$checklist_subid_start" \
  --validation-mib "$validation_mib" --validation-inodes "$validation_inodes" \
  --live-mib "$live_mib" --live-inodes "$live_inodes" \
  --reserve-mib "$reserve_mib" --reserve-inodes "$reserve_inodes"
```

The protected source install verifies the locked nonlogin `dp-checklist` account, private primary group, disjoint primary/subordinate IDs and the complete canonical Fedora sudo denial. Before writing sub-ID mappings, mounting its filesystems or starting a manager, the provisioner opens the exact installed code, selected managed bundle, Podman configuration and public mTLS certificate pins as `dp-checklist`. It checks that the per-UID Quadlet directory can be listed. Install the Fedora `acl` package through the authorized signed prerequisite path when an existing installer-owned directory needs a named access grant. For a protected private shared ancestor, the helper only grants the dedicated UID search access after checking its other contents remain private. The owned per-UID Quadlet input directory may also grant that UID listing access. The root signing directory and unrelated private files retain their own restrictions. Unknown ACLs or a mode that would disclose unrelated state block before a grant. After mounts and the private user manager are ready, initialize the Q ledger and independent execution history with the executor stopped. Preserve existing history on reapply. Installations with a prior ready marker and missing independent history require recovery.

For managed commissioning, install U's reviewed host bundle and config and seed its private current records first. Install the protected `checklist-entry` wrapper, systemd units and exact `checklist-release.conf` executor drop-in. The provision command initializes fresh Q history before fencing, or retains existing history during a handover from direct commissioning. It checks that U’s boot dispatch marker is present before queuing host observation. When an active boot-fence service has already consumed its marker, it restarts that service and reads back the reinstated marker. It reports pending manager state while observation or recovery runs. Re-run the exact provision command to join the observation, verify the actual selected wrapper process and queue U recovery. Reapplication while recovery is active reports its status. Managed readiness requires same-boot protected host verification, a fresh successful manager witness for U’s recovery, enabled-on-boot recovery and the fence cleared by U. `status` exposes the persisted listener phase and the live fence marker. Verify the exact `127.0.0.1:19425` listener after settling. See [renewal](renewal.md) for the exact initial bundle and selector contract. Use the explicit `--commissioning` option for the direct private Q executor when the renewal drop-in is absent and that commissioning route is authorized.

The authorized build conductor holds the approved validation receipt at `/var/lib/dev-pair/checklist-receipts/`. After its independently approved exact candidate is available in the validation graph, use `preload-validation --apply --receipt "$receipt"`. This validates the protected loopback host path before or after external access cutover. Continue with the [authenticated request and result flow](host-handoff.md). The external candidate builder and conductor remain required for this flow.

## Publish, deploy and recover

The [checklist publisher](../.github/workflows/checklist-release.yml) runs on pushes to protected `main`. Its read-only build job uses `CHECKLIST_BASE_POLICY` to verify the selected base signature before pulling its exact registry digest. The base supplies `/usr/bin/python3` and SQLite. The workload builds without network, labels the resulting manifest with the base reference and proof hash, and stages the exact OCI archive alongside the canonical base proof. Only the postmerge publisher job receives the scoped registry writer and GitHub attestation and OIDC permissions. Its summary records the full source revision, exact registry manifest and run ID. Pull requests keep read-only workflow roles.

The independently administered repository must enforce main branch protection, recent independent review, strict checks, admin enforcement and denied force pushes/deletion. Operators need a read-only GitHub identity for branch protection, PR reviews, checks, trusted workflows and attestations. Configure the independently held `checklist-release` GitHub Environment with a deployment branch policy allowing only the `main` branch and an independently administered custom deployment-protection GitHub App. That App admits only the exact reviewed checklist publisher workflow, repository, source, protected `main` push and independently approved `CHECKLIST_BASE_POLICY` before GitHub passes the job its environment secret. Each base policy identifies `image` at its immutable OCI digest, the independently approved GitHub `repo`, signing `workflow`, full `source` commit and Git `ref`. The writer signs the exact resulting image with both normal provenance and the retained base-proof predicate. Hold `CHECKLIST_GHCR_TOKEN` there and set `CHECKLIST_GHCR_WRITER` to the independently administered registry writer. Disable repository-derived package write on the GHCR package. A private registry also needs a scoped read credential for Podman and the verifier. Verify that author identities cannot change GitHub policy or publisher access. The host verifier needs a protected installed GitHub CLI with `attestation verify`, source and signer digest flags, and `api --paginate --slurp`.

Place the actual authority in root-protected `/etc/dev-pair/release-trust.json`. Its fields are `version: 1`, numeric `writer_app_id` for the independently installed protector, `reviewer_ids` containing independently held GitHub user IDs, `check` with `context`, numeric GitHub App `app_id`, `workflow` and exact file `sha256`, and `components`. Each component maps to `workflow`, exact file `sha256`, and `registry`, which is the authorized registry path or null for an attested file. The path for checklist is `.github/workflows/checklist-release.yml` and its registry is `ghcr.io/oso-gato/dev-pair/checklist`. For checklist, add the same independently approved `base` policy object to its protected publisher entry. The host verifies the custom publication attestation, independently verifies the retained upstream base signature and requires the resulting image labels to match. Pin `.github/workflows/release-check.yml` and require its `release-source-check` job in branch protection. It runs read-only and binds the actual synthetic merge tree and executed workflow revision to the check annotation. The controller requires identical reviewed-head, tested-merge and production trees. The currently unprovisioned App and GitHub policy are external release prerequisites. An independent verifier updates the protected policy if an authorized gate change is adopted. Review of the exact merged PR head and workflow custody are the release gate. The workflow has no extra per-release owner review step.

```sh
/usr/bin/python3 -EBs tools/destination_release.py deploy --apply \
  --source-sha "$published_source" --image "$published_image_at_digest" --run-id "$publisher_run"
```

For private OCI access, supply `--registry-auth-file "$root_private_registry_read_file"` to the deployment controller and preconfigure read access for the GitHub CLI in its protected root credential store. The controller verifies exact main source, current-head independent review, trusted completed check, protected workflow bytes, the successful publisher run and GitHub attestation certificate. It verifies the downloaded manifest, source label and compatible SQLite format before rendering the root-owned Quadlet. Deployment checks the actual Podman image ID, SELinux MCS data label and loopback application. It enables only private HTTPS at `https://erebus.<tailnet>.ts.net/` through Tailscale Serve to `127.0.0.1:18279`.

The independent destination verifier signs a fresh `dev-pair-access-review` receipt using the same base fields. Include `release_source`, exact `image`, `dns_name`, live `guard_sha256`, the actual completed `item_id`, `item_title_sha256` and the structured `probes` list. For each address family observe `browser-add-and-complete`, `restart-same-item`, `reboot-same-item`, `clean-restore-same-item`, `public-app`, `unauthorized-app`, `tailnet-loss-app`, `tailnet-recovery-app` and `remote-root`. When a previously confirmed digest exists, also observe `rollback-same-item`. The controller checks that the same completed item is present in live storage and its actual HTTP result. For a standalone release, use `confirm --apply --evidence "$destination_receipt"` from the same protected checkout. For a release owned by a checklist promotion job, the signed receipt also carries `job_id`, `publisher_run_id` and `publisher_run_attempt`. `status` reports pending data and proxy states alongside active and prior releases. [Job-specific proof](destination-observation.md#return-the-signed-proof)

The controller reserves the rollout, closes the exact private proxy and stops the app before reading the data snapshot. It proves SQLite restore to a separate file and compares the stored and HTTP item inventories while ingress is closed. An unhealthy candidate restores the verified snapshot, retains the backup and archives changed candidate data. A failed first release removes the owned route and unit, archives its data and clears the pending release so an independently approved correction can proceed. Promotion becomes durable before HTTPS reopens. An interrupted enable of the proxy can resume from the promoted release with accepted writes preserved. `rollback --apply` checks a previously confirmed compatible digest against a fresh snapshot of current live data. Keep an authorized independent backup outside the VPS for host loss.

If the first release passes its local data checks and later fails independent destination verification, the independent verifier signs a fresh rejection receipt with the same base fields, `release_source`, `image`, `dns_name`, `failed_check` and `observation_sha256`. The failed check identifies the actual failed browser, public-denial, unauthorized-denial, tailnet-loss, restart, reboot, clean-restore or remote-root observation. Quarantine that exact locally promoted digest through the protected entry.

```sh
/usr/bin/python3 -EBs tools/destination_release.py reject --apply --evidence "$rejection_receipt"
```

Quarantine closes ingress, stops the unit and durably snapshots all accepted compatible data. An independently approved new digest can reuse that data. A failed correction leaves the rejected unit and proxy closed. An interrupted quarantine can settle through `rollback --apply`, which consumes the retained local operation. For any interrupted replacement, separately archive each changed database identity and keep its verified coherent backup. Snapshots and restores use compact UTF-8 under the existing output bound.

The installed common verifier at `/usr/libexec/dev-pair/tools/release_trust.py` also admits a protected canonical portable `platform.json` for `verify --component host|devbox|maintenance|development --source-sha ... --subject /absolute/protected/platform.json --sha256 ... --run-id ...`. It verifies the attested index, exact component and trusted run. Host-specific site and job plans are governed by the local protected authority using the verified portable index and the site configuration. Maintenance and development may also select an independently pinned `agent_refresh` workflow with exact `workflow` and `sha256` to admit its protected-main scheduled or manual attempt. Host and DevBox remain on the deliberate protected-main push publisher. The independent platform publisher and signed-role resolver are separate dependencies. Real hPanel transport, policy, client behavior, rootless Fedora confinement, package publication and clean destination restore still need evidence.
