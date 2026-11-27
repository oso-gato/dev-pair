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

Transfer the independently verified exact platform checkout to protected `/root/dev-pair-bootstrap-source`, with an external full commit pin. The observed planning baseline was `657eec5d0d16a56fb34360af9883777ea3e51f31`. Use the independently reviewed integrated successor for this procedure. On a minimal Fedora image, the signed `git-core` prerequisite can be installed during explicitly authorized setup after the first inspection and independent recovery verification. Verify the transfer before executing its code. Use the checked [SELinux transition](selinux-bootstrap.md) if necessary. Issue boot-bound evidence again after a setup reboot.

```sh
cd /root/dev-pair-bootstrap-source
/usr/bin/python3 -EBs tools/bootstrap.py console-inspect --source-sha "$platform_sha"
/usr/bin/python3 -EBs tools/bootstrap.py inspect
```

For verified out-of-band access, the authorized transport verifier records `provider: hostinger`, the selected `provider_vps_id`, `transport: out-of-band`, `reopened_root: true` and externally observed `public_ssh_denied: true`. Add `version: 1`, `source_sha`, `machine_id`, `boot_id`, and integer Unix `issued_at` and `expires_at`, within two hours. Sign the exact receipt bytes in the `dev-pair-destination` namespace using an existing authorized signer mapped to `dev-pair-provider-console` in the protected `/etc/dev-pair/trust/allowed_signers`. Place the receipt and its `.sig` sibling in a protected root directory. The inventory command needs no signing key or receipt.

```sh
/usr/bin/python3 -EBs tools/bootstrap.py initialize --apply \
  --source-sha "$platform_sha" --distrobox-source "$distrobox_source" \
  --gptbox-context "$maintenance_context" --expected-context-sha256 "$maintenance_context_sha" \
  --password-file "$core_password_file" --console-receipt "$console_receipt"
```

For an SSH-backed hPanel terminal, pass `--bootstrap-source` with the separately verified temporary SSH source CIDR in place of `--console-receipt`. Restrict the provider firewall to the actual approved source and record the retirement condition. Read the current peer from the terminal and provider evidence. Explicit CIDRs are required for this path, and the live SSH peer must fall inside them. Preserve the admitted temporary route through enrollment and named-admin checks. `--retry` is reserved for rerunning an interrupted exact initialization. Use separate independently verified context digests for the maintenance and development placements.

Enroll with the external restricted auth-key file and the exact expected Tailscale network. Set the authorized admin policy for ordinary SSH TCP 22 and mosh UDP 60000–61000, and the authorized app policy for HTTPS TCP 443. Use the admitted node identity and scope each grant to the intended group. Keep Funnel disabled and exercise an ACL-denied client and an independent public vantage.

```sh
/usr/bin/python3 -EBs tools/bootstrap.py enroll --apply \
  --auth-key-file "$tailnet_auth_key_file" --tailnet "$tailnet_name"
```

Before cutover, the independent verifier must exercise the GitHub-imported key from a new authorized `core` session, password rejection, password-gated sudo, mosh and tmux, scripted SSH and transfers, and independent recovery without the pair or tailnet. Include unauthorized tailnet rejection and public SSH denial outside any temporary approved source. Record IPv4 and IPv6 observations. The protected signed access receipt uses `dev-pair-access-review` and the same base `version`, source, machine and boot fields, within 30 minutes. Add exact `node_id`, `tailnet`, `dns_name`, `keys_sha256`, `acl_sha256` and a `checks` object with boolean true for each required observation.

```text
named_key password_denied password_gated_sudo mosh_tmux scripted_ssh
independent_recovery unauthorized_tailnet_denied public_ssh_denied
```

```sh
/usr/bin/python3 -EBs tools/bootstrap.py finalize --apply --evidence "$access_receipt"
```

Apply through the independently reopened non-SSH recovery terminal or through named tailnet SSH with `SSH_CONNECTION` preserved when escalating to root. Finalization records a root-owned intent and verifies effective OpenSSH settings before activating the host firewall change. The final firewall drops external SSH, HTTPS and mosh before the established-flow allowance. OpenSSH is key-only for `core` with remote root disabled. An interrupted application can be completed with fresh exact evidence through the preserved recovery path. Recovery after finalization uses the independently verified provider path. Verify the actual new logins, denied paths and reboot persistence before marking access delivered.

## Provision the closed host test

Use the exact integrated platform source containing the Fedora checklist Quadlet and its executor. Inspect actual free bytes, inodes, CPU, memory, live users/groups, subordinate mappings and existing mounts before choosing the sizing variables. The helper creates two distinct, fully allocated non-discarding ext4 loop filesystems for validation and live storage, each up to 2 GiB and 65,536 inodes. The backing filesystem keeps at least the existing 8 GiB reserve and the specified inode reserve. Provide the externally protected mTLS server profile containing `cert.pem`, `peer.pem` and `key.pem`. Keep the separately provisioned conductor key outside both agent workspaces.

```sh
/usr/bin/python3 -EBs tools/destination_release.py provision --apply \
  --platform-sha "$platform_sha" --tls-profile "$executor_tls_profile" \
  --uid "$checklist_uid" --subid-start "$checklist_subid_start" \
  --validation-mib "$validation_mib" --validation-inodes "$validation_inodes" \
  --live-mib "$live_mib" --live-inodes "$live_inodes" \
  --reserve-mib "$reserve_mib" --reserve-inodes "$reserve_inodes"
```

The protected source install enables the private `dp-checklist` user manager and fixed executor on `127.0.0.1:19425`. Its account has a locked password, no login shell, no sudo and a private primary group. The job-owned ledger, TLS profile, protected receipt and bounded data store have dedicated locations. The authorized build conductor holds the approved validation receipt at `/var/lib/dev-pair/checklist-receipts/`. After its independently approved exact candidate is available in the validation graph, use `preload-validation --apply --receipt "$receipt"`. This validates the protected loopback host path before or after external access cutover. Continue with the [authenticated request and result flow](host-handoff.md). The external candidate builder and conductor remain required for this flow.

## Publish, deploy and recover

The [checklist publisher](../.github/workflows/checklist-release.yml) runs on pushes to protected `main`. Its build job uses a verified pinned `CHECKLIST_BASE` registry reference with `/usr/bin/python3` and SQLite, builds without network in the workload build step and stages an exact OCI archive. Only the postmerge publisher job receives the scoped registry writer and GitHub attestation and OIDC permissions. Its summary records the full source revision, exact registry manifest and run ID. Pull requests keep read-only workflow roles.

The independently administered repository must enforce main branch protection, recent independent review, strict checks, admin enforcement and denied force pushes/deletion. Operators need a read-only GitHub identity for branch protection, PR reviews, checks, trusted workflows and attestations. Configure the independently held `checklist-release` GitHub Environment with a deployment branch policy allowing only the `main` branch. Hold `CHECKLIST_GHCR_TOKEN` there and set `CHECKLIST_GHCR_WRITER` to the independently administered registry writer. Disable repository-derived package write on the GHCR package. A private registry also needs a scoped read credential for Podman and the verifier. Verify that author identities cannot change GitHub policy or publisher access. The host verifier needs a protected installed GitHub CLI with `attestation verify`, source and signer digest flags, and `api --paginate --slurp`.

Place the actual authority in root-protected `/etc/dev-pair/release-trust.json`. Its fields are `version: 1`, `reviewer_ids` containing independently held GitHub user IDs, `check` with `context`, numeric GitHub App `app_id`, `workflow` and exact file `sha256`, and `components`. Each component maps to `workflow`, exact file `sha256`, and `registry`, which is the authorized registry path or null for an attested file. The path for checklist is `.github/workflows/checklist-release.yml` and its registry is `ghcr.io/oso-gato/dev-pair/checklist`. Pin the required PR workflow from the reviewed exact integration. An independent verifier updates the protected policy if an authorized gate change is adopted. Review of the exact merged PR head and workflow custody are the release gate. The workflow has no extra per-release owner review step.

```sh
/usr/bin/python3 -EBs tools/destination_release.py deploy --apply \
  --source-sha "$published_source" --image "$published_image_at_digest" --run-id "$publisher_run"
```

For private OCI access, supply `--registry-auth-file "$root_private_registry_read_file"` to the deployment controller and preconfigure read access for the GitHub CLI in its protected root credential store. The controller verifies exact main source, current-head independent review, trusted completed check, protected workflow bytes, the successful publisher run and GitHub attestation certificate. It verifies the downloaded manifest, source label and compatible SQLite format before rendering the root-owned Quadlet. Deployment checks the actual Podman image ID, SELinux MCS data label and loopback application. It enables only private HTTPS at `https://erebus.<tailnet>.ts.net/` through Tailscale Serve to `127.0.0.1:18279`.

The independent destination verifier signs a fresh receipt using `dev-pair-access-review`. Include the same base fields with the platform source, and `release_source`, exact `image`, `dns_name`, live `guard_sha256` and a `checks` object with true values for `authorized_browser`, `public_app_denied`, `unauthorized_app_denied`, `tailnet_loss_denied`, `reboot_persistence`, `clean_restore` and `remote_root_denied`. Exercise the browser journey and restore with actual data before signing. Use `confirm --apply --evidence "$destination_receipt"` from the same protected checkout. `status` distinguishes unconfirmed activation, current and previous targets and interrupted effects.

The controller retains the prior independently confirmed compatible release. Before replacing an active release it copies the SQLite database and verifies a restore to a separate file. `rollback --apply` reopens the stored exact prior digest with the same verified data format. An unhealthy attempted replacement restores the active release and preserves its database. A failed first attempt removes its owned listener and proxy, and retains its exact attempt and data for inspection and retry. Keep an authorized independent backup outside the VPS for host loss.

The installed common verifier at `/usr/libexec/dev-pair/tools/release_trust.py` also accepts `verify --component host|devbox|maintenance|development --source-sha ... --subject /absolute/protected/file --sha256 ... --run-id ...` for independently provisioned local-file publishers. Production publishers, exact artifacts and release transport for the host, DevBox and both agent placements remain separate work. This slice includes checklist publication and deployment source only. Real hPanel transport, policy, client behavior, rootless Fedora confinement, package publication and clean destination restore still need evidence.
