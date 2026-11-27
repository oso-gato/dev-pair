# Independent destination observations

The destination verifier can use `tools/destination_observation.py` to observe the normal checklist page and assemble the existing D confirmation receipt. The producer runs under separately controlled client identities. It uses the already accepted release and destination selected by the product agreement. The owner can follow the original job status while the independent verifier collects the evidence.

## Commission once

An independent verifier needs an authorized Tailscale browser client, a separate Tailscale identity denied the app grant, and a separate public vantage outside the tailnet. The public vantage needs a working route for every public address family actually assigned by the VPS provider. Each active negative client needs a selected source address and a second, independently selected HTTPS service that it can reach over that address family. The control service must have a valid certificate and return HTTP 200 or 204 at its root. Use a protected, independently maintained site profile to select these exact hosts and addresses. An approved Tailscale destination needs valid HTTPS for its exact DNS name.

Run the browser collector on the separate authorized client with managed Chromium and its Playwright Python binding, verified platform trust roots, the normal browser sandbox and outbound policy scoped to this checklist address. The collector checks the actual address used by the browser, opens the checklist page, adds and completes a distinct acceptance item per family, and verifies the visible Done state. Later checks open a separate browser to read the same primary item over each family. The negative clients use direct HTTPS with their selected source, numeric destination and verified DNS certificate. They allow no redirects or inherited proxies. A target refusal, timeout or authenticated HTTP 401/403 qualifies only with healthy control requests before and after and a fresh authorized result for the same family. A certificate, name or other unclassified transport failure leaves the proof blocked.

Use a separately authorized provider recovery operator with the actual VPS recovery terminal, and a destination controller authorized for the fixed checklist lifecycle. The provider recovery and controller identities must be distinct from each other and from the three client identities. Provision the following public observation trust entries under protected `/etc/dev-pair/destination-observer/allowed_signers` on the independent stations. Use one independently held key per principal. The supported public key forms are `ssh-ed25519` and `sk-ssh-ed25519@openssh.com`. Each entry has the form `principal namespaces="dev-pair-destination-observation" public-key-type base64-key`. The six principals are:

- `dev-pair-observer-plan` for the independently selected release observation plan.
- `dev-pair-observer-authorized` for the authorized browser and named access client.
- `dev-pair-observer-denied` for the Tailscale-denied client.
- `dev-pair-observer-public` for the public client.
- `dev-pair-observer-provider` for the provider recovery terminal and provider-confirmed address absence.
- `dev-pair-observer-controller` for the separately authorized checklist lifecycle controller.

The initial access verifier also needs the admitted `core` key, independently checked SSH host identity, the existing password-gated administrative account path, and the authorized mosh and tmux clients. The recovery operator needs its own authorized provider login and a newly opened VPS recovery terminal that stays usable when tailnet access is interrupted. Use the protected provider-held inventory to establish public address assignment. The checklist controller needs the existing rootless systemd and backup/restore authority for the exact checklist deployment and its data, including an independently approved clean restore location and bounded outage window. These authorities come from the site commissioning agreement.

The final verifier uses its separate existing `dev-pair-access-review` authority in namespace `dev-pair-destination`. Use authorized OpenSSH signing custody on the independent station. An existing agent-backed public key or hardware-backed signer can produce detached signatures with `ssh-keygen -Y sign`. Keep private signing keys and agent access away from the owner terminal, development and maintenance roles, release proposer, product orchestrator and target.

The root-protected site JSON is fixed independently before use. For release observations it has `version: 1`, `kind: checklist-release`, `dns_name`, `provider_recovery` in the form `hostinger://VPS-ID/recovery`, `public_addresses`, `tailnet_addresses`, five `clients` mapped by the vantage names above, and `negative_routes`. Address maps have `ipv4` and `ipv6` keys with canonical numeric values. A provider-confirmed absent public family and its negative route use null. The `negative_routes` map has `denied` and `public` maps, each with both family keys. Each selected route has `source_address`, `control_address` and `control_dns`. The client names identify actual individually admitted identities. The independent access administrator supplies actual ACL policy and route provenance during commissioning.

## Observe a pending release

From the existing authorized destination controller, export the exact protected J/D binding when the owner job is awaiting independent destination confirmation. This reads the settled activation, matching J release, guarded private route, platform source, machine, boot and exact CI run/attempt. Treat the result as a selection to check independently against the approved site and publication. A destination export alone supplies no client or recovery result. Transfer it through the existing authenticated protected controller path.

```sh
/usr/bin/python3 -EBs tools/destination_observation.py export-release "$job"
```

On the independent verifier, prepare the plan in a new private ceremony directory. The tool uses the protected site profile and observed binding directly. It generates a random ceremony ID, produces `plan.json`, and retains that same plan on a repeated invocation. The existing plan signer signs the exact bytes, then distributes the plan and its detached signature to the named client stations. Each station uses a private directory under protected ancestry. Retain the original per-client records and transcripts in the independent evidence store.

```sh
/usr/bin/python3 -EBs tools/destination_observation.py \
  --directory "$ceremony" begin --binding "$received_binding" --site "$protected_site"
ssh-keygen -Y sign -n dev-pair-destination-observation -f "$plan_signer_public" "$ceremony/plan.json"
```

Use `collect browser-add-and-complete ipv4` and `collect browser-add-and-complete ipv6` on the authorized client first. Provide `--plan` and `--directory` before each command. The returned path is the exact file for that client to sign and transfer with its detached signature. Collecting an already recorded check returns the original bytes. If a browser write reaches the checklist before its observation can be saved, the same title prevents a second item on retry. A completed existing row cannot supply the lost original add-and-complete observation. Recover the original independently retained evidence or schedule a new observation ceremony.

Collect both `unauthorized-app` and `public-app` from their respective vantages once the authorization path returns after the tailnet-loss exercise. If the provider confirms absence of a public address family, use `record-access public-app FAMILY` with the original provider inventory transcript. Its record is signed by the provider vantage. Run the authorized `tailnet-recovery-app` check close to the negative tests. Use the independently admitted named SSH client for actual `remote-root` denial on each family, keeping a simultaneous successful named login on those paths. Record that client’s transcript with `record-access remote-root FAMILY`.

The separately authorized lifecycle operator supplies the original actual transition transcript to `record-event EVENT --before ID --after ID --observed-at EPOCH --transcript FILE` on its own station and signs that exact record. The file must be an independently retained, bounded record of the observed action. Record both families' ordinary browser item check after each transition and before the next one. Keep the exact completed item and its database through these checks.

| Independently observed transition | Operator | Authorized post-transition browser check |
|---|---|---|
| Checklist rootless unit restart with changed systemd invocation ID | Controller | `restart-same-item` |
| Reopened recovery on the same VPS with changed kernel boot ID | Provider | `reboot-same-item` |
| Scoped restore of the retained data into a separately clean destination data volume selected for the same configured checklist route | Controller | `clean-restore-same-item` |
| Tailscale loss with recovery terminal already open and no fallback ingress | Provider | Record each actual authorized `tailnet-loss-app` denied-session transcript during loss |
| Re-enrollment with recovery independently preserved | Provider | `tailnet-recovery-app` |
| When a previous compatible verified digest exists, rollback after restore and re-promote the selected digest before the loss exercise | Controller | `rollback-same-item` while the previous digest is active |

The tool verifies the distinct restart/boot identities, exact before/after OCI digests for rollback and re-promotion, event order, time windows and the same completed item. The browser reconnects do not attest that a privileged transition occurred. The independent provider or controller supplies the authorized action and observation. A clean restore that changes machines needs a separately admitted commissioning and observation scope. This initial source has no provider, SSH, mosh, firewall, rollback or restore command executor. Those actions and observations require the admitted native operators and recovery scope.

## Return the signed proof

Gather the signed probe and event files in the verifier's private ceremony directory. Records bind the exact signed plan, including the original job and publisher attempt. Keep the receipts, plan, and raw transcripts together in the independent record.

```sh
/usr/bin/python3 -EBs tools/destination_observation.py \
  --plan "$ceremony/plan.json" --directory "$ceremony" assemble
ssh-keygen -Y sign -n dev-pair-destination -f "$access_review_signer_public" \
  "$ceremony/destination-receipt.json"
```

The assembler waits for every required check and verifies the signature against its exact role. It issues the existing D JSON schema and puts the boot observed after the admitted reboot in the receipt. The wire format stores the exact production source, OCI image, completed primary item, observed boot and guard. The job and run remain in the separately signed retained plan. Use the normal protected J import path for the signed files as `/var/lib/dev-pair/product-release-evidence/JOB.json` and `JOB.json.sig`. D still checks the current machine/boot, private route, stored item and actual application health before recording confirmation.

The assembler also accepts separately measured pre-cutover access records against D's existing `Bootstrap.access_probe_plan`. Use a protected `kind: access-cutover` site profile with the same common site fields plus `node_id`, `tailnet`, `keys_sha256`, `acl_sha256`, and `execution_route`. Its independently checked binding carries the common exact job, platform source, machine, boot, DNS, recovery and provider addresses. Use `record-access TEST FAMILY --observed-at EPOCH --transcript FILE` for each actual typed access observation and `assemble` for the cutover schema. Confirm the initial operator scope and independently verified provider recovery through the [existing destination commissioning entry](destination-release.md). Generating initial access observations remains a native commissioning task.

The source fixture drove the stock checklist through Chromium over loopback, then read the same item after restarting the application process. A separate bounded loopback TLS test exercised direct negative HTTP, healthy control and certificate rejection. Receipt tests used disposable local OpenSSH keys and fixture recovery records. The real VPS, Tailnet policy, named SSH/mosh, independent provider terminal, reboot, rollback, clean restore and external signing custody have not been exercised.
