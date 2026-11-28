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

### Prepare the first access station

Use the exact reviewed source in a root-protected Git checkout on the separately
authorized station. The station uses stock Python 3, Git, OpenSSH, Tailscale
and `runuser`. Keep the dedicated unprivileged courier and independent reviewer
accounts separate. The courier needs a root-owned, traversable home, a standard
shell for its forced command, and the station's approved key-only SSH listener
on the tailnet. Use the normal root-managed `.ssh/authorized_keys` route and
preserve any existing unrelated identities. The reviewer enrolls an approved
read-only Tailscale OAuth credential in their private directory using
`tools/agent_observer_station.py enroll-acl`.

The station administrator runs the following from the reviewed checkout. Use
the provider's independently confirmed public addresses, or `none` for each
confirmed absent family. Choose the approved execution route, `provider-recovery`
or `tailnet-core`, where the receipt will be applied.

```sh
sudo /usr/bin/python3 -IB tools/day0_access_station.py prepare \
  --source-sha "$reviewed_commit" --station-address "$station_ip" \
  --courier-user "$courier" --reviewer-user "$reviewer" --acl-oauth "$oauth_file" \
  --dns-name "$vps_dns" --tailnet "$tailnet" --provider-recovery "$recovery_route" \
  --public-ipv4 "$public_v4" --public-ipv6 "$public_v6" --execution-route "$apply_route" \
  --authorized-client "$authorized_client" --denied-client "$denied_client" \
  --public-client "$public_client" --provider-client "$provider_client" \
  --controller-client "$controller_client" \
  --plan-key "$plan_public_key" --authorized-key "$authorized_public_key" \
  --denied-key "$denied_public_key" --public-key "$public_client_key" \
  --provider-key "$provider_public_key" --controller-key "$controller_public_key" \
  --access-review-key "$access_review_public_key"
```

The command verifies the source and station address, measures the current ACL
through the reviewer's read-only authority, and records the core site and
separate public signer roster. The scoped final public trust is available at
`/etc/dev-pair/destination-observer/access-review-allowed-signers` for the
approved candidate observer. The station operator conveys the contact values
and both OpenSSH SHA256 fingerprints through an independently authenticated
handoff. After obtaining the VPS's newly generated courier public key and its
approved source address on the same tailnet, the station operator runs:

```sh
sudo /usr/bin/python3 -IB tools/day0_access_station.py admit-courier \
  --source-sha "$reviewed_commit" --vps-address "$vps_tailnet_ip" \
  --courier-key "$vps_courier_public_key"
```

The exact authorization restricts that key to the approved source and a fixed
mailbox command with no terminal or forwarding. The command verifies any
existing scoped authorization before reuse. The mailbox is private to the
courier, and observation and signing custody stay with the independent roles.

### Prepare a checklist release site

The independent station administrator runs `prepare-release-site` once with
approved site facts and the public SSH key for each role. It writes the
protected release site and observer signer set under
`/etc/dev-pair/destination-observer`. Use each site's actual identities and
addresses. The command never asks for a private key. For example, when the
provider's independently checked inventory has no public IPv6 address:

```sh
sudo /usr/bin/python3 -EBs tools/destination_observation.py prepare-release-site \
  --dns-name "$dns" --provider-recovery "$recovery_route" \
  --public-ipv4 "$public_v4" --public-ipv6 none \
  --tailnet-ipv4 "$tailnet_v4" --tailnet-ipv6 "$tailnet_v6" \
  --authorized-client "$authorized_client" --denied-client "$denied_client" \
  --public-client "$public_client" --provider-client "$provider_client" \
  --controller-client "$controller_client" \
  --denied-route-ipv4 "$denied_source_v4" "$denied_control_v4" "$denied_control_dns_v4" \
  --denied-route-ipv6 "$denied_source_v6" "$denied_control_v6" "$denied_control_dns_v6" \
  --public-route-ipv4 "$public_source_v4" "$public_control_v4" "$public_control_dns_v4" \
  --plan-key "$plan_public_key" --authorized-key "$authorized_public_key" \
  --denied-key "$denied_public_key" --public-key "$public_client_key" \
  --provider-key "$provider_public_key" --controller-key "$controller_public_key"
```

Use `hostinger://VPS-ID/recovery` for the independently approved provider
recovery route. Provide `--public-route-ipv6` with the public client's source,
control address and control DNS when the provider assigns a public IPv6
address. Both denied-client routes always require an independent HTTPS
control. Distribute the protected public signer configuration to each station
through its independent administrator. Read the actual ACL and route
provenance from the responsible access administrator.

## Observe a pending release

From the existing authorized destination controller, export the exact protected J/D binding when the owner job is awaiting independent destination confirmation. This reads the settled activation, matching J release, guarded private route, platform source, machine, boot and exact CI run/attempt. Treat the result as a selection to check independently against the approved site and publication. A destination export alone supplies no client or recovery result. Transfer it through the existing authenticated protected controller path.

```sh
sudo /usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/destination_observation.py export-release "$job"
```

On the independent verifier, prepare the plan in a new private ceremony directory. The tool uses the protected site profile and observed binding directly. It generates a random ceremony ID, produces `plan.json`, and retains that same plan on a repeated invocation. The existing plan signer signs the exact bytes, then distributes the plan and its detached signature to the named client stations. Each station uses a private directory under protected ancestry. Retain the original per-client records and transcripts in the independent evidence store.

```sh
/usr/bin/python3 -EBs tools/destination_observation.py \
  --directory "$ceremony" begin --binding "$received_binding" \
  --site /etc/dev-pair/destination-observer/release-site.json
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
/usr/bin/python3 -EBs tools/destination_observation.py bundle-release \
  --receipt "$ceremony/destination-receipt.json" > "$ceremony/release-proof.envelope"
```

The assembler waits for every required check and verifies each role signature.
The signed plan and final receipt identify the owner job, publisher run ID and
run attempt. The receipt also includes the production source, OCI image,
primary item, observed boot and guard. Return the envelope over the authenticated
controller channel.
From the protected destination terminal, submit it for the exact owner job:

```sh
sudo /usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/promotion_setup.py \
  import-proof "$job" < "$received_envelope"
```

The importer checks the independent signature and current release binding,
including the job and publisher attempt. The next commissioned promotion scan
checks the same binding again against the live checklist and records
confirmation on the same job. Resume Day 0 after a reboot if the schedule is
held for the new boot. `dev-pair status JOB` shows when a proof is missing or
expired. Return a fresh proof for an expired receipt or a changed publisher
attempt. An unfinished observation also needs fresh proof after a host source
or boot change. Export the current binding again. Confirmed delivery records
remain valid historical evidence.

The assembler also accepts separately measured pre-cutover access records against D's existing `Bootstrap.access_probe_plan`. Use a protected `kind: access-cutover` site profile with the same common site fields plus `node_id`, `tailnet`, `keys_sha256`, `acl_sha256`, and `execution_route`. Its independently checked binding carries the common exact job, platform source, machine, boot, DNS, recovery and provider addresses. Use `record-access TEST FAMILY --observed-at EPOCH --transcript FILE` for each actual typed access observation and `assemble` for the cutover schema. Confirm the initial operator scope and independently verified provider recovery through the [existing destination commissioning entry](destination-release.md). Generating initial access observations remains a native commissioning task.

## Review the named SSH and workload routes

Use the request displayed by the station mailbox as `begin --binding`. Use
`/etc/dev-pair/destination-observer/core-access-site.json` as `--site`.
For the offline route, use the output of `day0.sh access-request` as the
binding. The profile supplies the independently approved site and measured ACL.
The request supplies the live machine and boot, enrolled node, tailnet addresses
and installed core key digest. Verify those facts before signing the plan.
Continue using the separate observation and final access-review signing
authorities described above.

For the administrator stage measure the named key login, invalid-key and
password rejection, password-gated sudo, script and transfer, mosh/tmux reconnect,
denial from the unauthorized tailnet and public clients, and loss and recovery
on both address families. Reopen independent provider recovery before testing
tailnet failure. In the protected provider-SSH window the public test measures
denial of the named core route while the scoped initial provider route stays
available. The resulting cutover verifies the live firewall and effective SSH
configuration before recording the initial route closed. When the provider
confirms a public family is absent, it signs those absence observations.

After `assemble` and the existing final access-review signature, use
`bundle-access --receipt /protected/ceremony/destination-receipt.json` to export
one bounded stream. Return it through the authenticated controller channel.
The owner runs `day0.sh access-response` with the stream on stdin. No private
signing key is installed on the destination. If the selected verifier or an
independent vantage is unavailable, keep the applicable protected bootstrap
or recovery route and leave the corresponding stage pending.

Once the core cutover and approved private placement are complete, use the
owner's `access-request --workloads` output. Prepare a fresh plan with the same
independent core site profile. On an authorized client, connect to `core` with
the verified host key and each planned tailnet address. Within that SSH session,
run `sudo --preserve-env=SSH_CONNECTION,SSH_CLIENT /absolute/reviewed/checkout/day0.sh access-probe maintenance`
and the corresponding `access-probe development` command. Capture each command's
standard output to its authorized or restored observation transcript. The
destination checks the actual SSH daemon session and `tailscale0` route, then
runs the selected confined maintenance or nested DevBox probe twice. The
bounded offline probes use the existing SSH listener and leave jobs held. The
development probe reads the published immutable manifest and archive from their
digest-addressed paths. It uses separate labeled scratch within the bounded
development allocation and reaps its own containers and scratch. The collector
verifies the machine, boot, address and exact selected role images
before signing the observation. The denied, public and loss clients must try
the same named SSH command and verify denial. Restore the named route and run
the actual probe again before issuing the final workload bundle. The owner
imports that bundle with the same `access-response` command. Job authorization,
provider spending and application-specific validation remain independent gates.

The source fixture drove the stock checklist through Chromium over loopback, then read the same item after restarting the application process. A separate bounded loopback TLS test exercised direct negative HTTP, healthy control and certificate rejection. Receipt tests used disposable local OpenSSH keys and fixture recovery records. The real VPS, Tailnet policy, named SSH/mosh, independent provider terminal, reboot, rollback, clean restore and external signing custody have not been exercised.
