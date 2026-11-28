# Managed renewal

The external controller uses the existing private session registries and job ledger for agent-only, DevBox and host release windows. It preserves work before replacement, checks the exact session UUIDs through the fixed role runners, and leaves ordinary dispatch paused until every retained session has made fresh progress. A platform repair request carries its affected product job IDs and stays separate from their job and host request records.

## Installation boundary

Install the reviewed recovery controller and its companion Q imports at `/usr/libexec/dev-pair/tools`. Install the executable files from `runtime/renewal` in `/usr/libexec/dev-pair/renewal`, the services and timer in the host's unit path, and `dev-pair-renewal.conf` in the tmpfiles configuration. The recovery controller and fixed driver run as root outside both replaceable environments and the versioned host launch bundle. The job ledger remains under `dp-checklist` at `/var/lib/dev-pair/checklist-executor/ledger`. A fixed `runuser` helper uses the ledger's existing inventory and backup functions as that account. It reads Q's separately retained `execution-history` on the same machine and validation filesystem. A missing or stale mirror defers activation and reports the exact request for Q reconciliation. Initialize Q history while the listener is inactive before enabling the boot fence. Back up and validate the portable mirror in the external controller's private area while keeping Q's authoritative history in place.

Provision the following separately under the corresponding owner and release authority.

| Installation input | Control and evidence |
| --- | --- |
| Immutable role releases and launch plan | Portable maintenance uses typed local `/var/lib/dev-pair/bootstrap/gptbox-adapter/<context-sha256>/imported-releases/<platform-sha256>/<image-id>/<boot-id>.json` evidence with exact OCI, producer and current-boot probe identities. The existing local assembly route uses its exact `result.json`. Development reads the job's immutable `/var/lib/dev-pair/development/builds/<job>/inputs/<manifest-sha256>/manifest.json` and sibling OCI archive. The launch plan binds those manifests by digest. The portable resolver checks the mount, protected placement lease, directory identities, labels and manifest bytes. Retain both releases' inputs and bounded artifact overlap. |
| Current release | Seed the private `current.json` and `site-current.json` with the digest of the independently verified installed release. Start `dev-pair-renewal-host-observe.service` to measure the approved host bundle, current boot, Fedora version, hostname and enforcing SELinux. The recovery unit repeats that measurement after boot. |
| Stable tooling intake | Independent CI builds and attests the portable `platform.json` subject. The protected F intake verifies that subject with the D verifier and its approved workflow policy, checks its archived parts, and records exact `intake.json`. F’s native installer then imports exact roles, stages the job-specific manifests and produces the current-boot `installed.json` observation. `dev-pair-approved-agent-candidate.service` verifies the official stable Codex tag and derives the local release from those protected records and the independently approved site profile. Activation requires the resulting approval and unchanged offer bytes. A current offer or a withdrawal clears the former pending selection. A service failure leaves the current release running and records `agent-refresh.json`. |
| Scoped provider broker | Provision an approved credential under `/etc/dev-pair/provider-credentials/<credential_ref>` and an exact schema 1 grant for ordinary turns in `provider-grants/<request-sha256>.json`. `dev-pair-provider@<request-sha256>.service` starts the existing broker. The broker owns the labeled socket, validates the peer and records provider/model/usage evidence. The normal role runner admits an exact operation only after the protected socket is ready. |
| Host release and cleanup | Install `runtime/renewal/checklist-release.conf` in `/etc/systemd/system/dev-pair-checklist-executor@.service.d/` with the verified J executor unit. The drop-in preserves its fixed arguments through `checklist-entry`, selects the verified host bundle, and introduces the boot fence dependency. `dev-pair-managed-host-release.service` selects the exact reviewed host control-plane bundle and config, restarts the handoff executor and verifies its live PID, UID, cgroup, command and loopback listener. Recovery runs after the observer even when the observer fails. `dev-pair-renewal-owned-cleanup.service` consumes the exact role/job/operation records and nonce. DevBox owner identity is reserved before its operation can launch. Cleanup stops the request-bound broker and verifies and removes exact owned runtime containers. Ambiguous ownership retains the fences. |
| Host operation fence | The host-check executor holds a shared lease on the root-owned read-only `/var/lib/dev-pair/renewal-fence/owner.lock` during mutating handoffs. It denies execution while the persistent `frozen` marker exists. Read-only host status remains available. The renewer holds the exclusive lease through activation and recovery. |

The selected installation must additionally verify artifact custody, runtime/model access, native ownership/cleanup, the host service proof, boot recovery, and limits before enabling the timer. Use privileged entry permissions so agent processes cannot alter registry, launch plan, release selection or approval records. Keep verification turns on the normal role sandbox with no host action channel. Production credentials and document contents stay under their existing protected custody.

Store host bundles as `/usr/libexec/dev-pair/host-releases/<artifact-sha>/`. Their readonly `manifest.json` has schema 1, `source_revision`, `state_contract=1` and `files` mapping every relative file under `tools/` or `runtime/` to its SHA-256. The manifest's raw digest is the artifact identity. The host configuration at `/etc/dev-pair/host-releases/<config-sha>.json` has `schema=1`, `launch_contract=1`, `hostname`, `platform=fedora-44`, `selinux=enforcing`, and `role_launch_seconds` from 90 through 169. The controller checks its exact bytes and measures the live platform before selection. Lifecycle changes to Fedora packages, Tailscale or provisioning remain separate authorized site work.

Authorize unattended verification using root-private `provider-allowances/<credential_ref>.json`. The schema 1 profile contains `authorization_id`, `approved_until` as a Unix timestamp, `total_microusd`, `max_operations`, allowed `scopes`, and `permitted` records containing exactly `role`, `job`, `model` and `effort`. Its `grant` supplies `allowance_ref`, `allowance_sha256`, `spend_microusd`, `seconds`, `max_requests`, `max_request_bytes`, `max_context_tokens`, `max_output_tokens`, `input_microusd_per_million`, `output_microusd_per_million` and `observed_models`. Each grant permits at least two provider requests to run the bounded product tool and consume its output. Before reserving a replacement or rollback grant, the controller checks the exact broker tariff and a conservative body envelope covering the retained native rollout, staged startup and instructions, the new prompt, and stock tool exchange. An undersized grant or long retained transcript defers renewal before activation. The controller binds each generated request to the original logical session, UUID and checkpoint, and durably reserves only approved ceilings. Reusing a claim ID reads the previous exact reservation. With ordinary dispatch briefly fenced, the controller checks that the broker's independent job-wide escrow can fund every planned turn before expiry.

## Approval and dispatch

Controller records use UTF-8 JSON. Use private root-owned mode `0600` regular files. The release's exact file bytes identify it as `releases/<sha256>.json` under `/var/lib/dev-pair/renewal`. The schema 1 release has `source_revision`, `config_sha256`, `plan_sha256`, `ledger_contract`, `state_contract` and `components`. The contracts are both `1`. The four component keys are `host`, `devbox`, `maintenance-agent` and `development-agent`. Each names `source_revision`, `config_sha256` and `artifact_sha256`. The agent components also name `codex_version`. An imported `maintenance-agent` additionally pins its exact `platform_sha256`, which its launcher passes to P and deliberate host or DevBox renewal retains. The deployment `config_sha256` equals the host component's config digest. The launch plan at `plans/<plan-sha256>.json` has `schema=1`, `maintenance_context_sha256` and `development_manifests` mapping each development job to its exact manifest hash.

An independent admission service publishes either the stable agent offer, `requests/devbox.json`, or `requests/host.json` after verifying the approved source, immutable artifacts and compatibility with the retained release. Each schema 1 request contains `operation`, `scope`, `previous_sha256`, `target_sha256`, sorted `affected_jobs` and a short `reason`. Use a stable unique operation ID and retain it across retries. Agent intake writes the `requests/agent.json` approval from the exact verified offer. The agent scope allows only maintenance and development agent changes. The DevBox scope allows only its outer component. The host scope allows the host release and its configuration. A combined change needs staged compatible releases.

### Portable site selection

The portable release index is independent of site labels and paths. Its byte digest addresses `/var/lib/dev-pair/platform-releases/<digest>/platform.json`, beside the F `intake.json`, current-boot `installed.json`, and exact portable parts. The protected site profile at `/etc/dev-pair/renewal/site-configs/<sha256>.json` contains `schema=1`, `hostname`, `host_config_sha256` and `jobs`. Each approved job maps to `storage_bytes` and its exclusive `categories` with three outer and two inner classes. Include admitted manifest slots even if there is currently no job in that slot. Site governance owns the permitted profile digest. The CI artifact and verifier grant authority only for the portable subject's identities.

Root-private `offers/initial.json` and `offers/agent.json` use schema 2 with `scope`, `operation`, `platform_sha256`, `previous_release_sha256`, `site_config_sha256`, sorted `affected_jobs` and `reason`. The initial scope takes an unselected full package with `previous_release_sha256=null`. `renewal_site.py initial` derives protected local receipt files and prints the exact local release digest for host commissioning. It leaves the active pointers untouched. Agent scope requires the exact current local predecessor and exact prior portable index. The predecessor and candidate share the same immutable site profile and retain the exact current full host and DevBox base. The installed job manifest bytes are generated from the approved geometry, exact outer ID and development producer record. The resolver checks those bytes and their digest-addressed archive paths, the installed maintenance assembly and host bundle manifests. Before activation, the normal renewal preflight independently observes and verifies the actual selected and rollback images and archives.

The resolver pins the portable, site, plan and local release identities in `platform-bindings/<local-sha>.json`. A separate observation ties those identities to the F installed receipt and the current boot. The pending agent approval also covers the exact offer bytes. F supplies native imports and file installation, and G supplies the job-specific storage and SELinux layout. D uses the resulting exact local release for commissioning after the native installation checks. Deliberate host and DevBox changes use the existing scope requests with a separately verified local manifest. A deliberately selected mixed release needs its own verified portable binding before the nightly portable agent route can continue.

The trusted job coordinator enrolls each role/job with `renewal.py register <binding.json>` after its ledger checkpoint exists. The role binding uses the session controller's existing immutable fields plus `role`. For a production binding, `provider` is `gptbox`, `policy_sha256` records the admitted Codex configuration digest and `startup_sha256` records the startup manifest digest. The ledger still owns product identity and test checkpoints. Each role's registry owns its selected model and effort. Invoke authorized ordinary turns through `renewal.py turn <turn-spec.json> <prompt.txt>`. The private turn spec contains `operation`, `role`, `job`, `logical_session`, `session_uuid`, and `request_sha256` for the pre-staged schema 2 input. Use `null` for a first turn and the exact prior provider UUID for a resume. The registry leases and authorizes launch before the fixed driver invokes either role. Replaying a registered operation returns the original observation.

## Scheduled and on-demand operation

### Deliberate stable maintenance window

The stable publisher builds one complete signed package for protected main. Its
release environment identifies the exact preceding full package and the
approved artifact allocation. A live nightly agent pair can use that preceding
full package as its base. Stable preparation preserves that exact live pair as
the local recovery selection.

From the authorized root maintenance terminal, prepare the independently
reviewed release and inspect the displayed operation, affected jobs and four
component changes.

```sh
python3 -EBs /usr/libexec/dev-pair/tools/stable_renewal.py prepare \
  --reason 'Apply the reviewed stable platform repair'
```

The controller finds the protected-main run and subject through the existing
read credential, checks all four release proofs, and stages the exact native
artifacts under the original machine and site commitment. For an installation
that predates this entry point, open the separately approved successor checkout
using the [reviewed source procedure](../README.md#set-up-the-fedora-host). Run
each command below with `python3 -EBs tools/stable_renewal.py --kit-source-sha
<reviewed-successor-commit>` in that checkout. The controller checks the clean
exact checkout, its signed host bundle and the versioned driver before
activation. The existing fixed services stay available for recovery until the
fenced host step.

Preparation queues the exact window with the enrolled independent station.
Run `stable_renewal.py access-status` with the same command prefix to send
again if the station was unavailable or check for its decision. When the
command reports `stable-reviewer-trust-required`, ask the independent station
administrator to run `agent_observer_station.py stable-public-key`. Use the
public key and independently confirmed fingerprint for the one-time
`stable_renewal.py reviewer-trust --fingerprint <confirmed-fingerprint>`
enrollment. Paste the public key as a single line, then run `access-status`.

From the independent station's attended administration terminal, inspect the
queued window and approve the exact request using the enrolled access-plan
signer. Use its protected public key file when signing through its agent.

```sh
python3 -EBs /usr/libexec/dev-pair-observer/tools/agent_observer_station.py stable-pending
python3 -EBs /usr/libexec/dev-pair-observer/tools/agent_observer_station.py approve-stable \
  '<request-id>' --signing-key '<enrolled-access-plan-key>'
```

The station uses its existing named SSH route for each role and address
family, reads back the Tailscale policy under its independent reviewer
account, and returns the signed result through the same courier. Stable
approval uses the separately pinned access-plan key. The unattended nightly
job continues to process agent-only observations.

If the enrolled station predates the stable courier, its independent
administrator can update from the clean, separately approved successor
checkout.

```sh
python3 -EBs tools/agent_observer_station.py update-tools \
  --source-sha '<reviewed-successor-commit>' \
  --previous-kit '<protected-predecessor-checkout>' \
  --previous-source-sha '<installed-predecessor-commit>'
```

The update checks both source trees and the installed bytes. Existing station
accounts, approvals and mailbox remain in place. The destination uses the
exact signed host bundle to start a bounded observer for this request on
older hosts.

Apply the operation printed by preparation from the same root command prefix.

```sh
python3 -EBs /usr/libexec/dev-pair/tools/stable_renewal.py apply \
  --operation '<printed-operation>'
```

Apply polls the courier before entering the protected window. The controller
checkpoints every affected role, verifies native readback and resumes the
exact sessions. Reuse the same operation after
interruption. A compatible predecessor remains available for rollback. If a
protected fixed billing migration has already changed the launch chain, the
controller uses its recorded bounded forward recovery while keeping dispatch
fenced. After a reboot in that window, reuse the same operation. Apply keeps
the original signed approval and queues a fresh observation request for the
current boot of the exact fenced placement. Waiting for the station keeps the
operation and its recovery allowance intact. Reuse apply to collect the new
proof and finish the recorded transition.

Use the selected signed stable checkout for ordinary Day 0 status and resume.
These recheck the current placement and preserve the initial commissioning
policy, maintenance journal and source kit. A checkout with stable routing can
also find an already staged selected successor using its original Day 0 entry.
For an earlier immutable kit without stable routing, keep it for the
enrollment record and run the ordinary commands from the reviewed successor.

Before the stable activation journal is published, the controller verifies the
installed recovery services and hands boot recovery to the exact signed host
bundle for that window. On restart, recovery resumes the recorded operation
with its original job and session fence. It sends any required current-boot
access request to the enrolled independent station and checks for the signed
response for up to 45 minutes. The exact operation remains fenced while the
response is pending. Use its ordinary pinned `apply` command to continue after
the boot polling window or to use the offline handoff. The temporary service
handoff is cleared after a verified thaw, and the regular recovery service and
scheduled reconciliation return to their installed commands.

### Nightly and scoped manual operation

The engineering schedule is `04:00 Asia/Tokyo`, with persistent missed-run handling. Enable `dev-pair-renewal-agent.timer` and `dev-pair-renewal-recovery.service` after the installation gates pass. The timer and operator use the same service, including candidate resolution. For an on-demand check, start `dev-pair-renewal@agent.service`. The separate deliberate release windows use `dev-pair-renewal@devbox.service` and `dev-pair-renewal@host.service`. These commands consume only approved requests and accept no executable input. The boot recovery service uses the same reconciliation logic and exact interrupted operation.

Before activation, the controller publishes a private `attempts/<attempt>/inventory.json` and pins its digest in the journal. It reconciles both physical workspace and state roots against the protected role registries and job ledger. The maintenance assembly probe is accepted as infrastructure only when the completed current image assembly receipt and all three exact owned empty probe leaves agree. It independently reads the native Codex SQLite and rollout catalogues. Archived threads and their rollouts stay in the backup, while current UUIDs each require a protected logical-session binding. The inventory includes checkpoint hashes, complete uncommitted source and session tree digests, target and credential references, and host request and effect identities. Activation also requires a verified clean restore, both releases' actual locally inspectable artifacts, and usable broker grants. Active turns drain under their original ownership. The workload's cache stays in its separately managed durable mount.

Before replacing either runtime, the checklist adapter executes the bounded continuation against the actual saved source, including uncommitted edits. Its disposable baseline unit runs as the dedicated role account with network and live application data restricted. A failed baseline or unrecognized adapter defers activation and reopens original dispatch after verifying the retained release. After replacement, each role resumes the same UUID through its Distrobox placement. The completed turn must retain the original native rollout prefix, append history and repeat the observed product action at the saved checkpoint. The journal binds this typed result to the exact job, role, UUID, checkpoint, operation, measured image/version and provider receipt. The original host test and its pending ID remain available to the product supervisor.

General DevBox jobs use their own protected agreement, saved local-validation evidence and exact tested candidate. Both roles first re-observe their current Git revision, exact workspace bytes, original UUIDs and the retained authenticated test events. The development role repeats the supported Python `unittest` action on a disposable copy of its saved source and records the actual test count. Maintenance performs the approved read-only source and validation review. The controller runs the same bounded baseline with the workspace mounted read-only in an isolated role process before replacement. A passing baseline can preserve uncommitted general work and the original `awaiting-external-validation` state. An unsupported test, unresolved local checkpoint or failing baseline defers renewal and restores ordinary dispatch. The authorized test selects a fixed local adapter with an allowlisted argument vector. External validation retains its separate approval.

The persistent effect fence stays closed through current-boot host observation, typed imported maintenance readback and pending-operation reconciliation. If the process stops after accepting the target and before clearing the fence, recovery rechecks the target and either finishes the exact cutover or verifies and activates the funded compatible predecessor. Recovery can reseal a partially opened registry only when the protected dispatch gate prevented new operations and its exact saved operation history still agrees. An ordinary later boot uses a separate marker and never replays a completed transition. The imported maintenance readback uses the fixed offline F installer re-observation path for an already retained image after a reboot. Interrupted rollback uses the saved launcher, CLI and broker evidence for a settled operation. Uncertain operations stay fenced.

Inspect the latest journal with `renewal.py status`. A pre-disruption deferral can retry after 30 seconds. Each scope and target can incur at most three deferred attempts, and rejected and rolled-back targets retain their decision across operation IDs. A newly approved return to a previously successful release gets a fresh activation generation and actual live proof. An exact completed replay also checks the live identity. `blocked` retains the durable fence and recovery evidence. Backups include private source and history. The first implementation bounds the entire set at 16 active sessions, 64 jobs, 32 retained attempt directories, and 512 MiB of source/state copy per attempt. It requires an eight GiB free-space reserve plus copy capacity. A larger set defers as a whole. Retain relevant target decisions, compatible releases and useful backups, and remove only independently checked terminal data under the storage policy.

## Evidence

Run `python3 -m unittest discover -s tests -p 'test_renewal*.py'` for local component evidence. These tests use real SQLite registries and ledger records, real filesystem trees and an external subprocess, including termination of the controller after a replacement effect and restoration of both missing registry directories. Stock authenticated provider progress, physical Fedora release activation, host reboot, stable tooling CI resolution, scoped broker custody and the actual scheduled firing require the authorized target and its installed services.
