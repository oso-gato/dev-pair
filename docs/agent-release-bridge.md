# Scheduled and on-demand agent release intake

GitHub Actions starts the protected `agent-refresh.yml` run at 04:00 JST. Its fixed
manual dispatch accepts no build or source arguments. The independently approved
workflow verifies the official latest stable release tag, source commit, archive,
executable and Sigstore bundle. Each disposable role builder verifies the selected
bytes and signature again. Its authenticated native Fedora guest binds the selected
tooling to that role’s exact reviewed checkout and input context. The hosted
publisher attests the single canonical portable agent index. The normal full
platform publisher keeps its existing fixed-input behavior.

A schema 3 agent index fixes the retained full platform base and leaves the site
predecessor empty. The protected destination supplies the exact active local
platform to release intake. Intake records it in the private `site-predecessor.json`
alongside the existing `intake.json`. Renewal binds both records, the exact local
release selector and the selected site configuration into the new release. Schema 2
packages continue to carry and enforce their signed exact portable predecessor.
A newly signed upstream version must advance both agent image digests. A repeated
version may produce a new image with the same signed executable and tag source.
The destination rejects a lower version and a changed executable or signing
commit under the current version.

Install the bridge from the same protected host bundle as the release verifier,
installer and renewal scripts. The release policy must pin the approved workflow
bytes for both agent roles. GitHub's protected `agent-refresh` environment needs
its authorized independent enforcement, a deliberately selected `PLATFORM_BASE_SHA256`,
the existing enabled flag and an approved artifact budget. The base variable tracks
the selected full host and DevBox lifecycle. Site access uses the existing read-only
GitHub credential and protected local release bindings. The host never dispatches
GitHub Actions or modifies repository policy.

Day 0 commissioning arms `dev-pair-agent-bridge.timer` after the initial
platform, renewal recovery and agent publisher authority have been verified. The bridge
service starts `dev-pair-agent-observer.socket` on demand. The timer starts at 04:00 JST and observes that morning’s run
every 15 minutes through 09:15. It also observes recent authorized manual runs
throughout the day. `systemctl start dev-pair-agent-bridge@on-demand.service` can
wake an immediate observation of a manual run from the past six hours. A run
waiting for completion remains eligible for a later observation. The bridge
checks GitHub's exact completed run and artifact transport, calls the existing
independent attestation verifier and native installer, and confirms the retained
base and same-boot placement proofs. It rechecks the live predecessor and that
renewal is idle under the owner lock before recording the offer. The bridge also requires a signed prospective result for the exact candidate before
offering it to renewal. The ordinary `dev-pair-renewal@agent.service` checks the
observation again and owns continuity validation, activation and rollback.

The existing artifact store retains at most three full or agent packages and
must have its verified physical reserve. A base plus two successful agent refreshes
fits the package count. Later acquisition requires the existing bounded retained
release policy to reconcile old packages with dependency and rollback evidence.
The bridge performs no package pruning and preserves the active and recovery bytes.

The latest scheduled outcome is written to the protected renewal control directory
as `agent-nightly.json`. It records the observed run or missed window and the exact
retained site release, platform and Codex version. A late observation can see a
failed or missed run without attempting activation outside the schedule window.
Discovery uses a separate fixed scratch directory, which reclaims only its owned
partial portable index on a later attempt.

An obsolete bridge-owned offer can be replaced only after independent verification
and same-boot staging of a newer current official stable. The exact predecessor
must still be active and no agent request or matching renewal attempt may exist.
The prior installed evidence stays available for scoped recovery.

## Enroll the independent nightly verifier

After the initial signed workload review, the independent station administrator
runs `tools/agent_observer_station.py install --help` from the exact protected
station checkout. Installation takes the prior signed workload receipt, its
trusted public signers, the approved host and guard digests, and the separate
courier, collector and reviewer account inputs. The reviewer uses
`tools/agent_observer_station.py enroll-acl` with a new private path for its
approved read-only Tailscale OAuth credential. The station measures the live
policy against the independently signed workload receipt before enabling its
station timer. The restricted courier mailbox uses the existing Day 0 SSH
transport. [Access station setup](owner-day0.md#independent-access-station-setup)

The installed station verifies both independently approved signing keys during
collection, assembly and publication. A withdrawn key holds the station's
owned timer and leaves retained access evidence in custody. For an approved
reviewer rotation, update the protected public trust and selected public key
at their registered paths, enroll the new key in the reviewer's agent and
rerun installation with a matching independently signed workload receipt.
Setup checks the loaded service and timer before and after arming. Conflicting
service policy holds the station timer. The only admitted service drop-in is
the verified stock Fedora 44 timeout policy. Resolve other overrides through
the station administrator and rerun the checked installation.

For an earlier provisional development station, preserve the private mailboxes,
independent evidence and credential custody during a separately reviewed
replacement window.

On the destination, `./day0.sh resume` offers to enroll the collector when
agent renewal is waiting for that approval. Supply the collector's public
key and its `SHA256:` OpenSSH fingerprint from a separate verified handoff.
Use `./day0.sh observer-trust` to enroll it directly. The collector's key is
separate from named SSH, station transport, billing and final access signing.
To withdraw the collector, run `./day0.sh observer-trust --revoke` and enter
its exact enrolled fingerprint. Pending automatic observations from that key
lose authorization. The selected release may need a fresh workload review
if its current approval used the withdrawn key.

The collector connects as the admitted named operator over Tailnet SSH and
uses the destination observer gateway for the exact candidate on both role
paths. The independent reviewer checks the observations and current policy
under separate signing custody and returns the signed response. The bridge
holds activation when that response is missing, expired or invalid. The
station timer and worker are installed on the verifier station. Commissioning
the destination installs only its bridge and local observer gateway.
