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

Enable `dev-pair-agent-bridge.timer` after initial platform and renewal recovery
have been verified. The timer starts at 04:00 JST and observes that morning’s run
every 15 minutes through 09:15. It also observes recent authorized manual runs
throughout the day. `systemctl start dev-pair-agent-bridge@on-demand.service` can
wake an immediate observation of a manual run from the past six hours. A run
waiting for completion remains eligible for a later observation. The bridge
checks GitHub's exact completed run and artifact transport, calls the existing
independent attestation verifier and native installer, and confirms the retained
base and same-boot placement proofs. It rechecks the live predecessor and that
renewal is idle under the owner lock before recording the offer. The ordinary
`dev-pair-renewal@agent.service` owns continuity validation, activation and rollback.

The existing artifact store retains at most three full or agent packages and
must have its verified physical reserve. A base plus two successful agent refreshes
fits the package count. Later acquisition requires the existing bounded retained
release policy to reconcile old packages with dependency and rollback evidence.
The bridge performs no package pruning and preserves the active and recovery bytes.
