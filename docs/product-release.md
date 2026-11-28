# Promote a validated checklist

The installed `dev-pair start` command on `core` records and confirms the product agreement. When its checklist job returns a changed source candidate, successful confined local validation, and the authenticated checklist restart and persistence result for that same candidate, the protected promotion timer can take it through review and delivery. The job keeps its original ID. Use `dev-pair status JOB` for the current record or `dev-pair reattach JOB` to follow changes for up to two minutes at a time. Both retain the validation result and show the separate promotion phase, proposed pull request, published image, and destination as that evidence arrives. The destination is confirmed only once the independent verifier and the live service agree on the deployed result. See [owner intake](owner-intake.md) and [destination release](destination-release.md).

The supported promotion scope is the existing checklist in `oso-gato/dev-pair`, delivered to the exact private tailnet DNS name in the confirmed agreement and the site policy. Validated local jobs keep their local evidence. Other requested external destinations retain their pending adapter status. The checklist proposer accepts regular modifications to the existing checklist application, its focused tests, and its README. The host retains the Q result and effect identity, source materialization receipt, exact Git commit and tree, and incremental candidate bundle.

## Enroll during Day 0

After the named `core` terminal is ready, `./day0.sh resume` offers optional
checklist promotion. Defer it to run local checklist jobs while the separate
release authorities are being prepared. Obtain the independently approved
fork, GitHub proposer and observer logins, merge actor and protection App IDs,
merge-workflow SHA-256, and the UTC grant expiry. The grant can last up to 31
days. The installer reads the private destination from the approved owner
catalogue and checks it against the live guarded route.

Enter three separately scoped fine-grained credentials at the hidden prompts.
One grants the proposer branch write in the single admitted fork. The second
identifies the same proposer and grants upstream pull request creation with
read-only upstream contents. The third identifies a separate observer with
read access to repository metadata, contents, branch protection, deployments,
PR reviews, checks, actions and attestations. The GitHub accounts have no
upstream push, maintenance or administrator role. Provide a fourth pull-only
GHCR credential if the checklist registry is private. The independently held
reviewer and upstream merge credential stay in their separate approved custody.

The setup reads back the exact fork and GitHub identities, protected main,
required check, workflow bytes and the separately gated merge and publisher
environments before it asks to activate the confirmed scope. Commissioning
installs the reviewed controller and units and enables the owned scan timer
when local custody and current independent workload access are ready. The
bound `dp-release-dev` account has a locked password and no login or extra
system group. The proposer receives read access to its two root-owned
credentials. Proposal checkout work uses a 256 MiB dedicated tmpfs with
`nodev,nosuid,noexec`. The root observer and optional registry credential have
separate protected storage. Setup checks GitHub CLI support and installs
Skopeo through Fedora's signed package repositories if it is absent.

After a disconnect, rerun `./day0.sh resume`. If enrollment was interrupted
before activation, use the same approved expiry, identities and credentials to
finish it. A changed enrollment must first withdraw the old custody. For
withdrawal, use the authorized root terminal and run:

```sh
/usr/bin/python3 -EBs /usr/libexec/dev-pair/tools/promotion_setup.py withdraw
```

A running promotion must settle before withdrawal can acquire the custody
lock. Withdrawal removes the locally enrolled credentials and holds new work.
Run `./day0.sh resume` to remove the owned timer schedule. Job state and
independent evidence remain available. Revoke or rotate the remote credentials
through their custodians. To replace withdrawn authority, run the installed
`promotion_setup.py enroll` command and then resume Day 0.

The timer schedules eligible terminal product jobs after boot and on a
three-minute interval when current commissioning admits it. The protected
root entries are `product_release.py status JOB` and `product_release.py
advance JOB`, run with `/usr/bin/python3 -EBs` from the installed tools path.
Advance observes the existing proposal and deployment before any next allowed
mutation. Observational failures retry after three, six and twelve minutes.
Resolve a held authority or verifier rejection before using `advance JOB
--resume-held`.

## Independent upstream merge

Configure the independently administered main branch gate with enforced reviews, stale-review dismissal, last-push approval, the strict pinned required check, and no review bypass. Enable merge commits. Register `CHECKLIST_PRODUCT_FORK` and `CHECKLIST_PRODUCT_DEVELOPER_ID` as independent repository configuration for the PR check. The existing read-only `release-source-check` runs on the synthetic merge tree for that fork, author and branch prefix. Pin its updated file digest in release trust and merge policy when commissioning this route. Verify GitHub lets that expected ordinary fork check run under the approved repository Actions policy.

The protected scheduled `checklist-product-merge.yml` job runs from upstream protected main. Configure the `checklist-merge` environment with the exact `main` branch and an independent workflow-specific deployment-protection App. It must admit only this protected workflow, repository, branch and allowed events. In that environment, set `PRODUCT_MERGE_POLICY` to the closed JSON object with `version` (1), `developer_id`, `fork`, `merge_actor_id`, `reviewer_ids`, `check`, and `expires_unix`. Use the same reviewer IDs and `check` object as the protected host trust policy. `CHECKLIST_MERGE_TOKEN` is a separately held non-admin fine-grained credential for the upstream developer-side merge actor. It needs protected readback and the scoped upstream contents permission for the exact-head merge. Keep it in the protected upstream environment. This credential allows the resulting push to trigger the normal publishing workflow. The proposer and host observer lack that credential.

The independently held reviewer approves the actual current candidate in GitHub after the fresh review specified by the repository's model and effort rules. The merge job searches open upstream main proposals by the approved author's GitHub identity and checks four pages of up to 30 results. Invalid marked proposals receive a hold keyed by PR number. The job excludes both the PR author and merge actor from eligible reviewers, verifies the pinned CI run and the tested merge tree and parent pair, and supplies the exact head to GitHub's protected merge operation. Branch policy applies atomically. A stale base or changed head remains held under the original job. It requires freshly authorized development and validation before any new proposal. Once merged, the host observer checks the actual merge actor, parent pair, tree, independently approved review and matching postmerge CI workflow run. The publisher's tag is only a lookup for a manifest digest. The destination controller receives the signed OCI subject at that digest and verifies it again before deployment.

## Independent destination evidence

The normal observer advances the release through the existing destination controller and observes its active, pending, and confirmed records. It can resume the same pending deployment and recover a lost reply from the exact active record. A different pending or unconfirmed activation remains held. After independent quarantine of a failed first release, the controller can admit an independently reviewed correction with a different verified digest.

The independent verifier exercises the named private URL and the required
access, persistence, restart, reboot and restore checks. The verifier returns a
fresh signed envelope for the same job through the protected proof importer.
The D verifier checks the signature, current boot and guard, exact source and
OCI, exact DNS, actual live item and required observations before recording
confirmation. The resolved image and DNS remain visible while the signed proof
is pending or expired. Keep the independent signing authority and probe access
outside the host, proposer and provider roles. [Independent destination observations](destination-observation.md)

The implementation can be exercised locally with an isolated Git fork, synthetic GitHub API and a fixture activation journal. The protected GitHub permissions, workflow App, independent reviewer, registry publication, actual Fedora destination and independent probe producer require commissioned authority and real observations.
