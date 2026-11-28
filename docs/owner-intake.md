# Start a job from the owner terminal

Connect as the named operator `core` over the authorized tailnet route. Give
the command an approved repository and a short product brief.

```sh
dev-pair start owner/approved-repository
```

For a multiline brief, give the command a local file. Include a known
acceptance criterion and data limits when they matter.

```sh
dev-pair start owner/approved-repository --brief-file brief.txt \
  --audience 'People who already use the private checklist' \
  --access 'Existing users retain current access and item ownership' \
  --acceptance 'The same completed item appears once after restart' \
  --constraints 'Keep existing data and item IDs' \
  --workload checklist-persistence
```

The command asks for missing product decisions before it makes a draft. Give
the intended users, who may act or access affected data, and a result those
users should be able to observe. Include those answers in flags or use the
lines `Users:`, `Access:` and `Acceptance:` in the brief. The preview shows
those answers alongside the exact repository, starting commit, delivery
destination, validation scope, startup policy and limits. Answer yes once
to confirm the displayed agreement. Use `dev-pair draft` to save it for later
confirmation. The preview prints its job ID and confirmation digest.

Select the validation path that fits the outcome and is approved for the
repository. `checklist-persistence` repairs restart persistence in the
existing app with its access and sharing policy preserved.
`general-development` runs authorized development and tests in the confined
DevBox. Use `general-with-external-validation` and describe the additional
check with `--external-validation` when full acceptance needs a boundary
beyond DevBox. DevBox work can proceed, and the external check remains
pending until that boundary has an admitted adapter.

```sh
dev-pair submit JOB AGREEMENT_SHA256
dev-pair status JOB
dev-pair reattach JOB
dev-pair agreement JOB
```

Save the job ID before disconnecting. Preparation and product work run in
detached services and publish durable state. Reattach reads the same job
and shows recorded role session IDs and validation evidence as it becomes
available. A confirmed job whose scheduling was interrupted is retried within
fixed bounds, including after host restart. Recovery reuses the confirmed
plan and original role inputs. The saved agreement and diagnostics remain
readable when preparation stops. Use a new draft for a materially different
brief.

The [product loop](product-job.md) owns workspace changes, scoped tests,
candidate repair and role registration. The controlled private release
process remains the delivery path.

## Install the intake once

Install these files from the combined independently reviewed release, with
root ownership and protected ancestors.

| Source | Installed path and mode |
| --- | --- |
| [Terminal command](../runtime/product-job/dev-pair) | `/usr/local/bin/dev-pair` mode 0755 |
| [Protected entry](../tools/owner_intake.py) | `/usr/libexec/dev-pair/tools/owner_intake.py` mode 0755, alongside the existing trusted Python components |
| [Scoped sudoers rule](../runtime/product-job/dev-pair-owner.sudoers) | `/etc/sudoers.d/60-dev-pair-owner` mode 0440, admitted by `visudo` |
| [Preparation service](../runtime/product-job/dev-pair-intake@.service) | `/etc/systemd/system/dev-pair-intake@.service` mode 0644 |
| [Scheduling recovery service](../runtime/product-job/dev-pair-intake-recovery.service) and [timer](../runtime/product-job/dev-pair-intake-recovery.timer) | Matching filenames under `/etc/systemd/system`, mode 0644 |
| [Private directories](../runtime/product-job/dev-pair-intake.conf) | `/etc/tmpfiles.d/dev-pair-intake.conf` mode 0644 |

Enable `dev-pair-intake-recovery.timer` as part of controlled installation
after the configured role and product roots are present. The timer observes
only confirmed jobs from the bounded intake catalogue. A job has up to eight
schedule attempts and four preparation attempts. A confirmed job with an
acknowledged product start can recover once per boot while its durable
product state is eligible. Terminal jobs and jobs whose normal conductor
has exhausted automatic retries stay available for inspection.

The named operator rule invokes the fixed entry with zero command-line
arguments. The entry accepts a bounded stdin request containing the
repository, brief, or job ID and agreement digest. Site paths, startup source,
execution scope, role profiles and budgets come from root-owned configuration.
The terminal command reads a brief file as the operator and passes only its
text. The preparation unit uses a separate internal mode.

Provision the ordinary [product](product-job.md), [role](role-entry.md),
renewal and [Fedora executor](host-handoff.md) paths first. Trusted role image
selection, provider credentials and allowance, independent release and named
operator access are part of controlled setup. Keep
`/var/lib/dev-pair/{maintenance,development}/conductor-inputs` as fixed
mode-0700 directories owned by their role accounts for bounded Git transfer.

The intake reads the selected renewal launch plan's admitted
`development_manifests` map. A slot has a released DevBox manifest, bounded
build filesystem and root-owned templates. Its role workspaces, state and cache
leaves are created after the owner confirms. Approve the provider and product
limits for each available slot in advance. The pool serves different
authorized repositories. A used slot retains its original logical job ID and
durable history. Automatic replenishment needs verified terminal jobs,
preserved backups and results, settled pending operations and sessions, and
a freshly approved logical ID and manifest.

### Repository and slot inputs

On a new commissioned site, accept the first owner setup prompt in
`./day0.sh resume` in the protected root terminal. To reopen that same wizard,
use the installed entry.

```sh
/usr/bin/python3 -IB /usr/libexec/dev-pair/tools/owner_intake.py --setup-site
```

Select the authorized repository and workload. On first acquisition, enter the
approved full project commit and startup commit. Enter uses the project commit
for startup. Confirm the exact GitHub origins and revisions. The wizard uses
hidden prompts for approved GitHub Contents read tokens. A public project can
be read without a token. The separate private `oso-gato/standards` repository
requires its own authorized read access for the exact adopted commit. The wizard
verifies the approved objects and startup corpus, then retains them in protected
custody. Use `--restore-source` to recover approved inputs and
`--rotate-source-credential` to replace a stored Git read credential after its
exact read check. Both use the same protected terminal and installed entry.

Use the hidden provider credential-reference prompt to select a registered
OpenAI project credential with signed billing terms. The protected provider
custodian gets the scoped credential from the authorized OpenAI project.
The independent billing reviewer measures the actual credential assignment,
full billable input ceiling, worst applicable input and output prices, and
allowed response model identities. Billing approval and the owner's job
budget cover separate decisions.

### Provider billing handoff

Use `tools/provider_billing.py` in the exact reviewed checkout, or the same tool
under `/usr/libexec/dev-pair/tools/` after installation. In the protected root
terminal, `register --credential-ref` takes the custodian's root-private
`--secret-file`. Then `request --credential-ref` writes the protected request
using `--output`. Send the request on the authenticated custody path to the
independent billing reviewer. That reviewer uses `review --help` for the full
set of reviewed inputs and signs the account, project and terms outside the
host and roles. The independent signing public key must be admitted in the
protected `/etc/dev-pair/trust/allowed_signers` under principal
`provider-billing` and namespace `dev-pair-provider-billing`.

In the protected root terminal, `receive --credential-ref` takes the review
bundle through `--bundle` or standard input. It checks the signature and live
project and model availability, then issues the protected records the broker
reads. Keep the API key in protected file custody and the reviewer signing key
with the independent reviewer. A missing, expired or rejected review keeps
first owner intake pending.

When the wizard displays the exact checkout, startup revision, verified
private destination, role limits and selected slot, enter the approved total
USD cap and UTC expiry and confirm the matching plan. The wizard publishes the
catalogue and role profiles. It can join an interrupted publication and retains
existing catalogue and job history. Resume Day 0 to finish activation. The
normal owner command has its own approval for each later product job before
issuing its job-bound provider allowance.

Protected automation can inspect the exact plan through `--inspect-site --help`
and confirm it through `--initialize-site`. These entries read the same signed
billing authority. Keep source, catalogue and role profiles in the protected
intake and role directories installed by commissioning.

## Validation

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_owner_intake.py -v
unshare --user --map-root-user /usr/bin/python3 -B -m unittest discover -s tests -p test_first_owner_catalogue.py -v
```

The local checks use real Git objects, private durable files and the regular
product submission path with fixture approval, placement and systemd seams.
Set `DEV_PAIR_TEST_STANDARDS_CACHE` to the verified private cache path to
exercise the read-only first-catalogue preview with the actual pinned corpus.
The installed sudo rule, enforcing Fedora labels, actual provider allowance,
role placement and owner reconnect journey require native acceptance.
