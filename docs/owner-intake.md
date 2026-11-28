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

## Installed intake service

Host commissioning installs these files from the independently reviewed
release with root ownership and protected ancestors.

| Source | Installed path and mode |
| --- | --- |
| [Terminal command](../runtime/product-job/dev-pair) | `/usr/local/bin/dev-pair` mode 0755 |
| [Protected entry](../tools/owner_intake.py) | `/usr/libexec/dev-pair/tools/owner_intake.py` mode 0755, alongside the existing trusted Python components |
| [Scoped sudoers rule](../runtime/product-job/dev-pair-owner.sudoers) | `/etc/sudoers.d/60-dev-pair-owner` mode 0440, admitted by `visudo` |
| [Preparation service](../runtime/product-job/dev-pair-intake@.service) | `/etc/systemd/system/dev-pair-intake@.service` mode 0644 |
| [Scheduling recovery service](../runtime/product-job/dev-pair-intake-recovery.service) and [timer](../runtime/product-job/dev-pair-intake-recovery.timer) | Matching filenames under `/etc/systemd/system`, mode 0644 |
| [Private directories](../runtime/product-job/dev-pair-intake.conf) | `/etc/tmpfiles.d/dev-pair-intake.conf` mode 0644 |

Commissioning enables `dev-pair-intake-recovery.timer` after the configured
role and product roots and a current site grant are present. The timer observes
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

The installed [product](product-job.md), [role](role-entry.md), renewal and
[Fedora executor](host-handoff.md) paths share the protected commissioning
policy. Trusted role selection, provider credentials and allowance, independent
release and named operator access control intake. The fixed role directories
`/var/lib/dev-pair/{maintenance,development}/conductor-inputs` use mode 0700
and belong to their respective role accounts for bounded Git transfer.

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

Choose a provider credential reference at the hidden prompt. For a new
reference, enter the scoped OpenAI project or service-account key at the hidden
prompt, or give the wizard the path of the key in a root-private file. The
provider credential custodian obtains the key from the authorized OpenAI
project. Billing approval and the owner's job budget cover separate decisions.

### Provider billing handoff

The wizard enrolls the separate billing custodian's OpenSSH Ed25519 public
key after you enter its SHA256 fingerprint from a separately authenticated
channel and confirm that exact identity. The custodian keeps the private
signing key. Use the billing custodian's own approved identity.

Send the wizard's protected request to that custodian over the authenticated
handoff channel. The wizard displays the request and expected return paths
under `/root/dev-pair-provider-billing`. The request binds the VPS, credential,
reviewer enrollment and selected model. The custodian checks the actual
OpenAI organization and project, credential assignment, full billable input
ceiling, highest applicable input and output rates, and exact response model
identities. Use `tools/provider_billing.py review --help` at the exact reviewed
source to produce the signed bundle from the evidence. Return it as a
root-owned mode-0600 file at the displayed path. On reopening, the wizard verifies
the bundle and checks model availability through a read-only OpenAI request
using the reviewed project and credential. Enter a different protected bundle
path if needed.

Enter the approved total USD cap and UTC expiry. Before confirming, check the
exact checkout, startup revision, verified private destination, role limits
and selected slot displayed by the wizard. The wizard publishes the
catalogue and role profiles. It can join an interrupted publication and retains
existing catalogue and job history. Resume Day 0 to finish activation. The
normal owner command has its own approval for each later product job before
issuing its job-bound provider allowance.

For a configured catalogue, reopen the same wizard to reauthorize an unused
slot with fresh signed terms and explicit budget consent. The catalogue,
original slot profiles and prior receipts are retained. A retained draft or
job reserves its existing slot. Older unscoped allowances remain available
for historical inspection and carry zero spendable balance. Their jobs need
freshly approved authority on another eligible slot before any further paid
work.

The same wizard can withdraw the selected credential's current terms,
withdraw the billing reviewer, or enroll the replacement reviewer. Enter
`billing` at the repository prompt to reach these actions before a catalogue
has been configured. Use
fresh signed terms for the resulting credential and enrollment. The broker
checks the current terms, signature and enrollment immediately before each
paid request. Before continuing a billing change, Day 0 holds new provider
starts and verifies the installed systemd fence. An earlier provider
instance or queued start can finish within its existing service limit.
Day 0 retains the exact pending change and applies it after verified idle
readback. Use the usual resume command while the transition is pending.
A request accepted before withdrawal can still incur a charge. Its reserved
effect stays recorded through the transition.

At reboot the start fence defaults to closed. The installed boot fence can
restore provider readiness from the current systemd and kernel readback.
An interrupted attended billing change stays pending for Day 0 to finish.
If the exact pending input can no longer be used, reopen owner setup and
choose `discard-pending` after confirming the decision. Any custody already
committed is retained.

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
