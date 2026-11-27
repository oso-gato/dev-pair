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

Keep the following under `/etc/dev-pair/product-intake` in root custody. The
catalogue `repositories.json` has schema 1 and the fields `schema`,
`repositories` and `slots`. The repository map binds each allowed
`owner/repository` to its exact Git `commit`, `startup_revision`,
human-readable private `destination` and optional list of approved
`workloads`. Existing entries without that list keep the checklist workload
they were configured for. The slots list gives the allocation order for
unused job IDs in the approved renewal plan. Intake skips slots with active
or retained job data, missing layout authority or an expired allowance.

For each repository, place protected Git checkouts at
`repositories/OWNER/REPOSITORY/acquired` and
`repositories/OWNER/REPOSITORY/startup`. The acquired checkout comes from the
approved GitHub origin at the configured commit. Repositories approved for
the checklist workload also contain that adapter's application source.
The startup checkout supplies the repository's
reviewed project documents at the configured revision. Place the verified
private standards cache at `standards`. The existing startup loader verifies
each repository's exact adoption and complete documents. At confirmation the
normal `gptbox.py approve-job` entry binds the acquisition, startup corpus and
agreed brief.

Each `slots/JOB/profile.json` contains these fields.

| Field | Value |
| --- | --- |
| `schema` | 1 |
| `host_seconds`, `build_seconds`, `turn_seconds` | Approved limits within the existing conductor maxima |
| `allowance_ref`, `spend_microusd`, `expires_unix` | Approved provider account reference, total job spend ceiling and actual expiration |
| `pricing` | Existing broker model fields `max_context_tokens`, `input_microusd_per_million`, `output_microusd_per_million`, `observed_models`, `context_evidence_sha256`, `tariff_evidence_sha256` |

Store the reviewed evidence as `slots/JOB/gpt-6.2-sol.context` and
`slots/JOB/gpt-6.2-sol.tariff`. Those files carry the existing broker's verified
billing ceiling and tariff for the actual account. The site's approved
allowance must cover all available grants. An unavailable or expired provider
authorization blocks preparation.

Each `slots/JOB/ROLE/profile.json` has the conductor's `runtime_sha256`,
`binary_sha256`, `layout_sha256`, named `credential_ref` and a `grant`
containing exactly `spend_microusd`, `seconds`, `max_requests`,
`max_request_bytes` and `max_output_tokens`. Store the credential in the
protected role provider path. Intake materializes the job-bound allowance and
role limits so the existing broker can validate them before role execution.

Each `slots/JOB/ROLE/seed` uses the reviewed role configuration and exclusive
SELinux categories. Include readonly placeholders for `turn/request.json`,
`turn/prompt.txt`, `turn/approval.json`, `turn/startup/manifest.json` and all seven
named startup documents. Intake preserves the seed's assigned role group
access and readonly metadata while binding the approved acquisition and
verified private startup files. The conductor replaces its request and prompt
placeholders during normal turn entry. Keep unallocated job inputs outside
the role workspace and state inventories.

## Validation

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_owner_intake.py -v
```

The local checks use real Git objects, private durable files and the regular
product submission path with fixture approval, placement and systemd seams.
The installed sudo rule, enforcing Fedora labels, actual provider allowance,
role placement and owner reconnect journey require native acceptance.
