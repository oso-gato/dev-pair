# Protected Fedora platform publication

The protected platform workflow builds the maintenance gptbox, development gptbox, outer DevBox and host control-plane bundle for one exact reviewed `main` commit. It uses standard GitHub-hosted Ubuntu runners. The existing Fedora PR probe continues to provide component-test evidence.

## Independent release authority

Merge through the independent branch and required-check policy, then authorize the exact run through the `platform-release` GitHub environment. The environment supplies the portable recovery selection and allocation.

| Setting | Value |
| --- | --- |
| `PLATFORM_PREVIOUS_SHA256` | Previously verified platform index digest, or `initial` for an empty staging store |
| `PLATFORM_ARTIFACT_BYTES` | Independently available no-spend Actions artifact capacity covering three 2GiB OCI archives, host and subject files, and transport overhead |

A release requires the protected push event, exact clean checkout, first run attempt,
integrated placement/review/renewal source and a currently verified upstream stable
Codex tag matching the repository's signed input pins. The publisher checks for a
new official version before starting the build. A changed stable release requires a
matching reviewed pin update or the separately approved refresh resolver.

Only the publication job receives GitHub attestation permissions. It attests the
exact `platform.json` schema 2 file after verifying the four build outputs. The
portable index binds repository, source, run ID, adopted standards, state/policy
contracts, raw host bundle manifest, exact OCI config and manifest digests,
and archive hashes and lengths. The run summary supplies the subject digest.
Actions retains the artifact parts for one day. Capture verified bytes on the
host within that window.

The protected destination controller uses its approved site configuration,
actual local placement and exact previous/current portable digests to derive
and durably bind the job manifests, launch plan and local renewal release.
The CI producer has no site topology inputs. Exact source, role, image ID,
archive or previous/base mismatch blocks admission.

Provision the independently held `release-trust.json` file-subject publisher
entry for each of `host`, `devbox`, `maintenance` and `development`. Pin
`.github/workflows/platform-release.yml` and its full SHA-256. The host uses the
shared GitHub verifier to check the actual protected branch policy, independent
source approval and required check, exact successful run and hosted attestation.
Its read-only GitHub identity needs the approval, check, workflow, artifact and
branch protection read scopes used by that verifier and the intake.

## Native build and export

Maintenance and development each boot the signed Fedora 44 Cloud image. The
guest still invokes the existing maintenance initialization or development host
preparation and development build. The maintenance image is saved from the
admitted `dp-maint` store by exact sealed image ID after both runtime cycles.
The development path sends the producer's original protected OCI archive and
inner record. The source/context-bound success report and binary export are
separate. Export uses a one-way virtio-serial endpoint with a nonce, a closed
metadata frame and an exact hash, length and end marker. The guest receives
only its public signed inputs and write endpoint.

The native path retains the 4GiB overhead and 16GiB qcow2 backing allocations.
It claims a third fully allocated 3GiB release-only filesystem before downloads
and checks that the final artifact copy also fits while keeping the 3GiB runner
reserve. Each OCI archive is limited to 2GiB. Maintenance checks space for the
save and image-copy overlap plus the 8GiB guest reserve. The existing outer
2,640-second window reserves up to 240 seconds each for guest export and outer
validation. The guest work allowance is 1,800 seconds and the VM has a
2,400-second ceiling. The controller verifies the archive and completes its
owned teardown before the Actions upload step can run.

The separate DevBox build consumes the exact placement recipe, signed Fedora
OCI base and pinned Distrobox entry. It publishes the outer immutable OCI
config and manifest digests and verifies the original Fedora/tooling layer
chain. The host bundle covers exact committed bytes under `tools/` and
`runtime/` with a closed hash manifest. Its format matches the renewal host
bundle loader. A checkout with code changes or an unsupported native or
storage capability blocks before publication.

## Read-only transport and staged intake

An authorized host operator uses the run ID and platform digest recorded by the
independently verified publisher. Provision the root-protected staging store,
read-only GitHub CLI identity and site configuration before running intake.

```sh
/usr/bin/python3 -B /usr/libexec/dev-pair/tools/platform_release_intake.py \
  --source "$SOURCE" --run-id "$RUN" --platform-sha256 "$PLATFORM_SHA" \
  --previous "$PREVIOUS_PLATFORM_SHA"
```

Use `--initial` for the approved first package with an empty staging store.
Intake verifies the Actions transport, portable attestation for each admitted
component, and compatible retained prior components. It extracts only the
declared files under explicit compressed, expanded and time limits. It verifies
actual OCI and host bundle content before publishing the content-addressed
staging directory and receipt. Agent intake measures the signed extracted
bytes plus the largest bounded ZIP, staging metadata and the existing 8GiB
recovery reserve. The archive and native role volumes count against the shared
20GiB managed capacity. The transfer also preserves the installer's inode
reserve. The stable base, active release, compatible rollback input and an
incoming transfer can overlap, so a site must have room for all four when
their archive bytes differ.

Under measured pressure, the intake lock and renewal selection protect the
base, active and compatible previous packages, pending offers and requests,
and in-progress renewal or native staging. Only positively superseded agent
transfer archives on the measured filesystem are eligible for reclamation.
Before removing each eligible package's verified OCI archive leaves, the
installer durably records the retirement at that digest. The signed index,
producer metadata, local predecessor, intake and installation evidence stay
in place. A retired archive cannot serve as a future intake or installation
input. Mixed selections without enough protected evidence to prove retirement
authority and sites that still lack capacity stop before the large transfer.
The ZIP spool has no reachable filename. A protected transaction records the
exact extraction workspace before any transfer writes, so an interrupted
invocation can discard its verified partial scratch on retry. Unknown entries
remain protected and block intake until their ownership is resolved.

The subjects and physical bytes are under
`/var/lib/dev-pair/platform-releases/<platform-sha256>/`. Each role has a
subdirectory with `<role>.oci.tar` and `part.json`. The host has `host.tar`
and `host-manifest.json`. The stage receipt is `intake.json`.

## Native installation and local derivation

D provisions the exact Fedora 44 site, independently verified host
configuration, managed role accounts and bounded storage. P's
`prepare-maintenance-host` establishes the host-only prerequisites and fixed
gateway from authenticated source and inputs. Provision G's reviewed
prebuilt entry, P's reviewed imported-image admission entry and the approved
site policy at `/etc/dev-pair/renewal/site-configs/<sha256>.json`. The policy
has `schema=1`, `hostname`, `host_config_sha256`, and the approved job map.
Each job entry supplies `storage_bytes` and disjoint `categories` for the
outer and inner roles. U owns live activation.

On the authorized enforcing host, stage the exact package and observe it.

```sh
/usr/bin/python3 -B /usr/libexec/dev-pair/tools/platform_release_install.py   --platform-sha256 "$PLATFORM_SHA" --site-config-sha256 "$SITE_CONFIG_SHA"
```

The installer validates the protected package and actual boot, scope and
control-plane file identities before invoking G and P. It checks the shared
20GiB managed allocation, including portable archives and rollback. A
separate archive filesystem counts its actual block device size. The native
maintenance import checks the rootless VFS graph, runroot, bounded copy
space, OCI expansion and live config/manifest identities. P then runs the
normal confined offline entry twice and records local cleanup under
`bootstrap/gptbox-adapter/<context>/imported-releases/<platform>/<image>/<boot>.json`.
The guest producer record remains in the signed artifact package.

Maintenance staging records its platform, image, physical allocation, copy
directory and exact transient systemd unit in a protected lease before native
execution. Before another staging attempt, the installer reconciles that lease
and removes its copy only after the owned unit has stopped and its cgroup is
empty. Uncertain launch or cleanup retains the lease and the copy. The retry
can reclaim its owned copy even when the measured volume is below the fresh
import reserve. New work starts only after the full reserve is measured again.
The retry first observes whether the exact image already exists in the role store.

G preflights and stages each job through its bounded role store. A
root-protected `development-placement.json` selects the exact site, inner
archive and stable base. G loads and observes the exact outer OCI bytes and
publishes its actual
`development/builds/<job>/inputs/<manifest-sha256>/manifest.json`. The
installer rechecks the actual manifest and archive, exact role/source
identities, protected mode, label and mounted capacity. For an agent-only
refresh, the stable host bundle and DevBox come from the retained full
platform index. Earlier compatible installed versions remain available for
rollback.

The site installer writes a protected `installed.json` only after both native
placement paths and the immutable installed host bundle read back. It binds
`platform_sha256`, `base_platform_sha256`, `site_config_sha256`,
`source_sha`, the current `boot_id`, and these exact component proofs.

| Component key | Readback fields |
| --- | --- |
| `host` | `manifest_sha256` |
| `maintenance` | `context_sha256`, `oci_config_sha256`, `oci_manifest_sha256`, `result_sha256` of P's local admission record |
| `devbox` | `oci_config_sha256`, `oci_manifest_sha256` |
| `development` | `context_sha256`, `oci_config_sha256`, `oci_manifest_sha256`, `inner_sha256` of the exact producer `inner.json` encoding, and `jobs` mapping each job to `manifest_sha256` |

U independently derives the local launch plan and release from the portable
index, protected site configuration and actual native scopes. Activation
uses its separately authorized staging and rollback path.

After a reboot, renewal can call the same installer with `--reobserve-maintenance`
and the already selected platform and site digests. The installer reads the
retained signed index, exact local launch plan and historical P admission,
then checks the existing rootless image and runs the ordinary P verification.
Only the maintenance boot observation is refreshed. The historical admission
and installer receipt remain available for recovery.

## Nightly and on-demand agent refresh

The protected `agent-refresh.yml` workflow declares 04:00 Asia/Tokyo and a fixed
on-demand entry on protected main. Provision the separate `agent-refresh`
environment and enable `PLATFORM_AGENT_REFRESH_ENABLED` only under authorized
release custody. The environment supplies the exact current
`PLATFORM_PREVIOUS_SHA256`, stable full `PLATFORM_BASE_SHA256`, and allocated
`PLATFORM_AGENT_ARTIFACT_BYTES`, including bounded temporary public input
retention. D's independent file-subject policy pins the separate agent workflow
under the maintenance and development `agent_refresh` fields.

The resolver uses the official latest stable release, its exact Git tag
commit and role-appropriate x86_64 archive and Sigstore asset. It bootstraps
Cosign from the reviewed pinned digest and verifies the binary against the
official workflow, tag, repo, issuer and source. Both role jobs share the
eligible exact verified assets inside the run and reverify them through the
existing authenticated producer. A new version or altered signed bytes yield
a `tooling.json` pin proposal for independent review. The live release keeps its
previous verified artifact pending approval of the new exact build inputs.

The resulting `dev-pair-agent-release` index contains two agents and refers
to the exact previous selection and full stable platform base. The host uses
the same intake with `--agent-only --previous <digest>`. Intake validates that
the base matches the retained previous selection, so an agent-only operation
retains the prior host bundle and DevBox. U derives the local activation plan
after the actual artifacts and per-job manifests are verified.

## Evidence still required

Run `PYTHONPATH=tests python3 -B -m unittest -q test_platform_release` for local
source/transport checks. Hosted tests still need to establish the standard
runner's extra ext4 volume, virtio endpoint, clipped native role time and exact
OCI transport. The destination needs the approved read-only identity,
artifact retention allocation and actual installed recovery pair.
