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
staging directory and receipt. The store holds up to three staged versions
under one lock and preserves the 8GiB host reserve. Retiring a retained digest
requires the authorized activation and recovery procedure.

The subjects and physical bytes are under
`/var/lib/dev-pair/platform-releases/<platform-sha256>/`. Each role has its own
subdirectory with `<role>.oci.tar` and `part.json`. The host subdirectory contains
`host.tar` and `host-manifest.json`. The site installer supplies the actual
rootless image, digest-addressed host bundle and per-job G manifest readback.
That installer and G's prebuilt release path are the remaining native source
connections. The release transport has its own protected receipt
`intake.json`; local installed readback and selection follow under the
authorized destination controller.

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
