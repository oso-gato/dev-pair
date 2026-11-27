# Protected Fedora platform publication

The protected platform workflow builds the maintenance gptbox, development gptbox, outer DevBox and host control-plane bundle for one exact reviewed `main` commit. It uses standard GitHub-hosted Ubuntu runners. The existing Fedora PR probe continues to provide component-test evidence.

## Independent release authority

Merge through the independent branch and required-check policy, then authorize the exact run through the `platform-release` GitHub environment. The environment supplies these protected site coordinates.

| Setting | Value |
| --- | --- |
| `PLATFORM_HOST_CONFIG_SHA256` | Digest of the independently held Fedora host configuration |
| `PLATFORM_LAUNCH_PLAN_SHA256` | Digest of the independently staged schema 1 launch plan |
| `PLATFORM_PREVIOUS_SHA256` | Previously verified platform index digest, or `initial` for an empty staging store |
| `PLATFORM_ARTIFACT_BYTES` | Independently available no-spend Actions artifact capacity covering three 2GiB OCI archives, host and subject files, and transport overhead |

A release requires the protected push event, exact clean checkout, first run attempt,
integrated placement/review/renewal source and a currently verified upstream stable
Codex tag matching the repository's signed input pins. The publisher checks for a
new official version before starting the build. A changed stable release requires a
matching reviewed pin update or the separately approved refresh resolver.

Only the publication job receives the GitHub attestation permissions. It attests
the exact `platform.json` and `release.json` file subjects after verifying all four
build outputs. The platform index binds the repository, source, run ID, archive
digests/lengths and prior platform. The renewal manifest uses the control-plane
schema and binds the deployed component configuration and immutable image IDs.
The run summary supplies both subject digests. The Actions service retains the
artifact parts for one day. Capture verified bytes on the host within that window.

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
Intake verifies the Actions transport identity, both attested subjects, the
site configuration and plan hashes, and previously retained compatible
components. It extracts only the declared files under explicit compressed,
expanded and time limits. It verifies the actual OCI and host bundle content
before publishing the new content-addressed staging directory and receipt.
The store holds up to three staged versions under a single lock and preserves
the 8GiB host reserve. Retiring a retained digest requires the separate
authorized activation and recovery procedure.

The staged `release.json` is the exact renewal subject for the protected
`renewal/releases/<sha256>.json` input. The destination activation work owns
installation of the verified host bundle, rootless OCI imports, site launch
plan, previous selection and the matching activation request. Credential
custody, live selection, job admission and network cutover belong to the
authorized destination controller.

## Evidence still required

Run `PYTHONPATH=tests python3 -B -m unittest -q test_platform_release` for the
local source/transport checks. Native checks must establish that the current
standard runner supports the added release volume and virtio endpoint, that
the role builders fit the clipped time/space envelope and that the approved
Actions quota and the read-only host identity work. The full protected push
publishes a complete platform set. Separate nightly and on-demand agent-only
refresh needs the approved agent event policy and an intake that retains the
current host and DevBox components.
