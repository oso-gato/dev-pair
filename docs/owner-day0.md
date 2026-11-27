# Day-zero operations from hPanel

The [README acquisition command](../README.md#set-up-the-fedora-host) uses the
public repository and the exact commit delivered for this host. Run it from the
chosen VPS root terminal. If the terminal lacks a controlling TTY, reopen the
interactive terminal and run the same command. The installer uses a local
pseudo-terminal when available, with transcript output discarded.

## Resume and recovery

From the same protected checkout run `./day0.sh status` to read the recorded phase
and inspect the live host. Run `./day0.sh resume` to continue. Its machine-bound
progress survives the setup reboot. Keep the opened provider recovery session
available and use the same source until setup completes.

During initial setup the installer scopes temporary SSH to an observed live peer
when the hPanel terminal uses SSH. In a local hPanel console it displays a short
challenge. Open a second hPanel root terminal for the same VPS and run the
command displayed on screen. Enter the challenge there, then continue in the
first terminal. This confirms a separate local session on the same machine and
boot. The existing SSH route stays available during setup. The new `core` SSH
login is restricted to tailnet sources and destinations. An already available
independently signed provider proof can instead authorize the zero-public-SSH
setup route. The final access review still checks external reachability.

After tailnet enrollment, keep the independent provider recovery terminal
available and test `core` SSH from your tailnet. In the selected root terminal,
run `./day0.sh access-request > ../access-request.json` from the verified checkout.
Send the generated request to your independent access verifier on the
authenticated controller channel. The verifier checks the actual named
administrator, outside clients and provider recovery and returns one signed
bundle. Place it beside the checkout and run
`./day0.sh access-response < ../signed-access.bundle` in the selected
root terminal. The installer verifies the bundle against the live machine, boot,
tailnet node and keys before closing the initial SSH route. Run `./day0.sh resume`
to continue. [Independent access verification](destination-observation.md)

If cutover stopped partway through, return a fresh bundle for the same pending
scope, boot and route. After a reboot or when the earlier scope cannot be
established, use a fresh administrator-only bundle verified from the independent
provider terminal. Run `./day0.sh access-response --recover-cutover < ../signed-access.bundle`
there. The installer keeps the previous journal, preserves the current ingress
restrictions and holds workloads until their separate access review is complete.

The first bootstrap builds and verifies the confined maintenance gptbox using
public signed build inputs. Both offline probe cycles must pass before the host
reports completion. Reapply checks the recorded result and immutable image. A
separately approved full platform release, site policy, and provider access are
needed for later authenticated workloads. They are consumed by the protected
commissioning entry as available. After protected commissioning installs the
role images, `./day0.sh access-request --workloads > ../workload-access-request.json`
requests the separate role
review for those exact images and the selected DevBox placement. The verifier
runs the confined role checks through the same named core tailnet SSH path and
returns the next signed bundle for `access-response`. The provider and owner
intake grants still independently control normal jobs. [Commissioning](host-commissioning.md)

When a replacement changes the selected role release or images, the existing
approval holds job and application dispatch until a fresh workload review
binds the replacement. A protected rollback can reuse the retained approval
for its exact previous placement. An unattended replacement also needs a
prospective observation route to test the candidate before changing the live
selection. Optional owner and provider activation needs its own supported
policy transition and approved grants.

On a previously reviewed legacy host, resume verifies the stored full cutover
and can retain its unchanged managed release. A changed or unavailable release
requires a fresh workload review. The installer reports which review is pending.

If you ran a reviewed offline-only bootstrap, retain its checkout, journals and
local gptbox. Stage the separately reviewed continuation checkout in its own
standard directory, then run `./day0.sh resume` there. The installer verifies
the earlier completed maintenance proof and original production-source bytes
before recording the new controller identity. It reuses your earlier sealed
image and named core setup. Keep using the originally reviewed checkout if its
maintenance initialization was interrupted before completion. The standard
public checkout and offline kit paths let the new command locate the original
protected Git tree when the historical commit contains test-only changes.

## Optional offline source kit

The delivery can include a deterministic source archive with the exact source
commit and shallow Git objects. In the protected hPanel root directory, verify
the archive against the SHA-256 supplied separately by the reviewer. Then unpack
it into a fresh directory, check `MANIFEST.sha256`, enter the enclosed `dev-pair`
checkout and run `./day0.sh start`. The installer verifies the kit again before
installing the signed Fedora Git prerequisite. It checks the full checkout commit
before any further host setup. The public-input verification and Tailscale steps
use their normal network services after source acquisition.
