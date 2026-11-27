# Day-zero operations from hPanel

For a first run, paste the command supplied for the published offline
maintenance bootstrap into the chosen VPS root terminal in hPanel. It follows
the [README acquisition command](../README.md#dr11-2) and pins the
[published bootstrap source](https://github.com/oso-gato/dev-pair/tree/11fbe9e0e0ff911fce13e33527c55020958a50a7).
If the terminal lacks a controlling TTY, reopen an interactive terminal and run
the same command. The installer uses a local pseudo-terminal when available and
discards its transcript.

## Resume and recovery

From the protected checkout, run `./day0.sh status` to read the recorded phase
and inspect the live host. Run `./day0.sh resume` to continue. Its machine-bound
progress survives the setup reboot. Keep the provider recovery terminal available.

Finish building the confined maintenance gptbox and passing both offline
probe cycles with the original checkout. If interrupted, resume that checkout
until the maintenance checkpoint completes. Retain the checkout, the protected
journals and the sealed image. When you receive a separately reviewed
continuation, use its pinned acquisition command in the same root terminal.
It stages the new revision in its own `/root/dev-pair-day0-<full-commit>/dev-pair`
checkout and runs `./day0.sh resume` there. Keep the original checkout at its
standard path. The public checkout uses the full commit in its path and the
offline kit uses the first 12 characters. The continuation checks the earlier
completed maintenance proof and source, reuses the sealed image and named
`core` setup, and records the new controller identity.

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

Protected commissioning requires the signed full platform release for the
reviewed source, a protected site policy and the applicable release trust and
read authority. After commissioning installs the role images, run
`./day0.sh access-request --workloads > ../workload-access-request.json` to
request a separate review of those images and the selected DevBox placement.
The independent verifier runs the confined role checks through the named
`core` tailnet SSH path and returns a signed workload bundle. Apply it in
the selected root terminal with
`./day0.sh access-response < ../signed-workload-access.bundle`, then run
`./day0.sh resume`. Provider and owner intake grants still control normal jobs.
[Commissioning](host-commissioning.md)

When a replacement changes the selected role release or images, the existing
approval holds job and application dispatch until a fresh workload review
binds the replacement. A protected rollback can reuse the retained approval
for its exact previous placement. An unattended replacement also needs a
prospective observation route to test the candidate before changing the live
selection. Optional owner and provider activation needs its own supported
policy transition and approved grants.

On a previously reviewed legacy host, resume verifies the stored full cutover
and can retain the managed release recorded when that review was accepted. A
standalone review keeps its original scope when commissioning adds the first
managed release. That release gets a fresh signed workload review. If you moved
from an approved earlier checkout, the installer retains its completed cutover
record and binds the new workload review to the verified continuation source.

When Day 0 reports that owner intake is waiting for the first catalogue, use the
protected root terminal. First arrange the approved repository acquisition,
startup checkout and pinned private standards. The direct OpenAI API profile
requires a root-private credential in authorized custody, an approved allowance
with a cap and expiry, and independently reviewed machine-readable billing
evidence for the account and model. The evidence binds the full billable
context, applicable rates and authorized response model names. Repository and
startup provisioning and issuance of those normalized billing records still
need a controlled path on a fresh host. Keep credential values outside the
terminal, source and artifacts.

```sh
/usr/bin/python3 -IB /usr/libexec/dev-pair/tools/owner_intake.py --setup-site
```

The wizard asks for the approved repository, workload, credential reference,
job budget and expiry. Check the displayed checkout and startup revisions,
destination and bounded API use for both roles. Type `yes` to confirm that
exact setup or press Enter to leave it pending. After confirmation, run
`./day0.sh resume` from the continuation checkout. When the owner terminal is
ready, connect as `core` over the verified tailnet route and use the
[owner terminal command](owner-intake.md).

## Optional offline source kit

The delivery can include a deterministic source archive with the exact source
commit and shallow Git objects. In the protected hPanel root directory, verify
the archive against the SHA-256 supplied separately by the reviewer. Then unpack
it into a fresh directory, check `MANIFEST.sha256`, enter the enclosed `dev-pair`
checkout and run `./day0.sh start`. The installer verifies the kit again before
installing the signed Fedora Git prerequisite. It checks the full checkout commit
before any further host setup. The public-input verification and Tailscale steps
use their normal network services after source acquisition.
