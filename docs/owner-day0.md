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

After verified tailnet enrollment, use the independent provider recovery
terminal and test `core` SSH from the intended tailnet. The installer writes
`/var/lib/dev-pair-day0/cutover-request.json` for the independent access verifier.
Use the separately signed result under `/etc/dev-pair/day0/cutover.json` with
its adjacent signature. The existing cutover controller verifies the live node,
keys, probes and recovery route before it restricts ingress. [Recovery and access
verification](destination-release.md)

Host preparation installs the restricted gateway from verified public inputs.
An independent full platform release, its protected site configuration and
provider grants are needed before the workload can be admitted. When the
independently approved policy is delivered, stage it in the protected location
`/etc/dev-pair/day0/commission-policy.json` and run
`./day0.sh resume --commission-policy-sha` followed by its independently
supplied full SHA-256. The commissioning controller verifies the staged portable
release and approved host configuration before activating services. [Commissioning](host-commissioning.md)

## Optional offline source kit

The delivery can include a deterministic source archive with the exact source
commit and shallow Git objects. In the protected hPanel root directory, verify
the archive against the SHA-256 supplied separately by the reviewer. Then unpack
it into a fresh directory, check `MANIFEST.sha256`, enter the enclosed `dev-pair`
checkout and run `./day0.sh start`. The installer verifies the kit again before
installing the signed Fedora Git prerequisite. It checks the full checkout commit
before any further host setup. The public-input verification and Tailscale steps
use their normal network services after source acquisition.
