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

After verified tailnet enrollment, keep the independent provider recovery
terminal available and test `core` SSH from your tailnet. The final access
controller requires independent authorized, denied, public and provider
observations of the intended routes. This setup does not yet automate the
pre-cutover role availability and evidence handoff. The initial SSH route stays
available until the separate review succeeds. [Recovery and access verification](destination-release.md)

The first bootstrap builds and verifies the confined maintenance gptbox using
public signed build inputs. Both offline probe cycles must pass before the host
reports completion. Reapply checks the recorded result and immutable image. A
separately approved full platform release, site policy, and provider access are
needed for later authenticated workloads. They are consumed by the protected
commissioning entry as available. [Commissioning](host-commissioning.md)

## Optional offline source kit

The delivery can include a deterministic source archive with the exact source
commit and shallow Git objects. In the protected hPanel root directory, verify
the archive against the SHA-256 supplied separately by the reviewer. Then unpack
it into a fresh directory, check `MANIFEST.sha256`, enter the enclosed `dev-pair`
checkout and run `./day0.sh start`. The installer verifies the kit again before
installing the signed Fedora Git prerequisite. It checks the full checkout commit
before any further host setup. The public-input verification and Tailscale steps
use their normal network services after source acquisition.
