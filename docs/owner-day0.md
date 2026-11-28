# Day-zero operations from hPanel

Open the selected Fedora 44 VPS root terminal in hPanel and keep an independent
provider recovery session available. Start from the exact reviewed draft source
using the [source kit](#optional-offline-source-kit) or the [README acquisition command](../README.md#dr11-2).
Use the same checkout throughout fresh setup.

```sh
./day0.sh start
./day0.sh status
./day0.sh resume
```

Run `start` once to open setup. Run `status` to see the recorded phase and
`resume` to continue after a pause, a reboot or an independent handoff. If a
prompt requires a controlling TTY, reopen an interactive root terminal and run
`resume`. The installer uses a local pseudo-terminal when available and discards
its transcript.

## Resume and recovery

Begin with the approved operator account, the owner's GitHub public keys and the
selected tailnet. The named `core` console and sudo password is entered without
echo. Press Enter at the Tailscale auth-key prompt to use browser sign-in. Leave
the tailnet name blank to defer enrollment. Setup checks Fedora, the selected
host, storage and SELinux and can resume a checked relabel across setup reboots.
The confined maintenance gptbox must complete both offline probe cycles before
commissioning proceeds.

During initial setup the installer scopes temporary SSH to the observed live
peer when the hPanel terminal uses SSH. In a local hPanel console it displays a
challenge. Open a second hPanel root terminal on the same VPS, run the displayed
command and enter the challenge there. This confirms a separate local session
on the same machine and boot. An already available independently signed provider
proof can authorize the zero-public-SSH route. Keep provider recovery available
until authorized tailnet access and independent recovery have been measured.

After enrollment, `resume` asks for the independent access verifier's signing
public key, its station's Tailscale IP, its dedicated SSH transport account and
its pinned SSH host public key. Give the station operator the request transport
public key displayed by setup. The station operator admits it for the selected
VPS. A later `resume` sends the exact request or picks up its signed reply. The
verifier checks named `core` SSH, public and unauthorized tailnet denial, loss
and recovery, and the independent provider terminal. The host checks the reply
against the current machine, boot, tailnet node and keys before closing the
initial SSH route. [Independent access verification](destination-observation.md#review-the-named-ssh-and-workload-routes)

If the independent station is reached through an approved offline handoff, leave
its IP blank. In the protected root terminal, export the request beside the
checkout, convey it over the authenticated controller channel, and import the
verifier's signed response.

```sh
./day0.sh access-request > ../access-request.json
./day0.sh access-response < ../signed-access.bundle
./day0.sh resume
```

If cutover stops partway through, obtain a fresh bundle for the same pending
scope, boot and route. After reboot, or when the earlier scope cannot be
established, get a fresh administrator-only bundle verified from the independent
provider terminal. Run `./day0.sh access-response --recover-cutover < ../signed-access.bundle`
there. The installer preserves the previous journal and current ingress
restrictions and holds workloads for their separate access review.

Protected commissioning requires an independently authorized, signed full
platform publication for the exact source. At the release prompt, supply the
custodian's protected handoff path and separately conveyed SHA-256. When asked,
enter the scoped GitHub read token at the hidden prompt. A draft checkout or
kit can reach this point before protected publication. Resume when the eligible
signed publication is available. [Host commissioning](host-commissioning.md)

After commissioning installs the role images, `resume` uses the same station
for a separate signed review of both roles and the selected DevBox placement.
For the offline path, export with `./day0.sh access-request --workloads`, return
the signed workload bundle via `./day0.sh access-response` and resume. Keep
operator recovery available throughout. A replacement that changes the selected
role release or images needs a fresh scope for those bytes and placement. A
protected rollback can reuse the retained exact previous approval. An unattended
agent replacement also needs independently signed prospective observations.

At the first owner setup prompt, select the approved project repository and
workload. Follow the prompts for exact source and startup revisions, approved
read access and pinned private standards. The same wizard selects or registers
the OpenAI project key using a hidden prompt or a protected file. Enroll the
independent billing custodian with their separately authenticated signing
fingerprint. Send the wizard's VPS-bound request to that custodian and place
the returned signed bundle at the protected path it displays. Resume to
check the bundle and confirm the exact project, role settings, budget cap
and UTC expiry. Day 0 can also reopen billing setup for a configured catalogue
whose unused slot needs signed reauthorization. Once activation completes,
connect as `core` over the verified route. [Owner setup and terminal command](owner-intake.md#repository-and-slot-inputs)

When the named owner terminal is available, `resume` can offer optional
checklist promotion. Enroll only after the independent release authorities
and time-limited credentials for that destination have been approved. See the
protected enrollment, withdrawal and signed destination proof commands in the
[promotion runbook](product-release.md).

## Independent access station setup

The independent station operator prepares the access site and protected
mailbox on a separate authorized Tailnet device. The operator supplies the
station address and account, both public keys, and the matching OpenSSH
SHA256 fingerprints through the independently verified handoff. Enter those
values in Day 0. The operator then admits the VPS transport public key that Day
0 displays. [Prepare and enroll the station](destination-observation.md#prepare-the-first-access-station)

The station operator selects a pending request and uses `begin-review` to
prepare the plan in the independent reviewer's private directory. The verifier
conducts the named checks and signs the exact request's observation
bundle. Under the approved mailbox account, use `publish` with the request
identifier (its filename without `.request`) and the signed bundle on standard
input. `./day0.sh resume` retrieves and verifies it from the pinned station.
The verifier retains its evidence independently of the request mailbox.
[Named SSH and workload checks](destination-observation.md#review-the-named-ssh-and-workload-routes)

## Previously installed November 27 bootstrap

A host already seeded at
[11fbe9e0e0ff911fce13e33527c55020958a50a7](https://github.com/oso-gato/dev-pair/tree/11fbe9e0e0ff911fce13e33527c55020958a50a7)
can resume that checkout to complete its original offline maintenance proof.
Keep that checkout at its original path along with the protected journals and
sealed image. Stage the current reviewed source in its own protected checkout
and run `./day0.sh resume` there. The compatibility path verifies the earlier
source and proof, reuses the maintained image and operator setup, and records
the current controller identity. Existing standalone cutover evidence keeps
its scope. The first managed release gets its own signed workload access review.

## Optional offline source kit

The deterministic kit contains the exact source commit and shallow Git objects.
In the protected hPanel root directory, verify it against the SHA-256 conveyed
separately by the reviewer. Unpack it into a fresh directory, check
`MANIFEST.sha256`, enter the enclosed `dev-pair` checkout and run `./day0.sh start`.
The installer verifies the kit again before installing the signed Fedora Git
prerequisite, then checks the full checkout commit. Public-input verification
and Tailscale use their normal network services after source acquisition.
