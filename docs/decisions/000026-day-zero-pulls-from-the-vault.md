# 000026 — Day zero pulls identity from the vault after one authorization

- status: accepted
- date: 2026-08-18

## Problem

Day zero has to put three things on a new host that the host cannot invent and the repository may never carry: the administrative user's password hash, the tailnet auth key, and the pair's GitHub App private keys. `dev-pair` is a public repository, so committing any of them is out on its face, and a password hash published to the world is an invitation to crack it offline whatever C6 says about declarations being records rather than secrets.

The objective allows exactly one human interaction per project and C11 calls a gate that needs a human a summons, so the answer cannot be "prompt the operator for each value". The bylaw's own day-zero contract for the VPS track already fixes the shape — one pasted script that creates `core`, joins the tailnet, activates the pair's GitHub App, hands off to the converger, and retires root — without saying where the secrets come from.

The donor answers this question for the bare-metal track by pulling a `firstboot.yaml` from a separate private repository. That answer cannot simply be carried over. ADR 000011 made `homelab-root` → `identity/` the estate's one sanctioned resting place for live credentials, and a second credential home would be exactly the duplication C1 exists to prevent.

## Decision

Day zero splits into two phases with the single human act between them, and the vault is the only source of anything secret.

The first phase needs no authority. It installs the bootstrap set from Fedora's own repositories, clones the public declaration source, creates `core`, authorises the maintainer's published keys from `github.com/oso-gato.keys`, and closes `sshd` to keys only. Every input here is public, so nothing gates it, and the operator has a working key-authenticated way back in before the script has finished — which matters, because the next phase closes the console path.

The second phase opens the vault. The script runs GitHub's device flow once, the maintainer approves the printed code from a phone, and the script then reads `homelab-root` → `identity/` for the three values. It applies them, hands off to the converger, joins the tailnet, and retires root. The device-flow token lives in an ephemeral directory destroyed by an exit trap covering the signal paths, and it is revoked and deleted the moment it has done its work rather than at the end of the run.

Two details follow from making the vault the source. The tailnet auth key carries its expiry in its filename, so day zero lists the vault directory, picks the newest key whose expiry has not passed, and refuses rather than present an expired key — which turns a naming convention into a working check. And the App private keys are validated by exit code alone, never printed, in keeping with the vault discipline that binds every agent in the estate.

This binds every future pair, not only erebus. A new lineage adds an environment adapter naming its own vault paths and App identities, and inherits this shape unchanged.

## Options considered

- **Bake the hash into `day-zero.sh` and pull only the rest.** Rejected. The repository is public, and the bare-metal track's precedent of baking identity happens at image build from the vault, never in committed source. It would also split the identity declaration across two homes for no gain.
- **Pull the whole bundle from a second private repository, as the donor does.** Rejected on C1. The estate settled its credential home in ADR 000011, and the donor predates that ruling. Carrying the donor's shape here would have re-created the split the vault decision closed.
- **Prompt the operator for each value interactively.** Rejected. It is three interactions where the workflow allows one, and it puts a tailnet auth key and a PEM through a console paste, which is worse handling than a device-flow token that self-destructs.
- **Fetch with a long-lived fine-grained token pasted at the prompt.** Rejected. It is still a paste of a credential, and a token that outlives the run is a standing secret on a host that has no way to rotate it yet.
- **Have the converger fetch the credentials on every apply.** Rejected, and this one is the trap worth naming. It would make every routine re-converge require authority, so a converge run could never be unattended, and the deploy mechanism the bylaw calls re-run-safe would need a human every time. Credentials enter once, at genesis; the converger holds none and needs none.

## Consequences

`host/day-zero.sh` is credential-free and re-runnable, and the self-test proves the tree carries no private key, no token, and no password hash.

The converger never needs authority, which is what lets it be the unattended, idempotent mechanism the bylaw asks for. The one place this shows is the tailnet: a converge run reports the join state and cannot perform the join, because the join needs a key and a converge run holds none.

Root retirement gained a precondition. The converger locks root only once `core` is provably usable — present, in wheel, holding an authorized key, and carrying a real password. Locking it before that would strand the host with no way in and no self-heal path, which is what C11 forbids, so the unit reports why it declined instead.

A vault path change is now an adapter edit rather than a code change, and the expiry-dated key filename is load-bearing rather than decorative.
