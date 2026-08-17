# Implementation Plan: Genesis of the strix pair

**Branch**: `claude/dev-pair-universal-constitution-4xtdos` | **Date**: 2026-08-18 | **Spec**: [spec.md](spec.md)

## Design

### The track decides which units apply

This is the load-bearing difference between the lineages, and it comes from the bylaw rather than from convenience. The VPS track's sanctioned deploy mechanism is the converger, so erebus runs every unit. The bare-metal track's is image rebase with atomic rollback, so strix's host state — the administrative user, the package set, the tailnet client, podman, the agent box — is baked into the donor image and arrives by rebase.

Converging those facts on strix would put two mechanisms in charge of one thing, and installing a package on an image-immutable host is the out-of-band change C7 forbids outright. So the adapter declares `CONVERGE_UNITS`, and strix names only the two the image does not carry: the estate's pair-neutral App minter, and the dev-container. An unset list means every unit, which is what erebus wants and what any future VPS host will want.

The converger's preamble — its own fetch tooling, the trust-root sync — is gated the same way, because it installs packages too.

### One dev-container image, two instances

Writing the strix ticket exposed a defect in the erebus work. The image was named `ghcr.io/oso-gato/nox`, the entrypoint `nox-session`, the enter command `nox`, and the Quadlet was a per-pair file. All four were pair-specific names for things that are not pair-specific, and a second pair would have had to fork every one of them — exactly what the bylaw's adapter rule exists to prevent.

The image is now `ghcr.io/oso-gato/dev-container`, the entrypoint `pair-session`, and the Quadlet a template the converger renders per pair. The enter command takes its container from its own invocation name, so one source file installs as `nox` on erebus and `moros` on strix. This is corrected in the same change rather than left for the strix ticket to work around, because a known-wrong name that ships is harder to remove than one that never did.

`moros` and `nox` therefore differ in exactly two facts: their name and their App identity. Both are adapter values.

### Activation confirms rather than creates

`host/activate.sh` is the bare-metal track's day zero and its first phase is entirely assertions. It checks that the image gave it `gh`, `curl`, `tailscale` and a baked `core` holding an authorized key, and dies if any is missing — because an image that did not bake those is not one this script can activate, and finding that out at the tailnet join would be worse.

The declaration source is fetched without git, since a minimal image may not carry it: git if present, the public codeload tarball otherwise. Both are public fetches of a public artifact and neither installs anything.

The one human act, the vault read, and root's guarded retirement are the same shapes day zero uses, because ADR 000026 binds every pair rather than only erebus.

### The Apps do not exist, and the artifact says so

The registry lists both strix Apps as planned. Creating a GitHub App is an act on github.com that no artifact can perform, so the adapter carries their names with empty IDs, and `install_app` treats an empty ID as a warned, non-fatal state rather than a failure. Activation completes, the host joins, the dev-container runs, and the boxes hold no GitHub authority until the maintainer creates the Apps, puts the keys in the vault under the names already declared, and re-runs.

Making this fatal was considered and rejected: it would block a working tailnet join and a working dev-container on a prerequisite unrelated to either, and an idempotent apply exists precisely so the remaining piece can land later without redoing the rest.

## Proof

The adapter rule is the claim most likely to be quietly false, so it is the one tested directly. The self-test renders the shared Quadlet template against every adapter in the tree and requires a complete, fully substituted unit from each; it requires every adapter to declare the full variable set the units read; and it fails if any unit or library branches on a pair name.

That last check earned its place immediately. Its first version matched the `if` inside `verify` and fired on a comment, which is the "guard that looks like rigour" failure the constitution's preamble names — a check reporting a finding it cannot justify. It is now word-boundaried and skips comments.

## Not in this ticket

The self-renewal chain (B4) and the ticket-envelope contract (B3).

GPU capability inside `moros`, per the spec's out-of-scope reasoning.

## Decisions that graduate

One binds beyond this ticket — that one dev-container image serves every lineage, and that the track decides which converger units apply.
