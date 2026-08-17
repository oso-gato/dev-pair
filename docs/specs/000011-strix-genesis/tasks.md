# Tasks: Genesis of the strix pair

Dependencies are marked so the independent work fans out and only the dependent work waits (C12). A task marked `after:` may not start until every task it names is done; everything else is concurrent.

## Correcting the erebus work first — `after:` nothing

The strix ticket exposed pair-specific names in `#10`'s output. They are corrected before the second lineage is built on top of them.

- [x] S1 — The dev-container image becomes `ghcr.io/oso-gato/dev-container`; the CI workflow renamed with it.
- [x] S2 — The entrypoint becomes `pair-session`; the enter command becomes `pair-enter` and takes its container from its own invocation name.
- [x] S3 — The Quadlet becomes a template, rendered per pair by `fs_render`, which fails closed on an unset variable or a leftover placeholder.
- [x] S4 — `50-github-app.sh` stops hardcoding the erebus instance name.

## The track split — `after: S3`

- [x] S5 — `CONVERGE_UNITS` in the adapter: the VPS track runs every unit, the bare-metal track runs only what its image does not carry.
- [x] S6 — The converger's package-installing preamble gated the same way, because an install on an image-immutable host is the out-of-band change C7 forbids.

## The strix lineage

- [x] S7 — `host/converge/environments/strix.env`: the adapter, carrying the LAN route, the `/var/home` paths, the donor image's facts, and the two Apps that do not exist yet.
- [x] S8 — `host/activate.sh`: the bare-metal day zero. Installs nothing, sets no password, one device-flow approval, guarded root retirement. `after: S7`

## Proof — `after: S5, S7, S8`

- [x] S9 — The shared Quadlet template renders completely against every adapter in the tree.
- [x] S10 — Every adapter declares the full variable set the units read.
- [x] S11 — No unit or library branches on which pair is converging.
- [x] S12 — Shell correctness of every delivered script under `bash -n` and shellcheck at style level.

## Records — `after: S9, S10, S11, S12`

- [x] S13 — ADR: one dev-container image serves every lineage, and the track decides which units apply.
- [x] S14 — `ARCHITECTURE.md` updated in the same change.
- [x] S15 — `CHANGELOG.md` entry.
- [x] S16 — Analyze pass across spec, plan and tasks.

## What the analyze pass found

The three documents agree, and the one thing worth recording is a claim the spec makes that the code cannot satisfy alone.

Acceptance 1 asks for an App-activated host from a single command. The strix pair's two GitHub Apps do not exist, and no artifact can create one. Rather than let that surface as a failed run, the adapter declares the names with empty IDs, `install_app` treats an empty ID as a warned non-fatal state, and the spec's Acceptance section names the prerequisite outright. The ticket is therefore delivered against a stated, visible gap rather than a hidden one.

One scope boundary was tested and held. `strix.env` is the only file that mentions strix outside documentation, and S11 proves no unit or library branches on a pair — so the adapter rule the bylaw states is a fact about this tree rather than an aspiration in it.
