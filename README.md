# dev-pair

The autonomous dev pair: a Fedora host and its dev-container, governed by one objective
and one set of build principles.

A maintainer states an objective in a single session and confirms it. From there the pair
derives the requirements, architects the design, builds, validates against a live
environment, and ships — with no second human act.

## Where things are

Start at [`AGENTS.md`](AGENTS.md) — it routes to everything and states which document
governs what.

| | |
|---|---|
| [`00-OBJECTIVE.md`](00-OBJECTIVE.md) | Why this exists, and its boundaries |
| [`00-BUILDPRINCIPLE.md`](00-BUILDPRINCIPLE.md) | How anything gets built, universally |
| [`01-SPEC.md`](01-SPEC.md) | What the platform must do |
| [`02-DESIGN.md`](02-DESIGN.md) | How it is arranged |
| [`docs/adr/`](docs/adr/) | Why it is arranged that way |

This file is orientation only. It carries no law — if it disagrees with a governing
document, the governing document wins and this file is defective.

## Status

Rebuilding. The document architecture is being established first; the source trees are
slated for throwaway and restart under the confirmed objective.
