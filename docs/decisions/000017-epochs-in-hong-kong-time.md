# 000017 — Epoch timestamps in Hong Kong time

- status: accepted (amends 000016's zone)
- date: 2026-08-17

## Problem

000016 chose UTC for epoch timestamps on machine-unambiguity grounds. The maintainer lives on Hong Kong time, and the names exist for the maintainer to recognise a moment.

## Decision

Epoch tags are `chartered-YYYY-MM-DD-HHMM` in Hong Kong time (UTC+8), the zone stated in law so the grammar stays unambiguous. The UTC-named epoch `chartered-2026-08-17-0304` stands grandfathered — immutable by its ruleset, its name speaking its brief grammar — and the next natural re-lock takes the maintainer's clock.

## Consequences

C11 and the genesis step carry the zone; the AGENTS echoes name no zone and need no change; the floating `chartered` already points at the correct commit, so no cosmetic re-tag.
