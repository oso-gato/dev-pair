# 000016 — Epoch names are minute-accurate UTC timestamps

- status: accepted (amends 000014's naming)
- date: 2026-08-17

## Problem

The first same-day re-lock exposed the epoch grammar's gap: `chartered-YYYY-MM-DD` cannot name two locks in one day, and the interim counter suffix (`-2`) was numbering where the maintainer wants time.

## Decision

Every epoch tag is `chartered-YYYY-MM-DD-HHMM`, minute-accurate, in UTC — one grammar, no conditional, unambiguous across timezones. Epoch names from before this grammar (`chartered-2026-08-17`, `chartered-2026-08-17-2`) stand unchanged: they are immutable by their own ruleset, and frozen names speak their epoch.

## Consequences

C11, the genesis step, and both AGENTS echoes carry the new grammar; the floating `chartered` re-locks onto a properly-named epoch at the current law state.
