# 000013 — Citation letters C/B; six-digit record numbering

- status: accepted
- date: 2026-08-17

## Problem

The rule prefixes P and R were fossils of the pre-split vocabulary ("universal principles", "repo-specific principles"), decoding to neither document's name and requiring a declared legend — and P was ambiguous on its face, since both documents contain principles. Separately, four-digit record numbering had a hard failure mode: GitHub numbers issues and PRs from one shared counter, the loop consumes two numbers per ticket, and at #10000 four-digit folder padding breaks lexical sort. Measured on the prior fleet: fedora-dev burned 342 numbers and fedora-bootstrap 389 in roughly two months each, pre-autonomous.

## Decision

1. Constitution rules cite as **C1–C11** and bylaw rules as **B1–B4** — the letter names the document, decoding without a legend. Numerals unchanged: **P≡C and R≡B, one to one**.
2. Record numbering widens to **six digits** for `docs/decisions/` and `docs/specs/`, uniformly — 999,999 capacity, safe at any plausible machine cadence. Existing files renamed (`0006-repo-genesis` → `000006-repo-genesis`; ADRs likewise); contents byte-identical; **leading zeros widen without changing identity** — 0007 and 000007 are the same decision.
3. Alphabetical order of B before C encodes nothing: the sets never interleave in any listing, the root already sorts `00-BYLAW.md` before `CONSTITUTION.md` by the initiation prefix, and authority is legislated in the subordination clause, not the alphabet.

## Options considered

- Spelled-out citations ("Constitution 7") — rejected: every legal and standards tradition converged on compact citation; verbose buys nothing the letter doesn't say.
- Five digits — rejected on the measured burn rate: a mature multi-tenant loop plausibly compresses five digits to under a decade, and the sixth digit's cost is one leading zero.
- Letter pairs that sort with the hierarchy (A/B, C/L) — rejected: they destroy the decode-to-document property, which is worth more than lexicographic aesthetics.

## Consequences

Live surfaces swept in both repos and the genesis kit; frozen records (ADRs 000001–000012, the changelog, the shipped spec) keep their epoch's P/R letters and four-digit citations, readable forever under the two equivalence rules above. This is the last cheap moment the rename existed: the merge gate and future repos will consume these identifiers mechanically.
