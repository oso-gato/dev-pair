# Tasks: Mechanical gates

All complete at ship.

- [x] Verify `actions/checkout` v7.0.1 tag sha against live upstream; record the trail in plan.md
- [x] `shared/gates/scan_structure.sh` — P2 root inventory, casing grammar, docs/ children, no .md in component trees
- [x] `shared/gates/scan_channels.sh` — P4 forbidden channels over component trees and .github
- [x] `shared/gates/scan_secrets.sh` — P6 secret patterns over the whole tracked tree
- [x] `shared/gates/gate_specs.sh` — locked documents, specs-completeness, frozen-at-ship over the PR diff
- [x] `shared/gates/gate.sh` — one-command repo-state runner: structure, channels, secrets, shellcheck
- [x] Fixtures: one violating tree per scan, real-shaped dummies only
- [x] `shared/gates/test/test_gates.sh` — every scanner proven to fail on its fixture and pass on the clean tree; specs gate proven on constructed histories
- [x] `.github/workflows/gate.yml` — thin caller, checkout pinned by sha, job name `gate`
- [x] AGENTS.md Build & test filled in the same change; ARCHITECTURE.md components and promised-list updated; CHANGELOG entry
- [x] Analyze pass: spec ↔ plan ↔ tasks consistent
- [x] PR green under its own gate; non-author adversarial review; merge; branch protection set on main; freeze this folder, close #7
