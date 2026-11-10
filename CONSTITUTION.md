# The Dev Pair — CONSTITUTION (universal law, applied by reference)

The estate's universal constitution — `oso-gato/homelab-root` → `principles/CONSTITUTION.md` (private; resolvable by the pair's agents) — governs all work in this repository. It is never re-dictated; a re-dictation is a fork. Bare C-numbers estate-wide refer to it. This file is the charter's third member (C2): the reference is what this repository holds and what its epoch locks, while the law's own text stays live at its one home.

Load it at session start:

```
gh api repos/oso-gato/homelab-root/contents/principles/CONSTITUTION.md --jq .content | base64 -d
```

Repo-specific law, subordinate to it: [00-BYLAW.md](00-BYLAW.md).

## Maintainer direction for this revision

The 2026-11-10 requirements revision records the maintainer's instruction for dev-pair to use Podman and Codex in both roles, with development Codex running directly inside the dev-container. This later direction takes precedence for this repository over C8's prescribed nested Distrobox placement and independently rebuilt inner agent layer. The replacement keeps disposable images, durable external state and verified renewal; [00-BYLAW.md](00-BYLAW.md) B5 defines its runtime contract.

This is a scoped departure recorded for the charter merge, not a claim that the universal constitution or other repositories have been amended. C4's package-admission requirements remain in force, and the Codex installation route must be resolved before runtime implementation. The rationale and transition are in [docs/decisions/000034-codex-on-podman.md](docs/decisions/000034-codex-on-podman.md).

Agent names and the default selection follow [00-BYLAW.md](00-BYLAW.md) B5. A name or default assignment is not an admission manifest and does not prove that the corresponding runtime exists.
