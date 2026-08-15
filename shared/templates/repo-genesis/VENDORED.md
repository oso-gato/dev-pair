# Vendored — adoption trail (P1/P2)

The three files in [specs/](specs/) are vendored verbatim from GitHub Spec Kit:

- source: https://github.com/github/spec-kit `templates/`
- files: `spec-template.md`, `plan-template.md`, `tasks-template.md`
- release at adoption: v0.16.4 (2026-08-14); main sha `bf88c9f9a82fa370c7a7257aa2b3cf10b457b65c`
- adopted: 2026-08-16, fetched from the live upstream via the GitHub API
- re-verify: against upstream on the periodic P2 live-check cadence; a bump is a deliberate adoption with this trail updated, never a silent sync

The Spec Kit CLI itself is deliberately not adopted (ADR 0004): the pair needs the artifacts and gates, not the interactive scaffolding. If adopted later, it runs inside an agent box (P11) after a P2 scratch-test.
