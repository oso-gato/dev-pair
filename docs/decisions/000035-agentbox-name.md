# 000035 — Agentbox selects the default agent environment

- status: accepted direction; charter revision pending maintainer merge
- date: 2026-11-10

## Decision

The maintainer selected separate names for the concrete agents and the default entry point. [00-BYLAW.md](../../00-BYLAW.md) B5 owns the mapping: `gptbox` is Codex, `claudebox` is Claude Code, and `agentbox` resolves to the configured default, currently `gptbox`.

This makes the default easy to change without changing the operator's entry point. Explicit agent selection remains available, and a default change never transfers an in-flight job or transcript to another provider. Agent selection and the model selected within an agent are separate settings.

Shared lifecycle code and small agent-specific adapters are preferred over copied launcher stacks. Each adapter must prove authentication, invocation, isolation, persistence and resume before it can be selected. The names do not require a nested container layer or reverse the direct-in-container development design in decision 000034.

## Consequences

This naming change updates the requirements and orientation. Existing Claude scripts remain the retained implementation; the Codex adapter and default launcher are not implemented by this change. Existing App identities and credential filenames retain their actual names. Historical decisions and frozen specs remain unchanged.
