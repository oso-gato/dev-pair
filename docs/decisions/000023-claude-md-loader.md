# 000023 — The CLAUDE.md loader, admitted to the skeleton

- status: accepted
- date: 2026-08-17

## Problem

`AGENTS.md` calls itself the session-loaded operating manual and was not being loaded. Claude Code reads `CLAUDE.md` and does not read `AGENTS.md`, and no repository in the estate held a `CLAUDE.md` — not dev-pair, not homelab-root, not the genesis skeleton. `claudebox` is Claude Code, so the working method, ticket routing, self-renewal, session conduct and the writing style reached a session only when an agent chose to open the file, never by construction. The constitution sat one hop further back, because the fetch line lives inside `CONSTITUTION.md`, which `AGENTS.md` points at.

The claim was measured rather than read. On Claude Code 2.1.232 a tree holding only `AGENTS.md` with a codeword in it answers NOT LOADED; the same tree with a `CLAUDE.md` carrying an unrelated codeword returns that one, proving the test detects a positive; and the same tree with a `CLAUDE.md` containing the single line `@AGENTS.md` returns the codeword from `AGENTS.md`. Documentation alone would not have settled it: the estate's largest upstream feature request for native `AGENTS.md` support, `anthropics/claude-code` issue 6235, was closed as completed at 03:37 on the morning of this record, while the memory documentation still states that Claude Code reads `CLAUDE.md` and not `AGENTS.md`, the changelog carries no matching entry, and issue 34235 asking for the same thing stays open.

## Decision

Every repository carries `CLAUDE.md`, and it holds one line: `@AGENTS.md`. C2's skeleton admits it, so it is a standing surface rather than accretion.

The loader is never a second home. An instruction written below that import would be law only one agent in the fleet could read, and it belongs in `AGENTS.md` instead, which stays the one tool contract. The explanation of why the file exists sits in an HTML comment, which Claude Code strips before injection, so the note costs no context and still reaches a human opening the file.

The import form was chosen over the symlink the same documentation offers. A symlink needs Administrator rights or Developer Mode on Windows, Kimi Code shipped a fix in 0.28.0 for its web backend ignoring symlinked `AGENTS.md`, and a symlink leaves no place to record why the file exists.

## Options considered

- **A symlink, `ln -s AGENTS.md CLAUDE.md`** — rejected for the portability and record reasons above. It is otherwise equivalent and remains a fallback.
- **Move the manual into `CLAUDE.md` and drop `AGENTS.md`** — rejected. Kimi Code loads `AGENTS.md` automatically, into its system prompt, verified by running it at 0.35.0; Codex reads `AGENTS.md` before doing any work and never reads `CLAUDE.md`. Renaming would break two boxes to fix one and would abandon the cross-agent name C8's admission contract depends on.
- **Inline the charter or the constitution into the loaded file** — rejected on measurement. `AGENTS.md` is 6,128 bytes and sits comfortably everywhere, but the charter and constitution together are 39.0 KiB — 10,261 plus 8,017 plus 712 plus 20,923 bytes — past Codex's 32 KiB `project_doc_max_bytes` ceiling by roughly a quarter, and Kimi truncates as well, visibly since 0.20.0 and against no published limit. What auto-loads stays lean; the charter is opened when a session needs it.
- **Do nothing and rely on agents opening the file** — rejected. That is the condition this record was written to end, and 000018 already found that a rule which must be volunteered loses to anything that loads.

## Consequences

`CLAUDE.md` lands in dev-pair and in homelab-root, and `CLAUDE.template.md` in the genesis skeleton so every future repository is born loaded. C2 admits it to the standing surface set and states the loader rule beside the one-tool-contract sentence; the genesis manual gains its row and a line in the procedure. The homelab-root copy matters most of the three: the vault discipline that forbids reading a credential now reaches a session by construction rather than by an agent's choice to look.

This changes what reaches an agent, not what the law says. Where the universal constitution lives, and whether its fetch is pinned, stays open.
