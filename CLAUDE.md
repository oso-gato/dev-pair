@AGENTS.md

<!--
A loader, not a second home for instructions.

Claude Code reads CLAUDE.md and does not read AGENTS.md, so without this file
none of the operating manual reaches a claudebox session and the constitution's
fetch line is never seen. The @-import loads AGENTS.md at session start and
re-injects it after compaction; a fetched document does not survive compaction.

Verified 2026-08-17 on Claude Code 2.1.232 by measurement, not by documentation:
a tree holding only AGENTS.md loads nothing, and the same tree with this one
line loads it in full.

Nothing else belongs here. AGENTS.md is the one tool contract (C2), and an
instruction written below the import would be law that only one agent in the
fleet can read. HTML comments are stripped before injection, so this note
costs no context.
-->
