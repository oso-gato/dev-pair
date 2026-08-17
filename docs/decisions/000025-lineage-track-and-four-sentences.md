# 000025 — A track is not a lineage; four sentences redrawn

- status: accepted
- date: 2026-08-18

## Problem

Two problems, found by an independent audit of the charter and confirmed by the maintainer sentence by sentence.

The word **lineage** carried two incompatible senses across two charter files. `00-OBJECTIVE.md` fixed it as a pair named by its host, so `erebus` is a lineage and `strix` is a lineage. `00-BYLAW.md` used it for the deploy-mechanism family, saying the host has two lineages, meaning VPS and bare metal. Under the objective's sense a host cannot have two lineages, because a host is one. The senses coincided only because the estate runs exactly one host per mechanism, and the objective's own next clause is that the platform is replicable. A second cloud host would have split them: the objective would call it a new lineage, the bylaw would call it the same one, while tickets are stamped per pair, the registry holds one file per host, and the deploy mechanism is defined per bylaw-lineage. Three surfaces would have been counting different things under one word. ADR 000001 fixed this vocabulary once already, after `lineage` had meant three things.

Separately, four sentences in `00-OBJECTIVE.md` failed the estate's own style law at AGENTS.md, which asks for full prose sentences that happen to be short and one subject per sentence. The host bullet ran to 65 words and put a 46-word interruption between its subject and its first finite verb, switching grammatical mood twice inside it, while `AGENTS.md` already states the same fact in 18 words. The dev-container bullet carried no finite verb at all and hung four items off its subject in four different shapes. The Confirmation bullet left a trailing clause whose attachment two reviewers resolved in opposite directions. And one line held the corpus's only typo.

## Decision

Maintainer-confirmed, wording chosen by him from drafted alternatives.

**A track is not a lineage.** A lineage is a pair, named by its host — the objective's sense, unchanged. A **track** is the deploy-mechanism family, and the estate already used that word two paragraphs later for exactly this split: the bare-metal track and the VPS track. The bylaw was the only file mixing them, and it now reads that a host belongs to one of two tracks, each with one sanctioned deploy mechanism. One consequence follows and was applied: the objective's host bullet said genesis follows its lineage's deploy mechanism, and a mechanism belongs to a track, so it now says its track's.

**Four sentences redrawn, no meaning moved.** Each was rewritten into short prose with every element preserved, and each was put before the maintainer as before and after. The Confirmation bullet's trailing clause was the one genuine ambiguity, and he settled it: the constitution joins the objective and the bylaw as the charter's third file, applied by reference and never re-dictated. That reading was chosen over attaching the clause to the bylaw alone, over attaching it to the session, and over deleting it and letting the same statement at the top of the document carry it.

**Two propagating defects closed.** The genesis skeleton still shipped the label-colon register into every future charter, in both `00-OBJECTIVE.template.md` and `00-BYLAW.template.md`, while the live files it was removed from sat one directory away. Both templates now carry the conforming prose. And `AGENTS.md` regains the qualifier "For structural work", dropped without record at commit `0566238` when the charter widened; the same restoration lands in the skeleton's template.

## Options considered

- **Rename the pair rather than the mechanism** — rejected. `lineage` for a host-named pair is fixed by ADR 000001 and used throughout the objective and AGENTS.md, while `track` was already the estate's word for the mechanism split and was in use two paragraphs from the collision. The smaller change was also the correct one.
- **Bind each track permanently to its instance name**, so that `erebus` names the VPS track and `strix` the bare-metal track — proposed by one audit agent and rejected. It would have entrenched the collision, tying a mechanism family to one machine and contradicting the objective the moment a second host of either kind appeared.
- **Leave the four sentences alone as a matter of taste** — rejected. Two agents found the host bullet independently by different instruments, and the estate's own AGENTS.md proves the readable version exists, since it already carries the same fact in a third of the words.
- **Adopt the audit's other rewrites of C1, C3 and C11** — rejected. Adversarial verification found that each lost meaning: one would have raised an AGENTS.md condition into supreme law, one replaced a length bound with a form bound and licensed unbounded restatement, and one would have made restoration a human summons, which C11 itself calls UNSAFE.

## Consequences

`00-OBJECTIVE.md` changes in four places and `00-BYLAW.md` in two. `AGENTS.md` regains its qualifier. In `homelab-root`, three genesis templates carry the same corrections forward, so no future repository is born with the label-colon register or with the collision.

The audit that produced this record returned a verdict on the charter as a whole, and it was not a critical one: the construct is sound, every structural measurement reproduced independently, and the two files the maintainer co-created meet the standard he set. These are the local exceptions to that verdict, and they are the whole of it.
