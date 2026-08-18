# 000033 — The estate names two platforms, and their ladder naming folds into C4

- status: accepted
- date: 2026-08-18
- amends: the universal constitution — the Conformance section and C4
- continues: [000018](000018-no-sieves-and-product-before-mechanism.md), which moved four fifths of the provenance ladder from bylaw to C4 and left the naming behind

## Problem

ADR 000018 rehomed the provenance ladder's shape, its c1/c2/c3 grading and the estate-wide forbidden categories from this repository's bylaw into universal C4. It left the platform naming in the bylaw, and it recorded why in its own words — four fifths of that ladder was universal law living in a repository, and the next repository chartered would have copied it, which is the shape that produced a 670-line guard-parity workflow because one payload lived in three repositories and one silently missed a fix.

The remaining fifth was left behind because the platform set was open. A repository on another platform was expected to inherit the law and write only its own names, so naming Fedora universally would have served one platform at the expense of the rest.

The maintainer has closed the set. The estate builds on Fedora, and on Debian where a workload requires it, and on nothing else. That changes what the naming is. A fact true of every repository forever is an estate-wide constant, not one repository's implementation, and C1 gives a constant one home. Under the old arrangement every future charter would restate the same ladder, the same minimalism flag and the same forbidden instances, differing in one word.

The measured cost was already visible at n=1. This repository's own L2 instantiation described a hand-written `.repo` with `gpgcheck=1` while its code had moved to pinning the vendor's own file by sha256 — recorded in 000031 as needing sharpening, and still unsharpened. One copy drifted below the constitution it instantiates. The arrangement proposed to reproduce that copy per repository.

## Decision

C4 gains a closing paragraph naming the estate's two platforms and their ladder tiers, their minimalism flags and their forbidden instances. The Conformance section is narrowed to match: per-ecosystem instantiations still live in the repositories that own them, with the two operating-system platforms as the stated exception. C4's delegation sentence is narrowed the same way.

A repository now states one thing about provenance, in one line — which of the two it builds on. This repository builds on Fedora. The genesis skeleton's bylaw template carries that line as a slot, so the question is asked once during charter co-creation and answered in a word.

The Debian half is drafted from Debian's current documented practice, verified live this session. Sources are deb822 `.sources` files in `/etc/apt/sources.list.d/`, which Debian 13 makes the default and against which the one-line `.list` format is deprecated. A third-party repository names its key in `Signed-By`. Keys the estate installs itself belong in `/etc/apt/keyrings/`, the recommended location since APT 2.4, rather than `/usr/share/keyrings/`, which is for keyrings shipped inside a package. A key placed in `/etc/apt/trusted.gpg.d/` or added by the deprecated `apt-key` is trusted for every repository on the host rather than for the one it belongs to, so C4 forbids it by name.

## Options

**Keep the naming in each repository's bylaw.** Rejected by the maintainer, on the ground the arrangement was built to serve: he does not want to state a platform's provenance again at every charter. The estate's own template already shows the design assumed an open platform set, and that assumption no longer holds.

**A `platform.md` at the estate root, referenced by each bylaw.** Rejected on the estate's own text, after reading the repository rather than reasoning about it. `environments/` states its doctrine in its README — facts are inputs, never law, re-verified before use and expiring with hardware, provider or OS release — and platform naming is neither an input nor expiring. `principles/` holds the constitution alone, so a second file there invents a law-adjacent category with no loader, in the one repository C2 leaves private, unprotected and untagged by the epoch. Law with the accountability removed.

**Name the platforms but leave the mechanisms per-repository.** Rejected as the worst of both: the constitution would carry the constant and each bylaw would still carry the naming, which is two homes for one concept.

## Consequence

Every future bylaw carries one line where this one carried two paragraphs, and the ladder has one home for both platforms.

The staleness 000031 flagged is closed by deletion rather than repair. The bylaw sentence describing the weaker L2 is gone, and C4's new wording — the vendor's own file, pinned to it, never a definition transcribed into this estate — is the corrected form, which is what this repository's code already does.

000031's recommendation that the maintainer sharpen the bylaw's L2 instantiation is superseded by this record. The sharpening did not happen and will not; the sentence no longer exists.

What this does not do is reach repositories already chartered. A template is instantiated once and frozen into a bylaw, so a later correction to C4 reaches every repository by reference while a later correction to the template reaches only repositories chartered after it. Proximity to the code remains the only defence against a bylaw drifting from what its repository does, and that is an argument for bylaws staying short rather than for them staying full.

A third platform is a new maintainer confirmation of C4's paragraph, never a repository's own decision.
