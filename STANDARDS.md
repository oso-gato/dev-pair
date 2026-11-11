# Adopted standards

<a id="version-and-approval"></a>
<a id="s1"></a>
## S1 — Version and approval

- <a id="s1-1"></a>**S1.1** Source: `oso-gato/standards` (private).
- <a id="s1-2"></a>**S1.2** Standards status: **pre-1.0 working draft (unreleased)**.
- <a id="s1-3"></a>**S1.3** Full commit SHA: `b9d4da5d442ac48dba2e8be62d81b5bdc83690b8`.
- <a id="s1-4"></a>**S1.4** [Governance](https://github.com/oso-gato/standards/blob/b9d4da5d442ac48dba2e8be62d81b5bdc83690b8/GOVERNANCE.md).
- <a id="s1-5"></a>**S1.5** [Engineering standards](https://github.com/oso-gato/standards/blob/b9d4da5d442ac48dba2e8be62d81b5bdc83690b8/ENGINEERING-STANDARDS.md).
- <a id="s1-6"></a>**S1.6** [Development repository standard](https://github.com/oso-gato/standards/blob/b9d4da5d442ac48dba2e8be62d81b5bdc83690b8/REPOSITORY-SETUP.md).
- <a id="s1-7"></a>**S1.7** Status: adoption and the documented product decisions are owner-directed as of November 10, 2026, including restoration of the original Distrobox agent layers and nightly rebuilds, with retained lowercase machine names `erebus` and `strix`. The owner explicitly approved this Tailscale standards upgrade and migration of the current DR10 / PR #13 job on November 10, 2026 (America/New_York); the prior job pin was `08fc080dc8463a16e7ef753eefdefd98463b76b9`.
- <a id="s1-8"></a>**S1.8** Project exceptions: none.

<a id="s1-9"></a>
**S1.9** All three references use the same exact commit. The commit identifies the exact draft content; adoption does not declare the standards ready for 1.0. Publishing new standards does not automatically change this project or an existing job's recorded version. Both shared rules documents remain centrally stored; this repository contains references only.

<a id="project-documentation"></a>
<a id="s2"></a>
## S2 — Project documentation

- <a id="s2-1"></a>**S2.1** [REQUIREMENTS.md](REQUIREMENTS.md) defines the product outcomes, scope and acceptance criteria.
- <a id="s2-2"></a>**S2.2** [ARCHITECTURE.md](ARCHITECTURE.md) defines the intended system structure, platform, agent roles and operating design.
- <a id="s2-3"></a>**S2.3** [README.md](README.md) describes current implementation status and verified use.

<a id="s2-4"></a>
**S2.4** This file records adoption and exceptions; it is not a local copy of governance or engineering standards. The product owner controls changes to shared-standard adoption, product scope and authority. Ordinary engineering choices remain autonomous within those boundaries. Resolve conflicts and identify implementation gaps when changing the adopted version.

<a id="loading-the-standards"></a>
<a id="s3"></a>
## S3 — Loading the standards

<a id="s3-1"></a>
**S3.1** Before work, read README, this file, the pinned governance, engineering standards and repository setup guide, then local requirements and architecture. Use authorized read access to the private repository. Verify the full commit and record it for the job. A verified execution cache of the same revision outside this repository's tracked files is acceptable; it is not an editable policy source.

<a id="s3-2"></a>
**S3.2** If the exact documents cannot be loaded, report the access blocker. Do not substitute remembered rules, a moving branch or another release. Do not commit shared private rules or access credentials here.

<a id="implementation-gaps-and-restart-boundary"></a>
<a id="s4"></a>
## S4 — Implementation gaps and restart boundary

<a id="s4-1"></a>
**S4.1** This adoption establishes documentation requirements; it does not claim runtime compliance. Tailnet enrollment, authorized application/administrative access, public/unauthorized denial and fail-closed loss/recovery (R7.17–R7.18), agent startup, standards retrieval/version checks, job records, host-test handoffs and result-driven repair, immutable host and container code, build-tree/cache lifecycle, platform self-update, nested Distrobox agent placement, nightly rebuild scheduling and complete session restoration, independent release checks and all other platform capabilities remain to be implemented or adapted and verified for this restart. A11 identifies the existing Claudebox implementations; their existence must not be confused with verified Codex compatibility. README records actual progress. Operational budgets, credentials and the designated VPS must be resolved before dependent execution, as required by the product agreement.

<a id="s4-2"></a>
**S4.2** The November 10, 2026 development restart remains in effect. Historical source and documents are reference material, not binding instructions. Historical governance from `oso-gato/homelab-root` is not imported. Git history is preserved. Premature release labels were retired centrally; this adoption uses the verified draft commit. Other repositories require their own authorized adoption changes.
