# Adopted standards

## Version and approval

- Source: `oso-gato/standards` (private).
- Release: `v2.0.0`.
- Full commit SHA: `8f228c9bb0845f27c64797d07ac1d302c14c9dfb`.
- [Governance](https://github.com/oso-gato/standards/blob/8f228c9bb0845f27c64797d07ac1d302c14c9dfb/GOVERNANCE.md).
- [Engineering standards](https://github.com/oso-gato/standards/blob/8f228c9bb0845f27c64797d07ac1d302c14c9dfb/ENGINEERING-STANDARDS.md).
- [Development repository standard](https://github.com/oso-gato/standards/blob/8f228c9bb0845f27c64797d07ac1d302c14c9dfb/REPOSITORY-SETUP.md).
- Status: adoption and documentation migration approved by the product owner on November 10, 2026.
- Project exceptions: none.

All three references use the same exact commit. The release label is descriptive; the commit identifies the content. Publishing new standards does not automatically change this project or an existing job's recorded version. Both shared rules documents remain centrally stored; this repository contains references only.

## Project documentation

- [REQUIREMENTS.md](REQUIREMENTS.md) defines the product outcomes, scope and acceptance criteria.
- [ARCHITECTURE.md](ARCHITECTURE.md) defines the intended system structure, platform, agent roles and operating design.
- [README.md](README.md) describes current implementation status and verified use.

This file records adoption and exceptions; it is not a local copy of governance or engineering standards. The product owner controls changes to shared-standard adoption, product scope and authority. Ordinary engineering choices remain autonomous within those boundaries. Resolve conflicts and identify implementation gaps when changing the adopted version.

## Loading the standards

Before work, read README, this file, the pinned governance, engineering standards and repository setup guide, then local requirements and architecture. Use authorized read access to the private repository. Verify the full commit and record it for the job. A verified execution cache of the same revision outside this repository's tracked files is acceptable; it is not an editable policy source.

If the exact documents cannot be loaded, report the access blocker. Do not substitute remembered rules, a moving branch or another release. Do not commit shared private rules or access credentials here.

## Implementation gaps and restart boundary

This adoption establishes documentation requirements; it does not claim runtime compliance. Agent startup, standards retrieval/version checks, job records, independent release checks and all other platform capabilities remain to be implemented and verified. README records actual progress. Operational budgets, credentials and the designated VPS must be resolved before dependent execution, as required by the product agreement.

The November 10, 2026 development restart remains in effect. Historical source and documents are reference material, not binding instructions. Historical governance from `oso-gato/homelab-root` is not imported. Git history and published tags are preserved. Other repositories require their own authorized adoption changes.
