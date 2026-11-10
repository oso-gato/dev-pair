# dev-pair

<a id="dr0"></a>
## DR0 — Overview

<a id="dr0-1"></a>
**DR0.1** Dev-pair is an autonomous development pair: a Fedora host that maintains the platform and a Podman development environment that builds products. You describe the outcome; the pair asks focused questions until the product agreement is settled, then develops, tests, repairs and delivers usable software with evidence and instructions. You are the product owner and do not need to write or review code.

<a id="project-documentation"></a>
<a id="dr1"></a>
## DR1 — Project documentation

<a id="dr1-1"></a>
**DR1.1** The development restart has four local starting documents:

| Clause | Document | Purpose |
|---|---|---|
| <a id="dr1-2"></a>**DR1.2** | [README.md](README.md) | Product introduction, implementation status and verified use |
| <a id="dr1-3"></a>**DR1.3** | [STANDARDS.md](STANDARDS.md) | Adopted shared version, links, approval, exceptions and implementation gaps |
| <a id="dr1-4"></a>**DR1.4** | [REQUIREMENTS.md](REQUIREMENTS.md) | Product outcomes, scope and acceptance criteria |
| <a id="dr1-5"></a>**DR1.5** | [ARCHITECTURE.md](ARCHITECTURE.md) | Intended platform, components, agent roles and operating design |

<a id="dr1-6"></a>
**DR1.6** Governance and engineering standards live in the private `oso-gato/standards` repository. Both are referenced at the same full commit SHA, alongside the repository setup guide, in STANDARDS. Neither shared rules document is copied here. A central update does not automatically change this project's adopted version.

<a id="dr1-7"></a>
**DR1.7** Read this README, STANDARDS, its three pinned shared documents, then REQUIREMENTS and ARCHITECTURE before work. Authorized access to the private standards is required, or a verified execution cache of the exact revision. Report an access blocker if those documents cannot be loaded. Runtime enforcement of this entry procedure remains to be built and tested.

<a id="current-status"></a>
<a id="dr2"></a>
## DR2 — Current status

<a id="dr2-1"></a>
**DR2.1** This project adopts a **pre-1.0 working draft** of `oso-gato/standards`, pinned to the exact commit in [STANDARDS.md](STANDARDS.md). Version 1.0 remains a future milestone. The product owner approved the naming and adoption model on November 10, 2026.

<a id="dr2-2"></a>
**DR2.2** This is a documentation baseline for restarting development. There are no runtime scripts, container images defined here, installation commands, automated tests or CI workflows yet. No live host has been verified or changed by this restart. The intended architecture and acceptance requirements are documented; operational access and budgets still need to be established before dependent execution.

<a id="dr2-3"></a>
**DR2.3** The previous source and documentation remain in Git history at commit [`90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`](https://github.com/oso-gato/dev-pair/tree/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5). They may be consulted selectively but do not govern the new implementation. No history or existing tags are rewritten.

<a id="platform-and-agents"></a>
<a id="dr3"></a>
## DR3 — Platform and agents

<a id="dr3-1"></a>
**DR3.1** The first deployment targets **Fedora Cloud 45** and rootless **Podman**, with Quadlet and systemd managing container lifecycle. Fedora lists Cloud 45 as released on November 3, 2026: [official download](https://fedoraproject.org/cloud/download/). The provider's actual image and required capabilities must be verified during implementation.

| Clause | Name | Meaning | Implementation status |
|---|---|---|---|
| <a id="dr3-2"></a>**DR3.2** | `gptbox` | OpenAI Codex environment | To be built and tested first |
| <a id="dr3-3"></a>**DR3.3** | `claudebox` | Claude Code environment | Reserved alternative; no adapter retained in this restart |
| <a id="dr3-4"></a>**DR3.4** | `agentbox` | Selects the configured default, initially `gptbox` | Launcher to be built |

<a id="dr3-5"></a>
**DR3.5** The complete selection and isolation rules live in [ARCHITECTURE.md](ARCHITECTURE.md). These names do not install software or introduce a nested agent container. Selecting an agent environment is separate from selecting its model.

<a id="required-development-loop"></a>
<a id="dr4"></a>
## DR4 — Required development loop

<a id="dr4-1"></a>
**DR4.1** DevBox is the Podman development container running Codex. It implements the agreed product and runs function/unit, integration and end-to-end checks wherever its environment is sufficient. Checks requiring the real VPS go to the maintenance agent through a durable request. That agent returns results and diagnostics; DevBox repairs failures and requests retesting until acceptance passes or agreed limits produce a clear blocker. Independent review and verification at the delivery destination complete the loop.

<a id="dr4-2"></a>
**DR4.2** Builds and tests use isolated work trees and dependency environments, protecting both the host and DevBox Fedora OS trees. Valid work trees and caches persist through active iteration to avoid repeated downloads. Cleanup occurs at configured lifecycle boundaries and preserves source, evidence and deliverables. [REQUIREMENTS.md](REQUIREMENTS.md) defines the acceptance outcomes; [ARCHITECTURE.md](ARCHITECTURE.md) defines the intended handoff and storage boundaries. None of these capabilities is implemented yet.

<a id="first-working-milestone"></a>
<a id="dr5"></a>
## DR5 — First working milestone

<a id="dr5-1"></a>
**DR5.1** Prove one complete journey on one VPS: provision the platform, start Codex in both roles, accept a small product brief, build and independently verify the product, deploy it, and return its usable address. Demonstrate job recovery after interruption, recovery from a failed deployment, a failed host test followed by a successful DevBox repair/retest, protected Fedora OS paths, repeated-build reuse and safe cleanup.

<a id="dr5-2"></a>
**DR5.2** REQUIREMENTS defines the acceptance evidence. Build this path before adding concurrent projects, bare-metal support or another agent adapter. Add source, meaningful tests and setup instructions as the implementation earns them; four files are the starting point, not a permanent file-count limit.

<a id="setup"></a>
<a id="dr6"></a>
## DR6 — Setup

<a id="dr6-1"></a>
**DR6.1** There is no setup command yet. Implementation must provide a reproducible Fedora 45 setup and validate it on a disposable or explicitly designated VPS before this README can describe it as ready to use. Do not use a historical installer as the new setup procedure without adapting and testing it against the adopted standards, requirements and architecture.

<a id="dr7"></a>
## DR7 — Required platform self-update

<a id="dr7-1"></a>
**DR7.1** Dev-pair must repair platform defects encountered during its own development or other product jobs. DevBox requests its replacement with a verified Podman image; the maintenance side performs the replacement and restores every active session to actual work. Host configuration and maintenance-agent updates follow the same recorded-target, checkpoint, verification and recovery discipline. See REQUIREMENTS R9 and ARCHITECTURE A8. These capabilities are required but not yet implemented.

<a id="dr8"></a>
## DR8 — Later hosted applications

<a id="dr8-1"></a>
**DR8.1** After the development pair is proven, the host also serves other owner-requested Podman applications. The named later workload is a remotely accessible Omarchy desktop succeeding the Fedora desktop experience. REQUIREMENTS R10 records the outcome and feasibility boundary; the Fedora host remains unchanged. No desktop migration or implementation is included in this documentation update.
