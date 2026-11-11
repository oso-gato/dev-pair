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
**DR2.2** The restart now includes an offline, Python-standard-library [candidate preparation tool and local tests](docs/candidate-preparation.md). It validates explicit operator-supplied identities, prepares a deterministic digest-pinned Fedora/Codex build context, verifies transferred context bytes against a separately recorded handoff hash and prints blocked invocation proposals for both Distrobox placements. No image has been built or agent launched; Distrobox confinement, Fedora validation, authentication and model access remain unverified. There is no working installation, deployment or CI workflow. Operational access and budgets still need to be established before dependent execution.

<a id="dr2-3"></a>
**DR2.3** The previous source and documentation remain in Git history at commit [`90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`](https://github.com/oso-gato/dev-pair/tree/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5). They may be consulted selectively but do not govern the new implementation. No history or existing tags are rewritten.

<a id="platform-and-agents"></a>
<a id="dr3"></a>
## DR3 — Platform and agents

<a id="dr3-1"></a>
**DR3.1** The first deployment targets **Fedora Cloud 44** and rootless **Podman**, with Quadlet and systemd managing container lifecycle. On November 10, 2026, the owner reported that the existing Hostinger VPS runs Fedora Cloud 44 and corrected the earlier Fedora 45 target. The actual host OS, provider image and required capabilities have not been inspected and must be verified before adoption or deployment.

| Clause | Name | Meaning | Implementation status |
|---|---|---|---|
| <a id="dr3-2"></a>**DR3.2** | `gptbox` | OpenAI Codex environment | To be built and tested first |
| <a id="dr3-3"></a>**DR3.3** | `claudebox` | Claude Code environment | Reserved alternative; no adapter retained in this restart |
| <a id="dr3-4"></a>**DR3.4** | `agentbox` | Selects the configured default, initially `gptbox` | Launcher to be built |

<a id="dr3-5"></a>
**DR3.5** The complete selection, placement and isolation rules live in [ARCHITECTURE.md](ARCHITECTURE.md), especially A2.4 and A10. The original layered design is restored: a Distrobox-based gptbox on the host and another inside DevBox. Selecting an agent environment is separate from selecting its model. The machine names remain `erebus` and `strix`, both lowercase; A11 records the existing implementation references.

<a id="required-development-loop"></a>
<a id="dr4"></a>
## DR4 — Required development loop

<a id="dr4-1"></a>
**DR4.1** DevBox is the stable Podman development container hosting its Distrobox-based Codex gptbox. It implements the agreed product and runs function/unit, integration and end-to-end checks wherever its environment is sufficient. Checks requiring the real VPS go to the maintenance agent through a durable request. That agent returns results and diagnostics; DevBox repairs failures and requests retesting until acceptance passes or agreed limits produce a clear blocker. Independent review and verification at the delivery destination complete the loop.

<a id="dr4-2"></a>
**DR4.2** Builds and tests use isolated work trees and dependency environments, protecting all deployed code on the host, DevBox, maintenance container and application/test containers. Runtime code is immutable; updates activate verified replacement artifacts. Explicit workspaces, data and caches remain writable without overriding installed code. Valid work trees and caches persist through active iteration to avoid repeated downloads. Cleanup occurs at configured lifecycle boundaries and preserves source, evidence and deliverables. [REQUIREMENTS.md](REQUIREMENTS.md) defines the acceptance outcomes; [ARCHITECTURE.md](ARCHITECTURE.md) defines the intended handoff and storage boundaries. Offline candidate preparation records proposed boundaries; their runtime enforcement and the remaining lifecycle capabilities are not implemented or verified.

<a id="first-working-milestone"></a>
<a id="dr5"></a>
## DR5 — First working milestone

<a id="dr5-1"></a>
**DR5.1** Prove one complete journey on one VPS: provision the platform, start Codex in both roles, accept a small product brief, build and independently verify the product, deploy it, and return its usable address. Demonstrate job recovery after interruption, recovery from a failed deployment, a failed host test followed by a successful DevBox repair/retest, immutable OS/application/agent code, repeated-build reuse and safe cleanup.

<a id="dr5-2"></a>
**DR5.2** REQUIREMENTS defines the acceptance evidence. Build this path before adding concurrent projects, bare-metal support or another agent adapter. Add source, meaningful tests and setup instructions as the implementation earns them; four files are the starting point, not a permanent file-count limit.

<a id="setup"></a>
<a id="dr6"></a>
## DR6 — Setup

<a id="dr6-1"></a>
**DR6.1** There is no working platform setup command yet. The [local fixture exercise](docs/candidate-preparation.md#exercise-the-local-path) runs without container tools or external services; it is not a platform installation. Implementation must provide a reproducible Fedora 44 setup and validate it on a disposable or explicitly designated VPS before this README can describe it as ready to use. Do not use a historical installer as the new setup procedure without adapting and testing it against the adopted standards, requirements and architecture.

<a id="dr7"></a>
## DR7 — Required platform self-update

<a id="dr7-1"></a>
**DR7.1** Dev-pair must repair platform defects encountered during its own development or other product jobs. DevBox requests its replacement with a verified Podman image; the maintenance side performs the replacement and restores every active session to actual work. Host configuration and maintenance-agent updates follow the same recorded-target, checkpoint, verification and recovery discipline. See REQUIREMENTS R9 and ARCHITECTURE A8. These capabilities are required but not yet implemented.

<a id="dr8"></a>
## DR8 — Later hosted applications

<a id="dr8-1"></a>
**DR8.1** After the development pair is proven, the host also serves other owner-requested Podman applications. The named later workload is a remotely accessible Omarchy desktop succeeding the Fedora desktop experience. REQUIREMENTS R10 records the outcome and feasibility boundary; the Fedora host remains unchanged. No desktop migration or implementation is included in this documentation update.

<a id="dr9"></a>
## DR9 — Agent freshness and stable platform releases

<a id="dr9-1"></a>
**DR9.1** The two active agent environments rebuild nightly from verified official stable tooling, with cached inputs and complete session restoration. Host and DevBox releases run on separate, slower tested change cycles. Requirements R11 and architecture A10 define the contract. Model availability is checked separately from CLI/image version; these capabilities have not yet been adapted and verified in this restart. Existing Claudebox implementations in fedora-bootstrap and fedora-dev are linked in A11; they are the reference for the Codex adaptation.

<a id="dr10"></a>
## DR10 — Development sessions and launch brief

<a id="dr10-1"></a>
**DR10.1** Follow [A12's session workflow](ARCHITECTURE.md#a12): architecture/coordination with **GPT-6 Astra High**, implementation with **GPT-6.1 Sol High**, and independent review in a fresh **GPT-6 Astra High** session. Use Sol Medium for settled mechanical work; reserve Extra High for a specific difficult problem. Each handoff records the exact candidate, applicable requirements, evidence and next action. The owner provides product decisions, not code review or manual worker coordination.

<a id="dr10-2"></a>
**DR10.2** To start the separate development conversation, select repository **`oso-gato/dev-pair`**, branch **`main`**, model **GPT-6 Astra**, effort **High**, and an environment with authorized access to private `oso-gato/standards` and the two A11 reference repos. Verify the actual checkout and permissions after startup. Use the title **Dev-pair — architecture and coordination** and the following brief; selecting settings in the client is required because text in a prompt does not switch models:

> Develop oso-gato/dev-pair under ARCHITECTURE A12. First verify the checkout, record its exact revision, and read README, STANDARDS, its three pinned shared documents, REQUIREMENTS and ARCHITECTURE. Begin with the original-charter omission review in A12.11 and inspect the existing fedora-bootstrap and fedora-dev implementations at A11's revisions. Preserve the lowercase names erebus and strix, Fedora/Podman, separate Distrobox agent layers, agentbox → gptbox, nightly agent refreshes, slower platform releases, immutable deployed code, reusable isolated build trees, host-test feedback and complete session recovery. Produce a concise evidence-backed mapping and resolve only material product/authority decisions with me. Then coordinate A12.12's first implementation slice in a separate GPT-6.1 Sol High builder session, with fresh GPT-6 Astra High review and authorized host validation. Keep durable handoffs so I do not have to carry context between sessions. I am the product owner and do not review code. Verify model settings and session creation; report unavailable capabilities, missing execution budgets/access and genuine blockers without inventing success or silently changing requirements. Proceed autonomously within the established agreement and permissions.

<a id="dr10-3"></a>
**DR10.3** This section documents the workflow and supplies a launch brief. It does not create cloud conversations, configure their models, implement orchestration, or establish runtime/release compliance. Report actual session links and verified progress separately. Current model-selection references are [OpenAI's Codex model guidance](https://learn.chatgpt.com/docs/models) and [GPT-6.1 Sol effort settings](https://developers.openai.com/api/docs/models/gpt-6.1-sol); verify account/client support when launching.

<a id="dr10-4"></a>
**DR10.4** The [DR10 work record](docs/dr10-work-record.md) records the source baseline, original-charter reconciliation, owner decisions, actual session capabilities and implementation handoffs. [Local candidate preparation](docs/candidate-preparation.md) is the first partial A12.12(1) implementation; actual Fedora construction, both Distrobox placements and runtime acceptance remain unverified. Exact candidate review and current delivery status belong in the accompanying pull request.
