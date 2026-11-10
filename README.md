# dev-pair

Dev-pair is an autonomous development pair: a Fedora host that maintains the platform and a Podman development environment that builds products. You describe the outcome; the pair delivers tested, usable software and explains how to use it. You are the product owner and do not need to write or review code.

## Project documentation

The development restart has four local starting documents:

| Document | Purpose |
|---|---|
| [README.md](README.md) | Product introduction, implementation status and verified use |
| [STANDARDS.md](STANDARDS.md) | Adopted shared version, links, approval, exceptions and implementation gaps |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Product outcomes, scope and acceptance criteria |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Intended platform, components, agent roles and operating design |

Governance and engineering standards live in the private `oso-gato/standards` repository. Both are referenced at the same full commit SHA, alongside the repository setup guide, in STANDARDS. Neither shared rules document is copied here. A central update does not automatically change this project's adopted version.

Read this README, STANDARDS, its three pinned shared documents, then REQUIREMENTS and ARCHITECTURE before work. Authorized access to the private standards is required, or a verified execution cache of the exact revision. Report an access blocker if those documents cannot be loaded. Runtime enforcement of this entry procedure remains to be built and tested.

## Current status

This project adopts a **pre-1.0 working draft** of `oso-gato/standards`, pinned to the exact commit in [STANDARDS.md](STANDARDS.md). Version 1.0 remains a future milestone. The product owner approved the naming and adoption model on November 10, 2026.

This is a documentation baseline for restarting development. There are no runtime scripts, container images defined here, installation commands, automated tests or CI workflows yet. No live host has been verified or changed by this restart. The intended architecture and acceptance requirements are documented; operational access and budgets still need to be established before dependent execution.

The previous source and documentation remain in Git history at commit [`90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`](https://github.com/oso-gato/dev-pair/tree/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5). They may be consulted selectively but do not govern the new implementation. No history or existing tags are rewritten.

## Platform and agents

The first deployment targets **Fedora Cloud 45** and rootless **Podman**, with Quadlet and systemd managing container lifecycle. Fedora lists Cloud 45 as released on November 3, 2026: [official download](https://fedoraproject.org/cloud/download/). The provider's actual image and required capabilities must be verified during implementation.

| Name | Meaning | Implementation status |
|---|---|---|
| `gptbox` | OpenAI Codex environment | To be built and tested first |
| `claudebox` | Claude Code environment | Reserved alternative; no adapter retained in this restart |
| `agentbox` | Selects the configured default, initially `gptbox` | Launcher to be built |

The complete selection and isolation rules live in [ARCHITECTURE.md](ARCHITECTURE.md). These names do not install software or introduce a nested agent container. Selecting an agent environment is separate from selecting its model.

## First working milestone

Prove one complete journey on one VPS: provision the platform, start Codex in both roles, accept a small product brief, build and independently verify the product, deploy it, and return its usable address. Demonstrate job recovery after interruption and recovery from a failed deployment.

REQUIREMENTS defines the acceptance evidence. Build this path before adding concurrent projects, bare-metal support or another agent adapter. Add source, meaningful tests and setup instructions as the implementation earns them; four files are the starting point, not a permanent file-count limit.

## Setup

There is no setup command yet. Implementation must provide a reproducible Fedora 45 setup and validate it on a disposable or explicitly designated VPS before this README can describe it as ready to use. Do not use a historical installer as the new setup procedure without adapting and testing it against the adopted standards, requirements and architecture.
