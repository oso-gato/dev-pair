# dev-pair

Dev-pair is an autonomous development pair: a Fedora host that maintains the platform and a Podman development environment that builds products. You describe the outcome; the pair delivers tested, usable software and explains how to use it. You are the product owner and do not need to write or review code.

## The charter

These three governing documents are collectively **the charter**:

- [00-OBJECTIVE.md](00-OBJECTIVE.md) defines the product outcome, scope and acceptance criteria.
- [00-BYLAW.md](00-BYLAW.md) defines this project's platform, agent roles and operating contract.
- [00-CONSTITUTION.md](00-CONSTITUTION.md) records the exact adopted versions of the global constitution and shared development principles.

Together with this README, they are the complete local starting documentation. Read the charter and both pinned standards documents before making changes. Development principles live centrally; they do not require a fourth charter document. The private standards repository requires authorized read access.

## Current status

This project adopts `oso-gato/standards` release `v1.0.0`, with both shared documents pinned to the exact commit recorded in [00-CONSTITUTION.md](00-CONSTITUTION.md).

This is a charter restart, not a working installation. The initial tree contains only these four files. There are no runtime scripts, container images defined here, installation commands, automated tests or CI workflows yet. No live host has been verified or changed by this restart.

The previous source and documentation remain in Git history at commit [`90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5`](https://github.com/oso-gato/dev-pair/tree/90b7fac3bea54ae61a5dabf1ff9aede1a7a67cd5). They may be consulted selectively but do not govern the new implementation. No history or existing tags are rewritten.

## Platform and agents

The first deployment targets **Fedora Cloud 45** and rootless **Podman**, with Quadlet and systemd managing container lifecycle. Fedora lists Cloud 45 as released on November 3, 2026: [official download](https://fedoraproject.org/cloud/download/). The provider's actual image and required capabilities must be verified during implementation.

| Name | Meaning | Implementation status |
|---|---|---|
| `gptbox` | OpenAI Codex environment | To be built and tested first |
| `claudebox` | Claude Code environment | Reserved alternative; no adapter retained in this restart |
| `agentbox` | Selects the configured default, initially `gptbox` | Launcher to be built |

The complete selection and isolation rules live in [the bylaw](00-BYLAW.md). These names do not install software or introduce a nested agent container. Selecting an agent environment is separate from selecting its model.

## First working milestone

Prove one complete journey on one VPS: provision the platform, start Codex in both roles, accept a small product brief, build and independently verify the product, deploy it, and return its usable address. Demonstrate job recovery after interruption and recovery from a failed deployment.

The objective defines the acceptance evidence. Build this path before adding concurrent projects, bare-metal support or another agent adapter. Add source, meaningful tests and setup instructions as the implementation earns them; four files are the starting point, not a permanent file-count limit.

## Setup

There is no setup command yet. Implementation must provide a reproducible Fedora 45 setup and validate it on a disposable or explicitly designated VPS before this README can describe it as ready to use. Do not use a historical installer as the new setup procedure without adapting and testing it against the charter.
