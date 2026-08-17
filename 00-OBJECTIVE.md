# The Dev Pair — OBJECTIVE (spec of record)

**The foremost objective is autonomous development**: a host and its dev-container — one **dev pair** — running an autonomous development-loop workflow, with exactly one human interaction per project, then shipping on its own. **The second objective: the host is a mother platform**, hosting containers as apps and services for whatever the maintainer needs. Everything below serves those two; on any conflict, the twofold objective wins and the conflicting clause is defective.

## Authority

Confirmed 2026-08-16, and fixed: amendment is a new maintainer confirmation, never a silent edit, and only the maintainer merges this document, the constitution, or the bylaw. It holds the WHY and the WHAT — intent, outcomes, boundaries. The HOW belongs to the constitution and the bylaw; the arrangement to `ARCHITECTURE.md`, which stays agent-owned, mutable-on-fact, and never a conformance target.

Why objective and constitution are separate documents: the objective is **scoped** — this platform's here, each project's own `00-OBJECTIVE.md` in its repository — while the constitution is **universal**. A project's one initiation session co-creates its objective and bylaw — the constitution applied by reference, never re-dictated. One session, two artifacts, the third by reference; nothing assumed.

## The workflow — one interaction, then ship

- **Initiation.** Exactly one interactive session at the very beginning: the maintainer states the objective, the intended outcome, the scope and the boundaries.
- **Confirmation.** The pair co-creates the **confirmed objective and the bylaw** with the maintainer in that session, sharpening and expanding his statement and settling both together: the objective's outcomes and boundaries, and the bylaw's runtime shape, repo-specific principles and instantiations. The constitution joins them as the charter's third file, applied by reference and never re-dictated. The maintainer confirms. That confirmation is the one and only human act the workflow requires.
- **Execution.** The **charter** — the three law files at the new repository's root: `00-OBJECTIVE.md` and `00-BYLAW.md`, co-created and confirmed in that session, and `CONSTITUTION.md`, the universal law applied by reference (C2) — is the pair's whole instruction. From it the pair autonomously builds the functional requirements, architects the design that serves them, and then builds, validates, and iterates in a live environment, recovering from failure automatically, until the product ships. Humans approve goals, never deployments; there is no second approval.
- **Ship.** Nothing ships on its builder's own word — the ship gate is universal C10. If review fails, the product goes back into the loop, not out the door.
- **Delivery.** Shipping ends with the pair handing the maintainer the live outcome — the running service, where to find it, how to use it — together with an account of what was decided along the way. Delivery is a report, not a request: the one interaction this workflow counts is an approval, and delivery asks for none.

Between confirmation and delivery, two policies stand. Where the charter is silent, the pair decides for itself — taking the smallest footprint that serves the objective, recording the decision, and reporting it at delivery; if the choice was wrong, the maintainer amends the charter afterward. And a project that cannot meet its objective within its boundaries halts and says so, naming the contradiction and proposing an amendment — it never loops indefinitely, and it never quietly ships a compromise.

## After ship

New work arrives as tickets. A ticket that fits within the charter's scope proceeds autonomously under the standing law. A ticket that would exceed the objective or the bylaw is a scope change, and a scope change amends the charter first — a new maintainer confirmation — before the work proceeds. A scope change reaches only this repository's own two files; the constitution is amended once for the whole estate and never for a ticket.

## The pair — three parts, one system

The pair is three parts, always: **the GitHub ticket bus, the host, and the dev-container** — one lifecycle, one specification, one repository. Tickets and PRs are the first-class hand-off; the dev-container never touches the host directly. The host is Fedora and environment-agnostic by construction — the only constants are Fedora and headlessness; provisioning facts are registry inputs, never baked-in assumptions. The runtime boundary between host and dev-container is real; no other boundary is manufactured.

- **The host** takes its genesis from its track's deploy mechanism, instantiated in the bylaw. It operates and maintains the platform: deploy, refresh, roll back, create and remove containers, keep itself sound. It hosts applications per the second objective, each its own container from a registry, a VM only as C7 allows. It live-diagnoses and develops fixes — **PRs only, never merges**. It never builds production images; CI does. It never applies an unmerged change. On merge it renews itself, no standing human tap (B4).
- **The dev-container** develops and validates (tier-1). It is the platform's **sole merge authority** under its empirical gates, except the charter, which only the maintainer merges. It is home to the multi-tenant sessions, and the host refreshes it from outside.
- **The agent layer** — every agent in a disposable box per universal C8, so the components stay relatively stable while every agent stays always current, and no rebuild costs live work.

**One repository, many pairs.** The platform is replicable: each deployment is one pair — a **lineage, named by its host**. `erebus`, the first, is also the **genesis agent** that spins up all future containers; `strix` is the bare-metal pair. Instance facts live in the estate's environment registry, never here. Each pair works under its own dedicated GitHub App identities, never shared. Authority is per-pair: each dev-container is the sole merger of its own work; each host the single shared validator of its own sessions. A host is always deployed as a dev pair foremost and first — application workloads come after.

**Two capability tracks.** Pairs differ in capability, never in contract. The **bare-metal track** carries full virtualization (libvirt/KVM) and a GPU as shared substrate — shared to containers and VMs, never monopolised from the host. The **VPS track** is assumed to have neither. Validation needing those capabilities routes to bare metal (C9); a capability may be used where it exists, but no platform function may require it.

## The loop

Built by dogfooding: every change to this repository lands through the platform's own loop, under the constitution and bylaw — construction law is not restated here.

- **Three decoupled clocks.** The host OS, the dev-container image, and each agent box advance on their own cadence — the boxes' cadence is the fast, nightly one — none forcing a rebuild of the others, each advance verified by reading the live artifact back.
- **Multi-tenant development.** The dev-container runs any number of isolated agent sessions, each on its own declared repository set. Isolation is by scope, code-enforced, not by identity; no session reads, touches, or iterates another's work. The host is the single shared validator for all of them.
- **Two-tier validation.** A session proves what it can inside the dev-container and engages the host only for the live validation the container cannot perform itself — then iterates on the host's verdict until GREEN. Where the container cannot validate at all, that fallback is forced, not chosen. Both tracks share the model.
- **Merged is not live — in both directions.** A merge is not a deployment: it self-arms the matching renewal (B4), staggered so neither component rebuilds the agent doing the work, and every refresh is confirmed by reading the live artifact back against merged source, fail-closed.

## Security outcomes

1. **Minimal public surface.** Every service is private by default. The only public doors: hardened SSH/MOSH on both components of every pair. Everything else — desktops, consoles, dashboards, admin interfaces — is reachable only from private networks (the tailnet everywhere; the local LAN on a local pair), bounded at the network layer.
2. **Keys, never passwords.** Every public door authenticates by SSH keys only; no password ever authenticates remote shell access anywhere in the platform, public or private. The maintainer's published key set is the single trust root (C6): access is granted and revoked by managing keys, never by distributing credentials. Private-network consoles may use their own hardened per-service authentication — never a shared or default credential. The administrative user is `core` and root never authenticates remotely after genesis (C7); the sudo password that escalates it exists for escalation only and never authenticates a remote shell.
3. **Sessions survive.** Interactive sessions survive frequent disconnections — network roams, device sleeps, client restarts — and persist long-term: a session left running for weeks resumes exactly where it was, from any authorized device, with no loss of running state, transcript, or work context. Outcome only; the mechanism is the architecture's and may change without amending this document.

## Boundaries

- The host never merges; the dev-container merges — except the confirmed charter, which only the maintainer merges.
- Neither component builds production images; CI builds them. The host builds only throwaway validation candidates.
- No unmerged change is ever applied to either component. Proposing is never applying.
- The platform operates only on the repositories its GitHub App is installed on — the maintainer's live install choice, private repositories included — and never widens its own reach.
- No secrets in the repository or in image layers; credentials enter at runtime only (C6).
- Nothing durable accumulates on the pair's components except what the confirmed objective names — until the product ships.
- **Headless is binding.** Nothing may assume a physical display or a local seat on any host after genesis. A change that needs one is a defect.
