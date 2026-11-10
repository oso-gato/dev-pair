# Dev-pair requirements

## Outcome

Dev-pair takes a product brief and delivers tested, ready-to-use software. The product owner specifies the intended outcome and constraints; the pair handles design, implementation, testing, independent review and delivery. The product owner is not required to inspect code or operate development tools.

## Product agreement

At initiation, establish the intended users, essential user journeys, acceptance criteria, delivery destination, data constraints, spending limits and permitted autonomous actions. Turn those into a short executable plan, then proceed without routine human approvals within that agreement.

Resolve ordinary implementation choices independently and report material decisions at delivery. If the requirements conflict, necessary access is unavailable, or bounded recovery cannot make progress, stop the affected work and report the blocker and a proposed resolution. Never silently weaken acceptance criteria or keep retrying without a limit.

## The pair

The host maintains the platform, manages deployment and recovery, and performs checks requiring the real host. The development environment implements and tests products in isolation. Both use Codex by default. [ARCHITECTURE.md](ARCHITECTURE.md) defines their boundaries and the agent-selection contract.

Development work must not directly administer the host. The two roles exchange durable requests and evidence so a lost terminal or restarted container does not lose the job.

## Initial scope

Build one pair on one Fedora Cloud 45 VPS with rootless Podman. Prove one small demonstrator product from brief to delivery. The demonstrator must have observable user journeys and enough persistent job or application state to prove recovery.

Concurrency, bare-metal and GPU support, additional agent adapters, and unrelated hosted applications are later work. Keep their addition possible without implementing them before the first delivery succeeds.

## Acceptance for the first pair

1. A fresh designated Fedora 45 VPS can be provisioned reproducibly. Reapplying setup preserves work and makes no unnecessary changes.
2. The default entry point starts Codex in each role with the intended permissions. Authentication works for unattended execution without credentials appearing in source, images or reports.
3. A product brief produces a working demonstrator whose agreed user journeys and relevant failure paths pass. Test evidence identifies the exact source and artifact tested.
4. A separate agent session reviews the candidate against the agreed requirements. Automated checks and independent evidence control release; the author cannot approve its own result or weaken its own gates.
5. The released product works at its agreed destination. A build, merge, image upload or successful process start alone is not delivery.
6. Interrupting a job and restarting its environment restores durable work and resumes from a verified checkpoint without duplicating consequential actions. A failed deployment recovers to a known working state. Backed-up durable data can be restored into a clean destination.
7. The product owner receives the usable address or artifact, brief instructions, acceptance evidence, remaining limitations, operating costs and recovery information in plain language.

These are acceptance requirements, not claims of current capability. The README states what has actually been built and verified.

## Continuing work

An in-scope request follows the same delivery loop under the standing product agreement. Changes to outcomes, permissions, spending or scope require the product owner's direction. Routine code review and release decisions belong to the pair within those boundaries.
