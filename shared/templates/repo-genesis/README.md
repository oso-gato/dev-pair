# Repo genesis — the standard project structure

How the pair starts every new repository. The trigger is the maintainer declaring a new development repo. One interactive initiation session co-creates and confirms the objective, captures the build principles by reference, and decides any project-specific constraints. Then genesis: instantiate this template, and the loop takes over — no second interaction.

## Procedure

1. Create the repository — private by default, the pair's GitHub App installed.
2. Instantiate the skeleton for the declared runtime shape (below).
3. `OBJECTIVE.md` — the confirmed objective, locked verbatim. Maintainer-merge-only from that moment.
4. `constitution.md` — the universal principles applied by reference, plus the project-specific constraints from the initiation session. Captured, never re-dictated — a re-dictation is a fork.
5. `AGENTS.md` — from template. Fill build/test commands and boundaries as they come into existence.
6. `ARCHITECTURE.md`, `CHANGELOG.md`, `README.md` — from templates, near-empty; they grow mutable-on-fact and per notable change.
7. `decisions/0001-genesis.md` — the genesis ADR: the shape chosen, the constraints captured, anything decided at initiation that binds the future.
8. `specs/` — starts empty. The first ticket creates `specs/<NNN-slug>/` (NNN = the GitHub issue number) from the templates in [specs/](specs/).

Every template here is `*.template.md`: copy, drop the `.template`, fill the `{{placeholders}}`. The ticket templates under [specs/](specs/) are vendored from GitHub Spec Kit verbatim — provenance and pin in [VENDORED.md](VENDORED.md).

## The three shapes

The documentation surfaces above are invariant (constitution P13). Only the component tree varies:

### 1. Single artifact (one container, one program)

```
<repo>/
├── <standing surfaces>
├── Containerfile        the artifact, if containerised
└── src/                 one source tree — no component split, no shared/
```

`shared/` is forbidden here: with one component there is nothing to share.

### 2. Host + container (a dev pair)

```
<repo>/
├── <standing surfaces>
├── host/                everything that provisions, converges, or operates the host
├── dev-container/       everything that builds or operates the dev container
└── shared/              contracts and templates both sides genuinely use
```

### 3. Container swarm (containers working together)

```
<repo>/
├── <standing surfaces>
├── <container-a>/       one folder per container: its Containerfile, config, code
├── <container-b>/
└── shared/              only code and contracts genuinely shared between containers
```

For shapes 2 and 3: `shared/` exists only for genuinely shared content — nothing lands there to escape a boundary. Every file belongs unambiguously to exactly one component; there is no fourth place.

## What each surface is for

| Surface | Content | Authority |
|---|---|---|
| `OBJECTIVE.md` | WHY — the confirmed objective, outcomes, boundaries | locked; maintainer-merge-only |
| `constitution.md` | HOW — universal principles by reference + project constraints | locked; maintainer-merge-only |
| `AGENTS.md` | session-loaded operating manual: method, commands, boundaries | agent-maintained |
| `ARCHITECTURE.md` | current-state map — updated in the same change that alters a fact | agent-owned; never a conformance target |
| `decisions/` | ADRs — decisions binding beyond one ticket; append-only, superseded not edited | agent-proposed |
| `specs/<NNN-slug>/` | per-ticket spec, plan, tasks — frozen at ship; a change is a new ticket | working record |
| `CHANGELOG.md` | curated notable changes + incidents, newest first | agent-maintained |
| `README.md` | human orientation | agent-maintained |
