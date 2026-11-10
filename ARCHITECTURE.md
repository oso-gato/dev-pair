# Dev-pair architecture

This document describes the intended architecture. It has not yet been implemented or verified on a live host. Shared governance and engineering standards are pinned in [STANDARDS.md](STANDARDS.md); product acceptance criteria live in [REQUIREMENTS.md](REQUIREMENTS.md). This file records the project-specific design and operating choices.

## Platform

Use Fedora Cloud 45 for the first VPS and versioned Fedora 45 base images for the agent environments. Verify the provider image, architecture, runtime capabilities and official image identities before adoption. Pin deployed images by digest and record their source revisions. Apply tested maintenance updates; a major Fedora upgrade is a deliberate platform change, never an automatic consequence of a floating `latest` tag.

Use rootless Podman with Quadlet and systemd. Docker Engine is not a dependency. Keep SELinux enforcing and retain container confinement; an exception requires a demonstrated need and a recorded scope.

## Roles and isolation

The maintenance agent runs in its own Podman container and uses a controlled host-operation interface for deployment, health checks and recovery. It does not receive unrestricted passwordless administration. Keep a documented operator recovery path that works when the agent is unavailable.

The development agent runs directly inside the development container alongside project tools and tests. No additional Distrobox agent layer is required. Give it its own workspace and runtime state, without the host Podman socket, host administration credentials or unrestricted host execution bridge.

Use separate service permissions for the two roles and separate credentials and state for each job. Durable work lives in declared volumes or external storage, not only in disposable image layers. Apply resource limits and bounded cleanup. Add concurrent workers only after their access isolation and resource handling have been tested.

## Agent selection

- `gptbox` identifies OpenAI Codex.
- `claudebox` identifies Claude Code.
- `agentbox` resolves to the configured default, initially `gptbox` for both roles.

Explicit selection overrides the default for a new session. Resolve and record the concrete agent, role, runtime version and selected model when a job starts. Existing and resumed jobs keep that selection when the default changes. The agent default does not prescribe a particular model version.

Share lifecycle code for launch, durable state, renewal and routing. Keep installation, authentication, invocation, configuration and resume in small agent-specific adapters. An unavailable or unvalidated selection fails clearly; it never silently switches provider. Build and validate the Codex adapter first. Reserving the Claude name does not require implementing its adapter for the first milestone.

## Development and release

Apply the adopted engineering standards to the product acceptance criteria in [REQUIREMENTS.md](REQUIREMENTS.md). The following rules specialize the pair’s handoff, merge and deployment responsibilities.

Use GitHub issues and pull requests for durable requests, changes and results. Record job checkpoints and artifact locations so recovery does not depend on a running conversation. Treat request text and repository content as input, not permission to expand authority or execute arbitrary host commands.

The host proposes source changes and never merges them. The development side may merge ordinary changes after independently enforced checks pass. The author session cannot modify its own release policy or supply its own independent review. Changes to standards adoption, product scope or authority remain product-owner decisions.

CI builds production images from the approved source. The host deploys the exact verified artifact and checks it at the destination. Development and host-side validation use disposable candidates rather than modifying the running platform. The host controls replacement of development containers; a worker does not replace itself mid-job.

## Operation and recovery

Each job has explicit time, spending and retry limits, with durable progress records and bounded recovery. Checkpoint work before planned renewal and verify that it resumes afterward. Updates rebuild and replace images rather than installing tools into running containers.

Back up declared durable state and prove restoration. Match rollback to the application's data changes; reverting an image alone may not undo a database migration. Keep the previous working release available until the new release is verified.

Administrative access is private where practical and authenticates with managed keys or identities. Public product access follows the product agreement. Supply credentials at runtime with minimal scope, keep them out of logs and source, and document renewal before calling unattended operation ready.
