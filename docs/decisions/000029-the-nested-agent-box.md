# 000029 — What the nested agent box costs, including one SELinux relaxation

- status: accepted
- date: 2026-08-18

## Problem

C8 puts every agent inside a disposable box on its component. On the host that is straightforward: the component is an immutable Fedora, and `claudebox` is a distrobox layer on it. On the dev-container it is not, because the dev-container is itself a rootless container — so the box becomes a distrobox inside a rootless container, needing nested user namespaces.

The author of the erebus work built exactly that and then said, in session, that it was likely fragile or outright broken. The concern was honest and untested, and the maintainer's response was to authorise a narrow consult of a repository where the same stack is known to run.

It runs. It also does not run by default, and none of what makes it work is guessable from the failure messages: a missing capability surfaces as `crun: sethostname: Operation not permitted`, and a mis-sized subordinate range surfaces as `newuidmap: write to uid_map failed`. Both read as podman bugs rather than as missing declarations.

## Decision

The nested box is kept, and everything it needs is declared explicitly with its reason attached, so that none of it reads later as an unexplained loosening someone should tidy away.

**`SYS_ADMIN`.** `distrobox enter` calls `sethostname()` to name the inner box. Podman's default seccomp profile gates that syscall behind `CAP_SYS_ADMIN`, and seccomp is not namespace-aware, so the capability is required even though nothing here touches the host. The full default seccomp profile stays active; the alternative would have been forking the profile, which is a larger and less legible change.

**`/dev/fuse`.** fuse-overlayfs is the storage driver nested rootless podman uses.

**Subordinate ID ranges sized to the outer map.** `core:10000:55000`, not the host-side habit of `100000:65536`. The container's own uid 1000 plus the range must fit inside the outer rootless 65536-ID map, and a range that overflows it cannot be written at all. This corrected a real defect: the erebus work shipped `100000:65536`, which would have failed on the first assemble.

**File capabilities on `newuidmap` and `newgidmap`, set at build and re-verified at boot.** shadow-utils' own scriptlet sets them, but the `security.capability` xattr does not reliably survive layer commits in every podman storage configuration. Setting them in our layer is the first defence and checking them in the component's init is the second, because the failure is silent until the first box assemble.

**SELinux label separation off, and this one is a genuine relaxation.** Nested rootless podman, plus fuse-overlayfs on a mounted volume, plus the passed devices, cannot run under `container_t` confinement — SELinux denies the overlay mount and the device access. With confinement on, the agent box does not assemble.

The relaxation is accepted with its boundary stated. The container is launched rootless, so every capability above is held inside an unprivileged user namespace and confers nothing on the host; the host itself stays enforcing throughout. The blast radius is bounded by the namespace rather than by SELinux, and that is a smaller guarantee than the estate holds everywhere else. It is recorded here rather than left as a line in a unit file precisely so that the next reader finds the reasoning before the flag.

## Options considered

- **Attempt a confined variant first.** Rejected, and the reason is worth stating: the estate where this stack runs has already measured the answer, and re-deriving it here would have been guesswork dressed as diligence. C5's verify-before-adopt is satisfied by checking a working implementation, not by reproducing its failures.
- **Drop the box on the dev-container and run the agent directly in the image.** Considered seriously, because the dev-container is already disposable and already rebuilt from CI, so it arguably *is* the layer C8 asks for. Rejected for now on the grounds that C8 pairs boxes by agent across a pair's components and a second agent would then have no place to go on this side. Worth revisiting if the relaxation ever becomes the blocking cost rather than an accepted one.
- **Run the dev-container rootful to sidestep the userns nesting.** Rejected outright. It would trade a bounded relaxation inside an unprivileged namespace for real host privilege, which is the wrong direction on every principle involved.

## Consequences

The dev-container's Quadlet carries `AddCapability`, `AddDevice` and `SecurityLabelDisable=true`, each with its reason inline and a pointer here. `SecurityLabelDisable` is the only line in the pair that weakens a host-level protection, and it is not to be copied to another workload without the same analysis.

The subuid defect was caught before any apply, which is the whole value of consulting a working implementation rather than shipping an untested one.

The author's original doubt was correct in substance and wrong in conclusion. Recording that is the point of a decision log: the instinct that something was untested was right, and the fix was to test it against something real rather than to reason harder about it.
