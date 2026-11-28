# Offline nested DevBox probe

[DevBox's launcher](../tools/devbox.py) runs the A2.4/A10 development placement on an enforcing Fedora 44 runner. The managed host account `dp-dev` starts an immutable outer DevBox. Its fixed controller checks the live parent boundary, imports one digest-bound development archive into a private rootless VFS store and runs the genuinely assembled inner gptbox. It enters the same child twice across a stop and restart using the pinned upstream Distrobox script. Each entry checks the protected code and writable development data and returns `codex-cli 0.169.0`.

This source candidate covers a credential-free capability probe for R3.1, R7.10 and part of R11.6. Fedora execution and confinement evidence are pending. The probe admits no authenticated sessions, model calls, regular product jobs, network access or renewal.

## Build the outer candidate

Use the exact reviewed source and a separately verified local Fedora 44 tooling image with Podman, crun, shadow utilities, Python, libcap and SELinux utilities. The builder needs the executable upstream `distrobox-enter` from commit `40c3cd724faa434aeb0a23e28776665b92de68bd`. The [Containerfile](../runtime/devbox/Containerfile) checks the script SHA-256, builds the controller and Podman configuration into the outer image, and limits executable privilege acquisition to the two immutable namespace-mapping helpers. Installed tool provenance, image digest and build context belong in the external release record.

From the reviewed source checkout, prepare a disposable build context and build against the verified local tooling digest.

```sh
build_context="$(mktemp -d)"
cp runtime/devbox/{Containerfile,controller.py,containers.conf,enter-podman} "$build_context/"
git -C "$VERIFIED_DISTROBOX_CHECKOUT" show \
  40c3cd724faa434aeb0a23e28776665b92de68bd:distrobox-enter > "$build_context/distrobox-enter"
podman build --pull=never --network=none \
  --build-arg "TOOLING_IMAGE=$LOCAL_TOOLING_DIGEST_REFERENCE" \
  --build-arg "SOURCE_SHA=$(git rev-parse HEAD)" \
  --iidfile "$build_context/outer.iid" "$build_context"
```

The outer tooling image and built DevBox stay in the host's local `dp-dev` image store after verified transfer. The runtime resolves the full immutable image ID. The launcher's dedicated host Podman config supplies just SETUID and SETGID to the UID 1000 parent's bounding set. Podman 5.8.1 derives the nonroot effective, permitted, inheritable and ambient sets from explicit capability additions. The launcher supplies none and checks all five live sets before running the nested engine. [Podman 5.8.1 capability setup](https://github.com/containers/podman/blob/c6077f645788743258a1a749f8005b4fb3cbe533/pkg/specgen/generate/security_linux.go)

## Supply the development gptbox

The development release producer must assemble and seal its own gptbox through the existing genuine Distrobox initialization and finalizer flow in an isolated builder. It must emit these inputs to the launcher.

- The source SHA, context hash and full immutable image config ID for a development release, with the associated immutable `dev-pair.role=development`, `dev-pair.context`, `dev-pair.inputs`, `dev-pair.standards`, `dev-pair.distrobox`, `dev-pair.codex.version` and `org.opencontainers.image.revision` labels.
- The original `/usr/lib/dev-pair/gptbox/inputs.json` with `role=development` and the development source SHA, and the finalizer-generated `sealed.json` binding those input bytes, source and UID/GID 1000. Record both raw file hashes.
- The ordered OCI rootfs layer DiffIDs and one uncompressed `podman save --format oci-archive` tar of that exact image, with plain or gzip-compressed OCI layers. Record the archive SHA-256 and byte count. Before Podman loads it, the controller requires canonical OCI structural keys and verifies the exact config and ordered layer contents independently of the local image cache. It checks the imported image identity and verifies the sealed data through the exact running child.

Separate development image construction and export are an outstanding implementation dependency. A maintenance artifact has a separate role and evidence record.

## Prepare the probe inputs

Use a fresh, dedicated development probe leaf under the existing managed role paths. Allocate three exclusive outer SELinux categories and assign two of those categories to the one inner child. The allocation belongs to the designated runner and must be disjoint from other roles and jobs. Existing enforcing policy must permit the confined `container_engine_t` parent and `container_t` child transition.

| Path under `/var/lib/dev-pair/development` | Required preparation |
| --- | --- |
| `builds/<job>` | Private ext4 or XFS block filesystem mounted at its root, with capacity at or below the approved manifest ceiling and eight GiB remaining on the role filesystem. Loop storage must be fully allocated and verifiable as such. |
| `builds/<job>/graph` | Private `dp-dev` directory on that filesystem, labeled `container_file_t` at the outer category level. |
| `builds/<job>/image-copy` | Private `dp-dev` directory on the same bounded filesystem with the same outer label. Podman uses it for archive extraction. The controller checks the mounted directory and the engine's effective image-copy path before loading. |
| `builds/<job>/inputs/manifest.json` and `development.oci.tar` | Regular read-only files on that filesystem, both labeled `container_file_t` at the outer category level. Provide the manifest hash independently. |
| `workspaces/<job>`, `state/<job>`, `cache/<job>` | Separate empty private `dp-dev` directories labeled `container_file_t` at the inner category level. The existing runtime creates and removes its write probes in these directories. |
| `evidence/<job>` | The launcher establishes a private lease and exact container ownership under the existing `evidence` root. This path stays outside both containers. |

Private directories use UID/GID of host `dp-dev` and mode `0700`. The configured rootless role needs its existing subordinate IDs, systemd user runtime, and enforcing-policy support. This launcher does not provision host accounts, SELinux policy, storage or filesystems.

The closed manifest has the following shape. Substitute all placeholders, use unprefixed lowercase hex for image IDs and hashes, and use OCI `sha256:` prefixes for DiffIDs. The capacities, job and categories below are illustrative.

```json
{
  "kind": "dev-pair-development-nested-v1",
  "standards_sha": "b9d4da5d442ac48dba2e8be62d81b5bdc83690b8",
  "job": "nested-probe",
  "storage_bytes": 2147483648,
  "outer": {
    "source_sha": "<40 hex>",
    "image_id": "<64 hex>"
  },
  "inner": {
    "source_sha": "<40 hex>",
    "image_id": "<64 hex>",
    "context_sha256": "<64 hex>",
    "inputs_sha256": "<64 hex>",
    "sealed_sha256": "<64 hex>",
    "archive_sha256": "<64 hex>",
    "archive_bytes": 100000000,
    "diff_ids": ["sha256:<64 hex per layer>"]
  },
  "categories": {"outer": [10, 11, 12], "inner": [10, 11]}
}
```

## Native acceptance command

On the designated enforcing Fedora 44 runner, use the authorized managed-account executor to run this command as `dp-dev` with a sufficient remaining execution budget. Capture the output and scoped host/policy diagnostics under that runner's existing evidence limit.

```sh
python3 tools/devbox.py run \
  --manifest /var/lib/dev-pair/development/builds/nested-probe/inputs/manifest.json \
  --sha256 "$TRUSTED_DEVBOX_MANIFEST_SHA256"
```

A successful receipt includes the exact image and manifest identities, observed namespaces and mapping data, enforcing labels, confirmed outer cgroup ceilings, both distinct start identities, Distrobox probe results, and exact-owned container removal. The parent has a 600-second native lifetime and the child has a 180-second native lifetime per cycle. Host-side aggregate limits are two GiB of memory with no swap, 512 tasks and one CPU. The inner uses the private outer cgroup namespace and its aggregate limits.

SELinux checks compare the exact user, role, type and category membership. The reader accepts the kernel's single terminating NUL and either category range or list syntax.

A compatible native profile still has to demonstrate transported mapping-helper xattrs, ancestor seccomp compatibility, the composed UID/GID mappings and a real confined SELinux transition. Collect the first failed stage and applicable native AVCs before making a versioned profile correction. Full negative policy and mount-escape tests, interrupted native cleanup, quota-pressure tests and independent exact-candidate review remain open. The probe retains the verified local image store and synthetic job leaves. Retry the exact input under the same lease to reconcile an owned container; use a fresh job leaf for a different admission.

Local tests exercise the manifest and policy, failed creation and exact removal, the real lock and bounded subprocesses. They run with `python3 -m unittest discover -s tests -p 'test_devbox.py'`.
