# Build the development gptbox image

The development release uses its own signed-input context, rootless image store and assembly stage. The existing maintenance bootstrap still accepts maintenance inputs. This command creates a candidate for the nested DevBox probe described in A2.4 and A10. It does not start the nested agent or allocate a job.

## Prepare the signed inputs

From the clean, reviewed source checkout, use the verified public input cache and pinned Distrobox checkout. The public helper checks the original Codex signature and the signed Fedora release again and emits a source-bound development context.

```sh
python3 tools/public_inputs.py build --role development \
  --cache "$PUBLIC_INPUT_CACHE" \
  --distrobox-source "$PINNED_DISTROBOX_CHECKOUT" \
  --output "$DEVELOPMENT_HANDOFF"
```

Keep the reported manifest and context SHA-256 values in the trusted handoff. On the designated builder, transfer `manifest.json` and `development-inputs.tar.gz` and extract the bundle to a new protected path. Use an absolute staging path controlled by root on the builder.

```sh
sudo python3 tools/public_inputs.py extract --role development \
  --payload "$DEVELOPMENT_HANDOFF/development-inputs.tar.gz" \
  --manifest "$DEVELOPMENT_HANDOFF/manifest.json" \
  --expected-manifest-sha256 "$TRUSTED_MANIFEST_SHA256" \
  --output "$PROTECTED_STAGING"
```

## Prepare a fresh builder

Use an authorized disposable Fedora 44 x86_64 guest with enforcing SELinux. Run
the command from the protected extraction above. It accepts the development
context and the exact extracted source and Distrobox inputs. Supply the allowed
temporary bootstrap SSH CIDR and a disposable `core` password in a protected
root-owned file. The caller owns removal of this file.

```sh
sudo python3 -B "$PROTECTED_STAGING/dev-pair/tools/gptbox.py" prepare-development-host --apply \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --context "$PROTECTED_STAGING/context" \
  --expected-context-sha256 "$TRUSTED_CONTEXT_SHA256" \
  --distrobox-source "$PROTECTED_STAGING/distrobox" \
  --bootstrap-source "$TEMPORARY_BOOTSTRAP_CIDR" \
  --password-file "$DISPOSABLE_CORE_PASSWORD_FILE"
```

The command runs the existing host prerequisites under the 600-second native
preparation budget. When Git is absent it installs only the signed Fedora
`git-core` prerequisite before verifying the exact source and upstream scripts.
It publishes `/var/lib/dev-pair/bootstrap/host-ready.json` after successful
convergence. Image assembly is a separate command. An interrupted preparation requires
`--retry` with the same inputs and CIDRs. A retry reconciles recorded owned
native units before host effects, with at most two preparation attempts. Use a
fresh guest for a different target. The no-`--apply` preview checks the protected
inputs and reports whether the Git-dependent checks are complete.

## Assemble and export

Use an authorized enforcing Fedora 44 x86_64 builder with protected bootstrap readiness evidence, rootless Podman and signed bootstrap tooling. The producer checks the recorded host package inventory and the live `dp-maint` identity, private group, subordinate ranges and denied sudo policy before using that account. A builder prepared with `prepare-development-host` uses that exact development target. A builder provisioned through the existing maintenance bootstrap may have a different source and context. The executor has its own development graph and runroot. It needs signed Fedora package repository access for construction and enough scratch capacity for the candidate and its export. The release archive is limited to 2 GiB and the archive verifier permits up to 8 GiB of expanded layer data. The export checks free capacity for its work files and the existing eight GiB reserve.

```sh
sudo python3 "$PROTECTED_STAGING/dev-pair/tools/gptbox.py" build-development --apply \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --context "$PROTECTED_STAGING/context" \
  --expected-context-sha256 "$TRUSTED_CONTEXT_SHA256" \
  --distrobox-source "$PROTECTED_STAGING/distrobox"
```

Without `--apply`, the command verifies the target and inputs. An interrupted target requires `--retry`, with at most two assembly attempts. If validated files are already waiting for publication, a retry checks them against the protected receipt, reconciles any unfinished cleanup and publishes the same files. The protected records and diagnostics are under `/var/lib/dev-pair/bootstrap/gptbox-development/<context-sha256>/`.

The builder runs pinned `distrobox-init`, checks the finalizer's evidence, and commits the stopped container. It reads the raw input and seal files from a separate never-started container at that full image ID. The export is saved by immutable config ID and checked with the same OCI graph validator that DevBox runs before import. The archive and `inner.json` become visible together under `/var/lib/dev-pair/artifacts/gptbox-development/<context-sha256>/release/` after verification and exact container cleanup. Later calls check the published files against the protected publication receipt before returning their paths.

Use `inner.json` as the nested manifest's `inner` value and place `development.oci.tar` at the job's declared input path. The designated target supplies the job identity, storage ceiling, SELinux categories and separately verified outer image. Compute and transport the completed manifest hash through the trusted handoff. Run `tools/devbox.py run` on enforcing Fedora 44 to validate the actual nested entry and restart; the producer's local component tests exercise only a synthetic engine.
