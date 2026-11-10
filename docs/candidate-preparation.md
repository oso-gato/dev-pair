# Local candidate preparation (A12.12(1), partial)

This is an offline preparation tool, not a working installation or a Distrobox
launcher. Python 3 and Git suffice. No image has been built here. No Fedora,
Podman, Distrobox, SELinux, authentication or remote-model acceptance is claimed.
`launch` always exits 2. `plan` prints a **blocked proposal**, including Codex argv,
without running it. Both maintenance-on-host and development-inside-DevBox are
represented. This deliberately leaves A12.12(1) partially accepted.

## Exercise the local path

Run from the repository root, using a fresh output directory:

```sh
python3 -m unittest discover -s tests -v
python3 tests/make_fixture.py /tmp/dev-pair-inputs-fixture
python3 tools/candidate.py prepare --fixture --manifest /tmp/dev-pair-inputs-fixture/inputs.fixture.json --binary /tmp/dev-pair-inputs-fixture/codex.fixture --output /tmp/dev-pair-context-fixture
python3 tools/candidate.py plan --fixture --manifest /tmp/dev-pair-inputs-fixture/inputs.fixture.json --model gpt-6.1-sol --effort high
python3 tools/candidate.py plan --fixture --manifest /tmp/dev-pair-inputs-fixture/inputs.fixture.json --model gpt-6.1-sol --effort high --resume 12345678-1234-1234-1234-123456789abc
python3 tools/candidate.py launch
```

The final command **must fail** with exit 2. Fixture version `0.0.0`, fake Fedora
digest and nonexecutable bytes are explicitly labelled, require `--fixture` and
produce `fixture-not-admissible` outputs. They are never production pins. Repeat
with a fresh directory or retain existing evidence; preparation refuses overwrite.
To inspect the other placement, change the fixture manifest's `role` to
`maintenance` and run `plan` again. The tests exercise both roles.

The tests cover stable context bytes, corrupted binary rejection before writes,
fixture admission, missing/unknown inputs, unsupported providers, missing pins,
unsafe/overlapping mounts, overwrite protection, exact resume identity,
model/effort mismatch and unconditional execution refusal. Non-fixture regression
tests use isolated real Git repositories to check matching source, mismatched
source, unavailable commits and absent source files. Synthetic, explicitly
untrusted metadata and ELF headers test the non-fixture path, including matching
hashes on wrong-architecture/non-ELF bytes and placeholder rejection; they do not
establish upstream acceptance. These are local function/CLI checks, not container
boundary tests.

## Supply real inputs without inventing pins

Create a private JSON manifest with the same **exact** fields as the fixture,
replacing every fixture identity. Do not commit credentials or private evidence.
Set `kind` to `operator-verified-inputs`. Required evidence and identities:

- `source_sha`: the exact Git commit containing this preparation implementation.
  Preparation checks its own bytes against `git show <SHA>:tools/candidate.py`.
  Record the final reviewed source revision in the host request separately.
- `standards_sha`: `08fc080dc8463a16e7ef753eefdefd98463b76b9`.
- `fedora.image`: `registry.fedoraproject.org/fedora:45@sha256:<actual digest>`.
  An authorized operator must resolve the official Fedora 45 x86_64 manifest,
  inspect `/etc/os-release`/architecture, and record registry inspection and
  available signature/attestation results in `fedora.verification` (evidence
  reference, not a bare assertion). No digest has been resolved in this work.
- `codex.version`: actual official **stable** numeric version, not the local
  `0.167.0-alpha.4` executor CLI. `codex.source` must be the matching official
  `https://github.com/openai/codex/releases/download/rust-v<VERSION>/codex-x86_64-unknown-linux-musl.tar.gz`.
  Acquire and verify it outside this tool using upstream's strongest available
  signature/attestation/checksum evidence; safely extract the x86_64 musl binary.
  Record the release/archive identity, verification method/results and binary
  version evidence in `codex.verification`; put the extracted binary's actual
  SHA256 in `codex.sha256`. Disclose any unavailable stronger provenance.
- `role`: `maintenance` or `development`; `provider`: `gptbox`; explicit `model`
  and `effort` for this job. `agentbox` resolves to this recorded provider.
  There is no Claude fallback or implicit resume/latest model. Changed selection
  requires a separate explicit migration; this tool offers no migration command.
- `mounts`: four distinct, nonoverlapping canonical source leaves under
  `/var/lib/dev-pair/jobs/<job>/`: `workspace`, `state`, `cache`, `credentials`.
  For actual use the authorized executor must provision and inspect ownership,
  symlinks, mount topology and role-specific credential scope. Path syntax does
  not prove permissions or that a directory's contents are safe.

Then use the same `prepare` command **without** `--fixture`, replacing the paths.
It checks the local binary SHA256, ELF architecture and recorded source bytes;
it does **not** contact a registry, authenticate upstream evidence, execute the
binary to verify its reported version, or attest that operator assertions are
true. Missing identities/evidence, floating images, prereleases and unknown
fields fail. Keep evidence review as a separate required admission gate. A
correctly formatted manifest is not an admitted release.

The generated `Containerfile` uses an exact Fedora digest and copies only the
verified local binary at `/opt/dev-pair/bin/codex`; it performs no network package
installation. `inputs.json` records the inputs; `candidate.json` hashes each
context file and a canonical file-hash manifest. Identical bytes/inputs produce
identical contexts. The context hash is **not an OCI image digest** and does not
promise bit-identical image metadata across builders. The recipe is a starting
candidate: Distrobox initialization dependencies/user/home integration still need
isolated, pinned assembly and compatibility testing. Do not fix that by installing
packages or modifying hooks in a live parent or admitted agent container.

## Storage and invocation boundary

Installed OS/configuration, Codex and any eventual entrypoints/plugins must be
protected by a read-only root, with no mount shadowing `/usr`, `/etc`, `/bin`,
`/lib*` or `/opt/dev-pair`. The plan fixes mount destinations; arbitrary destinations,
extra mounts, sockets, capabilities and host bridges are unsupported. It proposes
`/work/job`, `/state/codex`, `/cache/job` as writable, credentials at
`/run/secrets/codex` read-only, plus isolated `/state/home`, private `/tmp` and
`/run`. Those latter runtime tmpfs/ownership details remain to be implemented.
Role/job-specific durable state must survive replacement. Caches contain no
secrets; resource ceilings, idle retention and active-use protection must be
configured before execution; this slice implements no cleanup controller.

No command here creates mounts or enforces these boundaries. Normal Distrobox
integration shares parent resources/home and can expose host-exec facilities.
Neither sanitizing mount strings nor proposing a read-only root makes that safe.
There is deliberately no emitted `distrobox create/enter` command that might be
mistaken for a supported confined launch. Both placements remain blocked until a
measured compatible adapter exists; privileged mode, `label=disable`, outer-host
sockets and unrestricted host-spawn are not proposed workarounds.

The argv proposal runs `/opt/dev-pair/bin/codex exec`, or `exec resume <UUID>`,
with explicit model, `model_reasoning_effort` and OpenAI provider; prompt arrives
on stdin and cwd is `/work/job`. It uses no shell interpolation, arbitrary user
flags or `--last`. The flag shape was inspected against the local alpha CLI's
help **only**. The pinned stable binary's own help/schema must confirm it before
use. The plan is not unattended launch proof. In particular Codex writable-home
configuration, skills, MCP/hooks and authentication loading need a tested immutable
configuration policy and a constrained credential adapter; do not copy arbitrary
parent home/configuration into CODEX_HOME or treat workspace instructions as
permission. No auth secret value is included in the plan.

## Candidate-bound Fedora validation request

Dispatch two dependent executor requests. Required clauses: A1, A2.4, A3,
A4, A5, A10.1/A10.4–A10.6, R5, R7 (including R7.14–R7.16) and R11.1/R11.6.
The current source commit is supplied by Git handoff, never a moving branch.
No A3 ticket bus is implemented by this document.

- **A12.12(1)-Fedora-build** is initially bound to the exact reviewed source/test
  SHA, real input manifest and context hash, recipe revision, official upstream
  verification evidence, base/parent image identities, target/executor identity,
  approved build effects, time/disk/network/spending limits and cleanup authority.
  It performs steps 1–2 below. A candidate image digest/build log is an **output**
  of this request, not a prerequisite. The executor returns the context identity,
  output image digest, build log and recipe revision, or a candidate-bound blocker.
- **A12.12(1)-Fedora-placements** follows only after a successful build result.
  It carries the same source/test/context identities plus that result's exact
  built image digest and build log, separately identified DevBox/parent digests,
  role/job credential references and explicit runtime-test effects/limits/cleanup
  authority. It performs steps 3–8 against that image. A missing/mismatched image
  digest or unverified changed candidate returns **blocked**, not pass.

Fixtures are inadmissible to either request. A changed recipe, initialization or
binary produces a new context and build result before runtime validation.

Use only a designated disposable Fedora Cloud 45 VPS and separately identified
DevBox candidate. Requested effects are limited to building/inspecting disposable
candidates and job-owned test resources; no deployed replacement, host-policy
change, live package install, paid API call or expanded privilege follows from
this procedure. Model/auth probes require explicit host credentials and budget.
The operator recovery path and known working artifacts must remain available.

1. Record Fedora image/version, kernel, rootless UID/subuid/subgid mappings,
   Podman/Distrobox versions and SELinux enforcing state; bind initial logs to
   the source/context hash and base/parent image identities. Check stable binary version and actual manifest
   architecture, upstream verification and the source/standards pins.
2. Build the exact prepared context in isolated storage, return the output image
   digest and build log bound to the source/context/recipe identities, and record
   reproducibility limits and initialization requirements. Prepare any Distrobox
   integration in a separate versioned candidate, then review/retest that changed
   candidate. If normal initialization needs mutable code or excessive privileges,
   return the exact error and scoped design question; do not grant an exception.
3. For host → maintenance gptbox and host → DevBox → development gptbox separately,
   inspect actual user/mount/PID/network namespaces, UID maps, storage driver,
   rootfs/mount flags, capabilities, SELinux labels/AVCs and lifecycle. Compare
   intended mounts with `podman inspect` and `/proc/self/mountinfo` inside the
   candidates. Verify rootless nested storage survives the selected lifecycle
   without writing parent code or requiring outer-engine sockets.
4. As the actual agent user, attempt isolated test-file creation in `/usr`, `/etc`,
   `/opt/dev-pair/bin` and parent code trees: expect permission/read-only failures
   and unchanged hashes. Attempt symlink/mount shadowing and executable/home
   config/plugin injection: expect rejection. Write/read/checkpoint inside each
   declared workspace/state/cache and private tmpfs: expect success. Credential
   mounts must be readable only by their intended job/role and unwritable; never
   print credential content. A writable credentials/state loader that can execute
   untracked hooks is a failure.
5. Inspect actual mounts/environment and test absence of the outer-host Podman
   socket, host filesystem administration path, shared parent home, host-exec/
   host-spawn bridge, dangerous capabilities and role-crossing credentials.
   Demonstrate forbidden host operation denial with a harmless scoped probe.
   Maintenance gets no unrestricted bridge either; its future controlled host
   interface is outside this slice. Inspect host administration exposure for
   R7.16: private administrative services, key-only shell authentication and no
   direct root login after bootstrap. Return a mismatch as a blocker; this test
   request does not authorize changing host access policy. Record expected versus
   actual per denial.
6. For R7.14, use no graphical seat and unset display variables; verify the
   documented headless installation/inspection/authentication/launch/recovery
   route with separately authorized account/budget. Verify supported unattended
   Codex authentication, discovered/available explicit model
   and effort, and the pinned CLI invocation/configuration policy. Capture actual
   process argv and nonsecret service evidence; distinguish requested selection
   from provider-attested metadata. Run a tiny job that writes a checkpoint only
   in the workspace, retain its returned exact session UUID, interrupt/restart
   and resume that identity with the same model/effort to observable further work.
   Reject expired auth, unavailable model/provider, missing UUID and mismatched
   model without substitution. Never count process start or a mock as recovery.
7. Separately exercise R7.15 without stopping the worker: disconnect/reconnect
   the client, change its network and sleep/wake the client device through an
   authorized test route. Observe continued server-side work during detachment
   using independent timestamped progress/checkpoint evidence. Reattach to the
   same job/session UUID and verify preserved context, uncommitted work, pending
   requests and further progress without a manual worker nudge or duplicated
   effects. A worker process interruption/restart in step 6 does not satisfy this
   client-continuity check. If the client test route is unavailable, return blocked.
8. Return pass/fail/blocked per check and placement, exact candidate/test/artifact
   IDs, environment identity, exit codes, nonsecret diagnostics, effects and
   cleanup status. Preserve logs/checkpoints/uncommitted work; remove only the
   request's disposable containers/storage after confirming none is active.
   Retest changed candidates from the affected step. Full all-session renewal,
   nightly scheduling, job bus and deployment are later slices.

Current blocker: this Debian executor has no Podman/Distrobox, designated Fedora
target, host auth or paid execution budget. Host validation and independent
candidate review are separate acceptance gates; local tests cannot close them.
