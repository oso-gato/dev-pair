# Authenticated local Fedora base

`tools/fedora_oci.py` authenticates the official Fedora44-1.7 Base Generic OCI
archive with the adopted Fedora44 key. This April release replaces the old
November registry selection; its signature never authenticates that old digest.
No native import, signed-package refresh, container acceptance or deployment is
established by the local parser/crypto tests.

The three fixed public cache files are `fedora.oci.tar.xz`, `fedora-CHECKSUM` and
`fedora-key`. Source-controlled URLs, lengths and hashes are in `ARTIFACTS`.
The archive is70,170,200 bytes, SHA256
`75200f5752a74a21a616ca9a75e25beb594e2e117a0195c54f87c0b3e3974d1b`.
Its CHECKSUM signature must yield exactly fingerprint
`36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. GnuPG uses a private keyring,
no options, automatic key retrieval or agent startup. Original signed key and
CHECKSUM bytes remain in the context; bounded successful signature status and
OCI proof remain in `evidence/fedora-verification.json` and producer verification
storage. Failed downstream packaging preserves successful verification evidence.

The full compressed snapshot is checked before decoding. An80MiB outer tar,
16 raw headers,256KiB metadata and192MiB inner gzip ceiling bound inspection.
Every raw tar header is checked before Python can consume hidden GNU/PAX records;
links, devices, extensions, duplicate/unknown paths, missing graph members,
invalid descriptors, bad hashes/platform/diff ID and nonzero tails reject.
The rootfs stream is hashed, never extracted by this helper; legitimate rootfs
symlinks are left to the container importer. A120s verification deadline covers
capture/crypto/stream checks; a separate120s import deadline is clipped by callers'
existing phase/native limits.

Public-input manifest version2 binds the provenance object and all files.
Real candidate creation requires `--fedora-inputs` and verifies signatures/graph.
Initial Python-only context admission checks the same captured bytes against
these reviewed exact artifact pins, avoiding a GPG prerequisite before initial
host package provisioning. Actual import verifies the full chain again.
The separate trusted manifest hash and filesystem/controller source boundary
remain necessary; caller JSON is not authentication.

Candidate, bootstrap, maintenance adapter and CI-tooling recipes use only local
`sha256:9eaa56a730854ae53f57e58c16179d09c2fa1f4157a5d69ccb39647e33c6464d`
and `--pull=never`. The archive's `fedora:44` annotation is never a FROM or remote
lookup. Podman5.8.1 source supports OCI archive load; no runtime compatibility is
assumed. Load must inspect the exact config ID, manifest metadata/type, platform
and diff ID, then save back OCI and hash/validate every actual exported descriptor/blob.
Podman storage exports uncompressed layers and the default OCI destination
recompresses them; original gzip/manifest equality is therefore not assumed.
The derived gzip and manifest identities are recorded separately, requiring exact
source config bytes and the complete original uncompressed rootfs diff stream.
Only this gzip representation derivation is supported; changed content, zstd or
uncompressed exports block. Transport tar directory metadata can differ. Save alone gets a192MiB native per-file `prlimit` ceiling, admitting the
188,336,128-byte immediately unlinked storage spool. Final output admission
remains80MiB before capture/decoding; package/image writes retain their limits.
No global signature-policy relaxation, registry fallback or broad prune occurs.

Signed Fedora/updates RPM refresh is explicit in every disposable candidate's
existing540s inner package command, inside600s image work. Resulting package
inventories are recorded. Live repositories are authenticated package inputs,
not a reproducible frozen repository snapshot. Installed runtimes are immutable.

The192MiB compressed,384MiB expanded and1536MiB producer-work ceilings remain.
A160MiB verification reserve is charged while the producer/candidate child runs.
At import, retained source70.2MB, private snapshot70.2MB, plain tar70.9MB,
save-back<=80MiB and captured save-back<=80MiB may coexist, plus uncompressed
rootfs188.3MB, image-store/candidate layers and driver overhead. These are size
observations, not reserved storage or quotas; existing guest/CI reserve and hard
limits still govern. A failed Podman load is nontransactional and can retain
unreferenced store data. Only private owned temporary files are automatically
removed; no rollback or crash-finally claim is made. Uncertain import/derivation,
capacity, package freshness, cleanup or native capability blocks acceptance.

Repair ownership/accounting: verification temporaries now live inside the
producer work tree, native context artifact stage or CI owned scratch. Image
copying gets a separate0700 writable leaf, while verified source remains
controller-owned under0755 parents with0444 files. An exclusive0600 ownership
record binds the exact leaf/parent inode and actor. A retry reconciles the exact
owned executor before reclaiming only that proven leaf; foreign/unproven or
uncertain workers preserve it. SIGKILL may retain this recorded leaf for later
reconciliation; no finally-after-crash claim is made.

Every actual image operation receives explicit TMPDIR after environment clearing.
Podman4.9.3/5.8.1 tagged source routes TMPDIR to BigFilesTemporaryDir; --tmpdir
alone is not used as proof. CI uses a fixed root-side timeout and preserves scratch
if an image-copy worker's termination is uncertain. Its live measurement charges
an additional192MiB for the unlinked spool; du alone cannot observe it. The lease
requires the existing free reserve plus768MiB for bounded coexisting base input,
copy layout, output/capture and spool before starting. Guest8GiB reserve and
CI4GiB-overhead/3GiB-host ceilings remain unchanged. Driver/candidate peaks and
actual native cleanup still require measured acceptance.

The actual executing public_inputs.py dependency is included in exact source
and protection checks. CI seeds the payload cache from its already verified
Fedora artifact copies; stale bytes reject without overwrite or network fallback.
No artifact is downloaded twice merely to transfer the same authenticated input.

Interrupted-work recovery also records a controller-owned0755
`verification-work` ancestor. Its random verification children stay0700 until
signature/graph verification succeeds; only then is the public input child
traversable with0444 source bytes. The actor's0700 `image-copy` leaf remains
separate. After the exact executor is reconciled, retry reclaims both proven
leases before checking capacity for a new peak. The exhausted-attempt
cleanup-only route reaches the same recovery without starting another build.
Unknown/foreign leases and legacy unrecorded siblings remain preserved; names
alone never authorize deletion. This supplies next-recovery behavior, not a
finally-after-SIGKILL guarantee or a claim that native helper cleanup is proven.
