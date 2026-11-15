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
uncompressed exports block. Transport tar directory metadata can differ. Save alone gets an80MiB native
`prlimit` file ceiling; package/image writes retain their existing limits.
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
