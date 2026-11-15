# Verified public maintenance input payload

[public_inputs.py](../tools/public_inputs.py) fetches and verifies the exact public
Codex0.169.0/Cosign3.1.4/Distrobox1.8.2.5 inputs, creates a current-HEAD
maintenance candidate context using the existing preparation tool, and packages
it with clean public Git objects and original signature evidence. It does not
change CI, VM budgets, guest preparation, production bootstrap or runtime
admission. No login, account, model, VPS or deployment operation is included.

The producer must execute from a committed clean checkout; its own bytes must
match HEAD. Output/cache paths must be outside that checkout, in operator-owned
storage. A future CI integration can transfer the compressed payload without
placing another uncompressed 294MB binary into its ISO. The helper still needs
bounded staging space; it does not prove the present CI overhead allowance fits.

## Fetch, build and transfer

```sh
# Public HTTPS/Git downloads only; creates a new directory, never overwrites.
python3 tools/public_inputs.py fetch --output /YOUR/PRIVATE/PUBLIC-INPUT-CACHE

# Reuses those files; the Distrobox repository must have its pinned commit at HEAD.
python3 tools/public_inputs.py build --cache /YOUR/PRIVATE/PUBLIC-INPUT-CACHE \
  --distrobox-source /YOUR/PRIVATE/PUBLIC-INPUT-CACHE/distrobox \
  --output /YOUR/PRIVATE/MAINTENANCE-HANDOFF

# Record manifest_sha256 separately through a trusted controller handoff.
# Transfer manifest.json and maintenance-inputs.tar.gz as public data.
python3 tools/public_inputs.py extract \
  --manifest /TRANSFER/manifest.json \
  --payload /TRANSFER/maintenance-inputs.tar.gz \
  --expected-manifest-sha256 SEPARATELY_TRUSTED_MANIFEST_SHA256 \
  --output /NEW/PROTECTED/STAGING
```

`build` returns source, context, payload and manifest SHA256 identities. The strict
version-1 manifest records each regular file's size/hash, payload size/hash,
standards pin and public upstream identities. Unknown fields/versions, duplicate
fields/paths and unsafe metadata fail closed. The consumer requires an independently
supplied manifest digest; accepting it from the same untrusted transport is not
authentication. Extraction establishes transport integrity under that controller
boundary, not remote authentication, release approval or runtime acceptance. The
later bootstrap/adapter must still perform their actual context/source checks.

No private standards text, runner environment, credential store, runner Git
configuration, hooks, remotes, alternates or unrelated history is copied. For each
repository the helper packs only the selected commit and its tree/blob objects,
declares that commit as a shallow boundary, installs a fixed minimal configuration
and checks it using real `git fsck`. Source files and required Git objects are
available before guest Git installation, so existing bootstrap verification can
run immediately after its signed Git prerequisite. This is public data staging,
not permission to execute an arbitrary uploaded script.

## Provenance and limits

The fixed official archive SHA256 is
`9af4d751fce183faedea629437d5252dbf458eeb04130cf4f97be844621ea985`
(117805733 bytes). Its sole allowed tar member is the regular extracted binary,
294277432 bytes, SHA256
`b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b`.
The original 8489-byte Sigstore bundle remains unchanged in the payload, SHA256
`3146e0f44e249125606667091d5de4cdc04abb8089ae329546c5d870ad822c91`.

Before execution, Cosign3.1.4 is checked against its exact 145688404-byte size and
official-release SHA256
`424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`.
Its bootstrap trust is official HTTPS plus that pinned digest; no independent
Cosign signature verification is claimed. Actual `verify-blob` requires exact
OpenAI release workflow identity, GitHub issuer, repository, tag and source
`d32063f96c2dff1dc96af839b3952abb6acfeda4`, with default certificate/SCT/transparency
checks intact. No insecure-ignore flags or fixture fallback exist. Failure
prevents publication. Original bundle and successful output remain in the handoff.

Legacy-bundle verification can need public Sigstore trust metadata even with
cached artifacts. A clean HOME carries only approved inherited proxy/CA variables
when networking is needed; their values are never printed or serialized. An
unavailable trust endpoint blocks verification. Prior `Verified OK` text or parsed
certificate claims cannot supply a new pass. Distrobox is pinned to
`40c3cd724faa434aeb0a23e28776665b92de68bd`. Fedora's OCI digest is pinned
separately; its signature gap remains distinct from signed Cloud-image provenance.

Fetch/build each have a 600-second wall deadline. Downloads enforce exact lengths,
digests and HTTPS redirects. Fixed child commands have 120-second deadlines,
bounded output and native file-size limits; timeout kills their process group.
Build staging is checked against 1536MiB, each clean repository against 32MiB,
compressed payload against 192MiB, and expanded files against 384MiB/2048 files.
Extraction has a 120-second deadline and a bounded raw-tar expansion before member
parsing. Only declared regular files are written; links, devices, sparse/PAX
records, traversal, duplicates and trailing nonzero tar data are rejected.
Failure removes only the newly created owned output; success removes temporary
copies while preserving the handoff/evidence. Original caches remain intact.

Run `python3 -m unittest discover -s tests -p test_public_inputs.py -v` for real
Git sanitization/history exclusion, filesystem/hash/archive rejection, trusted
manifest transfer and process-limit tests. Parser fixtures are explicitly
non-admissible and establish no signatures or Fedora behavior. Actual cached-input
exercise evidence belongs in the exact-candidate handoff; local success is not
hosted-CI, authentication or maintenance-runtime acceptance.
