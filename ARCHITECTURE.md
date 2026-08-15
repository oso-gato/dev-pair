# ARCHITECTURE.md — current state

Agent-owned map of the system as built. Mutable-on-fact: updated in the same change that alters a fact. Never a conformance target — this map chases the code, not the reverse.

## Current state (2026-08-16)

This repository holds the governing documents only — spec, constitution, and the documentation surfaces. The component tree (`host/`, `dev-container/`, `shared/`) is not yet rebuilt; it returns as code lands under the constitution.

## Pairs

- `erebus` — VPS pair (Hostinger KVM 4, stock Fedora Cloud, idempotent converger). Facts: homelab-root `environments/erebus.md`.
- `strix` — bare-metal pair (Minisforum MS-S1 MAX, `strix-ms-s1-bootc` image, rebase with rollback). Facts: homelab-root `environments/strix.md`.

## Components

- (none built yet)
