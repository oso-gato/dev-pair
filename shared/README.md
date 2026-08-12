# shared/

Versioned atomic contracts between host and dev-container, and only what both
artifacts genuinely share.

Every contract here is versioned; producers and consumers tolerate a stagger of
one version. Nothing lands in `shared/` to escape the `host/` / `dev-container/`
boundary — if only one side uses it, it belongs to that side.

## contracts/

The machine-readable grammars of the ticket bus, one file per grammar per
version (`<name>.v<N>.schema.json`), with one valid instance each in
`examples/`. The law (P7, stated once in `00-SPEC.md` Part P):

- A consumer **fail-safe refuses** an unknown grammar, version, or field —
  it never mis-parses.
- A new producer emission is **gated off until the consumer that understands it
  is confirmed live**.
- A contract change lands **atomically — producer and consumer in one change**.

Tests: `python3 shared/contracts/test_contracts.py` (needs `python3-jsonschema`,
Fedora dnf, provenance L1). Every grammar change ships its test rows (P8).
