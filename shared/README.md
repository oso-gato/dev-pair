# shared/

Versioned atomic contracts between host and dev-container, and only what both
artifacts genuinely share.

Every contract here is versioned; producers and consumers tolerate a stagger of
one version. Nothing lands in `shared/` to escape the `host/` / `dev-container/`
boundary — if only one side uses it, it belongs to that side.
