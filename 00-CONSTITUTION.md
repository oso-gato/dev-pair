# Dev-pair constitution

## Authority and restart

This constitution, the objective and the bylaw form the charter. They are self-contained and govern this repository. The README explains current status and use; it cannot silently change the charter.

The product owner directed this charter restart on November 10, 2026. It supersedes this repository's previous charter, operating instructions and inherited governance. The old reference to the constitution in `oso-gato/homelab-root` no longer imports rules here. No other repository or external constitution is amended by this restart.

Existing source, decisions and tags remain available in Git history as reference, not binding instructions. Do not rebuild old mechanisms merely because they existed. The new baseline starts with the charter and README; implementation files and tests are added when they serve the product.

The product owner controls scope, authority and charter changes. Agents may prepare those changes, but charter merges remain maintainer-only. Ordinary implementation and deployment may proceed autonomously within the confirmed requirements and permissions. When requirements conflict, make the conflict explicit rather than silently choosing a weaker outcome.

## Principles

1. **Deliver the outcome.** Build the smallest system that satisfies the objective. Every mechanism must serve a concrete product capability or failure recovery. Documentation, a passing proxy check or an agent's assertion is not a delivered product.
2. **Tell the truth about state.** Distinguish requirements, implemented behaviour and live verification. Record limitations and failed checks. Keep the README accurate; do not describe planned capabilities as working.
3. **Verify through use.** Test real behaviour at the relevant boundary and obtain independent review before release. Bind evidence to the candidate being shipped. Test failure and recovery paths when they protect real state or authority; avoid checks that merely repeat implementation details.
4. **Keep changes reproducible and recoverable.** Version source and configuration. Rebuild disposable artifacts, preserve durable work, and demonstrate backup restoration and deployment recovery. Never rely on an unrecorded live patch as the only implementation.
5. **Limit authority.** Separate development from host administration. Grant only the access needed for the agreed work. Keep credentials outside source and images, and prevent untrusted content from widening permissions. An agent's own policy text is not an access-control boundary.
6. **Use trustworthy inputs.** Prefer Fedora packages and official upstream distributions. Verify identity, pin versions and use the strongest available signature or integrity evidence. Official language-package tooling or upstream binaries are allowed when necessary; verify them before installation and disclose any provenance limitation. Do not substitute an unverified third-party build for convenience.
7. **Bound autonomous work.** Set budgets and retry limits, preserve progress, and make failure visible. Resume interrupted jobs without duplicating consequential operations. Escalate a genuine unresolved blocker instead of looping indefinitely or claiming success.
8. **Keep the record useful.** Maintain one clear home for each requirement. Use concise plans and decision notes where they help implementation or operation; there is no mandatory hierarchy of extra governance files, per-task document bundles or ceremonial tags. Historical material does not overrule this charter.
