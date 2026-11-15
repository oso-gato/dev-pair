# Offline stock Codex tool fixture

`tools/codex_tools.py` drives the exact verified stock0.169.0 binary through
actual `codex exec` tool handlers using independently generated Responses SSE.
It is an acceptance component, never a production provider or job launcher.
No real model, account authentication, entitlement or runtime admission is tested.

Run with an existing pinned binary, a supplied frozen source model catalog and a
new report path:

```sh
python3 tools/codex_tools.py --binary /absolute/cached/codex \
  --catalog /absolute/cached/models.json --report /absolute/new-report.json
```

The helper snapshots/rechecks the pinned binary and reuses all nine reviewed
[codex_state checks](codex-offline-state.md), including immutable loader mounts,
strict generated managed requirements and stock SQLite/session operations.
Requirements and provider ID remain unchanged. Explicit fixture deltas are a
private loopback endpoint override, synthetic API-key mode, a frozen catalog
selecting gpt-5.5, a synthetic parent-environment canary and `--skip-git-repo-check`.
Catalog/model hashes and complete nonsecret argv delta are recorded. These are
fixture metadata, not production endpoint/catalog integrity or model availability.

The outer unprivileged user namespace maps only the existing host task identity
to UID0 for loopback setup. Namespace-only NET_ADMIN/SETPCAP/SETFCAP permit setup
and the second single-ID mapping to UID1000; SETFCAP is needed for Linux's
parent-UID0 mapping rule. Setup mappings/caps are observed. The inner worker
shares only that private network namespace, observes UID/GID1000, drops/verifies
effective/permitted/inheritable/bounding/ambient capabilities0 and sets NNP
before creating the listener or supervisor. It mounts no ambient HOME/auth/proxy
or credentials. This is a fixture identity delta, not distinct root/job ownership
acceptance. The supervisor alone gets a synthetic key; child environment is cleared.

Fourteen finite actions independently inspect product effects and unchanged
protected objects: shell positive/negative, allowed and forbidden cwd requests,
escalation/login rejection, denied connection to the live fixture, direct patch,
forbidden/partial patch, intercepted shell patch and identical valid PNG
allow/denial through direct and symlink paths. Wrong-path, unsupported-tool and
invalid-image errors cannot count as denial. Failed actions and actual partial
product effects are retained. The denied cwd request may execute confined at the
HOME fallback; its actual cwd and absolute-target denial remain visible.

Actual request tool inventories are hashed and classified from completed checks.
Unknown/unexercised surfaces block inventory closure and overall status, even when
all fourteen actions pass. In the observed direct-tool fixture, goals,
write_stdin, tool_search, request_user_input and provider-hosted web_search remain
unclosed. This is deliberately partial representative coverage; PTY/session
continuation, helper-in-script patch routes, additional permission modes, complete
loader discovery and auth/backend-dependent tools remain later gates.

The total envelope is180s with20s per action clipped to remaining time,64 private
connections/requests,256KiB bodies/lines,2MiB combined capture (64KiB reserved for
outer diagnostics),4MiB report,2GiB address space and16MiB per file. Input snapshots
are regular/nofollow/nonblocking and bounded. Storage sampling is not a quota.
The listener validates the synthetic bearer without recording its value, returns
426 for the known WebSocket fallback and serves only planned Responses calls.
It never fabricates tool outputs. Tool children must remain unable to reach it.

On handled failures the helper stops the listener and supervisor, then the outer
PID-namespace owner is terminated. A dedicated host subreaper uses waitpid and
pidfds to kill/reap owned orphan descendants before removing its private tree.
Uncertain ownership/cleanup preserves the fixture and returns blocked. Cleanup
failure cannot retain passing status. SIGKILL/reboot and production lifecycle
ownership remain separate runtime gates.

Local tests cover matching IDs, orphan/duplicate output rejection, protected
mutation, invalid denial oracles, exact image bytes, real capture time/output
limits, detached-child cleanup, FIFO/oversize snapshots and cleanup failure.
They open no host listener and make no model request. Fedora/Podman/SELinux,
production endpoint/catalog integrity, credential lifecycle, complete tools and
loaders, identity ownership and hard storage enforcement remain unverified.
