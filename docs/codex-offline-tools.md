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

The original fourteen actions independently inspect product effects and unchanged
protected objects: shell positive/negative, allowed and forbidden cwd requests,
escalation/login rejection, denied connection to the live fixture, direct patch,
forbidden/partial patch, intercepted shell patch and identical valid PNG
allow/denial through direct and symlink paths. Wrong-path, unsupported-tool and
invalid-image errors cannot count as denial. Failed actions and actual partial
product effects are retained. The denied cwd request may execute confined at the
HOME fallback; its actual cwd and absolute-target denial remain visible.

The fixed expansion has32 mandatory actions and at most one explicit completion
poll (33 maximum). It adds five owned-PTY actions: start with a bound header ID,
empty poll, exact-once input consumption, retired-ID rejection and invalid-ID
rejection. The continued child independently writes the product marker, reports
UID/capabilities/NNP and attempts the known denied read and protected-code write.
Its18-second alarm and the existing action/experiment deadlines bound input wait.
The optional completion poll is inserted once only if the input result is still
running; remaining running state blocks instead of polling indefinitely.

Nine goal actions exercise initial absence, missing-goal update, empty objective,
nonpositive budget, create, duplicate create, forbidden active update, complete
and final get. The controller binds the actual CLI `thread.started` UUID to
read-only SQLite row snapshots, parameterized lookup, stable goal identity,
unchanged unrelated rows and final database integrity after supervisor stop.
Usage may advance legitimately; token entitlement/spending and recovery are
unverified. The objective contains a literal protected path as data, and product
file snapshots must remain unchanged during these supervisor operations.

One valid input request observes rejection under the unchanged current exec/
Default configuration, followed by subsequent tool work. It does not establish
interactive answer/client correlation. Three special client `tool_search_call`
items use object arguments and require correlated `tool_search_output` kinds.
Positive search requires the actual advertised Multi-agent source and its exact
cached-source namespace/function schema; the fixture never invokes the discovered
`spawn_agent`. Complete definitions and every request inventory are retained and
hashed. Empty invalid-input results establish bounded no-definition behavior
only: the same completed/client/empty shape can encode errors or cancellation,
so it cannot prove a particular handler validator without a separate witness.

Each action record retains its emitted call kind and the actual returned output
kind. The pinned stock source maps `function_call` to `function_call_output` and
`custom_tool_call` to `custom_tool_call_output` (`core/src/tools/context.rs`,
`function_tool_response`, and `parallel.rs`, `failure_response`, at source
`d32063f96c2dff1dc96af839b3952abb6acfeda4`). Every returned output, including
replayed history, must match its issued ID and kind. Unknown, orphan, duplicate
or cross-kind outputs cannot advance the sequence or pass an action. Older
reports without these fields do not establish observed wire kinds.

Stock successful goal creation can also inject a source-defined named untrusted
context item (`context-fragments/src/additional_context.rs` and
`ext/goal/src/tool.rs` at the same pinned source). The fixture recognizes only
`function_call_output` with omitted call ID, namespace `agent`, name
`goal_objective` and the exact planned objective, first alongside a correlated
successful create result and its actual thread/database identity. It records
this supervisor context separately and permits only unchanged replay. Other
uncorrelated items block. A protocol rejection retains bounded complete output
items, request hash/size and issued IDs for diagnosis under the existing caps.

Actual request tool inventories are hashed and classified from completed checks.
Unknown/unexercised surfaces block inventory closure and overall status, even when
all planned actions pass. Provider-hosted web_search, discovered untested
collaboration tools, interactive input/client behavior, cross-job ownership and
renewal remain gates. Same-session PTY continuation, one thread's supervisor goal
state, local registry metadata and current-mode input rejection are separate
coverage classes. Search definitions in history need not be copied into the
request's top-level tools array; the report inventories their union. Helper-in-
script patch routes, additional permission modes, complete loader discovery and
auth/backend-dependent paths remain later acceptance work.

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
Expansion checks cover dynamic header-only PTY binding, one conditional poll,
real pending-PTY termination, exact input effects, read-only goal identity/foreign
row preservation, special search wire/kind/byte accounting, ambiguous empty search
results, named context causal binding and bounded product metadata snapshots.
They open no host listener and make no model request. Fedora/Podman/SELinux,
production endpoint/catalog integrity, credential lifecycle, complete tools and
loaders, identity ownership and hard storage enforcement remain unverified.
