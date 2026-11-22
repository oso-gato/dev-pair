# Headless gptbox role entry

`Gptbox.enter(container_id, sealed_image_id, 'turn')` uses the existing
headless Distrobox route and the image command
`/usr/bin/python3 -I /usr/lib/dev-pair/gptbox/runtime.py entry turn`. The
controller requires the exact running container, its frozen image, the existing
network-none confinement and the declared job mounts. The assembly probe still
uses its three probe mounts and cannot dispatch a turn.

The mounted request in `/run/dev-pair-turn/request.json` supplies one operation
ID, the role, provider, recorded model and effort, the standards pin, the local
endpoint, and the SHA256 of the prompt and both configuration inputs. The role
must match the sealed image. `/run/dev-pair-turn/prompt.txt` supplies the prompt
on stdin. Codex receives the managed startup instruction from
`/etc/codex/requirements.toml` and its validated configuration and frozen
loaders through the read-only binds listed in `TURN_READONLY_MOUNTS`. The fixture
seeds the pinned CLI's bundled skills before mounting them read-only.

`/credentials/api-key` is a separate read-only credential input. This entry
accepts only the fixed synthetic credential and an HTTP endpoint on the isolated
runtime's IPv4 loopback interface. New maintenance input manifests select
`gpt-6.2-sol` at High effort. The launcher passes the request's recorded selection
through, including older selections, and never selects a replacement model.

The runtime creates the operation directory before starting Codex. An existing
directory suppresses another launch for that operation. The CLI writes its
usual rollout under `/state/codex`. Private output and a successful completion
receipt are written under `/state/turns/<operation>`, with a bounded summary on
stdout. A failed or interrupted operation retains its directory for inspection.

The focused local fixture runs the exact pinned Codex 0.169.0 executable through
the image entry, checks the model, effort, startup directive, prompt and synthetic
bearer header on the wire, sees a completed assistant turn and verifies the
persisted session rollout. It also checks that a duplicate dispatch produces no
request. Run with a locally verified copy of the binary.

```sh
python3 tests/role_entry_stock.py --binary /path/to/pinned/codex --report /path/to/new-receipt.json
```

The fixture runs locally in isolated Linux namespaces. Live Fedora/Distrobox
turns in both placements, provisioning the admitted job mounts, external model
transport, production credentials and deployment remain open.
