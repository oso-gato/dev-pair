# Checklist

Run this small checklist locally with Python 3.11 or later and its standard
SQLite module. From the repository root, create a private data directory and
start the server.

```sh
checklist_state="${XDG_STATE_HOME:-$HOME/.local/state}/dev-pair-checklist"
install -d -m 700 "$checklist_state"
python3 examples/checklist/checklist.py serve --database "$checklist_state/checklist.sqlite3"
```

Open the printed address, usually `http://127.0.0.1:8000`. Enter a title and
select **Add**, then select **Complete** on an item. Stop with `Ctrl+C` and run
`serve` with the same database path to resume. Use `--port 0` to have the
operating system choose a free port. The listener accepts only `127.0.0.1`.
VPS delivery requires separately verified authorized tailnet access before use.

A local test runner can pass `--listen-fd` in place of `--port` to hand the
server an already listening IPv4 TCP socket on `127.0.0.1`. The server prints
the socket's URL once the database is ready.

## HTTP API

| Request | Successful response |
| --- | --- |
| `POST /items` with `Content-Type: application/json` and `{"title":"Check backup"}` | `201` and `{"id":1,"title":"Check backup","done":false}` for the first item |
| `GET /items` | `200` and a JSON array sorted by ID |
| `POST /items/1/complete` with an empty body | `200` and `{"id":1,"title":"Check backup","done":true}` |

Titles are trimmed and limited to 120 characters. Request bodies are limited
to 4 KiB, and the checklist holds up to 1,000 items in a SQLite database capped
at 2 MiB. Repeating completion returns the same completed item.

## Back up and restore

Take a consistent snapshot using a new output filename. The server can stay
running. Restore into a clean directory and start a separate instance using the
restored file to verify the result.

```sh
install -d -m 700 "$checklist_state/backups" "$checklist_state/restored"
python3 examples/checklist/checklist.py backup \
  --database "$checklist_state/checklist.sqlite3" \
  --output "$checklist_state/backups/checklist-01.sqlite3"
python3 examples/checklist/checklist.py restore \
  --backup "$checklist_state/backups/checklist-01.sqlite3" \
  --database "$checklist_state/restored/checklist.sqlite3"
python3 examples/checklist/checklist.py serve \
  --database "$checklist_state/restored/checklist.sqlite3" --port 0
```

Store backups outside the repository and retain a copy separately from the live
database. Both commands refuse to overwrite an existing destination.

## Verify locally

```sh
python3 -B examples/checklist/test_checklist.py -v
```

The tests exercise loopback HTTP, a real process restart, backup restoration in
an empty directory, and rejected inputs.
