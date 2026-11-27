#!/usr/bin/env python3
"""A private checklist with a durable SQLite database."""

import argparse
from contextlib import ExitStack, closing
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
import time


HOST = "127.0.0.1"
MAX_ITEMS = 1000
MAX_TITLE = 120
MAX_BODY = 4096
MAX_DATABASE_BYTES = 2 * 1024 * 1024
SQLITE_TIMEOUT = 3
APPLICATION_ID = 0x43484B4C  # CHKL
SCHEMA = f"""CREATE TABLE items (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND {MAX_TITLE}),
    done INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0, 1))
)"""
COMPLETE = re.compile(r"/items/([1-9][0-9]{0,18})/complete")
TAILNET_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}ts\.net")

PAGE = b"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checklist</title>
<style>
  :root { color-scheme: light; background: #f5f5ed; color: #272d26;
    font: 16px/1.5 system-ui, sans-serif; }
  body { max-width: 38rem; margin: 8vh auto; padding: 0 1.25rem; }
  h1 { font: bold clamp(2.5rem, 6vw, 4rem)/1.1 Georgia, serif; margin: 0 0 1.5rem; }
  form, li { display: flex; align-items: center; gap: .75rem; }
  input, button { box-sizing: border-box; padding: .625rem .75rem; border-radius: .375rem;
    border: 1px solid #72776d; font: inherit; }
  input { flex: 1; min-width: 0; background: #fff; }
  button { background: #315336; color: #fff; cursor: pointer; }
  button:disabled { opacity: .55; cursor: default; }
  ul { list-style: none; padding: 0; margin: 0; }
  li { padding: .75rem 0; border-top: 1px solid #c6c9bd; }
  li span { flex: 1; overflow-wrap: anywhere; }
  li small { color: #4c594c; }
  #status { min-height: 1.5em; margin: .5rem 0; }
</style>
<main>
  <h1>Checklist</h1>
  <form><input type="text" aria-label="Item title" placeholder="Add an item" required>
    <button disabled>Add</button></form>
  <p id="status" role="status">Loading checklist...</p>
  <ul aria-label="Checklist items"></ul>
</main>
<script>
  const form = document.querySelector('form');
  const input = document.querySelector('input');
  const statusMessage = document.querySelector('#status');
  const list = document.querySelector('ul');
  const add = form.querySelector('button');
  let items = [];
  let busy = false;

  async function request(path, options) {
    const response = await fetch(path, options);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error);
    return body;
  }

  function render() {
    list.replaceChildren(...items.map(item => {
      const row = document.createElement('li');
      const title = document.createElement('span');
      const action = document.createElement(item.done ? 'small' : 'button');
      title.textContent = item.title;
      action.textContent = item.done ? 'Done' : 'Complete';
      if (!item.done) {
        action.setAttribute('aria-label', 'Complete ' + item.title);
        action.onclick = () => run(async () => {
          const updated = await request(`/items/${item.id}/complete`, {method: 'POST'});
          items = items.map(existing => existing.id === updated.id ? updated : existing);
        });
      }
      row.append(title, action);
      return row;
    }));
    statusMessage.textContent = items.length ? '' : 'Your checklist is empty.';
  }

  async function run(action) {
    if (busy) return;
    busy = true;
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => button.disabled = true);
    try {
      await action();
      render();
    } catch (error) {
      statusMessage.textContent = error.message;
    } finally {
      busy = false;
      buttons.forEach(button => button.disabled = false);
    }
  }

  form.onsubmit = event => {
    event.preventDefault();
    run(async () => {
      const item = await request('/items', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({title: input.value})});
      items.push(item);
      input.value = '';
      input.focus();
    });
  };
  run(async () => { items = await request('/items'); });
</script>
</html>
"""


class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def connect(path, *, readonly=False):
    mode = "ro" if readonly else "rwc"
    db = sqlite3.connect(
        f"{path.resolve().as_uri()}?mode={mode}", uri=True, timeout=SQLITE_TIMEOUT
    )
    db.execute("PRAGMA trusted_schema = OFF")
    return db


def page_limit(db):
    return MAX_DATABASE_BYTES // db.execute("PRAGMA page_size").fetchone()[0]


def verify_database(db):
    if db.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,):
        raise ValueError("Expected a checklist database.")
    if db.execute("PRAGMA user_version").fetchone() != (1,):
        raise ValueError("Unsupported checklist database version.")
    if db.execute("PRAGMA page_count").fetchone()[0] > page_limit(db):
        raise ValueError("Checklist database exceeds the storage limit.")
    if db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
        raise ValueError("Checklist database failed its integrity check.")
    db.execute("SELECT id, title, done FROM items LIMIT 0")


def initialize(db):
    with db:
        db.execute("BEGIN IMMEDIATE")
        if (
            db.execute("PRAGMA application_id").fetchone() == (0,)
            and db.execute("PRAGMA user_version").fetchone() == (0,)
            and not db.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone()
        ):
            db.execute(SCHEMA)
            db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            db.execute("PRAGMA user_version = 1")
        verify_database(db)
        db.execute(f"PRAGMA max_page_count = {page_limit(db)}")


def copy_database(source, destination):
    deadline = time.monotonic() + SQLITE_TIMEOUT

    def check_deadline(_status, _remaining, _total):
        if time.monotonic() > deadline:
            raise ValueError("Timed out copying the checklist database.")

    with closing(connect(source, readonly=True)) as db:
        verify_database(db)
        with tempfile.TemporaryDirectory(prefix=".checklist-", dir=destination.parent) as staging:
            staged = Path(staging) / "checklist.sqlite3"
            with closing(connect(staged)) as copied:
                db.backup(copied, pages=64, progress=check_deadline)
                verify_database(copied)
            if any(os.path.lexists(f"{destination}{suffix}") for suffix in ("-journal", "-wal", "-shm")):
                raise ValueError("Destination has SQLite sidecar files. Use a clean destination.")
            # Publish only a completed snapshot and refuse to overwrite any destination.
            os.link(staged, destination)


def validated_title(body):
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Expected a UTF-8 JSON object.") from None
    if not isinstance(data, dict) or set(data) != {"title"} or not isinstance(data["title"], str):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Expected an object with a string title.")
    title = data["title"].strip()
    if not 1 <= len(title) <= MAX_TITLE:
        raise RequestError(HTTPStatus.BAD_REQUEST, f"Title must be 1 to {MAX_TITLE} characters.")
    if any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in title):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Title must be a single line of valid text.")
    return title


def item_object(row):
    item_id, title, done = row
    return {"id": item_id, "title": title, "done": bool(done)}


class ChecklistServer(HTTPServer):
    def __init__(self, port, db, listener, *, container=False, tailnet_host=None):
        bind_host = "0.0.0.0" if container else HOST
        super().__init__((bind_host, port), ChecklistHandler, bind_and_activate=listener is None)
        if listener is not None:
            self.socket.close()
            self.socket = listener
            self.server_address = listener.getsockname()
            self.server_name, self.server_port = self.server_address
        self.db = db
        self.authority = tailnet_host or f"{HOST}:{self.server_port}"
        scheme = "https" if tailnet_host else "http"
        self.url = f"{scheme}://{self.authority}"


class ChecklistHandler(BaseHTTPRequestHandler):
    timeout = 3

    def handle(self):
        try:
            super().handle()
        except ConnectionError:
            pass

    def log_message(self, *_args):
        pass

    def respond(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def respond_json(self, status, data):
        self.respond(
            status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def read_body(self, limit):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) > 1:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Use a single Content-Length header.")
        if lengths and not re.fullmatch(r"[0-9]{1,9}", lengths[0]):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length.")
        length = int(lengths[0]) if lengths else 0
        if length > limit:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body exceeds the limit.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Incomplete request body.")
        return body

    def route(self):
        if self.headers.get_all("Host") != [self.server.authority]:
            raise RequestError(HTTPStatus.FORBIDDEN, "Use the checklist address printed at startup.")
        origins = self.headers.get_all("Origin", [])
        if origins and origins != [self.server.url]:
            raise RequestError(HTTPStatus.FORBIDDEN, "Request origin is outside the checklist.")

        db = self.server.db
        if self.command == "GET" and self.path == "/":
            self.respond(HTTPStatus.OK, PAGE, "text/html; charset=utf-8")
            return
        if self.command == "GET" and self.path == "/items":
            rows = db.execute("SELECT id, title, done FROM items ORDER BY id")
            self.respond_json(HTTPStatus.OK, [item_object(row) for row in rows])
            return
        if self.command == "POST" and self.path == "/items":
            if self.headers.get_content_type() != "application/json":
                raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Use application/json.")
            title = validated_title(self.read_body(MAX_BODY))
            with db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT count(*) FROM items").fetchone()[0] >= MAX_ITEMS:
                    raise RequestError(HTTPStatus.CONFLICT, "The checklist is full.")
                item_id = db.execute("INSERT INTO items (title) VALUES (?)", (title,)).lastrowid
            self.respond_json(HTTPStatus.CREATED, item_object((item_id, title, 0)))
            return
        match = COMPLETE.fullmatch(self.path)
        if self.command == "POST" and match:
            self.read_body(0)
            item_id = int(match[1])
            if item_id <= 2**63 - 1:
                with db:
                    db.execute("UPDATE items SET done = 1 WHERE id = ?", (item_id,))
                    row = db.execute(
                        "SELECT id, title, done FROM items WHERE id = ?", (item_id,)
                    ).fetchone()
                if row is not None:
                    self.respond_json(HTTPStatus.OK, item_object(row))
                    return
        raise RequestError(HTTPStatus.NOT_FOUND, "Checklist route or item not found.")

    def dispatch(self):
        try:
            self.route()
        except RequestError as error:
            self.respond_json(error.status, {"error": str(error)})
        except sqlite3.Error:
            self.respond_json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Checklist storage unavailable."}
            )

    do_GET = dispatch
    do_POST = dispatch


def serve(database, port, listen_fd, *, container=False, tailnet_host=None):
    with ExitStack() as resources:
        listener = None
        if listen_fd is not None:
            listener = resources.enter_context(socket.socket(fileno=listen_fd))
            if (
                listener.family != socket.AF_INET
                or listener.type != socket.SOCK_STREAM
                or listener.getsockname()[0] != HOST
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            ):
                raise ValueError("The inherited socket must already listen on 127.0.0.1.")
        db = resources.enter_context(closing(connect(database)))
        initialize(db)
        server = resources.enter_context(ChecklistServer(port, db, listener, container=container,
                                                          tailnet_host=tailnet_host))
        print(server.url, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve", help="start the loopback HTTP server")
    server.add_argument("--database", required=True, type=Path)
    endpoint = server.add_mutually_exclusive_group()
    endpoint.add_argument("--port", default=8000, type=int, help="use 0 for a free port")
    endpoint.add_argument("--listen-fd", type=int, help="inherit an already listening loopback socket")
    server.add_argument("--container", action="store_true", help="listen on the private container network")
    server.add_argument("--tailnet-host", help="exact DNS name served by the host HTTPS proxy")
    backup = commands.add_parser("backup", help="copy the database to a new snapshot file")
    backup.add_argument("--database", required=True, type=Path)
    backup.add_argument("--output", required=True, type=Path)
    restore = commands.add_parser("restore", help="restore a snapshot to a new database file")
    restore.add_argument("--backup", required=True, type=Path)
    restore.add_argument("--database", required=True, type=Path)
    args = parser.parse_args()

    os.umask(0o077)
    try:
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                parser.error("--port must be between 0 and 65535")
            if args.listen_fd is not None and args.listen_fd < 3:
                parser.error("--listen-fd must be at least 3")
            if args.container and args.listen_fd is not None:
                parser.error("--container and --listen-fd cannot be combined")
            if args.tailnet_host is not None and (
                not args.container or len(args.tailnet_host) > 253 or not TAILNET_HOST.fullmatch(args.tailnet_host)
            ):
                parser.error("--tailnet-host requires --container and an exact .ts.net name")
            serve(args.database, args.port, args.listen_fd, container=args.container, tailnet_host=args.tailnet_host)
        elif args.command == "backup":
            copy_database(args.database, args.output)
        else:
            copy_database(args.backup, args.database)
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.exit(1, f"checklist: {error}\n")


if __name__ == "__main__":
    main()
