"""Exercise the checklist over loopback and recover its actual SQLite state."""

from contextlib import closing, contextmanager
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import select
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest


APP = Path(__file__).with_name("checklist.py")


class ChecklistTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="checklist-test-")))
        self.database = self.root / "checklist.sqlite3"

    def command(self, *args, expected=0, pass_fds=()):
        result = subprocess.run(
            [sys.executable, "-I", "-B", APP, *args],
            capture_output=True, text=True, timeout=10, check=False, pass_fds=pass_fds,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    @contextmanager
    def serve(self, database=None, listener=None):
        database = self.database if database is None else database
        endpoint = ["--port", "0"]
        pass_fds = ()
        if listener is not None:
            endpoint = ["--listen-fd", str(listener.fileno())]
            pass_fds = (listener.fileno(),)
        with tempfile.TemporaryFile(mode="w+") as errors:
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", APP, "serve", "--database", database, *endpoint],
                stdout=subprocess.PIPE, stderr=errors, pass_fds=pass_fds,
            )
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                startup = os.read(process.stdout.fileno(), 128) if ready else b""
                match = re.fullmatch(rb"http://127\.0\.0\.1:([1-9][0-9]{0,4})\n", startup)
                if match is None:
                    errors.seek(0)
                    self.fail(f"Checklist did not start: {startup!r}\n{errors.read(4096)}")
                yield int(match[1])
            finally:
                process.stdout.close()
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    self.fail("Checklist did not stop after termination.")

    def request(self, port, method, path, *, body=None, headers=None):
        with closing(HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            content_type = response.getheader("Content-Type")
            content = response.read()
        if content_type == "application/json; charset=utf-8":
            content = json.loads(content)
        return response.status, content

    def add_item(self, port, title):
        return self.request(port, "POST", "/items", body=json.dumps({"title": title}),
                            headers={"Content-Type": "application/json"})

    def test_add_list_complete_restart_and_restore(self):
        snapshot = self.root / "snapshot.sqlite3"
        restore_root = self.root / "restored"
        restore_root.mkdir()
        restored = restore_root / "checklist.sqlite3"
        with self.serve() as port:
            status, page = self.request(port, "GET", "/")
            self.assertEqual(status, 200)
            self.assertIn(b"<title>Checklist</title>", page)
            self.assertEqual(self.request(port, "GET", "/items"), (200, []))
            status, item = self.add_item(port, "  Check backup ☀  ")
            self.assertEqual(status, 201)
            self.assertIs(type(item["id"]), int)
            self.assertGreater(item["id"], 0)
            self.assertEqual(item, {"id": item["id"], "title": "Check backup ☀", "done": False})
            self.assertEqual(self.request(port, "GET", "/items"), (200, [item]))
            completed = {**item, "done": True}
            complete_path = f"/items/{item['id']}/complete"
            self.assertEqual(self.request(port, "POST", complete_path), (200, completed))
            self.assertEqual(self.request(port, "POST", complete_path), (200, completed))
        with self.serve() as port:
            self.assertEqual(self.request(port, "GET", "/items"), (200, [completed]))
            self.command("backup", "--database", self.database, "--output", snapshot)
            self.assertEqual(self.add_item(port, "Added after snapshot")[0], 201)
        self.command("restore", "--backup", snapshot, "--database", restored)
        self.assertEqual(list(restore_root.iterdir()), [restored])
        with self.serve(restored) as port:
            self.assertEqual(self.request(port, "GET", "/items"), (200, [completed]))
            status, new_item = self.add_item(port, "Restored checklist is writable")
            self.assertEqual(status, 201)
            self.assertGreater(new_item["id"], item["id"])
        for file in [self.database, snapshot, restored]:
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_rejected_requests_preserve_state(self):
        with self.serve() as port:
            for title in ("   ", "x" * 121, "bad\x00title", "\ud800", None):
                with self.subTest(title=title):
                    self.assertEqual(self.add_item(port, title)[0], 400)
            headers = {"Content-Type": "application/json"}
            for request_body, status in [("{", 400), ("x" * 4097, 413)]:
                with self.subTest(status=status):
                    self.assertEqual(self.request(port, "POST", "/items", body=request_body,
                                                  headers=headers)[0], status)
            self.assertEqual(self.request(port, "POST", "/items", body="title=unauthorized")[0], 415)
            self.assertEqual(self.request(port, "POST", "/items/42/complete")[0], 404)
            self.assertEqual(self.request(port, "POST", "/items/9999999999999999999/complete")[0], 404)
            self.assertEqual(self.request(port, "POST", "/items/42/complete", body="x")[0], 413)
            self.assertEqual(self.request(port, "POST", "/items/42/complete",
                                          headers={"Origin": "https://example.invalid"})[0], 403)
            self.assertEqual(self.request(port, "GET", "/items",
                                          headers={"Host": "example.invalid"})[0], 403)
            self.assertEqual(self.request(port, "GET", "/items"), (200, []))

    def test_full_checklist_can_still_complete_items(self):
        with self.serve() as port:
            # Seed the bounded table in one transaction so the test does not need 1,000 HTTP writes.
            with closing(sqlite3.connect(self.database)) as db, db:
                db.executemany("INSERT INTO items (title) VALUES (?)", [("Fixture item",)] * 1000)
            self.assertEqual(self.add_item(port, "Over capacity")[0], 409)
            status, item = self.request(port, "POST", "/items/1000/complete")
            self.assertEqual((status, item), (200, {"id": 1000, "title": "Fixture item", "done": True}))
            status, items = self.request(port, "GET", "/items")
            self.assertEqual(status, 200)
            self.assertEqual(len(items), 1000)

    def test_parent_supplied_loopback_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            result = self.command(
                "serve", "--database", self.database, "--listen-fd", str(listener.fileno()),
                expected=1, pass_fds=(listener.fileno(),),
            )
            self.assertIn("must already listen on 127.0.0.1", result.stderr)
            self.assertFalse(self.database.exists())
            listener.listen()
            with self.serve(listener=listener) as port:
                self.assertEqual(port, listener.getsockname()[1])
                self.assertEqual(self.add_item(port, "Parent-owned endpoint")[0], 201)
                self.assertEqual(self.request(port, "GET", "/items"),
                                 (200, [{"id": 1, "title": "Parent-owned endpoint", "done": False}]))

    def test_restore_refuses_wrong_source_and_existing_destination(self):
        foreign = self.root / "foreign.sqlite3"
        destination = self.root / "destination.sqlite3"
        with closing(sqlite3.connect(foreign)) as db:
            db.execute("CREATE TABLE other (id INTEGER PRIMARY KEY)")
        result = self.command("restore", "--backup", foreign, "--database", destination, expected=1)
        self.assertIn("Expected a checklist database", result.stderr)
        self.assertFalse(destination.exists())
        with self.serve() as port:
            self.assertEqual(self.add_item(port, "Keep this item")[0], 201)
        destination.write_bytes(b"existing file")
        result = self.command("restore", "--backup", self.database, "--database", destination, expected=1)
        self.assertIn("File exists", result.stderr)
        self.assertEqual(destination.read_bytes(), b"existing file")
        self.assertEqual(set(self.root.iterdir()), {self.database, foreign, destination})
        clean = self.root / "clean.sqlite3"
        old_journal = self.root / "clean.sqlite3-journal"
        old_journal.write_bytes(b"old sidecar")
        result = self.command("restore", "--backup", self.database, "--database", clean, expected=1)
        self.assertIn("Use a clean destination", result.stderr)
        self.assertFalse(clean.exists())
        self.assertEqual(old_journal.read_bytes(), b"old sidecar")


if __name__ == "__main__":
    unittest.main()
