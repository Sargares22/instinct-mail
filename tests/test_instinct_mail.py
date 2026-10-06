"""Offline tests: no network, no real mailbox. Run with `python -m unittest discover tests`."""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import instinct_mail as im  # noqa: E402

V1_SCHEMA = """
  CREATE TABLE jobs(
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL,
    origin_thread_id TEXT NOT NULL, subject TEXT NOT NULL, state TEXT NOT NULL,
    created_at TEXT NOT NULL, closed_at TEXT, resolution TEXT
  );
  CREATE TABLE messages(
    id TEXT PRIMARY KEY, direction TEXT NOT NULL, job_id TEXT REFERENCES jobs(id),
    request_id TEXT UNIQUE, payload_hash TEXT, rfc_message_id TEXT UNIQUE, gmail_message_id TEXT UNIQUE,
    in_reply_to TEXT, refs TEXT, sender TEXT NOT NULL, recipient TEXT NOT NULL, subject TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '', raw_mime BLOB, provenance TEXT NOT NULL, state TEXT NOT NULL,
    error TEXT, created_at TEXT NOT NULL, source_uid TEXT, source_folder TEXT, notified_at TEXT
  );
  CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.saved_env = dict(os.environ)
        for key in list(os.environ):
            if key.startswith(("NOTIFY_", "INSTINCT_", "GMAIL_", "IMAP_", "POLL_")):
                del os.environ[key]
        os.environ["INSTINCT_DATA_DIR"] = str(self.dir / "data")
        os.environ["INSTINCT_ENV_FILE"] = str(self.dir / "absent.env")
        self.saved_attrs = {name: getattr(im, name) for name in ("poll_mailbox", "poll_seconds", "DB_WATCH_SECONDS")}
        self.connections = []

    def tearDown(self):
        for db in self.connections:
            db.close()
        for name, value in self.saved_attrs.items():
            setattr(im, name, value)
        os.environ.clear()
        os.environ.update(self.saved_env)
        self.tmp.cleanup()

    def db(self):
        db = im.connect()
        self.connections.append(db)
        return db

    def credentials(self, password=True):
        os.environ["GMAIL_ADDRESS"] = "me@example.com"
        os.environ["INSTINCT_ADDRESS"] = "agent@example.com"
        if password:
            os.environ["GMAIL_APP_PASSWORD"] = "abcdabcdabcdabcd"

    def add_job(self, db, job_id="j_1", thread="", notifier=None):
        with db:
            db.execute("""INSERT INTO jobs (id, request_id, payload_hash, origin_thread_id, subject, state,
                                            created_at, notifier) VALUES (?, ?, 'h', ?, 's', 'open', ?, ?)""",
                       (job_id, "r_" + job_id, thread, im.now(), notifier))

    def add_reply(self, db, message_id, job_id="j_1", body="hello"):
        with db:
            db.execute("""INSERT INTO messages (id, direction, job_id, sender, recipient, subject, body,
                                                provenance, state, created_at)
                          VALUES (?, 'in', ?, 'a', 'b', 'Re', ?, 'test', 'received', ?)""",
                       (message_id, job_id, body, im.now()))

    def fake_mailbox(self, error=None):
        calls = []

        def poll(db):
            calls.append(1)
            if error:
                raise OSError(error)
            return {"synced": True, "received": 0, "folders": []}

        im.poll_mailbox = poll
        return calls


class ConfigTests(Base):
    def test_env_file_parsing(self):
        path = self.dir / "conf.env"
        path.write_text('# comment\nGMAIL_ADDRESS=me@example.com\nGMAIL_APP_PASSWORD="abcd efgh"\n'
                        'INSTINCT_ADDRESS=agent@example.com # trailing\n'
                        'NOTIFY_BB=["bb", "thread", "tell", "{thread}", "{text}"]\n', encoding="utf-8")
        os.chmod(path, 0o600)
        im.load_env(str(path))
        self.assertEqual(im.env("GMAIL_APP_PASSWORD"), "abcd efgh")
        self.assertEqual(im.env("INSTINCT_ADDRESS"), "agent@example.com")
        self.assertEqual(im.notifier_argv("bb"), ["bb", "thread", "tell", "{thread}", "{text}"])

    def test_env_file_rejects_garbage(self):
        path = self.dir / "bad.env"
        path.write_text("not a key value line\n", encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaises(ValueError):
            im.load_env(str(path))

    def test_lock_is_exclusive_and_released_on_close(self):
        path = self.dir / "x.lock"
        first = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        second = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self.assertTrue(im.lock_file(first, blocking=False))
            self.assertFalse(im.lock_file(second, blocking=False))
        finally:
            os.close(first)
        try:
            self.assertTrue(im.lock_file(second, blocking=False))
        finally:
            os.close(second)

    def test_skill_text_carries_the_invocation(self):
        self.assertIn("@CMD@", im.SKILL_TEXT)
        self.assertIn("instinct_mail.py", im.invocation())


class SchemaTests(Base):
    def old_database(self):
        (self.dir / "data").mkdir()
        raw = sqlite3.connect(self.dir / "data" / "instinct.sqlite3")
        raw.executescript(V1_SCHEMA)
        raw.execute("INSERT INTO jobs VALUES ('j_old', 'r_old', 'h', 'thread-7', 's', 'open', '2026-01-01', NULL, NULL)")
        raw.execute("""INSERT INTO messages (id, direction, job_id, sender, recipient, subject, provenance, state, created_at)
                       VALUES ('m_old', 'in', 'j_old', 'a', 'b', 'Re', 'p', 'received', '2026-01-02')""")
        raw.commit()
        raw.close()

    def test_fresh_database_gets_current_schema(self):
        db = self.db()
        version = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        self.assertEqual(int(version), im.SCHEMA_VERSION)

    def test_old_database_is_upgraded_and_history_counts_as_read(self):
        self.old_database()
        db = self.db()
        self.assertIsNotNone(db.execute("SELECT read_at FROM messages WHERE id='m_old'").fetchone()[0])
        self.assertIsNone(db.execute("SELECT notifier FROM jobs WHERE id='j_old'").fetchone()[0])

    def test_old_database_that_already_has_a_read_column(self):
        self.old_database()
        raw = sqlite3.connect(self.dir / "data" / "instinct.sqlite3")
        raw.execute("ALTER TABLE messages ADD COLUMN read_at TEXT")
        raw.commit()
        raw.close()
        db = self.db()
        self.assertIsNotNone(db.execute("SELECT read_at FROM messages WHERE id='m_old'").fetchone()[0])

    def test_newer_database_is_refused(self):
        db = self.db()
        with db:
            db.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        with self.assertRaisesRegex(ValueError, "schema_too_new"):
            im.connect()

    def test_migrate_assigns_notifier_to_open_jobs_with_a_thread(self):
        self.old_database()
        os.environ["NOTIFY_BB"] = json.dumps(["bb", "thread", "tell", "{thread}", "{text}"])
        db = self.db()
        self.add_job(db, "j_no_thread")
        self.assertEqual(im.cmd_migrate(db, "bb")["jobs_assigned"], 1)
        self.assertEqual(db.execute("SELECT notifier FROM jobs WHERE id='j_old'").fetchone()[0], "bb")


class NotifierTests(Base):
    def test_rejects_bad_configuration(self):
        for value in ("bb thread tell", '["bb", 5]', "[]", '["bb", "{job}"]'):
            os.environ["NOTIFY_X"] = value
            with self.assertRaisesRegex(ValueError, "configuration_error"):
                im.notifier_argv("x")
        with self.assertRaisesRegex(ValueError, "not configured"):
            im.notifier_argv("missing")
        with self.assertRaises(ValueError):
            im.notifier_argv("Bad Name")

    def test_runs_argv_without_a_shell(self):
        target = self.dir / "note.txt"
        script = "import sys; open(sys.argv[1], 'w', encoding='utf-8').write(sys.argv[2] + '|' + sys.argv[3])"
        os.environ["NOTIFY_T"] = json.dumps([sys.executable, "-c", script, str(target), "{thread}", "{text}"])
        self.assertTrue(im.send_notification("t", "thread; rm -rf", "j_1", "m_1"))
        thread, text = target.read_text(encoding="utf-8").split("|", 1)
        self.assertEqual(thread, "thread; rm -rf")
        self.assertIn("m_1", text)

    def test_serve_side_notifies_only_jobs_with_a_notifier(self):
        target = self.dir / "note.txt"
        script = "import sys; open(sys.argv[1], 'a').write(sys.argv[2] + '\\n')"
        os.environ["NOTIFY_T"] = json.dumps([sys.executable, "-c", script, str(target), "{thread}"])
        db = self.db()
        self.add_job(db, "j_wait")
        self.add_job(db, "j_tell", thread="thread-9", notifier="t")
        self.add_reply(db, "m_a", "j_wait")
        self.add_reply(db, "m_b", "j_tell")
        self.assertEqual(im.notify_pending_messages(db), 1)
        self.assertEqual(target.read_text().split(), ["thread-9"])
        self.assertIsNone(db.execute("SELECT notified_at FROM messages WHERE id='m_a'").fetchone()[0])


class AskTests(Base):
    def test_notify_needs_thread_and_configuration(self):
        self.credentials(password=False)
        db = self.db()
        with self.assertRaisesRegex(ValueError, "requires --thread"):
            im.cmd_ask(db, None, "q", "req_1", notifier="bb")
        with self.assertRaisesRegex(ValueError, "not configured"):
            im.cmd_ask(db, "thread-1", "q", "req_1", notifier="bb")

    def test_ask_without_thread_is_stored_and_not_sent_without_password(self):
        self.credentials(password=False)
        db = self.db()
        result = im.cmd_ask(db, None, "question", "req_1")
        self.assertEqual(result["status"], "not_sent")
        job = db.execute("SELECT origin_thread_id, notifier FROM jobs WHERE id=?", (result["job_id"],)).fetchone()
        self.assertEqual((job["origin_thread_id"], job["notifier"]), ("", None))


class WaitTests(Base):
    def setUp(self):
        super().setUp()
        self.credentials()
        im.DB_WATCH_SECONDS = 0.01
        im.poll_seconds = lambda: 0

    def test_wait_returns_all_unread_ids_and_no_email_text(self):
        self.fake_mailbox()
        db = self.db()
        self.add_job(db)
        self.add_reply(db, "m_1", body="first SECRET-TEXT")
        self.add_reply(db, "m_2", body="second")
        result = im.cmd_wait(db, "j_1", timeout=5)
        self.assertEqual(result["status"], "replied")
        self.assertEqual([m["id"] for m in result["messages"]], ["m_1", "m_2"])
        self.assertNotIn("SECRET-TEXT", json.dumps(result))

    def test_wait_ignores_notified_at_and_stops_firing_once_read(self):
        self.fake_mailbox()
        db = self.db()
        self.add_job(db)
        self.add_reply(db, "m_1")
        self.add_reply(db, "m_2")
        with db:
            db.execute("UPDATE messages SET notified_at=?", (im.now(),))
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=5)["status"], "replied")

        first = im.cmd_read(db, "j_1", None)
        self.assertEqual((first["message_id"], first["unread_remaining"]), ("m_1", 1))
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=5)["messages"][0]["id"], "m_2")
        self.assertEqual(im.cmd_read(db, "j_1", None)["unread_remaining"], 0)
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=0)["status"], "timeout")

    def test_message_is_marked_read_only_after_its_last_page(self):
        self.fake_mailbox()
        db = self.db()
        self.add_job(db)
        self.add_reply(db, "m_1", body="x" * 30)
        page = im.cmd_read(db, None, "m_1", cursor=0, limit=20)
        self.assertEqual(page["next_cursor"], 20)
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=5)["status"], "replied")
        im.cmd_read(db, None, "m_1", cursor=20, limit=20)
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=0)["status"], "timeout")

    def test_wait_gives_up_after_repeated_mailbox_failures(self):
        calls = self.fake_mailbox(error="network down")
        db = self.db()
        self.add_job(db)
        result = im.cmd_wait(db, "j_1", timeout=30)
        self.assertEqual(result["status"], "sync_failed")
        self.assertEqual(len(calls), im.MAX_SYNC_FAILURES)
        self.assertEqual(result["sync"]["reason"], "poll_error")

    def test_wait_reports_missing_credentials_at_once(self):
        del os.environ["GMAIL_APP_PASSWORD"]
        db = self.db()
        self.add_job(db)
        self.assertEqual(im.cmd_wait(db, "j_1", timeout=30)["status"], "sync_failed")

    def test_polls_are_rate_limited_across_callers(self):
        calls = self.fake_mailbox()
        db = self.db()
        self.assertTrue(im.sync_mailbox(db, min_interval=60)["synced"])
        self.assertEqual(im.sync_mailbox(db, min_interval=60)["reason"], "recent_sync")
        self.assertTrue(im.sync_mailbox(db)["synced"])
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
