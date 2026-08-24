"""Session registry — v2 authoritative bindings, run ledger, pruning,
awareness lines, CLI + launcher wiring.

v2 entries are identity-stamped (starttime + boot_id + pidns) and carry
the authoritative session→project binding; v1 entries remain advisory.
These tests pin: the identity/foreign/prune predicates, the binding
state machine (bound/none/advisory/absent), sentinel semantics, the run
ledger (grammar, CAS finish, injection rejection, zombie correction,
resume), and the pre-series advisory surfaces (awareness lines,
launcher wiring) that must keep working unchanged.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project import sessions
from core.project.cli import main
from core.project.project import ProjectManager

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"

DEAD_PID = 999999999

#: Unpatched starttime reader, for fixtures that fake ONE pid's identity
#: while leaving real pids alone.
_REAL_STARTTIME = sessions.proc_starttime


class _RegistryCase(unittest.TestCase):
    """Shared fixture: isolated SESSIONS_DIR + claude-shaped self.

    Tests run under pytest (comm ``python3``), so pids that must read
    as sessions get a patched comm probe. Liveness stays real unless a
    test patches it.
    """

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sessions_dir = Path(self._tmp.name) / "sessions.d"
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _write_v1(self, pid: int, project: str,
                  since: str = "2026-08-20T00:00:00+00:00"):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / str(pid)).write_text(
            f"project={project}\nsince={since}\n", encoding="utf-8")


class SessionsRegistryTest(_RegistryCase):

    def test_record_and_read_roundtrip(self):
        pid = sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(pid, os.getpid())
        entries = sessions.read_sessions()
        self.assertEqual(entries[os.getpid()]["project"], "myapp")
        self.assertIn("since", entries[os.getpid()])
        self.assertEqual(entries[os.getpid()]["v"], "2")

    def test_record_stamps_identity(self):
        sessions.record_session("myapp", pid=os.getpid())
        fields = sessions._parse_entry(self.sessions_dir / str(os.getpid()))
        self.assertTrue(fields.get("starttime"))
        self.assertTrue(fields.get("boot_id"))
        if sys.platform == "linux":
            self.assertTrue(fields.get("pidns"))

    def test_record_none_clears_entry_and_ledger(self):
        sessions.record_session("myapp", pid=os.getpid())
        sessions.ledger_record_start(self._tmp.name, pid=os.getpid())
        sessions.record_session(None, pid=os.getpid())
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())

    def test_record_without_session_pid_is_noop(self):
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            self.assertIsNone(sessions.record_session("myapp"))
        self.assertFalse(self.sessions_dir.exists())

    def test_record_refuses_invalid_name(self):
        self.assertIsNone(
            sessions.record_session("../evil", pid=os.getpid()))
        self.assertIsNone(
            sessions.record_session("a\nb", pid=os.getpid()))

    def test_record_preserves_seeded_by_and_token_on_rebind(self):
        sessions.record_session("myapp", pid=os.getpid(),
                                token="ab" * 16, seeded_by="flag")
        sessions.record_session("other", pid=os.getpid())
        fields = sessions._parse_entry(self.sessions_dir / str(os.getpid()))
        self.assertEqual(fields["project"], "other")
        self.assertEqual(fields["token"], "ab" * 16)
        self.assertEqual(fields["seeded_by"], "flag")

    def test_record_refreshes_stale_identity_stamp(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        good_start = fields["starttime"]
        # Corrupt the stamp on disk, rebind: the stale stamp must be
        # refreshed, never propagated.
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={good_start}", "starttime=1"),
            encoding="utf-8")
        sessions.record_session("myapp", pid=os.getpid())
        fields = sessions._parse_entry(entry)
        self.assertEqual(fields["starttime"], good_start)

    def test_control_chars_stripped_from_fields(self):
        sessions.record_session("myapp", pid=os.getpid(),
                                seeded_by="use\x1b[2J\nproject=evil")
        entry = self.sessions_dir / str(os.getpid())
        text = entry.read_text(encoding="utf-8")
        self.assertNotIn("\x1b", text)
        # The newline was stripped, so no forged key LINE exists: the
        # parse must still see the real project, and the hostile text
        # survives only as inert substring inside the seeded_by value.
        self.assertNotIn("\nproject=evil", text)
        fields = sessions._parse_entry(entry)
        self.assertEqual(fields["project"], "myapp")

    def test_dead_pid_entries_pruned_at_read(self):
        self._write_v1(DEAD_PID, "myapp")
        self._write_v1(os.getpid(), "myapp")
        entries = sessions.read_sessions()
        self.assertIn(os.getpid(), entries)
        self.assertNotIn(DEAD_PID, entries)
        self.assertFalse((self.sessions_dir / str(DEAD_PID)).exists(),
                         "dead entry not unlinked")

    def test_stale_v2_prunes_ledger_too(self):
        sessions.record_session("myapp", pid=os.getpid())
        sessions.ledger_record_start(self._tmp.name, pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        # Positively mismatching stamp on a live pid → stale → pruned.
        content = entry.read_text(encoding="utf-8")
        fields = sessions._parse_entry(entry)
        entry.write_text(content.replace(
            f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertFalse(entry.exists())
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())

    def test_foreign_boot_never_pruned_never_returned(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        entry = self.sessions_dir / str(DEAD_PID)
        entry.write_text(
            "v=2\nproject=other\nsince=x\nstarttime=42\n"
            "boot_id=00000000-dead-beef-0000-000000000000\n"
            "pidns=1\n", encoding="utf-8")
        entries = sessions.read_sessions()
        self.assertNotIn(DEAD_PID, entries)
        self.assertTrue(entry.exists(), "foreign entry was pruned")

    @unittest.skipUnless(sys.platform == "linux", "pidns identity")
    def test_same_boot_different_pidns_is_foreign(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"pidns={fields['pidns']}", "pidns=424242"),
            encoding="utf-8")
        self.assertTrue(
            sessions._foreign_entry(sessions._parse_entry(entry)))
        self.assertTrue(entry.exists())
        self.assertNotIn(os.getpid(), sessions.read_sessions())
        self.assertTrue(entry.exists(), "cross-pidns entry was pruned")

    def test_include_stale_labels_states(self):
        self._write_v1(os.getpid(), "adv")           # advisory (live)
        self._write_v1(DEAD_PID, "dead")             # stale
        entries = sessions.read_sessions(prune=False, include_stale=True)
        self.assertEqual(entries[os.getpid()]["_state"], "advisory")
        self.assertEqual(entries[DEAD_PID]["_state"], "stale")

    def test_non_pid_files_left_alone(self):
        self.sessions_dir.mkdir(parents=True)
        stray = self.sessions_dir / "README"
        stray.write_text("not an entry", encoding="utf-8")
        sessions.read_sessions()
        self.assertTrue(stray.exists())

    def test_other_sessions_filters_project_and_self(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026-08-20T01:00:00+00:00")
        others = sessions.other_sessions("myapp")
        self.assertEqual([e["pid"] for e in others], [os.getpid()])
        self.assertEqual(
            sessions.other_sessions("myapp", exclude_pid=os.getpid()), [])
        self.assertEqual(sessions.other_sessions("otherapp"), [])

    def test_registry_dir_is_private(self):
        self.sessions_dir.mkdir(parents=True, mode=0o755)
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(self.sessions_dir.stat().st_mode & 0o777, 0o700)

    def test_hostile_since_field_is_escaped_and_bounded(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026\x1b[2J\x07" + "C" * 4000)
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(len(lines), 1)
        self.assertNotIn("\x1b", lines[0])
        self.assertNotIn("\x07", lines[0])
        self.assertLess(len(lines[0]), 400)

    def test_awareness_line_wording(self):
        self._write_v1(os.getpid(), "myapp",
                       since="2026-08-20T01:00:00+00:00")
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(lines, [
            f"project myapp is also active in session pid {os.getpid()} "
            f"(since 2026-08-20T01:00:00+00:00)"
        ])


class SessionBindingTest(_RegistryCase):
    """The authoritative binding state machine."""

    def test_bound(self):
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         ("myapp", "bound"))

    def test_none_sentinel(self):
        sessions.bind_session(None, pid=os.getpid())
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "none"))
        text = (self.sessions_dir / str(os.getpid())).read_text(
            encoding="utf-8")
        self.assertIn("project=-", text)

    def test_v1_entry_is_advisory(self):
        self._write_v1(os.getpid(), "myapp")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "advisory"))

    def test_no_entry_is_absent(self):
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "absent"))

    def test_corrupt_v2_is_authoritative_none_not_fallthrough(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        # v2 shape, empty project value (the torn/legacy-empty case).
        stamp = sessions._identity_for(os.getpid())
        (self.sessions_dir / str(os.getpid())).write_text(
            "v=2\nproject=\nsince=x\n"
            f"starttime={stamp['starttime']}\n"
            f"boot_id={stamp['boot_id']}\n"
            + (f"pidns={stamp['pidns']}\n" if "pidns" in stamp else ""),
            encoding="utf-8")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "none"))

    @unittest.skipUnless(sys.platform == "linux", "starttime identity")
    def test_identity_mismatch_is_absent(self):
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        fields = sessions._parse_entry(entry)
        entry.write_text(
            entry.read_text(encoding="utf-8").replace(
                f"starttime={fields['starttime']}", "starttime=1"),
            encoding="utf-8")
        self.assertEqual(sessions.session_binding(pid=os.getpid()),
                         (None, "absent"))

    def test_env_credential_resolution(self):
        token = sessions.mint_token()
        sessions.record_session("myapp", pid=os.getpid(), token=token)
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: token,
        }):
            self.assertEqual(sessions._env_session_pid(), os.getpid())
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: "wrong" * 8,
        }):
            self.assertIsNone(sessions._env_session_pid())
        # Tokenless entry: env path unusable even with a "matching" var.
        sessions.record_session("myapp", pid=os.getpid())
        entry = self.sessions_dir / str(os.getpid())
        content = entry.read_text(encoding="utf-8")
        entry.write_text(
            "\n".join(ln for ln in content.splitlines()
                      if not ln.startswith("token=")) + "\n",
            encoding="utf-8")
        with patch.dict(os.environ, {
            sessions.ENV_SESSION_PID: str(os.getpid()),
            sessions.ENV_SESSION_TOKEN: token,
        }):
            self.assertIsNone(sessions._env_session_pid())


class RunLedgerTest(_RegistryCase):
    """Ledger grammar, CAS finish, injection defense, zombie
    correction, resume wiring."""

    def setUp(self):
        super().setUp()
        self.run_root = Path(self._tmp.name) / "runs"
        self.run_root.mkdir()
        # Ledger records belong to REGISTERED sessions only — give the
        # test pids entries (mandatory-seed invariant).
        sessions.record_session("ledgerapp", pid=os.getpid())
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / "777777").write_text(
            "project=ledgerapp\nsince=x\n", encoding="utf-8")

    def _mk_run(self, name: str, status: str = "running") -> Path:
        d = self.run_root / name
        d.mkdir()
        (d / ".raptor-run.json").write_text(
            f'{{"status": "{status}"}}', encoding="utf-8")
        return d

    def test_start_and_finish_roundtrip(self):
        d = self._mk_run("scan_1")
        sessions.ledger_record_start(d, pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "running")
        self.assertEqual(runs[0]["run_id"], "scan_1")
        self.assertEqual(runs[0]["run_dir"], str(d.resolve()))
        (d / ".raptor-run.json").write_text(
            '{"status": "completed"}', encoding="utf-8")
        sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(runs[0]["status"], "completed")

    def test_true_statuses_no_coercion(self):
        d = self._mk_run("scan_2")
        sessions.ledger_record_start(d, pid=os.getpid())
        (d / ".raptor-run.json").write_text(
            '{"status": "interrupted"}', encoding="utf-8")
        sessions.ledger_record_finish(d, "interrupted", pid=os.getpid())
        self.assertEqual(
            sessions.ledger_runs(pid=os.getpid())[0]["status"],
            "interrupted")

    def test_finish_cas_only_touches_its_run(self):
        d1 = self._mk_run("a_1")
        d2 = self._mk_run("b_2")
        sessions.ledger_record_start(d1, pid=os.getpid())
        sessions.ledger_record_start(d2, pid=os.getpid())
        (d1 / ".raptor-run.json").write_text(
            '{"status": "failed"}', encoding="utf-8")
        sessions.ledger_record_finish(d1, "failed", pid=os.getpid())
        by_id = {r["run_id"]: r["status"]
                 for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(by_id, {"a_1": "failed", "b_2": "running"})

    def test_linesep_injection_rejected(self):
        evil = self.run_root / ("x running 9 fake /victim")
        with contextlib.suppress(OSError):
            evil.mkdir()
        sessions.ledger_record_start(evil, pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])

    def test_whitespace_in_parent_path_rejected(self):
        spaced = self.run_root / "with space"
        spaced.mkdir()
        d = spaced / "run_1"
        d.mkdir()
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertEqual(sessions.ledger_runs(pid=os.getpid()), [])

    def test_zombie_running_records_corrected(self):
        d = self._mk_run("scan_3")
        sessions.ledger_record_start(d, pid=os.getpid())
        # Run dir's metadata flips terminal without a finish call
        # (crash path); the next write corrects the zombie.
        (d / ".raptor-run.json").write_text(
            '{"status": "failed"}', encoding="utf-8")
        d2 = self._mk_run("scan_4")
        sessions.ledger_record_start(d2, pid=os.getpid())
        by_id = {r["run_id"]: r["status"]
                 for r in sessions.ledger_runs(pid=os.getpid())}
        self.assertEqual(by_id["scan_3"], "failed")

    def test_cap_prunes_finished_only(self):
        live = self._mk_run("live_run")
        for i in range(40):
            d = self._mk_run(f"r{i}", status="completed")
            sessions.ledger_record_start(d, pid=os.getpid())
            sessions.ledger_record_finish(d, "completed", pid=os.getpid())
        sessions.ledger_record_start(live, pid=os.getpid())
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertLessEqual(len(runs), sessions._LEDGER_CAP + 1)
        self.assertIn("live_run", [r["run_id"] for r in runs])

    def test_resume_cross_session(self):
        d = self._mk_run("resumed_1")
        other = 777777
        # Original owner's ledger (fake pid) gets the running line.
        sessions.ledger_record_start(d, pid=other)
        # A different session resumes: own line running, old line
        # CAS-marked interrupted.
        sessions.ledger_record_resume(d, prior_session_pid=other,
                                      pid=os.getpid())
        mine = sessions.ledger_runs(pid=os.getpid())
        theirs = sessions.ledger_runs(pid=other)
        self.assertEqual(mine[0]["status"], "running")
        self.assertEqual(theirs[0]["status"], "interrupted")

    def test_dedup_on_reused_run_id(self):
        d = self._mk_run("dup_1")
        sessions.ledger_record_start(d, pid=os.getpid())
        sessions.ledger_record_start(d, pid=os.getpid())
        self.assertEqual(len(sessions.ledger_runs(pid=os.getpid())), 1)


class UseCommandAwarenessTest(unittest.TestCase):
    """/project use writes the registry and prints the awareness line.

    NOTE (pre-P05 semantics): the CLI still calls the historical
    record/clear paths; P05 rewires `use`/`none` to the binding-first
    contract and updates these expectations.
    """

    FAKE_SELF = 555555

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        target = root / "code"
        target.mkdir()
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(target),
                   output_dir=str(root / "out" / "myapp"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            # `use` runs outside a real claude session here; give it a
            # deterministic fake session pid, and make both our real
            # pid and the fake read as live claude sessions.
            patch.object(sessions, "resolve_session_pid",
                         return_value=self.FAKE_SELF),
            patch.object(sessions, "_pid_running",
                         lambda pid: pid in (os.getpid(), self.FAKE_SELF)),
            patch.object(sessions, "_comm",
                         lambda pid: "claude"
                         if pid in (os.getpid(), self.FAKE_SELF)
                         else None),
            # The fake session pid has no /proc entry; give it a
            # stable fake starttime so writer validation and the
            # subsequent authoritative read both succeed.
            patch.object(sessions, "proc_starttime",
                         lambda pid: "7777" if pid == self.FAKE_SELF
                         else _REAL_STARTTIME(pid)),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_use_records_entry(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        entry = self.sessions_dir / str(self.FAKE_SELF)
        self.assertTrue(entry.exists())
        self.assertIn("project=myapp", entry.read_text(encoding="utf-8"))

    def test_use_prints_awareness_for_other_session(self):
        self.sessions_dir.mkdir(parents=True)
        (self.sessions_dir / str(os.getpid())).write_text(
            "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
            encoding="utf-8")
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertIn(
            f"project myapp is also active in session pid {os.getpid()}",
            out)

    def test_use_no_awareness_when_alone(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertNotIn("also active", out)

    def test_use_none_binds_sentinel_and_keeps_bookmark(self):
        """In-session `/project none` is a session-only clear: the entry
        binds the `-` sentinel (authoritatively projectless) and the
        last-activated default is untouched."""
        self._run("use", "myapp")
        code, out, _ = self._run("none")
        self.assertEqual(code, 0)
        entry = self.sessions_dir / str(self.FAKE_SELF)
        self.assertTrue(entry.exists())
        self.assertIn("project=-", entry.read_text(encoding="utf-8"))
        self.assertIn("Session project cleared", out)
        self.assertIn("unchanged", out)
        # Bookmark still points at myapp.
        target = os.readlink(self.projects_dir / ".active")
        self.assertEqual(target, "myapp.json")


@unittest.skipIf(sys.platform == "win32", "bash launcher")
class LauncherAwarenessTest(unittest.TestCase):
    """The launcher prunes, warns, and registers before exec.

    Pre-P06: the launcher writes v1 entries and prunes with kill -0;
    P06 upgrades it to the v2 mandatory seed + sentinel handoff and
    extends these tests.
    """

    def _launch(self, home: Path, tmpdir: Path):
        path_dirs = [str(Path(sys.executable).resolve().parent)]
        path_dirs += [d for d in ("/usr/bin", "/bin") if os.path.isdir(d)]
        stub_dir = home / "stub-bin"
        stub_dir.mkdir(exist_ok=True)
        stub = stub_dir / "claude"
        stub.write_text("#!/usr/bin/env bash\necho STUB_CLAUDE_RAN\n",
                        encoding="utf-8")
        stub.chmod(0o755)
        return subprocess.run(
            ["bash", str(LAUNCHER)],
            capture_output=True, text=True, timeout=120, check=False,
            env={
                "PATH": ":".join([str(stub_dir)] + path_dirs),
                "HOME": str(home), "TMPDIR": str(tmpdir), "TERM": "xterm",
            },
            cwd=str(home),
        )

    def test_launcher_registers_prunes_and_warns(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            (sessions_dir / str(DEAD_PID)).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout,
                          (r.stdout, r.stderr))
            self.assertIn(
                f"project myapp is also active in session pid {os.getpid()}",
                r.stderr)
            self.assertNotIn(str(DEAD_PID), r.stderr,
                             "dead session produced an awareness line")
            self.assertFalse((sessions_dir / str(DEAD_PID)).exists(),
                             "dead entry not pruned at launch")
            own = [f for f in sessions_dir.iterdir()
                   if f.name.isdigit()
                   and f.name not in (str(os.getpid()), str(DEAD_PID))]
            self.assertEqual(len(own), 1, list(sessions_dir.iterdir()))
            self.assertIn("project=myapp",
                          own[0].read_text(encoding="utf-8"))
            self.assertEqual(sessions_dir.stat().st_mode & 0o777, 0o700,
                             "registry dir readable by other users")

    def test_launcher_awareness_escapes_hostile_since(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026\x1b[2J\x07" + "C" * 4000 + "\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("also active in session pid", r.stderr)
            self.assertNotIn("\x1b", r.stderr, "raw ESC reached stderr")
            self.assertNotIn("\x07", r.stderr)
            line = next(ln for ln in r.stderr.splitlines()
                        if "also active" in ln)
            self.assertLess(len(line), 300, "since field flooded the line")


if __name__ == "__main__":
    unittest.main()


class LayeredChokepointTest(unittest.TestCase):
    """get_active() / get_active_name() layered resolution:
    binding beats symlink, bound-to-none is authoritative, stale
    bindings never fall through, expiry remediation clears only the
    producing layer — and the two chokepoints always agree."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        (root / "code").mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("bound-proj", str(root / "code"),
                        output_dir=str(root / "out" / "bound-proj"))
        self.mgr.create("bookmark-proj", str(root / "code"),
                        output_dir=str(root / "out" / "bookmark-proj"))
        self.mgr.set_active("bookmark-proj")
        import core.startup as startup
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(startup, "PROJECTS_DIR", self.projects_dir),
            patch.object(startup, "ACTIVE_LINK",
                         self.projects_dir / ".active"),
            patch.object(sessions, "resolve_session_pid",
                         return_value=os.getpid()),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.startup = startup

    def test_binding_beats_bookmark_in_both_chokepoints(self):
        sessions.record_session("bound-proj", pid=os.getpid())
        self.assertEqual(self.mgr.get_active(), "bound-proj")
        self.assertEqual(self.startup.get_active_name(), "bound-proj")

    def test_bound_to_none_is_authoritative_in_both(self):
        sessions.bind_session(None, pid=os.getpid())
        self.assertIsNone(self.mgr.get_active())
        self.assertIsNone(self.startup.get_active_name())

    def test_no_binding_falls_to_bookmark_in_both(self):
        self.assertEqual(self.mgr.get_active(), "bookmark-proj")
        self.assertEqual(self.startup.get_active_name(), "bookmark-proj")

    def test_stale_binding_never_falls_through(self):
        self.mgr.create("doomed", str(Path(self._tmp.name) / "code"),
                        output_dir=str(Path(self._tmp.name) / "out" / "d"))
        sessions.record_session("doomed", pid=os.getpid())
        (self.projects_dir / "doomed.json").unlink()
        self.assertIsNone(self.mgr.get_active())
        self.assertIsNone(self.startup.get_active_name())

    def _make_expired_machine_project(self, name: str):
        self.mgr.create(name, "/tmp")
        proj = self.mgr.load(name)
        proj.expires_at = "2020-01-01T00:00:00+00:00"
        self.mgr._save(proj)

    def test_expired_binding_clears_binding_not_bookmark(self):
        """a review finding/a review finding: the expiry vet fired via a session binding
        must never destroy the machine-wide bookmark."""
        self._make_expired_machine_project("corpus-999")
        sessions.record_session("corpus-999", pid=os.getpid())
        self.assertIsNone(self.mgr.get_active())
        # Binding re-bound to none...
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), (None, "none"))
        # ...bookmark untouched.
        self.assertEqual(
            os.readlink(self.projects_dir / ".active"),
            "bookmark-proj.json")

    def test_expired_bookmark_unlinks_symlink(self):
        self._make_expired_machine_project("corpus-888")
        self.mgr.set_active("corpus-888")
        self.assertIsNone(self.mgr.get_active())
        self.assertFalse(
            (self.projects_dir / ".active").is_symlink())


class ProjectMutationHygieneTest(unittest.TestCase):
    """delete/rename binding hygiene + the purge live-run guard
   ."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        (root / "code").mkdir()
        # Output under the expected base so purge containment passes.
        from core.project.project import DEFAULT_OUTPUT_BASE
        self.out_base = DEFAULT_OUTPUT_BASE / f"_test-{os.getpid()}"
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.out_base, ignore_errors=True))
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("victim", str(root / "code"),
                        output_dir=str(self.out_base / "victim"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def test_delete_nulls_live_bindings(self):
        sessions.record_session("victim", pid=os.getpid())
        self.mgr.delete("victim")
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), (None, "none"))

    def test_rename_repoints_live_bindings(self):
        sessions.record_session("victim", pid=os.getpid())
        self.mgr.rename("victim", "renamed")
        name, state = sessions.session_binding(pid=os.getpid())
        self.assertEqual((name, state), ("renamed", "bound"))

    def test_purge_refuses_on_live_run(self):
        from core.json import save_json
        run = Path(self.mgr.load("victim").output_dir) / "scan-live"
        run.mkdir(parents=True)
        save_json(run / ".raptor-run.json", {
            "status": "running", "tool_pid": os.getpid(),
        })
        with self.assertRaises(ValueError):
            self.mgr.delete("victim", purge=True)
        # force overrides.
        self.mgr.delete("victim", purge=True, force=True)
        self.assertFalse(run.exists())


@unittest.skipIf(sys.platform == "win32", "bash launcher")
class LauncherSeedV2Test(LauncherAwarenessTest):
    """The v2 mandatory seed: identity-stamped entry,
    exported env credential, seed even with an empty bookmark."""

    def test_seed_is_v2_with_identity_and_credential(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            # Stub claude echoes the exported credential.
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout)
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            own = [f for f in sessions_dir.iterdir() if f.name.isdigit()]
            self.assertEqual(len(own), 1, list(sessions_dir.iterdir()))
            text = own[0].read_text(encoding="utf-8")
            self.assertIn("v=2", text)
            self.assertIn("project=myapp", text)
            self.assertIn("seeded_by=bookmark", text)
            self.assertIn("starttime=", text)
            self.assertIn("boot_id=", text)
            self.assertIn("token=", text)
            self.assertEqual(own[0].stat().st_mode & 0o777, 0o600)

    def test_empty_bookmark_seeds_projectless_sentinel(self):
        """a review finding: a launch with NO active project still writes an
        entry — 'project=-' — so the session is insulated from later
        bookmark moves by other sessions."""
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout,
                          (r.stdout, r.stderr))
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            own = [f for f in sessions_dir.iterdir() if f.name.isdigit()]
            self.assertEqual(len(own), 1)
            text = own[0].read_text(encoding="utf-8")
            self.assertIn("project=-", text)
            self.assertIn("v=2", text)

    def test_startup_check_sentinel_never_reaches_terminal_stdout(self):
        """The launcher consumes startup-check stdout — the sentinel
        line must not leak into what the operator sees."""
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            r = self._launch(home, tmpdir)
            self.assertNotIn("RAPTOR_RESOLVED_PROJECT", r.stdout)
            self.assertNotIn("RAPTOR_RESOLVED_PROJECT", r.stderr)
