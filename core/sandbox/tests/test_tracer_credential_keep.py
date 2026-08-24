"""Credential-path pre-budget lane on the Linux tracer path.

The file-open budget category has a small burst cap and — by
documented design — no post-cap sampling. Pre-fix, a target that
flooded that bucket could then open ~/.ssh/id_rsa with no live AND no
durable record on Linux, while macOS fires its stderr banner before
its budget (seatbelt_audit._maybe_escalate_credential_path). The lane
under test restores parity: the credential-path match is evaluated
BEFORE the allowlist filter and BEFORE budget.evaluate. Two
independent per-path dedups: the stderr banner fires on the first
SIGHTING (filter outcome irrespective, like macOS); the guaranteed
JSONL keep is consumed only by the first FILTER-SURVIVING touch.
Both are bounded by a distinct-path cap; keep-lane exhaustion is
announced with an in-band marker.

All tests drive _handle_waitpid_event with the same synthetic-helper
injection points test_audit_filter.py uses — no real ptrace, no forked
children, hermetic on any host.
"""

import json
import sys

import pytest

import core.sandbox.audit_budget as audit_budget
import core.sandbox.tracer as tracer_mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="ptrace tracer is Linux-only",
)

_CRED_PATH = "/home/user/.ssh/id_rsa"


def _seccomp_event_status() -> int:
    import signal
    return ((tracer_mod._PTRACE_EVENT_SECCOMP << 16)
            | (signal.SIGTRAP << 8) | 0x7f)


def _flooded_budget() -> audit_budget.AuditBudget:
    """A budget whose file-open bucket is tiny and never refills."""
    return audit_budget.AuditBudget(
        category_caps={"file-open": 2},
        refill_rates={"file-open": 0.0},
        clock=lambda: 0.0,
    )


class _Harness:
    """One tracer dispatch harness: fake ptrace helpers + a recorded
    list capturing write_record calls."""

    def __init__(self):
        self.recorded: list = []
        self.arch_info = tracer_mod._ARCH_INFO[tracer_mod._ARCH]
        self._nr = 257 if tracer_mod._ARCH == "x86_64" else 56
        self._path = "/etc/hostname"

    def helpers(self, flags: int = 0) -> dict:
        args = [tracer_mod._AT_FDCWD & 0xffffffffffffffff,
                0x1000, flags, 0, 0, 0]

        def fake_write_record(run_dir, name, n, a, target_pid,
                              path=None, *, filename=None,
                              mode_field=None, nonce=None):
            self.recorded.append({"name": name, "path": path})
            return True

        return {
            "ptrace_cont": lambda pid, sig=0: True,
            "read_regs": lambda pid, ai: (
                b"\x00" * ai["user_regs_size"]),
            "decode_syscall": lambda regs, ai: (self._nr, list(args)),
            "read_tracee_string": (
                lambda pid, addr, max_bytes=4096: self._path),
            "read_tracee_bytes": lambda pid, addr, n: None,
            "get_event_msg": lambda pid: None,
            "write_record": fake_write_record,
            "resolve_path": (
                lambda pid, path, dirfd: path
                if path.startswith("/") else f"/cwd/{path}"),
            "decode_sockaddr": (
                lambda pid, addr, addrlen: ("AF_INET", 443,
                                            "1.2.3.4")),
        }

    def open_event(self, tmp_path, budget, cred_state, path,
                   pid=1000, flags=0, audit_filter=None):
        """Dispatch one synthetic openat(path) through the tracer.

        Default audit_filter=None (no filter: every record survives
        to the budget site, isolating budget-vs-lane behaviour);
        pass a filter dict + write flags to exercise the filter
        ordering."""
        self._path = path
        tracer_mod._handle_waitpid_event(
            pid, _seccomp_event_status(),
            {pid}, pid, self.arch_info,
            tmp_path, budget,
            audit_filter=audit_filter,
            credential_state=cred_state,
            **self.helpers(flags=flags),
        )


def _fresh_state() -> dict:
    return {"announced": set(), "kept": set(), "overflowed": 0,
            "banner_capped": False}


def _flood(h, tmp_path, budget, state):
    """Exhaust the file-open bucket with non-credential opens."""
    for i in range(4):
        h.open_event(tmp_path, budget, state, f"/data/file{i}")


class TestCredentialKeepSurvivesFlood:
    def test_flooded_budget_drops_ordinary_open(self, tmp_path):
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        _flood(h, tmp_path, budget, state)
        # Bucket cap is 2: only the first two landed.
        assert len(h.recorded) == 2

    def test_credential_record_kept_after_flood(self, tmp_path,
                                                capfd):
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        _flood(h, tmp_path, budget, state)
        h.open_event(tmp_path, budget, state, _CRED_PATH)
        paths = [r["path"] for r in h.recorded]
        assert _CRED_PATH in paths, (
            "credential-path open must survive a flooded file-open "
            "bucket — durable-record parity with the macOS pre-budget "
            "escalation")
        # Live signal fired too, same wording family as macOS.
        err = capfd.readouterr().err
        assert "credential-looking path touched" in err
        assert "id_rsa" in err

    def test_guaranteed_keep_does_not_consume_budget(self, tmp_path):
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        h.open_event(tmp_path, budget, state, _CRED_PATH)
        # The pre-budget keep bypasses evaluate() entirely.
        assert budget.total_records == 0
        assert [r["path"] for r in h.recorded] == [_CRED_PATH]

    def test_repeat_touch_flows_through_budget(self, tmp_path):
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        h.open_event(tmp_path, budget, state, _CRED_PATH)  # lane keep
        _flood(h, tmp_path, budget, state)                 # exhaust
        before = len(h.recorded)
        h.open_event(tmp_path, budget, state, _CRED_PATH)  # repeat
        assert len(h.recorded) == before, (
            "repeat touches of an already-recorded credential path "
            "must obey the normal budget — the lane dedups per path")

    def test_banner_once_per_path(self, tmp_path, capfd):
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        h.open_event(tmp_path, budget, state, _CRED_PATH)
        h.open_event(tmp_path, budget, state, _CRED_PATH)
        err = capfd.readouterr().err
        assert err.count("credential-looking path touched") == 1

    def test_live_escalation_disabled_suppresses_banner_not_keep(
            self, tmp_path, capfd, monkeypatch):
        monkeypatch.setattr(tracer_mod.audit_budget,
                            "live_escalation_disabled",
                            lambda: True)
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        _flood(h, tmp_path, budget, state)
        h.open_event(tmp_path, budget, state, _CRED_PATH)
        assert "credential-looking" not in capfd.readouterr().err
        assert _CRED_PATH in [r["path"] for r in h.recorded], (
            "disabling live escalation must not cost the durable "
            "record")


class TestFilterOrdering:
    def test_filtered_sighting_does_not_burn_keep_guarantee(
            self, tmp_path, capfd):
        """An in-allowlist read of a credential path is filter-
        suppressed (would-be-allowed under enforcement) — it must
        announce (live parity) but NOT consume the path's guaranteed
        keep: a later out-of-policy touch of the SAME path against a
        flooded budget still gets its durable record."""
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        filt = {
            "verbose": False,
            "writable_paths": [str(tmp_path)],
            "read_allowlist": ["/home"],
            "allowed_tcp_ports": [],
        }
        # Read-intent, inside the read allowlist -> suppressed.
        h.open_event(tmp_path, budget, state, _CRED_PATH,
                     audit_filter=filt)
        assert h.recorded == []
        assert ("credential-looking path touched"
                in capfd.readouterr().err)
        # Flood the bucket, then a WRITE-intent open (O_WRONLY=1)
        # outside writable_paths -> the filter keeps it; the keep
        # lane must too, despite the earlier suppressed sighting.
        _flood(h, tmp_path, budget, state)
        h.open_event(tmp_path, budget, state, _CRED_PATH,
                     flags=0x1, audit_filter=filt)
        assert _CRED_PATH in [r["path"] for r in h.recorded], (
            "a filter-suppressed sighting burned the guaranteed "
            "keep for a later out-of-policy touch")
        # Banner stays deduped per sighting.
        assert ("credential-looking"
                not in capfd.readouterr().err)


class TestCredentialKeepLaneBounded:
    def _drive_distinct(self, h, tmp_path, budget, state, n):
        for i in range(n):
            h.open_event(tmp_path, budget, state,
                         f"/home/u{i}/.ssh/id_rsa")

    def test_lane_cap_enforced_with_marker(self, tmp_path,
                                           monkeypatch):
        monkeypatch.setattr(tracer_mod, "_CRED_KEEP_MAX_PATHS", 3)
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        _flood(h, tmp_path, budget, state)   # bucket empty
        self._drive_distinct(h, tmp_path, budget, state, 5)
        cred_paths = [r["path"] for r in h.recorded
                      if r["path"] and ".ssh" in r["path"]]
        assert len(cred_paths) == 3, (
            "attacker-minted distinct credential-lookalike names "
            "must not turn the bypass lane into an unbounded flood "
            "channel")
        assert state["overflowed"] == 2
        # The exhaustion is announced in-band, never silent: the
        # marker is written through the real _write_record_dict while
        # data records go through the faked write_record, so the
        # JSONL contains exactly the control-plane entry.
        jsonl = (tmp_path / tracer_mod.AUDIT_SUBDIR
                 / ".sandbox-denials.jsonl")
        assert jsonl.exists(), "lane-cap marker missing from JSONL"
        records = [json.loads(line) for line in
                   jsonl.read_text().splitlines() if line.strip()]
        markers = [r for r in records
                   if r.get("type") == "credential_keep_cap_exceeded"]
        assert len(markers) == 1, "marker must be one-shot"
        assert markers[0]["cap"] == 3

    def test_banner_cap_announced_once(self, tmp_path, monkeypatch,
                                       capfd):
        """Banner-lane exhaustion must not be silent: one stderr
        notice when the first banner is suppressed, then quiet."""
        monkeypatch.setattr(tracer_mod, "_CRED_KEEP_MAX_PATHS", 2)
        h = _Harness()
        budget = audit_budget.AuditBudget()
        state = _fresh_state()
        self._drive_distinct(h, tmp_path, budget, state, 5)
        err = capfd.readouterr().err
        assert err.count("credential-looking path touched") == 2
        assert err.count("banner lane reached its distinct-path "
                         "cap") == 1
        assert state["banner_capped"] is True

    def test_marker_type_is_triage_control_plane(self):
        """The lane-cap marker rides the denials JSONL into
        sandbox-summary.json; triage must classify it as a
        control-plane record, not an enforcement denial."""
        from core.sandbox import triage
        assert ("credential_keep_cap_exceeded"
                in triage._BUDGET_MARKER_TYPES)

    def test_no_marker_below_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(tracer_mod, "_CRED_KEEP_MAX_PATHS", 3)
        h = _Harness()
        budget = _flooded_budget()
        state = _fresh_state()
        self._drive_distinct(h, tmp_path, budget, state, 2)
        jsonl = (tmp_path / tracer_mod.AUDIT_SUBDIR
                 / ".sandbox-denials.jsonl")
        if jsonl.exists():
            records = [json.loads(line) for line in
                       jsonl.read_text().splitlines()
                       if line.strip()]
            assert not any(
                r.get("type") == "credential_keep_cap_exceeded"
                for r in records)


class TestNonCredentialUnaffected:
    def test_plain_open_unchanged(self, tmp_path, capfd):
        h = _Harness()
        budget = audit_budget.AuditBudget()
        state = _fresh_state()
        h.open_event(tmp_path, budget, state, "/etc/hostname")
        assert [r["path"] for r in h.recorded] == ["/etc/hostname"]
        assert budget.total_records == 1
        assert "credential-looking" not in capfd.readouterr().err

    def test_none_state_is_safe(self, tmp_path):
        # Callers that don't thread the lane state (older embedders,
        # direct test drives) must keep working with lane disabled.
        h = _Harness()
        budget = audit_budget.AuditBudget()
        h.open_event(tmp_path, budget, None, _CRED_PATH)
        assert [r["path"] for r in h.recorded] == [_CRED_PATH]
        assert budget.total_records == 1
