"""Per-lane scoping of the egress proxy's audit-log-only mode.

The audit leniency used to be a process-global flag: while ANY audit
sandbox was active, every consumer of the proxy singleton — concurrent
non-audit sandboxes and in-process HTTP/LLM clients alike — had gate 1
downgraded to allow-and-log. Lanes scope the decision to the transport
the connection arrived on: per-context unix sockets (netns tier) and
per-context TCP listeners (Landlock-TCP / seatbelt tiers) carry their
own audit bit; the shared main listener has no lane and stays
enforcing.
"""

import os
import socket

import pytest

import core.sandbox.proxy as proxy_mod

pytestmark = pytest.mark.skipif(
    os.environ.get("RAPTOR_SKIP_PROXY_TESTS") == "1",
    reason="proxy tests disabled",
)

_DENIED = "denied.invalid:443"


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _connect_tcp(port: int, target: str, timeout: float = 5.0) -> int:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        return _drive_connect(s, target)
    finally:
        s.close()


def _connect_unix(path: str, target: str, timeout: float = 5.0) -> int:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    try:
        return _drive_connect(s, target)
    finally:
        s.close()


def _drive_connect(s: socket.socket, target: str) -> int:
    s.sendall((f"CONNECT {target} HTTP/1.1\r\n"
               f"Host: {target}\r\n\r\n").encode("latin-1"))
    buf = b""
    while b"\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = line.split(None, 2)
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0


class TestUnixLaneIsolation:
    def test_audit_bit_scoped_to_one_lane(self, reset_proxy, tmp_path):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        path_a = str(tmp_path / "a.sock")
        path_b = str(tmp_path / "b.sock")
        try:
            proxy.bind_unix(path_a, label="audit-ctx")
            proxy.bind_unix(path_b, label="normal-ctx")
            assert proxy.set_lane_audit(path_a, True) is True

            token = proxy.register_sandbox(caller_label="lane-test")

            # Audit lane: would-deny falls through to the connect
            # attempt (guaranteed-failing .invalid DNS -> 502-ish,
            # never the gate's 403).
            assert _connect_unix(path_a, _DENIED) != 403
            # Sibling lane and the main listener stay enforcing.
            assert _connect_unix(path_b, _DENIED) == 403
            assert _connect_tcp(proxy.port, _DENIED) == 403

            events = proxy.unregister_sandbox(token)
            would = [e for e in events
                     if e.get("result") == "would_deny_host"]
            denied = [e for e in events
                      if e.get("result") == "denied_host"]
            assert len(would) == 1
            assert would[0].get("lane") == "audit-ctx"
            assert {e.get("lane") for e in denied} == {
                "normal-ctx", "main"}
        finally:
            proxy.stop()

    def test_unbound_lane_key_returns_false(self, reset_proxy, tmp_path):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            assert proxy.set_lane_audit(str(tmp_path / "no.sock"),
                                        True) is False
            assert proxy.set_lane_audit(65001, True) is False
        finally:
            proxy.stop()

    def test_in_flight_connection_keeps_its_lane(self, reset_proxy,
                                                 tmp_path):
        # W5: a connection ACCEPTED before unbind is decided by the
        # lane object captured at accept time — deterministic, no
        # enforce/lenient flapping during teardown.
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        path = str(tmp_path / "w5.sock")
        try:
            proxy.bind_unix(path, label="w5")
            assert proxy.set_lane_audit(path, True) is True
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(path)
            # Deterministic ACCEPTED-before-unbind ordering: wait for
            # the handler task to exist. (A connection still sitting
            # in the backlog at close time is simply never served —
            # verified separately — which also fails closed.)
            import time as _time
            deadline = _time.monotonic() + 5.0
            while not proxy._unix_tasks and _time.monotonic() < deadline:
                _time.sleep(0.01)
            assert proxy._unix_tasks, "handler never accepted"
            try:
                proxy.unbind_unix(path)
                # Lane registry entry is gone...
                assert proxy.set_lane_audit(path, True) is False
                # ...but the accepted connection still carries it.
                assert _drive_connect(s, _DENIED) != 403
            finally:
                s.close()
        finally:
            proxy.stop()


class TestTcpLanes:
    def test_tcp_lane_scoping_and_lifecycle(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            port = proxy.bind_tcp_lane(label="tier2-ctx")
            assert port != proxy.port
            assert proxy.set_lane_audit(port, True) is True
            assert _connect_tcp(port, _DENIED) != 403
            assert _connect_tcp(proxy.port, _DENIED) == 403

            proxy.close_tcp_lane(port)
            assert proxy.set_lane_audit(port, True) is False
            with pytest.raises(OSError):
                socket.create_connection(("127.0.0.1", port),
                                         timeout=1.0)
            # Idempotent.
            proxy.close_tcp_lane(port)
        finally:
            proxy.stop()

    def test_lane_churn_leaves_no_residue(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            for _ in range(30):
                port = proxy.bind_tcp_lane(label="churn")
                proxy.close_tcp_lane(port)
            assert not proxy._tcp_lanes
            assert not proxy._tcp_lane_servers
        finally:
            proxy.stop()


class TestContextWiring:
    """The sandbox() context engages lanes, never the global flag."""

    def _fake_proxy(self):
        class _Fake:
            port = 18080

            def __init__(self):
                self.calls = []

            def bind_unix(self, path, *, label="sandbox"):
                self.calls.append(("bind_unix", path, label))

            def unbind_unix(self, path):
                self.calls.append(("unbind_unix", path))

            def bind_tcp_lane(self, *, label="sandbox"):
                self.calls.append(("bind_tcp_lane", label))
                return 18081

            def close_tcp_lane(self, port):
                self.calls.append(("close_tcp_lane", port))

            def set_lane_audit(self, key, value):
                self.calls.append(("set_lane_audit", key, value))
                return True

            def acquire_audit_log_only(self):
                self.calls.append(("acquire_audit",))

            def release_audit_log_only(self):
                self.calls.append(("release_audit",))

            def register_sandbox(self, caller_label=None):
                self.calls.append(("register", caller_label))
                return 1

            def unregister_sandbox(self, token):
                self.calls.append(("unregister", token))
                return []

            def add_hosts(self, hosts):
                self.calls.append(("add_hosts", tuple(sorted(hosts))))

            def update_idle_timeout(self, seconds):
                pass

        return _Fake()

    def test_tier2_audit_uses_tcp_lane_not_global(self, tmp_path,
                                                  monkeypatch):
        import core.sandbox.context as ctx
        fake = self._fake_proxy()
        monkeypatch.setattr(proxy_mod, "get_proxy",
                            lambda *a, **k: fake)
        # Force the Landlock-TCP tier: no netns capability.
        monkeypatch.setattr(ctx, "check_net_available", lambda: False)
        with ctx.sandbox(use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         audit=True, output=str(tmp_path)):
            pass
        names = [c[0] for c in fake.calls]
        assert "acquire_audit" not in names
        assert "release_audit" not in names
        assert ("bind_tcp_lane", "sandbox") in fake.calls
        assert ("set_lane_audit", 18081, True) in fake.calls
        # Teardown clears the bit and closes the lane.
        assert ("set_lane_audit", 18081, False) in fake.calls
        assert ("close_tcp_lane", 18081) in fake.calls
