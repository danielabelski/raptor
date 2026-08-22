"""Per-lane destination-port allowlist (gate 1b).

The networked untrusted helper promises "the listed hosts on port
443", but hostname authorisation alone let a child CONNECT to any
1-65535 port on an allowlisted host (the local allowed_tcp_ports pin
is replaced by the lane listener port on the TCP tier, so it never
bounded the DESTINATION port). Lanes now carry a caller-declared port
allowlist, enforced before DNS resolution and never subject to
audit-mode leniency (gate-2 semantics).
"""

import os
import socket

import pytest

import core.sandbox.proxy as proxy_mod

pytestmark = pytest.mark.skipif(
    os.environ.get("RAPTOR_SKIP_PROXY_TESTS") == "1",
    reason="proxy tests disabled",
)

_HOST = "portal.example"


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _connect_tcp(port: int, target: str, timeout: float = 5.0) -> int:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
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
        line = buf.split(b"\r\n", 1)[0].decode("latin-1",
                                               errors="replace")
        parts = line.split(None, 2)
        return (int(parts[1])
                if len(parts) >= 2 and parts[1].isdigit() else 0)
    finally:
        s.close()


class TestLanePortAllowlist:
    def test_non_allowlisted_port_denied_before_dns(self, reset_proxy):
        """An allowlisted HOST on a non-declared PORT must be refused
        — pre-fix this CONNECT sailed through gate 1 to DNS/dial."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={_HOST})
        try:
            port = proxy.bind_tcp_lane(label="untrusted-networked",
                                       allowed_ports=[443])
            # The deny fires BEFORE resolution, so the unresolvable
            # test hostname is irrelevant: 403 proves the port gate.
            assert _connect_tcp(port, f"{_HOST}:8443") == 403
            assert _connect_tcp(port, f"{_HOST}:22") == 403
        finally:
            proxy.stop()

    def test_declared_port_admitted_past_the_gate(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={_HOST})
        try:
            port = proxy.bind_tcp_lane(label="untrusted-networked",
                                       allowed_ports=[443])
            # 443 passes gates 1/1b; the unresolvable name then fails
            # at DNS — anything but 403 proves the gate admitted it.
            assert _connect_tcp(port, f"{_HOST}:443") != 403
        finally:
            proxy.stop()

    def test_lane_without_port_contract_unchanged(self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={_HOST})
        try:
            port = proxy.bind_tcp_lane(label="legacy")
            assert _connect_tcp(port, f"{_HOST}:8443") != 403
        finally:
            proxy.stop()

    def test_port_gate_ignores_audit_leniency(self, reset_proxy):
        """Audit mode may allow unknown HOSTS (learning), but the
        caller-declared port contract stays enforcing (gate-2
        semantics)."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={_HOST})
        try:
            port = proxy.bind_tcp_lane(label="audit-ctx",
                                       allowed_ports=[443])
            assert proxy.set_lane_audit(port, True) is True
            assert _connect_tcp(port, f"{_HOST}:8443") == 403
        finally:
            proxy.stop()

    def test_unix_lane_carries_port_contract(self, reset_proxy,
                                             tmp_path):
        proxy = proxy_mod.EgressProxy(allowed_hosts={_HOST})
        try:
            sock_path = str(tmp_path / "lane.sock")
            proxy.bind_unix(sock_path, label="netns-ctx",
                            allowed_ports=[443])
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(sock_path)
            try:
                s.sendall((f"CONNECT {_HOST}:8443 HTTP/1.1\r\n"
                           f"Host: {_HOST}:8443\r\n\r\n").encode())
                buf = s.recv(4096)
            finally:
                s.close()
            assert b" 403 " in buf.split(b"\r\n", 1)[0]
        finally:
            proxy.stop()
