"""Narrowed best-effort handlers in JoernServer.stop().

Representative fails-before coverage for the suppress(Exception)
narrowing sweep in packages/joern: the http-client close during
stop() used to eat *any* exception; after narrowing only OSError
(socket teardown) is suppressed, so a miswired call surfaces.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from packages.joern.server import JoernServer


def _server_with_fake_proc() -> JoernServer:
    srv = JoernServer()
    proc = MagicMock()
    # A pid that cannot exist forces the ProcessLookupError fallback in
    # _signal_group, so no real signal is ever sent.
    proc.pid = 2**22 + 12345
    proc.wait.return_value = 0
    srv._proc = proc
    return srv


class TestStopHttpClientCloseNarrowing:
    def test_miswiring_class_exception_propagates(self):
        srv = _server_with_fake_proc()
        client = MagicMock()
        client.close.side_effect = TypeError("close() takes no arguments")
        srv._http_client = client
        with pytest.raises(TypeError):
            srv.stop()

    def test_oserror_on_close_still_suppressed(self):
        srv = _server_with_fake_proc()
        client = MagicMock()
        client.close.side_effect = OSError("transport already torn down")
        srv._http_client = client
        srv.stop()
        assert srv._http_client is None
        assert srv._proc is None
