"""Batch taint-query transport contract.

/query-sync drops println output and truncates responses flooded by
huge top-level val echoes, so run_taint_queries_batch must return its
flows through the final string expression's REPL echo — the same
transport tiered_taint.sc and _build_taint_query use.
"""

from __future__ import annotations


class TestBatchQueryTransport:
    def _server_with_capture(self):
        from packages.joern.server import JoernServer
        srv = JoernServer.__new__(JoernServer)
        srv._query_timeout_s = 1
        captured = {}

        class _Result:
            errors = []
            flows = []

        srv.query = (  # noqa: SLF001 — test seam
            lambda q, **kw: captured.update(script=q) or _Result()
        )
        return srv, captured

    def test_batch_transport_contract(self):
        # /query-sync drops println output and truncates on huge val
        # echoes: flows must ride the final string expression, pairs
        # must run inside locally{} so no intermediate val echoes.
        srv, captured = self._server_with_capture()
        srv.run_taint_queries_batch([("src_fn", "sink_fn")])
        script = captured["script"]
        assert "println(" not in script
        assert script.rstrip().endswith(
            '"JOERN_FLOWS_START\\n" + raptorBatchLines.mkString("\\n") '
            '+ "\\nJOERN_FLOWS_END"'
        )
        assert "locally {\nval src0" in script
        # Single interpolator dollars — $$ would print literal $ln.
        assert "$$" not in script
