"""Tests for scalar CFG complexity metrics.

Pure-graph tests: a tiny adjacency-backed ``GraphLike`` stands in for
the real producers (Python CFGs, binary basic-block CFGs), so these run
with no external tooling.
"""

from core.analysis.cfg_metrics import cyclomatic_number


class _Adj:
    """Minimal GraphLike over a ``{node: [successors]}`` mapping."""

    def __init__(self, adjacency):
        self._adj = adjacency

    def nodes(self):
        return list(self._adj.keys())

    def successors(self, node):
        return self._adj.get(node, [])


class TestCyclomaticNumber:
    def test_empty_graph_is_zero(self):
        assert cyclomatic_number(_Adj({})) == 0

    def test_single_node_no_edges_is_zero(self):
        assert cyclomatic_number(_Adj({0: []})) == 0

    def test_straight_line_is_zero(self):
        assert cyclomatic_number(_Adj({0: [1], 1: [2], 2: []})) == 0

    def test_single_node_self_loop_is_one(self):
        # McCabe regression: a single-block spin loop is one decision.
        # (The pre-carve extraction dropped self-edges and reported 0.)
        assert cyclomatic_number(_Adj({0: [0]})) == 1

    def test_self_loop_plus_exit(self):
        # spin block with an exit edge: E=2, V=2, c=1 -> 1.
        assert cyclomatic_number(_Adj({0: [0, 1], 1: []})) == 1

    def test_if_else_diamond_is_one(self):
        # E=4, V=4, c=1 -> 1 (one independent undirected cycle).
        assert cyclomatic_number(_Adj({0: [1, 2], 1: [3], 2: [3], 3: []})) == 1

    def test_while_loop_is_one(self):
        # entry -> head -> {body, exit}; body -> head. E=4, V=4, c=1 -> 1.
        assert cyclomatic_number(_Adj({0: [1], 1: [2, 3], 2: [1], 3: []})) == 1

    def test_two_independent_cycles(self):
        # two back-to-back while loops: E=7, V=6, c=1 -> 2.
        adj = {0: [1], 1: [2, 3], 2: [1], 3: [4, 5], 4: [3], 5: []}
        assert cyclomatic_number(_Adj(adj)) == 2

    def test_anti_parallel_edges_count_separately(self):
        # a -> b and b -> a form one undirected cycle: E=2, V=2, c=1 -> 1.
        assert cyclomatic_number(_Adj({0: [1], 1: [0]})) == 1

    def test_duplicate_edges_collapsed(self):
        assert cyclomatic_number(_Adj({0: [1, 1, 1], 1: []})) == 0

    def test_successors_outside_nodes_ignored(self):
        # 99 never appears in nodes(); the dangling edge must not count.
        assert cyclomatic_number(_Adj({0: [1, 99], 1: []})) == 0

    def test_disconnected_components(self):
        # two straight-line components: E=2, V=4, c=2 -> 0.
        assert cyclomatic_number(_Adj({0: [1], 1: [], 2: [3], 3: []})) == 0
        # add a cycle to one component: E=3, V=4, c=2 -> 1.
        assert cyclomatic_number(_Adj({0: [1], 1: [0], 2: [3], 3: []})) == 1

    def test_accepts_dominators_graph_producers(self):
        # The real Graph-protocol producers (which also carry `entry`)
        # satisfy GraphLike structurally.
        class _Rooted(_Adj):
            @property
            def entry(self):
                return 0

        assert cyclomatic_number(_Rooted({0: [1, 2], 1: [3], 2: [3], 3: []})) == 1
