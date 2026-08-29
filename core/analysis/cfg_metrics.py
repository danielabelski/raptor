"""Scalar complexity metrics over flow graphs.

Companion to :mod:`core.analysis.dominators` and
:mod:`core.analysis.cfg_builder`: those modules produce and consume
``Graph``-protocol flow graphs; this one reduces such a graph to a
scalar complexity signal. Dependency-free and pure — safe to call from
any producer (Python intra-procedural CFGs, binary basic-block CFGs,
call graphs).

The one metric provided is the cyclomatic number. It earned the slot
empirically: a head-to-head evaluation against path homology's
direction-aware ``beta_1`` (Huntsman, "Path homology as a stronger
analogue of cyclomatic complexity", arXiv:2003.00944, 2020) on 8,459
functions across six real binaries found plain cyclomatic complexity
marginally better at ranking dangerous-sink-reaching functions
(AUC 0.707 vs 0.693) and far cheaper to compute.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from collections.abc import Hashable, Iterable

N = TypeVar("N", bound=Hashable)


class GraphLike(Protocol[N]):
    """The subset of :class:`core.analysis.dominators.Graph` a scalar
    metric needs — no ``entry``, since the metrics are global over the
    edge set rather than rooted."""

    def nodes(self) -> Iterable[N]: ...

    def successors(self, node: N) -> Iterable[N]: ...


def _normalise(graph: GraphLike[N]) -> tuple[int, list[list[int]]]:
    """Materialise ``graph`` into ``(vertex_count, successor rows)`` keyed
    by vertex index. Duplicate edges are collapsed; successors pointing
    outside ``nodes()`` are ignored. Self-loops are KEPT — a block that
    branches to itself is a real edge (a single-block spin loop must
    count as one decision, per McCabe)."""
    nodes = list(dict.fromkeys(graph.nodes()))
    idx = {n: i for i, n in enumerate(nodes)}
    succ_idx: list[list[int]] = []
    for n in nodes:
        seen: set[int] = set()
        row: list[int] = []
        for m in graph.successors(n):
            j = idx.get(m)
            if j is None or j in seen:
                continue
            seen.add(j)
            row.append(j)
        succ_idx.append(row)
    return len(nodes), succ_idx


def cyclomatic_number(graph: GraphLike[N]) -> int:
    """Cyclomatic number ``|E| - |V| + c`` of ``graph`` over the
    *directed* edge set (``c`` = weakly-connected components).

    This is the first Betti number of the underlying undirected graph —
    the count of independent cycles — computed with McCabe's edge
    conventions: anti-parallel edges ``a -> b`` and ``b -> a`` are counted
    separately, duplicate edges are collapsed, and self-loops count as
    edges (a single-block spin loop has cyclomatic number 1). For a
    connected single-entry/single-exit CFG this equals McCabe's
    ``E - V + 2P`` minus 1; to reproduce ``E - V + 2P`` exactly, add the
    virtual exit-to-entry arc (McCabe's strongly-connected convention)
    before calling.

    Empty graph returns 0.
    """
    v, succ_idx = _normalise(graph)
    if v == 0:
        return 0
    n_edges = sum(len(row) for row in succ_idx)

    # Weakly-connected components via union-find (self-loops are
    # connectivity no-ops but still counted in n_edges above).
    parent = list(range(v))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(v):
        for j in succ_idx[i]:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj
    components = sum(1 for i in range(v) if find(i) == i)
    return n_edges - v + components


__all__ = [
    "GraphLike",
    "cyclomatic_number",
]
