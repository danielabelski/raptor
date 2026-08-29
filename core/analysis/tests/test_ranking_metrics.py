"""Tests for threshold-free ranking metrics."""

import random

import pytest

from core.analysis.ranking_metrics import auc


class TestAuc:
    def test_perfect_separation(self):
        assert auc([(1.0, True), (0.0, False)]) == 1.0
        assert auc([(3, True), (2, True), (1, False), (0, False)]) == 1.0

    def test_perfectly_inverted(self):
        assert auc([(0.0, True), (1.0, False)]) == 0.0

    def test_tie_is_half(self):
        assert auc([(1.0, True), (1.0, False)]) == 0.5

    def test_constant_score_is_chance(self):
        scored = [(7.0, i % 2 == 0) for i in range(10)]
        assert auc(scored) == 0.5

    def test_undefined_when_one_class_empty(self):
        assert auc([]) is None
        assert auc([(1.0, True)]) is None
        assert auc([(1.0, False), (2.0, False)]) is None

    def test_hand_computed_mixed_case(self):
        # scores: pos {3, 1}, neg {2, 0}.
        # Pairs (pos vs neg): 3>2 win, 3>0 win, 1<2 loss, 1>0 win
        # -> 3/4 = 0.75.
        assert auc([(3, True), (1, True), (2, False), (0, False)]) == 0.75

    def test_hand_computed_with_partial_ties(self):
        # pos {2, 1}, neg {2, 0}: 2v2 tie (0.5), 2>0 win, 1<2 loss,
        # 1>0 win -> 2.5/4 = 0.625.
        assert auc([(2, True), (1, True), (2, False), (0, False)]) == 0.625

    def test_order_invariant(self):
        scored = [(2, True), (1, True), (2, False), (0, False), (5, True)]
        rng = random.Random(42)
        expected = auc(scored)
        for _ in range(10):
            shuffled = scored[:]
            rng.shuffle(shuffled)
            assert auc(shuffled) == expected

    def test_equals_pairwise_definition_on_random_data(self):
        # Cross-check against the O(n^2) pairwise definition.
        rng = random.Random(1234)
        scored = [
            (rng.randint(0, 5), rng.random() < 0.4)
            for _ in range(60)
        ]
        pos = [s for s, lab in scored if lab]
        neg = [s for s, lab in scored if not lab]
        wins = sum(
            1.0 if p > n else 0.5 if p == n else 0.0
            for p in pos for n in neg
        )
        expected = wins / (len(pos) * len(neg))
        assert auc(scored) == pytest.approx(expected)

    def test_int_and_float_scores_mix(self):
        assert auc([(1, True), (0.5, False)]) == 1.0
