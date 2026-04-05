"""Tests for src.utils.spa_detector — SPA detection helper functions."""

from src.utils.spa_detector import _body_hash, _similarity


class TestBodyHash:
    def test_deterministic(self):
        data = b"hello world"
        assert _body_hash(data) == _body_hash(data)

    def test_strips_whitespace(self):
        assert _body_hash(b"  hello  ") == _body_hash(b"hello")

    def test_different_content(self):
        assert _body_hash(b"aaa") != _body_hash(b"bbb")


class TestSimilarity:
    def test_identical(self):
        data = b"same content here"
        assert _similarity(data, data) == 1.0

    def test_empty_a(self):
        assert _similarity(b"", b"test") == 0.0

    def test_empty_b(self):
        assert _similarity(b"test", b"") == 0.0

    def test_both_empty(self):
        assert _similarity(b"", b"") == 0.0

    def test_very_different_lengths(self):
        short = b"ab"
        long = b"a" * 100
        score = _similarity(short, long)
        assert score < 0.7  # len_ratio < 0.7, returned directly

    def test_same_hash_different_objects(self):
        a = b"hello world"
        b = b"hello world"
        assert _similarity(a, b) == 1.0

    def test_head_and_tail_match(self):
        # Build two ~3KB bodies with same head/tail (2048 bytes each)
        head = b"A" * 2048
        tail = b"Z" * 2048
        a = head + b"X" * 500 + tail
        b_data = head + b"Y" * 500 + tail
        score = _similarity(a, b_data)
        assert score >= 0.90  # head+tail match → 0.95

    def test_only_head_match(self):
        head = b"A" * 2048
        a = head + b"X" * 2048
        b_data = head + b"Y" * 2048
        score = _similarity(a, b_data)
        assert 0.75 <= score <= 0.85  # only head → 0.80

    def test_no_head_no_tail_match(self):
        a = b"A" * 4096
        b_data = b"B" * 4096
        score = _similarity(a, b_data)
        assert score <= 0.55  # len_ratio * 0.5 = 0.5
