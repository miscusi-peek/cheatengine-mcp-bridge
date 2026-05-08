"""
Regression tests for stability/service.py — covers both empirical analysis
and the structural volatility heuristics.
"""
from __future__ import annotations

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from ct_updater.stability.service import analyze_stability, _volatile_indexes


class TestVolatileIndexes(unittest.TestCase):
    def test_call_rel32(self):
        # E8 XX XX XX XX — 4 offset bytes are volatile
        raw = bytes([0xE8, 0x12, 0x34, 0x56, 0x78])
        volatile = _volatile_indexes(raw)
        self.assertEqual(volatile, frozenset({1, 2, 3, 4}))

    def test_jmp_rel32(self):
        raw = bytes([0xE9, 0xAA, 0xBB, 0xCC, 0xDD])
        volatile = _volatile_indexes(raw)
        self.assertEqual(volatile, frozenset({1, 2, 3, 4}))

    def test_jmp_short(self):
        raw = bytes([0xEB, 0x08])
        volatile = _volatile_indexes(raw)
        self.assertIn(1, volatile)

    def test_jcc_short(self):
        # 74 XX — JZ short
        raw = bytes([0x74, 0x10])
        volatile = _volatile_indexes(raw)
        self.assertIn(1, volatile)

    def test_jcc_near(self):
        # 0F 84 XX XX XX XX — JZ near
        raw = bytes([0x0F, 0x84, 0x11, 0x22, 0x33, 0x44])
        volatile = _volatile_indexes(raw)
        self.assertEqual(volatile & {2, 3, 4, 5}, {2, 3, 4, 5})

    def test_rip_relative_mov(self):
        # 48 8B 05 XX XX XX XX — MOV rax,[rip+disp32]
        raw = bytes([0x48, 0x8B, 0x05, 0x10, 0x20, 0x30, 0x40])
        volatile = _volatile_indexes(raw)
        self.assertEqual(volatile & {3, 4, 5, 6}, {3, 4, 5, 6})

    def test_stable_bytes_not_flagged(self):
        # 48 89 C8 — MOV rax, rcx  (no immediate or displacement)
        raw = bytes([0x48, 0x89, 0xC8])
        volatile = _volatile_indexes(raw)
        self.assertEqual(len(volatile), 0)

    def test_mov_reg_imm64(self):
        # 48 B8 XX*8 — MOV rax, imm64
        raw = bytes([0x48, 0xB8]) + bytes(range(8))
        volatile = _volatile_indexes(raw)
        self.assertEqual(volatile & set(range(2, 10)), set(range(2, 10)))


class TestAnalyzeStability(unittest.TestCase):
    def test_exact_match_full_stability(self):
        pattern = [0xAA, 0xBB, 0xCC]
        actual = bytes([0xAA, 0xBB, 0xCC])
        report = analyze_stability(pattern, actual)
        self.assertAlmostEqual(report.stability_score, 1.0)
        self.assertEqual(report.wildcard_indexes, [])

    def test_one_byte_changed(self):
        pattern = [0xAA, 0xBB, 0xCC]
        actual = bytes([0xAA, 0xFF, 0xCC])
        report = analyze_stability(pattern, actual)
        self.assertIn(1, report.wildcard_indexes)
        self.assertAlmostEqual(report.stability_score, 2 / 3)

    def test_wildcard_in_pattern_not_counted(self):
        pattern = [0xAA, None, 0xCC]
        actual = bytes([0xAA, 0xFF, 0xCC])
        report = analyze_stability(pattern, actual)
        # Only 2 non-wildcard bytes; both should be stable
        self.assertAlmostEqual(report.stability_score, 1.0)

    def test_hardened_pattern_wildcards_volatile(self):
        # E8 XX XX XX XX — call with relative offset
        pattern = [0xE8, 0x12, 0x34, 0x56, 0x78]
        actual = bytes([0xE8, 0x12, 0x34, 0x56, 0x78])
        report = analyze_stability(pattern, actual)
        # The 4 offset bytes should be in predicted_volatile
        self.assertTrue(len(report.predicted_volatile_indexes) >= 4)
        # Hardened pattern should wildcard them
        hardened_bytes = report.hardened_pattern.split()
        self.assertEqual(hardened_bytes[0], "E8")
        for i in range(1, 5):
            self.assertEqual(hardened_bytes[i], "??")

    def test_no_predicted_volatile_for_stable_sequence(self):
        # Simple register-to-register moves — no volatility
        pattern = [0x48, 0x89, 0xC8, 0x48, 0x89, 0xD1]
        actual = bytes(pattern)
        report = analyze_stability(pattern, actual)
        self.assertEqual(report.predicted_volatile_indexes, [])
        self.assertEqual(report.hardened_pattern, report.wildcard_pattern)


class TestAnalyzeStabilityReport(unittest.TestCase):
    def test_replacement_pattern_uses_actual_bytes(self):
        pattern = [0xAA, 0xBB, 0xCC]
        actual = bytes([0xAA, 0xFF, 0xCC])
        report = analyze_stability(pattern, actual)
        self.assertIn("FF", report.replacement_pattern)
        self.assertIn("AA", report.replacement_pattern)

    def test_wildcard_pattern_uses_question_marks(self):
        pattern = [0xAA, 0xBB, 0xCC]
        actual = bytes([0xAA, 0xFF, 0xCC])
        report = analyze_stability(pattern, actual)
        parts = report.wildcard_pattern.split()
        self.assertEqual(parts[0], "AA")
        self.assertEqual(parts[1], "??")
        self.assertEqual(parts[2], "CC")


if __name__ == "__main__":
    unittest.main()
