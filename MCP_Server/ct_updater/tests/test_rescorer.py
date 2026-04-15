"""
Regression tests for postprocess/rescorer.py — covers intent consistency
scoring and the majority-intent computation.
"""
from __future__ import annotations

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from ct_updater.postprocess.models import CandidateInput, HookInput
from ct_updater.postprocess.rescorer import rescore_hook, _majority_intent, _intent_consistency_score


def _make_candidate(**kwargs) -> CandidateInput:
    defaults = dict(
        offset=0,
        address=0x1000,
        byte_score=0.9,
        confidence=0.9,
        diff_count=0,
        exact=True,
        within_range=True,
        tags=[],
        notes=[],
        actual_bytes="AA BB CC DD EE",
        replacement_pattern=None,
        wildcard_pattern=None,
        suggested_range=None,
        instructions=[],
        uniqueness_classification="unique",
        uniqueness_match_count=1,
        stability_score=0.9,
        intent_label="",
    )
    defaults.update(kwargs)
    return CandidateInput(**defaults)


def _make_hook(candidates: list[CandidateInput]) -> HookInput:
    return HookInput(
        name="TestHook",
        description="Test Hook",
        symbol="TestClass:TestMethod",
        scan_range=200,
        pattern="AA BB CC DD EE",
        method_addr=0x1000,
        status="high_similarity",
        summary="",
        error=None,
        candidates=candidates,
    )


class TestMajorityIntent(unittest.TestCase):
    def test_empty_candidates(self):
        self.assertEqual(_majority_intent([]), "")

    def test_all_same_intent(self):
        candidates = [_make_candidate(intent_label="write")] * 3
        self.assertEqual(_majority_intent(candidates), "write")

    def test_majority_wins(self):
        candidates = [
            _make_candidate(intent_label="write"),
            _make_candidate(intent_label="write"),
            _make_candidate(intent_label="read"),
        ]
        self.assertEqual(_majority_intent(candidates), "write")

    def test_mixed_ignored_for_majority(self):
        candidates = [
            _make_candidate(intent_label="write"),
            _make_candidate(intent_label="mixed"),
            _make_candidate(intent_label="mixed"),
        ]
        # "mixed" is excluded from majority vote — "write" should win
        self.assertEqual(_majority_intent(candidates), "write")

    def test_all_empty_labels(self):
        candidates = [_make_candidate(intent_label="")] * 3
        self.assertEqual(_majority_intent(candidates), "")


class TestIntentConsistencyScore(unittest.TestCase):
    def test_matching_intent_full_score(self):
        candidate = _make_candidate(intent_label="write")
        score = _intent_consistency_score(candidate, "write")
        self.assertAlmostEqual(score, 1.0)

    def test_different_intent_low_score(self):
        candidate = _make_candidate(intent_label="read")
        score = _intent_consistency_score(candidate, "write")
        self.assertAlmostEqual(score, 0.2)

    def test_mixed_candidate_neutral(self):
        candidate = _make_candidate(intent_label="mixed")
        score = _intent_consistency_score(candidate, "write")
        self.assertGreater(score, 0.2)
        self.assertLess(score, 1.0)

    def test_no_majority_neutral(self):
        candidate = _make_candidate(intent_label="write")
        score = _intent_consistency_score(candidate, "")
        self.assertAlmostEqual(score, 0.5)

    def test_no_candidate_label_neutral(self):
        candidate = _make_candidate(intent_label="")
        score = _intent_consistency_score(candidate, "write")
        self.assertAlmostEqual(score, 0.5)


class TestRescorerIntentIntegration(unittest.TestCase):
    def test_matching_intent_ranks_higher(self):
        # Two candidates with same byte scores; one matches majority intent, one doesn't
        candidates = [
            _make_candidate(offset=0, address=0x1000, intent_label="write"),
            _make_candidate(offset=20, address=0x1014, byte_score=0.88, confidence=0.88, intent_label="read"),
            _make_candidate(offset=40, address=0x1028, byte_score=0.88, confidence=0.88, intent_label="write"),
        ]
        hook = _make_hook(candidates)
        rescored = rescore_hook(hook)
        # The top candidates should have "write" intent
        top_labels = [s.candidate.intent_label for s in rescored[:2]]
        self.assertIn("write", top_labels)

    def test_intent_reason_code_present(self):
        candidates = [_make_candidate(intent_label="write")]
        hook = _make_hook(candidates)
        rescored = rescore_hook(hook)
        self.assertTrue(any("intent_write" in rc for rc in rescored[0].reason_codes))

    def test_intent_conflict_flag_on_mismatch(self):
        candidates = [
            _make_candidate(offset=0, address=0x1000, byte_score=0.95, confidence=0.95, intent_label="write"),
            _make_candidate(offset=20, address=0x1014, byte_score=0.94, confidence=0.94, intent_label="read"),
        ]
        hook = _make_hook(candidates)
        rescored = rescore_hook(hook)
        top_codes = rescored[0].reason_codes
        self.assertIn("intent_conflict_with_backup", top_codes)

    def test_no_conflict_flag_when_intents_agree(self):
        candidates = [
            _make_candidate(offset=0, address=0x1000, byte_score=0.95, intent_label="write"),
            _make_candidate(offset=20, address=0x1014, byte_score=0.94, intent_label="write"),
        ]
        hook = _make_hook(candidates)
        rescored = rescore_hook(hook)
        top_codes = rescored[0].reason_codes
        self.assertNotIn("intent_conflict_with_backup", top_codes)

    def test_rescore_without_intent_still_works(self):
        # Candidates with no intent label — should not crash
        candidates = [
            _make_candidate(offset=0, intent_label=""),
            _make_candidate(offset=20, intent_label=""),
        ]
        hook = _make_hook(candidates)
        rescored = rescore_hook(hook)
        self.assertEqual(len(rescored), 2)


if __name__ == "__main__":
    unittest.main()
