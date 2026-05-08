"""
Regression tests for script_template_generator/generator.py.
"""
from __future__ import annotations

import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from ct_updater.script_template_generator.generator import (
    generate_aa_script,
    generate_from_feature_packet,
)


class TestGenerateAAScript(unittest.TestCase):
    def _gen(self, **kwargs):
        defaults = dict(
            feature_name="TestFeature",
            symbol="TestClass:TestMethod",
            pattern="AA BB ?? DD EE",
            scan_range=200,
        )
        defaults.update(kwargs)
        return generate_aa_script(**defaults)

    def test_enable_section_present(self):
        script = self._gen()
        self.assertIn("[ENABLE]", script)

    def test_disable_section_present(self):
        script = self._gen()
        self.assertIn("[DISABLE]", script)

    def test_aobscanregion_line_present(self):
        script = self._gen()
        self.assertIn("aobscanregion(", script)

    def test_pattern_in_aobscan(self):
        script = self._gen(pattern="AA BB ?? DD EE")
        self.assertIn("AA BB ?? DD EE", script)

    def test_symbol_in_aobscan(self):
        script = self._gen(symbol="SomeClass:SomeMethod")
        self.assertIn("SomeClass:SomeMethod", script)

    def test_custom_aob_name(self):
        script = self._gen(aob_name="MyCustomAOB")
        self.assertIn("MyCustomAOB", script)

    def test_alloc_line_present(self):
        script = self._gen()
        self.assertIn("alloc(", script)

    def test_registersymbol_present(self):
        script = self._gen()
        self.assertIn("registersymbol(", script)

    def test_jmp_present(self):
        script = self._gen()
        self.assertIn("jmp ", script)

    def test_dealloc_in_disable(self):
        script = self._gen()
        disable_part = script.split("[DISABLE]")[1]
        self.assertIn("dealloc(", disable_part)

    def test_scan_range_in_aobscan(self):
        script = self._gen(scan_range=350)
        self.assertIn("350", script)


class TestGenerateFromFeaturePacket(unittest.TestCase):
    def _make_packet(self, **overrides) -> str:
        packet = {
            "target_symbol": "TestClass:TestMethod",
            "target_range": 200,
            "reference": {"description": "Test Hook", "name": "TestAOB"},
            "candidates": [
                {
                    "recommended_pattern": "AA BB ?? DD EE",
                    "scan_range": 200,
                }
            ],
        }
        packet.update(overrides)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8")
        json.dump(packet, tmp)
        tmp.close()
        return tmp.name

    def test_generates_from_packet(self):
        path = self._make_packet()
        try:
            script = generate_from_feature_packet(path)
            self.assertIn("[ENABLE]", script)
            self.assertIn("AA BB ?? DD EE", script)
        finally:
            os.unlink(path)

    def test_raises_on_empty_candidates(self):
        path = self._make_packet(candidates=[])
        try:
            with self.assertRaises(ValueError):
                generate_from_feature_packet(path)
        finally:
            os.unlink(path)

    def test_raises_on_bad_index(self):
        path = self._make_packet()
        try:
            with self.assertRaises(IndexError):
                generate_from_feature_packet(path, candidate_index=99)
        finally:
            os.unlink(path)

    def test_raises_on_missing_pattern(self):
        path = self._make_packet(candidates=[{"scan_range": 200}])
        try:
            with self.assertRaises(ValueError):
                generate_from_feature_packet(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
