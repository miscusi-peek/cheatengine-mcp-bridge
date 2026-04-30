"""
Regression tests for lint/service.py — no bridge required.
"""
from __future__ import annotations

import sys
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

# Make ct_updater importable when running from MCP_Server/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from ct_updater.lint.service import lint_ct
from ct_updater.lint.models import LintReport


def _make_ct(scripts: list[str]) -> str:
    """Write a minimal CT XML file containing the given AssemblerScript blocks."""
    root = ET.Element("CheatTable")
    entries = ET.SubElement(root, "CheatEntries")
    for i, script in enumerate(scripts):
        entry = ET.SubElement(entries, "CheatEntry")
        ET.SubElement(entry, "Description").text = f"Entry {i}"
        ET.SubElement(entry, "VariableType").text = "Auto Assembler Script"
        ET.SubElement(entry, "AssemblerScript").text = script
    tmp = tempfile.NamedTemporaryFile(suffix=".CT", delete=False, mode="w", encoding="utf-8")
    ET.ElementTree(root).write(tmp.name, encoding="unicode", xml_declaration=False)
    tmp.close()
    return tmp.name


class TestLintZeroWildcards(unittest.TestCase):
    def test_long_exact_pattern_triggers_warning(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE FF 11 22 33 44 55)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertIn("ZERO_WILDCARDS", codes)
        finally:
            os.unlink(ct)

    def test_short_exact_pattern_no_warning(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertNotIn("ZERO_WILDCARDS", codes)
        finally:
            os.unlink(ct)

    def test_wildcarded_pattern_no_warning(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+200,AA BB ?? DD EE FF 11 22 33 44 55)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertNotIn("ZERO_WILDCARDS", codes)
        finally:
            os.unlink(ct)


class TestLintTightScanRange(unittest.TestCase):
    def test_tight_range_triggers_warning(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+50,AA BB CC DD EE)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertIn("TIGHT_SCAN_RANGE", codes)
        finally:
            os.unlink(ct)

    def test_adequate_range_no_warning(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertNotIn("TIGHT_SCAN_RANGE", codes)
        finally:
            os.unlink(ct)


class TestLintDuplicateAOB(unittest.TestCase):
    def test_duplicate_patterns_trigger_warning(self):
        script1 = "aobscanregion(TestAOB1,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE FF 11 22)"
        script2 = "aobscanregion(TestAOB2,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE FF 11 22)"
        ct = _make_ct([script1, script2])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertIn("DUPLICATE_AOB", codes)
        finally:
            os.unlink(ct)

    def test_unique_patterns_no_warning(self):
        script1 = "aobscanregion(TestAOB1,TestClass:TestMethod,TestClass:TestMethod+200,AA BB CC DD EE FF 11 22)"
        script2 = "aobscanregion(TestAOB2,TestClass:TestMethod,TestClass:TestMethod+200,11 22 33 44 55 66 77 88)"
        ct = _make_ct([script1, script2])
        try:
            report = lint_ct(None, ct)
            codes = [issue.code for issue in report.issues]
            self.assertNotIn("DUPLICATE_AOB", codes)
        finally:
            os.unlink(ct)


class TestLintReportProperties(unittest.TestCase):
    def test_no_issues_no_errors(self):
        script = "aobscanregion(TestAOB,TestClass:TestMethod,TestClass:TestMethod+200,AA BB ?? DD EE)"
        ct = _make_ct([script])
        try:
            report = lint_ct(None, ct)
            self.assertFalse(report.has_errors)
        finally:
            os.unlink(ct)

    def test_empty_ct_no_issues(self):
        ct = _make_ct([])
        try:
            report = lint_ct(None, ct)
            self.assertEqual(len(report.issues), 0)
        finally:
            os.unlink(ct)


if __name__ == "__main__":
    unittest.main()
