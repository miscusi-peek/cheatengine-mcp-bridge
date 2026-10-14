"""Tiny shared kit for the offline test suites: paths, argument handling and pass/fail accounting.

Every suite prints lines that start with ``PASS`` or ``FAIL``; this module counts them (whatever prints them)
and `finish()` turns the totals into the process exit code, so a suite can be run on its own or via run_all.py.
"""
import atexit
import re
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
BRIDGE_LUA = REPO_ROOT / "MCP_Server" / "ce_mcp_bridge.lua"
BRIDGE_PY = REPO_ROOT / "MCP_Server" / "mcp_cheatengine.py"

EXIT_SKIP = 77          # a prerequisite (Lua DLL, pywin32, mcp) is missing; run_all reports "skipped"

_ERROR_LINE = re.compile(r"^(COMPILE FAIL|LUA EXEC ERROR|LUA ERROR|REAL DLL VALIDATION FAILED)")


def arg_path(index, default):
    """sys.argv[index] if it is a path-like argument (not a --flag), else `default`."""
    if len(sys.argv) > index and not sys.argv[index].startswith("--"):
        return Path(sys.argv[index])
    return Path(default)


def has_flag(flag):
    return flag in sys.argv


class _Counter:
    """Wraps stdout and tallies PASS / FAIL / error lines as they are printed."""

    def __init__(self, inner):
        self._inner = inner
        self._buf = ""
        self.passed = self.failed = self.errors = 0

    def _count(self, line):
        if line.startswith("PASS"):
            self.passed += 1
        elif line.startswith("FAIL"):
            self.failed += 1
        elif _ERROR_LINE.match(line):
            self.errors += 1

    def write(self, text):
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._count(line)
        return self._inner.write(text)

    def flush(self):
        self._inner.flush()

    def __getattr__(self, name):
        return getattr(self._inner, name)


COUNTER = None


def install():
    global COUNTER
    if COUNTER is None:
        COUNTER = _Counter(sys.stdout)
        sys.stdout = COUNTER
    return COUNTER


def finish():
    """Print the totals and exit non-zero on any failure, error line or an empty run."""
    counter = install()
    counter._count(counter._buf)
    counter._buf = ""
    print("TOTAL: %d passed, %d failed, %d errors" % (counter.passed, counter.failed, counter.errors))
    sys.stdout.flush()
    ok = counter.failed == 0 and counter.errors == 0 and counter.passed > 0
    sys.exit(0 if ok else 1)


install()
