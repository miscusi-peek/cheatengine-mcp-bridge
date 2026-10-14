"""Run every offline test suite and print a summary. No Cheat Engine process is needed.

    python tests/run_all.py            # all suites
    python tests/run_all.py -v         # also show each suite's full output
    python tests/run_all.py --real     # + validate PE/RTTI parsing against real system DLLs
    python tests/run_all.py --mutation # + check that the suites catch deliberate breakages
    python tests/run_all.py --only lua # only suites whose name contains "lua"
    python tests/run_all.py --strict   # a skipped suite (missing prerequisite) counts as a failure

Prerequisites: Windows, `pip install -r MCP_Server/requirements.txt` (mcp + pywin32) and Cheat Engine's
lua53-64.dll (found in the usual install folders, or set CE_LUA_DLL). Missing prerequisites skip the affected
suites instead of failing them.
"""
import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

TESTS = Path(__file__).resolve().parent
EXIT_SKIP = 77

# (name, file, needs python deps for the MCP server?)
SUITES = [
    ("lua robustness", "test_lua_robustness.py", False),
    ("lua jobs",       "test_lua_jobs.py",       False),
    ("lua analysis",   "test_lua_analysis.py",   False),
    ("lua breakpoints", "test_lua_breakpoints.py", False),
    ("lua xrefs",     "test_lua_xrefs.py",      False),
    ("lua pathsets",  "test_lua_pathsets.py",   False),
    ("lua load",      "test_lua_load.py",       False),
    ("client retry",   "test_client_retry.py",   True),
    ("client jobs",    "test_client_jobs.py",    True),
    ("client analysis", "test_client_analysis.py", True),
    ("policy",         "test_policy.py",         True),
]


def python_deps_ok():
    probe = subprocess.run([sys.executable, "-c", "import win32file, win32pipe, mcp"], capture_output=True)
    return probe.returncode == 0


def run_suite(name, filename, extra, timeout=600):
    start = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, str(TESTS / filename)] + extra, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", cwd=TESTS, timeout=timeout)
        out = proc.stdout + proc.stderr
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + (exc.stderr or "") + "\nTIMEOUT"
        code = 124
    elapsed = time.monotonic() - start
    m = re.findall(r"TOTAL: (\d+) passed, (\d+) failed, (\d+) errors", out)
    counts = tuple(int(x) for x in m[-1]) if m else (0, 0, 0)
    return code, counts, out, elapsed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--real", action="store_true", help="validate PE/RTTI parsing against real system DLLs")
    ap.add_argument("--mutation", action="store_true", help="run mutation_check.py afterwards")
    ap.add_argument("--only", default="", help="only suites whose name contains this text")
    ap.add_argument("--strict", action="store_true", help="skipped suites count as failures")
    args = ap.parse_args()

    deps = python_deps_ok()
    rows, failed, skipped = [], 0, 0
    for name, filename, needs_deps in SUITES:
        if args.only and args.only not in name:
            continue
        if needs_deps and not deps:
            rows.append((name, "SKIP", "needs `pip install -r MCP_Server/requirements.txt` (mcp, pywin32)", 0.0))
            skipped += 1
            continue
        extra = ["--real"] if (args.real and ("analysis" in name or "xrefs" in name) and filename.startswith("test_lua")) else []
        code, (p, f, e), out, secs = run_suite(name, filename, extra)
        if code == EXIT_SKIP:
            reason = (out.strip().splitlines() or ["prerequisite missing"])[-1]
            rows.append((name, "SKIP", reason, secs))
            skipped += 1
            continue
        ok = code == 0
        rows.append((name, "ok" if ok else "FAIL", "%d passed, %d failed, %d errors" % (p, f, e), secs))
        if not ok:
            failed += 1
        if args.verbose or not ok:
            interesting = out if args.verbose else "\n".join(
                l for l in out.splitlines() if l.startswith(("FAIL", "COMPILE FAIL", "LUA", "REAL DLL", "Traceback", "  File", "TIMEOUT")) or "Error" in l)
            print("--- %s%s\n%s\n" % (name, "" if args.verbose else " (problems)", interesting.strip() or out[-1500:]))

    print("%-18s %-5s %-44s %s" % ("suite", "", "result", "time"))
    for name, status, detail, secs in rows:
        print("%-18s %-5s %-44s %5.1fs" % (name, status, detail[:44], secs))
    total_p = sum(1 for r in rows if r[1] == "ok")
    print("\n%d suite(s) ok, %d failed, %d skipped" % (total_p, failed, skipped))

    if args.mutation and not failed:
        print("\n== mutation check ==")
        proc = subprocess.run([sys.executable, str(TESTS / "mutation_check.py")], cwd=TESTS)
        if proc.returncode == EXIT_SKIP:
            skipped += 1
        elif proc.returncode != 0:
            failed += 1

    sys.exit(1 if failed or (args.strict and skipped) else 0)


if __name__ == "__main__":
    main()
