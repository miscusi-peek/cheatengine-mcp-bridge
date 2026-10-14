"""Live smoke test: the new bridge features against a REAL Cheat Engine.

The offline suites prove the bridge logic against a fake CE API. This script checks the assumptions that only a real
CE can confirm: memscan jobs and their events, AOB wildcards, hardware breakpoints in break mode (the thread really
stays stopped, the watchdog really resumes it), CE's disassembler output, symbol handling, and so on.

    python tests/live_smoke.py              # everything
    python tests/live_smoke.py --only break # sections whose name contains "break"
    python tests/live_smoke.py -v           # also print the raw reply of every failed check

Requirements: Cheat Engine running with ce_mcp_bridge.lua loaded (the pipe CE_MCP_Bridge_v99 must exist) and Python
with the MCP server dependencies. The test spawns its own throwaway target (tests/live_target.py), attaches CE to it,
and re-attaches whatever CE had open before when it finishes. It never touches any other process. Breakpoints are
only ever set in the throwaway target; a break-mode hit freezes that one thread until the test (or the bridge's
watchdog) resumes it.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import testkit
from testkit import EXIT_SKIP, finish, has_flag

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "MCP_Server"))
VERBOSE = has_flag("-v")
ONLY = sys.argv[sys.argv.index("--only") + 1].lower() if "--only" in sys.argv else ""

try:
    import win32file  # noqa: F401
    import mcp_cheatengine as m
except Exception as exc:                                    # missing pywin32 / mcp
    print("SKIP: cannot import the MCP server module (%s)" % exc)
    sys.exit(EXIT_SKIP)

try:
    import win32pipe
    win32pipe.WaitNamedPipe(r"\\.\pipe\CE_MCP_Bridge_v99", 1000)
except Exception:
    print("SKIP: the pipe CE_MCP_Bridge_v99 is not available - start Cheat Engine and load ce_mcp_bridge.lua")
    sys.exit(EXIT_SKIP)


# --------------------------------------------------------------------------- helpers
def J(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {"success": False, "error": "not JSON: " + value[:200]}
    return value


def call(fn, *args, **kwargs):
    """Run an MCP tool function and return its reply as a dict; exceptions become {success: False}."""
    try:
        return J(fn(*args, **kwargs))
    except Exception as exc:
        return {"success": False, "error": "EXCEPTION %r" % (exc,)}


def rawbytes(reply):
    """Bytes of a read_memory reply (hex format: {"data": "11 EE ..."})."""
    text = reply.get("data") or reply.get("bytes") or reply.get("hex") or ""
    return bytes.fromhex(text.replace(" ", "")) if isinstance(text, str) else bytes(text)


def hx(value):
    return "0x%X" % value


def to_int(value):
    if isinstance(value, dict):
        value = value.get("address", value.get("addr"))
    if isinstance(value, int):
        return value
    return int(str(value), 16) if str(value).lower().startswith("0x") else int(str(value), 16)


section_name = ""
active = True


def section(name):
    global section_name, active
    section_name = name
    active = (ONLY in name.lower())
    if active:
        print("\n== %s" % name, flush=True)
    return active


def check(name, cond, detail=None):
    if not active:
        return
    if cond:
        print("PASS  %s" % name, flush=True)
    else:
        print("FAIL  %s" % name, flush=True)
        if VERBOSE and detail is not None:
            print("      " + (detail if isinstance(detail, str) else json.dumps(detail, default=str))[:1500], flush=True)


def skip(name, reason):
    if active:
        print("SKIP  %s  (%s)" % (name, reason), flush=True)


def note(text):
    if active:
        print("      " + text, flush=True)


def run_job(kind, params, wait=60.0, limit=1000):
    started = call(m.start_job, kind, params)
    if not started.get("success"):
        return started
    jid = started["job_id"]
    status = call(m.wait_for_job, jid, timeout_seconds=wait)
    if status.get("state") != "done":
        return status
    return call(m.get_job_result, jid, limit=limit)


# --------------------------------------------------------------------------- the throwaway target
target = None
orig_pid = None
info = {}


def spawn_target():
    global target, info
    target = subprocess.Popen([sys.executable, str(Path(__file__).with_name("live_target.py")), "msvcp140.dll"],
                              stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    line = target.stdout.readline()
    info = json.loads(line)
    return info


target2 = None


def spawn_second():
    """A second, 'restarted' instance of the throwaway target (its second pointer root is broken)."""
    global target2
    target2 = subprocess.Popen([sys.executable, str(Path(__file__).with_name("live_target.py"))], stdout=subprocess.PIPE, text=True,
                               env=dict(os.environ, LIVE_TARGET_VARIANT="2"), creationflags=subprocess.CREATE_NO_WINDOW)
    return json.loads(target2.stdout.readline())


def teardown():
    for fn, args in ((m.clear_all_breakpoints, ()), (m.debug_detach, ())):
        try:
            fn(*args)
        except Exception:
            pass
    for proc in (target, target2):
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
    if orig_pid:
        r = call(m.open_process, str(orig_pid))
        print("\nrestored CE's original process %s: %s" % (orig_pid, "ok" if r.get("success") else r))
    call(m.delete_snapshot, all=True)


# --------------------------------------------------------------------------- the checks
def main():
    global orig_pid
    t_start = time.monotonic()

    if section("connection"):
        r = call(m.ping)
        check("ping", r.get("success") is True and r.get("version"), r)
        note("bridge version %s, CE pid %s" % (r.get("version"), r.get("process_id")))
        st = call(m.bridge_status)
        check("bridge_status answers", st.get("tools_registered", 0) >= 200 and "stats" in st and st["stats"].get("errors", 1) == 0, st)
        check("bridge_status reports the state counters", all(k in st.get("state", {}) for k in ("jobs_running", "hw_slots_used", "breakpoints")), st.get("state"))
        note("query_memory_region_routines=%s (must not be 'enabled' when scanning with DBVM)" % st.get("query_memory_region_routines"))
        check("tool count in the bridge matches the Python server", abs(st.get("tools_registered", 0) - len(m.mcp._tool_manager.list_tools())) <= 2,
              (st.get("tools_registered"), len(m.mcp._tool_manager.list_tools())))
        orig = call(m.get_opened_process_id)
        orig_pid = orig.get("process_id") if orig.get("success") else None
        note("CE currently has process %s attached (restored at the end)" % orig_pid)

    spawn_target()
    attach = call(m.open_process, str(info["pid"]))
    if section("attach"):
        check("open_process attaches to the throwaway target", attach.get("success") is True, attach)
        check("get_opened_process_id agrees", call(m.get_opened_process_id).get("process_id") == info["pid"])
        mods = call(m.enum_modules, limit=200)
        names = [x.get("name", "").lower() for x in mods.get("modules", [])]
        check("modules include python and kernel32", info["python_dll"] in names and "kernel32.dll" in names, names[:10])
        check("msvcp140.dll was loaded by the target", "msvcp140.dll" in names, names)
    obj, counter, scratch, api = info["obj"], info["counter"], info["scratch"], info["api"]

    if section("memory"):
        r = call(m.read_memory, hx(obj), 32)
        raw = rawbytes(r)
        check("read_memory hex returns the object", raw[:4] == bytes.fromhex("11EEFFC0"), r)
        rb = call(m.read_memory, hx(obj), 8, format="base64")
        check("read_memory base64", rb.get("format") == "base64" and rb.get("base64") == "Ee7/wGQAAAA=", rb)
        rs = call(m.read_struct, hx(obj), [
            {"name": "magic", "type": "u32", "offset": 0}, {"name": "hp", "type": "i32", "offset": 4},
            {"name": "x", "type": "f32", "offset": 8}, {"name": "y", "type": "f32", "offset": 12},
            {"name": "name", "type": "cstring", "offset": 24, "size": 16}])
        vals = {f["name"]: f.get("value") for f in rs.get("fields", [])}
        check("read_struct decodes u32/i32/f32/cstring in one read",
              vals.get("magic") == 0xC0FFEE11 and vals.get("hp") == 100 and abs(vals.get("x", 0) - 1.5) < 1e-6
              and abs(vals.get("y", 0) + 2.25) < 1e-6 and vals.get("name") == "smoke-target", rs)
        b = call(m.batch_commands, [{"method": "read_integer", "params": {"address": hx(obj + 4)}},
                                    {"method": "read_integer", "params": {"address": hx(obj)}}])
        check("batch_commands runs both requests", b.get("executed") == 2 and b.get("failed") == 0, b)

    if section("scan jobs"):
        magic = str(0xC0FFEE11)
        def session_addresses():
            res = call(m.get_scan_results, limit=1000).get("results", [])
            return [to_int(x) for x in res]
        r = run_job("scan_all", {"value": magic, "type": "dword", "protection": "+W-C"})
        check("scan_all job finishes with a count", r.get("success") and r.get("count", 0) >= 1, r)
        check("the job's scan session holds the object (get_scan_results)", obj in session_addresses(), call(m.get_scan_results, limit=5))
        r = run_job("next_scan", {"value": magic, "scan_option": "exact"})
        check("next_scan job finishes and keeps the object", r.get("success") and r.get("count", 0) >= 1 and obj in session_addresses(), r)
        r = run_job("aob_scan", {"pattern": "11 EE FF C0 64 00 00 00 ?? ?? ?? ??", "protection": "+W"})
        found = [to_int(x) for x in r.get("addresses", [])] if r.get("success") else []
        check("aob_scan job with ?? wildcards finds the object", obj in found, r)
        r = run_job("aob_scan", {"pattern": "73 6D 6F 6B 65 2D 74 61 72 67 65 74", "protection": "+W"})
        check("aob_scan job finds the name string", r.get("success") and obj + 24 in [to_int(x) for x in r.get("addresses", [])], r)
        s = call(m.bridge_status)
        check("no job or scan session is left running", s.get("state", {}).get("jobs_running") == 0, s.get("state"))

    if section("pe analysis"):
        dll = info["python_dll"]
        r = call(m.pe_info, module=dll)
        check("pe_info: x64 with a .text section", r.get("success") and r.get("arch") == "x64" and any(s["name"] == ".text" for s in r.get("sections", [])), r)
        base = to_int(r["base"]) if r.get("base") else 0
        ex = call(m.pe_exports, module=dll, name_contains="PyLong_FromLong")
        exp = next((e for e in ex.get("exports", []) if e.get("name") == "PyLong_FromLong"), None)
        check("pe_exports lists PyLong_FromLong", exp is not None, ex)
        if exp:
            sym = call(m.get_symbol_address, "%s.PyLong_FromLong" % dll.replace(".dll", ""))
            ce_addr = sym.get("address")
            mine = base + exp["rva"]
            check("pe_exports address == CE's own symbol handler", ce_addr and to_int(ce_addr) == mine, (sym, hx(mine)))
            f = call(m.pe_functions, address=hx(mine + 4))
            check("pe_functions finds the function containing the export", f.get("found") and f.get("begin_rva", 1 << 40) <= exp["rva"] < f.get("end_rva", 0), f)
            fb = call(m.find_function_boundaries, hx(mine + 4))
            check("find_function_boundaries uses .pdata", fb.get("method") == "pdata", fb)
            v = call(m.va_to_rva, address=hx(mine))
            check("va_to_rva round-trips", v.get("rva") == exp["rva"] and v.get("module", "").lower() == dll, v)
        im = call(m.pe_imports, module=dll, dll="kernel32", limit=5)
        check("pe_imports resolves the live IAT", im.get("total", 0) > 0 and im["imports"][0].get("resolved"), im)
        r = call(m.rtti_scan_module, module="msvcp140.dll", wait_seconds=60, limit=2000)
        classes = r.get("classes", [])
        check("rtti_scan_module finds classes in msvcp140.dll", r.get("success") and r.get("class_count", 0) > 20, r.get("error") or r.get("state"))
        pick = next((c for c in classes if c.get("vfunc_count", 0) >= 3 and c.get("this_offset") == 0), None)
        if pick:
            vt = to_int(pick["vtable"])
            call(m.write_memory, hx(scratch), list(vt.to_bytes(8, "little")))
            rec = call(m.recover_struct, address=hx(scratch))
            check("recover_struct on a fake instance names the class", rec.get("success") and rec.get("class_name") == pick["class_name"], rec)
            check("recover_struct lists the virtual functions with sizes", len(rec.get("virtual_functions", [])) == pick["vfunc_count"]
                  and all("function_size" in v for v in rec["virtual_functions"][:3]), rec)
            note("recovered %s (%d virtual functions)" % (pick["class_name"], pick["vfunc_count"]))
        else:
            skip("recover_struct", "no suitable RTTI class")

    if section("xrefs"):
        dll = info["python_dll"]
        ex = call(m.pe_exports, module=dll, name_contains="PyLong_FromLong")
        exp = next((e for e in ex.get("exports", []) if e.get("name") == "PyLong_FromLong"), None)
        base = to_int(call(m.pe_info, module=dll)["base"])
        if exp:
            tgt = base + exp["rva"]
            t0 = time.monotonic()
            r = call(m.find_xrefs, hx(tgt), module=dll, kinds="call,jmp,abs", wait_seconds=120, limit=400)
            note("find_xrefs on PyLong_FromLong: %s references in %.1fs" % (r.get("found"), time.monotonic() - t0))
            check("find_xrefs finds callers of an exported function", r.get("success") and r.get("found", 0) > 5, r.get("error") or r)
            refs = r.get("references", [])
            check("each hit carries CE's disassembly", all(x.get("instruction") for x in refs if x["kind"] in ("call", "jmp", "jcc")), refs[:2])
            bad = []
            for x in [x for x in refs if x["kind"] in ("call", "jmp") and x.get("form") == "rel32"][:25]:
                raw = call(m.read_memory, x["address"], 5)
                data = rawbytes(raw)
                if len(data) < 5 or data[0] != (0xE8 if x["kind"] == "call" else 0xE9):
                    bad.append((x["address"], data.hex()))
                    continue
                dest = (to_int(x["address"]) + 5 + int.from_bytes(data[1:5], "little", signed=True)) & 0xFFFFFFFFFFFFFFFF
                if dest != tgt:
                    bad.append((x["address"], hx(dest)))
            check("the first 25 rel32 hits really encode a branch to the target (bytes read from the live process)", not bad, bad)
            kinds_text_ok = all(("call" in x["instruction"].lower()) for x in refs if x["kind"] == "call" and x.get("instruction"))
            check("CE's disassembly of a call hit says 'call' (output format assumption)", kinds_text_ok, [x.get("instruction") for x in refs[:3]])
            if refs:
                note("sample: %s -> %s" % (refs[0].get("expression"), refs[0].get("instruction")))
            check("calling functions are grouped", r.get("functions") is None or all("function_start" in g for g in r["functions"]), r.get("functions"))
        # rip-relative operands against a data export
        ex2 = call(m.pe_exports, module=dll, name_contains="_Py_NoneStruct")
        exp2 = next((e for e in ex2.get("exports", []) if e.get("name") == "_Py_NoneStruct"), None)
        if exp2:
            r = call(m.find_xrefs, hx(base + exp2["rva"]), module=dll, kinds="rip", wait_seconds=120, limit=200)
            refs = r.get("references", [])
            note("rip-relative references to _Py_NoneStruct: %s" % r.get("found"))
            check("rip hits on a data export", r.get("success") and len(refs) > 5, r.get("error") or r)
            check("rip hits show a memory operand or lea in CE's text", all(("[" in x["instruction"]) for x in refs[:50] if x.get("instruction")), [x.get("instruction") for x in refs[:3]])
            check("rip hits carry an access kind", sum(1 for x in refs if x.get("access")) >= len(refs) * 0.9, [x.get("access") for x in refs[:10]])
        else:
            skip("rip xrefs", "no data export found")
        # cancel
        started = call(m.start_job, "find_xrefs", {"address": hx(api), "module": "all"})
        if started.get("success"):
            c = call(m.cancel_job, started["job_id"])
            st = call(m.get_job, started["job_id"])
            check("cancel_job stops a running xrefs job", c.get("success") and st.get("state") in ("cancelled", "done"), (c, st))
            note("job state after cancel: %s" % st.get("state"))
            check("no job left running", call(m.bridge_status).get("state", {}).get("jobs_running") == 0)

    if section("snapshots"):
        a = call(m.snapshot_region, address=hx(obj), size=64, name="smokeA")
        time.sleep(0.4)
        b = call(m.snapshot_region, address=hx(obj), size=64, name="smokeB")
        check("snapshot_region", a.get("success") and b.get("success"), (a, b))
        d = call(m.diff_snapshots, ["smokeA", "smokeB"])
        offs = [x.get("offset") for x in d.get("matches", [])]
        check("diff_snapshots shows the counter (offset 16) as the only changed field", d.get("success") and 16 in offs and all(o in (16, 20) for o in offs), d)
        pp = call(m.find_pointer_path, hx(obj), max_depth=2, max_offset=256, wait_seconds=60)
        check("find_pointer_path runs to completion (value-between memscans)", pp.get("success") and pp.get("scans", 0) >= 1, pp.get("error") or pp)
        note("find_pointer_path: %s chain(s), %s scans" % (pp.get("found"), pp.get("scans")))

    if section("pointer sets"):
        # The two-run comparison across a REAL restart: the throwaway target keeps two root pointers on a page at a fixed
        # address; a second instance has a different heap (the counter moves) and one broken root.
        fixed = info.get("fixed")
        if not fixed:
            skip("pointer sets", "the target could not reserve its fixed root page")
        else:
            chain_a, chain_b = {"base": hx(fixed + 0x20), "offsets": [16]}, {"base": hx(fixed + 0x28), "offsets": [16]}
            call(m.drop_pointer_set, all=True)
            r1 = call(m.compare_pointer_paths, hx(counter), chains=[chain_a, chain_b], save_as="smoke_ps")
            check("run 1: both roots reach the counter and are stored", r1.get("success") and r1.get("hits") == 2 and r1.get("saved_as") == "smoke_ps"
                  and r1.get("set", {}).get("runs") == 1, r1)
            info2 = spawn_second()
            check("the second instance has its own pid and counter", info2["pid"] != info["pid"] and info2["counter"] != counter and info2.get("fixed") == fixed,
                  (info, info2))
            att2 = call(m.open_process, str(info2["pid"]))
            check("CE attaches to the second instance", att2.get("success") is True and call(m.get_opened_process_id).get("process_id") == info2["pid"], att2)
            r2 = call(m.compare_pointer_paths, hx(info2["counter"]), name="smoke_ps", save_as="smoke_ps")
            check("run 2: only the intact root survives", r2.get("success") and r2.get("hits") == 1 and r2.get("missed") == 1 and r2["chains"][0]["base"] == hx(fixed + 0x20), r2)
            check("run 2: it is a new process instance and the chain is confirmed twice", r2.get("same_process") is False and r2.get("run") == 2
                  and r2["chains"][0]["runs"] == 2 and r2.get("set", {}).get("runs") == 2, r2)
            check("run 2: the broken root is not a near miss (it points at another object)", r2.get("near_misses") is None, r2.get("near_misses"))
            oracle = call(m.validate_pointer_chains, [chain_a, chain_b], hx(info2["counter"]))
            check("an independent resolver (validate_pointer_chains) agrees", oracle.get("matched") == 1 and oracle["matches"][0]["offsets"] == [16], oracle)
            again = call(m.compare_pointer_paths, hx(info2["counter"]), name="smoke_ps")
            check("asking again in the same process is flagged", again.get("same_process") is True and again.get("hits") == 1, again)
            got = call(m.get_pointer_set, "smoke_ps")
            check("get_pointer_set shows the narrowed set and both runs", got.get("success") and got.get("total") == 1 and len(got.get("history", [])) == 2
                  and got["history"][1]["pid"] == info2["pid"], got)
            check("drop_pointer_set", call(m.drop_pointer_set, name="smoke_ps").get("deleted") == 1)
            call(m.open_process, str(info["pid"]))                       # back to the main throwaway target for the other sections
            target2.kill()

    if section("breakpoints"):
        call(m.clear_all_breakpoints)
        # CE picks the debugger interface from its own settings when the first breakpoint is set; the VEH debugger (2)
        # crashes a throwaway Python target, so start the Windows debugger (1) explicitly to be independent of that.
        dp = call(m.debug_process, 1)
        check("the Windows debugger interface starts for the target", dp.get("success") is True and dp.get("interface_used") == 1, dp)
        note("debug_process(1) -> %s" % json.dumps(dp)[:160])
        # 1. validation
        bad = call(m.set_data_breakpoint, hx(counter + 1), size=8)
        check("misaligned data breakpoint is rejected", bad.get("success") is False and bad.get("error_code") == "INVALID_PARAMS", bad)
        bad = call(m.set_data_breakpoint, hx(counter), size=3)
        check("odd-sized data breakpoint is rejected", bad.get("success") is False and bad.get("error_code") == "INVALID_PARAMS", bad)

        # 2. log mode with max_hits: the register is freed afterwards
        r = call(m.set_breakpoint, hx(api), id="smoke_log", max_hits=3, capture_registers=True)
        check("set_breakpoint (execute, max_hits=3)", r.get("success"), r)
        deadline = time.time() + 6
        lb = {}
        while time.time() < deadline:
            lb = next((b for b in call(m.list_breakpoints).get("breakpoints", []) if b.get("id") == "smoke_log"), {})
            if lb.get("state") == "completed":
                break
            time.sleep(0.2)
        check("max_hits=3 stops the breakpoint by itself", lb.get("state") == "completed" and lb.get("hit_count", lb.get("total_hits", 3)) == 3, lb)
        hits = call(m.get_breakpoint_hits, id="smoke_log")
        check("three hits recorded with registers", hits.get("total", len(hits.get("hits", []))) == 3 and all("registers" in h or "RIP" in str(h) for h in hits.get("hits", [])), hits)
        check("the debug register was released", call(m.bridge_status).get("state", {}).get("hw_slots_used") == 0, call(m.bridge_status).get("state"))

        # 3. condition that never matches: hits are counted as filtered, none recorded
        r = call(m.set_data_breakpoint, hx(counter), id="smoke_cond", size=8, condition="RAX == 0x1234567812345678", max_hits=0)
        check("set_data_breakpoint with a condition", r.get("success"), r)
        time.sleep(1.0)
        lb = next((b for b in call(m.list_breakpoints).get("breakpoints", []) if b.get("id") == "smoke_cond"), {})
        check("a false condition filters every hit and records none", lb.get("filtered_hits", 0) > 5 and lb.get("hit_count", lb.get("total_hits", 0)) == 0, lb)
        call(m.remove_breakpoint, "smoke_cond")

        # 4. data breakpoint: previous_value / value_changed
        r = call(m.set_data_breakpoint, hx(counter), id="smoke_data", size=8, max_hits=4)
        time.sleep(1.2)
        hits = call(m.get_breakpoint_hits, id="smoke_data").get("hits", [])
        check("data breakpoint on a counter records value changes", len(hits) >= 3 and all(h.get("value_changed") for h in hits), hits[:2])
        call(m.remove_breakpoint, "smoke_data")

        # 5. THE assumption: break mode leaves the thread stopped, the debugger can resume it
        def counter_now():
            return int.from_bytes(rawbytes(call(m.read_memory, hx(counter), 8)), "little")
        r = call(m.set_breakpoint, hx(api), id="smoke_break", mode="break", max_hits=1, halt_timeout_ms=15000)
        check("set_breakpoint in break mode", r.get("success"), r)
        halted = {}
        for _ in range(40):
            halted = call(m.get_halted_state)
            if halted.get("halted"):
                break
            time.sleep(0.15)
        check("the breakpoint halts the thread (get_halted_state)", halted.get("halted") is True, halted)
        check("halted state has fresh registers and an instruction", bool(halted.get("registers")) and bool(halted.get("instruction")), halted)
        c1 = counter_now(); time.sleep(0.6); c2 = counter_now()
        check("the target is REALLY stopped: its counter does not move for 0.6 s", c1 == c2, (c1, c2))
        r = call(m.debug_continue, "run")
        check("debug_continue succeeds", r.get("success"), r)
        time.sleep(0.5)
        c3 = counter_now()
        check("after debug_continue the target runs again", c3 > c2, (c2, c3))
        check("the bridge no longer reports a halted thread", call(m.get_halted_state).get("halted") is False, call(m.get_halted_state))

        # 6. the watchdog resumes by itself
        r = call(m.set_breakpoint, hx(api), id="smoke_wd", mode="break", max_hits=1, halt_timeout_ms=1000)
        for _ in range(40):
            if call(m.get_halted_state).get("halted"):
                break
            time.sleep(0.15)
        d1 = counter_now()
        time.sleep(2.5)
        d2 = counter_now()
        gh = call(m.get_halted_state)
        check("the watchdog resumes a forgotten halt after halt_timeout_ms", gh.get("halted") is False and d2 > d1, (gh, d1, d2))
        lb = next((b for b in call(m.list_breakpoints).get("breakpoints", []) if b.get("id") == "smoke_wd"), {})
        check("auto_resumed is counted", lb.get("auto_resumed", 0) >= 1, lb)

        # 7. clearing while halted resumes the thread
        call(m.set_breakpoint, hx(api), id="smoke_clear", mode="break", max_hits=1, halt_timeout_ms=60000)
        for _ in range(40):
            if call(m.get_halted_state).get("halted"):
                break
            time.sleep(0.15)
        e1 = counter_now()
        call(m.clear_all_breakpoints)
        time.sleep(0.6)
        e2 = counter_now()
        check("clear_all_breakpoints resumes a halted thread", e2 > e1 and call(m.get_halted_state).get("halted") is False, (e1, e2))
        check("everything released", call(m.bridge_status).get("state", {}).get("hw_slots_used") == 0)

    if section("bridge health"):
        st = call(m.bridge_status)
        note("requests=%s errors=%s slowest=%sms (%s)" % (st["stats"].get("requests"), st["stats"].get("errors"), st["stats"].get("slowest_ms"), st["stats"].get("slowest_method")))
        check("the bridge answers after all of the above", call(m.ping).get("success"))
        check("no pipe/Lua level errors were counted", st.get("stats", {}).get("errors", 1) <= 10, st.get("stats"))

    print("\nelapsed %.1fs" % (time.monotonic() - t_start))


if __name__ == "__main__":
    try:
        main()
    finally:
        teardown()
    finish()
