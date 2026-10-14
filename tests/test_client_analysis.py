"""UNIT-26 tools (PE, translation, IDA exchange, analysis jobs, snapshots): parameter forwarding, job wrappers and retry policy against a fake bridge.

Usage: python tests/test_client_analysis.py [path/to/mcp_cheatengine.py]
"""
import importlib.util, json, os, struct, sys, threading, time
import win32file, win32pipe

from testkit import arg_path, BRIDGE_PY, finish

path = str(arg_path(1, BRIDGE_PY))
spec = importlib.util.spec_from_file_location("mcp_cheatengine_under_test", path)
mod = importlib.util.module_from_spec(spec)
real_stdout = sys.stdout
spec.loader.exec_module(mod)
sys.stdout = real_stdout

NAME = "\\\\.\\pipe\\CE_OPS2_%d" % os.getpid()
mod.PIPE_NAME = NAME
mod.CE_MCP_CONNECT_WAIT = 1.5
mod.ce_client.timeout_seconds = 2.0

params_seen = {}
calls = []
polls = {}
lock = threading.Lock()
stop = False


def read_exact(h, n):
    buf = b""
    while len(buf) < n:
        _, chunk = win32file.ReadFile(h, n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send(h, obj, rid):
    raw = json.dumps({"jsonrpc": "2.0", "result": obj, "id": rid}).encode()
    win32file.WriteFile(h, struct.pack("<I", len(raw)))
    win32file.WriteFile(h, raw)


def serve_one(h):
    while True:
        n = struct.unpack("<I", read_exact(h, 4))[0]
        req = json.loads(read_exact(h, n).decode())
        m, rid, p = req["method"], req["id"], req.get("params", {})
        with lock:
            params_seen[m] = p
            calls.append(m)
        if m == "start_job":
            job = "job_slow" if p["kind"] == "find_pointer_path" else ("job_fail" if p["kind"] == "find_code_caves" else "job_fast")
            send(h, {"success": True, "job_id": job, "kind": p["kind"], "state": "running"}, rid)
        elif m == "get_job":
            with lock:
                polls[p["job_id"]] = polls.get(p["job_id"], 0) + 1
                k = polls[p["job_id"]]
            if p["job_id"] == "job_slow" or (p["job_id"] == "job_fast" and k <= 2):
                send(h, {"success": True, "job_id": p["job_id"], "state": "running", "progress": {"current": k, "total": 10}}, rid)
            elif p["job_id"] == "job_fail":
                send(h, {"success": True, "job_id": p["job_id"], "state": "failed", "error": "boom"}, rid)
            else:
                send(h, {"success": True, "job_id": p["job_id"], "state": "done"}, rid)
        elif m == "get_job_result":
            send(h, {"success": True, "echo_offset": p.get("offset"), "echo_limit": p.get("limit")}, rid)
        else:
            send(h, {"success": True, "echo": m}, rid)


def server():
    while not stop:
        h = win32pipe.CreateNamedPipe(NAME, win32pipe.PIPE_ACCESS_DUPLEX,
                                      win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                                      1, 65536, 65536, 0, None)
        try:
            win32pipe.ConnectNamedPipe(h, None)
            serve_one(h)
        except Exception:
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h)
            except Exception:
                pass
            win32file.CloseHandle(h)
        time.sleep(0.1)


results = []


def check(name, cond, extra=""):
    results.append(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(extra)))
    print(results[-1], flush=True)


threading.Thread(target=server, daemon=True).start()
time.sleep(0.3)

# ---- parameter cleaning / forwarding of the synchronous tools
mod.pe_info()
check("pe_info() sends no params", params_seen["pe_info"] == {}, params_seen["pe_info"])
mod.pe_info(module="game.exe")
check("pe_info module forwarded", params_seen["pe_info"] == {"module": "game.exe"})
mod.pe_imports(dll="kernel")
check("pe_imports drops empty module, keeps paging", params_seen["pe_imports"] == {"dll": "kernel", "offset": 0, "limit": 100}, params_seen["pe_imports"])
mod.pe_exports(name_contains="Create", limit=5)
check("pe_exports filter", params_seen["pe_exports"] == {"name_contains": "Create", "offset": 0, "limit": 5}, params_seen["pe_exports"])
mod.pe_tls_callbacks()
check("pe_tls_callbacks", params_seen["pe_tls_callbacks"] == {})
mod.va_to_rva(addresses=["0x1000", "0x2000"], ida_image_base="0x400000")
check("va_to_rva list + ida base", params_seen["va_to_rva"] == {"addresses": ["0x1000", "0x2000"], "ida_image_base": "0x400000", "include_section": True}, params_seen["va_to_rva"])
mod.rva_to_va(module="game.exe", rva="0x10")
check("rva_to_va", params_seen["rva_to_va"] == {"module": "game.exe", "rva": "0x10"}, params_seen["rva_to_va"])
mod.rebase_address(address="0x402800", from_base="0x400000", to_module="game.exe")
check("rebase_address", params_seen["rebase_address"] == {"address": "0x402800", "from_base": "0x400000", "to_module": "game.exe"}, params_seen["rebase_address"])
mod.export_names(module="game.exe", format="idapython")
check("export_names", params_seen["export_names"] == {"module": "game.exe", "format": "idapython", "include_types": True}, params_seen["export_names"])
mod.export_structures()
check("export_structures", params_seen["export_structures"] == {})
mod.import_names([{"name": "A", "rva": "0x10"}], module="game.exe")
p = params_seen["import_names"]
check("import_names", p["names"][0]["name"] == "A" and p["module"] == "game.exe" and p["do_not_save"] is True and "address_is_ida" not in p, p)
mod.import_names([{"name": "A", "address": "0x1"}], address_is_ida=True, ida_image_base="0x400000", prefix="x_")
p = params_seen["import_names"]
check("import_names ida flags", p["address_is_ida"] is True and p["prefix"] == "x_" and p["ida_image_base"] == "0x400000", p)
mod.pe_functions()
check("pe_functions() sends only paging", params_seen["pe_functions"] == {"offset": 0, "limit": 100}, params_seen["pe_functions"])
mod.pe_functions(address="0x140001025", include_unwind=True)
check("pe_functions address + unwind", params_seen["pe_functions"] == {"address": "0x140001025", "offset": 0, "limit": 100, "include_unwind": True}, params_seen["pe_functions"])
mod.recover_struct(addresses=["0x2A000000", "0x2A000200"], create=True, name="Player")
check("recover_struct forwards instances/create/name", params_seen["recover_struct"] == {"addresses": ["0x2A000000", "0x2A000200"], "name": "Player", "create": True}, params_seen["recover_struct"])
mod.recover_struct(address="0x2A000000", size=512)
check("recover_struct single instance", params_seen["recover_struct"] == {"address": "0x2A000000", "size": 512}, params_seen["recover_struct"])
mod.set_breakpoint("0x1000")
check("set_breakpoint defaults send no new options", params_seen["set_breakpoint"] == {"address": "0x1000", "capture_registers": True, "capture_stack": False, "stack_depth": 16}, params_seen["set_breakpoint"])
mod.set_breakpoint("0x1000", id="x", condition="RAX==5", mode="break", max_hits=3, halt_timeout_ms=2000, inspect=[{"expr": "RDX", "size": 8}])
check("set_breakpoint forwards condition/mode/max_hits/halt_timeout/inspect", params_seen["set_breakpoint"] == {
    "address": "0x1000", "id": "x", "capture_registers": True, "capture_stack": False, "stack_depth": 16, "condition": "RAX==5",
    "mode": "break", "max_hits": 3, "halt_timeout_ms": 2000, "inspect": [{"expr": "RDX", "size": 8}]}, params_seen["set_breakpoint"])
mod.set_data_breakpoint("0x9000")
check("set_data_breakpoint defaults", params_seen["set_data_breakpoint"] == {"address": "0x9000", "access_type": "w", "size": 4}, params_seen["set_data_breakpoint"])
mod.set_data_breakpoint("0x9000", access_type="rw", size=8, condition="1", max_hits=2)
check("set_data_breakpoint forwards options", params_seen["set_data_breakpoint"] == {"address": "0x9000", "access_type": "rw", "size": 8, "condition": "1", "max_hits": 2}, params_seen["set_data_breakpoint"])
mod.get_halted_state()
check("get_halted_state defaults", params_seen["get_halted_state"] == {"stack_depth": 16}, params_seen["get_halted_state"])
mod.get_halted_state(stack_depth=4, extend_ms=500)
check("get_halted_state options", params_seen["get_halted_state"] == {"stack_depth": 4, "extend_ms": 500}, params_seen["get_halted_state"])
mod.snapshot_region(address="0x9000", size=16, name="A")
check("snapshot_region address", params_seen["snapshot_region"] == {"address": "0x9000", "size": 16, "name": "A"}, params_seen["snapshot_region"])
mod.snapshot_region(module="game.exe", section=".data")
check("snapshot_region section (size omitted)", params_seen["snapshot_region"] == {"module": "game.exe", "section": ".data"}, params_seen["snapshot_region"])
mod.list_snapshots()
mod.delete_snapshot(name="A")
check("delete_snapshot name", params_seen["delete_snapshot"] == {"name": "A"}, params_seen["delete_snapshot"])
mod.delete_snapshot(all=True)
check("delete_snapshot all", params_seen["delete_snapshot"] == {"all": True}, params_seen["delete_snapshot"])
mod.diff_snapshots(["A", "B"])
check("diff_snapshots minimal", params_seen["diff_snapshots"] == {"snapshots": ["A", "B"], "unit": 4, "limit": 200}, params_seen["diff_snapshots"])
mod.diff_snapshots(["A", "B", "C"], pattern="CU", unit=8, offset=16, length=64, merge_gap=8, limit=5)
check("diff_snapshots full", params_seen["diff_snapshots"] == {"snapshots": ["A", "B", "C"], "pattern": "CU", "unit": 8, "offset": 16, "length": 64, "merge_gap": 8, "limit": 5}, params_seen["diff_snapshots"])

# ---- job-backed tools
out = json.loads(mod.rtti_scan_module(module="game.exe", wait_seconds=5, limit=50, offset=10))
check("rtti_scan_module: start_job params", params_seen["start_job"] == {"kind": "rtti_scan", "params": {"module": "game.exe", "max_vtable_entries": 256}}, params_seen["start_job"])
check("rtti_scan_module waits then fetches paged result", out.get("echo_offset") == 10 and out.get("echo_limit") == 50, out)
t0 = time.monotonic()
out = json.loads(mod.find_pointer_path("0x2A000100", wait_seconds=0.7))
check("find_pointer_path: params", params_seen["start_job"] == {"kind": "find_pointer_path", "params": {
    "address": "0x2A000100", "max_depth": 3, "max_offset": 1024, "max_per_level": 16, "max_results": 100, "protection": "+W"}}, params_seen["start_job"])
check("find_pointer_path: times out cleanly with the job id", out.get("timed_out") is True and out.get("job_id") == "job_slow" and "wait_for_job('job_slow')" in out.get("hint", ""), out)
check("find_pointer_path: honoured wait_seconds", 0.5 < time.monotonic() - t0 < 3, time.monotonic() - t0)
out = json.loads(mod.find_code_caves(wait_seconds=3))
check("find_code_caves: failed job status is returned as-is", out.get("state") == "failed" and out.get("error") == "boom", out)
check("find_code_caves: defaults", params_seen["start_job"] == {"kind": "find_code_caves", "params": {"byte": 204, "min_size": 16, "sections": "exec"}}, params_seen["start_job"])
mod.find_string_refs(text="Hello", wait_seconds=3)
check("find_string_refs: params (wide dropped when false)", params_seen["start_job"] == {"kind": "find_string_refs", "params": {"text": "Hello", "match": "start", "include_data": True}}, params_seen["start_job"])
mod.find_string_refs(address="0x1000", wide=True, match="any", include_data=False, wait_seconds=3)
check("find_string_refs: address/wide/any/no-data", params_seen["start_job"]["params"] == {"address": "0x1000", "wide": True, "match": "any", "include_data": False}, params_seen["start_job"])
out = json.loads(mod.find_xrefs("game.exe+1234", wait_seconds=3, limit=20, offset=40))
check("find_xrefs: defaults send only the address", params_seen["start_job"] == {"kind": "find_xrefs", "params": {"address": "game.exe+1234"}}, params_seen["start_job"])
check("find_xrefs: paging goes to get_job_result", out.get("echo_offset") == 40 and out.get("echo_limit") == 20, out)
mod.find_xrefs("0x3000", size=32, module="all", kinds="call,rip", max_results=100, wait_seconds=3)
check("find_xrefs: size/module/kinds/max_results forwarded", params_seen["start_job"] == {"kind": "find_xrefs", "params": {
    "address": "0x3000", "size": 32, "module": "all", "kinds": "call,rip", "max_results": 100}}, params_seen["start_job"])
mod.find_pointer_path("0x2A000100", save_as="hp", wait_seconds=0.3)
check("find_pointer_path: save_as forwarded", params_seen["start_job"]["params"].get("save_as") == "hp", params_seen["start_job"])

# ---- pointer path sets (two-run comparison)
mod.compare_pointer_paths("0x1F000100", name="hp")
check("compare_pointer_paths: defaults send only target, name and limit", params_seen["compare_pointer_paths"] == {"target": "0x1F000100", "name": "hp", "limit": 100}, params_seen["compare_pointer_paths"])
mod.compare_pointer_paths("0x1F000100", chains=[{"base": "game.exe+0x10", "offsets": [64]}], save_as="x", near_delta=64, near_limit=3, offset=5, limit=10)
check("compare_pointer_paths: everything forwarded", params_seen["compare_pointer_paths"] == {
    "target": "0x1F000100", "chains": [{"base": "game.exe+0x10", "offsets": [64]}], "save_as": "x", "near_delta": 64, "near_limit": 3, "offset": 5, "limit": 10}, params_seen["compare_pointer_paths"])
mod.list_pointer_sets()
check("list_pointer_sets calls the bridge", calls[-1] == "list_pointer_sets")
mod.get_pointer_set("hp", offset=2, limit=5)
check("get_pointer_set params", params_seen["get_pointer_set"] == {"name": "hp", "offset": 2, "limit": 5}, params_seen["get_pointer_set"])
mod.drop_pointer_set(name="hp")
check("drop_pointer_set by name", params_seen["drop_pointer_set"] == {"name": "hp"}, params_seen["drop_pointer_set"])
mod.drop_pointer_set(all=True)
check("drop_pointer_set all", params_seen["drop_pointer_set"] == {"all": True}, params_seen["drop_pointer_set"])

# ---- retry policy table for the new bridge methods
for m, want in [("pe_info", True), ("get_halted_state", True), ("pe_functions", True), ("pe_imports", True), ("pe_exports", True), ("pe_tls_callbacks", True), ("va_to_rva", True),
                ("rva_to_va", True), ("rebase_address", True), ("export_names", True), ("export_structures", True), ("diff_snapshots", True),
                ("snapshot_region", True), ("list_snapshots", True), ("delete_snapshot", True), ("import_names", False), ("start_job", False),
                ("list_pointer_sets", True), ("get_pointer_set", True), ("compare_pointer_paths", False), ("drop_pointer_set", False)]:
    check("is_idempotent(%s)==%s" % (m, want), mod.is_idempotent(m) == want)

# ---- MCP registration / schemas
tools = {tool.name: tool for tool in mod.mcp._tool_manager.list_tools()}
need = ["pe_info", "get_halted_state", "pe_functions", "recover_struct", "pe_imports", "pe_exports", "pe_tls_callbacks", "va_to_rva", "rva_to_va", "rebase_address", "export_names", "export_structures",
        "import_names", "rtti_scan_module", "find_string_refs", "find_xrefs", "find_code_caves", "find_pointer_path", "snapshot_region", "list_snapshots",
        "delete_snapshot", "diff_snapshots", "compare_pointer_paths", "list_pointer_sets", "get_pointer_set", "drop_pointer_set"]
check("all new tools registered with MCP", all(n in tools for n in need), [n for n in need if n not in tools])
check("diff_snapshots schema", tools["diff_snapshots"].parameters["properties"]["snapshots"]["type"] == "array", tools["diff_snapshots"].parameters)
check("find_xrefs requires address", tools["find_xrefs"].parameters.get("required") == ["address"], tools["find_xrefs"].parameters.get("required"))
check("compare_pointer_paths requires only target", tools["compare_pointer_paths"].parameters.get("required") == ["target"], tools["compare_pointer_paths"].parameters.get("required"))
check("compare_pointer_paths chains schema is a list", tools["compare_pointer_paths"].parameters["properties"]["chains"].get("anyOf") is not None
      or tools["compare_pointer_paths"].parameters["properties"]["chains"].get("type") == "array", tools["compare_pointer_paths"].parameters["properties"]["chains"])
check("find_pointer_path requires address", tools["find_pointer_path"].parameters.get("required") == ["address"], tools["find_pointer_path"].parameters.get("required"))

stop = True
finish()
