"""Offline checks of the capability profiles and tool groups (MCP_Server/tool_policy.py).

No Cheat Engine needed. The end-to-end part starts the real MCP server module in subprocesses with different
CE_MCP_* environments and only ever sends calls that must be DENIED, so nothing can reach a live bridge.

Usage: python tests/test_policy.py
"""
import json
import re
import subprocess
import sys

import testkit
from testkit import EXIT_SKIP, BRIDGE_LUA, REPO_ROOT, finish

SERVER_DIR = REPO_ROOT / "MCP_Server"
sys.path.insert(0, str(SERVER_DIR))
try:
    import tool_policy as tp
except Exception as exc:
    print("SKIP: cannot import tool_policy (%s)" % exc)
    sys.exit(EXIT_SKIP)


def check(name, cond, detail=None):
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else ("  " + str(detail)[:400] if detail is not None else "")), flush=True)


SNIPPET = r'''
import json, os, sys
sys.path.insert(0, %(dir)r)
import mcp_cheatengine as m
tools = m.mcp._tool_manager.list_tools()
out = {"names": sorted(t.name for t in tools),
       "schema_bytes": sum(len(t.description or "") + len(json.dumps(t.parameters)) for t in tools)}
c = m.ce_client
def probe(method, params):
    # only calls the policy refuses go through send_command: an allowed one would reach a live bridge (or fail when CE is closed)
    if m.POLICY.check(method, params) is None:
        return {"success": True, "not_sent": True}
    return c.send_command(method, params)
out["write"] = probe("write_memory", {"address": "0x1", "bytes": [1]})
out["lua"] = probe("evaluate_lua", {"code": "return 1"})
out["batch_bad"] = probe("batch", {"requests": [{"method": "read_memory", "params": {}}, {"method": "write_memory", "params": {}}]})
out["job_bad"] = probe("start_job", {"kind": "evaluate_lua", "params": {}})
out["allowed"] = {"read": m.POLICY.check("read_memory", {}) is None, "bp": m.POLICY.check("set_breakpoint", {}) is None,
                  "write": m.POLICY.check("write_memory", {}) is None, "lua": m.POLICY.check("evaluate_lua", {}) is None,
                  "batch_read": m.POLICY.check("batch", {"requests": [{"method": "read_memory", "params": {}}]}) is None,
                  "job_scan": m.POLICY.check("start_job", {"kind": "scan_all", "params": {}}) is None}
out["info"] = json.loads(m.policy_info(details=True))
print("@@" + json.dumps(out))
'''


def run_server(**env):
    import os
    full = dict(os.environ)
    for k in ("CE_MCP_PROFILE", "CE_MCP_ALLOW", "CE_MCP_DENY", "CE_MCP_TOOLSET"):
        full.pop(k, None)
    full.update(env)
    proc = subprocess.run([sys.executable, "-c", SNIPPET % {"dir": str(SERVER_DIR)}], capture_output=True, text=True, env=full, timeout=120, encoding="utf-8", errors="replace")
    line = next((l for l in proc.stdout.splitlines() if l.startswith("@@")), None)
    if not line:
        return None, proc.stderr
    return json.loads(line[2:]), proc.stderr


# ----------------------------------------------------------------------------- catalogue completeness
default, err = run_server()
if default is None:
    print("SKIP: the MCP server module cannot be imported here:", err[-300:])
    sys.exit(EXIT_SKIP)
tools = set(default["names"])
src = BRIDGE_LUA.read_bytes().decode("utf-8").replace("\r\n", "\n")
block = src[src.index("local commandHandlers = {"):src.index("serverState.dispatch = commandHandlers")]
wire = set(re.findall(r"^\s+([A-Za-z0-9_]+)\s*=\s*cmd_[A-Za-z0-9_]+", block, re.M))
print("-- catalogue")
check("every MCP tool is classified (%d tools)" % len(tools), not [n for n in tools if n not in tp.CATALOG], sorted(n for n in tools if n not in tp.CATALOG))
check("every bridge wire method is classified (%d methods)" % len(wire), not [n for n in wire if n not in tp.CATALOG], sorted(n for n in wire if n not in tp.CATALOG))
check("no stale catalogue entries", not [n for n in tp.CATALOG if n not in tools and n not in wire], sorted(n for n in tp.CATALOG if n not in tools and n not in wire))
check("every group named in the catalogue exists", {g for g, _ in tp.CATALOG.values()} <= set(tp.GROUPS), {g for g, _ in tp.CATALOG.values()} - set(tp.GROUPS))
check("every start_job kind the bridge knows is classified", all(k in tp.JOB_KIND_TIERS for k in ("scan_all", "next_scan", "aob_scan", "find_references", "find_call_references", "rtti_scan", "find_string_refs", "find_code_caves", "find_pointer_path", "find_xrefs")))
check("unknown names are treated as the most dangerous tier", tp.Policy.tier_of("some_future_tool") == tp.EXEC)

# anything that can run code or touch the host must sit in the top tier: a short list of tools that may never be lowered
MUST_BE_EXEC = ["evaluate_lua", "auto_assemble", "auto_assemble_check", "compile_c_code", "compile_cs_code", "create_thread", "queue_to_main_thread",
                "set_global_variable", "execute_code", "execute_code_ex", "execute_method", "execute_code_local", "execute_code_local_ex",
                "inject_dll", "inject_dotnet_dll", "create_process", "run_command", "shell_execute", "delete_file", "write_region_to_file",
                "read_region_from_file", "read_clipboard", "write_clipboard", "load_table", "save_table", "write_process_memory_cr3",
                "map_memory", "allocate_kernel_memory", "set_mouse_pos", "key_down", "do_key_press", "send_window_message", "show_message"]
check("code execution / host access tools are all in the top tier", all(tp.Policy.tier_of(n) == tp.EXEC for n in MUST_BE_EXEC),
      [n for n in MUST_BE_EXEC if tp.Policy.tier_of(n) != tp.EXEC])
MUST_BE_WRITE_OR_HIGHER = ["write_memory", "write_integer", "write_string", "copy_memory", "allocate_memory", "free_memory", "set_memory_protection",
                           "full_access", "debug_set_context", "set_memory_record_value"]
check("tools that change the target are at least 'patch'", all(tp.Policy.tier_of(n) >= tp.WRITE for n in MUST_BE_WRITE_OR_HIGHER))
MUST_BE_READ = ["read_memory", "read_struct", "scan_all", "aob_scan", "disassemble", "pe_info", "find_xrefs", "recover_struct", "ping", "bridge_status", "get_job"]
check("plain observation stays in 'readonly'", all(tp.Policy.tier_of(n) == tp.READ for n in MUST_BE_READ), [n for n in MUST_BE_READ if tp.Policy.tier_of(n) != tp.READ])

# ----------------------------------------------------------------------------- the policy itself
print("-- profiles")
P = lambda profile, **kw: tp.Policy(profile=profile, warn=lambda m: None, **kw)
ro, an, pa, fu = P("readonly"), P("analysis"), P("patch"), P("full")
check("readonly: reads yes, breakpoints no", ro.check("read_memory") is None and ro.check("set_breakpoint")["error_code"] == "PERMISSION_DENIED")
check("analysis: breakpoints yes, writes no", an.check("set_breakpoint") is None and an.check("write_memory")["error_code"] == "PERMISSION_DENIED")
check("patch: writes yes, Lua no", pa.check("write_memory") is None and pa.check("evaluate_lua")["error_code"] == "PERMISSION_DENIED")
check("full: everything", all(fu.check(n) is None for n in tp.CATALOG))
check("the denial says what is needed and how to change it", "'full'" in ro.check("evaluate_lua")["error"] and "CE_MCP_PROFILE" in ro.check("evaluate_lua")["hint"], ro.check("evaluate_lua"))
check("tiers nest: whatever a lower profile may do, a higher one may too",
      all((ro.check(n) is None) <= (an.check(n) is None) <= (pa.check(n) is None) <= (fu.check(n) is None) for n in tp.CATALOG))
bad = tp.Policy(profile="admin", warn=lambda m: None)
check("an unknown profile fails CLOSED", bad.profile == "readonly" and bad.check("write_memory") is not None and len(bad.warnings) == 1)
check("env parsing: default is full, values are case-insensitive", tp.policy_from_env({}).profile == "full" and tp.policy_from_env({"CE_MCP_PROFILE": " ReadOnly "}).profile == "readonly")

print("-- allow / deny")
al = P("readonly", allow={"write_memory"})
check("allow lifts one tool above the profile", al.check("write_memory") is None and al.check("write_integer") is not None)
dn = P("full", deny={"evaluate_lua"})
check("deny removes one tool below the profile", dn.check("evaluate_lua")["error_code"] == "PERMISSION_DENIED" and dn.check("write_memory") is None)
both = P("full", allow={"evaluate_lua"}, deny={"evaluate_lua"})
check("deny wins over allow", both.check("evaluate_lua") is not None)
check("deny on the tool name blocks the wire method behind it (batch_commands -> batch)", P("full", deny={"batch_commands"}).check("batch", {"requests": []}) is not None)
check("deny on a job tool blocks the job kind (find_xrefs -> start_job)", P("full", deny={"find_xrefs"}).check("start_job", {"kind": "find_xrefs"}) is not None and P("full", deny={"rtti_scan_module"}).check("start_job", {"kind": "rtti_scan"}) is not None)

print("-- batch and jobs cannot smuggle")
check("batch of reads is fine in readonly", ro.check("batch", {"requests": [{"method": "read_memory", "params": {}}, {"method": "pe_info", "params": {}}]}) is None)
d = ro.check("batch", {"requests": [{"method": "read_memory", "params": {}}, {"method": "write_memory", "params": {}}]})
check("a write inside a batch is denied, and the reply names it", d and d["error_code"] == "PERMISSION_DENIED" and "write_memory" in d["error"] and "batch" in d["error"], d)
check("Lua inside a batch is denied", ro.check("batch", {"requests": [{"method": "evaluate_lua", "params": {}}]}) is not None and pa.check("batch", {"requests": [{"method": "evaluate_lua", "params": {}}]}) is not None)
check("a nested batch is refused", fu.check("batch", {"requests": [{"method": "batch", "params": {"requests": []}}]}) is not None)
check("malformed batch entries do not crash the check", ro.check("batch", {"requests": ["x", {"params": 1}, None, {"method": 5}]}) is None and ro.check("batch", {"requests": "nope"}) is None and ro.check("batch", None) is None)
check("scan jobs are fine in readonly", ro.check("start_job", {"kind": "scan_all"}) is None and ro.check("start_job", {"kind": "find_xrefs"}) is None)
check("an unknown job kind is treated as dangerous", ro.check("start_job", {"kind": "evaluate_lua"}) is not None and pa.check("start_job", {"kind": "whatever"}) is not None and fu.check("start_job", {"kind": "whatever"}) is None)

print("-- toolsets")
ts = tp.Policy(profile="full", toolset="minimal", warn=lambda m: None)
check("minimal lists memory and scan, not analysis", ts.visible("read_memory") and ts.visible("scan_all") and not ts.visible("pe_info") and not ts.visible("set_breakpoint"))
check("core is always listed", all(tp.Policy(profile="full", toolset=g, warn=lambda m: None).visible("ping") for g in tp.GROUPS))
check("groups combine", tp.Policy(profile="full", toolset="core,analysis", warn=lambda m: None).visible("pe_info") and not tp.Policy(profile="full", toolset="core,analysis", warn=lambda m: None).visible("read_memory"))
check("presets and groups mix", tp.Policy(profile="full", toolset="reverse,asm", warn=lambda m: None).visible("assemble_instruction") and tp.Policy(profile="full", toolset="reverse,asm", warn=lambda m: None).visible("find_xrefs"))
warned = []
unk = tp.Policy(profile="full", toolset="memory,bogus", warn=warned.append)
check("an unknown group is reported and ignored", warned and "bogus" in warned[0] and unk.visible("read_memory") and not unk.visible("pe_info"), warned)
check("only unknown groups: everything stays listed (a toolset is not a security setting)", tp.Policy(profile="full", toolset="bogus", warn=lambda m: None).visible("pe_info"))
check("a toolset never grants anything the profile denies", not tp.Policy(profile="readonly", toolset="all", warn=lambda m: None).visible("write_memory"))
check("hiding is not the gate: a hidden-by-toolset tool can still be called", ts.check("pe_info") is None)

# ----------------------------------------------------------------------------- the real server module
print("-- end to end (real MCP server module in subprocesses)")
check("default: nothing changes, every tool is listed (%d)" % len(default["names"]), len(default["names"]) == len(tools) and "evaluate_lua" in tools and "write_memory" in tools and "policy_info" in tools)
check("default: policy_info reports profile full and hides nothing", default["info"]["profile"] == "full" and sum(default["info"]["tools_hidden"].values()) == 0, default["info"])
check("default: everything is allowed", all(default["allowed"].values()), default["allowed"])

ro_run, _ = run_server(CE_MCP_PROFILE="readonly")
check("readonly: a write is refused before any connection is made", ro_run["write"].get("error_code") == "PERMISSION_DENIED", ro_run["write"])
check("readonly: Lua is refused", ro_run["lua"].get("error_code") == "PERMISSION_DENIED")
check("readonly: a write smuggled in a batch is refused", ro_run["batch_bad"].get("error_code") == "PERMISSION_DENIED" and "write_memory" in ro_run["batch_bad"]["error"], ro_run["batch_bad"])
check("readonly: an exec job kind is refused", ro_run["job_bad"].get("error_code") == "PERMISSION_DENIED")
check("readonly: reads, batches of reads and scan jobs pass", ro_run["allowed"]["read"] and ro_run["allowed"]["batch_read"] and ro_run["allowed"]["job_scan"] and not ro_run["allowed"]["bp"] and not ro_run["allowed"]["write"] and not ro_run["allowed"]["lua"], ro_run["allowed"])
listed = set(ro_run["names"])
check("readonly: dangerous tools are not even listed", not (listed & set(MUST_BE_EXEC)) and not (listed & set(MUST_BE_WRITE_OR_HIGHER)), sorted(listed & (set(MUST_BE_EXEC) | set(MUST_BE_WRITE_OR_HIGHER)))[:10])
check("readonly: the analysis tools are still there", {"read_memory", "scan_all", "pe_info", "find_xrefs", "recover_struct", "policy_info"} <= listed)
check("readonly: no listed tool is above the read tier", all(tp.Policy.tier_of(n) == tp.READ for n in listed), [n for n in listed if tp.Policy.tier_of(n) != tp.READ])
info = ro_run["info"]
check("readonly: policy_info explains it", info["profile"] == "readonly" and info["tier_ceiling"] == "read" and info["tools_hidden"]["profile"] > 50 and "write_memory" in info["hidden_tools"]["profile"], {k: info[k] for k in ("profile", "tools_listed", "tools_hidden")})

an_run, _ = run_server(CE_MCP_PROFILE="analysis")
check("analysis: breakpoints listed, writes not", "set_breakpoint" in an_run["names"] and "write_memory" not in an_run["names"] and an_run["allowed"]["bp"] and not an_run["allowed"]["write"])
pa_run, _ = run_server(CE_MCP_PROFILE="patch")
check("patch: writes listed, Lua not", "write_memory" in pa_run["names"] and "evaluate_lua" not in pa_run["names"] and pa_run["allowed"]["write"] and not pa_run["allowed"]["lua"])
check("each profile lists strictly more than the one below", len(ro_run["names"]) < len(an_run["names"]) < len(pa_run["names"]) < len(default["names"]),
      [len(x["names"]) for x in (ro_run, an_run, pa_run, default)])
bad_run, err = run_server(CE_MCP_PROFILE="superuser")
check("an unknown profile in the environment fails closed and warns on stderr", bad_run["write"].get("error_code") == "PERMISSION_DENIED" and "superuser" in err, err[-200:])
al_run, _ = run_server(CE_MCP_PROFILE="readonly", CE_MCP_ALLOW="write_memory")
check("CE_MCP_ALLOW lifts a single tool and lists it", "write_memory" in al_run["names"] and "write_integer" not in al_run["names"] and al_run["allowed"]["write"])
dn_run, _ = run_server(CE_MCP_DENY="evaluate_lua,run_command")
check("CE_MCP_DENY removes tools from a full profile", "evaluate_lua" not in dn_run["names"] and "run_command" not in dn_run["names"] and "write_memory" in dn_run["names"] and dn_run["lua"].get("error_code") == "PERMISSION_DENIED")

print("-- toolset context saving (informational)")
sizes = {"all": default["schema_bytes"]}
for ts_name in ("minimal", "reverse"):
    run, _ = run_server(CE_MCP_TOOLSET=ts_name)
    sizes[ts_name] = run["schema_bytes"]
    check("toolset %s lists fewer tools than all and still has core + policy_info" % ts_name, len(run["names"]) < len(default["names"]) and {"ping", "bridge_status", "policy_info", "batch_commands"} <= set(run["names"]), len(run["names"]))
ro_sz = ro_run["schema_bytes"]
print("      tool schema size (description + parameters, bytes): all=%d (%d tools), reverse=%d, minimal=%d, readonly profile=%d (%d tools)" %
      (sizes["all"], len(default["names"]), sizes["reverse"], sizes["minimal"], ro_sz, len(ro_run["names"])))
check("a toolset really shrinks what the model has to read", sizes["minimal"] < sizes["reverse"] < sizes["all"] and sizes["minimal"] < sizes["all"] * 0.6, sizes)
tsr, _ = run_server(CE_MCP_TOOLSET="minimal")
check("a hidden-by-toolset tool is still enforced by profile only (policy_info lists the hidden count)", tsr["info"]["tools_hidden"]["toolset"] > 100 and tsr["info"]["toolset"] != "all", tsr["info"]["tools_hidden"])

finish()
