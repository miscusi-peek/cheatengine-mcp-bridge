"""Offline checks of the Lua bridge's JSON codec, reply handling and breakpoint-hit recording.

Drives the real functions extracted from ce_mcp_bridge.lua inside CE's Lua 5.3 (no Cheat Engine process).
Usage: python tests/test_lua_robustness.py [path/to/ce_mcp_bridge.lua]
"""
import sys

from lua_harness import run_lua, load, between, func_block, arg_path, finish, BRIDGE_LUA


def suite(label, path):
    t = load(path)
    print("=" * 70)
    print(label, path)
    print("=" * 70)
    # Compile only (never execute the bridge here - it needs CE globals)
    ok, msg = run_lua('local f, e = load([==[' + t + ']==], "bridge", "t"); return f and "COMPILE OK" or ("COMPILE FAIL: " .. tostring(e))')
    print(msg)

    codec = between(t, "local json = {}", "json.decode = decode\n")
    codec_tests = r'''
local results = {}
local function eq(name, got, want)
  results[#results+1] = (got == want and "PASS  " or "FAIL  ") .. name .. (got == want and "" or ("  got=" .. tostring(got)))
end
local function try(f, ...) local ok, r = pcall(f, ...) if ok then return r end return "ERR:" .. tostring(r) end

eq("decode \\u00e9 -> UTF-8", try(function() return json.decode('{"s":"\\u00e9"}').s end), "\xC3\xA9")
eq("decode \\u20ac (>0xFF) -> UTF-8", try(function() return json.decode('["\\u20ac"]')[1] end), "\xE2\x82\xAC")
eq("decode surrogate pair", try(function() return json.decode('["\\ud83d\\ude00"]')[1] end), "\xF0\x9F\x98\x80")
eq("decode lone surrogate -> U+FFFD", try(function() return json.decode('["\\ud83dx"]')[1] end), "\xEF\xBF\xBDx")
eq("decode escaped backslash + u0041", try(function() return json.decode('["\\\\u0041"]')[1] end), "\\u0041")
eq("decode simple escapes", try(function() return json.decode('["a\\n\\t\\"b\\\\"]')[1] end), 'a\n\t"b\\')
eq("decode plain string", try(function() return json.decode('{"k":"v"}').k end), "v")
eq("decode nested obj", try(function() return json.decode('{"a":{"b":[1,2,"x"]}}').a.b[3] end), "x")

local big = 0x7FF612345678
eq("encode int64 pointer exact", try(json.encode, {v = big}), '{"v":' .. string.format("%d", big) .. '}')
eq("encode maxint64", try(json.encode, {v = math.maxinteger}), '{"v":9223372036854775807}')
eq("encode negative int", try(json.encode, {v = -1}), '{"v":-1}')
eq("encode float 0.1", try(json.encode, {v = 0.1}), '{"v":0.1}')
local third = 1/3
eq("encode float round-trips", tonumber(json.encode({v = third}):match(":(.-)}")), third)
eq("encode nan -> null", try(json.encode, {v = 0/0}), '{"v":null}')
eq("encode invalid UTF-8 -> U+FFFD", try(json.encode, {s = "a\xFFb"}), '{"s":"a\xEF\xBF\xBDb"}')
eq("encode valid UTF-8 untouched", try(json.encode, {s = "\xC3\xA9"}), '{"s":"\xC3\xA9"}')
eq("encode control char", try(json.encode, {s = "a\1b"}), '{"s":"a\\u0001b"}')
eq("encode NUL byte", try(json.encode, {s = "a\0b"}), '{"s":"a\\u0000b"}')
eq("encode quote+backslash", try(json.encode, {s = 'q"\\'}), '{"s":"q\\"\\\\"}')
eq("round-trip unicode", try(function() return json.decode(json.encode({s = "h\xC3\xA9llo \xE2\x82\xAC"})).s end), "h\xC3\xA9llo \xE2\x82\xAC")
return table.concat(results, "\n")
'''
    ok, msg = run_lua(codec + "\n" + codec_tests, "codec")
    print("-- JSON codec"); print(msg)

    if "local function recordBpHit" in t:
        helpers = between(t, "-- Max buffered hits per breakpoint", "function cmd_set_breakpoint(params)", include_end=False)
        bp_tests = r'''
local results = {}
local function eq(name, got, want)
  results[#results+1] = (got == want and "PASS  " or "FAIL  ") .. name .. (got == want and "" or ("  got=" .. tostring(got)))
end
local serverState = { breakpoints = {}, breakpoint_hits = {} }
local continues = 0
co_run = 1
function debug_continueFromBreakpoint() continues = continues + 1 end
local function log() end
''' + helpers + r'''
-- bucket missing (cleared/removed in flight): must not raise
eq("recordBpHit with nil bucket doesn't raise", pcall(recordBpHit, "ghost", {n = 1}), true)

-- callback body that throws must still continue the target and return 1
local cb = safeBpCallback(function() error("boom") end)
local r = cb()
eq("throwing body -> still continues", continues, 1)
eq("throwing body -> returns 1", r, 1)
-- the original failure mode: table.insert on a nil bucket
cb = safeBpCallback(function() table.insert(serverState.breakpoint_hits["gone"], {}) end)
cb()
eq("nil-bucket insert -> still continues", continues, 2)

-- capped buffer + cumulative counters
serverState.breakpoints.a = {}
serverState.breakpoint_hits.a = {}
for i = 1, 5000 do recordBpHit("a", {n = i}) end
local b = serverState.breakpoint_hits.a
eq("buffer capped", #b <= MAX_HITS_PER_BP, true)
eq("total_hits cumulative", serverState.breakpoints.a.total_hits, 5000)
eq("hits conserved (kept + dropped)", #b + (serverState.breakpoints.a.dropped_hits or 0), 5000)
eq("newest hit last", b[#b].n, 5000)
local ordered = true
for i = 2, #b do if b[i].n ~= b[i-1].n + 1 then ordered = false end end
eq("order preserved, no gaps", ordered, true)
-- clear by replacement (get_breakpoint_hits clear) then keep recording
serverState.breakpoint_hits = {}
eq("record after wholesale clear doesn't raise", pcall(recordBpHit, "a", {n = 1}), true)
serverState.breakpoint_hits.a = {}
recordBpHit("a", {n = 7})
eq("records into fresh bucket", #serverState.breakpoint_hits.a, 1)
return table.concat(results, "\n")
'''
        ok, msg = run_lua(bp_tests, "bp")
        print("-- breakpoint recording"); print(msg)

    if "local function encodeReply" in t:
        blk = between(t, "-- json.encode can throw", "local function executeCommand(jsonRequest)", include_end=False)
        blk += func_block(t, "local function executeCommand(jsonRequest)")
        reply_tests = r'''
local results = {}
local function eq(name, got, want)
  results[#results+1] = (got == want and "PASS  " or "FAIL  ") .. name .. (got == want and "" or ("  got=" .. tostring(got)))
end
local commandHandlers = {
  ok = function(p) return { success = true, v = p.x } end,
  circular = function() local t = {}; t.self = t; return t end,
  badtype = function() return { co = coroutine.create(function() end) } end,
  throws = function() error("kaboom") end,
  nilret = function() return nil end,
  badutf = function() return { s = "x\xFFy" } end,
}
''' + blk + r'''
local function reply(s) return json.decode(executeCommand(s)) end
local r = reply('{"jsonrpc":"2.0","method":"ok","params":{"x":5},"id":9}')
eq("normal call", r.result.v, 5)
eq("id echoed", r.id, 9)
r = reply('{"method":"circular","params":{},"id":1}')
eq("circular result -> JSON error reply (-32603)", r.error and r.error.code, -32603)
r = reply('{"method":"badtype","id":2}')
eq("unencodable type -> JSON error reply", r.error and r.error.code, -32603)
r = reply('{"method":"throws","id":3}')
eq("handler throws -> error reply", r.error and r.error.code, -32603)
eq("handler throws -> id kept", r.id, 3)
r = reply('{"method":"badutf","id":4}')
eq("invalid UTF-8 result still valid JSON", r.result and r.result.s, "x\xEF\xBF\xBDy")
r = reply('{"method":"nope","id":5}')
eq("unknown method -> -32601", r.error and r.error.code, -32601)
r = reply('5')
eq("non-object request -> parse error", r.error and r.error.code, -32700)
r = reply('not json')
eq("garbage -> parse error", r.error and r.error.code, -32700)
r = reply('{"method":"ok","params":[1,2],"id":6}')
eq("non-object params tolerated", r.result and r.result.success, true)
eq("nil result doesn't raise", pcall(executeCommand, '{"method":"nilret","id":7}'), true)
return table.concat(results, "\n")
'''
        ok, msg = run_lua(codec + "\nlocal serverState = { stats = { requests = 0, errors = 0 } }\n" + reply_tests, "reply")
        print("-- executeCommand"); print(msg)


def contract_lint(path):
    """The three "is a process attached?" helpers have different return contracts. They once shared one name, so the
    last `local function requireProcess` silently replaced the earlier ones for everything below it (every UNIT-25..28
    tool returned `true` in a real Cheat Engine while the offline tests, which extract only the first definition,
    passed). Each contract now has its own name; this lint keeps it that way."""
    import re
    lines = load(path).split("\n")
    print("-- requireProcess contract lint")
    contracts = {
        "requireProcess": (r"local \w+ = requireProcess\(\)\s*$", "returns nil or an error table"),
        "requireProcessPair": (r"local ok, err = requireProcessPair\(\)\s*$", "returns ok, err"),
        "requireProcessBool": (r"if not requireProcessBool\(\) then", "returns a boolean"),
    }
    for name, (call_re, meaning) in contracts.items():
        defs = [i for i, l in enumerate(lines) if re.match(r"local function %s\(\)" % name, l)]
        print(("PASS  " if len(defs) == 1 else "FAIL  ") + "%s is defined exactly once (found %d)" % (name, len(defs)))
        calls = [(i, l) for i, l in enumerate(lines) if re.search(r"\b%s\(" % name, l) and not l.lstrip().startswith("--") and not re.match(r"local function ", l)]
        bad = [(i + 1, l.strip()[:70]) for i, l in calls if not re.search(call_re, l)]
        print(("PASS  " if not bad else "FAIL  ") + "every call of %s expects what it %s (%d call sites)%s" % (name, meaning, len(calls), "" if not bad else "  bad=%s" % bad[:3]))
        early = [i + 1 for i, _ in calls if defs and i < defs[0]]
        print(("PASS  " if not early else "FAIL  ") + "%s is never called before its definition%s" % (name, "" if not early else "  lines=%s" % early[:3]))
    dup = sorted({m.group(1) for l in lines for m in [re.match(r"local function (requireProcess\w*)\(", l)] if m} - set(contracts))
    print(("PASS  " if not dup else "FAIL  ") + "no other requireProcess* helper has appeared%s" % ("" if not dup else "  " + str(dup)))
    body = "\n".join(lines[next(i for i, l in enumerate(lines) if l.startswith("local function requireProcess()")):][:7])
    print(("PASS  " if "return nil" in body and "error_code" in body else "FAIL  ") + "requireProcess() returns nil when a process is attached, else an error table")


suite("bridge", arg_path(1, BRIDGE_LUA))
contract_lint(arg_path(1, BRIDGE_LUA))
finish()
