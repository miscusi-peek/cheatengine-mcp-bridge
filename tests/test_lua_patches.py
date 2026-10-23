"""Offline checks of UNIT-31: the patch journal (every write through the bridge's write tools is recorded with the bytes
it replaced) and undo_patch / list_patches.

The real write handlers (write_memory, write_integer, write_string, copy_memory, auto_assemble) run against a fake CE
whose write functions change the fake memory, wrapped exactly as the dispatcher wraps them (U26.pjWrap).

Usage: python tests/test_lua_patches.py [path/to/ce_mcp_bridge.lua]
Set BRIDGE_TEST_DUMP=<file> to write the generated Lua test program for debugging.
"""
import json
import os
import shutil
import tempfile
from pathlib import Path

from lua_harness import run_lua, load, func_end, arg_path, finish, compile_check, BRIDGE_LUA
from fake_ce import STUBS, HELPERS


t = load(arg_path(1, BRIDGE_LUA))
compile_check(t)

prefix = t[:t.index("-- Shared helper: scan for MZ PE headers")]
_, j = func_end(t, "function cmd_read_memory(params)")
read_block = t[t.index("-- Byte-table helpers shared by read_memory"):j]
_, j = func_end(t, "function cmd_next_scan(params)")
scan_block = t[t.index("local USER_MODE_MAX"):j]
handlers = ""
for name in ("cmd_write_integer", "cmd_write_memory", "cmd_write_string", "cmd_copy_memory", "cmd_auto_assemble"):
    i, j = func_end(t, "function %s(params)" % name)
    handlers += t[i:j] + "\n"


def unit(n):
    return t[t.index("-- >>> BEGIN UNIT-%d" % n):t.index("-- >>> END UNIT-%d <<<" % n)]


common = (STUBS + "\n" + 'local BPX = { watchdog = function() return false end }\n' + prefix + "\n" + read_block + "\n" + scan_block + "\n" +
          unit(25) + "\n" + unit(26) + "\n" + unit(27) + "\n" + unit(28) + "\n" + unit(30) + "\n" + unit(31) + "\n" + handlers + "\n")

TESTS = r'''
-- fake CE writes: they change the fake memory like the real ones change the target
local function bytesOf(t) local o = {} for i = 1, #t, 4096 do o[#o + 1] = string.char(table.unpack(t, i, math.min(i + 4095, #t))) end return table.concat(o) end
WRITE_PROTECTED = {}
function writeBytes(a, t)
  if WRITE_PROTECTED[a] then return true end          -- "succeeds" but nothing changes
  poke(a, bytesOf(t)); return true
end
function writeByte(a, v) poke(a, string.pack("<I1", v)) return true end
function writeSmallInteger(a, v) poke(a, string.pack("<I2", v)) return true end
function writeInteger(a, v) poke(a, string.pack("<I4", v)) return true end
function writeQword(a, v) poke(a, string.pack("<i8", v)) return true end
function writeFloat(a, v) poke(a, string.pack("<f", v)) return true end
function writeDouble(a, v) poke(a, string.pack("<d", v)) return true end
function writeString(a, s, wide)
  if wide then s = s:gsub(".", "%0\0") end
  poke(a, s); return true
end
function copyMemory(src, size, dest)
  local b = readBytes(src, size, true); if not b then return nil end
  if not dest then dest = 0xC0000 end
  poke(dest, bytesOf(b)); return dest
end
AA_CALLS = {}
function autoAssemble(script, info)
  AA_CALLS[#AA_CALLS + 1] = { script = script, info = info }
  if script:find("SYNTAX ERROR", 1, true) then return false, "line 1: syntax" end
  if info then poke(0x140003100, "\x01\x02"); return true end              -- the [DISABLE] section restores the bytes
  poke(0x140003100, "\x90\x90")
  return true, { symbols = { newmem = 0x7FF00000 }, allocs = {} }
end

local G = 0x140000000
MODULES = { { Name = "game.exe", Address = G, Size = 0x5000, Is64Bit = true } }
PROCESS_PID = 4242
TARGET64 = true
local function rdhex(a, n) local s = U26.rd(a, n); return s and U26.pjHex(s) or "unreadable" end
local H = { write_memory = cmd_write_memory, write_integer = cmd_write_integer, write_string = cmd_write_string,
            copy_memory = cmd_copy_memory, auto_assemble = cmd_auto_assemble, read_memory = function() return { success = true } end }
U26.pjWrap(H)
eq("only the write tools are wrapped", H.write_memory ~= cmd_write_memory and H.auto_assemble ~= cmd_auto_assemble and H.read_memory ~= nil, true)
local function byId(r, id) for _, p in ipairs(r.patches or {}) do if p.id == id then return p end end return {} end

-- ===================== recording =====================
poke(G + 0x3000, "\x11\x22\x33\x44")
local r = H.write_memory({ address = G + 0x3000, bytes = { 0xAA, 0xBB } })
eq("write_memory succeeds and returns a patch id", r.success == true and r.patch_id == "p1" and r.patch_note == nil, true)
eq("the write happened", rdhex(G + 0x3000, 4), "AA BB 33 44")
local l = cmd_list_patches({})
local p1 = byId(l, "p1")
eq("journal entry: original, written, size, expression", p1.original == "11 22" and p1.written == "AA BB" and p1.size == 2
   and p1.expression == "game.exe+0x3000" and p1.address == string.format("0x%X", G + 0x3000) and p1.kind == "bytes", true)
eq("journal entry: live state and undoable", p1.state == "applied" and p1.undoable == true and p1.method == "write_memory" and p1.pid == 4242, true)

poke(G + 0x3010, "\x04\x03\x02\x01\xEE")
r = H.write_integer({ address = G + 0x3010, value = 5, type = "dword" })
eq("write_integer journals exactly 4 bytes", r.patch_id == "p2" and byId(cmd_list_patches({}), "p2").original == "04 03 02 01", true)
r = H.write_integer({ address = G + 0x3018, value = 1.5, type = "double" })
eq("write_integer double journals 8 bytes", byId(cmd_list_patches({}), r.patch_id).size, 8)
r = H.write_integer({ address = string.format("0x%X", G + 0x3020), value = 1, type = "byte" })
eq("an address given as text works", byId(cmd_list_patches({}), r.patch_id).size == 1 and r.success, true)
r = H.write_string({ address = G + 0x3040, value = "hi", wide = true })
eq("write_string wide journals 2 bytes per character", byId(cmd_list_patches({}), r.patch_id).size == 4 and rdhex(G + 0x3040, 4) == "68 00 69 00", true)
r = H.write_string({ address = G + 0x3048, value = "abc" })
eq("write_string ansi journals its length (no terminator)", byId(cmd_list_patches({}), r.patch_id).size, 3)
r = H.copy_memory({ source = G + 0x3000, size = 2, dest = G + 0x3050 })
eq("copy_memory into existing memory is journaled", r.patch_id ~= nil and byId(cmd_list_patches({}), r.patch_id).size == 2 and rdhex(G + 0x3050, 2) == "AA BB", true)
local before = cmd_list_patches({}).total
r = H.copy_memory({ source = G + 0x3000, size = 2 })
eq("copy_memory into fresh memory overwrites nothing: no entry", r.success == true and r.patch_id == nil and cmd_list_patches({}).total == before, true)

-- failed writes leave no trace
before = cmd_list_patches({}).total
r = H.write_memory({ address = "nowhere", bytes = { 1 } })
eq("a failed write is not journaled", r.success == false and r.patch_id == nil and cmd_list_patches({}).total == before, true)
r = H.write_integer({ address = G + 0x3010, value = 0x1FF, type = "byte" })
eq("a refused write is not journaled", r.success == false and cmd_list_patches({}).total == before, true)

-- ===================== undo =====================
r = cmd_undo_patch({ id = "p1" })
eq("undo_patch restores the original bytes", r.success == true and r.undone == true and rdhex(G + 0x3000, 4) == "11 22 33 44", true)
eq("an undone patch says so", byId(cmd_list_patches({}), "p1").state == "undone" and byId(cmd_list_patches({}), "p1").undoable == false, true)
r = cmd_undo_patch({ id = "p1" })
eq("undoing twice is refused", r.success == false and r.error == "already undone", true)
eq("active_only hides undone patches", byId(cmd_list_patches({ active_only = true }), "p1").id, nil)

r = H.write_memory({ address = G + 0x3060, bytes = { 0x10, 0x20 } })
local pc = r.patch_id
poke(G + 0x3060, "\x99")                                   -- the game changes the patched bytes afterwards
eq("a changed patch shows state=changed", byId(cmd_list_patches({}), pc).state, "changed")
r = cmd_undo_patch({ id = pc })
eq("undo refuses to overwrite bytes that changed since the patch", r.success == false and r.conflict == true and rdhex(G + 0x3060, 2) == "99 20", true)
r = cmd_undo_patch({ id = pc, force = true })
eq("force=true restores them anyway", r.success == true and rdhex(G + 0x3060, 2) == "00 00", true)

-- overlapping patches: the older one cannot be undone underneath the newer one
r = H.write_memory({ address = G + 0x3080, bytes = { 0xCC, 0xCC } }); local pOld = r.patch_id
r = H.write_memory({ address = G + 0x3080, bytes = { 0xDD, 0xDD } }); local pNew = r.patch_id
r = cmd_undo_patch({ id = pOld })
eq("undoing an older patch under a newer one is a conflict", r.success == false and r.conflict == true and rdhex(G + 0x3080, 2) == "DD DD", true)

-- a write that does not stick
WRITE_PROTECTED[G + 0x3020] = true
r = cmd_undo_patch({ id = "p4" })
eq("an undo that does not change the memory is reported", r.success == false and r.error:find("did not stick", 1, true) ~= nil, true)
WRITE_PROTECTED[G + 0x3020] = nil

-- undo everything: newest first, so stacked patches unwind cleanly
r = cmd_undo_patch({ all = true })
eq("undo all: everything active is undone", r.success == true and r.failed == 0 and r.undone >= 8, true)
eq("undo all goes newest first (stacked patches unwind)", r.results[1].id == pNew and rdhex(G + 0x3080, 2) == "00 00", true)
eq("undo all restored the integers and strings", rdhex(G + 0x3010, 5) == "04 03 02 01 EE" and rdhex(G + 0x3040, 4) == "00 00 00 00", true)
r = cmd_undo_patch({ all = true })
eq("undo all with nothing left", r.success == true and r.undone == 0 and r.failed == 0, true)

-- ===================== what cannot be undone =====================
r = H.write_memory({ address = 0x900000, bytes = { 1, 2 } })    -- no page there before the write: the original is unknown
eq("unreadable original: journaled, flagged, not undoable", r.success == true and r.patch_note ~= nil and byId(cmd_list_patches({}), r.patch_id).state == "not_undoable", true)
eq("... and undo says why", cmd_undo_patch({ id = r.patch_id }).error, "the original bytes could not be read before the write")
local big = {}
for k = 1, 0x10001 do big[k] = 0x41 end
poke(0x2000000, string.rep("\0", 0x10001))                         -- readable: only the size keeps it out of the journal
r = H.write_memory({ address = 0x2000000, bytes = big })
eq("a write over 64 KB is journaled as not undoable", r.success == true and byId(cmd_list_patches({}), r.patch_id).reason:find("larger than", 1, true) ~= nil, true)
local mid = {}
for k = 1, 70 do mid[k] = 0x42 end
poke(G + 0x3200, string.rep("\0", 70))
r = H.write_memory({ address = G + 0x3200, bytes = mid })
local pm = byId(cmd_list_patches({}), r.patch_id)
eq("long patches are previewed, not dumped", pm.written:sub(-4) == " ..." and #pm.written < 70 * 3, true)
eq("... but undone in full", cmd_undo_patch({ id = r.patch_id }).success == true and U26.rd(G + 0x3200, 70) == string.rep("\0", 70), true)

-- ===================== auto_assemble =====================
poke(0x140003100, "\x01\x02")
r = H.auto_assemble({ script = "[ENABLE]\nnop\n[DISABLE]\ndb 01 02" })
eq("auto_assemble with [DISABLE] is journaled as a script", r.success == true and r.patch_id ~= nil and byId(cmd_list_patches({}), r.patch_id).kind == "script"
   and rdhex(0x140003100, 2) == "90 90", true)
eq("the reply does not leak the disable info", r.disable_info == nil and r.patch_note == nil and serverState.aa_last == nil, true)
local enableInfo = AA_CALLS[#AA_CALLS].info
r = cmd_undo_patch({ id = r.patch_id })
eq("undo runs the [DISABLE] section with CE's disable info", r.success == true and rdhex(0x140003100, 2) == "01 02" and AA_CALLS[#AA_CALLS].info ~= nil
   and AA_CALLS[#AA_CALLS].info.symbols.newmem == 0x7FF00000, true)
eq("enable was called without info", enableInfo, nil)
r = H.auto_assemble({ script = "game.exe+3100:\ndb 90 90" })
eq("a script without [DISABLE] is journaled as not undoable", r.patch_note ~= nil and byId(cmd_list_patches({}), r.patch_id).reason == "the script has no [DISABLE] section", true)
before = cmd_list_patches({}).total
r = H.auto_assemble({ script = "SYNTAX ERROR" })
eq("a failing script leaves no entry", r.success == false and cmd_list_patches({}).total == before, true)

-- ===================== batch goes through the same table =====================
serverState.dispatch = H
poke(G + 0x3300, "\x55")
r = cmd_batch({ requests = { { method = "write_memory", params = { address = G + 0x3300, bytes = { 0x66 } } } } })
eq("a write inside batch() is journaled too", r.results[1].patch_id ~= nil and byId(cmd_list_patches({}), r.results[1].patch_id).original == "55", true)

-- ===================== another process =====================
r = H.write_memory({ address = G + 0x3310, bytes = { 0x77 } })
local pOther = r.patch_id
PROCESS_PID = 5555
eq("a patch from another process shows state=other_process", byId(cmd_list_patches({}), pOther).state, "other_process")
r = cmd_undo_patch({ id = pOther })
eq("... and is not undone in the new process", r.success == false and r.error:find("another process", 1, true) ~= nil, true)
r = cmd_undo_patch({ all = true })
eq("undo all skips other processes' patches", r.success == true and r.undone == 0, true)
PROCESS_PID = 4242

-- ===================== bounds and errors =====================
eq("undo_patch needs an id", cmd_undo_patch({}).error_code, "INVALID_PARAMS")
eq("undo_patch unknown id", cmd_undo_patch({ id = "p999" }).error_code, "NOT_FOUND")
PROCESS_PID = 0
eq("undo_patch without a process", cmd_undo_patch({ id = "p1" }).error_code, "NO_PROCESS")
eq("list_patches works without a process", cmd_list_patches({}).success, true)
PROCESS_PID = 4242
l = cmd_list_patches({ limit = 2, offset = 1 })
eq("list_patches pages, newest first", l.returned == 2 and l.offset == 1 and l.total >= 10, true)
local all = cmd_list_patches({ limit = 1000 })
eq("newest first", all.patches[1].id == pOther, true)

U26.PJ_MAX_ENTRIES = 5
for k = 1, 3 do H.write_memory({ address = G + 0x3400 + k, bytes = { k } }) end
l = cmd_list_patches({ limit = 1000 })
eq("the journal keeps the latest PJ_MAX_ENTRIES, counting the dropped ones", l.total == 5 and l.dropped ~= nil and l.dropped > 0, true)
U26.PJ_MAX_ENTRIES = 500
local total0 = serverState.patch_bytes
U26.PJ_MAX_TOTAL = total0 + 10
H.write_memory({ address = G + 0x3500, bytes = { 1, 2, 3, 4, 5, 6, 7, 8 } })
eq("the journal is bounded in bytes too", serverState.patch_bytes <= U26.PJ_MAX_TOTAL, true)
U26.PJ_MAX_TOTAL = 16 * 1024 * 1024

return table.concat(results, "\n")
'''

prog = common + HELPERS + TESTS
if os.environ.get("BRIDGE_TEST_DUMP"):
    open(os.environ["BRIDGE_TEST_DUMP"], "w", encoding="utf-8").write(prog)
ok, msg = run_lua(prog, "patches")
print(msg)
# ===================== saved to a file: a reload of the bridge / a restart of CE keeps the journal =====================
SETUP = TESTS[:TESTS.index("-- ===================== recording =====================")].replace('eq("only the write tools are wrapped"', 'select(1, "only the write tools are wrapped"', 1) + r"""
process = "game.exe"
local function slurp(path) local f = io.open(path, "rb"); if not f then return nil end local t = f:read("a"); f:close(); return t end
local function lines(path) local n = 0; for _ in (slurp(path) or ""):gmatch("[^\n]+") do n = n + 1 end return n end
local JOURNAL = STATE_DIR .. "\\ce_mcp_patch_journal.jsonl"
"""

FIRST = SETUP + r"""
poke(G + 0x3000, "\x11\x22\x33\x44")
eq("persist: p1", H.write_memory({ address = G + 0x3000, bytes = { 0xAA, 0xBB } }).patch_id, "p1")
eq("persist: p2", H.write_integer({ address = G + 0x3010, value = 5, type = "dword" }).patch_id, "p2")
eq("persist: p3 (a script)", H.auto_assemble({ script = "[ENABLE]\nnop\n[DISABLE]\ndb 1 2" }).patch_id, "p3")
eq("persist: p4", H.write_memory({ address = G + 0x3020, bytes = { 0x77 } }).patch_id, "p4")
eq("persist: undo p4", cmd_undo_patch({ id = "p4" }).success, true)
eq("persist: one line per patch and per undo", lines(JOURNAL), 5)
local l = cmd_list_patches({})
eq("persist: list_patches says where the journal is saved", l.saved_to == JOURNAL and l.save_error == nil, true)
return table.concat(results, "\n")
"""

SECOND = SETUP + r"""
poke(G + 0x3000, "\xAA\xBB\x33\x44")           -- the target kept the patched bytes while the bridge was reloaded
poke(G + 0x3010, "\x05\x00\x00\x00")
local l = cmd_list_patches({ limit = 100 })
eq("reload: the journal is back", l.total, 4)
local p1, p3, p4 = byId(l, "p1"), byId(l, "p3"), byId(l, "p4")
eq("reload: a byte patch keeps its bytes and stays undoable", p1.state == "applied" and p1.undoable == true and p1.original == "11 22"
   and p1.written == "AA BB" and p1.process == "game.exe", true)
eq("reload: a script patch cannot be undone any more (CE's disable info is gone) and says why",
   p3.state == "not_undoable" and p3.undoable == false and p3.reason:find("disable information", 1, true) ~= nil, true)
eq("reload: an undone patch stays undone", p4.state == "undone" and p4.undoable == false, true)
eq("reload: the file is compacted (the undo line is folded into its patch)", lines(JOURNAL), 4)
eq("reload: new ids continue after the old ones", H.write_memory({ address = G + 0x3030, bytes = { 1 } }).patch_id, "p5")
local r = cmd_undo_patch({ id = "p1" })
eq("reload: a byte patch from the previous instance is undone", r.success == true and rdhex(G + 0x3000, 2) == "11 22", true)
eq("reload: appended again (p5 and the undo)", lines(JOURNAL), 6)
return table.concat(results, "\n")
"""

THIRD = SETUP + r"""
process = "other.exe"                          -- the same pid now belongs to another program
poke(G + 0x3010, "\x05\x00\x00\x00")
local l = cmd_list_patches({ limit = 100 })
eq("pid reuse: a patch of another program with the same pid is other_process", byId(l, "p2").state, "other_process")
local r = cmd_undo_patch({ id = "p2" })
eq("pid reuse: ... and is not undone", r.success == false and r.error:find("another process", 1, true) ~= nil and rdhex(G + 0x3010, 4) == "05 00 00 00", true)
eq("pid reuse: undo all leaves it alone", cmd_undo_patch({ all = true }).undone, 0)
return table.concat(results, "\n")
"""

FOURTH = SETUP + r"""
poke(G + 0x3010, "\x05\x00\x00\x00")
poke(G + 0x3030, "\x01")
eq("drop_patches: an unknown 'which'", cmd_drop_patches({ which = "some" }).error_code, "INVALID_PARAMS")
local r = cmd_drop_patches({})
eq("drop_patches: forgets the undone and not undoable entries, keeps the applied ones", r.dropped == 3 and r.kept == 2, true)
local l = cmd_list_patches({ limit = 100 })
eq("drop_patches: what is left", l.total == 2 and byId(l, "p2").state == "applied" and byId(l, "p5").state == "applied", true)
eq("drop_patches: the target's memory is not touched", rdhex(G + 0x3010, 4), "05 00 00 00")
eq("drop_patches: the file is rewritten", lines(JOURNAL), 2)
eq("undo p5 adds an undo line", cmd_undo_patch({ id = "p5" }).success == true and lines(JOURNAL) == 3, true)
serverState.pj_lines = 2 * U26.PJ_MAX_ENTRIES + 100
H.write_memory({ address = G + 0x3040, bytes = { 2 } })
eq("a journal file that grew too long is compacted on the next write (one line per entry)", lines(JOURNAL), 3)
return table.concat(results, "\n")
"""

FIFTH = SETUP + r"""
local l = cmd_list_patches({ limit = 100 })
local ids = {}
for _, p in ipairs(l.patches) do ids[#ids + 1] = p.id end
eq("damaged lines (cut off, wrong size, unknown kind) are skipped", table.concat(ids, ","), "p7,p6,p5,p2")
eq("drop_patches(all) forgets everything", cmd_drop_patches({ which = "all" }).dropped == 4 and cmd_list_patches({}).total == 0 and lines(JOURNAL) == 0, true)
return table.concat(results, "\n")
"""

OFF = SETUP + r"""
local r = H.write_memory({ address = G + 0x3000, bytes = { 1 } })
local l = cmd_list_patches({})
eq("CE_MCP_STATE_DIR=off: the journal works in memory, nothing is saved", r.patch_id == "p1" and l.saved_to == nil and l.save_error == nil, true)
return table.concat(results, "\n")
"""


def run_in(state, body, name):
    return run_lua("CE_MCP_STATE_DIR = [[%s]]\nSTATE_DIR = CE_MCP_STATE_DIR\n" % state + common + HELPERS + body, name)


persist_msgs = []
state = tempfile.mkdtemp(prefix="ce_mcp_state_")
try:
    for body, name in ((FIRST, "persist-1"), (SECOND, "persist-2"), (THIRD, "persist-3"), (FOURTH, "persist-4")):
        ok_p, m = run_in(state, body, name)
        persist_msgs.append(m if ok_p else "FAIL  %s crashed: %s" % (name, m[:200]))
    journal = Path(state) / "ce_mcp_patch_journal.jsonl"
    with journal.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"op": "add", "e": {"id": "p7", "seq": 7, "pid": 4242, "kind": "bytes", "address": 4096, "size": 1,
                                               "original": "00", "written": "01", "method": "write_memory"}}) + "\n")
        f.write(json.dumps({"op": "add", "e": {"id": "p8", "seq": 8, "pid": 4242, "kind": "bytes", "address": 4096, "size": 2,
                                               "original": "00", "written": "01", "method": "write_memory"}}) + "\n")
        f.write(json.dumps({"op": "add", "e": {"id": "p9", "seq": 9, "pid": 4242, "kind": "magic"}}) + "\n")
        f.write('{"op":"add","e":{"id":"p10","seq":10,"ki')
    ok_p, m = run_in(state, FIFTH, "persist-5")
    persist_msgs.append(m if ok_p else "FAIL  persist-5 crashed: " + m[:200])
finally:
    shutil.rmtree(state, ignore_errors=True)
ok_p, m = run_lua('CE_MCP_STATE_DIR = "off"\nSTATE_DIR = ""\n' + common + HELPERS + OFF, "off")
persist_msgs.append(m if ok_p else "FAIL  off crashed: " + m[:200])
print("--- state file")
print("\n".join(persist_msgs))
msg = msg + "\n" + "\n".join(persist_msgs)

print("LUA EXEC", "OK" if ok else "ERROR")
print("%d passed, %d failed" % (sum(1 for l in msg.splitlines() if l.startswith("PASS")), sum(1 for l in msg.splitlines() if l.startswith("FAIL"))))

finish()
