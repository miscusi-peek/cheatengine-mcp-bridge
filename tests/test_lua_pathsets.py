"""Offline checks of UNIT-30: pointer path sets and the two-run comparison (compare_pointer_paths).

The fake CE API simulates target restarts: memory is wiped, the modules move (ASLR), the pid changes and the
pointer graph is rebuilt, with some chains surviving and others broken in different ways (resolves elsewhere,
resolves close by, a null pointer on the way, a module that is gone).

Usage: python tests/test_lua_pathsets.py [path/to/ce_mcp_bridge.lua]
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
unit25 = t[t.index("-- >>> BEGIN UNIT-25 Operations"):t.index("-- >>> END UNIT-25 <<<")]
unit26 = t[t.index("-- >>> BEGIN UNIT-26 Analysis"):t.index("-- >>> END UNIT-26 <<<")]
unit27 = t[t.index("-- >>> BEGIN UNIT-27"):t.index("-- >>> END UNIT-27 <<<")]
unit28 = t[t.index("-- >>> BEGIN UNIT-28"):t.index("-- >>> END UNIT-28 <<<")]
unit30 = t[t.index("-- >>> BEGIN UNIT-30"):t.index("-- >>> END UNIT-30 <<<")]
i, j = func_end(t, "function resolveChain(base, offsets)")
resolve_block = t[i:j]
common = (STUBS + "\n" + 'local BPX = { watchdog = function() return false end }\n' + prefix + "\n" + read_block + "\n" + scan_block + "\n" +
          unit25 + "\n" + unit26 + "\n" + unit27 + "\n" + unit28 + "\n" + resolve_block + "\n" + unit30 + "\n")


TESTS_X64 = r'''
local function putPtr(loc, val) poke(loc, string.pack("<I8", val)) end
local function restart(pid, mods)          -- the target process is started again: new memory, new addresses
  PAGES = {}
  PROCESS_PID = pid
  MODULES = mods
end
local function mods(g, l)
  local m = { { Name = "game.exe", Address = g, Size = 0x5000, Is64Bit = true } }
  if l then m[2] = { Name = "lib.dll", Address = l, Size = 0x5000, Is64Bit = true } end
  return m
end
local function bases(r)
  local o = {}
  for _, c in ipairs(r.chains or {}) do o[#o + 1] = c.base end
  return table.concat(o, ",")
end
TARGET64 = true
process = "game.exe"

-- ===================== run 1: find_pointer_path stores its chains =====================
local G1, L1, H1, B1 = 0x140000000, 0x7FF812340000, 0x2A000000, 0x2B000000
local T1 = H1 + 0x100
restart(4242, mods(G1, L1))
putPtr(B1 + 0x40, H1); putPtr(G1 + 0x3600, B1)      -- chain A: [[game.exe+3600]+40]+100
putPtr(G1 + 0x3680, H1 + 0xF0)                       -- chain B: [game.exe+3680]+10
putPtr(L1 + 0x3700, H1 + 0x8)                        -- chain C: [lib.dll+3700]+F8
putPtr(0x2C000000, H1 + 0xF0)                        -- a heap pointer without a static parent
PTR_MODEL = { [B1 + 0x40] = H1, [G1 + 0x3600] = B1, [G1 + 0x3680] = H1 + 0xF0, [L1 + 0x3700] = H1 + 0x8, [0x2C000000] = H1 + 0xF0 }

local scansBefore = #SCANS
eq("a bad save_as is refused before any scan runs", cmd_start_job({ kind = "find_pointer_path", params = { address = T1, save_as = "../x" } }).error_code == "INVALID_PARAMS" and #SCANS == scansBefore, true)
eq("save_as must be a string name", cmd_start_job({ kind = "find_pointer_path", params = { address = T1, save_as = 5 } }).error_code, "INVALID_PARAMS")
local r = runJob("find_pointer_path", { address = T1, max_depth = 3, max_offset = 0x200, save_as = "hp" })
eq("find_pointer_path found the three chains", r.found, 3)
eq("find_pointer_path reports the stored set", r.saved_as == "hp" and r.set.chain_count == 3 and r.set.runs == 1, true)
eq("the set remembers where it came from", r.set.history[1].source == "find_pointer_path" and r.set.history[1].pid == 4242
   and r.set.history[1].process == "game.exe" and r.set.history[1].target == string.format("0x%X", T1), true)
r = cmd_get_pointer_set({ name = "hp" })
eq("get_pointer_set lists the chains, shortest first", bases(r), "game.exe+0x3680,lib.dll+0x3700,game.exe+0x3600")
eq("a stored chain: offsets, expression, runs", r.chains[3].offsets[1] == 0x40 and r.chains[3].offsets[2] == 0x100 and r.chains[3].runs == 1
   and r.chains[3].expression == "[[game.exe+0x3600]+0x40]+0x100" and r.chains[3].offsets_hex[2] == "0x100" and r.chains[3].depth == 2, true)
r = runJob("find_pointer_path", { address = T1, max_depth = 3, max_offset = 0x8, save_as = "nothing" })
eq("nothing found: no set is created", r.found == 0 and r.set == nil and r.saved_as == nil and r.save_note ~= nil and cmd_get_pointer_set({ name = "nothing" }).error_code == "NOT_FOUND", true)
r = runJob("find_pointer_path", { address = T1, max_depth = 3, max_offset = 0x8, save_as = "hp" })
eq("nothing found: an existing set is not overwritten", r.found == 0 and cmd_get_pointer_set({ name = "hp" }).total == 3, true)
r = runJob("find_pointer_path", { address = T1, max_depth = 3, max_offset = 0x200 })
eq("without save_as nothing is stored", r.saved_as == nil and r.set == nil and cmd_list_pointer_sets({}).count == 1, true)
PTR_MODEL = nil

-- ===================== run 2: restart, same value, new addresses =====================
local G2, L2, H2, B2 = 0x7FF6A1B00000, 0x7FFB10000000, 0x1F000000, 0x1F100000
local T2 = H2 + 0x100
restart(5151, mods(G2, L2))
putPtr(B2 + 0x40, H2); putPtr(G2 + 0x3600, B2)       -- A survives
putPtr(G2 + 0x3680, 0x1E000000)                      -- B now points at some other object
putPtr(L2 + 0x3700, H2 + 0x8)                        -- C survives
r = cmd_compare_pointer_paths({ name = "hp", target = T2 })
eq("compare: counts", r.success and r.compared == 3 and r.hits == 2 and r.missed == 1 and r.unreadable == 0 and r.module_missing == 0, true)
eq("compare: run number and set name", r.run == 2 and r.name == "hp", true)
eq("compare: a new process instance", r.same_process, false)
eq("compare: survivors sorted (shortest first), confirmed twice", bases(r) == "lib.dll+0x3700,game.exe+0x3600" and r.chains[1].runs == 2 and r.chains[2].runs == 2, true)
eq("compare: survivors are paged like every list", r.total == 2 and r.offset == 0 and r.returned == 2, true)
eq("compare: nothing is stored unless asked", r.saved_as == nil and cmd_get_pointer_set({ name = "hp" }).total == 3 and cmd_get_pointer_set({ name = "hp" }).runs == 1, true)
eq("compare: a chain that resolves far away is not a near miss", r.near_misses, nil)

r = cmd_compare_pointer_paths({ name = "hp", target = T2, save_as = "hp" })
eq("compare save_as the same name narrows the set", r.saved_as == "hp" and r.set.chain_count == 2 and r.set.runs == 2, true)
local s = cmd_get_pointer_set({ name = "hp" })
eq("narrowed set: chains and run counts", bases(s) == "lib.dll+0x3700,game.exe+0x3600" and s.chains[1].runs == 2, true)
eq("narrowed set: history records both runs", #s.history == 2 and s.history[2].run == 2 and s.history[2].pid == 5151 and s.history[2].tested == 3
   and s.history[2].survivors == 2 and s.history[2].source == "compare", true)

r = cmd_compare_pointer_paths({ name = "hp", target = T2 })
eq("same process again: flagged, because no restart happened", r.same_process == true and r.notes ~= nil and r.notes[1]:find("not restarted", 1, true) ~= nil, true)
eq("same process again: runs still count up", r.chains[1].runs == 3 and r.run == 3, true)

-- ===================== run 3: another restart, C breaks by a small distance =====================
local G3, L3, H3, B3 = 0x7FF70F000000, 0x7FFB20000000, 0x1F800000, 0x1F900000
local T3 = H3 + 0x100
restart(6161, mods(G3, L3))
putPtr(B3 + 0x40, H3); putPtr(G3 + 0x3600, B3)
putPtr(L3 + 0x3700, H3 + 0x50)                       -- C now resolves 0x48 past the value
r = cmd_compare_pointer_paths({ name = "hp", target = T3 })
eq("run 3: only A survives, confirmed three times", r.hits == 1 and r.chains[1].base == "game.exe+0x3600" and r.chains[1].runs == 3 and r.run == 3 and r.same_process == false, true)
eq("run 3: C is reported as a near miss with the corrected offset", r.near_misses ~= nil and #r.near_misses == 1 and r.near_misses[1].base == "lib.dll+0x3700"
   and r.near_misses[1].delta == "+0x48" and r.near_misses[1].suggested_offsets[1] == 0xB0 and r.near_misses[1].final_address == string.format("0x%X", H3 + 0x148), true)

r = cmd_compare_pointer_paths({ name = "hp", target = T3 + 8 })
eq("a wrong target: nothing survives", r.hits == 0 and r.total == 0 and #r.chains == 0, true)
eq("a wrong target: near misses nearest first, with signed deltas", r.near_misses ~= nil and #r.near_misses == 2 and r.near_misses[1].base == "game.exe+0x3600" and r.near_misses[1].delta == "-0x8"
   and r.near_misses[2].delta == "+0x40", true)
eq("a near miss on A suggests the moved field", r.near_misses[1].suggested_offsets[1] == 0x40 and r.near_misses[1].suggested_offsets[2] == 0x108, true)
eq("a wrong target: the notes say so", r.notes ~= nil and #r.notes == 2 and r.notes[1]:find("No chain reaches", 1, true) ~= nil, true)
eq("near_delta limits the near misses", cmd_compare_pointer_paths({ name = "hp", target = T3 + 8, near_delta = 4 }).near_misses, nil)
eq("near_limit limits them too", #cmd_compare_pointer_paths({ name = "hp", target = T3 + 8, near_limit = 1 }).near_misses, 1)
eq("near_limit=0 switches them off", cmd_compare_pointer_paths({ name = "hp", target = T3 + 8, near_limit = 0 }).near_misses, nil)

r = cmd_compare_pointer_paths({ name = "hp", target = T3 + 0x1000, save_as = "hp" })
eq("nothing survived: the set is NOT overwritten", r.hits == 0 and r.saved_as == nil and r.save_note:find("unchanged", 1, true) ~= nil and cmd_get_pointer_set({ name = "hp" }).total == 2, true)
r = cmd_compare_pointer_paths({ name = "hp", target = T3 + 0x1000, save_as = "fresh" })
eq("nothing survived and no such set: nothing is created", r.saved_as == nil and cmd_get_pointer_set({ name = "fresh" }).error_code == "NOT_FOUND", true)

r = cmd_compare_pointer_paths({ name = "hp", target = T3, save_as = "hp_run3" })
eq("save_as another name leaves the source set alone", r.saved_as == "hp_run3" and cmd_get_pointer_set({ name = "hp" }).total == 2 and cmd_get_pointer_set({ name = "hp_run3" }).total == 1, true)
local copy, orig = cmd_get_pointer_set({ name = "hp_run3" }), cmd_get_pointer_set({ name = "hp" })
eq("the copy has its own history", #copy.history == 3 and #orig.history == 2 and copy.runs == 3 and orig.runs == 2, true)
r = cmd_compare_pointer_paths({ name = "hp", target = T3, save_as = "hp" })
eq("narrowing in place again", r.set.chain_count == 1 and r.set.runs == 3 and #r.set.history == 3, true)

-- module names are compared case-insensitively, and a chain keeps the spelling of the module it was saved with
MODULES[1].Name = "Game.EXE"
cmd_compare_pointer_paths({ target = T3, save_as = "mixed", chains = { { base = "game.exe+0x3600", offsets = { 0x40, 0x100 } } } })
eq("a chain is stored with the loaded module's own spelling", cmd_get_pointer_set({ name = "mixed" }).chains[1].base, "Game.EXE+0x3600")
MODULES[1].Name = "GAME.exe"
r = cmd_compare_pointer_paths({ name = "mixed", target = T3 })
eq("the module is found whatever its case in the next run", r.hits == 1 and r.module_missing == 0, true)
MODULES[1].Name = "game.exe"
cmd_drop_pointer_set({ name = "mixed" })

-- ===================== inline chains, normalisation, bad input =====================
putPtr(G3 + 0x3800, 0)
r = cmd_compare_pointer_paths({ target = T3, chains = {
  { base = "game.exe+0x3600", offsets = { 0x40, 0x100 } },
  { base = "GAME.EXE+3600", offsets = { "0x40", 256 } },                              -- same chain: other case, hex without 0x, offsets as text / decimal
  { base = string.format("0x%X", G3 + 0x3600), offsets = { 0x40, 0x100.0 } },          -- same chain again: an absolute address inside the module
  { base = "extra.dll+0x10", offsets = { 0 } },                                       -- a module this run does not have
  { base = "game.exe+0x3800", offsets = { 0, 8 } },                                   -- a null pointer on the way
} })
eq("inline: duplicates written differently count once", r.compared == 3 and r.duplicates_ignored == 2 and r.hits == 1, true)
eq("inline: the survivor is normalised to module+RVA", r.chains[1].base == "game.exe+0x3600" and r.chains[1].runs == 1, true)
eq("inline: module_missing and unreadable are told apart", r.module_missing == 1 and r.unreadable == 1 and r.missed == 0, true)
eq("inline chains have no run history, so no same-process note", r.run == 1 and r.same_process == false and r.name == nil, true)

r = cmd_compare_pointer_paths({ target = T3, save_as = "inline", chains = { { base = "game.exe+0x3600", offsets = { 0x40, 0x100 }, runs = 2 } } })
eq("inline chains can carry their run count and be saved", r.chains[1].runs == 3 and r.saved_as == "inline" and r.set.history[1].source == "inline" and r.set.runs == 1, true)

putPtr(G3 + 0x3900, 0x1234)
r = cmd_compare_pointer_paths({ target = G3 + 0x3900, chains = { { base = "game.exe+0x3900", offsets = {} }, { base = "game.exe+0x3900" } } })
eq("a chain without offsets is the base itself", r.hits == 1 and r.duplicates_ignored == 1 and r.chains[1].expression == "game.exe+0x3900" and r.chains[1].depth == 0 and #r.chains[1].offsets_hex == 0, true)
putPtr(G3 + 0x3A00, T3 + 0x10)
r = cmd_compare_pointer_paths({ target = T3, chains = { { base = "game.exe+0x3A00", offsets = { -0x10 } } } })
eq("negative offsets work and print signed", r.hits == 1 and r.chains[1].offsets_hex[1] == "-0x10" and r.chains[1].expression == "[game.exe+0x3A00]-0x10", true)
r = cmd_compare_pointer_paths({ target = T3, chains = { { base = "game.exe+0x3A00", offsets = { -0x10 } },
                                                       { base = "game.exe+0x3600", offsets = { 0x40, 0x100 }, runs = 2 } } })
eq("survivors confirmed in more runs come first, even if longer", r.hits == 2 and r.chains[1].base == "game.exe+0x3600" and r.chains[1].runs == 3 and r.chains[2].runs == 1, true)

for k = 1, 7 do putPtr(G3 + 0x3B00 + 8 * k, T3 - k) end
local many = {}
for k = 1, 7 do many[k] = { base = string.format("game.exe+0x%X", 0x3B00 + 8 * k), offsets = { k } } end
r = cmd_compare_pointer_paths({ target = T3, chains = many, limit = 3, offset = 2 })
eq("survivors page: total, offset, limit, returned", r.total == 7 and r.offset == 2 and r.limit == 3 and r.returned == 3 and #r.chains == 3, true)
eq("survivors of equal depth: smallest offsets first", r.chains[1].base == "game.exe+0x3B18" and r.chains[3].base == "game.exe+0x3B28", true)
eq("get_pointer_set pages too", cmd_get_pointer_set({ name = "hp_run3", limit = 1, offset = 0 }).returned, 1)

local p = U26.psParseChain({ base = "libc++.dll+0x10" }, {})
eq("parse: a module name containing '+'", p.module == "libc++.dll" and p.rva == 0x10 and #p.offsets == 0, true)
p = U26.psParseChain({ base = "game.exe", offsets = { 3.0 } }, U26.listModules())
eq("parse: a bare module name is its base; whole floats are integers", p.module == "game.exe" and p.rva == 0 and p.offsets[1] == 3 and math.type(p.offsets[1]) == "integer", true)
eq("parse: a fractional offset is refused", select(2, U26.psParseChain({ base = "game.exe+1", offsets = { 3.5 } }, {})), "offsets[1] is not an integer")
eq("parse: no base", select(2, U26.psParseChain({ offsets = { 1 } }, {})), "base must be 'module+0xRVA' or an address")
eq("parse: unresolvable base", select(2, U26.psParseChain({ base = "nosuch!", offsets = {} }, {})), "base must be 'module+0xRVA' or an address")
eq("parse: not an object", select(2, U26.psParseChain(5, {})) ~= nil, true)
local deep = {}
for k = 1, 17 do deep[k] = 1 end
eq("parse: too many offsets", select(2, U26.psParseChain({ base = "game.exe+1", offsets = deep }, {})):find("at most 16", 1, true) ~= nil, true)
eq("an unabsolute base outside every module stays absolute", U26.psParseChain({ base = 0x7000 }, U26.listModules()).abs, 0x7000)

eq("compare: needs name or chains", cmd_compare_pointer_paths({ target = T3 }).error_code, "INVALID_PARAMS")
eq("compare: not both", cmd_compare_pointer_paths({ target = T3, name = "hp", chains = { { base = "game.exe+1" } } }).error_code, "INVALID_PARAMS")
eq("compare: unknown set", cmd_compare_pointer_paths({ target = T3, name = "nope" }).error_code, "NOT_FOUND")
eq("compare: bad target", cmd_compare_pointer_paths({ target = "zzz", name = "hp" }).error_code, "INVALID_ADDRESS")
eq("compare: bad save_as", cmd_compare_pointer_paths({ target = T3, name = "hp", save_as = "a b" }).error_code, "INVALID_PARAMS")
eq("compare: empty chains", cmd_compare_pointer_paths({ target = T3, chains = {} }).error_code, "INVALID_PARAMS")
r = cmd_compare_pointer_paths({ target = T3, chains = { { base = "game.exe+1" }, { offsets = { 1 } } } })
eq("compare: the bad chain is named", r.error_code == "INVALID_PARAMS" and r.error:find("chains[2]", 1, true) ~= nil, true)
local lots = {}
for k = 1, 5001 do lots[k] = { base = "game.exe+" .. k } end
eq("compare: too many chains", cmd_compare_pointer_paths({ target = T3, chains = lots }).error_code, "INVALID_PARAMS")
PROCESS_PID = 0
eq("compare: no process", cmd_compare_pointer_paths({ target = T3, name = "hp" }).error_code, "NO_PROCESS")
PROCESS_PID = 6161

-- ===================== set management =====================
eq("get: unknown set", cmd_get_pointer_set({ name = "nope" }).error_code, "NOT_FOUND")
eq("drop: unknown set", cmd_drop_pointer_set({ name = "nope" }).error_code, "NOT_FOUND")
local l = cmd_list_pointer_sets({})
local names = {}
for _, x in ipairs(l.sets) do names[#names + 1] = x.name end
table.sort(names)
eq("list: every set once, with its size and runs", table.concat(names, ",") == "hp,hp_run3,inline" and l.count == 3, true)
eq("drop one set", cmd_drop_pointer_set({ name = "inline" }).deleted == 1 and cmd_list_pointer_sets({}).count == 2 and cmd_get_pointer_set({ name = "inline" }).error_code == "NOT_FOUND", true)

-- the number of sets and the length of a history are bounded
cmd_drop_pointer_set({ all = true })
eq("drop all", cmd_list_pointer_sets({}).count, 0)
local one = { { base = "game.exe+0x3600", offsets = { 0x40, 0x100 } } }
for k = 1, 16 do cmd_compare_pointer_paths({ target = T3, chains = one, save_as = "s" .. k }) end
r = cmd_compare_pointer_paths({ target = T3, chains = one, save_as = "s17" })
eq("at most 16 sets", r.saved_as == nil and r.save_note:find("at most 16", 1, true) ~= nil and cmd_list_pointer_sets({}).count == 16, true)
r = cmd_compare_pointer_paths({ target = T3, chains = one, save_as = "s1" })
eq("replacing an existing set is fine when the table is full", r.saved_as == "s1" and cmd_list_pointer_sets({}).count == 16, true)
for _ = 1, 25 do r = cmd_compare_pointer_paths({ target = T3, name = "s2", save_as = "s2" }) end
local s2 = cmd_get_pointer_set({ name = "s2" })
eq("history keeps the latest 20 runs", #s2.history == 20 and s2.history[20].run == s2.runs and s2.runs == 26 and s2.history[1].run == 7, true)
eq("drop all frees the table", cmd_drop_pointer_set({ all = true }).deleted == 16 and cmd_list_pointer_sets({}).count == 0, true)

return table.concat(results, "\n")
'''

TESTS_X86 = r'''
TARGET64 = false
PROCESS_PID = 100
MODULES = { { Name = "game.exe", Address = 0x00400000, Size = 0x5000, Is64Bit = false } }
poke(0x00403000, string.pack("<I4", 0x20000000))
poke(0x00403010, string.pack("<I4", 0xFFFFFFF0))
local chains = { { base = "game.exe+0x3000", offsets = { 0x10 } }, { base = "game.exe+0x3010", offsets = { 0x20 } } }
local r = cmd_compare_pointer_paths({ target = 0x20000010, chains = chains, save_as = "x86set" })
eq("x86: a 4-byte pointer chain", r.hits == 1 and r.chains[1].base == "game.exe+0x3000" and r.set.arch == "x86", true)
r = cmd_compare_pointer_paths({ target = 0x10, chains = chains })
eq("x86: addresses wrap at 32 bits", r.hits == 1 and r.chains[1].base == "game.exe+0x3010", true)
return table.concat(results, "\n")
'''


def program(body):
    return common + HELPERS + body


x64_prog = program(TESTS_X64)
if os.environ.get("BRIDGE_TEST_DUMP"):
    open(os.environ["BRIDGE_TEST_DUMP"], "w", encoding="utf-8").write(x64_prog)
ok, msg = run_lua(x64_prog, "x64")
print("--- x64 target")
print(msg)
ok2, msg2 = run_lua(program(TESTS_X86), "x86")
print("--- x86 target")
print(msg2)

# ===================== saved to a file: a reload of the bridge / a restart of CE keeps the sets =====================
PERSIST_SETUP = r"""
TARGET64 = true
process = "game.exe"
local function putPtr(loc, val) poke(loc, string.pack("<I8", val)) end
local function setup(g)                     -- [g+3000]+10 and [[g+3008]-8]+20 both reach 0x2A000010
  MODULES = { { Name = "game.exe", Address = g, Size = 0x5000, Is64Bit = true } }
  putPtr(g + 0x3000, 0x2A000000)
  putPtr(g + 0x3008, 0x2B000008); putPtr(0x2B000000, 0x29FFFFF0)
end
local CHAINS = { { base = "game.exe+0x3000", offsets = { 0x10 } }, { base = "game.exe+0x3008", offsets = { -0x8, 0x20 } } }
local function slurp(path) local f = io.open(path, "rb"); if not f then return nil end local t = f:read("a"); f:close(); return t end
"""

PERSIST_1 = PERSIST_SETUP + r"""
setup(0x140000000)
local r = cmd_compare_pointer_paths({ target = 0x2A000010, chains = CHAINS, save_as = "hp" })
eq("persist: both chains saved", r.hits == 2 and r.saved_as == "hp", true)
cmd_compare_pointer_paths({ target = 0x2A000010, chains = CHAINS, save_as = "gone" })
eq("persist: drop_pointer_set", cmd_drop_pointer_set({ name = "gone" }).deleted, 1)
local l = cmd_list_pointer_sets({})
eq("persist: list_pointer_sets says where the sets are saved", l.saved_to == STATE_DIR .. "\\ce_mcp_pointer_sets.json" and l.save_error == nil, true)
local text = slurp(l.saved_to) or ""
eq("persist: the file holds the set, not the dropped one", text:find('"hp"', 1, true) ~= nil and text:find('"gone"', 1, true) == nil, true)
eq("persist: no temporary copy is left behind", slurp(l.saved_to .. ".tmp"), nil)
return table.concat(results, "\n")
"""

PERSIST_2 = PERSIST_SETUP + r"""
PROCESS_PID = 5151
setup(0x7FF600000000)                         -- a new instance of the target: the module moved
local l = cmd_list_pointer_sets({})
eq("reload: the saved set is back", l.count == 1 and l.sets[1].name == "hp" and l.sets[1].chain_count == 2 and l.sets[1].runs == 1, true)
eq("reload: a dropped set stays dropped", cmd_get_pointer_set({ name = "gone" }).error_code, "NOT_FOUND")
local g = cmd_get_pointer_set({ name = "hp" })
local ex = {}
for _, c in ipairs(g.chains) do ex[#ex + 1] = c.expression end
table.sort(ex)
eq("reload: chains keep module, RVA and negative offsets", table.concat(ex, " "), "[[game.exe+0x3008]-0x8]+0x20 [game.exe+0x3000]+0x10")
eq("reload: history is kept", g.history[1].pid == 4242 and g.history[1].process == "game.exe", true)
local r = cmd_compare_pointer_paths({ target = 0x2A000010, name = "hp", save_as = "hp" })
eq("reload: run 2 compares against the saved set", r.hits == 2 and r.same_process == false and cmd_get_pointer_set({ name = "hp" }).runs == 2, true)
return table.concat(results, "\n")
"""

PERSIST_3 = PERSIST_SETUP + r"""
local l = cmd_list_pointer_sets({})
eq("third instance: the narrowed set (runs 2) was saved too", l.count == 1 and l.sets[1].runs == 2, true)
return table.concat(results, "\n")
"""

EDITED = r"""
local l = cmd_list_pointer_sets({})
local names = {}
for _, s in ipairs(l.sets) do names[#names + 1] = s.name .. ":" .. s.chain_count end
table.sort(names)
eq("an edited file: bad names and broken chains are skipped, the rest loads", table.concat(names, ","), "good:2,mixed:1")
return table.concat(results, "\n")
"""

GARBAGE = PERSIST_SETUP + r"""
local l = cmd_list_pointer_sets({})
eq("a damaged file is ignored and reported", l.count == 0 and type(l.save_error) == "string" and l.save_error:find("ignored", 1, true) ~= nil, true)
setup(0x140000000)
local r = cmd_compare_pointer_paths({ target = 0x2A000010, chains = CHAINS, save_as = "fresh" })
l = cmd_list_pointer_sets({})
eq("... and the next save replaces it", r.saved_as == "fresh" and l.save_error == nil and (slurp(l.saved_to) or ""):find('"fresh"', 1, true) ~= nil, true)
return table.concat(results, "\n")
"""

TMP_ONLY = r"""
local l = cmd_list_pointer_sets({})
eq("a save cut off between remove and rename: the .tmp copy is loaded", l.count == 1 and l.sets[1].name == "tmpset", true)
return table.concat(results, "\n")
"""

OFF = PERSIST_SETUP + r"""
setup(0x140000000)
local r = cmd_compare_pointer_paths({ target = 0x2A000010, chains = CHAINS, save_as = "mem" })
local l = cmd_list_pointer_sets({})
eq("CE_MCP_STATE_DIR=off: sets work, nothing is saved", r.saved_as == "mem" and l.saved_to == nil and l.save_error == nil, true)
return table.concat(results, "\n")
"""

UNWRITABLE = PERSIST_SETUP + r"""
setup(0x140000000)
local r = cmd_compare_pointer_paths({ target = 0x2A000010, chains = CHAINS, save_as = "mem" })
local l = cmd_list_pointer_sets({})
eq("an unwritable folder: the command still works and the problem is reported",
   r.saved_as == "mem" and l.saved_to == nil and type(l.save_error) == "string" and l.save_error:find("writable", 1, true) ~= nil, true)
return table.concat(results, "\n")
"""


def run_in(state, body, name):
    pre = "CE_MCP_STATE_DIR = [[%s]]\nSTATE_DIR = CE_MCP_STATE_DIR\n" % state
    return run_lua(pre + program(body), name)


persist_msgs = []
state = tempfile.mkdtemp(prefix="ce_mcp_state_")
try:
    for body, name in ((PERSIST_1, "persist-1"), (PERSIST_2, "persist-2"), (PERSIST_3, "persist-3")):
        ok_p, m = run_in(state, body, name)
        persist_msgs.append(m if ok_p else "FAIL  %s crashed: %s" % (name, m[:200]))
    sets_file = Path(state) / "ce_mcp_pointer_sets.json"
    chain = {"module": "game.exe", "rva": 0x3000, "offsets": [16], "runs": 1}
    sets_file.write_text(json.dumps({"version": 1, "sets": [
        {"name": "good", "chains": [chain, {"abs": 0x5000, "offsets": []}], "runs": 1},
        {"name": "../evil", "chains": [chain], "runs": 1},
        {"name": "mixed", "chains": [chain, {"module": "game.exe", "rva": 16, "offsets": ["x"]}, {"offsets": [1]}], "runs": 1},
        {"name": "empty", "chains": [], "runs": 1}]}), encoding="utf-8")
    ok_p, m = run_in(state, EDITED, "edited")
    persist_msgs.append(m if ok_p else "FAIL  edited crashed: " + m[:200])
    sets_file.write_text('{"version":1,"sets":[{"name":"x","chains":[{"mod', encoding="utf-8")
    ok_p, m = run_in(state, GARBAGE, "garbage")
    persist_msgs.append(m if ok_p else "FAIL  garbage crashed: " + m[:200])
    sets_file.unlink()
    Path(str(sets_file) + ".tmp").write_text(json.dumps({"version": 1, "sets": [{"name": "tmpset", "chains": [chain], "runs": 1}]}), encoding="utf-8")
    ok_p, m = run_in(state, TMP_ONLY, "tmp-only")
    persist_msgs.append(m if ok_p else "FAIL  tmp-only crashed: " + m[:200])
finally:
    shutil.rmtree(state, ignore_errors=True)
ok_p, m = run_lua('CE_MCP_STATE_DIR = "off"\nSTATE_DIR = ""\n' + program(OFF), "off")
persist_msgs.append(m if ok_p else "FAIL  off crashed: " + m[:200])
ok_p, m = run_in(os.path.join(tempfile.gettempdir(), "ce_mcp_no_such_dir", "deeper"), UNWRITABLE, "unwritable")
persist_msgs.append(m if ok_p else "FAIL  unwritable crashed: " + m[:200])
print("--- state file")
print("\n".join(persist_msgs))

allmsg = msg + "\n" + msg2 + "\n" + "\n".join(persist_msgs)
print("LUA EXEC", "OK" if ok and ok2 else "ERROR")
print("%d passed, %d failed" % (sum(1 for l in allmsg.splitlines() if l.startswith("PASS")), sum(1 for l in allmsg.splitlines() if l.startswith("FAIL"))))

finish()
