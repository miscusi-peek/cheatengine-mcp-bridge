"""Offline checks of UNIT-28: the find_xrefs job (everything that references an address or a range).

Synthetic x64 and x86 PE images are driven through the fake CE API. A tiny fake decoder (INSNS / PARTIAL tables)
stands in for CE's disassembler: INSNS maps an instruction start to (length, text); PARTIAL gives the length a
decoder would report when it starts in the middle of an instruction or code (an unregistered address decodes as one
byte). The start-of-instruction search decodes forward and must not be fooled by those mid-instruction answers.

Usage: python tests/test_lua_xrefs.py [path/to/ce_mcp_bridge.lua]
Set BRIDGE_TEST_DUMP=<file> to write the generated x64 Lua test program for debugging.
"""
import json, os, struct

from lua_harness import run_lua, load, func_end, arg_path, has_flag, finish, compile_check, BRIDGE_LUA
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
common = (STUBS + "\n" + 'local BPX = { watchdog = function() return false end }\n' + prefix + "\n" + read_block + "\n" + scan_block + "\n" +
          unit25 + "\n" + unit26 + "\n" + unit27 + "\n" + unit28 + "\n")


# --------------------------------------------------------------------------- synthetic images
def pe_header(img, is64, base, sections, size_of_image):
    def u32(off, v): struct.pack_into('<I', img, off, v)
    img[0:2] = b'MZ'; u32(0x3C, 0x80)
    nt = 0x80
    img[nt:nt + 4] = b'PE\0\0'
    optsize = 240 if is64 else 224
    struct.pack_into('<HHIIIHH', img, nt + 4, 0x8664 if is64 else 0x14C, len(sections), 0x5F5E1000, 0, 0, optsize, 0x22)
    opt = nt + 24
    struct.pack_into('<H', img, opt, 0x20B if is64 else 0x10B)
    u32(opt + 16, 0x1000); u32(opt + 20, 0x1000)
    if is64:
        struct.pack_into('<Q', img, opt + 24, base)
    else:
        u32(opt + 24, 0x2000); u32(opt + 28, base)
    u32(opt + 32, 0x1000); u32(opt + 36, 0x200)
    u32(opt + 56, size_of_image); u32(opt + 60, 0x1000)
    struct.pack_into('<HH', img, opt + 68, 3, 0x8160)
    u32(opt + (108 if is64 else 92), 16)
    sec = opt + optsize
    for k, (name, rva, vs, chars) in enumerate(sections):
        o = sec + k * 40
        img[o:o + 8] = name.ljust(8, b'\0')
        struct.pack_into('<IIII', img, o + 8, vs, rva, vs, rva)
        u32(o + 36, chars)
    return opt + (112 if is64 else 96)           # offset of the data directory array


SEC_TEXT = (b'.text', 0x1000, 0x1000, 0x60000020)
SEC_RDATA = (b'.rdata', 0x2000, 0x1000, 0x40000040)
SEC_DATA = (b'.data', 0x3000, 0x1000, 0xC0000040)
SEC_PDATA = (b'.pdata', 0x4000, 0x1000, 0x40000040)

T_RVA = 0x1300       # the "function" most code references
V_RVA = 0x3000       # a variable in .data (rip-relative / pointer target)
V2_RVA = 0x3010      # a neighbour inside the same 0x20-byte range


def build_x64(base, ext_target=None):
    """Returns (image bytes, INSNS {rva: (len, text)}, PARTIAL {rva: len})."""
    img = bytearray(0x5000)
    insns, partial = {}, {}
    dirs = pe_header(img, True, base, [SEC_TEXT, SEC_RDATA, SEC_DATA, SEC_PDATA], 0x5000)

    def w(off, b): img[off:off + len(b)] = b
    def ins(at, raw, text): w(at, raw); insns[at] = (len(raw), text)
    def rel(at, total_len, target): return struct.pack('<i', target - (at + total_len))
    def q(v): return struct.pack('<Q', v)

    for off in range(0x1000, 0x2000): img[off] = 0xC3

    # ---- branches to T (0x1300)
    ins(0x11FD, b'\xE8' + rel(0x11FD, 5, T_RVA), "call %d" % T_RVA)                 # crosses the 0x1200 chunk border; outside .pdata
    ins(0x1210, b'\xE9' + rel(0x1210, 5, T_RVA), "jmp T")
    ins(0x1220, b'\x0F\x84' + rel(0x1220, 6, T_RVA), "je T")
    ins(0x1230, b'\xE8' + rel(0x1230, 5, T_RVA + 1), "call T+1")                    # decoy: one byte past the function start
    ins(0x1290, b'\xEB\x6E', "jmp short T")                                         # 0x1290 + 2 + 0x6E = 0x1300
    ins(0x1310, b'\x75\xEE', "jne T")                                               # 0x1312 - 0x12 = 0x1300
    ins(0x12C0, b'\x83\x7D\x75\x3C', "cmp dword ptr [rbp+75],3C")                   # its last two bytes (75 3C) also read as `jne T`: mid-instruction
    # ---- rip-relative operands that reach V (0x3000)
    ins(0x13FC, b'\x48\x8B\x05' + rel(0x13FC, 7, V_RVA), "mov rax,[game.exe+3000]")             # displacement straddles the 0x1400 border
    ins(0x1410, b'\x48\x89\x0D' + rel(0x1410, 7, V_RVA), "mov [game.exe+3000],rcx")
    ins(0x1420, b'\x48\x8D\x15' + rel(0x1420, 7, V_RVA), "lea rdx,[game.exe+3000]")
    ins(0x1430, b'\x4C\x8D\x25' + rel(0x1430, 7, V_RVA), "lea r12,[game.exe+3000]"); partial[0x1431] = 6   # modrm 0x25 + a REX prefix
    ins(0x1440, b'\x83\x3D' + rel(0x1440, 7, V_RVA) + b'\x05', "cmp dword ptr [game.exe+3000],05")       # 1 immediate byte
    ins(0x1450, b'\xC7\x05' + rel(0x1450, 10, V_RVA) + b'\x01\x00\x00\x00', "mov dword ptr [game.exe+3000],00000001")
    ins(0x1460, b'\xFF\x15' + rel(0x1460, 6, V_RVA), "call [game.exe+3000]")
    ins(0x1470, b'\xF3\x0F\x10\x05' + rel(0x1470, 8, V_RVA), "movss xmm0,[game.exe+3000]"); partial[0x1471] = 7; partial[0x1472] = 6
    ins(0x1480, b'\x48\x8B\x05' + rel(0x1480, 7, V2_RVA), "mov rax,[game.exe+3010]")            # the neighbour
    ins(0x1490, b'\x48\x8B\x40\x40', "mov rax,[rax+40]")                                          # ends in 0x40, which also looks like a REX prefix
    ins(0x1494, b'\xFF\x15' + rel(0x1494, 6, V_RVA), "call [game.exe+3000]"); partial[0x1493] = 7  # a decoder starting at the 0x40 sees `rex call`
    w(0x1500, b'\x90\x05' + struct.pack('<i', V_RVA - 0x1506))                                    # looks like [rip+disp] but is not an instruction
    w(0x1530, b'\xC7\x05' + rel(0x1530, 10, V_RVA) + b'\x01\x00\x00\x00'); insns[0x1530] = (8, "mov eax,ebx")  # bytes of a rip operand, but the decoder disagrees
    ins(0x1960, b'\x48\x8B\x05' + rel(0x1960, 7, V_RVA), "mov rax,[game.exe+3000]"); partial[0x1902] = 100; insns[0x18C0] = (0x60, "(a long instruction that steps over 0x1902)")  # in function E: decoding from its start is exact
    ins(0x1A00, b'\x48\x8B\x05' + rel(0x1A00, 7, V_RVA), "mov rax,[game.exe+3000]")             # outside .pdata: decoding starts a runway back
    # ---- absolute pointers in code
    ins(0x1600, b'\x48\xB8' + q(base + V_RVA), "mov rax,game.exe+3000")
    w(0x1700, q(base + V_RVA))                                                                    # a bare pointer in the middle of the code
    ins(0x17F9, b'\xE9' + rel(0x17F9, 5, T_RVA), "jmp T (inside the carry bytes of the 0x1800 chunk border)")
    # ---- .pdata
    table = [(0x1200, 0x1300), (0x1300, 0x1340), (0x13F0, 0x1500), (0x1600, 0x1620), (0x18C0, 0x1980)]
    for k, (b, e) in enumerate(table):
        struct.pack_into('<III', img, 0x4000 + k * 12, b, e, 0x4120)
    struct.pack_into('<II', img, dirs + 3 * 8, 0x4000, len(table) * 12)
    img[0x4120:0x4124] = bytes([0x01, 0, 0, 0])
    # ---- data
    w(0x2100, q(base + T_RVA))                    # pointer table entry
    w(0x2208, struct.pack('<I', T_RVA))           # 32-bit RVA (jump table)
    w(0x2301, struct.pack('<I', T_RVA))           # unaligned: must not count
    w(0x2381, q(base + T_RVA))                    # unaligned pointer: must not count either
    w(0x2400, struct.pack('<I', V_RVA + 4))       # RVA into the V range
    if ext_target: w(0x2500, q(ext_target))
    w(0x3100, q(base + V_RVA)); w(0x3110, q(base + V2_RVA))
    return bytes(img), insns, partial


def build_x86(base):
    img = bytearray(0x4000)
    insns, partial = {}, {}
    pe_header(img, False, base, [SEC_TEXT, SEC_RDATA, SEC_DATA], 0x4000)

    def w(off, b): img[off:off + len(b)] = b
    def ins(at, raw, text): w(at, raw); insns[at] = (len(raw), text)
    def d(v): return struct.pack('<I', v)
    for off in range(0x1000, 0x2000): img[off] = 0xC3
    ins(0x1100, b'\xE8' + struct.pack('<i', T_RVA - 0x1105), "call T")
    va = base + V_RVA
    ins(0x1110, b'\x68' + d(va), "push 403000")
    ins(0x1120, b'\xA1' + d(va), "mov eax,[403000]")
    ins(0x1130, b'\xFF\x15' + d(va), "call [403000]")
    ins(0x1140, b'\x83\x3D' + d(va) + b'\x05', "cmp dword ptr [403000],05")
    w(0x1200, d(va))                                                    # a switch-table style pointer inside the code
    w(0x2100, d(base + T_RVA))
    w(0x3100, d(va))
    return bytes(img), insns, partial


def page_lines(base, data):
    return "\n".join('PAGE(0x%X, "%s")' % (base + off, data[off:off + 4096].hex()) for off in range(0, len(data), 4096) if any(data[off:off + 4096]))


def decoder_lua(base, insns, partial):
    lines = ['INSNS[%d] = {%d, %s}' % (base + rva, n, json.dumps(text)) for rva, (n, text) in insns.items()]
    lines += ['PARTIAL[%d] = %d' % (base + rva, n) for rva, n in partial.items()]
    return "\n".join(lines)


DECODER = r'''
INSNS, PARTIAL = {}, {}
function disassemble(addr)
  local i = INSNS[addr]
  return i and string.format("%X - xx xx - %s", addr, i[2]) or nil
end
function getInstructionSize(addr)
  local i = INSNS[addr]
  if i then return i[1] end
  return PARTIAL[addr] or 1
end
'''

GB, LB, JUNK = 0x140000000, 0x7FF812340000, 0x70000000
X86_BASE = 0x00400000
img_game, insn_game, part_game = build_x64(GB, ext_target=None)
img_lib, insn_lib, part_lib = build_x64(LB, ext_target=GB + T_RVA)       # lib.dll holds a pointer to game.exe's T
img_x86, insn_x86, part_x86 = build_x86(X86_BASE)


TESTS_X64 = r'''
MODULES = {
  { Name = "game.exe", Address = @GB@, Size = 0x5000, Is64Bit = true },
  { Name = "lib.dll",  Address = @LB@, Size = 0x5000, Is64Bit = true },
  { Name = "junk.dll", Address = @JUNK@, Size = 0x1000, Is64Bit = true },      -- nothing mapped there
}
TARGET64 = true
local GB, LB = @GB@, @LB@
U26.CHUNK = 512
local function summary(r)
  local o = {}
  for _, it in ipairs(r.references or {}) do o[#o + 1] = it.kind .. "@" .. string.format("%X", it.rva) end
  return table.concat(o, ",")
end
local function byAddr(r, rva) for _, it in ipairs(r.references or {}) do if it.rva == rva then return it end end return {} end

-- ===================== kinds / access helpers =====================
local k = U26.xrefKinds(nil)
eq("kinds default = everything", k.call and k.jmp and k.jcc and k.rip and k.abs_code and k.abs_data and k.rva, true)
k = U26.xrefKinds("call, abs")
eq("kinds: names and the abs shortcut", k.call and k.abs_code and k.abs_data and not k.jmp and not k.rip, true)
k = U26.xrefKinds({ "RIP", "rva" })
eq("kinds: list, case-insensitive", k.rip and k.rva and not k.call, true)
local bad, msg = U26.xrefKinds("call,bogus")
eq("kinds: unknown name rejected", bad == nil and msg:find("bogus", 1, true) ~= nil, true)
eq("kinds: non-string rejected", (U26.xrefKinds(42)), nil)

local access = {
  { "mov rax,[rip+10]", "read" }, { "mov [rip+10],rax", "write" }, { "mov dword ptr [rip+10],5", "write" },
  { "lea rax,[rip+10]", "address" }, { "call [rip+10]", "call" }, { "jmp qword ptr [rip+10]", "jump" },
  { "add [rip+10],eax", "read/write" }, { "cmp [rip+10],eax", "read" }, { "cmp eax,[rip+10]", "read" },
  { "inc dword ptr [rip+10]", "read/write" }, { "lock cmpxchg [rip+10],ecx", "read/write" },
  { "movss xmm0,[rip+10]", "read" }, { "movss [rip+10],xmm0", "write" }, { "vmovaps [rip+10],ymm0", "write" },
  { "push [rip+10]", "read" }, { "xchg [rip+10],eax", "read/write" }, { "setne byte ptr [rip+10]", "write" },
  { "ucomiss xmm0,[rip+4]", "read" }, { "fstp qword ptr [rip+10]", "write" }, { "test [rip+10],eax", "read" },
  { "00007FF6A1B01000 - 48 8B 05 00 00 00 00 - mov rax,[rip+0]", "read" },
  { "00007FF6A1B01000 - 48 89 05 00 00 00 00 - mov [rip+0],rax", "write" },
  { "mul dword ptr [rip+10]", "read" }, { "bts [rip+10],eax", "read/write" }, { "bt [rip+10],eax", "read" },
}
local accessBad = {}
for _, c in ipairs(access) do
  local got = U26.xrefAccess(c[1])
  if got ~= c[2] then accessBad[#accessBad + 1] = c[1] .. " -> " .. tostring(got) .. " (want " .. c[2] .. ")" end
end
eq("access classification of memory operands", table.concat(accessBad, "; "), "")
eq("access: no memory operand", U26.xrefAccess("nop"), nil)

-- ===================== a code target (branches + data references) =====================
local r = runJob("find_xrefs", { address = GB + 0x1300 })
eq("xrefs done", r.success, true)
eq("every way of reaching a function", summary(r), "call@11FD,jmp@1210,jcc@1220,jmp@1290,jcc@1310,jmp@17F9,abs_data@2100,rva@2208")
eq("found / modules", r.found == 8 and #r.modules == 1 and r.modules[1] == "game.exe", true)
eq("unaligned RVA / pointer and the .pdata begin address are not reported", byAddr(r, 0x2301).kind == nil and byAddr(r, 0x2381).kind == nil, true)
eq("an instruction inside the carry bytes is reported once", summary(r):find("jmp@17F9", 1, true) ~= nil and select(2, summary(r):gsub("17F9", "")) == 1, true)
eq("branch forms", byAddr(r, 0x11FD).form == "rel32" and byAddr(r, 0x1290).form == "rel8" and byAddr(r, 0x1310).form == "rel8", true)
eq("a call across a chunk border", byAddr(r, 0x11FD).kind, "call")
eq("two bytes inside another instruction that read as a short jump are dropped", byAddr(r, 0x12C2).kind, nil)
eq("branch target field", byAddr(r, 0x1210).target, string.format("0x%X", GB + 0x1300))
eq("instruction text", byAddr(r, 0x11FD).instruction, string.format("%X - xx xx - call %d", GB + 0x11FD, 0x1300))
eq("function of a branch", byAddr(r, 0x1210).function_start == "game.exe+0x1200" and byAddr(r, 0x1290).function_rva == 0x1200, true)
eq("function of a branch inside the target itself", byAddr(r, 0x1310).function_start, "game.exe+0x1300")
eq("no function outside .pdata", byAddr(r, 0x11FD).function_start, nil)
eq("sections", byAddr(r, 0x2100).section == ".rdata" and byAddr(r, 0x1210).section == ".text", true)
eq("data references have no instruction/function", byAddr(r, 0x2100).instruction == nil and byAddr(r, 0x2208).function_start == nil, true)
eq("expression", byAddr(r, 0x2208).expression, "game.exe+0x2208")
eq("by_kind", r.by_kind.jmp == 3 and r.by_kind.jcc == 2 and r.by_kind.call == 1 and r.by_kind.abs_data == 1 and r.by_kind.rva == 1, true)
eq("callers grouped by function (most first)", r.functions[1].function_start == "game.exe+0x1200" and r.functions[1].count == 3
   and r.functions[2].function_start == "game.exe+0x1300" and r.functions[2].count == 1, true)
eq("no offset for a single address", byAddr(r, 0x1210).offset_in_target, nil)
eq("no truncation", r.truncated, nil)
eq("job progress reaches the end", r.job.progress.current == r.job.progress.total and r.job.progress.total > 0, true)

-- a range: the neighbouring call lands one byte into it
r = runJob("find_xrefs", { address = GB + 0x1300, size = 2 })
eq("range of 2 bytes", summary(r), "call@11FD,jmp@1210,jcc@1220,call@1230,jmp@1290,jcc@1310,jmp@17F9,abs_data@2100,rva@2208")
eq("offset inside the range", byAddr(r, 0x1230).offset_in_target == 1 and byAddr(r, 0x1210).offset_in_target == 0, true)

-- kinds
r = runJob("find_xrefs", { address = GB + 0x1300, kinds = "call" })
eq("kinds=call", summary(r), "call@11FD")
r = runJob("find_xrefs", { address = GB + 0x1300, kinds = { "abs" } })
eq("kinds=[abs]", summary(r), "abs_data@2100")
r = runJob("find_xrefs", { address = GB + 0x1300, kinds = "jmp,jcc" })
eq("kinds=jmp,jcc includes the short forms", summary(r), "jmp@1210,jcc@1220,jmp@1290,jcc@1310,jmp@17F9")
r = runJob("find_xrefs", { address = GB + 0x1300, kinds = "rva" })
eq("kinds=rva", summary(r), "rva@2208")
eq("bad kinds", cmd_start_job({ kind = "find_xrefs", params = { address = GB, kinds = "bogus" } }).error_code, "INVALID_PARAMS")

-- ===================== a data target (rip-relative operands, absolute pointers) =====================
r = runJob("find_xrefs", { address = GB + 0x3000 })
eq("references to a variable", summary(r),
   "rip@13FC,rip@1410,rip@1420,rip@1430,rip@1440,rip@1450,rip@1460,rip@1470,rip@1494,abs_code@1600,abs_code@1700,rip@1960,rip@1A00,abs_data@3100")
eq("rip operand across a chunk border", byAddr(r, 0x13FC).kind, "rip")
eq("not-an-instruction bytes are dropped", byAddr(r, 0x1500).kind == nil and byAddr(r, 0x1501).kind == nil, true)
eq("the neighbour is not a reference", byAddr(r, 0x1480).kind, nil)
eq("rip access kinds", byAddr(r, 0x13FC).access .. "," .. byAddr(r, 0x1410).access .. "," .. byAddr(r, 0x1420).access .. "," ..
   byAddr(r, 0x1440).access .. "," .. byAddr(r, 0x1450).access .. "," .. byAddr(r, 0x1460).access .. "," .. byAddr(r, 0x1470).access,
   "read,write,address,read,write,call,read")
eq("lea r12 (modrm 0x25) is found", byAddr(r, 0x1430).access, "address")
eq("prefix bytes are part of the instruction", byAddr(r, 0x1430).kind == "rip" and byAddr(r, 0x1471).kind == nil and byAddr(r, 0x1472).kind == nil, true)
eq("the last byte of the previous instruction is not taken for a REX prefix", byAddr(r, 0x1494).kind == "rip" and byAddr(r, 0x1493).kind == nil and byAddr(r, 0x1494).access == "call", true)
eq("decoding from the function start is not thrown off by a mid-code decode", byAddr(r, 0x1960).kind, "rip")
eq("outside .pdata the search starts a runway back", byAddr(r, 0x1A00).kind == "rip" and byAddr(r, 0x1A00).function_start == nil, true)
eq("bytes the decoder reads as a different instruction are dropped", byAddr(r, 0x1530).kind == nil and byAddr(r, 0x1531).kind == nil, true)
eq("instruction text at the widened start", byAddr(r, 0x1470).instruction, string.format("%X - xx xx - movss xmm0,[game.exe+3000]", GB + 0x1470))
eq("rip operand with a 4 byte immediate", byAddr(r, 0x1450).kind, "rip")
eq("function of a rip operand", byAddr(r, 0x1410).function_start, "game.exe+0x13F0")
eq("absolute pointer in an instruction reports the instruction", byAddr(r, 0x1600).kind == "abs_code" and byAddr(r, 0x1600).field_address == string.format("0x%X", GB + 0x1602), true)
eq("absolute pointer without an instruction", byAddr(r, 0x1700).kind == "abs_code" and byAddr(r, 0x1700).instruction == nil and byAddr(r, 0x1700).field_address == nil, true)
eq("pointer in data", byAddr(r, 0x3100).section, ".data")

r = runJob("find_xrefs", { address = GB + 0x3000, size = 0x20 })
eq("range: rip operands, pointers and RVAs into it", summary(r),
   "rip@13FC,rip@1410,rip@1420,rip@1430,rip@1440,rip@1450,rip@1460,rip@1470,rip@1480,rip@1494,rip@1960,rip@1A00,rva@2400,abs_data@3100,abs_data@3110")
eq("range offsets", byAddr(r, 0x1480).offset_in_target == 0x10 and byAddr(r, 0x2400).offset_in_target == 4 and byAddr(r, 0x3110).offset_in_target == 0x10, true)
eq("range: code pointers are skipped and explained", r.notes ~= nil and r.notes[1]:find("absolute pointers in code", 1, true) ~= nil, true)
r = runJob("find_xrefs", { address = GB + 0x3000, kinds = "rip" })
eq("kinds=rip", r.found, 11)

-- ===================== modules =====================
r = runJob("find_xrefs", { address = LB + 0x1300 })
eq("the module holding the target is scanned by default", r.modules[1] == "lib.dll" and #r.modules == 1, true)
eq("same results in the copy", summary(r), "call@11FD,jmp@1210,jcc@1220,jmp@1290,jcc@1310,jmp@17F9,abs_data@2100,rva@2208")
eq("function lookup uses the right module", byAddr(r, 0x1210).function_start, "lib.dll+0x1200")
r = runJob("find_xrefs", { address = GB + 0x1300, module = "all" })
eq("module=all finds references from other modules", summary(r), "call@11FD,jmp@1210,jcc@1220,jmp@1290,jcc@1310,jmp@17F9,abs_data@2100,rva@2208,abs_data@2500")
eq("hit in the other module", r.references[#r.references].module == "lib.dll" and r.references[#r.references].expression == "lib.dll+0x2500", true)
eq("unreadable modules are skipped with a note", #r.modules == 2 and r.notes ~= nil and r.notes[1]:find("junk.dll", 1, true) ~= nil, true)
r = runJob("find_xrefs", { address = GB + 0x1300, module = "lib" })
eq("explicit module", summary(r), "abs_data@2500")
eq("unknown module", cmd_start_job({ kind = "find_xrefs", params = { address = GB, module = "nope.dll" } }).error_code, "NOT_FOUND")
r = runJob("find_xrefs", { address = 0x2A000000 })
eq("a heap target scans the main module", r.success and r.modules[1] == "game.exe" and r.found == 0, true)

-- ===================== limits, paging, errors =====================
r = runJob("find_xrefs", { address = GB + 0x3000, max_results = 2 })
eq("max_results stops the search and says so", r.truncated == true and r.notes ~= nil and r.notes[#r.notes]:find("max_results", 1, true) ~= nil, true)
eq("at most max_results items", r.found <= 2, true)
local started = cmd_start_job({ kind = "find_xrefs", params = { address = GB + 0x3000 } })
local id = started.job_id
for _ = 1, 20000 do
  if cmd_get_job({ job_id = id }).state ~= "running" then break end
  serverState.job_timer.OnTimer()
end
local page = cmd_get_job_result({ job_id = id, offset = 3, limit = 4 })
eq("paging", page.total == 14 and page.returned == 4 and page.offset == 3 and page.references[1].rva == 0x1430, true)
eq("bad address", cmd_start_job({ kind = "find_xrefs", params = { address = "zzz" } }).error_code, "INVALID_ADDRESS")
eq("address is required", cmd_start_job({ kind = "find_xrefs", params = {} }).error_code, "INVALID_ADDRESS")
started = cmd_start_job({ kind = "find_xrefs", params = { address = GB + 0x3000 } })
local cancelled = cmd_cancel_job({ job_id = started.job_id })
eq("cancel", cancelled.success and serverState.jobs[started.job_id].state == "cancelled", true)
eq("cancel releases the step", serverState.jobs[started.job_id]._step, nil)
PROCESS_PID = 0
eq("needs a process", cmd_start_job({ kind = "find_xrefs", params = { address = GB } }).error_code, "NO_PROCESS")
PROCESS_PID = 4242
eq("job kind is listed", cmd_start_job({ kind = "nope", params = {} }).error:find("find_xrefs", 1, true) ~= nil, true)
U26.CHUNK = 0x10000
r = runJob("find_xrefs", { address = GB + 0x3000 })
eq("same results with the normal chunk size", summary(r), "rip@13FC,rip@1410,rip@1420,rip@1430,rip@1440,rip@1450,rip@1460,rip@1470,rip@1494,abs_code@1600,abs_code@1700,rip@1960,rip@1A00,abs_data@3100")
return table.concat(results, "\n")
'''

TESTS_X86 = r'''
MODULES = {
  { Name = "old.exe", Address = @B86@, Size = 0x4000, Is64Bit = false },
}
TARGET64 = false
local GB = @B86@
U26.CHUNK = 512
local function summary(r)
  local o = {}
  for _, it in ipairs(r.references or {}) do o[#o + 1] = it.kind .. "@" .. string.format("%X", it.rva) end
  return table.concat(o, ",")
end
local function byAddr(r, rva) for _, it in ipairs(r.references or {}) do if it.rva == rva then return it end end return {} end

local r = runJob("find_xrefs", { address = GB + 0x1300 })
eq("x86: call and pointer table", summary(r), "call@1100,abs_data@2100")
eq("x86: no function table", byAddr(r, 0x1100).function_start, nil)
r = runJob("find_xrefs", { address = GB + 0x3000 })
eq("x86: absolute operands (push/mov/call/cmp imm32) and pointers", summary(r), "abs_code@1110,abs_code@1120,abs_code@1130,abs_code@1140,abs_code@1200,abs_data@3100")
eq("x86: instruction start found for an operand in the middle", byAddr(r, 0x1130).field_address, string.format("0x%X", GB + 0x1132))
eq("x86: trailing immediate byte", byAddr(r, 0x1140).field_address, string.format("0x%X", GB + 0x1142))
eq("x86: pointer without an instruction", byAddr(r, 0x1200).instruction == nil and byAddr(r, 0x1200).field_address == nil, true)
eq("x86: rip/rva kinds are ignored, not errors", runJob("find_xrefs", { address = GB + 0x3000, kinds = "rip,rva" }).found, 0)
U26.CHUNK = 0x10000
return table.concat(results, "\n")
'''


def program(images, decoders, body, repl):
    for k, v in repl.items():
        body = body.replace(k, str(v))
    return common + "\n".join(page_lines(b, d) for b, d in images) + "\n" + DECODER + "\n" + "\n".join(decoders) + "\n" + HELPERS + body


x64_prog = program([(GB, img_game), (LB, img_lib)], [decoder_lua(GB, insn_game, part_game), decoder_lua(LB, insn_lib, part_lib)],
                   TESTS_X64, {"@GB@": GB, "@LB@": LB, "@JUNK@": JUNK})
if os.environ.get("BRIDGE_TEST_DUMP"):
    open(os.environ["BRIDGE_TEST_DUMP"], "w", encoding="utf-8").write(x64_prog)
ok, msg = run_lua(x64_prog, "x64")
print("--- synthetic x64 modules")
print(msg)
x86_prog = program([(X86_BASE, img_x86)], [decoder_lua(X86_BASE, insn_x86, part_x86)], TESTS_X86, {"@B86@": X86_BASE})
ok2, msg2 = run_lua(x86_prog, "x86")
print("--- synthetic x86 module")
print(msg2)
allmsg = msg + "\n" + msg2
print("LUA EXEC", "OK" if ok and ok2 else "ERROR")
print("%d passed, %d failed" % (sum(1 for l in allmsg.splitlines() if l.startswith("PASS")), sum(1 for l in allmsg.splitlines() if l.startswith("FAIL"))))


# --------------------------------------------------------------------------- real DLL validation
# Independent oracle: capstone linear-sweeps the DLL's code (function by function, using its .pdata) and lists every
# direct branch and rip-relative operand with the address it reaches. The bridge then runs find_xrefs on the same
# bytes (capstone also answers its disassemble / getInstructionSize calls, as CE's disassembler would) and the two
# sets of instruction addresses are compared per target. Needs `pip install capstone`.
def real_xref_validation():
    import collections, ctypes, ctypes.wintypes as wt, functools, random
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM
        from capstone.x86 import X86_REG_RIP
    except ImportError:
        print("SKIP real xref validation: capstone is not installed (pip install capstone)")
        return None

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.LoadLibraryW.argtypes = [wt.LPCWSTR]
    k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.GetCurrentProcess.restype = ctypes.c_void_p

    def check_dll(dllname, n_hot=10, n_cold=8, seed=1234):
        hmod = k32.LoadLibraryW(dllname)
        if not hmod:
            print("cannot load", dllname); return None
        hdr = ctypes.string_at(hmod, 0x1000)
        nt = struct.unpack_from('<I', hdr, 0x3C)[0]
        soi = struct.unpack_from('<I', hdr, nt + 24 + 56)[0]
        nsec = struct.unpack_from('<H', hdr, nt + 6)[0]
        optsz = struct.unpack_from('<H', hdr, nt + 20)[0]
        img = bytearray(soi)
        for off in range(0, soi, 4096):
            buf = ctypes.create_string_buffer(4096)
            n = ctypes.c_size_t()
            if k32.ReadProcessMemory(k32.GetCurrentProcess(), hmod + off, buf, 4096, ctypes.byref(n)) and n.value == 4096:
                img[off:off + 4096] = buf.raw
        execs = []
        for k in range(nsec):
            o = nt + 24 + optsz + k * 40
            vs, va = struct.unpack_from('<II', hdr, o + 8)
            if struct.unpack_from('<I', hdr, o + 36)[0] & 0x20000000 and vs:
                execs.append((va, va + vs))
        pd_rva, pd_size = struct.unpack_from('<II', hdr, nt + 24 + 112 + 3 * 8)
        cuts = set()
        for b, e in execs:
            cuts.update((b, e))
        for i in range(pd_size // 12):
            b, e, _u = struct.unpack_from('<III', img, pd_rva + i * 12)
            for sb, se in execs:
                if sb <= b < se and e <= se:
                    cuts.update((b, e))
        points = sorted(cuts)
        intervals = [(a, b) for a, b in zip(points, points[1:]) if any(sb <= a and b <= se for sb, se in execs)]

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        oracle = {"branch": collections.defaultdict(set), "rip": collections.defaultdict(set)}
        ninsn = 0
        for s, e in intervals:
            pos = s
            while pos < e:
                last = pos
                for ins in md.disasm(bytes(img[pos:e]), hmod + pos):
                    ninsn += 1
                    last = ins.address - hmod + ins.size
                    mn = ins.mnemonic.replace("bnd ", "").replace("notrack ", "")
                    ops = ins.operands
                    if (mn == "call" or mn == "jmp" or (mn[0] == "j" and mn not in ("jrcxz", "jecxz", "jcxz"))) and len(ops) == 1 and ops[0].type == CS_OP_IMM:
                        oracle["branch"][ops[0].imm].add(ins.address)
                    for op in ops:
                        if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                            oracle["rip"][ins.address + ins.size + op.mem.disp].add(ins.address)
                if last >= e:
                    break
                pos = last + 1

        inside = lambda a: hmod <= a < hmod + soi
        rnd = random.Random(seed)
        picks = []
        for grp in ("branch", "rip"):
            cand = [(len(v), t) for t, v in oracle[grp].items() if inside(t)]
            cand.sort(reverse=True)
            picks += [(grp, t, 1) for _, t in cand[:n_hot]]
            cold = [t for c, t in cand if 1 <= c <= 3]
            picks += [(grp, t, 1) for t in rnd.sample(cold, min(n_cold, len(cold)))]
        hot_data = max(((len(v), t) for t, v in oracle["rip"].items() if inside(t)), default=(0, 0))[1]
        rng_base = hot_data & ~0x3F
        picks.append(("range", rng_base, 0x40))

        decode_md = Cs(CS_ARCH_X86, CS_MODE_64)

        @functools.lru_cache(maxsize=1 << 20)
        def decode(addr):
            rva = addr - hmod
            if not (0 <= rva < soi):
                return None
            for ins in decode_md.disasm(bytes(img[rva:rva + 15]), addr, 1):
                return ins.size, "%X - xx - %s %s" % (addr, ins.mnemonic, ins.op_str)
            return None

        targets = "\n".join("  { a = %d, size = %d }," % (t, size) for _g, t, size in picks)
        lua = common + "\n".join('PAGE(0x%X, "%s")' % (hmod + off, img[off:off + 4096].hex())
                                 for off in range(0, soi, 4096) if any(img[off:off + 4096])) + "\n" + HELPERS + """
MODULES = { { Name = %s, Address = %d, Size = %d, Is64Bit = true } }
TARGET64 = true
getInstructionSize = function(a) return py_isize(a) end
disassemble = function(a) return py_dis(a) end
local TARGETS = {
%s
}
local out = {}
for i, tg in ipairs(TARGETS) do
  local t0 = os.clock()
  local r = runJob("find_xrefs", { address = tg.a, size = tg.size, kinds = "call,jmp,jcc,rip", max_results = 50000 })
  local rec = { a = tg.a, size = tg.size, ok = r.success, found = r.found, secs = os.clock() - t0, refs = {} }
  local function take(page) for _, it in ipairs(page.references or {}) do rec.refs[#rec.refs + 1] = { it.kind, tonumber(it.address), it.access or "" } end end
  take(r)
  for off = 1000, (r.total or 0) - 1, 1000 do take(cmd_get_job_result({ job_id = r.job_id, offset = off, limit = 1000 })) end   -- runJob returns the first page only
  rec.total = r.total
  out[i] = rec
end
return json.encode(out)
""" % (json.dumps(dllname), hmod, soi, targets)
        okr, text = run_lua(lua, "real-xrefs", ascii_only=False,
                            callbacks={"py_isize": lambda a: (decode(a) or (None,))[0], "py_dis": lambda a: (decode(a) or (None, None))[1]})
        if not okr:
            print("LUA ERROR on", dllname, text[:400]); return None
        data = json.loads(text)
        tot_oracle = tot_hit = tot_missed = tot_extra = 0
        problems = []
        elapsed = 0.0
        for (grp, t, size), rec in zip(picks, data):
            elapsed += rec["secs"]
            want_b = set().union(*[oracle["branch"].get(x, set()) for x in range(t, t + size)]) if size == 1 else set().union(*[v for x, v in oracle["branch"].items() if t <= x < t + size])
            want_r = set().union(*[oracle["rip"].get(x, set()) for x in range(t, t + size)]) if size == 1 else set().union(*[v for x, v in oracle["rip"].items() if t <= x < t + size])
            got_b = {a for k, a, _acc in rec["refs"] if k in ("call", "jmp", "jcc")}
            got_r = {a for k, a, _acc in rec["refs"] if k == "rip"}
            for name, want, got in (("branch", want_b, got_b), ("rip", want_r, got_r)):
                tot_oracle += len(want)
                tot_hit += len(want & got)
                tot_missed += len(want - got)
                tot_extra += len(got - want)
                if want - got or got - want:
                    problems.append((name, hex(t), size, [hex(x - hmod) for x in sorted(want - got)][:4], [hex(x - hmod) for x in sorted(got - want)][:4]))
        print("--- real DLL %s: %d instructions swept, %d targets (+1 range), image 0x%X" % (dllname, ninsn, len(picks) - 1, soi))
        print("  oracle references: %d, found: %d, missed: %d, not in oracle: %d, bridge time %.2fs (%d jobs)" % (tot_oracle, tot_hit, tot_missed, tot_extra, elapsed, len(picks)))
        for p in problems[:6]:
            print("  mismatch", p)
        ok = tot_oracle > 100 and tot_missed == 0 and tot_extra <= max(2, tot_oracle // 100)
        print("%s real xrefs %s (recall %.3f%%, extras %d)" % ("PASS " if ok else "FAIL ", dllname, 100.0 * tot_hit / max(1, tot_oracle), tot_extra))
        return ok

    results = [check_dll("msvcp140.dll") if os.path.exists(os.path.join(os.environ["WINDIR"], "System32", "msvcp140.dll")) else None,
               check_dll("user32.dll")]
    return results


if has_flag("--real"):
    real_xref_validation()

finish()
