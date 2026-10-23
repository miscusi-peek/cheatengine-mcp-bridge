"""Runs Lua 5.3 chunks through Cheat Engine's own Lua DLL (no Cheat Engine process needed) and extracts
pieces of the bridge source so handlers can be driven against a fake CE API.

The DLL is found via the CE_LUA_DLL environment variable, then the usual Cheat Engine install folders.
If none is found the suite exits with code 77 (skipped).
"""
import ctypes
import os
import sys
from pathlib import Path

import testkit
from testkit import EXIT_SKIP, BRIDGE_LUA, arg_path, has_flag, finish  # re-exported for the suites  # noqa: F401

_CANDIDATES = [
    os.environ.get("CE_LUA_DLL"),
    r"C:\Program Files\Cheat Engine\lua53-64.dll",
    r"C:\Program Files\Cheat Engine 7.6\lua53-64.dll",
    r"C:\Program Files (x86)\Cheat Engine\lua53-64.dll",
]


def find_lua_dll():
    for cand in _CANDIDATES:
        if cand and Path(cand).is_file():
            return cand
    return None


def _load_lib():
    dll = find_lua_dll()
    if not dll:
        print("SKIP: Cheat Engine's lua53-64.dll was not found. Set CE_LUA_DLL to its path.", file=sys.stderr)
        sys.exit(EXIT_SKIP)
    lib = ctypes.CDLL(dll)
    lib.luaL_newstate.restype = ctypes.c_void_p
    lib.luaL_openlibs.argtypes = [ctypes.c_void_p]
    lib.luaL_loadbufferx.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
    lib.lua_pcallk.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ssize_t, ctypes.c_void_p]
    lib.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_size_t)]
    lib.lua_tolstring.restype = ctypes.c_void_p
    lib.lua_close.argtypes = [ctypes.c_void_p]
    lib.lua_pushcclosure.argtypes = [ctypes.c_void_p, _LUA_CFUNC, ctypes.c_int]
    lib.lua_setglobal.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.lua_tointegerx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.lua_tointegerx.restype = ctypes.c_longlong
    lib.lua_pushinteger.argtypes = [ctypes.c_void_p, ctypes.c_longlong]
    lib.lua_pushlstring.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.lua_pushnil.argtypes = [ctypes.c_void_p]
    return lib


_LUA_CFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
lib = _load_lib()


def _wrap_callback(fn):
    """Python function(int address) -> int | str | None, exposed to Lua as a one-argument global function."""
    def tramp(L):
        try:
            res = fn(lib.lua_tointegerx(L, 1, None))
        except Exception as exc:                    # a callback must never unwind through the Lua VM
            print("CALLBACK ERROR:", exc)
            res = None
        if res is None:
            lib.lua_pushnil(L)
        elif isinstance(res, int):
            lib.lua_pushinteger(L, res)
        else:
            raw = str(res).encode("utf-8", "replace")
            lib.lua_pushlstring(L, raw, len(raw))
        return 1
    return _LUA_CFUNC(tramp)


def run_lua(code, name="chunk", ascii_only=True, callbacks=None):
    """Run `code` in a fresh Lua state. Returns (ok, text) where text is the chunk's string result or its error.

    callbacks: {global name: python function(address) -> int | str | None}, available to the chunk as Lua globals
    (e.g. a real disassembler standing in for CE's getInstructionSize / disassemble).
    """
    L = lib.luaL_newstate()
    lib.luaL_openlibs(L)
    keep = []
    for gname, fn in (callbacks or {}).items():
        cfn = _wrap_callback(fn)
        keep.append(cfn)                            # must outlive the state
        lib.lua_pushcclosure(L, cfn, 0)
        lib.lua_setglobal(L, gname.encode())
    try:
        data = code.encode("utf-8")
        rc = lib.luaL_loadbufferx(L, data, len(data), name.encode(), None)
        if rc == 0:
            rc = lib.lua_pcallk(L, 0, 1, 0, 0, None)
        n = ctypes.c_size_t()
        p = lib.lua_tolstring(L, -1, ctypes.byref(n))
        text = ctypes.string_at(p, n.value).decode("utf-8", "replace") if p else ""
        if ascii_only:
            text = text.encode("ascii", "backslashreplace").decode("ascii")
        if rc != 0:
            # A crashed chunk produces no PASS/FAIL lines, so make sure it is counted as an error.
            print("LUA ERROR in chunk '%s': %s" % (name, text[:300].replace("\n", " ")))
        return rc == 0, text
    finally:
        lib.lua_close(L)


def load(path):
    """Bridge source with LF line endings."""
    return Path(path).read_bytes().decode("utf-8").replace("\r\n", "\n")


def func_end(text, start):
    """(start_index, end_index) of the top-level function that begins with the marker `start`."""
    i = text.index(start)
    return i, text.index("\nend\n", i) + 5


def func_block(text, start):
    i, j = func_end(text, start)
    return text[i:j]


def between(text, start, end_marker, include_end=True):
    i = text.index(start)
    j = text.index(end_marker, i)
    return text[i:j + (len(end_marker) if include_end else 0)]


def compile_check(text):
    """The whole bridge must at least compile under CE's Lua; prints COMPILE OK / COMPILE FAIL and exits on failure."""
    ok, msg = run_lua('local f, e = load([==[' + text + ']==], "bridge", "t"); return f and "COMPILE OK" or ("COMPILE FAIL: " .. tostring(e))')
    print(msg)
    if "COMPILE OK" not in msg:
        finish()
