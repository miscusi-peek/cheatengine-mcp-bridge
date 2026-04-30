"""
Shared helpers for ct_updater/tools.
"""
import math
import struct


# Windows 64-bit user-mode heap range.
# Floor at 64 GB to avoid false-positives from small integers forming fake pointers.
_PTR_LO = 0x1_0000_0000_0   # 64 GB
_PTR_HI = 0x7FFF_FFFF_FFFF  # 128 TB canonical user-mode ceiling


def is_heap_ptr(v: int) -> bool:
    """Return True if v looks like a valid 64-bit user-mode heap pointer."""
    return _PTR_LO < v < _PTR_HI


def looks_like_float(raw_dword: int) -> tuple:
    """Return (is_plausible_float, value). Rejects NaN, Inf, and denormals."""
    f = struct.unpack('<f', struct.pack('<I', raw_dword))[0]
    if math.isnan(f) or math.isinf(f):
        return False, 0.0
    exp = (raw_dword >> 23) & 0xFF
    if exp == 0:        # denormal
        return False, 0.0
    if abs(f) < 1e-4 or abs(f) > 1e7:
        return False, f
    return True, f


def parse_known(args: list) -> dict:
    """Parse ['name=value', ...] into {name: int_or_float}."""
    out = {}
    for a in args:
        if '=' not in a:
            continue
        k, _, v = a.partition('=')
        k, v = k.strip(), v.strip()
        try:
            out[k] = int(v, 0)
        except ValueError:
            try:
                out[k] = float(v)
            except ValueError:
                pass
    return out


def parse_comma_known(s: str) -> dict:
    """Parse 'name=val,name=val' string."""
    return parse_known(s.split(',')) if s else {}


def vtype_for(val) -> str:
    """Return the CE scan type string for a Python value."""
    if isinstance(val, float):
        return 'float'
    v = int(val)
    if v > 0xFFFFFFFF or v < -(2 ** 31):
        return 'qword'
    return 'dword'
