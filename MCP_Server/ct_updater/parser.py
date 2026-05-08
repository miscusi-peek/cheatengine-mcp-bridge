"""
CT file parser — extracts AOB patterns, asserts, and pointer entries
from Cheat Engine XML table files without modifying the source file.
"""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

Pattern = list  # list of int | None  (None = wildcard byte)


@dataclass
class AOBEntry:
    """An aobscanregion(...) call extracted from an AssemblerScript."""
    name: str           # the symbol name registered by aobscanregion
    symbol: str         # anchor method / start address expression
    scan_range: int     # bytes from symbol start to scan within
    pattern: Pattern    # list of int | None
    description: str    # parent CheatEntry description
    # line range within the raw CT text so the patcher can replace it
    raw_line: str = ''  # the original aobscanregion(...) line


@dataclass
class AssertEntry:
    """An assert(...) call extracted from an AssemblerScript."""
    symbol: str         # base symbol (already resolved by CE at enable-time)
    offset: int         # byte offset from symbol
    expected: Pattern   # expected bytes
    description: str
    raw_line: str = ''


@dataclass
class PointerEntry:
    """A non-script CheatEntry with a symbol address and offset chain."""
    description: str
    symbol: str         # e.g. "MoneyPtr"
    offsets: list[int]  # pointer chain offsets (hex)
    var_type: str


# ---------------------------------------------------------------------------
# Hex pattern parsing
# ---------------------------------------------------------------------------

_WILDCARD = re.compile(r'^\?+$|^\*+$')


def parse_pattern(pat_str: str) -> Pattern:
    """
    Parse a CE hex pattern string into a list of int | None.
    Wildcards (??, *, **) become None.
    """
    parts = pat_str.strip().split()
    result: Pattern = []
    for p in parts:
        if _WILDCARD.match(p):
            result.append(None)
        else:
            try:
                result.append(int(p, 16))
            except ValueError:
                result.append(None)  # treat garbage as wildcard
    return result


def pattern_to_str(pat: Pattern) -> str:
    return ' '.join('??' if b is None else f'{b:02X}' for b in pat)


# ---------------------------------------------------------------------------
# Assembler script parsing
# ---------------------------------------------------------------------------

_AOB_RE = re.compile(
    r'aobscanregion\s*\(\s*'
    r'(\w+)\s*,\s*'         # name
    r'([^,]+?)\s*,\s*'      # start expression
    r'([^,]+?)\s*,\s*'      # end expression
    r'([0-9A-Fa-f?* ]+?)'   # hex pattern
    r'\s*\)',
    re.IGNORECASE,
)

_ASSERT_RE = re.compile(
    r'assert\s*\(\s*'
    r'([\w:]+)'                           # symbol (allow colons e.g. Class:Method)
    r'(?:\s*\+\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+))?' # optional +offset (hex or dec)
    r'\s*,\s*'
    r'([0-9A-Fa-f ]+?)'                   # bytes
    r'\s*\)',
    re.IGNORECASE,
)


_HEX_CHARS = frozenset('abcdefABCDEF')


def _parse_ce_number(s: str) -> int:
    """
    Parse a CE auto-assembler number:
      - '0x'-prefixed  → hex
      - contains A-F   → hex (CE bare hex, e.g. 10C, 39C)
      - digits only    → decimal (CE default, e.g. 100, 350)
    """
    s = s.strip()
    if s.lower().startswith('0x'):
        return int(s, 16)
    if _HEX_CHARS.intersection(s):
        return int(s, 16)
    return int(s, 10)


def _parse_range(end_expr: str) -> int:
    """
    Extract the numeric offset from an end expression like 'Symbol+100',
    'Symbol+10C', or 'Symbol+0x6C'.
    """
    end_expr = end_expr.strip()
    if '+' in end_expr:
        suffix = end_expr.rsplit('+', 1)[1].strip()
        try:
            return _parse_ce_number(suffix)
        except ValueError:
            pass
    try:
        return _parse_ce_number(end_expr)
    except ValueError:
        return 256  # default


def _extract_enable_block(script: str) -> str:
    """Return only the [ENABLE] section of an assembler script."""
    if '[DISABLE]' in script:
        return script.split('[DISABLE]')[0]
    return script


def parse_script(script: str, description: str) -> tuple[list[AOBEntry], list[AssertEntry]]:
    enable_block = _extract_enable_block(script)
    aobs: list[AOBEntry] = []
    asserts: list[AssertEntry] = []

    for m in _AOB_RE.finditer(enable_block):
        name, start_expr, end_expr, pat_str = m.groups()
        symbol = start_expr.strip()
        scan_range = _parse_range(end_expr)
        aobs.append(AOBEntry(
            name=name,
            symbol=symbol,
            scan_range=scan_range,
            pattern=parse_pattern(pat_str),
            description=description,
            raw_line=m.group(0),
        ))

    for m in _ASSERT_RE.finditer(enable_block):
        sym, off_str, pat_str = m.groups()
        try:
            offset = _parse_ce_number(off_str) if off_str else 0
        except (ValueError, TypeError):
            offset = 0
        asserts.append(AssertEntry(
            symbol=sym,
            offset=offset,
            expected=parse_pattern(pat_str),
            description=description,
            raw_line=m.group(0),
        ))

    return aobs, asserts


# ---------------------------------------------------------------------------
# CT file parser
# ---------------------------------------------------------------------------

def parse_ct(path: str) -> tuple[list[AOBEntry], list[AssertEntry], list[PointerEntry]]:
    """
    Parse a .CT file and return all AOB entries, asserts, and pointer entries.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    all_aobs: list[AOBEntry] = []
    all_asserts: list[AssertEntry] = []
    all_pointers: list[PointerEntry] = []
    seen_aob_names: set[str] = set()

    for entry in root.iter('CheatEntry'):
        desc = (entry.findtext('Description') or '').strip('"').strip()
        var_type = (entry.findtext('VariableType') or '').strip()
        script = entry.findtext('AssemblerScript') or ''

        if var_type == 'Auto Assembler Script' and script:
            aobs, asserts = parse_script(script, desc)
            for a in aobs:
                if a.name not in seen_aob_names:
                    seen_aob_names.add(a.name)
                    all_aobs.append(a)
            all_asserts.extend(asserts)

        elif var_type and var_type != 'Auto Assembler Script':
            addr_text = (entry.findtext('Address') or '').strip()
            if not addr_text:
                continue
            # Only include symbol-based addresses (not raw hex)
            is_symbol = addr_text and not addr_text.startswith('0x') and not addr_text[:1].isdigit()
            if not is_symbol:
                continue
            offsets_elem = entry.find('Offsets')
            offsets: list[int] = []
            if offsets_elem is not None:
                for off_el in offsets_elem.findall('Offset'):
                    try:
                        offsets.append(int(off_el.text or '0', 16))
                    except ValueError:
                        pass
            all_pointers.append(PointerEntry(
                description=desc,
                symbol=addr_text,
                offsets=offsets,
                var_type=var_type,
            ))

    return all_aobs, all_asserts, all_pointers
