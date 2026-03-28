#!/usr/bin/env python3
"""
Comprehensive MCP Bridge Test Suite v3
=======================================
Enhanced test suite with:
- Data correctness validation (not just success/failure)
- Proper code address testing (using module entry points, not header data)
- Architecture validation (32/64-bit detection)
- Breakpoint tests with cleanup
- Proper SKIPPED vs PASSED distinction
- analyze_function and find_call_references tests

This test suite is designed to give 100% confidence in MCP bridge reliability.
"""

import win32file
import win32pipe
import struct
import json
import time
import sys
import os
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List, Callable

DEFAULT_PIPE_NAME = "CE_MCP_Bridge_v99"


def normalize_pipe_name(pipe_name: str | None) -> str:
    raw_name = pipe_name or os.getenv("CE_MCP_PIPE_NAME") or DEFAULT_PIPE_NAME
    if raw_name.startswith("\\\\.\\pipe\\"):
        return raw_name
    return rf"\\.\pipe\{raw_name}"


PIPE_NAME = normalize_pipe_name(None)
CONNECT_WAIT_MS = int(os.getenv("CE_MCP_CONNECT_WAIT_MS", "3000"))

class TestResult:
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

class MCPTestClient:
    def __init__(self):
        self.handle = None
        self.request_id = 0
        
    def connect(self) -> bool:
        try:
            win32pipe.WaitNamedPipe(PIPE_NAME, CONNECT_WAIT_MS)
            self.handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            print(f"✓ Connected to {PIPE_NAME}")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def send_command(self, method: str, params: Optional[dict] = None) -> dict:
        if params is None:
            params = {}
        
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }
        
        data = json.dumps(request).encode('utf-8')
        header = struct.pack('<I', len(data))
        win32file.WriteFile(self.handle, header + data)
        
        _, resp_header = win32file.ReadFile(self.handle, 4)
        resp_len = struct.unpack('<I', resp_header)[0]
        _, resp_data = win32file.ReadFile(self.handle, resp_len)
        
        return json.loads(resp_data.decode('utf-8'))
    
    def close(self):
        if self.handle:
            try:
                win32file.CloseHandle(self.handle)
            finally:
                self.handle = None


class PythonToolClient:
    """Invoke Python MCP helper functions directly for wrapper-level smoke tests."""

    def __init__(self):
        import mcp_cheatengine as python_server

        self.python_server = python_server
        self.tool_map = {
            "evaluate_lua_file": python_server.evaluate_lua_file,
            "auto_assemble_file": python_server.auto_assemble_file,
        }

    def send_command(self, method: str, params: Optional[dict] = None) -> dict:
        if params is None:
            params = {}

        if method not in self.tool_map:
            raise ValueError(f"Unsupported Python helper method: {method}")

        result = self.tool_map[method](**params)
        payload = json.loads(result) if isinstance(result, str) else result
        return {"result": payload}


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def validate_hex_address(value: str) -> bool:
    """Validate that a string is a valid hex address (0x...)"""
    if not isinstance(value, str):
        return False
    if not value.startswith("0x") and not value.startswith("0X"):
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False

def validate_bytes_match_data(bytes_array: list, data_string: str) -> bool:
    """Validate that bytes array matches space-separated hex data string"""
    expected_bytes = [int(b, 16) for b in data_string.split()]
    return bytes_array == expected_bytes

def validate_integer_in_range(value: int, min_val: int, max_val: int) -> bool:
    """Validate integer is within expected range"""
    return isinstance(value, int) and min_val <= value <= max_val


# ============================================================================
# TEST FRAMEWORK
# ============================================================================

class TestCase:
    """Represents a single test case with validation"""
    def __init__(self, name: str, method: str, params: dict = None,
                 validators: List[Callable] = None, skip_reason: str = None):
        self.name = name
        self.method = method
        self.params = params or {}
        self.validators = validators or []
        self.skip_reason = skip_reason
        self.result = None
        self.response = None
        self.error = None
        self.validation_errors = []
    
    def run(self, client: MCPTestClient) -> str:
        """Run the test and return result status"""
        print(f"\n{'='*60}")
        print(f"Testing: {self.name}")
        print(f"{'='*60}")
        
        if self.skip_reason:
            print(f"⊘ SKIPPED: {self.skip_reason}")
            self.result = TestResult.SKIPPED
            return self.result
        
        try:
            raw_result = client.send_command(self.method, self.params)
            
            # Check for protocol-level error
            if "error" in raw_result and raw_result["error"]:
                self.error = raw_result['error']
                print(f"✗ PROTOCOL ERROR: {self.error}")
                self.result = TestResult.FAILED
                return self.result
            
            self.response = raw_result.get("result", {})
            
            # Check for command-level failure
            if self.response.get("success") == False:
                # Check if this is an expected failure (like "no process attached")
                error_msg = self.response.get('error', 'Unknown error')
                self.error = error_msg
                print(f"✗ COMMAND FAILED: {error_msg}")
                self.result = TestResult.FAILED
                return self.result
            
            # Run validators
            self.validation_errors = []
            for validator in self.validators:
                try:
                    valid, msg = validator(self.response)
                    if not valid:
                        self.validation_errors.append(msg)
                except Exception as e:
                    self.validation_errors.append(f"Validator exception: {e}")
            
            # Print response (truncated)
            resp_str = json.dumps(self.response, indent=2)
            if len(resp_str) > 500:
                resp_str = resp_str[:500] + "\n  ... (truncated)"
            print(f"Response: {resp_str}")
            
            if self.validation_errors:
                print(f"✗ VALIDATION FAILED:")
                for err in self.validation_errors:
                    print(f"  - {err}")
                self.result = TestResult.FAILED
            else:
                print(f"✓ PASSED")
                self.result = TestResult.PASSED
            
            return self.result
            
        except Exception as e:
            self.error = str(e)
            print(f"✗ EXCEPTION: {e}")
            self.result = TestResult.FAILED
            return self.result


# ============================================================================
# VALIDATOR FACTORIES
# ============================================================================

def has_field(field: str, field_type: type = None):
    """Validator: response has required field"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing required field: {field}"
        if field_type and not isinstance(resp[field], field_type):
            return False, f"Field '{field}' should be {field_type.__name__}, got {type(resp[field]).__name__}"
        return True, ""
    return validator

def field_equals(field: str, expected):
    """Validator: field equals expected value"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing field: {field}"
        if resp[field] != expected:
            return False, f"Field '{field}' = {resp[field]}, expected {expected}"
        return True, ""
    return validator

def field_in_range(field: str, min_val, max_val):
    """Validator: numeric field is in range"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing field: {field}"
        val = resp[field]
        if not isinstance(val, (int, float)):
            return False, f"Field '{field}' is not numeric"
        if not (min_val <= val <= max_val):
            return False, f"Field '{field}' = {val}, expected range [{min_val}, {max_val}]"
        return True, ""
    return validator

def field_is_hex_address(field: str):
    """Validator: field is a valid hex address string"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing field: {field}"
        if not validate_hex_address(resp[field]):
            return False, f"Field '{field}' = {resp[field]}, not a valid hex address"
        return True, ""
    return validator

def array_not_empty(field: str):
    """Validator: array field is not empty"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing field: {field}"
        if not isinstance(resp[field], list):
            return False, f"Field '{field}' is not an array"
        if len(resp[field]) == 0:
            return False, f"Field '{field}' is empty, expected at least one element"
        return True, ""
    return validator

def array_min_length(field: str, min_len: int):
    """Validator: array has minimum length"""
    def validator(resp):
        if field not in resp:
            return False, f"Missing field: {field}"
        if not isinstance(resp[field], list):
            return False, f"Field '{field}' is not an array"
        if len(resp[field]) < min_len:
            return False, f"Field '{field}' has {len(resp[field])} items, expected >= {min_len}"
        return True, ""
    return validator

def bytes_match_pattern(bytes_field: str, data_field: str):
    """Validator: bytes array matches data string"""
    def validator(resp):
        if bytes_field not in resp:
            return False, f"Missing field: {bytes_field}"
        if data_field not in resp:
            return False, f"Missing field: {data_field}"
        if not validate_bytes_match_data(resp[bytes_field], resp[data_field]):
            return False, f"Bytes array doesn't match data string"
        return True, ""
    return validator

def mz_header_check():
    """Validator: First two bytes are 'MZ' (0x4D, 0x5A) for PE header"""
    def validator(resp):
        if "bytes" not in resp:
            return False, "Missing 'bytes' field"
        bytes_arr = resp["bytes"]
        if len(bytes_arr) < 2:
            return False, "Not enough bytes to check MZ header"
        if bytes_arr[0] != 0x4D or bytes_arr[1] != 0x5A:
            return False, f"Expected MZ header (4D 5A), got {bytes_arr[0]:02X} {bytes_arr[1]:02X}"
        return True, ""
    return validator

def arch_is_valid():
    """Validator: arch field is 'x86' or 'x64'"""
    def validator(resp):
        if "arch" not in resp:
            return False, "Missing 'arch' field"
        if resp["arch"] not in ["x86", "x64"]:
            return False, f"Invalid arch: {resp['arch']}, expected 'x86' or 'x64'"
        return True, ""
    return validator

def version_check(expected_prefix: str):
    """Validator: version starts with expected prefix"""
    def validator(resp):
        if "version" not in resp:
            return False, "Missing 'version' field"
        if not resp["version"].startswith(expected_prefix):
            return False, f"Version '{resp['version']}' doesn't start with '{expected_prefix}'"
        return True, ""
    return validator


# ============================================================================
# MAIN TEST SUITE
# ============================================================================

def main():
    print("=" * 70)
    print("MCP BRIDGE COMPREHENSIVE TEST SUITE v3")
    print("Enhanced with data validation and correctness checks")
    print("=" * 70)
    
    client = MCPTestClient()
    if not client.connect():
        sys.exit(1)
    
    all_tests: Dict[str, TestCase] = {}
    
    # =========================================================================
    # CATEGORY 1: Basic & Utility Commands
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 1: Basic & Utility Commands")
    print("=" * 70)
    
    all_tests["ping"] = TestCase(
        "Ping", "ping",
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("version", str),
            version_check("11.4"),
            has_field("message", str),
            has_field("timestamp", int),
        ]
    )
    
    all_tests["get_process_info"] = TestCase(
        "Get Process Info", "get_process_info",
        validators=[
            has_field("success", bool),
            has_field("process_id", int),
            field_in_range("process_id", 1, 0xFFFFFFFF),  # Valid PID range
        ]
    )
    
    all_tests["evaluate_lua_simple"] = TestCase(
        "Evaluate Lua (2+2)", "evaluate_lua",
        params={"code": "return 2 + 2"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("result", str),
            field_equals("result", "4"),  # Exact result validation!
        ]
    )
    
    all_tests["evaluate_lua_complex"] = TestCase(
        "Evaluate Lua (getCEVersion)", "evaluate_lua",
        params={"code": "return getCEVersion()"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("result", str),
        ]
    )
    
    all_tests["evaluate_lua_targetIs64Bit"] = TestCase(
        "Evaluate Lua (targetIs64Bit)", "evaluate_lua",
        params={"code": "return tostring(targetIs64Bit())"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("result", str),
            # Result should be "true" or "false"
            lambda r: (r.get("result") in ["true", "false"], 
                      f"Expected 'true' or 'false', got '{r.get('result')}'"),
        ]
    )

    all_tests["evaluate_lua_structured"] = TestCase(
        "Evaluate Lua (structured table)", "evaluate_lua",
        params={"code": 'return { answer = 42, label = "ok" }', "serialize_result": True},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("result", dict),
            has_field("result_type", str),
            field_equals("result_type", "table"),
            has_field("serialized", bool),
            field_equals("serialized", True),
            lambda r: (r.get("result", {}).get("answer") == 42,
                      f"Expected result.answer=42, got {r.get('result')}"),
            lambda r: (r.get("result", {}).get("label") == "ok",
                      f"Expected result.label='ok', got {r.get('result')}"),
        ]
    )
    
    # Run Category 1
    for test in ["ping", "get_process_info", "evaluate_lua_simple", "evaluate_lua_complex", "evaluate_lua_targetIs64Bit", "evaluate_lua_structured"]:
        all_tests[test].run(client)
    
    # Get arch info for later tests
    arch_result = client.send_command("evaluate_lua", {"code": "return tostring(targetIs64Bit())"})
    is_64bit = arch_result.get("result", {}).get("result") == "true"
    print(f"\n[Target Architecture: {'x64' if is_64bit else 'x86'}]")
    
    # =========================================================================
    # CATEGORY 2: Memory Scanning
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 2: Memory Scanning")
    print("=" * 70)
    
    all_tests["scan_all"] = TestCase(
        "Scan All (value=1)", "scan_all",
        params={"value": 1, "type": "dword"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("count", int),
            field_in_range("count", 1, 100000000),  # At least 1 result expected
        ]
    )

    all_tests["scan_all_default_type"] = TestCase(
        "Scan All (default dword type)", "scan_all",
        params={"value": 1},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("count", int),
            field_in_range("count", 1, 100000000),
        ]
    )
    
    all_tests["get_scan_results"] = TestCase(
        "Get Scan Results", "get_scan_results",
        params={"max": 5},
        validators=[
            has_field("success", bool),
            has_field("returned", int),
            has_field("results", list),
            array_not_empty("results"),
        ]
    )
    
    all_tests["aob_scan"] = TestCase(
        "AOB Scan (MZ header)", "aob_scan",
        params={"pattern": "4D 5A 90 00", "limit": 5},
        validators=[
            has_field("success", bool),
            has_field("count", int),
            has_field("addresses", list),
            array_not_empty("addresses"),
        ]
    )
    
    all_tests["search_string"] = TestCase(
        "Search String (test)", "search_string",
        params={"string": "test", "limit": 5},
        validators=[
            has_field("success", bool),
            has_field("count", int),
            has_field("addresses", list),
        ]
    )
    
    # Run Category 2
    for test in ["scan_all", "scan_all_default_type", "get_scan_results", "aob_scan", "search_string"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # GET PROPER TEST ADDRESSES
    # =========================================================================
    # Use module base address (PE header) for memory tests
    # Use entry point (code) for disassembly/analysis tests
    
    modules_result = client.send_command("enum_modules")
    module_base = None
    module_name = None
    
    if modules_result.get("result", {}).get("modules"):
        # Find a module (preferably the main executable)
        for mod in modules_result["result"]["modules"]:
            module_base = int(mod["address"], 16) if isinstance(mod["address"], str) else mod["address"]
            module_name = mod["name"]
            break
    
    if module_base:
        print(f"\n[Using module '{module_name}' at {hex(module_base)} for tests]")
    else:
        # Fallback to 0x400000 (common base address)
        module_base = 0x400000
        print(f"\n[Using fallback address {hex(module_base)} for tests]")
    
    # =========================================================================
    # CATEGORY 3: Memory Reading - WITH DATA VALIDATION
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 3: Memory Reading (with data validation)")
    print("=" * 70)
    
    all_tests["read_memory"] = TestCase(
        "Read Memory (16 bytes from PE header)", "read_memory",
        params={"address": module_base, "size": 16},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("bytes", list),
            has_field("data", str),
            has_field("size", int),
            field_equals("size", 16),
            mz_header_check(),  # Validates first 2 bytes are 'MZ'
            bytes_match_pattern("bytes", "data"),  # Cross-validate bytes vs data string
        ]
    )
    
    all_tests["read_integer_byte"] = TestCase(
        "Read Integer (byte) - should be 0x4D (M)", "read_integer",
        params={"address": module_base, "type": "byte"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("value", int),
            field_equals("value", 0x4D),  # 'M' from MZ header
            has_field("type", str),
            field_equals("type", "byte"),
        ]
    )
    
    all_tests["read_integer_word"] = TestCase(
        "Read Integer (word) - should be 0x5A4D (ZM little-endian)", "read_integer",
        params={"address": module_base, "type": "word"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("value", int),
            field_equals("value", 0x5A4D),  # MZ in little-endian
            has_field("type", str),
            field_equals("type", "word"),
        ]
    )
    
    all_tests["read_integer_dword"] = TestCase(
        "Read Integer (dword)", "read_integer",
        params={"address": module_base, "type": "dword"},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("value", int),
            has_field("type", str),
            field_equals("type", "dword"),
        ]
    )
    
    all_tests["read_string"] = TestCase(
        "Read String (MZ header)", "read_string",
        params={"address": module_base, "max_length": 32},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("value", str),
            # Value should start with "MZ" or contain it
            lambda r: ("MZ" in r.get("value", "") or r["value"].startswith("MZ"), 
                      f"Expected 'MZ' in value, got '{r.get('value')}'"),
        ]
    )
    
    # Run Category 3
    for test in ["read_memory", "read_integer_byte", "read_integer_word", "read_integer_dword", "read_string"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 4: Disassembly & Analysis
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 4: Disassembly & Analysis")
    print("=" * 70)
    
    # For disassembly, use a CODE address (entry point), not header data
    # Read PE header to find entry point
    entry_point = None
    pe_offset_result = client.send_command("read_integer", {"address": module_base + 0x3C, "type": "dword"})
    if pe_offset_result.get("result", {}).get("success"):
        pe_offset = pe_offset_result["result"]["value"]
        entry_rva_result = client.send_command("read_integer", {"address": module_base + pe_offset + 0x28, "type": "dword"})
        if entry_rva_result.get("result", {}).get("success"):
            entry_rva = entry_rva_result["result"]["value"]
            entry_point = module_base + entry_rva
            print(f"[Found entry point at {hex(entry_point)}]")
    
    if not entry_point:
        # Fallback - just use module base + some offset
        entry_point = module_base + 0x1000
        print(f"[Using fallback code address {hex(entry_point)}]")
    
    all_tests["disassemble"] = TestCase(
        "Disassemble (5 instructions from entry point)", "disassemble",
        params={"address": entry_point, "count": 5},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("instructions", list),
            array_min_length("instructions", 1),
            # Each instruction should have address, bytes, instruction fields
            lambda r: (all("address" in i and "bytes" in i and "instruction" in i 
                         for i in r.get("instructions", [])),
                       "Instruction missing required fields (address, bytes, instruction)"),
        ]
    )
    
    all_tests["get_instruction_info"] = TestCase(
        "Get Instruction Info", "get_instruction_info",
        params={"address": entry_point},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("instruction", str),
            has_field("size", int),
            field_in_range("size", 1, 15),  # x86 instructions are 1-15 bytes
            has_field("bytes", str),
        ]
    )
    
    all_tests["find_function_boundaries"] = TestCase(
        "Find Function Boundaries", "find_function_boundaries",
        params={"address": entry_point},
        validators=[
            has_field("success", bool),
            # Note: might not find prologue, but should have arch field
            arch_is_valid(),
        ]
    )
    
    all_tests["analyze_function"] = TestCase(
        "Analyze Function", "analyze_function",
        params={"address": entry_point},
        validators=[
            has_field("success", bool),
            # Note: might fail to find function start, but should return proper error or arch
        ]
    )
    
    # Run Category 4
    for test in ["disassemble", "get_instruction_info", "find_function_boundaries", "analyze_function"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 5: Reference Finding
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 5: Reference Finding")
    print("=" * 70)
    
    all_tests["find_references"] = TestCase(
        "Find References", "find_references",
        params={"address": entry_point, "limit": 5},
        validators=[
            has_field("success", bool),
            arch_is_valid(),
            has_field("references", list),
            has_field("count", int),
        ]
    )
    
    all_tests["find_call_references"] = TestCase(
        "Find CALL References", "find_call_references",
        params={"address": entry_point, "limit": 5},
        validators=[
            has_field("success", bool),
        ]
    )
    
    # Run Category 5
    for test in ["find_references", "find_call_references"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 6: Breakpoints (with cleanup)
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 6: Breakpoints")
    print("=" * 70)
    
    all_tests["list_breakpoints"] = TestCase(
        "List Breakpoints", "list_breakpoints",
        validators=[
            has_field("success", bool),
            has_field("breakpoints", list),
            has_field("count", int),
        ]
    )
    
    all_tests["clear_all_breakpoints"] = TestCase(
        "Clear All Breakpoints", "clear_all_breakpoints",
        validators=[
            has_field("success", bool),
            has_field("removed", int),
        ]
    )
    
    # Run Category 6 - just list and clear (safe operations)
    for test in ["list_breakpoints", "clear_all_breakpoints"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 7: Modules
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 7: Module Operations")
    print("=" * 70)
    
    all_tests["enum_modules"] = TestCase(
        "Enumerate Modules", "enum_modules",
        validators=[
            has_field("success", bool),
            has_field("count", int),
            has_field("modules", list),
            # Should have at least 1 module if process is attached
        ]
    )
    
    all_tests["get_symbol_address"] = TestCase(
        "Get Symbol Address", "get_symbol_address",
        params={"symbol": hex(module_base)},
        validators=[
            has_field("success", bool),
        ]
    )
    
    all_tests["get_memory_regions"] = TestCase(
        "Get Memory Regions", "get_memory_regions",
        params={"max": 5},
        validators=[
            has_field("success", bool),
            has_field("regions", list),
            has_field("count", int),
        ]
    )
    
    # Run Category 7
    for test in ["enum_modules", "get_symbol_address", "get_memory_regions"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 8: High-Level Analysis Tools
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 8: High-Level Analysis Tools")
    print("=" * 70)
    
    all_tests["get_thread_list"] = TestCase(
        "Get Thread List", "get_thread_list",
        validators=[
            has_field("success", bool),
            has_field("threads", list),
            array_not_empty("threads"),
        ]
    )
    
    all_tests["enum_memory_regions_full"] = TestCase(
        "Enum Memory Regions Full (Native API)", "enum_memory_regions_full",
        params={"max": 10},
        validators=[
            has_field("success", bool),
            has_field("regions", list),
            has_field("count", int),
        ]
    )
    
    all_tests["dissect_structure"] = TestCase(
        "Dissect Structure (autoGuess)", "dissect_structure",
        params={"address": hex(module_base), "size": 64},
        validators=[
            has_field("success", bool),
            has_field("base_address", str),
            has_field("size_analyzed", int),
        ]
    )
    
    all_tests["read_pointer_chain"] = TestCase(
        "Read Pointer Chain", "read_pointer_chain",
        params={"base": hex(module_base), "offsets": [0x3C]},
        validators=[
            has_field("success", bool),
            has_field("base", str),
            has_field("chain", list),
            has_field("final_address", str),
            field_is_hex_address("final_address"),
        ]
    )

    all_tests["read_pointer"] = TestCase(
        "Read Pointer (simple dereference)", "read_pointer",
        params={"address": hex(module_base)},
        validators=[
            has_field("success", bool),
            field_equals("success", True),
            has_field("base", str),
            has_field("final_address", str),
            has_field("path", list),
            field_is_hex_address("base"),
            field_is_hex_address("final_address"),
            lambda r: (len(r.get("path", [])) == 1,
                      f"Expected simple read_pointer path length 1, got {len(r.get('path', []))}"),
            lambda r: (r.get("path", [None])[0] == r.get("base"),
                      f"Expected path[0] to equal base, got {r.get('path')} vs {r.get('base')}"),
            lambda r: (int(r.get("final_address", "0"), 16) == module_base,
                      f"Expected final_address to stay at base {hex(module_base)}, got {r.get('final_address')}"),
        ]
    )
    
    all_tests["auto_assemble"] = TestCase(
        "Auto Assemble (safe alloc)", "auto_assemble",
        params={"script": "globalalloc(mcp_test_region_v3,4)"},
        validators=[
            has_field("success", bool),
            has_field("executed", bool),
        ]
    )
    
    all_tests["get_rtti_classname"] = TestCase(
        "Get RTTI Class Name", "get_rtti_classname",
        params={"address": hex(module_base)},
        validators=[
            has_field("success", bool),
            # RTTI might not be found, but should have 'found' field
            has_field("found", bool),
        ]
    )
    
    all_tests["get_address_info"] = TestCase(
        "Get Address Info", "get_address_info",
        params={"address": hex(module_base)},
        validators=[
            has_field("success", bool),
            has_field("address", str),
        ]
    )
    
    all_tests["checksum_memory"] = TestCase(
        "Checksum Memory (MD5)", "checksum_memory",
        params={"address": hex(module_base), "size": 256},
        validators=[
            has_field("success", bool),
            has_field("md5_hash", str),
            # MD5 hash should be 32 hex characters
            lambda r: (len(r.get("md5_hash", "")) == 32, 
                      f"MD5 hash should be 32 chars, got {len(r.get('md5_hash', ''))}"),
        ]
    )
    
    all_tests["generate_signature"] = TestCase(
        "Generate Signature (AOB)", "generate_signature",
        params={"address": hex(entry_point)},
        skip_reason="getUniqueAOB scans all memory (blocking, can take minutes)"
    )
    
    # Run Category 8
    for test in ["get_thread_list", "enum_memory_regions_full", "dissect_structure", 
                 "read_pointer", "read_pointer_chain", "auto_assemble", "get_rtti_classname", 
                 "get_address_info", "checksum_memory", "generate_signature"]:
        all_tests[test].run(client)
    
    # =========================================================================
    # CATEGORY 9: DBVM Hypervisor Tools
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 9: DBVM Hypervisor Tools (Ring -1)")
    print("=" * 70)
    print("Note: These require DBVM/DBK driver to be loaded in CE.")
    
    all_tests["get_physical_address"] = TestCase(
        "Get Physical Address", "get_physical_address",
        params={"address": hex(module_base)},
        validators=[
            has_field("success", bool),
            has_field("virtual_address", str),
            # Physical address should be present if success
            lambda r: (not r.get("success") or "physical_address" in r,
                      "Missing physical_address on success"),
        ]
    )
    
    # Run get_physical_address first to check if DBVM is available
    all_tests["get_physical_address"].run(client)
    
    # Check if DBVM is available based on physical address test
    dbvm_available = (all_tests["get_physical_address"].result == TestResult.PASSED and 
                      all_tests["get_physical_address"].response.get("success"))
    
    if dbvm_available:
        print(f"\n[DBVM detected - running full DBVM watch tests with cleanup]")
        
        # Use a READ address (module base) for safe monitoring
        # Watch for reads is safer than writes for testing
        dbvm_test_addr = hex(module_base)
        
        all_tests["start_dbvm_watch"] = TestCase(
            "Start DBVM Watch (read mode)", "start_dbvm_watch",
            params={"address": dbvm_test_addr, "mode": "r"},
            validators=[
                has_field("success", bool),
                # If success, should have watch_id and status
                lambda r: (not r.get("success") or "watch_id" in r,
                          "Missing watch_id on success"),
                lambda r: (not r.get("success") or r.get("status") == "monitoring",
                          f"Expected status 'monitoring', got '{r.get('status')}'"),
            ]
        )
        
        all_tests["start_dbvm_watch"].run(client)

        all_tests["poll_dbvm_watch"] = TestCase(
            "Poll DBVM Watch (clear=false)", "poll_dbvm_watch",
            params={"address": dbvm_test_addr, "max_results": 1, "clear": False},
            validators=[
                has_field("success", bool),
                has_field("clear_requested", bool),
                field_equals("clear_requested", False),
                has_field("hits", list),
            ]
        )

        all_tests["poll_dbvm_watch"].run(client)
        
        # Always run stop to clean up, whether start succeeded or not
        all_tests["stop_dbvm_watch"] = TestCase(
            "Stop DBVM Watch (cleanup)", "stop_dbvm_watch",
            params={"address": dbvm_test_addr},
            validators=[
                has_field("success", bool),
                # Stop might fail if start failed, that's okay
            ]
        )
        
        all_tests["stop_dbvm_watch"].run(client)
        
    else:
        print(f"\n[DBVM not detected - skipping watch tests]")
        
        all_tests["start_dbvm_watch"] = TestCase(
            "Start DBVM Watch", "start_dbvm_watch",
            params={"address": hex(module_base), "mode": "w"},
            skip_reason="DBVM not loaded (get_physical_address failed)"
        )

        all_tests["poll_dbvm_watch"] = TestCase(
            "Poll DBVM Watch", "poll_dbvm_watch",
            params={"address": hex(module_base), "max_results": 1, "clear": False},
            skip_reason="DBVM not loaded (no active watch)"
        )
        
        all_tests["stop_dbvm_watch"] = TestCase(
            "Stop DBVM Watch", "stop_dbvm_watch",
            params={"address": hex(module_base)},
            skip_reason="DBVM not loaded (no active watch)"
        )
        
        all_tests["start_dbvm_watch"].run(client)
        all_tests["poll_dbvm_watch"].run(client)
        all_tests["stop_dbvm_watch"].run(client)

    client.close()

    # =========================================================================
    # CATEGORY 10: Python MCP Wrapper Helpers
    # =========================================================================
    print("\n" + "=" * 70)
    print("CATEGORY 10: Python MCP Wrapper Helpers")
    print("=" * 70)

    python_tool_skip_reason = None
    try:
        python_tool_client = PythonToolClient()
    except Exception as exc:
        python_tool_client = None
        python_tool_skip_reason = f"Could not import or initialize Python MCP wrapper: {exc}"

    with tempfile.TemporaryDirectory(prefix="mcp_bridge_tests_") as temp_dir:
        temp_path = Path(temp_dir)
        lua_file = temp_path / "临时脚本.lua"
        aa_file = temp_path / "临时补丁.cea"
        lua_file.write_text('return { answer = 42, label = "ok" }\n', encoding="utf-8")
        aa_file.write_text("globalalloc(mcp_test_region_file_v3,4)\n", encoding="utf-8")

        all_tests["evaluate_lua_file"] = TestCase(
            "Evaluate Lua File (UTF-8 + Chinese path)", "evaluate_lua_file",
            params={"file_path": str(lua_file), "structured": True},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("result", dict),
                has_field("serialized", bool),
                field_equals("serialized", True),
                has_field("source_file", str),
                has_field("source_encoding", str),
                has_field("source_length", int),
                lambda r: (Path(r.get("source_file", "")).name == lua_file.name,
                          f"Expected source_file to end with {lua_file.name}, got {r.get('source_file')}"),
                lambda r: (r.get("result", {}).get("answer") == 42,
                          f"Expected result.answer=42, got {r.get('result')}"),
            ],
            skip_reason=python_tool_skip_reason
        )

        all_tests["auto_assemble_file"] = TestCase(
            "Auto Assemble File (UTF-8 + Chinese path)", "auto_assemble_file",
            params={"file_path": str(aa_file)},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("executed", bool),
                field_equals("executed", True),
                has_field("source_file", str),
                has_field("source_encoding", str),
                has_field("source_length", int),
                lambda r: (Path(r.get("source_file", "")).name == aa_file.name,
                          f"Expected source_file to end with {aa_file.name}, got {r.get('source_file')}"),
            ],
            skip_reason=python_tool_skip_reason
        )

        if python_tool_client:
            for test in ["evaluate_lua_file", "auto_assemble_file"]:
                all_tests[test].run(python_tool_client)
        else:
            all_tests["evaluate_lua_file"].run(client)
            all_tests["auto_assemble_file"].run(client)
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for t in all_tests.values() if t.result == TestResult.PASSED)
    failed = sum(1 for t in all_tests.values() if t.result == TestResult.FAILED)
    skipped = sum(1 for t in all_tests.values() if t.result == TestResult.SKIPPED)
    total = len(all_tests)
    
    categories = {
        "Basic & Utility": ["ping", "get_process_info", "evaluate_lua_simple", "evaluate_lua_complex", "evaluate_lua_targetIs64Bit", "evaluate_lua_structured"],
        "Scanning": ["scan_all", "scan_all_default_type", "get_scan_results", "aob_scan", "search_string"],
        "Memory Reading": ["read_memory", "read_integer_byte", "read_integer_word", "read_integer_dword", "read_string"],
        "Disassembly": ["disassemble", "get_instruction_info", "find_function_boundaries", "analyze_function"],
        "References": ["find_references", "find_call_references"],
        "Breakpoints": ["list_breakpoints", "clear_all_breakpoints"],
        "Modules": ["enum_modules", "get_symbol_address", "get_memory_regions"],
        "High-Level": ["get_thread_list", "enum_memory_regions_full", "dissect_structure", "read_pointer", "read_pointer_chain", 
                      "auto_assemble", "get_rtti_classname", "get_address_info", "checksum_memory", "generate_signature"],
        "DBVM": ["get_physical_address", "start_dbvm_watch", "poll_dbvm_watch", "stop_dbvm_watch"],
        "Python Wrapper": ["evaluate_lua_file", "auto_assemble_file"],
    }
    
    for cat_name, tests in categories.items():
        cat_passed = sum(1 for t in tests if all_tests.get(t) and all_tests[t].result == TestResult.PASSED)
        cat_failed = sum(1 for t in tests if all_tests.get(t) and all_tests[t].result == TestResult.FAILED)
        cat_skipped = sum(1 for t in tests if all_tests.get(t) and all_tests[t].result == TestResult.SKIPPED)
        cat_total = len(tests)
        print(f"\n{cat_name}: {cat_passed}/{cat_total - cat_skipped} passed" + (f" ({cat_skipped} skipped)" if cat_skipped else ""))
        for test in tests:
            if test in all_tests:
                t = all_tests[test]
                if t.result == TestResult.PASSED:
                    print(f"  ✓ {test}")
                elif t.result == TestResult.SKIPPED:
                    print(f"  ⊘ {test} (skipped)")
                else:
                    print(f"  ✗ {test}")
                    if t.validation_errors:
                        for err in t.validation_errors[:2]:  # Show first 2 errors
                            print(f"      → {err}")
    
    print(f"\n{'='*70}")
    print(f"TOTAL: {passed} passed, {failed} failed, {skipped} skipped (of {total})")
    print(f"PASS RATE: {100*passed//(total-skipped)}% (excluding skipped)")
    print(f"{'='*70}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! MCP Bridge is 100% functional and validated.")
    elif failed <= 2:
        print(f"\n✅ MOSTLY PASSED. {failed} test(s) failed - review above.")
    else:
        print(f"\n⚠ {failed} test(s) failed. Review errors above.")
    
    client.close()
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
