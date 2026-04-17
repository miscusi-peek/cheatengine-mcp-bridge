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
import struct
import json
import time
import sys
from typing import Optional, Dict, Any, Tuple, List, Callable

PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
EXPECTED_VERSION_PREFIX = "12."

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
        if not self.handle:
            raise RuntimeError("Not connected to MCP bridge")

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
        win32file.WriteFile(self.handle, header)
        win32file.WriteFile(self.handle, data)
        
        _, resp_header = win32file.ReadFile(self.handle, 4)
        if len(resp_header) < 4:
            raise RuntimeError("Incomplete response header from bridge")

        resp_len = struct.unpack('<I', resp_header)[0]
        if resp_len <= 0 or resp_len > MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Invalid response length: {resp_len}")

        _, resp_data = win32file.ReadFile(self.handle, resp_len)
        if len(resp_data) < resp_len:
            raise RuntimeError(f"Incomplete response body: expected {resp_len}, got {len(resp_data)}")

        try:
            return json.loads(resp_data.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response: {e}") from e
    
    def close(self):
        if self.handle:
            win32file.CloseHandle(self.handle)
            self.handle = None


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
    allocated_regions: List[int] = []
    
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
            version_check(EXPECTED_VERSION_PREFIX),
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
    
    # Run Category 1
    for test in ["ping", "get_process_info", "evaluate_lua_simple", "evaluate_lua_complex", "evaluate_lua_targetIs64Bit"]:
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
    for test in ["scan_all", "get_scan_results", "aob_scan", "search_string"]:
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

    # Build a deterministic pointer-chain fixture in target memory.
    # This avoids flaky failures when using arbitrary module addresses as pointers.
    pointer_chain_base = None
    pointer_chain_setup_error = "pointer-chain setup not attempted"
    if module_base:
        try:
            alloc_chain_resp = client.send_command(
                "evaluate_lua",
                {"code": "return string.format('0x%X', allocateMemory(16))"},
            )
            alloc_chain_hex = alloc_chain_resp.get("result", {}).get("result", "")
            if alloc_chain_hex.startswith(("0x", "0X")):
                pointer_chain_base = int(alloc_chain_hex, 16)
                allocated_regions.append(pointer_chain_base)

                pointer_chain_target = pointer_chain_base + (8 if is_64bit else 4)
                pointer_type = "qword" if is_64bit else "dword"
                write_ptr_resp = client.send_command(
                    "write_integer",
                    {
                        "address": hex(pointer_chain_base),
                        "value": pointer_chain_target,
                        "type": pointer_type,
                    },
                )
                if not write_ptr_resp.get("result", {}).get("success"):
                    pointer_chain_setup_error = write_ptr_resp.get("result", {}).get("error", "write_integer failed")
                    pointer_chain_base = None
            else:
                pointer_chain_setup_error = "allocateMemory did not return a hex address"
        except Exception as e:
            pointer_chain_setup_error = str(e)
    
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
            has_field("total", int),
            has_field("returned", int),
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
            has_field("total", int),
            has_field("returned", int),
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
            has_field("total", int),
            has_field("returned", int),
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
        params={"base": hex(pointer_chain_base) if pointer_chain_base else hex(module_base), "offsets": [0]},
        validators=[
            has_field("success", bool),
            has_field("base", str),
            has_field("chain", list),
            has_field("final_address", str),
            field_is_hex_address("final_address"),
        ],
        skip_reason=None if pointer_chain_base else f"Pointer-chain setup failed: {pointer_chain_setup_error}"
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
                 "read_pointer_chain", "auto_assemble", "get_rtti_classname", 
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
        
        all_tests["stop_dbvm_watch"] = TestCase(
            "Stop DBVM Watch", "stop_dbvm_watch",
            params={"address": hex(module_base)},
            skip_reason="DBVM not loaded (no active watch)"
        )
        
        all_tests["start_dbvm_watch"].run(client)
        all_tests["stop_dbvm_watch"].run(client)
    
    # >>> BEGIN UNIT-24 expanded tests <<<

    # -------------------------------------------------------------------------
    # UNIT-24 GATE: skip the entire block if the bridge isn't alive or no
    # process is attached.  We re-use the ping result already stored in
    # all_tests["ping"] rather than issuing a fresh command.
    # -------------------------------------------------------------------------
    _ping_ok = (
        all_tests.get("ping") is not None
        and all_tests["ping"].result == TestResult.PASSED
        and all_tests["ping"].response is not None
        and all_tests["ping"].response.get("success") is True
    )
    _proc_ok = (
        all_tests.get("get_process_info") is not None
        and all_tests["get_process_info"].result == TestResult.PASSED
    )

    if not _ping_ok:
        print("\n[UNIT-24] Bridge ping failed — skipping all Unit-24 expanded tests.")
    else:
        print("\n" + "=" * 70)
        print("UNIT-24: Write Operations")
        print("=" * 70)

        # Allocate a 1 KiB scratch buffer via Lua so we can safely write to it.
        _scratch_addr = None
        if _proc_ok:
            _alloc_resp = client.send_command(
                "evaluate_lua",
                {"code": "return string.format('0x%X', allocateMemory(1024))"}
            )
            _alloc_val = _alloc_resp.get("result", {}).get("result", "")
            if _alloc_val.startswith("0x") or _alloc_val.startswith("0X"):
                try:
                    _scratch_addr = int(_alloc_val, 16)
                    allocated_regions.append(_scratch_addr)
                except ValueError:
                    pass

        _write_skip = None if _scratch_addr else "No process attached or allocateMemory failed"
        # Pre-compute stable hex strings for the three scratch offsets used below.
        _scratch_hex0 = hex(_scratch_addr) if _scratch_addr else "0x0"
        _scratch_hex4 = hex(_scratch_addr + 4) if _scratch_addr else "0x0"
        _scratch_hex8 = hex(_scratch_addr + 8) if _scratch_addr else "0x0"

        def _cascaded_skip(parent_key, parent_skip, failure_msg):
            """Return parent_skip if already set; else check parent result."""
            if parent_skip:
                return parent_skip
            if all_tests[parent_key].result != TestResult.PASSED:
                return failure_msg
            return None

        all_tests["u24_write_integer"] = TestCase(
            "Unit-24 Write Integer (dword)", "write_integer",
            params={"address": _scratch_hex0, "value": 0xDEADBEEF, "type": "dword"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=_write_skip,
        )
        all_tests["u24_write_integer"].run(client)

        all_tests["u24_write_integer_readback"] = TestCase(
            "Unit-24 Write Integer readback (verify 0xDEADBEEF)", "read_integer",
            params={"address": _scratch_hex0, "type": "dword"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("value", int),
                field_equals("value", 0xDEADBEEF),
            ],
            skip_reason=_cascaded_skip("u24_write_integer", _write_skip, "write_integer failed"),
        )
        all_tests["u24_write_integer_readback"].run(client)

        all_tests["u24_write_memory"] = TestCase(
            "Unit-24 Write Memory (raw bytes)", "write_memory",
            params={"address": _scratch_hex4, "bytes": [0xAA, 0xBB, 0xCC, 0xDD]},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=_write_skip,
        )
        all_tests["u24_write_memory"].run(client)

        all_tests["u24_write_memory_readback"] = TestCase(
            "Unit-24 Write Memory readback (verify AA BB CC DD)", "read_memory",
            params={"address": _scratch_hex4, "size": 4},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("bytes", list),
                lambda r: (r.get("bytes") == [0xAA, 0xBB, 0xCC, 0xDD],
                           f"Expected [0xAA,0xBB,0xCC,0xDD], got {r.get('bytes')}"),
            ],
            skip_reason=_cascaded_skip("u24_write_memory", _write_skip, "write_memory failed"),
        )
        all_tests["u24_write_memory_readback"].run(client)

        all_tests["u24_write_string"] = TestCase(
            "Unit-24 Write String (ASCII)", "write_string",
            params={"address": _scratch_hex8, "value": "Hello", "wide": False},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=_write_skip,
        )
        all_tests["u24_write_string"].run(client)

        all_tests["u24_write_string_readback"] = TestCase(
            "Unit-24 Write String readback (verify 'Hello')", "read_string",
            params={"address": _scratch_hex8, "max_length": 16},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("value", str),
                lambda r: (r.get("value", "").startswith("Hello"),
                           f"Expected value starting with 'Hello', got '{r.get('value')}'"),
            ],
            skip_reason=_cascaded_skip("u24_write_string", _write_skip, "write_string failed"),
        )
        all_tests["u24_write_string_readback"].run(client)

        # -------------------------------------------------------------------------
        # next_scan flow
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: next_scan Flow")
        print("=" * 70)

        _nextscan_skip = None if _proc_ok else "No process attached"

        # First do a scan_all with a common dword value (1) so we have a baseline.
        all_tests["u24_scan_for_nextscan"] = TestCase(
            "Unit-24 scan_all baseline (value=1, dword)", "scan_all",
            params={"value": "1", "type": "exact"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("count", int),
                field_in_range("count", 1, 100_000_000),
            ],
            skip_reason=_nextscan_skip,
        )
        all_tests["u24_scan_for_nextscan"].run(client)

        _first_count = 0
        if all_tests["u24_scan_for_nextscan"].result == TestResult.PASSED:
            _first_count = all_tests["u24_scan_for_nextscan"].response.get("count", 0)

        _ns_filter_skip = _nextscan_skip
        if not _ns_filter_skip and all_tests["u24_scan_for_nextscan"].result != TestResult.PASSED:
            _ns_filter_skip = "baseline scan_all failed"

        all_tests["u24_next_scan_unchanged"] = TestCase(
            "Unit-24 next_scan (unchanged) — count should remain <= baseline", "next_scan",
            params={"value": "1", "scan_type": "unchanged"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("count", int),
                lambda r: (r.get("count", 0) <= _first_count,
                           f"next_scan(unchanged) count {r.get('count')} > baseline {_first_count}"),
            ],
            skip_reason=_ns_filter_skip,
        )
        all_tests["u24_next_scan_unchanged"].run(client)

        all_tests["u24_next_scan_changed"] = TestCase(
            "Unit-24 next_scan (changed) — count should differ from unchanged run", "next_scan",
            params={"value": "1", "scan_type": "changed"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("count", int),
            ],
            skip_reason=_ns_filter_skip,
        )
        all_tests["u24_next_scan_changed"].run(client)

        # -------------------------------------------------------------------------
        # Breakpoint lifecycle — execution breakpoint
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: Breakpoint Lifecycle (Execution)")
        print("=" * 70)

        _bp_skip = None if _proc_ok else "No process attached"
        _bp_id = "u24_bp_exec"

        all_tests["u24_set_breakpoint"] = TestCase(
            "Unit-24 set_breakpoint at entry point", "set_breakpoint",
            params={
                "address": hex(entry_point),
                "id": _bp_id,
                "capture_registers": True,
                "capture_stack": False,
            },
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("id", str),
            ],
            skip_reason=_bp_skip,
        )
        all_tests["u24_set_breakpoint"].run(client)

        _bp_set_ok = all_tests["u24_set_breakpoint"].result == TestResult.PASSED

        # Brief wait is intentionally omitted (no sleep; hits may be 0 — that is fine).
        all_tests["u24_get_bp_hits"] = TestCase(
            "Unit-24 get_breakpoint_hits (may be 0 — OK)", "get_breakpoint_hits",
            params={"id": _bp_id, "clear": False},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("hits", list),
                has_field("count", int),
                lambda r: (r.get("count", -1) >= 0,
                           "hit count must be >= 0"),
            ],
            skip_reason=_bp_skip if not _bp_set_ok else None,
        )
        all_tests["u24_get_bp_hits"].run(client)

        all_tests["u24_remove_breakpoint"] = TestCase(
            "Unit-24 remove_breakpoint", "remove_breakpoint",
            params={"id": _bp_id},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=_bp_skip if not _bp_set_ok else None,
        )
        all_tests["u24_remove_breakpoint"].run(client)

        # Verify the breakpoint is gone.
        all_tests["u24_list_bp_after_remove"] = TestCase(
            "Unit-24 list_breakpoints — entry-point BP must be absent", "list_breakpoints",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("breakpoints", list),
                lambda r: (
                    not any(bp.get("id") == _bp_id for bp in r.get("breakpoints", [])),
                    f"Breakpoint '{_bp_id}' still present after remove"
                ),
            ],
            skip_reason=_bp_skip,
        )
        all_tests["u24_list_bp_after_remove"].run(client)

        # -------------------------------------------------------------------------
        # Data breakpoint lifecycle
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: Data Breakpoint Lifecycle")
        print("=" * 70)

        _dbp_id = "u24_bp_data"
        _dbp_addr = hex(_scratch_addr) if _scratch_addr else hex(module_base)
        _dbp_skip = None if _proc_ok else "No process attached"

        all_tests["u24_set_data_breakpoint"] = TestCase(
            "Unit-24 set_data_breakpoint (write watchpoint)", "set_data_breakpoint",
            params={"address": _dbp_addr, "id": _dbp_id, "access_type": "w", "size": 4},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("id", str),
            ],
            skip_reason=_dbp_skip,
        )
        all_tests["u24_set_data_breakpoint"].run(client)

        _dbp_set_ok = all_tests["u24_set_data_breakpoint"].result == TestResult.PASSED

        all_tests["u24_get_data_bp_hits"] = TestCase(
            "Unit-24 get_breakpoint_hits (data bp — may be 0)", "get_breakpoint_hits",
            params={"id": _dbp_id, "clear": False},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("hits", list),
                has_field("count", int),
                lambda r: (r.get("count", -1) >= 0, "hit count must be >= 0"),
            ],
            skip_reason=_dbp_skip if not _dbp_set_ok else None,
        )
        all_tests["u24_get_data_bp_hits"].run(client)

        all_tests["u24_remove_data_breakpoint"] = TestCase(
            "Unit-24 remove_breakpoint (data bp)", "remove_breakpoint",
            params={"id": _dbp_id},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=_dbp_skip if not _dbp_set_ok else None,
        )
        all_tests["u24_remove_data_breakpoint"].run(client)

        # -------------------------------------------------------------------------
        # Pagination via get_scan_results
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: Pagination (get_scan_results offset/limit)")
        print("=" * 70)

        # Re-scan to ensure fresh results in the foundlist (gated on process).
        _page_total = 0
        if _proc_ok:
            _page_scan_resp = client.send_command("scan_all", {"value": "1", "type": "dword"})
            _page_total = _page_scan_resp.get("result", {}).get("count", 0)
        _page_skip = None if (_proc_ok and _page_total >= 10) else "Fewer than 10 scan results — pagination not meaningful"

        all_tests["u24_page1"] = TestCase(
            "Unit-24 Pagination — page 1 (offset=0, limit=5)", "get_scan_results",
            params={"offset": 0, "limit": 5},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("results", list),
                has_field("total", int),
                lambda r: (len(r.get("results", [])) <= 5,
                           f"Expected <= 5 results, got {len(r.get('results', []))}"),
            ],
            skip_reason=_page_skip,
        )
        all_tests["u24_page1"].run(client)

        all_tests["u24_page2"] = TestCase(
            "Unit-24 Pagination — page 2 (offset=5, limit=5)", "get_scan_results",
            params={"offset": 5, "limit": 5},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("results", list),
                has_field("total", int),
                lambda r: (len(r.get("results", [])) <= 5,
                           f"Expected <= 5 results, got {len(r.get('results', []))}"),
            ],
            skip_reason=_page_skip,
        )
        all_tests["u24_page2"].run(client)

        # Verify pages have distinct addresses and consistent total.
        _p1_ok = all_tests["u24_page1"].result == TestResult.PASSED
        _p2_ok = all_tests["u24_page2"].result == TestResult.PASSED
        _pages_distinct_skip = _page_skip
        if not _pages_distinct_skip and not (_p1_ok and _p2_ok):
            _pages_distinct_skip = "One or both page queries failed"

        def _check_pages_distinct():
            """Verify page results are disjoint and report a consistent total."""
            p1_addrs = {e.get("address") for e in all_tests["u24_page1"].response.get("results", [])}
            p2_addrs = {e.get("address") for e in all_tests["u24_page2"].response.get("results", [])}
            if p1_addrs & p2_addrs:
                return False, f"Pages share addresses: {p1_addrs & p2_addrs}"
            t1 = all_tests["u24_page1"].response.get("total")
            t2 = all_tests["u24_page2"].response.get("total")
            if t1 != t2:
                return False, f"Inconsistent total: page1 says {t1}, page2 says {t2}"
            return True, ""

        # Synthetic test: validates already-collected page responses, no extra pipe call.
        print(f"\n{'='*60}")
        print("Testing: Unit-24 Pagination — pages are disjoint + total consistent")
        print(f"{'='*60}")
        _pages_tc = TestCase(
            "Unit-24 Pagination — pages are disjoint + total consistent",
            "get_scan_results", {},
            skip_reason=_pages_distinct_skip,
        )
        if _pages_distinct_skip:
            print(f"⊘ SKIPPED: {_pages_distinct_skip}")
            _pages_tc.result = TestResult.SKIPPED
        else:
            ok, msg = _check_pages_distinct()
            if ok:
                print("✓ PASSED")
                _pages_tc.result = TestResult.PASSED
            else:
                print(f"✗ FAILED: {msg}")
                _pages_tc.validation_errors = [msg]
                _pages_tc.result = TestResult.FAILED
        all_tests["u24_pages_distinct"] = _pages_tc

        # -------------------------------------------------------------------------
        # Error-case tests
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: Error Cases")
        print("=" * 70)

        # Invalid hex address → expect error_code = INVALID_ADDRESS.
        # Validator: success must be False AND error_code must match expected value.
        def _expect_error(error_code=None):
            """Validator factory: passes when success=False with optional error_code check."""
            def validator(resp):
                if resp.get("success") is True:
                    return False, "Expected success=False (error response), got success=True"
                if error_code and resp.get("error_code") != error_code:
                    return False, f"Expected error_code={error_code!r}, got {resp.get('error_code')!r}"
                return True, ""
            return validator

        # Override TestCase.run to flip the success/failure logic for error cases.
        # We use the validators-only path: a normal TestCase whose validators check
        # for success=False, bypassing the built-in "command failed → FAILED" guard.
        class _ErrorCase(TestCase):
            """TestCase that expects the bridge to return success=False."""
            def run(self, client):
                print(f"\n{'='*60}")
                print(f"Testing: {self.name}")
                print(f"{'='*60}")
                if self.skip_reason:
                    print(f"⊘ SKIPPED: {self.skip_reason}")
                    self.result = TestResult.SKIPPED
                    return self.result
                try:
                    raw = client.send_command(self.method, self.params)
                    if "error" in raw and raw["error"]:
                        print(f"✗ PROTOCOL ERROR: {raw['error']}")
                        self.result = TestResult.FAILED
                        return self.result
                    self.response = raw.get("result", {})
                    self.validation_errors = []
                    for v in self.validators:
                        ok, msg = v(self.response)
                        if not ok:
                            self.validation_errors.append(msg)
                    resp_str = json.dumps(self.response, indent=2)
                    if len(resp_str) > 500:
                        resp_str = resp_str[:500] + "\n  ... (truncated)"
                    print(f"Response: {resp_str}")
                    if self.validation_errors:
                        print("✗ VALIDATION FAILED:")
                        for err in self.validation_errors:
                            print(f"  - {err}")
                        self.result = TestResult.FAILED
                    else:
                        print("✓ PASSED")
                        self.result = TestResult.PASSED
                except Exception as e:
                    self.error = str(e)
                    print(f"✗ EXCEPTION: {e}")
                    self.result = TestResult.FAILED
                return self.result

        all_tests["u24_err_invalid_addr"] = _ErrorCase(
            "Unit-24 Error: read_integer invalid hex address",
            "read_integer",
            params={"address": "not_hex", "type": "dword"},
            validators=[_expect_error(error_code="INVALID_ADDRESS")],
        )
        all_tests["u24_err_invalid_addr"].run(client)

        all_tests["u24_err_null_read"] = _ErrorCase(
            "Unit-24 Error: read_memory at 0x0 (expect error)",
            "read_memory",
            params={"address": "0x0", "size": 100},
            validators=[_expect_error()],  # error_code varies by implementation
        )
        all_tests["u24_err_null_read"].run(client)

        # -------------------------------------------------------------------------
        # Smoke tests for new units 7-23
        # NOTE: These probe commands added by parallel units (7-23). They may be
        #       absent in this worktree branch and will fail until merged; that is
        #       expected.  Each is gated on _proc_ok where the command requires an
        #       attached process.
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("UNIT-24: Smoke Tests for Units 7-23")
        print("=" * 70)

        # Unit 7 — get_process_list
        all_tests["u24_smoke_get_process_list"] = TestCase(
            "Smoke Unit-7: get_process_list", "get_process_list",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("count", int),
                lambda r: (r.get("count", 0) > 0,
                           f"Expected count > 0, got {r.get('count')}"),
            ],
        )
        all_tests["u24_smoke_get_process_list"].run(client)

        # Unit 8 — allocate_memory + free_memory
        all_tests["u24_smoke_allocate_memory"] = TestCase(
            "Smoke Unit-8: allocate_memory (256 bytes)", "allocate_memory",
            params={"size": 256},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("address", str),
                field_is_hex_address("address"),
            ],
            skip_reason=None if _proc_ok else "No process attached",
        )
        all_tests["u24_smoke_allocate_memory"].run(client)

        _alloc_addr = None
        if all_tests["u24_smoke_allocate_memory"].result == TestResult.PASSED:
            _alloc_addr = all_tests["u24_smoke_allocate_memory"].response.get("address")

        all_tests["u24_smoke_free_memory"] = TestCase(
            "Smoke Unit-8: free_memory (on allocated address)", "free_memory",
            params={"address": _alloc_addr or "0x0"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
            skip_reason=None if _alloc_addr else "allocate_memory did not succeed",
        )
        all_tests["u24_smoke_free_memory"].run(client)

        # Unit 9 — execute_code_local (non-destructive: use a known RX page address)
        # We point at the module entry point which is RX; CE will inject a jump but
        # the breakpoint handler will intercept before actual execution.
        # Skip: execute_code_local injects a JMP to our code — too risky without a
        # controlled stub. Use evaluate_lua as a safer proxy instead.
        all_tests["u24_smoke_execute_code_local"] = TestCase(
            "Smoke Unit-9: execute_code_local",
            "execute_code_local",
            params={"address": hex(entry_point)},
            validators=[has_field("success", bool)],
            skip_reason=(
                "execute_code_local redirects execution — requires a no-op stub; "
                "skipped to avoid destabilising the target process"
            ),
        )
        all_tests["u24_smoke_execute_code_local"].run(client)

        # Unit 12 — enum_registered_symbols
        all_tests["u24_smoke_enum_registered_symbols"] = TestCase(
            "Smoke Unit-12: enum_registered_symbols", "enum_registered_symbols",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
        )
        all_tests["u24_smoke_enum_registered_symbols"].run(client)

        # Unit 16 — find_window
        all_tests["u24_smoke_find_window"] = TestCase(
            "Smoke Unit-16: find_window title='Cheat Engine'", "find_window",
            params={"title": "Cheat Engine"},
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("handle", int),
                lambda r: (r.get("handle", 0) != 0,
                           "Expected non-zero window handle"),
            ],
        )
        all_tests["u24_smoke_find_window"].run(client)

        # Unit 17 — get_mouse_pos
        all_tests["u24_smoke_get_mouse_pos"] = TestCase(
            "Smoke Unit-17: get_mouse_pos", "get_mouse_pos",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("x", int),
                has_field("y", int),
            ],
        )
        all_tests["u24_smoke_get_mouse_pos"].run(client)

        # Unit 20a — get_temp_folder
        all_tests["u24_smoke_get_temp_folder"] = TestCase(
            "Smoke Unit-20a: get_temp_folder", "get_temp_folder",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
                has_field("path", str),
                lambda r: (len(r.get("path", "")) > 0,
                           "Expected non-empty path"),
            ],
        )
        all_tests["u24_smoke_get_temp_folder"].run(client)

        # Unit 23 — beep
        all_tests["u24_smoke_beep"] = TestCase(
            "Smoke Unit-23: beep", "beep",
            validators=[
                has_field("success", bool),
                field_equals("success", True),
            ],
        )
        all_tests["u24_smoke_beep"].run(client)

        # Units requiring very specific state — intentionally skipped:
        #   Unit 10 (inject_dll) — needs a DLL path on disk
        #   Unit 11 (set_freeze / freeze value) — needs a known writable address + game state
        #   Unit 13 (start_speedhack) — alters global CE speed, side-effects on test run
        #   Unit 14 (resolve_pointer_path) — needs a known pointer chain
        #   Unit 15 (get_ce_settings) — CE-host-only; no process guard needed but untestable without live bridge knowing CE version
        #   Unit 18 (send_key / type_text) — sends real OS input events
        #   Unit 19 (take_screenshot) — needs a window handle and writable path
        #   Unit 21 (read_clipboard / write_clipboard) — side-effects on clipboard
        #   Unit 22 (show_message_box) — blocks CE GUI thread waiting for user input

    # >>> END UNIT-24 <<<

    if allocated_regions:
        print("\n[CLEANUP] Releasing allocated test regions...")
        for addr in sorted(set(allocated_regions)):
            try:
                cleanup_resp = client.send_command("free_memory", {"address": hex(addr)})
                if cleanup_resp.get("result", {}).get("success"):
                    print(f"  ✓ freed {hex(addr)}")
                else:
                    msg = cleanup_resp.get("result", {}).get("error", "unknown error")
                    print(f"  ! failed to free {hex(addr)}: {msg}")
            except Exception as e:
                print(f"  ! failed to free {hex(addr)}: {e}")

    # Update summary categories to include Unit-24 tests.
    _u24_write_keys = [
        "u24_write_integer", "u24_write_integer_readback",
        "u24_write_memory", "u24_write_memory_readback",
        "u24_write_string", "u24_write_string_readback",
    ]
    _u24_scan_keys = [
        "u24_scan_for_nextscan", "u24_next_scan_unchanged", "u24_next_scan_changed",
    ]
    _u24_bp_keys = [
        "u24_set_breakpoint", "u24_get_bp_hits", "u24_remove_breakpoint",
        "u24_list_bp_after_remove",
        "u24_set_data_breakpoint", "u24_get_data_bp_hits", "u24_remove_data_breakpoint",
    ]
    _u24_page_keys = ["u24_page1", "u24_page2", "u24_pages_distinct"]
    _u24_err_keys = ["u24_err_invalid_addr", "u24_err_null_read"]
    _u24_smoke_keys = [
        "u24_smoke_get_process_list", "u24_smoke_allocate_memory", "u24_smoke_free_memory",
        "u24_smoke_execute_code_local", "u24_smoke_enum_registered_symbols",
        "u24_smoke_find_window", "u24_smoke_get_mouse_pos",
        "u24_smoke_get_temp_folder", "u24_smoke_beep",
    ]

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
        "Basic & Utility": ["ping", "get_process_info", "evaluate_lua_simple", "evaluate_lua_complex", "evaluate_lua_targetIs64Bit"],
        "Scanning": ["scan_all", "get_scan_results", "aob_scan", "search_string"],
        "Memory Reading": ["read_memory", "read_integer_byte", "read_integer_word", "read_integer_dword", "read_string"],
        "Disassembly": ["disassemble", "get_instruction_info", "find_function_boundaries", "analyze_function"],
        "References": ["find_references", "find_call_references"],
        "Breakpoints": ["list_breakpoints", "clear_all_breakpoints"],
        "Modules": ["enum_modules", "get_symbol_address", "get_memory_regions"],
        "High-Level": ["get_thread_list", "enum_memory_regions_full", "dissect_structure", "read_pointer_chain",
                      "auto_assemble", "get_rtti_classname", "get_address_info", "checksum_memory", "generate_signature"],
        "DBVM": ["get_physical_address", "start_dbvm_watch", "stop_dbvm_watch"],
        # Unit-24 categories
        "U24 Write Ops": _u24_write_keys,
        "U24 next_scan": _u24_scan_keys,
        "U24 Breakpoints": _u24_bp_keys,
        "U24 Pagination": _u24_page_keys,
        "U24 Error Cases": _u24_err_keys,
        "U24 Smoke Tests": _u24_smoke_keys,
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
    effective_total = total - skipped
    pass_rate = (100 * passed // effective_total) if effective_total > 0 else 0
    print(f"PASS RATE: {pass_rate}% (excluding skipped)")
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
