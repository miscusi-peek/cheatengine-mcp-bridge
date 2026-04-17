# MCP Bridge Command Reference (v12.0.0)

> **For AI Agents**: This document describes all available commands in the Cheat Engine MCP Bridge. Use these commands to perform memory analysis, reverse engineering, and dynamic tracing on target processes.
>
> **Architecture Support**: All commands automatically adapt to 32-bit or 64-bit targets. Pointer operations use `readPointer()` for automatic size handling.
>
> **Version**: This reference covers the full v12 tool surface (~180 tools) after all 26 implementation units land.

---

## Table of Contents

1. [Basic & Utility](#1-basic--utility)
2. [Process & Modules](#2-process--modules)
3. [Memory Read](#3-memory-read)
4. [Memory Write](#4-memory-write)
5. [Pattern Scanning](#5-pattern-scanning)
6. [Disassembly & Analysis](#6-disassembly--analysis)
7. [Breakpoints (Hardware Debug Registers)](#7-breakpoints-hardware-debug-registers)
8. [Memory Regions](#8-memory-regions)
9. [Lua Evaluation & Scripting](#9-lua-evaluation--scripting)
10. [High-Level Analysis Tools](#10-high-level-analysis-tools)
11. [DBVM Hypervisor Tools (Ring -1)](#11-dbvm-hypervisor-tools-ring--1)
12. [Process Lifecycle (Unit 7)](#12-process-lifecycle-unit-7)
13. [Memory Allocation (Unit 8)](#13-memory-allocation-unit-8)
14. [Code Injection (Unit 9)](#14-code-injection-unit-9)
15. [Debugger Control (Unit 10)](#15-debugger-control-unit-10)
16. [Context & Thread Breakpoints (Unit 11)](#16-context--thread-breakpoints-unit-11)
17. [Symbol Management (Unit 12)](#17-symbol-management-unit-12)
18. [Assembly & Code Generation (Unit 13)](#18-assembly--code-generation-unit-13)
19. [Advanced Memory Operations (Unit 14)](#19-advanced-memory-operations-unit-14)
20. [Advanced Scanning (Unit 15)](#20-advanced-scanning-unit-15)
21. [Window & GUI (Unit 16)](#21-window--gui-unit-16)
22. [Input & Display (Unit 17)](#22-input--display-unit-17)
23. [Cheat Tables (Unit 18)](#23-cheat-tables-unit-18)
24. [Structures (Unit 19)](#24-structures-unit-19)
25. [File, Clipboard & Shell (Units 20a-20b)](#25-file-clipboard--shell-units-20a-20b)
26. [Kernel & DBVM Extended (Unit 21)](#26-kernel--dbvm-extended-unit-21)
27. [Threading & Synchronization (Unit 22)](#27-threading--synchronization-unit-22)
28. [Debug Output & Multimedia (Unit 23)](#28-debug-output--multimedia-unit-23)
29. [Pagination Convention](#29-pagination-convention)
30. [Environment Variables](#30-environment-variables)
31. [Error Codes & Handling](#31-error-codes--handling)

---

## 1. Basic & Utility

### `ping`

**Purpose:** Verify the MCP bridge is running and responsive.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `version` (str): Bridge version string.
- `timestamp` (int): Unix timestamp.
- `message` (str): Status message.

**Example request:**
```json
{"method": "ping", "params": {}}
```

**Example response:**
```json
{"success": true, "version": "12.0.0", "timestamp": 1733540000, "message": "CE MCP Bridge alive"}
```

**Usage**: Call this first to verify connectivity before performing operations.

---

## 2. Process & Modules

### `get_process_info`

**Purpose:** Get information about the currently attached process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `process_name` (str): Name of the attached process.
- `process_id` (int): PID.
- `main_module_address` (str): Hex address of main module.
- `module_count` (int): Number of loaded modules.
- `modules` (array): List of `{name, address, size, source}` objects.

**Example request:**
```json
{"method": "get_process_info", "params": {}}
```

**Example response:**
```json
{"success": true, "process_name": "game.exe", "process_id": 12345, "main_module_address": "0x00400000", "module_count": 5, "modules": [{"name": "game.exe", "address": "0x00400000", "size": 1234567, "source": "enumModules"}]}
```

**Note**: If anti-cheat blocks `enumModules()`, the bridge uses AOB scanning with PE Export Directory name reading as fallback.

---

### `enum_modules`

**Purpose:** List all modules loaded in the target process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `modules` (array): List of `{name, address, size}` objects.

**Example request:**
```json
{"method": "enum_modules", "params": {}}
```

**Example response:**
```json
{"success": true, "count": 15, "modules": [{"name": "kernel32.dll", "address": "0x76000000", "size": 1234567}]}
```

---

### `get_thread_list`

**Purpose:** List all threads in the target process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `threads` (array): Thread ID strings.

**Example request:**
```json
{"method": "get_thread_list", "params": {}}
```

**Example response:**
```json
{"success": true, "count": 8, "threads": ["1234", "5678", "9012"]}
```

---

### `get_symbol_address`

**Purpose:** Resolve a symbol name to its memory address.

**Parameters:**
- `symbol` (str, required): Symbol name (e.g., `"kernel32.GetProcAddress"`, `"game.exe+0x1000"`).

**Returns:** JSON with:
- `success` (bool)
- `symbol` (str): Input symbol.
- `address` (str): Resolved hex address.

**Example request:**
```json
{"method": "get_symbol_address", "params": {"symbol": "kernel32.GetProcAddress"}}
```

**Example response:**
```json
{"success": true, "symbol": "kernel32.GetProcAddress", "address": "0x76001234"}
```

---

### `get_address_info`

**Purpose:** Convert a raw address to a symbolic name (reverse of `get_symbol_address`).

**Parameters:**
- `address` (str, required): Memory address.
- `include_modules` (bool, default=true): Include module name in result.
- `include_symbols` (bool, default=true): Include symbol name in result.
- `include_sections` (bool, default=false): Include PE section name.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Input address.
- `symbolic_name` (str): Human-readable name (e.g., `"game.exe+1000"`).
- `is_in_module` (bool)

**Example request:**
```json
{"method": "get_address_info", "params": {"address": "0x00401000"}}
```

**Example response:**
```json
{"success": true, "address": "0x00401000", "symbolic_name": "game.exe+1000", "is_in_module": true}
```

---

### `get_rtti_classname`

**Purpose:** Get C++ class name from RTTI information at an object's vtable pointer.

**Parameters:**
- `address` (str, required): Object address (pointer to vtable).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `class_name` (str): Demangled C++ class name.
- `found` (bool)

**Example request:**
```json
{"method": "get_rtti_classname", "params": {"address": "0x12345678"}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "class_name": "CPlayer", "found": true}
```

---

## 3. Memory Read

### `read_memory`

**Purpose:** Read raw bytes from memory.

**Parameters:**
- `address` (str, required): Memory address to read.
- `size` (int, default=256): Number of bytes to read (max 65536).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `length` (int): Bytes actually read.
- `hex` (str): Space-separated hex string.
- `bytes` (array): Array of byte integers.

**Example request:**
```json
{"method": "read_memory", "params": {"address": "0x00400000", "size": 8}}
```

**Example response:**
```json
{"success": true, "address": "0x00400000", "length": 8, "hex": "4D 5A 90 00 03 00 00 00", "bytes": [77, 90, 144, 0, 3, 0, 0, 0]}
```

---

### `read_integer`

**Purpose:** Read an integer or float value from memory.

**Parameters:**
- `address` (str, required): Memory address.
- `type` (str, default=`"dword"`): One of `"byte"`, `"word"`, `"dword"`, `"qword"`, `"float"`, `"double"`.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `value` (int|float): Numeric value.
- `hex` (str): Hex representation.

**Example request:**
```json
{"method": "read_integer", "params": {"address": "0x00400000", "type": "dword"}}
```

**Example response:**
```json
{"success": true, "address": "0x00400000", "value": 905969664, "hex": "0x36005A4D"}
```

---

### `read_string`

**Purpose:** Read a null-terminated string from memory.

**Parameters:**
- `address` (str, required): Memory address.
- `max_length` (int, default=256): Maximum characters to read.
- `wide` (bool, default=false): Read as UTF-16 (widechar).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `value` (str): String content.
- `wide` (bool)

**Example request:**
```json
{"method": "read_string", "params": {"address": "0x00400000", "max_length": 64, "wide": false}}
```

**Example response:**
```json
{"success": true, "address": "0x00400000", "value": "Hello World", "wide": false}
```

---

### `read_pointer`

**Purpose:** Read a pointer value (4 bytes on 32-bit, 8 bytes on 64-bit). Optionally follows an offset chain.

**Parameters:**
- `address` (str, required): Memory address.
- `offsets` (array, optional): If provided, follows this offset chain before returning.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `pointer` (str): Hex value of pointer read.
- `arch` (str): `"x86"` or `"x64"`.

**Example request:**
```json
{"method": "read_pointer", "params": {"address": "0x00400000"}}
```

**Example response:**
```json
{"success": true, "address": "0x00400000", "pointer": "0x12345678", "arch": "x64"}
```

**Note**: Uses CE's `readPointer()` which automatically reads 4 or 8 bytes based on target architecture.

---

### `read_pointer_chain`

**Purpose:** Follow a chain of pointers to resolve a dynamic address.

**Parameters:**
- `base` (str, required): Base address or symbol name.
- `offsets` (array, required): Array of integer offsets to apply at each dereference step.

**Returns:** JSON with:
- `success` (bool)
- `base` (str)
- `offsets` (array)
- `final_address` (str): Address reached after all dereferences.
- `final_value` (int): Value read at final address.
- `arch` (str)
- `chain` (array): Step-by-step dereference log `{step, address, read_value, offset_applied?}`.

**Example request:**
```json
{"method": "read_pointer_chain", "params": {"base": "0x00400000", "offsets": [60, 0, 24]}}
```

**Example response:**
```json
{"success": true, "base": "0x00400000", "offsets": [60, 0, 24], "final_address": "0x12345678", "final_value": 100, "arch": "x64", "chain": [{"step": 0, "address": "0x00400000", "read_value": "0x00500000"}, {"step": 1, "address": "0x00500000", "offset_applied": 60, "read_value": "0x00600000"}, {"step": 2, "address": "0x00600018", "offset_applied": 24, "read_value": "0x12345678"}]}
```

---

### `checksum_memory`

**Purpose:** Calculate MD5 hash of a memory region to detect modifications.

**Parameters:**
- `address` (str, required): Start address.
- `size` (int, required): Bytes to hash.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `size` (int)
- `md5_hash` (str): Hex MD5 digest.

**Example request:**
```json
{"method": "checksum_memory", "params": {"address": "0x00400000", "size": 256}}
```

**Example response:**
```json
{"success": true, "address": "0x00400000", "size": 256, "md5_hash": "d41d8cd98f00b204e9800998ecf8427e"}
```

---

## 4. Memory Write

> **Caution**: Writing to memory can crash the target process. Ensure the address is writable and the data is valid.

### `write_integer`

**Purpose:** Write a numeric value to memory.

**Parameters:**
- `address` (str, required): Memory address to write to.
- `value` (int|float, required): Value to write.
- `type` (str, default=`"dword"`): One of `"byte"`, `"word"`, `"dword"`, `"qword"`, `"float"`, `"double"`.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `value` (int|float)
- `type` (str)

**Example request:**
```json
{"method": "write_integer", "params": {"address": "0x12345678", "value": 100, "type": "dword"}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "value": 100, "type": "dword"}
```

---

### `write_memory`

**Purpose:** Write raw bytes to memory.

**Parameters:**
- `address` (str, required): Memory address to write to.
- `bytes` (array, required): Array of byte values (0–255).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `bytes_written` (int)

**Example request:**
```json
{"method": "write_memory", "params": {"address": "0x12345678", "bytes": [144, 144, 144]}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "bytes_written": 3}
```

---

### `write_string`

**Purpose:** Write a string to memory.

**Parameters:**
- `address` (str, required): Memory address to write to.
- `value` (str, required): String to write.
- `wide` (bool, default=false): Write as UTF-16 (widechar).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `length` (int): Bytes written.
- `wide` (bool)

**Example request:**
```json
{"method": "write_string", "params": {"address": "0x12345678", "value": "Hello", "wide": false}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "length": 6, "wide": false}
```

---

## 5. Pattern Scanning

### `scan_all`

**Purpose:** Perform a value-based memory scan (like CE's memory scanner).

**Parameters:**
- `value` (str, required): Value to search for.
- `type` (str, default=`"exact"`): Scan type — `"exact"`, `"string"`, `"array"`.
- `protection` (str, default=`"+W-C"`): Memory protection filter. `+W-C` = writable, not copy-on-write.

**Returns:** JSON with:
- `success` (bool)
- `message` (str): Status message.
- `value` (str): Scanned value.
- `scan_type` (str)

**Example request:**
```json
{"method": "scan_all", "params": {"value": "100", "type": "exact"}}
```

**Example response:**
```json
{"success": true, "message": "Scan started", "value": "100", "scan_type": "exact"}
```

---

### `get_scan_results`

**Purpose:** Retrieve results from the last `scan_all` operation.

**Parameters:**
- `max` (int, default=100): Maximum results to return.

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `addresses` (array): Hex address strings.

**Example request:**
```json
{"method": "get_scan_results", "params": {"max": 50}}
```

**Example response:**
```json
{"success": true, "count": 3, "addresses": ["0x12345678", "0x23456789", "0x34567890"]}
```

---

### `next_scan`

**Purpose:** Filter results from a previous scan, narrowing down candidates.

**Parameters:**
- `value` (str, optional): New value to scan for. Required when `scan_type` is `"exact"`, `"bigger"`, or `"smaller"`; omit for `"increased"`, `"decreased"`, `"changed"`, `"unchanged"`.
- `scan_type` (str, default=`"exact"`): One of `"exact"`, `"increased"`, `"decreased"`, `"changed"`, `"unchanged"`, `"bigger"`, `"smaller"`.

**Returns:** JSON with:
- `success` (bool)
- `count` (int): Number of remaining results.

**Example request:**
```json
{"method": "next_scan", "params": {"value": "95", "scan_type": "exact"}}
```

**Example response:**
```json
{"success": true, "count": 3}
```

**Workflow:**
```
1. scan_all(value="100")                        → 50000 results
2. next_scan(scan_type="decreased")             → 500 results
3. next_scan(value="95", scan_type="exact")     → 3 results
4. get_scan_results()                           → ["0x12345678", ...]
```

---

### `aob_scan`

**Purpose:** Scan memory for a byte pattern (Array of Bytes scan).

**Parameters:**
- `pattern` (str, required): AOB pattern with wildcards (e.g., `"4D 5A ?? 00"`).
- `protection` (str, default=`"+X"`): Memory protection filter.
- `limit` (int, default=100): Maximum results to return.

**Returns:** JSON with:
- `success` (bool)
- `pattern` (str)
- `count` (int)
- `addresses` (array): Hex address strings.

**Example request:**
```json
{"method": "aob_scan", "params": {"pattern": "48 89 5C 24 ?? 48 89 74 24", "limit": 10}}
```

**Example response:**
```json
{"success": true, "pattern": "48 89 5C 24 ?? 48 89 74 24", "count": 2, "addresses": ["0x00401000", "0x10001234"]}
```

**Tip**: Use `??` as wildcard for unknown bytes.

---

### `search_string`

**Purpose:** Search for a text string in memory.

**Parameters:**
- `string` (str, required): String to search for.
- `wide` (bool, default=false): Search as UTF-16.
- `limit` (int, default=100): Maximum results.

**Returns:** JSON with:
- `success` (bool)
- `value` (str)
- `count` (int)
- `addresses` (array)

**Example request:**
```json
{"method": "search_string", "params": {"string": "Player", "wide": false, "limit": 20}}
```

**Example response:**
```json
{"success": true, "value": "Player", "count": 3, "addresses": ["0x12345678", "0x23456789", "0x34567890"]}
```

---

### `generate_signature`

**Purpose:** Generate a unique AOB signature for an address that can be used to find it after updates.

**Parameters:**
- `address` (str, required): Target address.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `signature` (str): AOB pattern string.
- `offset_from_start` (int): Add this offset to scan result to reach target.
- `byte_count` (int)
- `usage_hint` (str)

**Example request:**
```json
{"method": "generate_signature", "params": {"address": "0x00401000"}}
```

**Example response:**
```json
{"success": true, "address": "0x00401000", "signature": "55 8B EC 83 EC ?? 53 56", "offset_from_start": 0, "byte_count": 8, "usage_hint": "aob_scan('55 8B EC 83 EC ?? 53 56') then add offset 0"}
```

> **Warning**: `generate_signature` calls `getUniqueAOB()` which scans ALL memory. It can take several minutes and will block the pipe. Use only on specific code addresses.

---

## 6. Disassembly & Analysis

### `disassemble`

**Purpose:** Disassemble instructions starting from an address.

**Parameters:**
- `address` (str, required): Starting address.
- `count` (int, default=20): Number of instructions to disassemble.

**Returns:** JSON with:
- `success` (bool)
- `start_address` (str)
- `instruction_count` (int)
- `instructions` (array): List of `{address, bytes, instruction, size}`.

**Example request:**
```json
{"method": "disassemble", "params": {"address": "0x00400000", "count": 5}}
```

**Example response:**
```json
{"success": true, "start_address": "0x00400000", "instruction_count": 5, "instructions": [{"address": "0x00400000", "bytes": "55", "instruction": "push ebp", "size": 1}, {"address": "0x00400001", "bytes": "8B EC", "instruction": "mov ebp,esp", "size": 2}]}
```

---

### `get_instruction_info`

**Purpose:** Get detailed information about a single instruction at an address.

**Parameters:**
- `address` (str, required): Instruction address.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `instruction` (str): Disassembled text.
- `size` (int): Byte length.
- `bytes` (str): Hex bytes.
- `is_call` (bool)
- `is_jump` (bool)
- `is_ret` (bool)

**Example request:**
```json
{"method": "get_instruction_info", "params": {"address": "0x00401050"}}
```

**Example response:**
```json
{"success": true, "address": "0x00401050", "instruction": "call 0x00405000", "size": 5, "bytes": "E8 AB CD 03 00", "is_call": true, "is_jump": false, "is_ret": false}
```

---

### `find_function_boundaries`

**Purpose:** Locate the start and end of a function containing the given address.

**Parameters:**
- `address` (str, required): Address within the function.
- `max_search` (int, default=4096): Maximum bytes to search backward/forward.

**Returns:** JSON with:
- `success` (bool)
- `found` (bool)
- `query_address` (str)
- `function_start` (str)
- `function_end` (str)
- `function_size` (int)

**Example request:**
```json
{"method": "find_function_boundaries", "params": {"address": "0x00401050"}}
```

**Example response:**
```json
{"success": true, "found": true, "query_address": "0x00401050", "function_start": "0x00401000", "function_end": "0x00401100", "function_size": 256}
```

---

### `analyze_function`

**Purpose:** Analyze a function to find all CALL instructions it makes.

**Parameters:**
- `address` (str, required): Function address (start of function).
- `max_instructions` (int, default=200): Maximum instructions to analyze.

**Returns:** JSON with:
- `success` (bool)
- `function_address` (str)
- `arch` (str)
- `prologue_type` (str): One of `"x86_standard"`, `"x64_standard"`, `"x64_leaf"`, `"unknown"`.
- `instructions_analyzed` (int)
- `calls_found` (int)
- `calls` (array): List of `{address, instruction, target, is_indirect}`.

**Example request:**
```json
{"method": "analyze_function", "params": {"address": "0x00401000"}}
```

**Example response:**
```json
{"success": true, "function_address": "0x00401000", "arch": "x64", "prologue_type": "x64_standard", "instructions_analyzed": 50, "calls_found": 2, "calls": [{"address": "0x00401020", "instruction": "call 0x00405000", "target": "0x00405000", "is_indirect": false}, {"address": "0x00401035", "instruction": "call qword ptr [rax+10]", "target": "indirect", "is_indirect": true}]}
```

**Prologue types:**
- `x86_standard`: `55 8B EC` (push ebp; mov ebp, esp)
- `x64_standard`: `55 48 89 E5` (push rbp; mov rbp, rsp)
- `x64_leaf`: `48 83 EC xx` (sub rsp, xx) — leaf functions without frame pointer
- `unknown`: Non-standard or mid-function address

---

### `find_references`

**Purpose:** Find all code locations that reference (access) a specific address.

**Parameters:**
- `address` (str, required): Target address to find references to.
- `limit` (int, default=50): Maximum results.

**Returns:** JSON with:
- `success` (bool)
- `target` (str)
- `count` (int)
- `references` (array): List of `{ref_address, instruction}`.

**Example request:**
```json
{"method": "find_references", "params": {"address": "0x00401000", "limit": 20}}
```

**Example response:**
```json
{"success": true, "target": "0x00401000", "count": 2, "references": [{"ref_address": "0x00402000", "instruction": "call 0x00401000"}]}
```

---

### `find_call_references`

**Purpose:** Find all CALL instructions that target a specific function.

**Parameters:**
- `function_address` (str, required): Function address.
- `limit` (int, default=100): Maximum results.

**Returns:** JSON with:
- `success` (bool)
- `function_address` (str)
- `caller_count` (int)
- `callers` (array): List of `{caller_address, instruction}`.

**Example request:**
```json
{"method": "find_call_references", "params": {"function_address": "0x00401000", "limit": 50}}
```

**Example response:**
```json
{"success": true, "function_address": "0x00401000", "caller_count": 10, "callers": [{"caller_address": "0x00402050", "instruction": "call 0x00401000"}]}
```

---

## 7. Breakpoints (Hardware Debug Registers)

> **Important**: All breakpoints use **hardware debug registers** (`bpmDebugRegister`) for anti-cheat safety. Maximum 4 breakpoints at a time (CPU limitation).

### `set_breakpoint`

**Purpose:** Set a hardware execution breakpoint. Non-breaking; logs registers on each hit.

**Parameters:**
- `address` (str, required): Code address.
- `id` (str, default=address): Unique identifier for this breakpoint.
- `capture_registers` (bool, default=true): Capture CPU registers on hit.
- `capture_stack` (bool, default=false): Capture stack values.
- `stack_depth` (int, default=16): Number of stack entries to capture.

**Returns:** JSON with:
- `success` (bool)
- `id` (str)
- `address` (str)
- `slot` (int): Hardware debug register slot (0-3).
- `method` (str): Always `"hardware_debug_register"`.

**Example request:**
```json
{"method": "set_breakpoint", "params": {"address": "0x00401000", "id": "bp_main"}}
```

**Example response:**
```json
{"success": true, "id": "bp_main", "address": "0x00401000", "slot": 1, "method": "hardware_debug_register"}
```

---

### `set_data_breakpoint`

**Purpose:** Set a hardware breakpoint that triggers on memory read/write access.

**Parameters:**
- `address` (str, required): Data address to monitor.
- `id` (str, default=address): Unique identifier.
- `access_type` (str, default=`"w"`): `"r"` (read), `"w"` (write), `"rw"` (both).
- `size` (int, default=4): Bytes to monitor (1, 2, or 4).

**Returns:** JSON with:
- `success` (bool)
- `id` (str)
- `address` (str)
- `slot` (int)
- `access_type` (str)
- `method` (str)

**Example request:**
```json
{"method": "set_data_breakpoint", "params": {"address": "0x12345678", "id": "health_watch", "access_type": "w", "size": 4}}
```

**Example response:**
```json
{"success": true, "id": "health_watch", "address": "0x12345678", "slot": 2, "access_type": "w", "method": "hardware_debug_register"}
```

---

### `get_breakpoint_hits`

**Purpose:** Retrieve logged breakpoint hits.

**Parameters:**
- `id` (str, optional): Specific breakpoint ID; omit for all breakpoints.
- `clear` (bool, default=false): Clear hit log after retrieval.

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `hits` (array): List of `{id, address, timestamp, breakpoint_type, registers?, stack?}`.

**Example request:**
```json
{"method": "get_breakpoint_hits", "params": {"id": "bp_main", "clear": true}}
```

**Example response:**
```json
{"success": true, "count": 1, "hits": [{"id": "bp_main", "address": "0x00401000", "timestamp": 1733540000, "breakpoint_type": "hardware_execute", "registers": {"EAX": "0x00000001", "EBX": "0x00000000"}}]}
```

---

### `remove_breakpoint`

**Purpose:** Remove a breakpoint by ID.

**Parameters:**
- `id` (str, required): Breakpoint ID to remove.

**Returns:** JSON with:
- `success` (bool)
- `id` (str)

**Example request:**
```json
{"method": "remove_breakpoint", "params": {"id": "bp_main"}}
```

**Example response:**
```json
{"success": true, "id": "bp_main"}
```

---

### `list_breakpoints`

**Purpose:** List all active breakpoints.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `breakpoints` (array): List of `{id, address, type, slot}`.

**Example request:**
```json
{"method": "list_breakpoints", "params": {}}
```

**Example response:**
```json
{"success": true, "count": 2, "breakpoints": [{"id": "bp_main", "address": "0x00401000", "type": "execute", "slot": 1}, {"id": "health_watch", "address": "0x12345678", "type": "data", "slot": 2}]}
```

---

### `clear_all_breakpoints`

**Purpose:** Remove all active breakpoints.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `removed_count` (int)

**Example request:**
```json
{"method": "clear_all_breakpoints", "params": {}}
```

**Example response:**
```json
{"success": true, "removed_count": 4}
```

---

## 8. Memory Regions

### `get_memory_regions`

**Purpose:** Get a list of valid memory regions using page protection sampling.

**Parameters:**
- `max` (int, default=100): Maximum regions to return.

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `regions` (array): List of `{address, readable, writable, executable}`.

**Example request:**
```json
{"method": "get_memory_regions", "params": {"max": 50}}
```

**Example response:**
```json
{"success": true, "count": 50, "regions": [{"address": "0x00400000", "readable": true, "writable": false, "executable": true}]}
```

---

### `enum_memory_regions_full`

**Purpose:** Get comprehensive memory map using native CE API.

**Parameters:**
- `max` (int, default=500): Maximum regions.

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `regions` (array): List of `{base_address, allocation_base, region_size, state, protect, type, readable, writable, executable}`.

**Example request:**
```json
{"method": "enum_memory_regions_full", "params": {"max": 200}}
```

**Example response:**
```json
{"success": true, "count": 200, "regions": [{"base_address": "0x00400000", "allocation_base": "0x00400000", "region_size": 4096, "state": "MEM_COMMIT", "protect": "PAGE_EXECUTE_READ", "type": "MEM_IMAGE", "readable": true, "writable": false, "executable": true}]}
```

---

## 9. Lua Evaluation & Scripting

### `evaluate_lua`

**Purpose:** Execute arbitrary Lua code in Cheat Engine's context.

**Parameters:**
- `code` (str, required): Lua code to execute.

**Returns:** JSON with:
- `success` (bool)
- `result` (str): Return value as string.

**Example request:**
```json
{"method": "evaluate_lua", "params": {"code": "return 1 + 1"}}
```

**Example response:**
```json
{"success": true, "result": "2"}
```

> **Caution**: Use responsibly. Avoid infinite loops or memory-intensive operations.

---

### `auto_assemble`

**Purpose:** Execute a Cheat Engine Auto Assembler script (code injection, code caves, patches).

**Parameters:**
- `script` (str, required): Auto Assembler script text.

**Returns:** JSON with:
- `success` (bool)
- `message` (str): Result message.

**Example request:**
```json
{"method": "auto_assemble", "params": {"script": "[ENABLE]\naob_scan('...') ...\n[DISABLE]\n..."}}
```

**Example response:**
```json
{"success": true, "message": "Script assembled successfully"}
```

> **Warning**: This can permanently modify game memory. Use with caution.

---

## 10. High-Level Analysis Tools

### `dissect_structure`

**Purpose:** Automatically analyze memory and heuristically guess data types at each offset.

**Parameters:**
- `address` (str, required): Base address.
- `size` (int, default=256): Bytes to analyze.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `size` (int)
- `element_count` (int)
- `elements` (array): List of `{offset, type, size, value}`.

**Example request:**
```json
{"method": "dissect_structure", "params": {"address": "0x12345678", "size": 128}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "size": 128, "element_count": 5, "elements": [{"offset": 0, "type": "Pointer", "size": 8, "value": "0x00401000"}, {"offset": 8, "type": "4 Bytes", "size": 4, "value": "100"}, {"offset": 12, "type": "Float", "size": 4, "value": "3.14159"}]}
```

---

## 11. DBVM Hypervisor Tools (Ring -1)

> **These tools require DBVM to be activated** (Edit → Settings → Debugger → Use DBVM). They operate at the hypervisor level (Ring -1), making them **100% invisible to anti-cheat software**.

### `get_physical_address`

**Purpose:** Convert a virtual address to its physical RAM address.

**Parameters:**
- `address` (str, required): Virtual memory address.

**Returns:** JSON with:
- `success` (bool)
- `virtual_address` (str)
- `physical_address` (str): Hex physical address.
- `physical_int` (int): Physical address as integer.

**Example request:**
```json
{"method": "get_physical_address", "params": {"address": "0x12345678"}}
```

**Example response:**
```json
{"success": true, "virtual_address": "0x12345678", "physical_address": "0x1A2B3C4D", "physical_int": 439041101}
```

---

### `start_dbvm_watch`

**Purpose:** Start hypervisor-level memory access monitoring (anti-cheat-safe equivalent of "Find what writes to this address").

**Parameters:**
- `address` (str, required): Address to monitor.
- `mode` (str, default=`"w"`): `"w"` (write), `"r"` (read), `"rw"` (both), `"x"` (execute).
- `max_entries` (int, default=1000): Log buffer size.

**Returns:** JSON with:
- `success` (bool)
- `status` (str): `"monitoring"`.
- `virtual_address` (str)
- `physical_address` (str)
- `watch_id` (int)
- `mode` (str)
- `note` (str)

**Example request:**
```json
{"method": "start_dbvm_watch", "params": {"address": "0x12345678", "mode": "w"}}
```

**Example response:**
```json
{"success": true, "status": "monitoring", "virtual_address": "0x12345678", "physical_address": "0x1A2B3C4D", "watch_id": 1, "mode": "w", "note": "Call stop_dbvm_watch to retrieve results"}
```

---

### `stop_dbvm_watch`

**Purpose:** Stop DBVM monitoring and retrieve all logged memory accesses.

**Parameters:**
- `address` (str, required): Address that was being monitored.

**Returns:** JSON with:
- `success` (bool)
- `virtual_address` (str)
- `physical_address` (str)
- `mode` (str)
- `hit_count` (int)
- `duration_seconds` (int)
- `hits` (array): List of `{hit_number, instruction_address, instruction, registers}`.

**Example request:**
```json
{"method": "stop_dbvm_watch", "params": {"address": "0x12345678"}}
```

**Example response:**
```json
{"success": true, "virtual_address": "0x12345678", "mode": "w", "hit_count": 3, "duration_seconds": 10, "hits": [{"hit_number": 1, "instruction_address": "0x00402000", "instruction": "mov [ecx+4], eax", "registers": {"RAX": "0x00000064", "RIP": "0x00402000"}}]}
```

---

### `poll_dbvm_watch`

**Purpose:** Poll DBVM watch logs without stopping the monitor.

**Parameters:**
- `address` (str, required): Address being monitored.
- `max_results` (int, default=1000): Maximum entries to return.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `hit_count` (int)
- `hits` (array): Current hit log (same format as `stop_dbvm_watch`).

**Example request:**
```json
{"method": "poll_dbvm_watch", "params": {"address": "0x12345678", "max_results": 100}}
```

**Example response:**
```json
{"success": true, "address": "0x12345678", "hit_count": 5, "hits": [{"hit_number": 1, "instruction_address": "0x00402000", "instruction": "mov [ecx+4], eax", "registers": {"RAX": "0x00000064", "RIP": "0x00402000"}}]}
```

---

## 12. Process Lifecycle (Unit 7)

### `open_process`

**Purpose:** Attach to a process by PID or name.

**Parameters:**
- `pid` (int, optional): Process ID to open.
- `name` (str, optional): Process name to search for and open.

**Returns:** JSON with:
- `success` (bool)
- `pid` (int): Opened process ID.
- `name` (str): Process name.

---

### `get_process_list`

**Purpose:** List all running processes on the system.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `processes` (array): List of `{pid, name}` objects.

---

### `get_processid_from_name`

**Purpose:** Find the PID of a process by its executable name.

**Parameters:**
- `name` (str, required): Process name (e.g., `"game.exe"`).

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `pid` (int): Found process ID, or `null` if not found.

---

### `get_foreground_process`

**Purpose:** Get the PID and name of the currently focused (foreground) window's process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `pid` (int)
- `name` (str)

---

### `create_process`

**Purpose:** Launch a new process.

**Parameters:**
- `path` (str, required): Full path to the executable.
- `args` (str, optional): Command-line arguments.
- `suspended` (bool, default=false): Start process in suspended state.

**Returns:** JSON with:
- `success` (bool)
- `pid` (int): New process ID.
- `handle` (str?): Process handle (if available).

---

### `get_opened_process_id`

**Purpose:** Get the PID of the currently opened (attached) process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `pid` (int)

---

### `get_opened_process_handle`

**Purpose:** Get the raw handle to the currently opened process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `handle` (str): Hex handle value.

---

## 13. Memory Allocation (Unit 8)

### `allocate_memory`

**Purpose:** Allocate a region of memory in the target process.

**Parameters:**
- `size` (int, required): Bytes to allocate.
- `address` (str, optional): Preferred allocation address.
- `protection` (str, default=`"rwx"`): Protection flags (`"r"`, `"rw"`, `"rwx"`, `"rx"`).

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Allocated region address.
- `size` (int): Actual allocated size.

---

### `free_memory`

**Purpose:** Free a previously allocated memory region.

**Parameters:**
- `address` (str, required): Address of the region to free.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)

---

### `allocate_shared_memory`

**Purpose:** Allocate a shared memory region accessible from both CE and the target process.

**Parameters:**
- `size` (int, required): Bytes to allocate.
- `name` (str, optional): Named share identifier.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Address in target process.
- `local_address` (str): Address in CE process.
- `size` (int)

---

### `get_memory_protection`

**Purpose:** Query the protection flags for a memory address.

**Parameters:**
- `address` (str, required): Memory address to query.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `protection` (str): Windows protection constant (e.g., `"PAGE_EXECUTE_READ"`).
- `readable` (bool)
- `writable` (bool)
- `executable` (bool)

---

### `set_memory_protection`

**Purpose:** Change the protection flags for a memory region.

**Parameters:**
- `address` (str, required): Start of region.
- `size` (int, required): Region size in bytes.
- `protection` (str, required): New protection (e.g., `"rwx"` or `"PAGE_EXECUTE_READWRITE"`).

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `old_protection` (str): Previous protection value.

---

### `full_access`

**Purpose:** Grant full read/write/execute access to a memory region (shorthand for `set_memory_protection` with `PAGE_EXECUTE_READWRITE`).

**Parameters:**
- `address` (str, required): Start of region.
- `size` (int, required): Region size in bytes.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `old_protection` (str)

---

### `allocate_kernel_memory`

**Purpose:** Allocate memory in kernel space (requires DBK driver).

**Parameters:**
- `size` (int, required): Bytes to allocate.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Kernel address of allocated region.

> **Note**: Requires the DBK kernel driver to be loaded.

---

## 14. Code Injection (Unit 9)

### `inject_dll`

**Purpose:** Inject a DLL into the target process.

**Parameters:**
- `path` (str, required): Full path to the DLL file.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `base_address` (str?): Loaded module base address.

---

### `inject_dotnet_dll`

**Purpose:** Inject a .NET assembly into the target process.

**Parameters:**
- `path` (str, required): Full path to the .NET DLL.
- `typename` (str, required): Full type name to instantiate (e.g., `"MyNamespace.MyClass"`).
- `method` (str, required): Method name to call after injection.
- `args` (str, optional): Arguments to pass to the method.

**Returns:** JSON with:
- `success` (bool)
- `return_value` (str?): Method return value.

---

### `execute_code`

**Purpose:** Execute a block of raw machine code in the target process.

**Parameters:**
- `address` (str, required): Address of code to execute.
- `args` (array, optional): Arguments to pass (register values or stack).

**Returns:** JSON with:
- `success` (bool)
- `return_value` (str?): EAX/RAX value after execution.

---

### `execute_code_ex`

**Purpose:** Execute code with extended context control (set any register before execution).

**Parameters:**
- `address` (str, required): Address of code to execute.
- `registers` (object, optional): Map of register name to value (e.g., `{"ECX": "0x12345678"}`).

**Returns:** JSON with:
- `success` (bool)
- `registers` (object): Register state after execution.
- `return_value` (str?)

---

### `execute_method`

**Purpose:** Call a specific method by symbol name with arguments.

**Parameters:**
- `symbol` (str, required): Symbol name of the method.
- `args` (array, optional): Arguments list.

**Returns:** JSON with:
- `success` (bool)
- `symbol` (str)
- `return_value` (str?)

---

### `execute_code_local`

**Purpose:** Execute Lua-generated code within CE's own process context.

**Parameters:**
- `code` (str, required): Lua code to generate machine code.

**Returns:** JSON with:
- `success` (bool)
- `result` (str?)

---

### `execute_code_local_ex`

**Purpose:** Execute code locally with extended options (return type, error handling).

**Parameters:**
- `code` (str, required): Code to execute.
- `return_type` (str, default=`"int"`): Expected return type.

**Returns:** JSON with:
- `success` (bool)
- `result` (str?)
- `return_type` (str)

---

## 15. Debugger Control (Unit 10)

### `debug_process`

**Purpose:** Attach CE's debugger to the target process.

**Parameters:**
- `pid` (int, optional): PID to debug; defaults to currently opened process.
- `debugger_type` (str, optional): Debugger type hint.

**Returns:** JSON with:
- `success` (bool)
- `pid` (int)
- `debugger` (str): Debugger interface name.

---

### `debug_is_debugging`

**Purpose:** Check whether the debugger is currently attached.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `is_debugging` (bool)

---

### `debug_get_current_debugger_interface`

**Purpose:** Get the name of the active debugger interface.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `interface` (str): Debugger interface name (e.g., `"Windows Debugger"`, `"DBVM Debugger"`).

---

### `debug_break_thread`

**Purpose:** Force a specific thread to break (pause execution).

**Parameters:**
- `thread_id` (int, required): Thread ID to break.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)

---

### `debug_continue`

**Purpose:** Resume a thread that was stopped by the debugger.

**Parameters:**
- `thread_id` (int, required): Thread ID to continue.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)

---

### `debug_detach`

**Purpose:** Detach CE's debugger from the process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)

---

### `pause_process`

**Purpose:** Suspend all threads in the target process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `threads_suspended` (int)

---

### `unpause_process`

**Purpose:** Resume all threads in the target process.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `threads_resumed` (int)

---

## 16. Context & Thread Breakpoints (Unit 11)

### `debug_get_context`

**Purpose:** Get the CPU register context of a paused thread.

**Parameters:**
- `thread_id` (int, required): Thread ID.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)
- `registers` (object): Map of register name to hex string value (e.g., `{"RAX": "0x...", "RIP": "0x..."}`).

---

### `debug_set_context`

**Purpose:** Set the CPU register context of a paused thread.

**Parameters:**
- `thread_id` (int, required): Thread ID.
- `registers` (object, required): Map of register name to new value.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)

---

### `debug_get_xmm_pointer`

**Purpose:** Get a pointer to the XMM/SSE register state of a paused thread.

**Parameters:**
- `thread_id` (int, required): Thread ID.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)
- `xmm_pointer` (str): Address of XMM register block.

---

### `debug_set_last_branch_recording`

**Purpose:** Enable or disable Last Branch Recording (LBR) for a thread.

**Parameters:**
- `thread_id` (int, required): Thread ID.
- `enabled` (bool, required): Enable or disable LBR.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)
- `enabled` (bool)

---

### `debug_get_last_branch_record`

**Purpose:** Retrieve the Last Branch Record buffer for a thread.

**Parameters:**
- `thread_id` (int, required): Thread ID.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int)
- `records` (array): List of `{from_address, to_address}`.

---

### `debug_set_breakpoint_for_thread`

**Purpose:** Set a breakpoint that only fires for a specific thread.

**Parameters:**
- `address` (str, required): Code address.
- `thread_id` (int, required): Thread ID to restrict to.
- `id` (str, optional): Breakpoint identifier.

**Returns:** JSON with:
- `success` (bool)
- `id` (str)
- `address` (str)
- `thread_id` (int)

---

### `debug_remove_breakpoint_for_thread`

**Purpose:** Remove a thread-specific breakpoint.

**Parameters:**
- `id` (str, required): Breakpoint ID to remove.
- `thread_id` (int, required): Thread ID the breakpoint was set for.

**Returns:** JSON with:
- `success` (bool)
- `id` (str)

---

## 17. Symbol Management (Unit 12)

### `register_symbol`

**Purpose:** Register a custom symbol name for a memory address.

**Parameters:**
- `name` (str, required): Symbol name to register.
- `address` (str, required): Memory address to associate.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `address` (str)

---

### `unregister_symbol`

**Purpose:** Remove a previously registered custom symbol.

**Parameters:**
- `name` (str, required): Symbol name to remove.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)

---

### `enum_registered_symbols`

**Purpose:** List all user-registered custom symbols.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `symbols` (array): List of `{name, address}`.

---

### `delete_all_registered_symbols`

**Purpose:** Remove all user-registered custom symbols.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `removed_count` (int)

---

### `enable_windows_symbols`

**Purpose:** Enable loading of Windows PDB symbol files from Microsoft symbol servers.

**Parameters:**
- `symbol_path` (str, optional): Custom symbol server or cache path.

**Returns:** JSON with:
- `success` (bool)

---

### `enable_kernel_symbols`

**Purpose:** Enable kernel-mode symbol loading (requires DBK driver).

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)

---

### `get_symbol_info`

**Purpose:** Get detailed information about a symbol by name or address.

**Parameters:**
- `symbol` (str, optional): Symbol name to look up.
- `address` (str, optional): Address to look up (alternative to name).

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `address` (str)
- `module` (str): Module the symbol belongs to.
- `size` (int?): Symbol size if known.

---

### `get_module_size`

**Purpose:** Get the size of a loaded module by name.

**Parameters:**
- `name` (str, required): Module name (e.g., `"game.exe"`).

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `size` (int): Module size in bytes.
- `base_address` (str)

---

### `load_new_symbols`

**Purpose:** Load symbols from an external PDB or symbol file.

**Parameters:**
- `path` (str, required): Path to symbol file.
- `module` (str, optional): Module to associate symbols with.

**Returns:** JSON with:
- `success` (bool)
- `symbols_loaded` (int)

---

### `reinitialize_symbol_handler`

**Purpose:** Reinitialize CE's symbol handler (refreshes all symbols).

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)

---

## 18. Assembly & Code Generation (Unit 13)

### `assemble_instruction`

**Purpose:** Assemble a single assembly instruction into machine code bytes.

**Parameters:**
- `instruction` (str, required): Assembly instruction text (e.g., `"mov eax, 1"`).
- `address` (str, optional): Base address for relative offsets.

**Returns:** JSON with:
- `success` (bool)
- `instruction` (str)
- `bytes` (array): Machine code byte array.
- `hex` (str): Hex string.
- `size` (int)

---

### `auto_assemble_check`

**Purpose:** Validate an Auto Assembler script without executing it.

**Parameters:**
- `script` (str, required): Auto Assembler script to validate.

**Returns:** JSON with:
- `success` (bool)
- `valid` (bool)
- `errors` (array): List of error message strings (empty if valid).

---

### `compile_c_code`

**Purpose:** Compile C code using CE's built-in C compiler and return the machine code.

**Parameters:**
- `code` (str, required): C source code.
- `return_type` (str, default=`"int"`): Return type of the entry function.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Address where compiled code was placed.
- `size` (int): Code size in bytes.

---

### `compile_cs_code`

**Purpose:** Compile C# source code and execute it in the target process context.

**Parameters:**
- `code` (str, required): C# source code.
- `entry_method` (str, required): Method name to call.

**Returns:** JSON with:
- `success` (bool)
- `return_value` (str?)

---

### `generate_api_hook_script`

**Purpose:** Generate a CE Auto Assembler script that hooks a Windows API function.

**Parameters:**
- `function` (str, required): Function name or address to hook (e.g., `"kernel32.CreateFileW"`).
- `hook_type` (str, default=`"mid"`): Hook type — `"pre"`, `"post"`, `"mid"`.

**Returns:** JSON with:
- `success` (bool)
- `script` (str): Ready-to-use Auto Assembler script.

---

### `generate_code_injection_script`

**Purpose:** Generate a CE Auto Assembler code injection script (code cave) for a given address.

**Parameters:**
- `address` (str, required): Injection address.
- `payload` (str, required): Assembly instructions for the code cave.

**Returns:** JSON with:
- `success` (bool)
- `script` (str): Complete Auto Assembler script with enable/disable sections.

---

## 19. Advanced Memory Operations (Unit 14)

### `copy_memory`

**Purpose:** Copy bytes from one address to another within the target process.

**Parameters:**
- `src` (str, required): Source address.
- `dst` (str, required): Destination address.
- `size` (int, required): Bytes to copy.

**Returns:** JSON with:
- `success` (bool)
- `src` (str)
- `dst` (str)
- `bytes_copied` (int)

---

### `compare_memory`

**Purpose:** Compare two memory regions byte-by-byte.

**Parameters:**
- `address1` (str, required): First region address.
- `address2` (str, required): Second region address.
- `size` (int, required): Bytes to compare.

**Returns:** JSON with:
- `success` (bool)
- `identical` (bool)
- `first_difference_offset` (int?): Offset of first differing byte, or `null` if identical.
- `differences` (int): Count of differing bytes.

---

### `write_region_to_file`

**Purpose:** Dump a memory region to a file on disk.

**Parameters:**
- `address` (str, required): Start address.
- `size` (int, required): Bytes to dump.
- `path` (str, required): Output file path.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `bytes_written` (int)

---

### `read_region_from_file`

**Purpose:** Load bytes from a file into a memory region.

**Parameters:**
- `path` (str, required): Input file path.
- `address` (str, required): Target address to write to.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `bytes_written` (int)

---

### `md5_memory`

**Purpose:** Compute an MD5 hash of a memory region.

**Parameters:**
- `address` (str, required): Start address.
- `size` (int, required): Bytes to hash.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `size` (int)
- `md5_hash` (str): Hex MD5 digest.

---

### `md5_file`

**Purpose:** Compute an MD5 hash of a file on disk.

**Parameters:**
- `path` (str, required): File path.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `md5_hash` (str): Hex MD5 digest.

---

### `create_section`

**Purpose:** Create a memory-mapped section object.

**Parameters:**
- `size` (int, required): Section size in bytes.
- `name` (str, optional): Section name.

**Returns:** JSON with:
- `success` (bool)
- `handle` (str): Section handle.
- `size` (int)

---

### `map_view_of_section`

**Purpose:** Map a view of a section object into the target process address space.

**Parameters:**
- `handle` (str, required): Section handle from `create_section`.
- `address` (str, optional): Preferred mapping address.
- `size` (int, optional): View size.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Mapped view address.
- `size` (int)

---

## 20. Advanced Scanning (Unit 15)

### `aob_scan_unique`

**Purpose:** Scan for an AOB pattern and return an error if not exactly one match is found.

**Parameters:**
- `pattern` (str, required): AOB pattern.
- `protection` (str, default=`"+X"`): Memory protection filter.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): The unique match address.
- `pattern` (str)

---

### `aob_scan_module`

**Purpose:** Scan for an AOB pattern within a specific module.

**Parameters:**
- `pattern` (str, required): AOB pattern.
- `module` (str, required): Module name to restrict the scan to.
- `limit` (int, default=100): Maximum results.

**Returns:** JSON with:
- `success` (bool)
- `module` (str)
- `count` (int)
- `addresses` (array)

---

### `aob_scan_module_unique`

**Purpose:** Scan for a unique AOB pattern within a specific module.

**Parameters:**
- `pattern` (str, required): AOB pattern.
- `module` (str, required): Module name.

**Returns:** JSON with:
- `success` (bool)
- `address` (str): Unique match address.
- `module` (str)

---

### `pointer_rescan`

**Purpose:** Rescan a pointer map to find pointers that still resolve to a given address.

**Parameters:**
- `address` (str, required): Target address to scan pointers for.
- `max_depth` (int, default=4): Maximum pointer chain depth.
- `limit` (int, default=100): Maximum results.

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `pointers` (array): List of `{base, offsets, resolved_address}`.

---

### `create_persistent_scan`

**Purpose:** Create a persistent scan session that survives multiple next-scans.

**Parameters:**
- `value_type` (str, required): Value type to scan for (e.g., `"4Bytes"`, `"Float"`).
- `protection` (str, default=`"+W-C"`): Memory protection filter.

**Returns:** JSON with:
- `success` (bool)
- `scan_id` (str): Identifier for this persistent scan session.

---

### `persistent_scan_first_scan`

**Purpose:** Perform the initial scan in a persistent scan session.

**Parameters:**
- `scan_id` (str, required): Persistent scan session ID.
- `value` (str, required): Value to scan for.
- `scan_type` (str, default=`"exact"`): Scan type.

**Returns:** JSON with:
- `success` (bool)
- `scan_id` (str)
- `count` (int): Initial result count.

---

### `persistent_scan_next_scan`

**Purpose:** Perform a follow-up scan in a persistent scan session.

**Parameters:**
- `scan_id` (str, required): Persistent scan session ID.
- `value` (str, optional): New value (required for exact/bigger/smaller).
- `scan_type` (str, default=`"exact"`): Scan type.

**Returns:** JSON with:
- `success` (bool)
- `scan_id` (str)
- `count` (int): Remaining result count.

---

### `persistent_scan_get_results`

**Purpose:** Retrieve results from a persistent scan session.

**Parameters:**
- `scan_id` (str, required): Persistent scan session ID.
- `offset` (int, default=0): Result offset for pagination.
- `limit` (int, default=100): Maximum results to return.

**Returns:** JSON with:
- `success` (bool)
- `scan_id` (str)
- `count` (int): Total result count.
- `addresses` (array): Hex address strings for this page.

---

### `persistent_scan_destroy`

**Purpose:** Destroy a persistent scan session and free its resources.

**Parameters:**
- `scan_id` (str, required): Persistent scan session ID.

**Returns:** JSON with:
- `success` (bool)
- `scan_id` (str)

---

## 21. Window & GUI (Unit 16)

### `find_window`

**Purpose:** Find a window by its title or class name.

**Parameters:**
- `title` (str, optional): Window title (partial match supported).
- `class_name` (str, optional): Window class name.

**Returns:** JSON with:
- `success` (bool)
- `handle` (str): Window handle (HWND) as hex string.
- `title` (str)
- `class_name` (str)

---

### `get_window_caption`

**Purpose:** Get the title text of a window.

**Parameters:**
- `handle` (str, required): Window handle.

**Returns:** JSON with:
- `success` (bool)
- `handle` (str)
- `caption` (str): Window title text.

---

### `get_window_class_name`

**Purpose:** Get the class name of a window.

**Parameters:**
- `handle` (str, required): Window handle.

**Returns:** JSON with:
- `success` (bool)
- `handle` (str)
- `class_name` (str)

---

### `get_window_process_id`

**Purpose:** Get the PID of the process that owns a window.

**Parameters:**
- `handle` (str, required): Window handle.

**Returns:** JSON with:
- `success` (bool)
- `handle` (str)
- `pid` (int)

---

### `send_window_message`

**Purpose:** Send a Windows message (WM_*) to a window.

**Parameters:**
- `handle` (str, required): Window handle.
- `message` (int, required): Windows message code.
- `wparam` (int, default=0): WPARAM value.
- `lparam` (int, default=0): LPARAM value.

**Returns:** JSON with:
- `success` (bool)
- `result` (int): Return value from SendMessage.

---

### `show_message`

**Purpose:** Display a CE message box dialog.

**Parameters:**
- `message` (str, required): Message text.
- `title` (str, default=`"CE MCP"`): Dialog title.

**Returns:** JSON with:
- `success` (bool)

---

### `input_query`

**Purpose:** Show an input dialog and return the user's text response.

**Parameters:**
- `prompt` (str, required): Prompt text shown to user.
- `default` (str, optional): Default input value.

**Returns:** JSON with:
- `success` (bool)
- `value` (str?): User-entered text, or `null` if cancelled.
- `cancelled` (bool)

---

### `show_selection_list`

**Purpose:** Show a list selection dialog and return the chosen item.

**Parameters:**
- `items` (array, required): List of string items to display.
- `title` (str, optional): Dialog title.

**Returns:** JSON with:
- `success` (bool)
- `selected` (str?): Selected item text, or `null` if cancelled.
- `index` (int?): Zero-based index of selection.
- `cancelled` (bool)

---

## 22. Input & Display (Unit 17)

### `get_pixel`

**Purpose:** Get the color of a pixel at screen coordinates.

**Parameters:**
- `x` (int, required): X coordinate.
- `y` (int, required): Y coordinate.

**Returns:** JSON with:
- `success` (bool)
- `x` (int)
- `y` (int)
- `color` (int): Color as 32-bit integer.
- `r` (int), `g` (int), `b` (int): RGB components.

---

### `get_mouse_pos`

**Purpose:** Get the current mouse cursor position.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `x` (int)
- `y` (int)

---

### `set_mouse_pos`

**Purpose:** Move the mouse cursor to specified screen coordinates.

**Parameters:**
- `x` (int, required): Target X coordinate.
- `y` (int, required): Target Y coordinate.

**Returns:** JSON with:
- `success` (bool)

---

### `is_key_pressed`

**Purpose:** Check whether a keyboard key is currently pressed.

**Parameters:**
- `key` (int|str, required): Virtual key code or key name (e.g., `65` or `"A"`).

**Returns:** JSON with:
- `success` (bool)
- `key` (str)
- `pressed` (bool)

---

### `key_down`

**Purpose:** Simulate pressing a keyboard key down.

**Parameters:**
- `key` (int|str, required): Virtual key code or key name.

**Returns:** JSON with:
- `success` (bool)

---

### `key_up`

**Purpose:** Simulate releasing a keyboard key.

**Parameters:**
- `key` (int|str, required): Virtual key code or key name.

**Returns:** JSON with:
- `success` (bool)

---

### `do_key_press`

**Purpose:** Simulate a complete key press (down + up) for a key.

**Parameters:**
- `key` (int|str, required): Virtual key code or key name.
- `duration_ms` (int, default=50): Milliseconds to hold the key.

**Returns:** JSON with:
- `success` (bool)

---

### `get_screen_info`

**Purpose:** Get screen resolution and display information.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `width` (int): Screen width in pixels.
- `height` (int): Screen height in pixels.
- `bpp` (int): Bits per pixel.

---

## 23. Cheat Tables (Unit 18)

### `load_table`

**Purpose:** Load a Cheat Engine table (.CT) file.

**Parameters:**
- `path` (str, required): Path to the .CT file.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `entry_count` (int): Number of memory records loaded.

---

### `save_table`

**Purpose:** Save the current Cheat Engine table to a file.

**Parameters:**
- `path` (str, required): Output file path.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)

---

### `get_address_list`

**Purpose:** Get all memory records from the current cheat table.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `count` (int)
- `records` (array): List of `{id, description, address, type, value, enabled}`.

---

### `get_memory_record`

**Purpose:** Get a specific memory record by ID or description.

**Parameters:**
- `id` (int, optional): Record ID.
- `description` (str, optional): Record description to search for.

**Returns:** JSON with:
- `success` (bool)
- `id` (int)
- `description` (str)
- `address` (str)
- `type` (str)
- `value` (str)
- `enabled` (bool)

---

### `create_memory_record`

**Purpose:** Add a new memory record to the cheat table.

**Parameters:**
- `description` (str, required): Display name.
- `address` (str, required): Memory address.
- `type` (str, default=`"4 Bytes"`): Value type.

**Returns:** JSON with:
- `success` (bool)
- `id` (int): New record ID.
- `description` (str)

---

### `delete_memory_record`

**Purpose:** Remove a memory record from the cheat table.

**Parameters:**
- `id` (int, required): Record ID to delete.

**Returns:** JSON with:
- `success` (bool)
- `id` (int)

---

### `get_memory_record_value`

**Purpose:** Read the current value of a memory record.

**Parameters:**
- `id` (int, required): Record ID.

**Returns:** JSON with:
- `success` (bool)
- `id` (int)
- `value` (str): Current value as string.

---

### `set_memory_record_value`

**Purpose:** Write a new value to a memory record (and optionally freeze it).

**Parameters:**
- `id` (int, required): Record ID.
- `value` (str, required): New value to set.
- `freeze` (bool, default=false): Keep writing this value continuously.

**Returns:** JSON with:
- `success` (bool)
- `id` (int)
- `value` (str)

---

## 24. Structures (Unit 19)

### `create_structure`

**Purpose:** Create a named structure definition in CE's structure dissector.

**Parameters:**
- `name` (str, required): Structure name.
- `size` (int, optional): Total structure size in bytes.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)

---

### `get_structure_by_name`

**Purpose:** Retrieve a structure definition by name.

**Parameters:**
- `name` (str, required): Structure name.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `size` (int)
- `element_count` (int)
- `elements` (array): List of `{offset, name, type, size}`.

---

### `add_element_to_structure`

**Purpose:** Add a field element to an existing structure definition.

**Parameters:**
- `structure` (str, required): Structure name.
- `name` (str, required): Field name.
- `offset` (int, required): Field offset within the structure.
- `type` (str, required): Field type (e.g., `"4 Bytes"`, `"Float"`, `"Pointer"`).

**Returns:** JSON with:
- `success` (bool)
- `structure` (str)
- `name` (str)

---

### `get_structure_elements`

**Purpose:** List all elements in a structure definition.

**Parameters:**
- `name` (str, required): Structure name.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `elements` (array): List of `{offset, name, type, size}`.

---

### `export_structure_to_xml`

**Purpose:** Export a structure definition to XML format.

**Parameters:**
- `name` (str, required): Structure name.
- `path` (str, optional): File path to save XML; if omitted, returns inline.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `xml` (str?): XML content (when no path provided).

---

### `delete_structure`

**Purpose:** Delete a structure definition.

**Parameters:**
- `name` (str, required): Structure name.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)

---

## 25. File, Clipboard & Shell (Units 20a-20b)

### `file_exists`

**Purpose:** Check whether a file exists on disk.

**Parameters:**
- `path` (str, required): File path to check.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `exists` (bool)

---

### `delete_file`

**Purpose:** Delete a file from disk.

**Parameters:**
- `path` (str, required): File path to delete.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)

---

### `get_file_list`

**Purpose:** List files in a directory.

**Parameters:**
- `path` (str, required): Directory path.
- `pattern` (str, default=`"*"`): File name pattern.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `count` (int)
- `files` (array): File name strings.

---

### `get_directory_list`

**Purpose:** List subdirectories in a directory.

**Parameters:**
- `path` (str, required): Directory path.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `count` (int)
- `directories` (array): Directory name strings.

---

### `get_temp_folder`

**Purpose:** Get the path to the system's temporary files directory.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `path` (str): Temp folder path.

---

### `get_file_version`

**Purpose:** Get the version information from a Windows PE file.

**Parameters:**
- `path` (str, required): File path.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)
- `version` (str): Version string (e.g., `"1.2.3.4"`).

---

### `read_clipboard`

**Purpose:** Read the current text content of the system clipboard.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `text` (str?): Clipboard text content, or `null` if empty/non-text.

---

### `write_clipboard`

**Purpose:** Write text to the system clipboard.

**Parameters:**
- `text` (str, required): Text to write to clipboard.

**Returns:** JSON with:
- `success` (bool)

---

### `run_command` *(Shell-gated)*

**Purpose:** Execute a shell command and return its output.

**Parameters:**
- `command` (str, required): Command to execute.
- `timeout_ms` (int, default=5000): Execution timeout.

**Returns:** JSON with:
- `success` (bool)
- `stdout` (str): Standard output.
- `stderr` (str): Standard error.
- `exit_code` (int)

> **Security**: Requires `CE_MCP_ALLOW_SHELL=1` environment variable. Returns an error if not enabled.

---

### `shell_execute` *(Shell-gated)*

**Purpose:** Open a file, URL, or application using Windows ShellExecute.

**Parameters:**
- `path` (str, required): File path or URL.
- `verb` (str, default=`"open"`): Shell verb (`"open"`, `"runas"`, `"print"`).
- `args` (str, optional): Arguments to pass.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)

> **Security**: Requires `CE_MCP_ALLOW_SHELL=1` environment variable. Returns an error if not enabled.

---

## 26. Kernel & DBVM Extended (Unit 21)

> **Note**: All tools in this section require the DBK kernel driver to be loaded.

### `dbk_get_cr0`

**Purpose:** Read the CR0 control register value (kernel mode).

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `cr0` (str): Hex value of CR0.
- `cr0_int` (int)

---

### `dbk_get_cr3`

**Purpose:** Read the CR3 control register (page directory base register).

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `cr3` (str): Hex value of CR3.
- `cr3_int` (int)

---

### `dbk_get_cr4`

**Purpose:** Read the CR4 control register value (kernel mode).

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `cr4` (str): Hex value of CR4.
- `cr4_int` (int)

---

### `read_process_memory_cr3`

**Purpose:** Read process memory using a specific CR3 value (bypasses normal memory access).

**Parameters:**
- `cr3` (str, required): CR3 value to use.
- `address` (str, required): Virtual address to read.
- `size` (int, required): Bytes to read.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `size` (int)
- `hex` (str)
- `bytes` (array)

---

### `write_process_memory_cr3`

**Purpose:** Write to process memory using a specific CR3 value.

**Parameters:**
- `cr3` (str, required): CR3 value to use.
- `address` (str, required): Virtual address to write.
- `bytes` (array, required): Bytes to write.

**Returns:** JSON with:
- `success` (bool)
- `address` (str)
- `bytes_written` (int)

---

### `map_memory`

**Purpose:** Map a physical memory region into the CE process address space.

**Parameters:**
- `physical_address` (str, required): Physical memory address.
- `size` (int, required): Bytes to map.

**Returns:** JSON with:
- `success` (bool)
- `physical_address` (str)
- `virtual_address` (str): Mapped virtual address.
- `size` (int)

---

### `unmap_memory`

**Purpose:** Unmap a previously mapped physical memory region.

**Parameters:**
- `virtual_address` (str, required): Virtual address returned by `map_memory`.

**Returns:** JSON with:
- `success` (bool)
- `virtual_address` (str)

---

### `dbk_writes_ignore_write_protection`

**Purpose:** Toggle whether kernel writes bypass write-protection (CR0.WP bit).

**Parameters:**
- `enabled` (bool, required): `true` to disable write protection, `false` to restore.

**Returns:** JSON with:
- `success` (bool)
- `enabled` (bool)

---

### `get_physical_address_cr3`

**Purpose:** Translate a virtual address to physical using a specific CR3.

**Parameters:**
- `cr3` (str, required): CR3 page directory value.
- `address` (str, required): Virtual address to translate.

**Returns:** JSON with:
- `success` (bool)
- `virtual_address` (str)
- `cr3` (str)
- `physical_address` (str)
- `physical_int` (int)

---

## 27. Threading & Synchronization (Unit 22)

### `create_thread`

**Purpose:** Create a new thread in the target process executing at a given address.

**Parameters:**
- `address` (str, required): Thread start address.
- `parameter` (str, optional): Parameter to pass to the thread function.

**Returns:** JSON with:
- `success` (bool)
- `thread_id` (int): New thread ID.
- `handle` (str?): Thread handle.

---

### `get_global_variable`

**Purpose:** Get the value of a CE global Lua variable.

**Parameters:**
- `name` (str, required): Variable name.

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `value` (str): Variable value as string.
- `type` (str): Lua type name.

---

### `set_global_variable`

**Purpose:** Set the value of a CE global Lua variable.

**Parameters:**
- `name` (str, required): Variable name.
- `value` (str, required): New value (will be coerced to appropriate type).

**Returns:** JSON with:
- `success` (bool)
- `name` (str)
- `value` (str)

---

### `queue_to_main_thread`

**Purpose:** Queue a Lua function call to execute on CE's main GUI thread.

**Parameters:**
- `code` (str, required): Lua code to execute on the main thread.

**Returns:** JSON with:
- `success` (bool)
- `queued` (bool)

---

### `check_synchronize`

**Purpose:** Process any pending main-thread synchronization callbacks.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `callbacks_processed` (int)

---

### `in_main_thread`

**Purpose:** Check whether the current execution context is on CE's main thread.

**Parameters:** None

**Returns:** JSON with:
- `success` (bool)
- `is_main_thread` (bool)

---

## 28. Debug Output & Multimedia (Unit 23)

### `output_debug_string`

**Purpose:** Emit a string to the Windows debug output stream (visible in debuggers).

**Parameters:**
- `message` (str, required): Message to output.

**Returns:** JSON with:
- `success` (bool)

---

### `speak_text`

**Purpose:** Use the system's text-to-speech engine to speak a string.

**Parameters:**
- `text` (str, required): Text to speak.
- `async` (bool, default=true): Return immediately without waiting for speech to finish.

**Returns:** JSON with:
- `success` (bool)

---

### `play_sound`

**Purpose:** Play a WAV sound file.

**Parameters:**
- `path` (str, required): Path to the WAV file.
- `async` (bool, default=true): Return immediately without waiting for playback.

**Returns:** JSON with:
- `success` (bool)
- `path` (str)

---

### `beep`

**Purpose:** Emit a system beep tone.

**Parameters:**
- `frequency` (int, default=800): Frequency in Hz.
- `duration_ms` (int, default=200): Duration in milliseconds.

**Returns:** JSON with:
- `success` (bool)

---

### `set_progress_state`

**Purpose:** Set the progress bar state in CE's main window taskbar button.

**Parameters:**
- `state` (str, required): Progress state — `"normal"`, `"error"`, `"paused"`, `"indeterminate"`, `"none"`.

**Returns:** JSON with:
- `success` (bool)
- `state` (str)

---

### `set_progress_value`

**Purpose:** Set the progress bar value in CE's main window taskbar button.

**Parameters:**
- `value` (int, required): Progress value (0–100).

**Returns:** JSON with:
- `success` (bool)
- `value` (int)

---

## 29. Pagination Convention

Several tools that return potentially large result sets support pagination via `offset` and `limit` parameters.

**Convention:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `offset` | int | 0 | Number of results to skip before returning. |
| `limit` | int | 100 | Maximum results to return in this page. |

**Tools that support pagination:**

- `persistent_scan_get_results` — uses `offset`/`limit`.
- `get_file_list` — `offset`/`limit` where supported.
- `get_scan_results` — currently uses `max` (equivalent to `limit`; `offset` not yet supported).
- `aob_scan`, `find_references`, `find_call_references`, `search_string` — use `limit` to cap results.

**Paginating through all scan results:**

```python
offset = 0
page_size = 100
while True:
    result = persistent_scan_get_results(scan_id="...", offset=offset, limit=page_size)
    process(result["addresses"])
    if len(result["addresses"]) < page_size:
        break
    offset += page_size
```

**Note**: Tools that return a `count` field alongside `addresses` will report the **total** result count even when paginating, allowing you to calculate total pages.

---

## 30. Environment Variables

The MCP bridge Python server (`mcp_cheatengine.py`) reads the following environment variables at startup:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CE_MCP_TIMEOUT` | int (ms) | 30000 | Timeout in milliseconds for pipe read/write operations. Increase for slow systems or large data transfers. |
| `CE_MCP_ALLOW_SHELL` | int (0 or 1) | 0 | Set to `1` to enable shell execution tools (`run_command`, `shell_execute`). **Disabled by default for security.** |

**Setting environment variables:**

Windows (Command Prompt):
```cmd
set CE_MCP_TIMEOUT=60000
set CE_MCP_ALLOW_SHELL=0
python mcp_cheatengine.py
```

Windows (PowerShell):
```powershell
$env:CE_MCP_TIMEOUT = "60000"
$env:CE_MCP_ALLOW_SHELL = "0"
python mcp_cheatengine.py
```

Claude Desktop `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": ["path/to/mcp_cheatengine.py"],
      "env": {
        "CE_MCP_TIMEOUT": "60000",
        "CE_MCP_ALLOW_SHELL": "0"
      }
    }
  }
}
```

---

## 31. Error Codes & Handling

### Standard Error Response

All commands return `success: false` with an `error` field on failure:

```json
{
  "success": false,
  "error": "Description of what went wrong"
}
```

### Common Error Messages

| Error String | Cause | Resolution |
|-------------|-------|------------|
| `"Invalid address"` | Address could not be parsed or is null. | Check address format; use hex strings like `"0x..."`. |
| `"Failed to read at 0x..."` | Memory is not readable (unmapped, protected, or invalid). | Check region with `get_memory_regions` first. |
| `"Failed to write at 0x..."` | Memory is not writable. | Use `set_memory_protection` to add write access. |
| `"No free hardware breakpoint slots"` | All 4 debug registers (DR0-DR3) are in use. | Call `clear_all_breakpoints` to free slots. |
| `"DBK driver not loaded"` | DBK/DBVM kernel driver not initialized. | Load DBK driver in CE settings. |
| `"DBVM watch returned nil"` | DBVM not activated in CE settings. | Enable DBVM in Edit → Settings → Debugger. |
| `"Cheat Engine Bridge not running"` | Named pipe not found. | Start CE with `ce_mcp_bridge.lua` loaded. |
| `"Response too large"` | Pipe response exceeded 16 MB limit. | Reduce `size` or `max` parameter. |
| `"Pipe Communication failed"` | Named pipe connection lost. | Bridge auto-reconnects on next call. |
| `"Invalid JSON received from CE"` | Corrupt pipe response. | Usually transient; retry the command. |
| `"Shell execution disabled"` | `run_command` or `shell_execute` called without `CE_MCP_ALLOW_SHELL=1`. | Set environment variable to enable. |
| `"Process not opened"` | No process is attached to CE. | Use `open_process` or attach via CE GUI. |
| `"Symbol not found"` | Symbol name could not be resolved. | Verify module is loaded with `enum_modules`. |
| `"Timeout"` | Operation exceeded `CE_MCP_TIMEOUT`. | Increase timeout or reduce operation scope. |

### Error Handling Best Practices

1. **Always check `success`** before reading other fields.
2. **Retry on pipe errors** — the bridge auto-reconnects, so a single retry is usually sufficient.
3. **Use `ping` to verify connectivity** before starting a long session.
4. **Hardware breakpoint slots** are a hard CPU limit (4 slots). Always call `clear_all_breakpoints` when done.
5. **DBVM errors are non-fatal** — if DBVM is unavailable, fall back to hardware breakpoints.

---

## Workflow Examples

### Example 1: Find and Monitor a Health Value

```
1. ping()                                    → Verify connectivity
2. get_process_info()                        → Confirm process and architecture
3. scan_all(value="100", type="exact")       → Initial scan
4. get_scan_results()                        → [0x12345678, ...]
5. start_dbvm_watch(address="0x12345678", mode="w")
6. [Player takes damage in game]
7. stop_dbvm_watch(address="0x12345678")     → Shows writing instruction at 0x00402000
8. disassemble(address="0x00402000", count=20)
9. generate_signature(address="0x00402000") → AOB for future updates
```

### Example 2: Trace a Pointer Chain

```
1. get_process_info()                              → main module at 0x00400000
2. read_pointer_chain(base="0x00400000", offsets=[0x1000, 0x10, 0x4])
   → Resolves to player struct at 0x12345678
3. dissect_structure(address="0x12345678", size=512)
   → health at offset +0x100, mana at +0x104, etc.
4. get_rtti_classname(address="0x12345678")
   → class_name: "CPlayer"
```

### Example 3: Find All Callers of a Function

```
1. aob_scan(pattern="55 8B EC 83 EC ?? A1 ?? ?? ?? ??")
   → Function at 0x00401000
2. find_call_references(function_address="0x00401000")
   → 15 callers found
3. For each caller: disassemble(address=caller, count=10)
```

### Example 4: Persistent Multi-Step Scan

```
1. create_persistent_scan(value_type="4Bytes") → scan_id="scan_1"
2. persistent_scan_first_scan(scan_id="scan_1", value="100")  → count: 50000
3. [Spend gold in game]
4. persistent_scan_next_scan(scan_id="scan_1", scan_type="decreased") → count: 500
5. persistent_scan_next_scan(scan_id="scan_1", value="75") → count: 3
6. persistent_scan_get_results(scan_id="scan_1") → ["0x12345678", ...]
7. persistent_scan_destroy(scan_id="scan_1")
```

---

## Best Practices

1. **Always call `ping` first** to verify connectivity before performing operations.
2. **Use `get_process_info`** to confirm the correct process is attached and check `targetIs64Bit`.
3. **Prefer DBVM tools** over breakpoints for anti-cheat safety where available.
4. **Clear breakpoints** when done to free debug register slots (`clear_all_breakpoints`).
5. **Generate signatures** for important addresses to survive game updates.
6. **Use `checksum_memory`** to detect if code regions have changed.
7. **Use `analyze_function`** to understand what a function calls before hooking.
8. **Check `arch` field** in responses to verify 32/64-bit handling.
9. **Use `read_pointer_chain`** instead of multiple individual `read_pointer` calls.
10. **Use `dissect_structure`** on unknown pointers to immediately understand their layout.
11. **Use `get_rtti_classname`** to identify C++ object types instantly.
12. **Enable BSOD prevention**: In CE Settings → Extra, disable "Query memory region routines".
