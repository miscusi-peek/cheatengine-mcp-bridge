# MCP Bridge Command Reference (v11.4.0)

> **For AI Agents**: This document describes all available commands in the Cheat Engine MCP Bridge. Use these commands to perform memory analysis, reverse engineering, and dynamic tracing on target processes.
>
> **Architecture Support**: All commands automatically adapt to 32-bit or 64-bit targets. Pointer operations use `readPointer()` for automatic size handling.

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
9. [Lua Evaluation](#9-lua-evaluation)
10. [High-Level Analysis Tools](#10-high-level-analysis-tools)
11. [DBVM Hypervisor Tools (Ring -1)](#11-dbvm-hypervisor-tools-ring--1)

---

## 1. Basic & Utility

### `ping`
**Purpose**: Verify the MCP bridge is running and responsive.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "version": "11.3.1",
  "timestamp": 1733540000,
  "message": "CE MCP Bridge alive"
}
```

**Usage**: Call this first to verify connectivity before performing operations.

---

## 2. Process & Modules

### `get_process_info`
**Purpose**: Get information about the currently attached process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "process_name": "L2.exe",
  "process_id": 12345,
  "main_module_address": "0x00400000",
  "module_count": 5,
  "modules": [
    {"name": "L2.exe", "address": "0x00400000", "size": 1234567, "source": "enumModules"},
    {"name": "ntdll.dll", "address": "0x77000000", "size": 2345678, "source": "export_directory"}
  ]
}
```

**Note**: If anti-cheat blocks `enumModules()`, the bridge uses AOB scanning with PE Export Directory name reading as fallback.

---

### `enum_modules`
**Purpose**: List all modules loaded in the target process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 15,
  "modules": [
    {"name": "kernel32.dll", "address": "0x76000000", "size": 1234567}
  ]
}
```

---

### `get_symbol_address`
**Purpose**: Resolve a symbol name to its memory address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `symbol` | string | Yes | Symbol name (e.g., "kernel32.GetProcAddress", "L2.exe+0x1000") |

**Returns**:
```json
{
  "success": true,
  "symbol": "kernel32.GetProcAddress",
  "address": "0x76001234"
}
```

---

## 3. Memory Read

### `read_memory` / `read_bytes`
**Purpose**: Read raw bytes from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to read |
| `size` | int | No | 16 | Number of bytes to read (max 65536) |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "length": 16,
  "hex": "4D 5A 90 00 03 00 00 00",
  "bytes": [77, 90, 144, 0, 3, 0, 0, 0]
}
```

---

### `read_integer`
**Purpose**: Read an integer value from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `type` | string | No | "dword" | "byte", "word", "dword", or "qword" |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "value": 905969664,
  "hex": "0x36005A4D"
}
```

---

### `read_string`
**Purpose**: Read a null-terminated string from memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `max_length` | int | No | 256 | Maximum characters to read |
| `wide` | bool | No | false | Read as UTF-16 (widechar) |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "value": "MZ",
  "wide": false
}
```

---

### `read_pointer`
**Purpose**: Read a pointer value (4 bytes on 32-bit, 8 bytes on 64-bit).

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Memory address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "pointer": "0x12345678",
  "arch": "x86"
}
```

**Note**: Uses Cheat Engine's `readPointer()` which automatically reads 4 bytes for 32-bit targets and 8 bytes for 64-bit targets.

---

## 4. Memory Write

### `write_integer`
**Purpose**: Write a numeric value to memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to write to |
| `value` | int/float | Yes | - | Value to write |
| `type` | string | No | "dword" | "byte", "word", "dword", "qword", "float", "double" |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "value": 100,
  "type": "dword"
}
```

---

### `write_memory`
**Purpose**: Write raw bytes to memory.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Memory address to write to |
| `bytes` | array | Yes | Array of byte values (0-255) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "bytes_written": 8
}
```

**Example**:
```json
{"address": "0x12345678", "bytes": [0x90, 0x90, 0x90]}  // Write 3 NOP instructions
```

---

### `write_string`
**Purpose**: Write a string to memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address to write to |
| `value` | string | Yes | - | String to write |
| `wide` | bool | No | false | Write as UTF-16 (widechar) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "length": 12,
  "wide": false
}
```

> **Caution**: Writing to memory can crash the target process. Ensure the address is writable and the data is valid.

---

## 5. Pattern Scanning

### `aob_scan` / `pattern_scan`
**Purpose**: Scan memory for a byte pattern (Array of Bytes).

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `pattern` | string | Yes | - | AOB pattern with wildcards (e.g., "4D 5A ?? 00") |
| `limit` | int | No | 100 | Maximum results to return |

**Returns**:
```json
{
  "success": true,
  "pattern": "4D 5A ?? 00",
  "count": 3,
  "addresses": ["0x00400000", "0x10000000", "0x20000000"]
}
```

**Tip**: Use `??` as wildcard for unknown bytes.

---

### `scan_all`
**Purpose**: Perform a value-based memory scan (like CE's memory scanner).

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | string | Yes | - | Value to search for |
| `scan_type` | string | No | "exact" | "exact", "fuzzy", "increased", "decreased" |
| `value_type` | string | No | "4Bytes" | "1Byte", "2Bytes", "4Bytes", "8Bytes", "Float", "Double", "String" |

**Returns**:
```json
{
  "success": true,
  "message": "Scan started",
  "value": "100",
  "scan_type": "exact"
}
```

---

### `get_scan_results`
**Purpose**: Retrieve results from the last `scan_all` operation.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | No | 100 | Maximum results to return |

**Returns**:
```json
{
  "success": true,
  "count": 5,
  "addresses": ["0x12345678", "0x23456789"]
}
```

---

### `next_scan`
**Purpose**: Filter results from a previous scan (narrowing down addresses).

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | string | Yes | - | New value to scan for (used with "exact", "bigger", "smaller") |
| `scan_type` | string | No | "exact" | "exact", "increased", "decreased", "changed", "unchanged", "bigger", "smaller" |

**Returns**:
```json
{
  "success": true,
  "count": 15
}
```

**Workflow**:
```
1. scan_all(value="100")       → 50000 results
2. next_scan(scan_type="decreased")  → 500 results (value went down)
3. next_scan(value="95", scan_type="exact")  → 3 results
4. get_scan_results()          → ["0x12345678", "0x23456789", "0x34567890"]
```

**Note**: Requires a previous `scan_all` to be executed first.

---

### `search_string`
**Purpose**: Search for a text string in memory.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `value` | string | Yes | - | String to search for |
| `wide` | bool | No | false | Search as UTF-16 |
| `limit` | int | No | 50 | Maximum results |

**Returns**:
```json
{
  "success": true,
  "value": "Player",
  "count": 3,
  "addresses": ["0x12345678", "0x23456789"]
}
```

---

## 6. Disassembly & Analysis

### `disassemble`
**Purpose**: Disassemble instructions starting from an address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Starting address |
| `count` | int | No | 10 | Number of instructions |

**Returns**:
```json
{
  "success": true,
  "start_address": "0x00400000",
  "instruction_count": 10,
  "instructions": [
    {"address": "0x00400000", "bytes": "55", "instruction": "push ebp", "size": 1},
    {"address": "0x00400001", "bytes": "8B EC", "instruction": "mov ebp,esp", "size": 2}
  ]
}
```

---

### `get_instruction_info`
**Purpose**: Get detailed information about a single instruction.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Instruction address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "instruction": "push ebp",
  "size": 1,
  "bytes": "55",
  "is_call": false,
  "is_jump": false,
  "is_ret": false
}
```

---

### `find_function_boundaries`
**Purpose**: Locate the start and end of a function containing the given address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Address within the function |
| `max_search` | int | No | 4096 | Maximum bytes to search |

**Returns**:
```json
{
  "success": true,
  "found": true,
  "query_address": "0x00401050",
  "function_start": "0x00401000",
  "function_end": "0x00401100",
  "function_size": 256
}
```

**Note**: Returns `found: false` if no standard prologue/epilogue is detected.

---

### `find_references`
**Purpose**: Find all code locations that reference a specific address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Target address to find references to |
| `limit` | int | No | 50 | Maximum results |

**Returns**:
```json
{
  "success": true,
  "target": "0x00401000",
  "count": 5,
  "references": [
    {"ref_address": "0x00402000", "instruction": "call 0x00401000"}
  ]
}
```

---

### `find_call_references`
**Purpose**: Find all CALL instructions that target a specific function.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `function_address` | string/int | Yes | - | Function address |
| `limit` | int | No | 100 | Maximum results |

**Returns**:
```json
{
  "success": true,
  "function_address": "0x00401000",
  "caller_count": 10,
  "callers": [
    {"caller_address": "0x00402050", "instruction": "call 0x00401000"}
  ]
}
```

---

### `analyze_function`
**Purpose**: Analyze a function to find all CALL instructions it makes.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Function address (start of function) |
| `max_instructions` | int | No | 200 | Maximum instructions to analyze |

**Returns**:
```json
{
  "success": true,
  "function_address": "0x00401000",
  "arch": "x64",
  "prologue_type": "x64_standard",
  "instructions_analyzed": 50,
  "calls_found": 5,
  "calls": [
    {
      "address": "0x00401020",
      "instruction": "call 0x00405000",
      "target": "0x00405000",
      "is_indirect": false
    },
    {
      "address": "0x00401035",
      "instruction": "call qword ptr [rax+10]",
      "target": "indirect",
      "is_indirect": true
    }
  ]
}
```

**Prologue Detection**:
- `x86_standard`: `55 8B EC` (push ebp; mov ebp, esp)
- `x64_standard`: `55 48 89 E5` (push rbp; mov rbp, rsp)
- `x64_leaf`: `48 83 EC xx` (sub rsp, xx) - leaf functions without frame pointer
- `unknown`: Non-standard or mid-function address

**Note**: Detects both direct CALL (E8) and indirect CALL (FF /2) instructions.

---

## 7. Breakpoints (Hardware Debug Registers)

> **Important**: All breakpoints use **hardware debug registers** (`bpmDebugRegister`) for anti-cheat safety. Maximum 4 breakpoints at a time (CPU limitation).

### `set_breakpoint` / `set_execution_breakpoint`
**Purpose**: Set a hardware breakpoint that triggers when code executes at the address.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Code address |
| `id` | string | No | address | Unique identifier for this breakpoint |
| `capture_registers` | bool | No | true | Capture CPU registers on hit |
| `capture_stack` | bool | No | false | Capture stack values |
| `stack_depth` | int | No | 16 | Number of stack entries to capture |

**Returns**:
```json
{
  "success": true,
  "id": "bp1",
  "address": "0x00401000",
  "slot": 1,
  "method": "hardware_debug_register"
}
```

---

### `set_data_breakpoint` / `set_write_breakpoint`
**Purpose**: Set a hardware breakpoint that triggers on memory read/write access.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Data address to monitor |
| `id` | string | No | address | Unique identifier |
| `access_type` | string | No | "w" | "r" (read), "w" (write), "rw" (both) |
| `size` | int | No | 4 | Bytes to monitor (1, 2, or 4) |

**Returns**:
```json
{
  "success": true,
  "id": "health_write",
  "address": "0x12345678",
  "slot": 2,
  "access_type": "w",
  "method": "hardware_debug_register"
}
```

---

### `get_breakpoint_hits`
**Purpose**: Retrieve logged breakpoint hits.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `id` | string | No | - | Specific breakpoint ID (omit for all) |
| `clear` | bool | No | true | Clear hits after retrieval |

**Returns**:
```json
{
  "success": true,
  "count": 5,
  "hits": [
    {
      "id": "bp1",
      "address": "0x00401000",
      "timestamp": 1733540000,
      "breakpoint_type": "hardware_execute",
      "registers": {"EAX": "0x00000001", "EBX": "0x00000000"}
    }
  ]
}
```

---

### `remove_breakpoint`
**Purpose**: Remove a breakpoint by ID.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `id` | string | Yes | Breakpoint ID to remove |

**Returns**:
```json
{
  "success": true,
  "id": "bp1"
}
```

---

### `list_breakpoints`
**Purpose**: List all active breakpoints.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 2,
  "breakpoints": [
    {"id": "bp1", "address": "0x00401000", "type": "execute", "slot": 1},
    {"id": "health_write", "address": "0x12345678", "type": "data", "slot": 2}
  ]
}
```

---

### `clear_all_breakpoints`
**Purpose**: Remove all active breakpoints.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "removed_count": 4
}
```

---

## 8. Memory Regions

### `get_memory_regions`
**Purpose**: Get memory regions using page protection sampling.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max` | int | No | 1000 | Maximum regions to return |

**Returns**:
```json
{
  "success": true,
  "count": 50,
  "regions": [
    {"address": "0x00400000", "readable": true, "writable": false, "executable": true}
  ]
}
```

---

### `enum_memory_regions_full`
**Purpose**: Get comprehensive memory map using native CE API.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max` | int | No | 10000 | Maximum regions |

**Returns**:
```json
{
  "success": true,
  "count": 500,
  "regions": [
    {
      "base_address": "0x00400000",
      "allocation_base": "0x00400000",
      "region_size": 4096,
      "state": "MEM_COMMIT",
      "protect": "PAGE_EXECUTE_READ",
      "type": "MEM_IMAGE",
      "readable": true,
      "writable": false,
      "executable": true
    }
  ]
}
```

---

## 9. Lua Evaluation

### `evaluate_lua`
**Purpose**: Execute arbitrary Lua code in Cheat Engine's context.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `code` | string | Yes | Lua code to execute |

**Returns**:
```json
{
  "success": true,
  "result": "return value as string"
}
```

**Example**:
```json
{"code": "return 1 + 1"}
→ {"success": true, "result": "2"}
```

> **Caution**: Use responsibly. Avoid infinite loops or memory-intensive operations.

---

## 10. High-Level Analysis Tools

### `dissect_structure`
**Purpose**: Automatically analyze memory and guess data types.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Base address |
| `size` | int | No | 256 | Bytes to analyze |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "size": 256,
  "element_count": 15,
  "elements": [
    {"offset": 0, "type": "Pointer", "size": 4, "value": "0x00401000"},
    {"offset": 4, "type": "4 Bytes", "size": 4, "value": "100"},
    {"offset": 8, "type": "Float", "size": 4, "value": "3.14159"}
  ]
}
```

---

### `get_thread_list`
**Purpose**: List all threads in the target process.

**Parameters**: None

**Returns**:
```json
{
  "success": true,
  "count": 8,
  "threads": ["1234", "5678", "9012"]
}
```

---

### `auto_assemble`
**Purpose**: Execute a Cheat Engine Auto Assembler script.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `script` | string | Yes | Auto Assembler script |

**Returns**:
```json
{
  "success": true,
  "message": "Script assembled successfully"
}
```

> **Warning**: This can modify game memory. Use with caution.

---

### `read_pointer_chain`
**Purpose**: Follow a chain of pointers to resolve a dynamic address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `base` | string/int | Yes | Base address or symbol |
| `offsets` | array | Yes | Array of offsets to apply |

**Returns**:
```json
{
  "success": true,
  "base": "0x00400000",
  "offsets": [60, 0, 24],
  "final_address": "0x12345678",
  "final_value": 100,
  "arch": "x86",
  "chain": [
    {"step": 0, "address": "0x00400000", "read_value": "0x00500000"},
    {"step": 1, "address": "0x00500000", "offset_applied": 60, "read_value": "0x00600000"},
    {"step": 2, "address": "0x00600018", "offset_applied": 24, "read_value": "0x12345678"}
  ]
}
```

**Note**: Uses `readPointer()` for all dereference operations, automatically handling 32-bit (4-byte) and 64-bit (8-byte) pointers.

---

### `get_rtti_classname`
**Purpose**: Get C++ class name from RTTI information.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Object address (pointer to vtable) |

**Returns**:
```json
{
  "success": true,
  "address": "0x12345678",
  "class_name": "CPlayer",
  "found": true
}
```

---

### `get_address_info`
**Purpose**: Convert a raw address to a symbolic name.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Memory address |
| `include_modules` | bool | No | true | Include module names |
| `include_symbols` | bool | No | true | Include symbol names |
| `include_sections` | bool | No | false | Include section names |

**Returns**:
```json
{
  "success": true,
  "address": "0x00401000",
  "symbolic_name": "L2.exe+1000",
  "is_in_module": true
}
```

---

### `checksum_memory`
**Purpose**: Calculate MD5 hash of a memory region.

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Start address |
| `size` | int | No | 256 | Bytes to hash |

**Returns**:
```json
{
  "success": true,
  "address": "0x00400000",
  "size": 256,
  "md5_hash": "d41d8cd98f00b204e9800998ecf8427e"
}
```

**Use Case**: Detect if game code has been modified (anti-tampering check).

---

### `generate_signature`
**Purpose**: Generate a unique AOB signature for an address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Target address |

**Returns**:
```json
{
  "success": true,
  "address": "0x00401000",
  "signature": "55 8B EC 83 EC ?? 53 56 57",
  "offset_from_start": 0,
  "byte_count": 10,
  "usage_hint": "aob_scan('55 8B EC 83 EC ?? 53 56 57') then add offset 0 to reach target"
}
```

> ⚠️ **Warning**: This command calls `getUniqueAOB()` which scans ALL memory to find unique patterns. It can take **several minutes** and will block the pipe. Use only on specific code addresses, not generic locations like PE headers.

**Use Case**: Find the same code location after game updates (signature scanning).

---

## 11. DBVM Hypervisor Tools (Ring -1)

> **These tools require DBVM to be activated** (Edit → Settings → Debugger → Use DBVM). They operate at the hypervisor level (Ring -1), making them **100% invisible to anti-cheat software**.

### `get_physical_address`
**Purpose**: Convert a virtual address to its physical RAM address.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Virtual memory address |

**Returns**:
```json
{
  "success": true,
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "physical_int": 439041101
}
```

**Note**: Requires DBK kernel driver to be loaded.

---

### `start_dbvm_watch` / `find_what_writes_safe`
**Purpose**: Start hypervisor-level memory access monitoring.

This is the **anti-cheat safe** equivalent of "Find what writes to this address".

**Parameters**:
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `address` | string/int | Yes | - | Address to monitor |
| `mode` | string | No | "w" | "w" (write), "r" (read), "rw" (both), "x" (execute) |
| `max_entries` | int | No | 1000 | Log buffer size |

**Returns**:
```json
{
  "success": true,
  "status": "monitoring",
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "watch_id": 1,
  "mode": "w",
  "note": "Call stop_dbvm_watch to retrieve results and stop monitoring"
}
```

---

### `stop_dbvm_watch` / `get_watch_results`
**Purpose**: Stop monitoring and retrieve all logged memory accesses.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string/int | Yes | Address that was being monitored |

**Returns**:
```json
{
  "success": true,
  "virtual_address": "0x12345678",
  "physical_address": "0x1A2B3C4D",
  "mode": "w",
  "hit_count": 3,
  "duration_seconds": 10,
  "hits": [
    {
      "hit_number": 1,
      "instruction_address": "0x00402000",
      "instruction": "mov [ecx+4], eax",
      "registers": {
        "RAX": "0x00000064",
        "RCX": "0x12345674",
        "RIP": "0x00402000"
      }
    }
  ],
  "note": "Found instructions that accessed the memory"
}
```

---

## Workflow Examples

### Example 1: Find and Monitor Health Value

```
1. scan_all(value="100", value_type="4Bytes")
2. get_scan_results() → [0x12345678, ...]
3. start_dbvm_watch(address="0x12345678", mode="w")
4. [Player takes damage in game]
5. stop_dbvm_watch(address="0x12345678")
   → Shows instruction at 0x00402000 wrote to health
6. disassemble(address="0x00402000", count=20)
   → Understand the damage calculation code
7. generate_signature(address="0x00402000")
   → Create AOB for future updates
```

### Example 2: Trace Pointer Chain

```
1. get_process_info() → main module at 0x00400000
2. read_pointer_chain(base="0x00400000", offsets=[0x1000, 0x10, 0x4])
   → Resolves to player structure at 0x12345678
3. dissect_structure(address="0x12345678", size=512)
   → Auto-detect fields (health at offset +0x100, mana at +0x104, etc.)
```

### Example 3: Find All Callers of a Function

```
1. aob_scan(pattern="55 8B EC 83 EC ?? A1 ?? ?? ?? ??")
   → Function at 0x00401000
2. find_call_references(function_address="0x00401000")
   → 15 callers found
3. For each caller, use disassemble() to understand context
```

---

## Error Handling

All commands return `success: false` with an `error` message on failure:

```json
{
  "success": false,
  "error": "Invalid address"
}
```

Common errors:
- `"Invalid address"` - Address could not be parsed
- `"Failed to read at 0x..."` - Memory is not readable
- `"No free hardware breakpoint slots"` - All 4 debug registers in use
- `"DBK driver not loaded"` - DBVM/DBK not initialized
- `"DBVM watch returned nil"` - DBVM not activated in CE settings

---

## Best Practices

1. **Always call `ping` first** to verify connectivity
2. **Use `get_process_info`** to confirm the correct process is attached and check `targetIs64Bit`
3. **Prefer DBVM tools** over breakpoints for anti-cheat safety
4. **Clear breakpoints** when done to free debug register slots
5. **Generate signatures** for important addresses to survive game updates
6. **Use `checksum_memory`** to detect if code regions have changed
7. **Use `analyze_function`** to understand what a function calls before hooking
8. **Check `arch` field** in responses to verify 32/64-bit handling
