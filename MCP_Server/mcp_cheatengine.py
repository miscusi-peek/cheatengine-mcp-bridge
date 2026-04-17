import sys
import os

# ============================================================================
# CRITICAL: WINDOWS LINE ENDING FIX FOR MCP (MONKEY-PATCH)
# The MCP SDK's stdio_server uses TextIOWrapper without newline='\n', causing
# Windows to output CRLF (\r\n) instead of LF (\n). This causes the error:
# "invalid trailing data at the end of stream"
# We MUST patch the MCP SDK BEFORE importing FastMCP.
# ============================================================================

if sys.platform == "win32":
    import msvcrt
    from io import TextIOWrapper
    from contextlib import asynccontextmanager
    
    # Set binary mode on underlying file handles
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    
    # Monkey-patch the MCP SDK's stdio_server to use newline='\n'
    import mcp.server.stdio as mcp_stdio
    import anyio
    import anyio.lowlevel
    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
    import mcp.types as types
    from mcp.shared.message import SessionMessage
    
    @asynccontextmanager
    async def _patched_stdio_server(
        stdin: "anyio.AsyncFile[str] | None" = None,
        stdout: "anyio.AsyncFile[str] | None" = None,
    ):
        """Patched stdio_server with proper Windows newline handling."""
        if not stdin:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdin = anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline='\n'))
        if not stdout:
            # Use newline='\n' to prevent CRLF translation on Windows
            stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline='\n'))

        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        async def stdin_reader():
            try:
                async with read_stream_writer:
                    async for line in stdin:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_stream_writer.send(exc)
                            continue
                        session_message = SessionMessage(message)
                        await read_stream_writer.send(session_message)
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async def stdout_writer():
            try:
                async with write_stream_reader:
                    async for session_message in write_stream_reader:
                        json = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                        await stdout.write(json + "\n")
                        await stdout.flush()
            except anyio.ClosedResourceError:
                await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            yield read_stream, write_stream
    
    # Apply the monkey-patch
    mcp_stdio.stdio_server = _patched_stdio_server

# ============================================================================
# STDOUT PROTECTION FOR MCP
# MCP uses stdout for JSON-RPC. ANY stray output corrupts it.
# ============================================================================

# Save original stdout for MCP to use
_mcp_stdout = sys.stdout

# Redirect stdout to stderr so any accidental prints go to logs, not MCP stream
sys.stdout = sys.stderr

# Now safe to import libraries that might print during import
import json
import struct
import time
import traceback

try:
    import win32file
    import win32pipe
    import win32con
    import pywintypes
    from mcp.server.fastmcp import FastMCP
    
    # CRITICAL: Also patch the reference inside the fastmcp module
    # FastMCP already imported stdio_server before our patch, so we need to update its reference too
    if sys.platform == "win32":
        import mcp.server.fastmcp.server as fastmcp_server
        fastmcp_server.stdio_server = _patched_stdio_server
        
except ImportError as e:
    print(f"[MCP CE] Import Error: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout

# Debug helper - always goes to stderr, never corrupts MCP
def debug_log(msg):
    print(f"[MCP CE] {msg}", file=sys.stderr, flush=True)

# Helper to format results as proper JSON strings for MCP tools
def format_result(result):
    """Format CE Bridge result as a proper JSON string for AI consumption."""
    if isinstance(result, dict):
        return json.dumps(result, indent=None, ensure_ascii=False)
    elif isinstance(result, str):
        return result  # Already a string
    else:
        return json.dumps(result)

# ============================================================================
# CONFIGURATION
# ============================================================================

# V11 Bridge uses 'CE_MCP_Bridge_v99'
PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
MCP_SERVER_NAME = "cheatengine"

# ============================================================================
# PIPE CLIENT
# ============================================================================

class CEBridgeClient:
    def __init__(self):
        self.handle = None

    def connect(self):
        """Attempts to connect to the CE Named Pipe."""
        try:
            self.handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            return True
        except pywintypes.error as e:
            # sys.stderr.write(f"[CEBridge] Connect Error: {e}\n")
            return False

    def send_command(self, method, params=None):
        """Send command to CE Bridge with auto-reconnection on failure."""
        max_retries = 2
        last_error = None
        
        for attempt in range(max_retries):
            if not self.handle:
                if not self.connect():
                    raise ConnectionError("Cheat Engine Bridge (v11/v99) is not running (Pipe not found).")

            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
                "id": int(time.time() * 1000)
            }
            
            try:
                req_json = json.dumps(request).encode('utf-8')
                header = struct.pack('<I', len(req_json))
                
                win32file.WriteFile(self.handle, header)
                win32file.WriteFile(self.handle, req_json)
                
                resp_header_buffer = win32file.ReadFile(self.handle, 4)[1]
                if len(resp_header_buffer) < 4:
                    self.close()
                    last_error = ConnectionError("Incomplete response header from CE.")
                    continue  # Retry
                    
                resp_len = struct.unpack('<I', resp_header_buffer)[0]
                
                if resp_len > 32 * 1024 * 1024:
                    self.close()
                    raise ConnectionError(f"Response too large: {resp_len} bytes")

                resp_body_buffer = win32file.ReadFile(self.handle, resp_len)[1]
                
                try:
                    response = json.loads(resp_body_buffer.decode('utf-8'))
                except json.JSONDecodeError:
                    self.close()
                    last_error = ConnectionError("Invalid JSON received from CE")
                    continue  # Retry
                
                if 'error' in response:
                    return {"success": False, "error": str(response['error'])}
                if 'result' in response:
                    return response['result']
                    
                return response

            except pywintypes.error as e:
                self.close()
                last_error = ConnectionError(f"Pipe Communication failed: {e}")
                if attempt < max_retries - 1:
                    continue  # Retry
        
        # All retries failed
        if last_error:
            raise last_error
        raise ConnectionError("Unknown communication error")

    def close(self):
        if self.handle:
            try:
                win32file.CloseHandle(self.handle)
            except:
                pass
            self.handle = None

ce_client = CEBridgeClient()

# ============================================================================
# MCP SERVER - v11 IMPLEMENTATION
# ============================================================================

mcp = FastMCP(MCP_SERVER_NAME)

# --- PROCESS & MODULES ---

@mcp.tool()
def get_process_info() -> str:
    """Get current process ID, name, modules count and architecture."""
    return format_result(ce_client.send_command("get_process_info"))

@mcp.tool()
def enum_modules(offset: int = 0, limit: int = 100) -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum modules to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, modules.
    """
    return format_result(ce_client.send_command("enum_modules", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_thread_list(offset: int = 0, limit: int = 100) -> str:
    """Get list of threads in the attached process.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum threads to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, threads.
    """
    return format_result(ce_client.send_command("get_thread_list", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_symbol_address(symbol: str) -> str:
    """Resolve a symbol name (e.g., 'Engine.GameEngine') to an address."""
    return format_result(ce_client.send_command("get_symbol_address", {"symbol": symbol}))

@mcp.tool()
def get_address_info(address: str, include_modules: bool = True, include_symbols: bool = True, include_sections: bool = False) -> str:
    """Get symbolic name and module info for an address (Reverse of get_symbol_address)."""
    return format_result(ce_client.send_command("get_address_info", {
        "address": address, 
        "include_modules": include_modules, 
        "include_symbols": include_symbols,
        "include_sections": include_sections
    }))

@mcp.tool()
def get_rtti_classname(address: str) -> str:
    """Try to identify the class name of an object at address using Run-Time Type Information."""
    return format_result(ce_client.send_command("get_rtti_classname", {"address": address}))

# --- MEMORY READING ---

@mcp.tool()
def read_memory(address: str, size: int = 256) -> str:
    """Read raw bytes from memory."""
    return format_result(ce_client.send_command("read_memory", {"address": address, "size": size}))

@mcp.tool()
def read_integer(address: str, type: str = "dword") -> str:
    """Read a number from memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("read_integer", {"address": address, "type": type}))

@mcp.tool()
def read_string(address: str, max_length: int = 256, wide: bool = False, encoding: str = "utf8") -> str:
    """Read a string from memory.

    Args:
        address: Memory address to read from.
        max_length: Maximum number of bytes to read.
        wide: Legacy flag — when True, overrides encoding to 'utf16le' for backward compat.
        encoding: One of 'ascii', 'utf8' (default), 'utf16le', or 'raw'.
                  'ascii': strip non-printable bytes.
                  'utf8': preserve valid UTF-8 multi-byte sequences.
                  'utf16le': read as wide (UTF-16 LE) string.
                  'raw': return bytes as a hex string (e.g. '48 65 6C 6C 6F').

    Returns JSON with: success, address, value, encoding, wide, length, raw_length.
    """
    # Backward compat: wide=True maps to utf16le unless caller also set encoding explicitly
    resolved_encoding = "utf16le" if wide else encoding
    return format_result(ce_client.send_command("read_string", {"address": address, "max_length": max_length, "wide": wide, "encoding": resolved_encoding}))

@mcp.tool()
def read_pointer(address: str, offsets: list[int] = None) -> str:
    """Read a pointer chain. Returns the final address and value."""
    # V11 supports 'read_pointer' command for simple dereference or 'read_pointer_chain' for multiple
    if offsets:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": offsets}))
    else:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": [0]}))

@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(ce_client.send_command("read_pointer_chain", {"base": base, "offsets": offsets}))

@mcp.tool()
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(ce_client.send_command("checksum_memory", {"address": address, "size": size}))

# --- SCANNING ---

@mcp.tool()
def scan_all(value: str, type: str = "exact", protection: str = "+W-C") -> str:
    """Unified Memory Scanner. Types: exact, string, array. Protection: +W-C (Writable, Not Copy-on-Write)."""
    return format_result(ce_client.send_command("scan_all", {"value": value, "type": type, "protection": protection}))

@mcp.tool()
def get_scan_results(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Get results from the last 'scan_all' operation.

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum results to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, results.
    """
    return format_result(ce_client.send_command("get_scan_results", {"offset": offset, "limit": limit, "max": max}))

@mcp.tool()
def next_scan(value: str, scan_type: str = "exact") -> str:
    """Next scan to filter results. Types: exact, increased, decreased, changed, unchanged, bigger, smaller."""
    return format_result(ce_client.send_command("next_scan", {"value": value, "scan_type": scan_type}))

@mcp.tool()
def write_integer(address: str, value: int, type: str = "dword") -> str:
    """Write a number to memory. Types: byte, word, dword, qword, float, double."""
    return format_result(ce_client.send_command("write_integer", {"address": address, "value": value, "type": type}))

@mcp.tool()
def write_memory(address: str, bytes: list[int]) -> str:
    """Write raw bytes to memory."""
    return format_result(ce_client.send_command("write_memory", {"address": address, "bytes": bytes}))

@mcp.tool()
def write_string(address: str, value: str, wide: bool = False) -> str:
    """Write a string to memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("write_string", {"address": address, "value": value, "wide": wide}))


@mcp.tool()
def aob_scan(pattern: str, protection: str = "+X", limit: int = 100) -> str:
    """Scan for an Array of Bytes (AOB) pattern. Example: '48 89 5C 24'."""
    return format_result(ce_client.send_command("aob_scan", {"pattern": pattern, "protection": protection, "limit": limit}))

@mcp.tool()
def search_string(string: str, wide: bool = False, limit: int = 100) -> str:
    """Quickly search for a text string in memory."""
    return format_result(ce_client.send_command("search_string", {"string": string, "wide": wide, "limit": limit}))

@mcp.tool()
def generate_signature(address: str) -> str:
    """Generate a unique AOB signature that can find this specific address again."""
    return format_result(ce_client.send_command("generate_signature", {"address": address}))

@mcp.tool()
def get_memory_regions(max: int = 100) -> str:
    """Get list of valid memory regions nearby common bases."""
    return format_result(ce_client.send_command("get_memory_regions", {"max": max}))

@mcp.tool()
def enum_memory_regions_full(offset: int = 0, limit: int = 100, max: int = None) -> str:
    """Enumerate ALL memory regions in the process (Native EnumMemoryRegions).

    Args:
        offset: Start index for pagination (default 0).
        limit: Maximum regions to return (default 100, max 10000). Preferred over 'max'.
        max: Deprecated alias for 'limit'. Use 'limit' instead.

    Returns JSON with: success, total, offset, limit, returned, regions.
    """
    return format_result(ce_client.send_command("enum_memory_regions_full", {"offset": offset, "limit": limit, "max": max}))

# --- ANALYSIS & DISASSEMBLY ---

@mcp.tool()
def disassemble(address: str, count: int = 20, offset: int = 0, limit: int = 100) -> str:
    """Disassemble instructions starting at an address.

    Args:
        address: Target address (hex string or symbol).
        count: Number of instructions to generate (default 20).
        offset: Start index within the generated list for pagination (default 0).
        limit: Maximum instructions to return (default 100, max 10000).

    Returns JSON with: success, start_address, total, offset, limit, returned, instructions.
    """
    return format_result(ce_client.send_command("disassemble", {"address": address, "count": count, "offset": offset, "limit": limit}))

@mcp.tool()
def get_instruction_info(address: str) -> str:
    """Get detailed info about a single instruction (size, bytes, opcode)."""
    return format_result(ce_client.send_command("get_instruction_info", {"address": address}))

@mcp.tool()
def find_function_boundaries(address: str, max_search: int = 4096) -> str:
    """Attempt to find the start and end of a function containing the address."""
    return format_result(ce_client.send_command("find_function_boundaries", {"address": address, "max_search": max_search}))

@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze a function to find all CALL instructions output (calls made by this function)."""
    return format_result(ce_client.send_command("analyze_function", {"address": address}))

@mcp.tool()
def find_references(address: str, offset: int = 0, limit: int = 50) -> str:
    """Find instructions that access (reference) this address.

    Args:
        address: Target address to find references to.
        offset: Start index for pagination (default 0).
        limit: Maximum references to return (default 50, max 10000).

    Returns JSON with: success, target, total, offset, limit, returned, references, arch.
    """
    return format_result(ce_client.send_command("find_references", {"address": address, "offset": offset, "limit": limit}))

@mcp.tool()
def find_call_references(function_address: str, offset: int = 0, limit: int = 100) -> str:
    """Find all locations that CALL this function.

    Args:
        function_address: Address of the function to find callers of.
        offset: Start index for pagination (default 0).
        limit: Maximum callers to return (default 100, max 10000).

    Returns JSON with: success, function_address, total, offset, limit, returned, callers.
    """
    return format_result(ce_client.send_command("find_call_references", {"address": function_address, "offset": offset, "limit": limit}))

@mcp.tool()
def dissect_structure(address: str, size: int = 256) -> str:
    """Use CE's auto-guess feature to interpret memory at address as a structure."""
    return format_result(ce_client.send_command("dissect_structure", {"address": address, "size": size}))

# --- DEBUGGING & BREAKPOINTS ---

@mcp.tool()
def set_breakpoint(address: str, id: str = None, capture_registers: bool = True, capture_stack: bool = False, stack_depth: int = 16) -> str:
    """Set a hardware execution breakpoint. Non-breaking/Logging only."""
    return format_result(ce_client.send_command("set_breakpoint", {
        "address": address, 
        "id": id,
        "capture_registers": capture_registers,
        "capture_stack": capture_stack,
        "stack_depth": stack_depth
    }))

@mcp.tool()
def set_data_breakpoint(address: str, id: str = None, access_type: str = "w", size: int = 4) -> str:
    """Set a hardware data breakpoint (watchpoint). Types: 'r' (read), 'w' (write), 'rw' (access)."""
    return format_result(ce_client.send_command("set_data_breakpoint", {
        "address": address, 
        "id": id,
        "access_type": access_type,
        "size": size
    }))

@mcp.tool()
def remove_breakpoint(id: str) -> str:
    """Remove a breakpoint by its ID."""
    return format_result(ce_client.send_command("remove_breakpoint", {"id": id}))

@mcp.tool()
def list_breakpoints() -> str:
    """List all active breakpoints."""
    return format_result(ce_client.send_command("list_breakpoints"))

@mcp.tool()
def clear_all_breakpoints() -> str:
    """Remove ALL breakpoints."""
    return format_result(ce_client.send_command("clear_all_breakpoints"))

@mcp.tool()
def get_breakpoint_hits(id: str = None, clear: bool = False, offset: int = 0, limit: int = 100) -> str:
    """Get hits for a specific breakpoint ID (or all if None). Set clear=True to flush buffer.

    Args:
        id: Breakpoint ID to query, or None for all breakpoints.
        clear: If True, flush the hit buffer after reading (default False).
        offset: Start index for pagination (default 0).
        limit: Maximum hits to return (default 100, max 10000).

    Returns JSON with: success, total, offset, limit, returned, hits.
    """
    return format_result(ce_client.send_command("get_breakpoint_hits", {"id": id, "clear": clear, "offset": offset, "limit": limit}))

# --- DBVM / HYPERVISOR TOOLS (Ring -1) ---

@mcp.tool()
def get_physical_address(address: str) -> str:
    """Translate Virtual Address to Physical Address (requires DBVM)."""
    return format_result(ce_client.send_command("get_physical_address", {"address": address}))

@mcp.tool()
def start_dbvm_watch(address: str, mode: str = "w", max_entries: int = 1000) -> str:
    """Start invisible DBVM hypervisor watch. Modes: 'w' (writes), 'r' (reads), 'x' (execute)."""
    return format_result(ce_client.send_command("start_dbvm_watch", {"address": address, "mode": mode, "max_entries": max_entries}))

@mcp.tool()
def stop_dbvm_watch(address: str) -> str:
    """Stop DBVM watch and return results."""
    return format_result(ce_client.send_command("stop_dbvm_watch", {"address": address}))

@mcp.tool()
def poll_dbvm_watch(address: str, max_results: int = 1000) -> str:
    """Poll DBVM watch logs WITHOUT stopping. Returns register state at each execution hit."""
    return format_result(ce_client.send_command("poll_dbvm_watch", {
        "address": address, 
        "max_results": max_results
    }))

# --- SCRIPTING & CONTROL ---

@mcp.tool()
def evaluate_lua(code: str) -> str:
    """Execute arbitrary Lua code in Cheat Engine."""
    return format_result(ce_client.send_command("evaluate_lua", {"code": code}))

@mcp.tool()
def auto_assemble(script: str) -> str:
    """Run an AutoAssembler script (injection, code caves, etc)."""
    return format_result(ce_client.send_command("auto_assemble", {"script": script}))

@mcp.tool()
def assemble_instruction(
    line: str,
    address: str = None,
    preference: int = 0,
    skip_range_check: bool = False,
) -> str:
    """Assemble a single x86/x64 instruction into bytes.

    Requires an attached process when an address is given (the address is used to
    resolve relative operands such as JMP targets).

    Returns {success, bytes: [int], size: int}.
    preference: 0=none, 1=short, 2=long, 3=far.
    """
    params: dict = {"line": line, "preference": preference, "skip_range_check": skip_range_check}
    if address is not None:
        params["address"] = address
    return format_result(ce_client.send_command("assemble_instruction", params))


@mcp.tool()
def auto_assemble_check(
    script: str,
    enable: bool = True,
    target_self: bool = False,
) -> str:
    """Validate an Auto Assembler script for syntax errors without executing it.

    Returns {success, valid: bool, errors: [str]}.
    enable: True checks the [Enable] section; False checks [Disable].
    target_self: if True, validates against CE's own process instead of the target.
    """
    return format_result(ce_client.send_command("auto_assemble_check", {
        "script": script,
        "enable": enable,
        "target_self": target_self,
    }))


@mcp.tool()
def compile_c_code(
    source: str,
    address: str = None,
    target_self: bool = False,
    kernelmode: bool = False,
) -> str:
    """Compile C source code using CE's built-in TCC compiler.

    Does not require an attached process unless an address is provided.
    Returns {success, symbols: {name: address}, errors: [str]}.
    If TCC is unavailable: {success=false, error="TCC compiler not available",
    error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "target_self": target_self, "kernelmode": kernelmode}
    if address is not None:
        params["address"] = address
    return format_result(ce_client.send_command("compile_c_code", params))


@mcp.tool()
def compile_cs_code(
    source: str,
    references: list = None,
    core_assembly: str = None,
) -> str:
    """Compile C# source code using CE's .NET compiler (requires .NET 4+).

    Returns {success, assembly_handle: str} where assembly_handle is the path to
    the generated assembly. On .NET runtime absent:
    {success=false, error_code="CE_API_UNAVAILABLE"}.
    """
    params: dict = {"source": source, "references": references or []}
    if core_assembly is not None:
        params["core_assembly"] = core_assembly
    return format_result(ce_client.send_command("compile_cs_code", params))


@mcp.tool()
def generate_api_hook_script(
    address: str,
    target_address: str,
    code_to_execute: str = "",
) -> str:
    """Generate an Auto Assembler script that hooks a function and redirects it.

    Requires an attached process. address is the function to hook;
    target_address is where execution should jump after the hook.
    code_to_execute is optional extra AA code inserted into the generated script.
    Returns {success, script: str}.
    """
    return format_result(ce_client.send_command("generate_api_hook_script", {
        "address": address,
        "target_address": target_address,
        "code_to_execute": code_to_execute,
    }))


@mcp.tool()
def generate_code_injection_script(address: str) -> str:
    """Generate a boilerplate code-injection Auto Assembler script for an address.

    Requires an attached process.
    Returns {success, script: str} — the script can be used as a starting point
    for patching code at that location.
    """
    return format_result(ce_client.send_command("generate_code_injection_script", {
        "address": address,
    }))


@mcp.tool()
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(ce_client.send_command("ping"))

# --- UNIT 15: ADVANCED SCANNING ---

@mcp.tool()
def aob_scan_unique(pattern: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern that must match exactly once. Returns {success, address} or error with count.
    Use this when you expect a signature to be unique in the process."""
    return format_result(ce_client.send_command("aob_scan_unique", {"pattern": pattern, "protection": protection}))

@mcp.tool()
def aob_scan_module(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern restricted to a specific module's memory range.
    Returns {success, count, addresses: [str]}."""
    return format_result(ce_client.send_command("aob_scan_module", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@mcp.tool()
def aob_scan_module_unique(pattern: str, module_name: str, protection: str = "+X") -> str:
    """Scan for an AOB pattern in a specific module that must match exactly once.
    Returns {success, address} or error with count."""
    return format_result(ce_client.send_command("aob_scan_module_unique", {
        "pattern": pattern,
        "module_name": module_name,
        "protection": protection
    }))

@mcp.tool()
def pointer_rescan(value: str, previous_results_file: str = None) -> str:
    """Re-scan an existing pointer scan for a new value. Requires a prior pointer scan in CE.
    Returns {success, result_count}. Run a Pointer Scanner scan in CE first."""
    params = {"value": value}
    if previous_results_file:
        params["previous_results_file"] = previous_results_file
    return format_result(ce_client.send_command("pointer_rescan", params))

@mcp.tool()
def create_persistent_scan(name: str) -> str:
    """Create a named, stateful memory scan session. Use the name with persistent_scan_* tools.
    Returns {success, scan_name}."""
    return format_result(ce_client.send_command("create_persistent_scan", {"name": name}))

@mcp.tool()
def persistent_scan_first_scan(name: str, value: str, type: str = "dword", scan_option: str = "exact") -> str:
    """Run the first scan on a named persistent scan session.
    Types: byte, word, dword, qword, float, double, string.
    Scan options: exact, unknown, between, bigger, smaller.
    Returns {success, scan_name, count}."""
    return format_result(ce_client.send_command("persistent_scan_first_scan", {
        "name": name,
        "value": value,
        "type": type,
        "scan_option": scan_option
    }))

@mcp.tool()
def persistent_scan_next_scan(name: str, value: str = None, scan_option: str = "exact") -> str:
    """Narrow down results with a next scan on a named persistent scan session.
    Scan options: exact, increased, decreased, changed, unchanged, bigger, smaller.
    Returns {success, scan_name, count}."""
    params = {"name": name, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    return format_result(ce_client.send_command("persistent_scan_next_scan", params))

@mcp.tool()
def persistent_scan_get_results(name: str, offset: int = 0, limit: int = 100) -> str:
    """Get paginated results from a named persistent scan session.
    Returns {success, total, offset, limit, results: [{address, value}]}."""
    return format_result(ce_client.send_command("persistent_scan_get_results", {
        "name": name,
        "offset": offset,
        "limit": limit
    }))

@mcp.tool()
def persistent_scan_destroy(name: str) -> str:
    """Destroy a named persistent scan session and free its memory.
    Returns {success, scan_name, destroyed}."""
    return format_result(ce_client.send_command("persistent_scan_destroy", {"name": name}))
# --- MEMORY OPERATIONS (Unit 14) ---

@mcp.tool()
def copy_memory(source: str, size: int, dest: str = None, method: int = 0) -> str:
    """Copy memory between addresses. Methods: 0=target→target, 1=target→CE, 2=CE→target, 3=CE→CE. Returns dest_address allocated by CE if dest is None."""
    return format_result(ce_client.send_command("copy_memory", {
        "source": source, "size": size, "dest": dest, "method": method
    }))

@mcp.tool()
def compare_memory(addr1: str, addr2: str, size: int, method: int = 0) -> str:
    """Compare two memory regions. Methods: 0=target/target, 1=addr1=target addr2=CE, 2=both CE. Returns equal flag and first_diff byte index (-1 if equal)."""
    return format_result(ce_client.send_command("compare_memory", {
        "addr1": addr1, "addr2": addr2, "size": size, "method": method
    }))

@mcp.tool()
def write_region_to_file(address: str, size: int, filename: str) -> str:
    """Write a memory region to a file. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("write_region_to_file", {
        "address": address, "size": size, "filename": filename
    }))

@mcp.tool()
def read_region_from_file(filename: str, destination: str) -> str:
    """Read a file into memory at the given destination address. Filename must be an absolute path and must not contain '..' components."""
    return format_result(ce_client.send_command("read_region_from_file", {
        "filename": filename, "destination": destination
    }))

@mcp.tool()
def md5_memory(address: str, size: int) -> str:
    """Calculate the MD5 hash of a memory region. Returns the hash as a hex string."""
    return format_result(ce_client.send_command("md5_memory", {
        "address": address, "size": size
    }))

@mcp.tool()
def md5_file(filename: str) -> str:
    """Calculate the MD5 hash of a file on the CE host. Filename must not contain '..' components."""
    return format_result(ce_client.send_command("md5_file", {"filename": filename}))

@mcp.tool()
def create_section(size: int) -> str:
    """Create a Windows section (shared memory) of the given size. Returns a handle as a hex string."""
    return format_result(ce_client.send_command("create_section", {"size": size}))

@mcp.tool()
def map_view_of_section(handle: str, address: str = None, size: int = 0) -> str:
    """Map a section into the target process. 'handle' is from create_section. 'address' is optional preferred base. Returns mapped_address."""
    return format_result(ce_client.send_command("map_view_of_section", {
        "handle": handle, "address": address, "size": size
    }))

# >>> BEGIN UNIT-12 Symbol Management <<<
@mcp.tool()
def register_symbol(name: str, address: str, do_not_save: bool = False) -> str:
    """Register a user-defined symbol with a given name and address.

    Args:
        name: Symbol name to register.
        address: Address to bind to the symbol (hex string or decimal).
        do_not_save: If True, this symbol is not persisted when the CE table is saved.

    Returns JSON with: success, name, address.
    """
    return format_result(ce_client.send_command("register_symbol", {
        "name": name, "address": address, "do_not_save": do_not_save
    }))

@mcp.tool()
def unregister_symbol(name: str) -> str:
    """Remove a previously registered user-defined symbol.

    Args:
        name: Symbol name to unregister.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("unregister_symbol", {"name": name}))

@mcp.tool()
def enum_registered_symbols() -> str:
    """List all user-registered symbols.

    Returns JSON with: success, count, symbols (list of {name, address, module}).
    """
    return format_result(ce_client.send_command("enum_registered_symbols"))

@mcp.tool()
def delete_all_registered_symbols() -> str:
    """Delete every user-registered symbol (both AA and Lua).

    Returns JSON with: success, deleted_count.
    """
    return format_result(ce_client.send_command("delete_all_registered_symbols"))

@mcp.tool()
def enable_windows_symbols() -> str:
    """Trigger download and load of Windows PDB symbol files.

    Note: The actual PDB download and indexing is asynchronous; this call returns
    immediately once the process has been initiated by Cheat Engine.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("enable_windows_symbols"))

@mcp.tool()
def enable_kernel_symbols() -> str:
    """Enable kernel-mode symbol resolution (requires DBK driver).

    Returns JSON with: success.
    On failure returns error_code DBK_NOT_LOADED if the kernel driver is absent.
    """
    return format_result(ce_client.send_command("enable_kernel_symbols"))

@mcp.tool()
def get_symbol_info(name: str) -> str:
    """Retrieve detailed information about a known symbol.

    Requires an attached process.

    Args:
        name: Symbol or export name to look up.

    Returns JSON with: success, name, address, module, size.
    Returns error_code NOT_FOUND if the symbol is unknown.
    """
    return format_result(ce_client.send_command("get_symbol_info", {"name": name}))

@mcp.tool()
def get_module_size(module_name: str) -> str:
    """Get the in-memory size of a loaded module.

    Requires an attached process.

    Args:
        module_name: Module filename (e.g. 'kernel32.dll').

    Returns JSON with: success, size.
    """
    return format_result(ce_client.send_command("get_module_size", {"module_name": module_name}))

@mcp.tool()
def load_new_symbols() -> str:
    """Scan for newly loaded modules and import their symbols.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_new_symbols"))

@mcp.tool()
def reinitialize_symbol_handler() -> str:
    """Perform a full reset and reload of the Cheat Engine symbol handler.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("reinitialize_symbol_handler"))
# >>> END UNIT-12 <<<
# --- UNIT-11: DEBUG CONTEXT + PER-THREAD BREAKPOINTS ---

@mcp.tool()
def debug_get_context(extra_regs: bool = False) -> str:
    """Get the current thread's CPU register context. Set extra_regs=True to include XMM0-15 and FP0-7."""
    return format_result(ce_client.send_command("debug_get_context", {"extra_regs": extra_regs}))

@mcp.tool()
def debug_set_context(registers: dict) -> str:
    """Set CPU register values in the paused thread. Pass a dict like {\"RAX\": \"0x1234\", \"RIP\": \"0x140001000\"}."""
    return format_result(ce_client.send_command("debug_set_context", {"registers": registers}))

@mcp.tool()
def debug_get_xmm_pointer(xmm_nr: int = 0) -> str:
    """Return the CE-local memory address of an XMM register (0-15) for the currently broken thread."""
    return format_result(ce_client.send_command("debug_get_xmm_pointer", {"xmm_nr": xmm_nr}))

@mcp.tool()
def debug_set_last_branch_recording(enable: bool) -> str:
    """Enable or disable Intel LBR (Last Branch Recording). Requires kernel-mode debugger."""
    return format_result(ce_client.send_command("debug_set_last_branch_recording", {"enable": enable}))

@mcp.tool()
def debug_get_last_branch_record(index: int) -> str:
    """Get the from/to addresses of a Last Branch Record entry at the given index."""
    return format_result(ce_client.send_command("debug_get_last_branch_record", {"index": index}))

@mcp.tool()
def debug_set_breakpoint_for_thread(thread_id: int, address: str, size: int = 1, trigger: str = "execute") -> str:
    """Set a breakpoint that fires only on a specific thread. trigger: execute|write|read|access."""
    return format_result(ce_client.send_command("debug_set_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
        "size": size,
        "trigger": trigger,
    }))

@mcp.tool()
def debug_remove_breakpoint_for_thread(thread_id: int, address: str) -> str:
    """Remove a per-thread breakpoint at the given address for the given thread."""
    return format_result(ce_client.send_command("debug_remove_breakpoint_for_thread", {
        "thread_id": thread_id,
        "address": address,
    }))

# --- DEBUGGER CONTROL (Unit 10) ---

@mcp.tool()
def debug_process(interface: int = 0) -> str:
    """Start the CE debugger for the currently opened process.

    interface: CE debugger interface enum.
      0 = default, 1 = Windows native, 2 = VEH debugger,
      3 = kernel debugger (DBK), 4 = DBVM.
    Requires a process to be attached. Returns {success, interface_used, interface_name}.
    """
    return format_result(ce_client.send_command("debug_process", {"interface": interface}))

@mcp.tool()
def debug_is_debugging() -> str:
    """Check whether the CE debugger has been started.

    Always safe to call; no process guard. Returns {success, is_debugging: bool}.
    """
    return format_result(ce_client.send_command("debug_is_debugging"))

@mcp.tool()
def debug_get_current_debugger_interface() -> str:
    """Return the active debugger interface used by CE.

    Returns {success, interface: int | null, interface_name: str}.
    interface_name values: 'windows_native', 'veh', 'kernel', 'mac_native', 'gdb', 'none'.
    """
    return format_result(ce_client.send_command("debug_get_current_debugger_interface"))

@mcp.tool()
def debug_break_thread(thread_id: int) -> str:
    """Break a specific thread by its thread ID.

    The thread may not stop instantly — it must be scheduled to run first.
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("debug_break_thread", {"thread_id": thread_id}))

@mcp.tool()
def debug_continue(method: str = "run") -> str:
    """Continue execution from a breakpoint.

    method: one of 'run' (co_run), 'step_into' (co_stepinto), 'step_over' (co_stepover).
    Requires the debugger to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("debug_continue", {"method": method}))

@mcp.tool()
def debug_detach() -> str:
    """Detach the debugger from the target process if possible.

    Returns {success, detached: bool}. Safe to call when no debugger is active.
    """
    return format_result(ce_client.send_command("debug_detach"))

@mcp.tool()
def pause_process() -> str:
    """Pause (freeze) the currently opened process using CE's global pause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("pause_process"))

@mcp.tool()
def unpause_process() -> str:
    """Resume (unfreeze) the currently opened process using CE's global unpause() function.

    Requires a process to be attached. Returns {success}.
    """
    return format_result(ce_client.send_command("unpause_process"))
# --- CODE INJECTION & EXECUTION ---

@mcp.tool()
def inject_dll(filepath: str, skip_symbol_reload: bool = False) -> str:
    """Inject a DLL into the currently attached target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        filepath: Absolute path to the DLL or dylib to inject.
        skip_symbol_reload: If True, skips waiting for symbol reload after injection.

    Returns:
        JSON with {success}.
    """
    return format_result(ce_client.send_command("inject_dll", {
        "filepath": filepath,
        "skip_symbol_reload": skip_symbol_reload,
    }))

@mcp.tool()
def inject_dotnet_dll(
    filepath: str,
    class_name: str,
    method_name: str,
    param: str = "",
    timeout: int = -1,
) -> str:
    """Inject a .NET DLL and invoke a static method in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The method must be declared as: public static int MethodName(string parameters).

    Args:
        filepath: Absolute path to the managed (.NET) DLL.
        class_name: Fully-qualified class name (e.g. 'MyNamespace.MyClass').
        method_name: Name of the static method to call.
        param: String parameter passed to the method.
        timeout: Milliseconds to wait for return (-1 = wait indefinitely).

    Returns:
        JSON with {success, result} where result is the integer return value.
    """
    return format_result(ce_client.send_command("inject_dotnet_dll", {
        "filepath":    filepath,
        "class_name":  class_name,
        "method_name": method_name,
        "param":       param,
        "timeout":     timeout,
    }))

@mcp.tool()
def execute_code(address: str, param: int = 0, timeout: int = -1) -> str:
    """Call a stdcall function with one argument at the given address in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    Args:
        address: Address (hex string or symbol) of the function to call.
        param: Integer argument passed as the single parameter.
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code", {
        "address": address,
        "param":   param,
        "timeout": timeout,
    }))

@mcp.tool()
def execute_code_ex(
    call_method: int,
    timeout: int,
    address: str,
    args: list = None,
) -> str:
    """Call a function with an explicit calling convention and multiple arguments.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        call_method: Integer calling convention identifier.
        timeout: Milliseconds to wait (-1 = indefinitely, 0 = fire-and-forget).
        address: Address (hex string or symbol) of the function to call.
        args: List of arguments. Each element can be a raw value (CE guesses type)
              or a dict with keys 'type' and 'value'.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_ex", {
        "call_method": call_method,
        "timeout":     timeout,
        "address":     address,
        "args":        args or [],
    }))

@mcp.tool()
def execute_method(
    address: str,
    instance: str,
    args: list = None,
    call_method: int = 0,
    timeout: int = -1,
) -> str:
    """Call a C++ instance method with an implicit 'this' pointer in the target process.

    Security warning: Executes arbitrary code in the target process. Use with caution.

    The instance pointer is placed into the register selected by call_method (ECX by default
    for thiscall). If instance is None the call behaves like execute_code_ex.

    Args:
        address: Address (hex string or symbol) of the method to call.
        instance: Address of the object instance ('this' pointer).
        args: List of additional arguments passed after 'this'.
        call_method: Calling convention (0=stdcall, 1=cdecl, 2=thiscall, 3=fastcall).
        timeout: Milliseconds to wait (-1 = indefinitely).

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_method", {
        "address":     address,
        "instance":    instance,
        "args":        args or [],
        "call_method": call_method,
        "timeout":     timeout,
    }))

@mcp.tool()
def execute_code_local(address: str, param: int = 0) -> str:
    """Call a stdcall function inside Cheat Engine's own process (NOT the target).

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    Useful for calling CE internal helpers or code loaded into CE itself.

    Args:
        address: Address within CE's memory space to call.
        param: Integer argument passed as the single parameter.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_local", {
        "address": address,
        "param":   param,
    }))

@mcp.tool()
def execute_code_local_ex(
    address: str,
    args: list = None,
    call_method: int = 0,
) -> str:
    """Call a function inside Cheat Engine's own process with explicit calling convention.

    Security warning: Executes arbitrary code in the CE process. Use with caution.

    call_method values:
        0 = stdcall
        1 = cdecl
        2 = thiscall
        3 = fastcall

    Args:
        address: Address within CE's memory space to call.
        args: List of arguments passed to the function.
        call_method: Integer calling convention identifier.

    Returns:
        JSON with {success, return_value}.
    """
    return format_result(ce_client.send_command("execute_code_local_ex", {
        "address":     address,
        "args":        args or [],
        "call_method": call_method,
    }))

# >>> BEGIN UNIT-08 Memory Allocation <<<

@mcp.tool()
def allocate_memory(size: int, base_address: str = None, protection: str = "rwx") -> str:
    """Allocate memory in the target process.

    Args:
        size: Number of bytes to allocate.
        base_address: Preferred base address as hex string (e.g. "0x140000000"). Optional.
        protection: Access flags — "r" (read-only), "rw" (read-write),
                    "rx" (read-execute), "rwx" (read-write-execute, default).

    Returns JSON with: success, address.
    """
    params = {"size": size, "protection": protection}
    if base_address is not None:
        params["base_address"] = base_address
    return format_result(ce_client.send_command("allocate_memory", params))

@mcp.tool()
def free_memory(address: str, size: int = 0) -> str:
    """Free memory previously allocated in the target process.

    Args:
        address: Address of the region to free as hex string.
        size: Size of the region in bytes. Use 0 to let the OS determine it (default).

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("free_memory", {"address": address, "size": size}))

@mcp.tool()
def allocate_shared_memory(name: str, size: int) -> str:
    """Create and map a shared memory region in the target process.

    The region is allocated with non-executable protection by default.

    Args:
        name: Unique name for the shared memory object.
        size: Size in bytes. Defaults to 4096 if the region does not yet exist.

    Returns JSON with: success, address.
    """
    return format_result(ce_client.send_command("allocate_shared_memory", {"name": name, "size": size}))

@mcp.tool()
def get_memory_protection(address: str) -> str:
    """Query the protection flags of a memory page in the target process.

    Args:
        address: Address to query as hex string.

    Returns JSON with: success, read (bool), write (bool), execute (bool), raw (PAGE_* name).
    """
    return format_result(ce_client.send_command("get_memory_protection", {"address": address}))

@mcp.tool()
def set_memory_protection(address: str, size: int, read: bool = True, write: bool = True, execute: bool = True) -> str:
    """Change the protection flags of a memory region in the target process.

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region to protect.
        read: Allow read access (default True).
        write: Allow write access (default True).
        execute: Allow execute access (default True).

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("set_memory_protection", {
        "address": address, "size": size, "read": read, "write": write, "execute": execute
    }))

@mcp.tool()
def full_access(address: str, size: int) -> str:
    """Grant full read-write-execute access to a memory region (convenience wrapper).

    Args:
        address: Start address as hex string.
        size: Size in bytes of the region.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("full_access", {"address": address, "size": size}))

@mcp.tool()
def allocate_kernel_memory(size: int) -> str:
    """Allocate non-paged kernel memory via the DBK driver.

    Requires the Cheat Engine kernel driver (DBK) to be loaded.

    Args:
        size: Number of bytes to allocate.

    Returns JSON with: success, address.
    Error codes: DBK_NOT_LOADED if the kernel driver is not active.
    """
    return format_result(ce_client.send_command("allocate_kernel_memory", {"size": size}))

# >>> END UNIT-08 <<<
# >>> BEGIN UNIT-07 Process Lifecycle <<<

@mcp.tool()
def open_process(process_id_or_name: str) -> str:
    """Open a process by PID or name and attach Cheat Engine to it.

    Args:
        process_id_or_name: Numeric PID as string (e.g. "12345") or process name (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id, process_name}.
    """
    return format_result(ce_client.send_command("open_process", {"process_id_or_name": process_id_or_name}))

@mcp.tool()
def get_process_list() -> str:
    """Get the list of running processes on the system.

    Returns:
        JSON with {success, count, processes: [{pid: int, name: str}, ...]}.
    """
    return format_result(ce_client.send_command("get_process_list"))

@mcp.tool()
def get_processid_from_name(name: str) -> str:
    """Look up the PID of a process by its executable name.

    Args:
        name: Process name to search for (e.g. "notepad.exe").

    Returns:
        JSON with {success, process_id} or {success=false, error, error_code="NOT_FOUND"}.
    """
    return format_result(ce_client.send_command("get_processid_from_name", {"name": name}))

@mcp.tool()
def get_foreground_process() -> str:
    """Get the PID and window handle of the process currently in the foreground.

    Returns:
        JSON with {success, process_id, window_handle}.
    """
    return format_result(ce_client.send_command("get_foreground_process"))

@mcp.tool()
def create_process(path: str, args: str = "", debug: bool = False, break_on_entry: bool = False) -> str:
    """Create and optionally debug a new process.

    Args:
        path: Full path to the executable.
        args: Command-line arguments string (default empty).
        debug: Attach Windows debugger if True.
        break_on_entry: Break on entry point if True (requires debug=True).

    Returns:
        JSON with {success, process_id}.
    """
    return format_result(ce_client.send_command("create_process", {
        "path": path,
        "args": args,
        "debug": debug,
        "break_on_entry": break_on_entry,
    }))

@mcp.tool()
def get_opened_process_id() -> str:
    """Get the PID of the process currently attached to Cheat Engine.

    Returns:
        JSON with {success, process_id} or {success=false, error_code="NO_PROCESS"}.
    """
    return format_result(ce_client.send_command("get_opened_process_id"))

@mcp.tool()
def get_opened_process_handle() -> str:
    """Get the OS handle of the process currently attached to Cheat Engine as a hex string.

    Returns:
        JSON with {success, handle} where handle is a hex string.
    """
    return format_result(ce_client.send_command("get_opened_process_handle"))

# >>> END UNIT-07 <<<

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v11/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
