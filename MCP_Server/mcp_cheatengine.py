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
                
                if resp_len > 16 * 1024 * 1024: 
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
def enum_modules() -> str:
    """List all loaded modules (DLLs) with their base addresses and sizes."""
    return format_result(ce_client.send_command("enum_modules"))

@mcp.tool()
def get_thread_list() -> str:
    """Get list of threads in the attached process."""
    return format_result(ce_client.send_command("get_thread_list"))

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
def read_string(address: str, max_length: int = 256, wide: bool = False) -> str:
    """Read a string from memory (ASCII or Wide/UTF-16)."""
    return format_result(ce_client.send_command("read_string", {"address": address, "max_length": max_length, "wide": wide}))

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
def get_scan_results(max: int = 100) -> str:
    """Get results from the last 'scan_all' operation. Use 'max' to limit output."""
    return format_result(ce_client.send_command("get_scan_results", {"max": max}))
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
def enum_memory_regions_full(max: int = 500) -> str:
    """Enumerate ALL memory regions in the process (Native EnumMemoryRegions)."""
    return format_result(ce_client.send_command("enum_memory_regions_full", {"max": max}))

# --- ANALYSIS & DISASSEMBLY ---

@mcp.tool()
def disassemble(address: str, count: int = 20) -> str:
    """Disassemble instructions starting at an address."""
    return format_result(ce_client.send_command("disassemble", {"address": address, "count": count}))

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
def find_references(address: str, limit: int = 50) -> str:
    """Find instructions that access (reference) this address."""
    return format_result(ce_client.send_command("find_references", {"address": address, "limit": limit}))

@mcp.tool()
def find_call_references(function_address: str, limit: int = 100) -> str:
    """Find all locations that CALL this function."""
    return format_result(ce_client.send_command("find_call_references", {"address": function_address, "limit": limit}))

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
def get_breakpoint_hits(id: str = None, clear: bool = False) -> str:
    """Get hits for a specific breakpoint ID (or all if None). Set clear=True to flush buffer."""
    return format_result(ce_client.send_command("get_breakpoint_hits", {"id": id, "clear": clear}))

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
def ping() -> str:
    """Check connectivity and get version info."""
    return format_result(ce_client.send_command("ping"))

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v11/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
