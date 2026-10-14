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
import socket
import struct
import time
import math
import ctypes
import itertools
import threading
import traceback

try:
    from mcp.server.fastmcp import FastMCP
    
    # CRITICAL: Also patch the reference inside the fastmcp module
    # FastMCP already imported stdio_server before our patch, so we need to update its reference too
    if sys.platform == "win32":
        import mcp.server.fastmcp.server as fastmcp_server
        fastmcp_server.stdio_server = _patched_stdio_server
        
except ImportError as e:
    print(f"[MCP CE] Import Error: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

try:
    import win32file
    import pywintypes
except ImportError:
    win32file = None
    pywintypes = None

try:
    import win32pipe
except ImportError:
    win32pipe = None

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout

# Debug helper - always goes to stderr, never corrupts MCP
def debug_log(msg):
    print(f"[MCP CE] {msg}", file=sys.stderr, flush=True)

# Capability profile / tool groups (CE_MCP_PROFILE, CE_MCP_ALLOW, CE_MCP_DENY, CE_MCP_TOOLSET); see tool_policy.py
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:                     # a sibling module must import however this file is launched (script, importlib, tests)
    sys.path.insert(0, _here)
import tool_policy
POLICY = tool_policy.policy_from_env(os.environ)

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

# Bridge wire protocol endpoint
PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
MCP_SERVER_NAME = "cheatengine"
MAX_RESPONSE_SIZE_BYTES = 32 * 1024 * 1024
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 9876


def _parse_timeout_seconds(raw_value):
    """Parse CE_MCP_TIMEOUT seconds; <=0 disables timeout."""
    if raw_value is None:
        return 30.0
    try:
        timeout = float(raw_value)
    except (TypeError, ValueError):
        return 30.0
    if not math.isfinite(timeout):
        return 30.0
    if timeout <= 0:
        return None
    return timeout


CE_MCP_TIMEOUT_SECONDS = _parse_timeout_seconds(os.environ.get("CE_MCP_TIMEOUT"))


def _parse_connect_wait(raw_value):
    """Parse CE_MCP_CONNECT_WAIT seconds: how long connect() keeps retrying a busy/re-created pipe."""
    if raw_value is None:
        return 2.0
    try:
        wait = float(raw_value)
    except (TypeError, ValueError):
        return 2.0
    if not math.isfinite(wait) or wait < 0:
        return 2.0
    return wait


CE_MCP_CONNECT_WAIT = _parse_connect_wait(os.environ.get("CE_MCP_CONNECT_WAIT"))


def _parse_transport(raw_value):
    """Parse CE_MCP_TRANSPORT; defaults to Windows named pipe."""
    transport = (raw_value or "pipe").strip().lower()
    aliases = {
        "named_pipe": "pipe",
        "named-pipe": "pipe",
        "np": "pipe",
        "socket": "tcp",
    }
    transport = aliases.get(transport, transport)
    if transport not in {"pipe", "tcp"}:
        raise ValueError("CE_MCP_TRANSPORT must be 'pipe' or 'tcp'.")
    return transport


def _parse_tcp_port(raw_value):
    """Parse CE_MCP_PORT as a TCP port number."""
    if raw_value is None or str(raw_value).strip() == "":
        return DEFAULT_TCP_PORT
    try:
        port = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("CE_MCP_PORT must be an integer TCP port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("CE_MCP_PORT must be between 1 and 65535.")
    return port


CE_MCP_TRANSPORT = _parse_transport(os.environ.get("CE_MCP_TRANSPORT"))
CE_MCP_HOST = os.environ.get("CE_MCP_HOST", DEFAULT_TCP_HOST).strip() or DEFAULT_TCP_HOST
CE_MCP_PORT = _parse_tcp_port(os.environ.get("CE_MCP_PORT"))

# ============================================================================
# BRIDGE CLIENTS
# ============================================================================

# Methods that only read state. If the outcome of one of these is unknown (timeout
# or dropped connection after the request was sent) it is safe to send it again.
# Everything else is NEVER re-sent once it may have reached Cheat Engine: the first
# attempt can still be running there (write_memory, auto_assemble, create_thread,
# inject_dll, show_message, ...), so a blind retry could execute it twice.
_IDEMPOTENT_PREFIXES = (
    "get_", "read_", "list_", "enum_", "find_", "is_", "aob_scan", "persistent_scan_get_",
    "md5_", "checksum_", "disassemble", "analyze_", "validate_", "dbk_get_",
    "pe_", "va_to_", "rva_to_", "rebase_", "export_", "diff_",
)
_IDEMPOTENT_EXACT = frozenset({
    "ping", "bridge_status", "search_string", "generate_signature", "dissect_structure", "file_exists",
    "compare_memory", "assemble_instruction", "auto_assemble_check", "in_main_thread",
    "list_snapshots", "snapshot_region", "delete_snapshot",
})
# Look read-only by name but consume or change state.
_NOT_IDEMPOTENT = frozenset({"get_breakpoint_hits", "read_region_from_file"})


def is_idempotent(method):
    if method in _NOT_IDEMPOTENT:
        return False
    return method in _IDEMPOTENT_EXACT or method.startswith(_IDEMPOTENT_PREFIXES)


# JSON-RPC error code -> bridge error_code enum
_RPC_ERROR_CODES = {-32700: "INVALID_PARAMS", -32600: "INVALID_PARAMS", -32601: "NOT_FOUND"}

ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231


def _cancel_pending_io(handle):
    """Cancel I/O other threads have pending on a pipe handle (kernel32!CancelIoEx)."""
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = ctypes.c_int
        ok = kernel32.CancelIoEx(int(handle), None)
        # ERROR_NOT_FOUND (1168) just means there was nothing pending
        return bool(ok) or ctypes.get_last_error() == 1168
    except Exception:
        return False


def _close_handle_quietly(handle):
    try:
        win32file.CloseHandle(handle)
    except Exception:
        pass


class CEBridgeClient:
    def __init__(self):
        self.timeout_seconds = CE_MCP_TIMEOUT_SECONDS
        self._ids = itertools.count(1)
        self._request_sent = False   # set once the full request frame has been written
        self._ever_connected = False
        self.last_connect_error = ""

    @property
    def connected(self):
        raise NotImplementedError

    def connect(self):
        raise NotImplementedError

    def _exchange_once(self, req_json):
        raise NotImplementedError

    def _endpoint_description(self):
        return "Cheat Engine Bridge"

    def _communication_error(self, error):
        return error

    def _decode_response(self, resp_header_buffer, resp_body_buffer):
        resp_len = struct.unpack('<I', resp_header_buffer)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ConnectionError(f"Response too large: {resp_len} bytes")
        try:
            # errors="replace": one bad byte in e.g. a window caption must not fail the whole reply
            return json.loads(resp_body_buffer.decode('utf-8', errors='replace'))
        except json.JSONDecodeError as exc:
            raise ConnectionError("Invalid JSON received from CE") from exc

    def _exchange_with_timeout(self, req_json, method):
        """Run exchange with optional CE_MCP_TIMEOUT enforcement."""
        timeout = self.timeout_seconds
        if timeout is None:
            return self._exchange_once(req_json)

        result_holder = {}
        error_holder = {}

        def _worker():
            try:
                result_holder["response"] = self._exchange_once(req_json)
            except Exception as exc:
                error_holder["error"] = exc

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()
        worker.join(timeout)

        if worker.is_alive():
            self.close()
            raise TimeoutError(
                f"Command '{method}' timed out after {timeout:g}s (CE_MCP_TIMEOUT)."
            )

        if "error" in error_holder:
            raise error_holder["error"]

        return result_holder["response"]

    def _not_reachable(self):
        detail = f" ({self.last_connect_error})" if self.last_connect_error else ""
        return ConnectionError(f"{self._endpoint_description()} is not reachable{detail}.")

    def send_command(self, method, params=None, idempotent=None):
        """Send command to CE Bridge, reconnecting once on failure.

        Read-only commands are re-sent after a failed attempt. Commands that change
        state are re-sent only if the request provably never left this process
        (connect/write failure); otherwise the error says the outcome is unknown.
        """
        denied = POLICY.check(method, params)
        if denied:
            return denied
        max_attempts = 2
        retry_after_send = is_idempotent(method) if idempotent is None else idempotent
        last_error = None

        for attempt in range(max_attempts):
            if not self.connected:
                if not self.connect():
                    raise self._not_reachable()

            request_id = next(self._ids)
            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
                "id": request_id
            }
            self._request_sent = False

            try:
                req_json = json.dumps(request).encode('utf-8')
                response = self._exchange_with_timeout(req_json, method)

                reply_id = response.get("id") if isinstance(response, dict) else None
                if reply_id is not None and reply_id != request_id:
                    raise ConnectionError(
                        f"Out-of-sync reply from CE (expected id {request_id}, got {reply_id})."
                    )

                if 'error' in response:
                    err = response['error']
                    if isinstance(err, dict):
                        message, rpc_code = err.get('message', err), err.get('code')
                    else:
                        message, rpc_code = err, None
                    return {
                        "success": False,
                        "error": str(message),
                        "error_code": _RPC_ERROR_CODES.get(rpc_code, "INTERNAL_ERROR"),
                    }
                if 'result' in response:
                    return response['result']

                return response

            except (OSError, ConnectionError, TimeoutError) as e:
                self.close()
                last_error = self._communication_error(e)
                if self._request_sent and not retry_after_send:
                    raise ConnectionError(
                        f"Command '{method}' was sent to Cheat Engine but no reply was received; "
                        f"it may or may not have run. Check the target's state before repeating it. "
                        f"Cause: {last_error}"
                    ) from last_error
                if attempt < max_attempts - 1:
                    continue  # Retry

        # All retries failed
        if last_error:
            raise last_error
        raise ConnectionError("Unknown communication error")

    def close(self):
        raise NotImplementedError


class CENamedPipeBridgeClient(CEBridgeClient):
    def __init__(self):
        super().__init__()
        self.handle = None
        if win32file is None or pywintypes is None:
            raise RuntimeError(
                "Named pipe transport requires Windows and pywin32. "
                "Set CE_MCP_TRANSPORT=tcp when the MCP server cannot open the Windows pipe directly."
            )

    @property
    def connected(self):
        return self.handle is not None

    def connect(self):
        """Attempts to connect to the CE Named Pipe.

        The bridge destroys and re-creates its pipe after every client disconnect, so
        a missing pipe right after a drop is normal for ~50 ms; and ERROR_PIPE_BUSY means
        the single pipe instance is momentarily taken. Retry within CE_MCP_CONNECT_WAIT
        in those cases instead of failing on the first attempt. A pipe that has never
        existed (CE not running) fails fast.
        """
        start = time.monotonic()
        while True:
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
                self._ever_connected = True
                self.last_connect_error = ""
                return True
            except pywintypes.error as exc:
                code = exc.winerror
                if code == ERROR_PIPE_BUSY:
                    self.last_connect_error = (
                        "pipe is busy: another MCP server/client is already connected to Cheat Engine"
                    )
                elif code == ERROR_FILE_NOT_FOUND:
                    self.last_connect_error = (
                        "pipe not found: is Cheat Engine running with ce_mcp_bridge.lua loaded?"
                    )
                else:
                    self.last_connect_error = f"{exc.strerror} (winerror {code})"

                budget = CE_MCP_CONNECT_WAIT
                if code == ERROR_FILE_NOT_FOUND and not self._ever_connected:
                    budget = min(budget, 0.25)
                remaining = budget - (time.monotonic() - start)
                if remaining <= 0:
                    return False

                if code == ERROR_PIPE_BUSY and win32pipe is not None:
                    try:
                        win32pipe.WaitNamedPipe(PIPE_NAME, max(1, int(min(remaining, 0.5) * 1000)))
                    except pywintypes.error:
                        pass
                else:
                    time.sleep(min(0.05, remaining))

    def _endpoint_description(self):
        return "Cheat Engine Bridge (v12/v99 pipe)"

    def _communication_error(self, error):
        if pywintypes is not None and isinstance(error, pywintypes.error):
            return ConnectionError(f"Pipe communication failed: {error}")
        return error

    @staticmethod
    def _read_exact(handle, size):
        chunks = []
        remaining = size
        while remaining > 0:
            try:
                chunk = win32file.ReadFile(handle, remaining)[1]
            except pywintypes.error as exc:
                raise ConnectionError(f"Pipe communication failed: {exc}") from exc
            if not chunk:
                raise ConnectionError("Connection closed while reading from CE pipe.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _exchange_once(self, req_json):
        """Send one framed request to the named pipe and parse one response."""
        # Bind the handle once: after a timeout close() + reconnect, this (abandoned)
        # worker must never read from the NEW connection's handle.
        handle = self.handle
        if handle is None:
            raise ConnectionError("Pipe is not connected.")
        header = struct.pack('<I', len(req_json))
        try:
            win32file.WriteFile(handle, header)
            win32file.WriteFile(handle, req_json)
        except pywintypes.error as exc:
            raise ConnectionError(f"Pipe communication failed: {exc}") from exc
        self._request_sent = True

        resp_header_buffer = self._read_exact(handle, 4)
        resp_len = struct.unpack('<I', resp_header_buffer)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ConnectionError(f"Response too large: {resp_len} bytes")
        resp_body_buffer = self._read_exact(handle, resp_len)
        return self._decode_response(resp_header_buffer, resp_body_buffer)

    def close(self):
        handle, self.handle = self.handle, None
        if not handle:
            return
        # A worker thread may be blocked in a synchronous ReadFile on this handle (after a
        # timeout). CloseHandle would then block behind it, so first cancel its pending I/O.
        # pywin32 has no CancelIoEx, hence ctypes. If cancelling fails, close on a helper
        # thread rather than risk hanging the caller.
        if _cancel_pending_io(handle):
            try:
                win32file.CloseHandle(handle)
            except Exception:
                pass
        else:
            threading.Thread(target=_close_handle_quietly, args=(handle,), daemon=True).start()


class CETcpBridgeClient(CEBridgeClient):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = None

    @property
    def connected(self):
        return self.sock is not None

    def connect(self):
        """Attempts to connect to the TCP relay."""
        try:
            connect_timeout = self.timeout_seconds if self.timeout_seconds is not None else None
            self.sock = socket.create_connection((self.host, self.port), timeout=connect_timeout)
            self.sock.settimeout(connect_timeout)
            self._ever_connected = True
            self.last_connect_error = ""
            return True
        except OSError as exc:
            self.last_connect_error = str(exc)
            self.close()
            return False

    def _endpoint_description(self):
        return f"Cheat Engine Bridge TCP relay ({self.host}:{self.port})"

    def _communication_error(self, error):
        if isinstance(error, OSError):
            return ConnectionError(f"TCP relay communication failed: {error}")
        return error

    @staticmethod
    def _read_exact(sock, size):
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Connection closed while reading from TCP relay.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _exchange_once(self, req_json):
        """Send one framed request to the TCP relay and parse one response."""
        sock = self.sock   # bound once, see CENamedPipeBridgeClient._exchange_once
        if sock is None:
            raise ConnectionError("Socket is not connected.")
        header = struct.pack('<I', len(req_json))
        sock.sendall(header + req_json)
        self._request_sent = True

        resp_header_buffer = self._read_exact(sock, 4)
        resp_len = struct.unpack('<I', resp_header_buffer)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ConnectionError(f"Response too large: {resp_len} bytes")
        resp_body_buffer = self._read_exact(sock, resp_len)
        return self._decode_response(resp_header_buffer, resp_body_buffer)

    def close(self):
        sock, self.sock = self.sock, None
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)   # wakes a worker blocked in recv()
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def _create_bridge_client():
    if CE_MCP_TRANSPORT == "tcp":
        debug_log(f"Using TCP relay transport at {CE_MCP_HOST}:{CE_MCP_PORT}")
        return CETcpBridgeClient(CE_MCP_HOST, CE_MCP_PORT)
    debug_log("Using Windows named pipe transport")
    return CENamedPipeBridgeClient()


ce_client = _create_bridge_client()

# ============================================================================
# MCP SERVER - v12 IMPLEMENTATION
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
def read_memory(address: str, size: int = 256, format: str = "hex") -> str:
    """Read raw bytes from memory.

    Args:
        address: Address (hex string or symbol).
        size: Number of bytes (max 1 MB).
        format: 'hex' (default, "48 65 6C ..."), 'base64' (smallest for big reads),
                'array' (list of ints) or 'both' (hex + array; 3x the tokens, legacy behaviour).
    """
    return format_result(ce_client.send_command("read_memory", {"address": address, "size": size, "format": format}))

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
    # Bridge supports 'read_pointer' for single dereference or 'read_pointer_chain' for multiple
    if offsets:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": offsets}))
    else:
        return format_result(ce_client.send_command("read_pointer_chain", {"base": address, "offsets": [0]}))

@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return analysis of every step."""
    return format_result(ce_client.send_command("read_pointer_chain", {"base": base, "offsets": offsets}))

@mcp.tool()
def analyze_pointer_access(instruction: str, registers: dict, accessed_address: str = None, is_64bit: bool = None) -> str:
    """Parse a captured memory access (instruction + register snapshot from a breakpoint/DBVM hit) into base register, displacement, and the concrete struct-base address for pointer-chain walk-back. Pure analysis; no process access. next_scan_value is the address to scan for (as a pointer) to find the next level up."""
    return format_result(ce_client.send_command("analyze_pointer_access", {
        "instruction": instruction,
        "registers": registers,
        "accessed_address": accessed_address,
        "is_64bit": is_64bit,
    }))

@mcp.tool()
def validate_pointer_chains(chains: list, target: str, include_misses: bool = False) -> str:
    """Resolve a list of candidate pointer chains and report which currently land on `target`. Each chain is {"base": <addr|symbol>, "offsets": [int,...]}. Returns only matches by default (token-frugal); set include_misses=true to also list non-matches. Re-run after a game restart with the new target to find chains that stay valid (the stable pointer). Max 5000 chains per call."""
    return format_result(ce_client.send_command("validate_pointer_chains", {
        "chains": chains,
        "target": target,
        "include_misses": include_misses,
    }))

@mcp.tool()
def checksum_memory(address: str, size: int) -> str:
    """Calculate MD5 checksum of a memory region to detect changes."""
    return format_result(ce_client.send_command("checksum_memory", {"address": address, "size": size}))

# --- SCANNING ---

@mcp.tool()
def scan_all(value: str = None, type: str = "dword", protection: str = "+W-C",
             scan_option: str = "exact", value2: str = None) -> str:
    """Unified Memory Scanner (first scan).

    Args:
        value: Value to search for. Omit when scan_option is 'unknown'.
        type: Value type: byte, word, dword, qword, float, double, string.
        protection: +W-C (Writable, Not Copy-on-Write).
        scan_option: exact, unknown, between, bigger, smaller.
        value2: Upper bound for 'between'.
            Alternatively pass both bounds in value as "min,max" (e.g. "0,1").
    """
    return format_result(ce_client.send_command("scan_all", {
        "value": value, "type": type, "protection": protection,
        "scan_option": scan_option, "value2": value2
    }))

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
def next_scan(value: str = None, scan_type: str = "exact", value2: str = None) -> str:
    """Next scan to filter results from the last 'scan_all'.

    Args:
        value: Value to compare against. Not needed for increased/decreased/changed/unchanged.
        scan_type: exact, between, bigger, smaller, increased, decreased, increased_by, decreased_by, changed, unchanged.
        value2: Upper bound for 'between'. Alternatively pass both bounds in value as "min,max" (e.g. "0,1").
    """
    return format_result(ce_client.send_command("next_scan", {
        "value": value, "scan_type": scan_type, "value2": value2
    }))

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
    """Find the start and end of the function containing the address.

    x64 modules: exact boundaries from the exception table (.pdata), reported with method="pdata", exact=true
    (also the exception handler address, and `fragment` when the address is in a split/cold part of a function).
    Anything else (x86, leaf functions without unwind data, JIT code): prologue/ret heuristic, method="heuristic".
    """
    return format_result(ce_client.send_command("find_function_boundaries", {"address": address, "max_search": max_search}))

@mcp.tool()
def analyze_function(address: str) -> str:
    """Analyze a function to find all CALL instructions (calls made by this function).

    When .pdata knows the function (x64) the whole exact range is walked, including code after the first `ret`;
    otherwise it stops at the first `ret` found by the heuristic. `method` says which was used.
    """
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
def set_breakpoint(address: str, id: str = None, capture_registers: bool = True, capture_stack: bool = False, stack_depth: int = 16,
                   condition: str = "", mode: str = "log", max_hits: int = 0, halt_timeout_ms: int = 0, inspect: list[dict] = None) -> str:
    """Set a hardware execution breakpoint (a debug register: invisible to most anti-cheat, at most 4 at a time).

    By default it only LOGS: every hit records registers (and optionally the stack) and the thread keeps running;
    read them with get_breakpoint_hits.

    Args:
        address: Address or symbol.
        id: Name for the breakpoint (default: the address; a clash gets a _2 suffix).
        capture_registers / capture_stack / stack_depth: What to record per hit.
        condition: Only record hits where this expression is true, e.g. "RAX == 5", "u32(RDX+8) == 0x1234 and RCX ~= 0",
                   "f32(RSP+0x20) > 100". It sees the registers (RAX..R15, RIP, EFLAGS; x86: EAX..), the memory readers
                   u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 ptr (return nil for unreadable memory), hits() (matched so far),
                   seen() (all hits) and abs/min/max/floor. Nothing else (no os/io/load), and it runs under an
                   instruction budget so it cannot hang the target. A condition that errors still records the hit,
                   flagged with `condition_error`, and is switched off after 5 failures.
        mode: "log" (default) or "break": leave the thread STOPPED for inspection. Use get_halted_state to look at it
              and debug_continue (run / step_into / step_over) to resume. A watchdog resumes it by itself after
              halt_timeout_ms so a vanished client can never leave the game frozen.
        max_hits: Detach automatically after this many matching hits (0 = unlimited).
        halt_timeout_ms: Watchdog timeout for mode "break" (default 10000, max 300000).
        inspect: For mode "break": [{"expr": "RDX+0x10", "size": 32}] memory to capture at the moment of the hit
                 (the address is an expression like a condition; at most 8 entries, 256 bytes each).
    """
    return format_result(ce_client.send_command("set_breakpoint", _params(
        address=address, id=id, capture_registers=capture_registers, capture_stack=capture_stack, stack_depth=stack_depth,
        condition=condition, mode=mode if mode != "log" else None, max_hits=max_hits or None,
        halt_timeout_ms=halt_timeout_ms or None, inspect=inspect)))

@mcp.tool()
def set_data_breakpoint(address: str, id: str = None, access_type: str = "w", size: int = 4,
                        condition: str = "", mode: str = "log", max_hits: int = 0, halt_timeout_ms: int = 0, inspect: list[dict] = None) -> str:
    """Set a hardware data breakpoint (watchpoint): finds what writes/accesses a value.

    Args:
        address: Address to watch. It must be aligned to `size`.
        access_type: 'w' (writes, default) or 'rw' (reads and writes); 'r' is an approximation because x86 debug
                     registers cannot watch reads only: it watches both and drops hits where the value changed.
        size: 1, 2, 4 (default) or 8 bytes.
        condition / mode / max_hits / halt_timeout_ms / inspect: as for set_breakpoint.

    Each hit records the value (read with the watched size), previous_value, value_changed (a write of the same value
    shows value_changed=false), the registers and the instruction that touched it.
    """
    return format_result(ce_client.send_command("set_data_breakpoint", _params(
        address=address, id=id, access_type=access_type, size=size,
        condition=condition, mode=mode if mode != "log" else None, max_hits=max_hits or None,
        halt_timeout_ms=halt_timeout_ms or None, inspect=inspect)))

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

# --- KERNEL MODE / DBVM EXTENSIONS (Unit 21) ---

@mcp.tool()
def dbk_get_cr0() -> str:
    """Read Control Register 0 (CR0) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr0 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr0"))

@mcp.tool()
def dbk_get_cr3() -> str:
    """Read Control Register 3 (CR3 — page-table base) via DBK or DBVM.

    Works when either the DBK kernel driver or the DBVM hypervisor is loaded.
    Returns cr3 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr3"))

@mcp.tool()
def dbk_get_cr4() -> str:
    """Read Control Register 4 (CR4) via the DBK kernel driver.

    Requires the DBK kernel driver to be loaded (CE Settings -> Debugger -> Kernelmode).
    Returns cr4 as a hex string.
    """
    return format_result(ce_client.send_command("dbk_get_cr4"))

@mcp.tool()
def read_process_memory_cr3(cr3: str, address: str, size: int) -> str:
    """Read virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path, making it effective for
    processes that hide memory from normal reads (e.g. anti-cheat analysis).

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to read from (hex string or symbol name).
        size: Number of bytes to read.
    """
    return format_result(ce_client.send_command(
        "read_process_memory_cr3",
        {"cr3": cr3, "address": address, "size": size}
    ))

@mcp.tool()
def write_process_memory_cr3(cr3: str, address: str, bytes: list) -> str:
    """Write to virtual memory using an explicit CR3 page-table base via DBK/DBVM.

    Bypasses the standard OS memory-translation path.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) identifying the target page table.
        address: Virtual address to write to (hex string or symbol name).
        bytes: List of integer byte values to write.
    """
    return format_result(ce_client.send_command(
        "write_process_memory_cr3",
        {"cr3": cr3, "address": address, "bytes": bytes}
    ))

@mcp.tool()
def map_memory(address: str, size: int) -> str:
    """Map a kernel/physical address range into the CE usermode context via DBK.

    Returns a mapped_address that can be used for ordinary memory reads/writes.
    Call unmap_memory() with the same mapped_address when finished.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        address: Source address to map (hex string or symbol name).
        size: Number of bytes to map.
    """
    return format_result(ce_client.send_command(
        "map_memory",
        {"address": address, "size": size}
    ))

@mcp.tool()
def unmap_memory(mapped_address: str, size: int = 0) -> str:
    """Release a memory mapping created by map_memory().

    The size parameter is accepted for API compatibility but unused internally;
    the MDL handle captured during map_memory() is used to release the mapping.

    Requires: DBK kernel driver loaded; a process must be attached.

    Args:
        mapped_address: The mapped address returned by a prior map_memory() call.
        size: Unused; kept for API symmetry with map_memory().
    """
    return format_result(ce_client.send_command(
        "unmap_memory",
        {"mapped_address": mapped_address, "size": size}
    ))

@mcp.tool()
def dbk_writes_ignore_write_protection(enable: bool) -> str:
    """Toggle whether DBK memory writes bypass copy-on-write (CoW) protection.

    When enabled, writes go directly to the underlying physical page instead of
    triggering a page fault and creating a process-private copy. Useful when
    patching shared read-only pages across all processes simultaneously.

    Requires: DBK kernel driver loaded.

    Args:
        enable: True to bypass CoW; False to restore normal CoW behaviour.
    """
    return format_result(ce_client.send_command(
        "dbk_writes_ignore_write_protection",
        {"enable": enable}
    ))

@mcp.tool()
def get_physical_address_cr3(cr3: str, virtual_address: str) -> str:
    """Translate a virtual address to its physical address using an explicit CR3.

    Unlike get_physical_address (which uses the currently attached process's CR3),
    this function lets you walk any process's page table — useful for cross-process
    physical memory analysis.

    Requires: DBK kernel driver or DBVM hypervisor loaded; a process must be attached.

    Args:
        cr3: CR3 value (hex string or integer) of the target process's page table.
        virtual_address: Virtual address to translate (hex string or symbol name).
    """
    return format_result(ce_client.send_command(
        "get_physical_address_cr3",
        {"cr3": cr3, "virtual_address": virtual_address}
    ))

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

# --- DEBUG OUTPUT & MULTIMEDIA (Unit 23) ---

@mcp.tool()
def output_debug_string(message: str) -> str:
    """Post a message to the Windows debugger via OutputDebugString (readable with tools like DebugView)."""
    return format_result(ce_client.send_command("output_debug_string", {"message": message}))

@mcp.tool()
def speak_text(text: str, english_only: bool = False) -> str:
    """Speak text via Windows SAPI text-to-speech. Set english_only=True to force the English voice."""
    return format_result(ce_client.send_command("speak_text", {"text": text, "english_only": english_only}))

@mcp.tool()
def play_sound(filename: str) -> str:
    """Play a WAV sound file by filename. Path must not contain '..' directory traversal."""
    return format_result(ce_client.send_command("play_sound", {"filename": filename}))

@mcp.tool()
def beep() -> str:
    """Play a simple system beep sound."""
    return format_result(ce_client.send_command("beep", {}))

@mcp.tool()
def set_progress_state(state: str) -> str:
    """Set the Cheat Engine taskbar progress state. Valid states: none, normal, paused, error, indeterminate."""
    return format_result(ce_client.send_command("set_progress_state", {"state": state}))

@mcp.tool()
def set_progress_value(current: int, max: int) -> str:
    """Set the Cheat Engine taskbar progress bar position. Provide current value and maximum value."""
    return format_result(ce_client.send_command("set_progress_value", {"current": current, "max": max}))
# --- THREADING & SYNCHRONIZATION (Unit-22) ---

@mcp.tool()
def create_thread(code: str, arg: str = "") -> str:
    """Execute Lua code in a new CE thread.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process,
    carrying the same risk as evaluate_lua. Only use with trusted code.

    Returns {success, thread_id}.
    """
    return format_result(ce_client.send_command("create_thread", {"code": code, "arg": arg}))

@mcp.tool()
def get_global_variable(name: str) -> str:
    """Read a global variable from CE's main Lua state.

    Useful for reading values set by scripts running in other threads.
    Returns {success, value} where value is stringified via tostring().
    """
    return format_result(ce_client.send_command("get_global_variable", {"name": name}))

@mcp.tool()
def set_global_variable(name: str, value: str) -> str:
    """Write a global variable in CE's main Lua state.

    Useful for passing values to scripts running in other threads.
    Returns {success}.
    """
    return format_result(ce_client.send_command("set_global_variable", {"name": name, "value": value}))

@mcp.tool()
def queue_to_main_thread(code: str) -> str:
    """Queue Lua code to run on CE's main thread without waiting for its result.

    SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    on the main thread, carrying the same risk as evaluate_lua. Only use with
    trusted code.

    Returns {success}.
    """
    return format_result(ce_client.send_command("queue_to_main_thread", {"code": code}))

@mcp.tool()
def check_synchronize() -> str:
    """Process queued main-thread calls (checkSynchronize).

    Call this from an infinite loop in the main thread when using threading
    and synchronize calls. Returns {success}.
    """
    return format_result(ce_client.send_command("check_synchronize"))

@mcp.tool()
def in_main_thread() -> str:
    """Check whether the current code is running in CE's main thread.

    Returns {success, is_main_thread}.
    """
    return format_result(ce_client.send_command("in_main_thread"))
# >>> BEGIN UNIT-20b Shell Execution <<<
def _check_shell_gate():
    if os.environ.get("CE_MCP_ALLOW_SHELL") != "1":
        return json.dumps({
            "success": False,
            "error": "Shell execution disabled. Set environment variable CE_MCP_ALLOW_SHELL=1 to enable.",
            "error_code": "PERMISSION_DENIED"
        })
    return None

@mcp.tool()
def run_command(command: str, args: str = "") -> str:
    """Execute a shell command in the host OS. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.
    By default, this tool returns a PERMISSION_DENIED error.

    Args:
        command: Command path or name (e.g. "notepad.exe", "cmd.exe").
        args: Arguments string.

    Returns JSON with: success, output, exit_code.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    return format_result(ce_client.send_command("run_command", {"command": command, "args": args}))

@mcp.tool()
def shell_execute(command: str, args: str = "", verb: str = "open", working_dir: str = "", showcommand: int = None) -> str:
    """Invoke Windows ShellExecute. SECURITY: Arbitrary code execution.

    REQUIRES environment variable CE_MCP_ALLOW_SHELL=1 at server startup.

    Args:
        command: Command or file to execute.
        args: Arguments string.
        verb: ShellExecute verb. CE currently supports "open" only.
        working_dir: Working directory (empty for current).
        showcommand: Optional Win32 show command integer.

    Returns JSON with: success.
    """
    blocked = _check_shell_gate()
    if blocked:
        return blocked
    params = {
        "command": command,
        "args": args,
        "verb": verb,
        "working_dir": working_dir,
    }
    if showcommand is not None:
        params["showcommand"] = showcommand
    return format_result(ce_client.send_command("shell_execute", params))
# >>> END UNIT-20b <<<
# >>> BEGIN UNIT-20a File IO Clipboard <<<

@mcp.tool()
def file_exists(filename: str) -> str:
    """Check whether a file exists at the given path. Returns {success, exists: bool}."""
    return format_result(ce_client.send_command("file_exists", {"filename": filename}))

@mcp.tool()
def delete_file(filename: str) -> str:
    """Delete a file at the given path. Returns {success}.

    WARNING: This is a destructive operation. The file will be permanently deleted
    from disk. Path traversal sequences ('..') are blocked by the bridge. Use with
    extreme caution — there is no undo.
    """
    return format_result(ce_client.send_command("delete_file", {"filename": filename}))

@mcp.tool()
def get_file_list(path: str) -> str:
    """List files in the given directory path. Returns {success, count, files: [str]}."""
    return format_result(ce_client.send_command("get_file_list", {"path": path}))

@mcp.tool()
def get_directory_list(path: str) -> str:
    """List subdirectories in the given directory path. Returns {success, count, directories: [str]}."""
    return format_result(ce_client.send_command("get_directory_list", {"path": path}))

@mcp.tool()
def get_temp_folder() -> str:
    """Return the path to the system temp folder. Returns {success, path: str}."""
    return format_result(ce_client.send_command("get_temp_folder"))

@mcp.tool()
def get_file_version(filename: str) -> str:
    """Get the version info of a file (major, minor, release, build). Returns {success, major, minor, release, build, version_string}."""
    return format_result(ce_client.send_command("get_file_version", {"filename": filename}))

@mcp.tool()
def read_clipboard() -> str:
    """Read text from the system clipboard. Returns {success, text: str}."""
    return format_result(ce_client.send_command("read_clipboard"))

@mcp.tool()
def write_clipboard(text: str) -> str:
    """Write text to the system clipboard. Returns {success}."""
    return format_result(ce_client.send_command("write_clipboard", {"text": text}))

# >>> END UNIT-20a <<<
# >>> BEGIN UNIT-19 Structure Management <<<

@mcp.tool()
def create_structure(name: str) -> str:
    """Create a new empty CE structure definition and add it to the global list.

    Args:
        name: The name for the new structure.

    Returns JSON with: success, structure_id.
    """
    return format_result(ce_client.send_command("create_structure", {"name": name}))


@mcp.tool()
def get_structure_by_name(name: str) -> str:
    """Find a CE structure by name in the global structure list.

    Args:
        name: The structure name to search for.

    Returns JSON with: success, structure_id, name, element_count, size.
    """
    return format_result(ce_client.send_command("get_structure_by_name", {"name": name}))


@mcp.tool()
def add_element_to_structure(structure_id: int, name: str, offset: int, type: str) -> str:
    """Add a new element to an existing CE structure.

    Args:
        structure_id: The structure ID returned by create_structure or get_structure_by_name.
        name: The element name.
        offset: The byte offset of the element within the structure.
        type: The variable type. Accepted values: byte, word, dword, qword,
              float, single, double, string, aob, bytearray, pointer.

    Returns JSON with: success, element_index.
    """
    return format_result(ce_client.send_command("add_element_to_structure", {
        "structure_id": structure_id,
        "name": name,
        "offset": offset,
        "type": type,
    }))


@mcp.tool()
def get_structure_elements(structure_id: int) -> str:
    """Get all elements of a CE structure.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, structure_id, elements (list of {name, offset, type, size}).
    """
    return format_result(ce_client.send_command("get_structure_elements", {"structure_id": structure_id}))


@mcp.tool()
def export_structure_to_xml(structure_id: int) -> str:
    """Export a CE structure definition as XML.

    Args:
        structure_id: The structure ID.

    Returns JSON with: success, xml (XML string representation of the structure).
    """
    return format_result(ce_client.send_command("export_structure_to_xml", {"structure_id": structure_id}))


@mcp.tool()
def delete_structure(structure_id: int) -> str:
    """Delete a CE structure from the global list and free it.

    Args:
        structure_id: The structure ID to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_structure", {"structure_id": structure_id}))

# >>> END UNIT-19 <<<
# >>> BEGIN UNIT-18 Cheat Table Records <<<

@mcp.tool()
def load_table(filename: str, merge: bool = False) -> str:
    """Load a Cheat Engine table (.ct) file into the current session.

    Args:
        filename: Path to the .ct or .cetrainer file to load.
        merge: If True, merge with the current table instead of replacing it.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("load_table", {"filename": filename, "merge": merge}))

@mcp.tool()
def save_table(filename: str, protect: bool = False) -> str:
    """Save the current cheat table to a file.

    Args:
        filename: Destination path for the .ct or .cetrainer file.
        protect: If True and the filename has a .cetrainer extension, protect it from normal reading.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("save_table", {"filename": filename, "protect": protect}))

@mcp.tool()
def get_address_list(offset: int = 0, limit: int = 100) -> str:
    """List memory records in the current cheat table's address list.

    Args:
        offset: Zero-based index of the first record to return.
        limit: Maximum number of records to return (default 100).

    Returns JSON with: success, total, offset, limit, returned, records (list of
    {id, description, address, type, value, offsets, enabled}).
    """
    return format_result(ce_client.send_command("get_address_list", {"offset": offset, "limit": limit}))

@mcp.tool()
def get_memory_record(id: int = None, description: str = None) -> str:
    """Retrieve a single memory record by ID or description.

    Args:
        id: Unique numeric ID of the memory record.
        description: Description string of the memory record (used when id is not provided).

    Returns JSON with: success, record ({id, description, address, type, value, offsets, enabled}).
    """
    params = {}
    if id is not None:
        params["id"] = id
    if description is not None:
        params["description"] = description
    return format_result(ce_client.send_command("get_memory_record", params))

@mcp.tool()
def create_memory_record(description: str, address: str, var_type: str = "dword") -> str:
    """Create a new memory record in the cheat table address list.

    Args:
        description: Human-readable label for the new entry.
        address: Address string (hex, symbol, or pointer expression) to watch.
        var_type: Variable type — byte, word, dword, qword, float, double, string, bytearray (default: dword).

    Returns JSON with: success, id, record ({id, description, address, type, value, offsets, enabled}).
    """
    return format_result(ce_client.send_command("create_memory_record", {
        "description": description,
        "address": address,
        "type": var_type,
    }))

@mcp.tool()
def delete_memory_record(id: int) -> str:
    """Delete a memory record from the cheat table address list by ID.

    Args:
        id: Unique numeric ID of the memory record to delete.

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("delete_memory_record", {"id": id}))

@mcp.tool()
def get_memory_record_value(id: int) -> str:
    """Read the current value of a memory record as a string.

    Args:
        id: Unique numeric ID of the memory record.

    Returns JSON with: success, value (string representation of the current value).
    """
    return format_result(ce_client.send_command("get_memory_record_value", {"id": id}))

@mcp.tool()
def set_memory_record_value(id: int, value: str) -> str:
    """Write a value to a memory record (and therefore to the target process memory).

    Args:
        id: Unique numeric ID of the memory record to update.
        value: New value as a string (e.g. "100", "3.14", "FF AA BB").

    Returns JSON with: success.
    """
    return format_result(ce_client.send_command("set_memory_record_value", {"id": id, "value": value}))

# >>> END UNIT-18 <<<
# --- INPUT AUTOMATION (Unit-17) — system-wide, no process guard required ---

@mcp.tool()
def get_pixel(x: int, y: int) -> str:
    """Get the colour of a screen pixel at (x, y). Returns r, g, b channels and the raw COLORREF integer."""
    return format_result(ce_client.send_command("get_pixel", {"x": x, "y": y}))

@mcp.tool()
def get_mouse_pos() -> str:
    """Get the current mouse cursor position. Returns x and y screen coordinates."""
    return format_result(ce_client.send_command("get_mouse_pos"))

@mcp.tool()
def set_mouse_pos(x: int, y: int) -> str:
    """Move the mouse cursor to screen position (x, y)."""
    return format_result(ce_client.send_command("set_mouse_pos", {"x": x, "y": y}))

@mcp.tool()
def is_key_pressed(vk: int) -> str:
    """Check whether a key is currently held down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space, 0x01 for left mouse button).
    Returns pressed: bool."""
    return format_result(ce_client.send_command("is_key_pressed", {"vk": vk}))

@mcp.tool()
def key_down(vk: int) -> str:
    """Simulate pressing a key down (does NOT release it automatically).
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_down", {"vk": vk}))

@mcp.tool()
def key_up(vk: int) -> str:
    """Release a key that was pressed with key_down.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("key_up", {"vk": vk}))

@mcp.tool()
def do_key_press(vk: int) -> str:
    """Simulate a full key press (down + up) for the given key.
    vk is a Windows virtual-key code (e.g. 0x41 for 'A', 0x20 for Space)."""
    return format_result(ce_client.send_command("do_key_press", {"vk": vk}))

@mcp.tool()
def get_screen_info() -> str:
    """Get the primary screen dimensions and DPI. Returns width, height (pixels) and dpi."""
    return format_result(ce_client.send_command("get_screen_info"))
# --- WINDOW / GUI TOOLS (Unit-16) ---

@mcp.tool()
def find_window(title: str = None, class_name: str = None) -> str:
    """Find a top-level window by title and/or class name (system-wide, no process required).

    At least one of title or class_name must be provided.
    Returns {success, handle} on success or {success=false, error_code="NOT_FOUND"} when
    no matching window exists.
    """
    params = {}
    if title is not None:
        params["title"] = title
    if class_name is not None:
        params["class_name"] = class_name
    return format_result(ce_client.send_command("find_window", params))

@mcp.tool()
def get_window_caption(handle: str) -> str:
    """Return the caption (title bar text) of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_caption", {"handle": handle}))

@mcp.tool()
def get_window_class_name(handle: str) -> str:
    """Return the window class name of a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_class_name", {"handle": handle}))

@mcp.tool()
def get_window_process_id(handle: str) -> str:
    """Return the process ID that owns a window given its handle (hex string)."""
    return format_result(ce_client.send_command("get_window_process_id", {"handle": handle}))

@mcp.tool()
def send_window_message(handle: str, msg: int, wparam: int = 0, lparam: int = 0) -> str:
    """Send a Windows message (WM_*) to a window.

    handle  -- hex window handle string
    msg     -- message ID (e.g. 0x000F for WM_PAINT)
    wparam  -- WPARAM value (default 0)
    lparam  -- LPARAM value (default 0)

    Returns {success, result} where result is the integer return value of SendMessage.
    """
    return format_result(ce_client.send_command("send_window_message", {
        "handle": handle,
        "msg": msg,
        "wparam": wparam,
        "lparam": lparam,
    }))

@mcp.tool()
def show_message(message: str) -> str:
    """Show a modal message dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user dismisses the dialog by
    clicking OK.  Do not invoke from automation that expects a timely response.

    Returns {success} after the user closes the dialog.
    """
    return format_result(ce_client.send_command("show_message", {"message": message}))

@mcp.tool()
def input_query(caption: str, prompt: str, default: str = "") -> str:
    """Show a modal text-input dialog in Cheat Engine and return what the user typed.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user submits or cancels the dialog.
    Do not invoke from automation that expects a timely response.

    Returns {success, value, cancelled}.  If cancelled is true, value is an empty string.
    """
    return format_result(ce_client.send_command("input_query", {
        "caption": caption,
        "prompt": prompt,
        "default": default,
    }))

@mcp.tool()
def show_selection_list(caption: str, prompt: str, options: list) -> str:
    """Show a modal list-selection dialog in Cheat Engine.

    WARNING — NOT SAFE FOR AUTOMATED WORKFLOWS:
    This call BLOCKS the CE main thread until the user picks an item or cancels.
    Do not invoke from automation that expects a timely response.

    options -- list of strings to display
    Returns {success, selected_index, selected_value, cancelled}.
    selected_index is -1 and cancelled is true when the user dismisses without selecting.
    """
    return format_result(ce_client.send_command("show_selection_list", {
        "caption": caption,
        "prompt": prompt,
        "options": options,
    }))

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
def persistent_scan_first_scan(name: str, value: str = None, type: str = "dword", scan_option: str = "exact", value2: str = None) -> str:
    """Run the first scan on a named persistent scan session.
    Types: byte, word, dword, qword, float, double, string.
    Scan options: exact, unknown, between, bigger, smaller.
    'between' needs two bounds: pass value2, or put both in value as "min,max" (e.g. value="0,1").
    'unknown' takes no value.
    Returns {success, scan_name, count}."""
    params = {"name": name, "type": type, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    if value2 is not None:
        params["value2"] = value2
    return format_result(ce_client.send_command("persistent_scan_first_scan", params))

@mcp.tool()
def persistent_scan_next_scan(name: str, value: str = None, scan_option: str = "exact", value2: str = None) -> str:
    """Narrow down results with a next scan on a named persistent scan session.
    Scan options: exact, between, bigger, smaller, increased, decreased, increased_by, decreased_by, changed, unchanged.
    'between' needs two bounds: pass value2, or put both in value as "min,max".
    Returns {success, scan_name, count}."""
    params = {"name": name, "scan_option": scan_option}
    if value is not None:
        params["value"] = value
    if value2 is not None:
        params["value2"] = value2
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
    Resumes a thread stopped by a mode="break" breakpoint ("run" ends the stop; a step keeps it under bridge
    control, see get_halted_state).
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

# >>> BEGIN UNIT-25 Operations: bridge_status, read_struct, batch, async jobs <<<

MAX_WAIT_FOR_JOB_SECONDS = 90.0   # keep below typical MCP host tool timeouts (e.g. 120 s)


@mcp.tool()
def bridge_status() -> str:
    """Health/diagnostics report for the Cheat Engine bridge. Works even when CE is unreachable.

    Returns bridge version, uptime, attached process (pid/name/arch), DBK/DBVM state, breakpoint and
    hardware-slot usage, async job counts, request statistics (count, errors, slowest/last command),
    the 'Query memory region routines' safety setting (best effort) and a `warnings` list.
    `python_side` shows this MCP server's own transport, timeouts and last connection error. When CE
    cannot be reached the result has reachable=false plus a `hint` explaining the likely cause
    (CE not running, bridge script not loaded, or another MCP client already holding the pipe).
    """
    python_side = {
        "transport": CE_MCP_TRANSPORT,
        "endpoint": PIPE_NAME if CE_MCP_TRANSPORT == "pipe" else f"{CE_MCP_HOST}:{CE_MCP_PORT}",
        "timeout_seconds": CE_MCP_TIMEOUT_SECONDS,
        "connect_wait_seconds": CE_MCP_CONNECT_WAIT,
        "python": sys.version.split()[0],
        "server_pid": os.getpid(),
        "ever_connected": ce_client._ever_connected,
    }
    try:
        result = ce_client.send_command("bridge_status")
    except (OSError, ConnectionError, TimeoutError) as exc:
        reason = ce_client.last_connect_error or ""
        python_side["last_connect_error"] = reason
        if "busy" in reason:
            hint = ("Another MCP server/client already holds the bridge's single pipe (for example Claude Desktop and "
                    "Claude Code both configured with this bridge). Close the other client first.")
        elif "not found" in reason:
            hint = ("The pipe does not exist: start Cheat Engine and load ce_mcp_bridge.lua "
                    "(its Lua console should print 'MCP Server Listening').")
        else:
            hint = "Cheat Engine did not answer; see `error` and check CE's Lua console."
        return format_result({
            "success": False, "reachable": False, "error": str(exc),
            "error_code": "CE_API_UNAVAILABLE", "hint": hint, "python_side": python_side,
        })
    if isinstance(result, dict):
        result["reachable"] = True
        result["python_side"] = python_side
    return format_result(result)


@mcp.tool()
def read_struct(address: str, fields: list[dict]) -> str:
    """Read several typed fields of a structure with ONE memory read (much cheaper than many read_integer calls).

    Args:
        address: Address of the structure (hex string or symbol).
        fields: List of {"name": str, "type": str, "offset": int (optional), "size": int (optional)}.
                `offset` defaults to the end of the previous field (packed, no padding), so give explicit
                offsets for real structs. Types: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 ptr bool bytes
                cstring wstring (aliases: byte word dword qword float double int short pointer string utf16).
                `size` is the byte length for bytes/cstring and the character count for wstring.

    Returns JSON with: success, address, span, arch, fields[{name, type, offset, value, hex?, error?}].
    u64 values above 2^63 and all pointers are returned as hex strings. A field that cannot be read gets
    an `error` instead of failing the whole call. Limits: 512 fields, 64 KB span.
    """
    return format_result(ce_client.send_command("read_struct", {"address": address, "fields": fields}))


@mcp.tool()
def batch_commands(requests: list[dict], stop_on_error: bool = False) -> str:
    """Run several bridge commands in ONE round trip (and one slot on CE's main thread).

    Args:
        requests: List of {"method": "<tool name>", "params": {...}} using the same names/params as the
                  individual tools, e.g. [{"method": "read_integer", "params": {"address": "0x1000"}}].
                  Max 100; nesting batch_commands is not allowed.
        stop_on_error: Stop at the first failing request (default: run all).

    Returns JSON with: success, requested, executed, failed, results[] (one result object per request, in order).
    The call is retried automatically after a connection problem only if every request is read-only.
    """
    problems = []
    for i, req in enumerate(requests):
        method = req.get("method") if isinstance(req, dict) else None
        if not isinstance(method, str) or not method:
            problems.append(f"requests[{i}] needs a 'method'")
        elif method == "batch":
            problems.append(f"requests[{i}]: batch cannot be nested")
    if problems:
        return format_result({"success": False, "error": "; ".join(problems), "error_code": "INVALID_PARAMS"})
    all_read_only = all(is_idempotent(req["method"]) for req in requests)
    return format_result(ce_client.send_command(
        "batch", {"requests": requests, "stop_on_error": stop_on_error}, idempotent=all_read_only))


@mcp.tool()
def start_job(kind: str, params: dict = None) -> str:
    """Start a long-running operation in the background and return immediately with a job_id.

    CE stays responsive and the MCP call cannot time out. Poll with get_job (or block with wait_for_job),
    then fetch the data with get_job_result. Up to 4 jobs run at once.

    Args:
        kind: 'scan_all' | 'next_scan' | 'aob_scan' | 'find_references' | 'find_call_references' | 'find_xrefs' |
              'rtti_scan' | 'find_string_refs' | 'find_code_caves' | 'find_pointer_path'.
        params: The same parameters the matching blocking tool takes, e.g.
                scan_all {"value": "100", "type": "dword"}, aob_scan {"pattern": "48 8B ?? 05", "limit": 100},
                find_references {"address": "0x140001000"}, find_call_references {"address": "game.exe+1234"},
                find_xrefs {"address": "game.exe+1234", "kinds": "call,jmp"}.

    scan_all/next_scan own the shared scan session: while one runs, scan_all, next_scan and
    get_scan_results answer error_code BUSY. Cancelling a next_scan discards the scan session.
    """
    return format_result(ce_client.send_command("start_job", {"kind": kind, "params": params or {}}))


@mcp.tool()
def get_job(job_id: str) -> str:
    """Status of a job: state (running|done|failed|cancelled), phase, progress {current,total,percent},
    elapsed_seconds, and a small result_summary once done. Use get_job_result for the full data."""
    return format_result(ce_client.send_command("get_job", {"job_id": job_id}))


@mcp.tool()
def get_job_result(job_id: str, offset: int = 0, limit: int = 100) -> str:
    """Result of a finished job, shaped like the blocking tool's reply (e.g. count for scans; total/offset/
    limit/returned + addresses|references|callers for list results). `offset`/`limit` page through lists.
    A job that is still running answers error_code BUSY."""
    return format_result(ce_client.send_command("get_job_result", {"job_id": job_id, "offset": offset, "limit": limit}))


@mcp.tool()
def wait_for_job(job_id: str, timeout_seconds: float = 30.0, poll_interval: float = 0.5) -> str:
    """Wait (polling get_job) until a job leaves the 'running' state or the timeout passes.

    Returns the final get_job status, or the latest status with timed_out=true if it is still running
    (just call again). timeout_seconds is capped at 90. CE is not blocked while waiting.
    """
    timeout = max(0.0, min(float(timeout_seconds), MAX_WAIT_FOR_JOB_SECONDS))
    poll = max(0.1, min(float(poll_interval), 5.0))
    deadline = time.monotonic() + timeout
    while True:
        status = ce_client.send_command("get_job", {"job_id": job_id})
        if not isinstance(status, dict) or not status.get("success") or status.get("state") != "running":
            return format_result(status)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status["timed_out"] = True
            status["hint"] = "Job is still running; call wait_for_job or get_job again."
            return format_result(status)
        time.sleep(min(poll, remaining))


@mcp.tool()
def cancel_job(job_id: str) -> str:
    """Cancel a running job and free its resources. Cancelling a next_scan discards the active scan
    session (run scan_all again). Cancelling a finished job is a harmless no-op."""
    return format_result(ce_client.send_command("cancel_job", {"job_id": job_id}))


@mcp.tool()
def list_jobs() -> str:
    """List tracked jobs (running ones plus the 20 most recent finished) with their status."""
    return format_result(ce_client.send_command("list_jobs"))

# >>> END UNIT-25 <<<

# >>> BEGIN UNIT-26 Analysis: PE/modules, address translation, RTTI, string refs, code caves, pointer paths, snapshots <<<


def _params(**kw):
    """Keyword arguments -> bridge params, dropping None / empty strings so Lua sees 'not given'."""
    return {k: v for k, v in kw.items() if v is not None and v != ""}


def _run_job(kind, params, wait_seconds, limit, offset=0):
    """start_job + wait up to `wait_seconds` + get_job_result. Returns the job id and status if still running."""
    started = ce_client.send_command("start_job", {"kind": kind, "params": params})
    if not isinstance(started, dict) or not started.get("success"):
        return started
    job_id = started["job_id"]
    deadline = time.monotonic() + max(0.0, min(float(wait_seconds), MAX_WAIT_FOR_JOB_SECONDS))
    while True:
        status = ce_client.send_command("get_job", {"job_id": job_id})
        if not isinstance(status, dict) or not status.get("success"):
            return status
        state = status.get("state")
        if state == "running":
            if time.monotonic() >= deadline:
                status["timed_out"] = True
                status["hint"] = (f"Still running in the background. Call wait_for_job('{job_id}') and then "
                                  f"get_job_result('{job_id}') for the data.")
                return status
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
            continue
        if state == "done":
            return ce_client.send_command("get_job_result", {"job_id": job_id, "offset": offset, "limit": limit})
        return status


# ---- PE / modules ---------------------------------------------------------------------------------

@mcp.tool()
def pe_info(module: str = "") -> str:
    """Parse a loaded module's PE headers from memory: architecture, entry point, preferred vs actual base
    (relocated?), sections with rwx flags and addresses, data directories, subsystem, timestamp.

    Args:
        module: Module name (case-insensitive, substring ok) or an address inside it. Empty = the main module.
    """
    return format_result(ce_client.send_command("pe_info", _params(module=module)))


@mcp.tool()
def pe_imports(module: str = "", dll: str = "", offset: int = 0, limit: int = 100) -> str:
    """List a module's imports: dll, function name (or ordinal + hint), IAT slot address, and the address the
    IAT currently holds (`resolved`, plus the module that contains it, so you can spot hooked imports).

    Args:
        module: Module name or address inside it (empty = main module).
        dll: Only imports from DLLs whose name contains this text.
        offset, limit: Pagination (default 100 per page).
    """
    return format_result(ce_client.send_command("pe_imports", _params(module=module, dll=dll, offset=offset, limit=limit)))


@mcp.tool()
def pe_exports(module: str = "", name_contains: str = "", offset: int = 0, limit: int = 100) -> str:
    """List a module's exports: name, ordinal, RVA, address and forwarder text for forwarded exports.

    Args:
        module: Module name or address inside it (empty = main module).
        name_contains: Case-insensitive name filter.
        offset, limit: Pagination (default 100 per page).
    """
    return format_result(ce_client.send_command("pe_exports", _params(module=module, name_contains=name_contains, offset=offset, limit=limit)))


@mcp.tool()
def pe_tls_callbacks(module: str = "") -> str:
    """List a module's TLS callbacks (code that runs before the entry point; common in packers and anti-debug).
    Returns each callback's address, RVA, section and owning module, plus the TLS directory fields."""
    return format_result(ce_client.send_command("pe_tls_callbacks", _params(module=module)))


# ---- address translation / IDA exchange -----------------------------------------------------------

@mcp.tool()
def va_to_rva(address: str = "", addresses: list[str] = None, ida_image_base: str = "", include_section: bool = True) -> str:
    """Convert runtime addresses to module + RVA (and section). Give `address` or a list in `addresses`.

    If `ida_image_base` is given (IDA's image base, from IDA's metadata), each result also carries
    `ida_address` = ida_image_base + rva, i.e. the address to jump to in IDA.
    Result `expression` is a CE-usable "module+0xRVA" string.
    """
    return format_result(ce_client.send_command("va_to_rva", _params(
        address=address, addresses=addresses, ida_image_base=ida_image_base, include_section=include_section)))


@mcp.tool()
def rva_to_va(module: str = "", rva: str = "", rvas: list[str] = None, ida_image_base: str = "") -> str:
    """Convert RVAs of a module into runtime addresses (give `rva` or `rvas`; hex strings like "0x1A2B" or numbers).
    With `ida_image_base` also returns the matching IDA address."""
    return format_result(ce_client.send_command("rva_to_va", _params(module=module, rva=rva, rvas=rvas, ida_image_base=ida_image_base)))


@mcp.tool()
def rebase_address(address: str = "", addresses: list[str] = None, from_base: str = "", from_module: str = "",
                   to_base: str = "", to_module: str = "") -> str:
    """Move addresses between two images loaded at different bases, e.g. an IDA address into the running
    process: from_base="0x140000000" (IDA image base), to_module="game.exe". Each side is a base address
    or a module name. Returns the new address and the shared RVA."""
    return format_result(ce_client.send_command("rebase_address", _params(
        address=address, addresses=addresses, from_base=from_base, from_module=from_module, to_base=to_base, to_module=to_module)))


@mcp.tool()
def export_names(module: str = "", sources: list[str] = None, format: str = "json", ida_image_base: str = "",
                 include_types: bool = True) -> str:
    """Export names for use in IDA: CE registered symbols and/or RTTI vtables of one module.

    Args:
        module: Module name (empty = main module).
        sources: any of "symbols" (CE registered symbols inside the module) and "rtti" (vtables found by the last
                 rtti_scan_module of this module). Default both.
        format: "json" (entries with rva, name, ida_name, kind) or "idapython" (a ready-to-run IDAPython script that
                renames and comments each address relative to the loaded image base).
        ida_image_base: Adds `ida_address` to each entry.
        include_types: Also return `c_declarations` (vtable/class struct skeletons built from RTTI) that can be fed
                       to IDA's declare_c_type.
    """
    return format_result(ce_client.send_command("export_names", _params(
        module=module, sources=sources, format=format, ida_image_base=ida_image_base, include_types=include_types)))


@mcp.tool()
def export_structures(name: str = "") -> str:
    """C declarations for Cheat Engine's structure definitions (all, or the one called `name`), with padding for gaps
    and a trailing pad up to the declared size. Paste into IDA's Local Types / declare_c_type."""
    return format_result(ce_client.send_command("export_structures", _params(name=name)))


@mcp.tool()
def import_names(names: list[dict], module: str = "", ida_image_base: str = "", address_is_ida: bool = False,
                 prefix: str = "", do_not_save: bool = True) -> str:
    """Register names (e.g. renamed functions from IDA) as CE symbols so they show up in disassembly and can be used
    in address expressions. At most 5000 per call.

    Args:
        names: [{"name": "Player::Update", "rva": "0x1A2B30"}, {"name": "x", "address": "0x7FF6..."}].
               `rva` needs `module`. With address_is_ida=true an `address` is treated as an IDA address and rebased
               using ida_image_base into `module`.
        prefix: Prepended to every name.
        do_not_save: Keep the symbols out of saved cheat tables (default true).
    """
    return format_result(ce_client.send_command("import_names", _params(
        names=names, module=module, ida_image_base=ida_image_base, address_is_ida=address_is_ida or None,
        prefix=prefix, do_not_save=do_not_save)))


# ---- long-running analysis (background jobs; each waits up to wait_seconds, then returns the job id) ----

@mcp.tool()
def rtti_scan_module(module: str = "", max_vtable_entries: int = 256, wait_seconds: float = 30.0, limit: int = 200, offset: int = 0) -> str:
    """Find every MSVC RTTI class in a module: class name (demangled + raw), vtable address/RVA, number of virtual
    functions, this-pointer offset (non-zero = secondary base vtable) and the base-class chain. x64 and x86.
    Results are cached so export_names can emit them for IDA.

    Runs as a background job. Returns the classes when finished within `wait_seconds`; otherwise returns
    {state:"running", job_id, progress} - call wait_for_job / get_job_result later.
    """
    return format_result(_run_job("rtti_scan", _params(module=module, max_vtable_entries=max_vtable_entries), wait_seconds, limit, offset))


@mcp.tool()
def find_string_refs(text: str = "", address: str = "", module: str = "", wide: bool = False, match: str = "start",
                     include_data: bool = True, wait_seconds: float = 30.0, limit: int = 100) -> str:
    """Find the code and data that reference a string.

    Give `text` (looked up in the module's data sections; wide=true for UTF-16) or the string's `address`.
    `match`: "start" (default, the text must begin a string) or "any" (also mid-string hits).
    Finds x64 rip-relative `lea reg,[rip+disp]` (how compilers load string addresses), absolute pointers in code
    (x86 push/mov imm32) and, with include_data, absolute pointers stored in data sections.
    Each reference has kind (rip_lea | abs_code | abs_data), address, module+RVA expression, section and disassembly.
    Background job; see rtti_scan_module for the wait/timeout behaviour.
    """
    return format_result(_run_job("find_string_refs", _params(
        text=text, address=address, module=module, wide=wide or None, match=match, include_data=include_data), wait_seconds, limit))


@mcp.tool()
def find_xrefs(address: str, size: int = 1, module: str = "", kinds: str = "", max_results: int = 5000,
               wait_seconds: float = 30.0, limit: int = 100, offset: int = 0) -> str:
    """Find everything that references `address` (or the `size` bytes starting there): "who calls this function",
    "who touches this variable", "which table points at this".

    Finds, in the scanned module(s):
      call / jmp / jcc  rel32 and short (rel8) branches whose target is in the range
      rip               x64 rip-relative operands (lea/mov/cmp/call [rip+x] ...); `access` says read | write |
                        read/write | address (lea) | call | jump
      abs_code          absolute pointers inside code (x86 push/mov imm32, x64 mov r64,imm64); `address` is the
                        instruction when one is found and `field_address` the pointer itself
      abs_data          pointer-aligned absolute pointers in data sections (vtables, pointer tables)
      rva               32-bit RVAs in data (x64 jump tables); the .pdata exception table is skipped
    Each reference has address, module+RVA `expression`, section, instruction text and the enclosing function
    (`function_start`, from .pdata on x64). The result also lists the calling functions with counts (`functions`).

    Args:
        address: Target address (hex string, symbol or module+offset).
        size: Treat [address, address+size) as the target - e.g. a whole struct or a function body's first bytes.
              Absolute pointers inside code are only searched for sizes up to 16.
        module: Module to scan - a name, "all", or empty for the module that contains `address` (else the main module).
        kinds: Comma separated subset of call, jmp, jcc, rip, abs, abs_code, abs_data, rva (default: all).
        max_results: Stop after this many raw hits (default 5000; `truncated` is set when reached).

    Static references only: pointers stored on the heap/stack are not found (use find_pointer_path for those).
    Background job; see rtti_scan_module for the wait/timeout behaviour.
    """
    return format_result(_run_job("find_xrefs", _params(address=address, size=size if size != 1 else None, module=module,
                                                        kinds=kinds, max_results=max_results if max_results != 5000 else None),
                                  wait_seconds, limit, offset))


@mcp.tool()
def find_code_caves(module: str = "", byte: int = 204, min_size: int = 16, sections: str = "exec", wait_seconds: float = 30.0, limit: int = 100) -> str:
    """Find runs of padding bytes (default 0xCC; also 0x00 or 0x90) of at least `min_size` bytes where you can place
    patches or hooks. `sections`: "exec" (executable sections only, default) or "all". Largest first.
    Background job; see rtti_scan_module for the wait/timeout behaviour."""
    return format_result(_run_job("find_code_caves", _params(module=module, byte=byte, min_size=min_size, sections=sections), wait_seconds, limit))


@mcp.tool()
def find_pointer_path(address: str, max_depth: int = 3, max_offset: int = 1024, max_per_level: int = 16,
                      max_results: int = 100, protection: str = "+W", save_as: str = "", wait_seconds: float = 30.0,
                      limit: int = 100) -> str:
    """Find static pointer chains that lead to `address` (a heap/stack value that moves between runs).

    Works backwards: each level runs one memory scan for pointers whose value lies within `max_offset` below the
    address, keeps the best `max_per_level` non-static holders and repeats, up to `max_depth` levels, until a holder
    lies inside a module (that module+RVA is the static base). Every chain is re-resolved to verify it reaches the
    address. Each result has `base` ("module+0xRVA"), `offsets` (outermost first), `expression`
    ("[[game.exe+0x1234]+0x40]+0x100") and `verified`.

    This is a plain reverse scan, far less thorough than Cheat Engine's pointer scanner; expect a handful of chains,
    each costing one full memory scan per frontier address (seconds to minutes in big processes).

    Two-run workflow: pass `save_as="hp"` to keep the verified chains in a named set inside the bridge. After the target
    restarts and you have found the same value again, compare_pointer_paths(target=<new address>, name="hp") keeps only
    the chains that still reach it (save_as there narrows the set; run it again after a third start). The stored set
    survives target restarts, not a reload of the bridge script.
    Background job; see rtti_scan_module for the wait/timeout behaviour, and use cancel_job to stop it.
    """
    return format_result(_run_job("find_pointer_path", _params(
        address=address, max_depth=max_depth, max_offset=max_offset, max_per_level=max_per_level,
        max_results=max_results, protection=protection, save_as=save_as), wait_seconds, limit))


# ---- snapshots ----------------------------------------------------------------------------------------

@mcp.tool()
def snapshot_region(address: str = "", size: int = 0, name: str = "", module: str = "", section: str = "") -> str:
    """Save a copy of a memory region (max 64 MB each, 128 MB / 16 snapshots in total) so you can later diff it:
    take one, change something in the game, take another, then diff_snapshots to see which values changed - without
    running a first scan over the whole process. Give address+size, or module+section (e.g. module="game.exe",
    section=".data"). Unreadable pages are zero-filled and reported in `unreadable_bytes`. Re-using a name replaces it."""
    return format_result(ce_client.send_command("snapshot_region", _params(address=address, size=size or None, name=name, module=module, section=section)))


@mcp.tool()
def list_snapshots() -> str:
    """List saved snapshots (name, address, size, unreadable bytes) and the memory they use."""
    return format_result(ce_client.send_command("list_snapshots"))


@mcp.tool()
def delete_snapshot(name: str = "", all: bool = False) -> str:
    """Delete one snapshot by name, or all of them with all=true."""
    return format_result(ce_client.send_command("delete_snapshot", _params(name=name, all=all or None)))


@mcp.tool()
def diff_snapshots(snapshots: list[str], pattern: str = "", unit: int = 4, offset: int = 0, length: int = 0,
                   merge_gap: int = 0, limit: int = 200) -> str:
    """Compare 2+ snapshots of the same region ("live" may be used for the current memory) and list the units that
    behave as expected - the 'unknown value' workflow without scans.

    Args:
        snapshots: Names in time order, e.g. ["before", "after_hit", "after_heal"].
        pattern: One character per consecutive pair: C = must have changed, U = must be unchanged, ? = don't care.
                 Default: all C. ["a","b","c"] with "CU" = changed between a and b, then stable (b == c).
        unit: Compare in 1, 2, 4 (default) or 8 byte units; 4 also shows float views, 8 double views.
        offset, length: Restrict to a sub-range of the region (bytes).
        merge_gap: Adjacent matches closer than this many bytes are merged in `groups` (default = unit).
        limit: Max matches returned (total_matches always counts all).

    Returns total_matches, matches[{address, offset, old, new, values?, old_float/new_float...}] and
    groups[{address, offset, size, units}] that point to likely fields.
    """
    return format_result(ce_client.send_command("diff_snapshots", _params(
        snapshots=snapshots, pattern=pattern, unit=unit, offset=offset or None, length=length or None,
        merge_gap=merge_gap or None, limit=limit)))

# >>> END UNIT-26 <<<

# >>> BEGIN UNIT-27 Functions (.pdata), struct recovery, breakpoint control <<<

@mcp.tool()
def pe_functions(module: str = "", address: str = "", offset: int = 0, limit: int = 100, include_unwind: bool = False) -> str:
    """x64 function table (.pdata): every function with unwind data, or the exact function containing `address`.

    With `address`: begin/end/size, `expression` ("module+0xRVA"), the exception handler address and the unwind info
    (prolog size, frame register, flags EHANDLER/UHANDLER/CHAININFO). Split ("cold") fragments are resolved to their
    primary function and described in `fragment`. found=false means the address is not covered: leaf functions that
    never touch the stack have no entry, so use find_function_boundaries for the heuristic fallback.
    Without `address`: a page of the table (`total`, `offset`, `limit`); include_unwind adds prolog/handler info per entry.
    The module defaults to the one containing `address`, else the main module. x86 modules have no function table
    (available=false).
    """
    return format_result(ce_client.send_command("pe_functions", _params(
        module=module, address=address, offset=offset, limit=limit, include_unwind=include_unwind or None)))

@mcp.tool()
def recover_struct(address: str = "", addresses: list[str] = None, size: int = 0, name: str = "", create: bool = False,
                   max_vtable_entries: int = 0) -> str:
    """Recover a class layout from live instance(s) of a polymorphic MSVC class.

    The object's vtable pointer (offset 0) leads to its RTTI: class name, base classes (with subobject offsets) and the
    virtual function table (each virtual function with its address and, on x64, exact size from .pdata). The fields are
    inferred by dissecting the memory: pointers (typed as `ClassName *` when they point at another RTTI object, `char *`
    for text, vfptr for secondary vtables, module+RVA for static data), floats, doubles, ints, inline char buffers and
    zero gaps. Pass several instances of the SAME class in `addresses` for much better guesses: values that differ are
    data, the all-zero tail is trimmed and mixed classes are refused.

    Args:
        address / addresses: Object address(es), 1 to 16 instances of one class.
        size: Bytes to analyse (default 0x100, max 0x4000; the all-zero tail is dropped).
        name: Name for the CE structure when create=true (default: the class name).
        create: Also create the CE structure definition (visible in the Structures list; for strings it sets the byte size).
        max_vtable_entries: Cap for the virtual function listing (default 64).

    Returns class_name, bases, vtable, fields[{offset,size,kind,type,name,samples}], virtual_functions, c_declaration
    (ready for IDA's declare_c_type) and, with create, structure_id. This is a heuristic: ints that look like floats (or
    the reverse), and two floats at an 8-aligned offset, can be misjudged; check the samples.
    """
    return format_result(ce_client.send_command("recover_struct", _params(
        address=address, addresses=addresses, size=size or None, name=name, create=create or None,
        max_vtable_entries=max_vtable_entries or None)))

@mcp.tool()
def get_halted_state(stack_depth: int = 16, extend_ms: int = 0) -> str:
    """State of a thread stopped by a mode="break" breakpoint (or by stepping from one).

    Returns halted=false when nothing is stopped (last_halt says how the last stop ended: resumed, timeout,
    breakpoint removed, resumed outside the bridge). When halted: fresh registers, the instruction at RIP, the stack,
    the memory the breakpoint asked to inspect, the hit, and auto_resume_in_seconds (the watchdog countdown).
    extend_ms postpones the watchdog. Resume with debug_continue(method="run" | "step_into" | "step_over"); after a step,
    call this again to see the new position.
    """
    return format_result(ce_client.send_command("get_halted_state", _params(stack_depth=stack_depth, extend_ms=extend_ms or None)))

# >>> END UNIT-27 <<<

# >>> BEGIN UNIT-30 Pointer path sets: comparing pointer chains across runs <<<

@mcp.tool()
def compare_pointer_paths(target: str, name: str = "", chains: list[dict] = None, save_as: str = "", near_delta: int = 256,
                          near_limit: int = 10, offset: int = 0, limit: int = 100) -> str:
    """Two-run pointer path comparison: which pointer chains from an earlier run still reach the value now?

    Run 1: find_pointer_path(address, save_as="hp") stores the chains of the value you found (or pass chains from
    Cheat Engine's pointer scanner inline, with `target` = the address they point to in the CURRENT process).
    Restart the target, find the same value again (scan, or any other way), then call this with `target` = its new
    address. Every chain is re-resolved from its module+RVA base in the new process; the ones that land exactly on
    `target` have survived a restart. Run it once more after another restart: the survivors then carry runs=3.

    Args:
        target: Address of the same value in the current process.
        name: A stored set (list_pointer_sets). Give this OR chains, not both.
        chains: Inline [{"base": "game.exe+0x1A2B3C" | address, "offsets": [0x40, 0x10]}]. Offsets are applied after each
                dereference, outermost first (CE convention). An absolute base inside a module is stored module-relative.
        save_as: Store the survivors under this name (same name as `name` narrows the set in place). Without it nothing
                 is stored. An empty result never overwrites a set.
        near_delta, near_limit: Chains that resolve to within +-near_delta bytes of target are reported as near_misses
                 with a suggested_offsets correction (a patch that moved the last field); up to near_limit shown.
        offset, limit: page through the surviving chains.

    Returns hits (survivors), missed (resolved elsewhere), unreadable (a pointer on the way could not be read),
    module_missing, same_process (true when the target was not restarted since the last run: weaker evidence), and
    chains[] sorted by runs (most confirmed first), then shortest/smallest. Reads memory only.
    """
    return format_result(ce_client.send_command("compare_pointer_paths", _params(
        target=target, name=name, chains=chains, save_as=save_as, near_delta=near_delta if near_delta != 256 else None,
        near_limit=near_limit if near_limit != 10 else None, offset=offset or None, limit=limit)))


@mcp.tool()
def list_pointer_sets() -> str:
    """List the stored pointer chain sets (name, chain_count, runs, history of the runs that produced them)."""
    return format_result(ce_client.send_command("list_pointer_sets"))


@mcp.tool()
def get_pointer_set(name: str, offset: int = 0, limit: int = 100) -> str:
    """The chains of a stored set (base, offsets, expression, runs) plus its run history. Feed them to
    validate_pointer_chains or write them into a cheat table; runs says in how many separate runs a chain reached its value."""
    return format_result(ce_client.send_command("get_pointer_set", {"name": name, "offset": offset, "limit": limit}))


@mcp.tool()
def drop_pointer_set(name: str = "", all: bool = False) -> str:
    """Delete one stored pointer set by name, or all of them with all=true."""
    return format_result(ce_client.send_command("drop_pointer_set", _params(name=name, all=all or None)))

# >>> END UNIT-30 <<<

# >>> BEGIN UNIT-29 Capability profiles and tool groups <<<

ALL_TOOLS = sorted(t.name for t in mcp._tool_manager.list_tools()) + ["policy_info"]


@mcp.tool()
def policy_info(details: bool = False) -> str:
    """What this server is allowed to do and which tools it lists (CE_MCP_PROFILE / CE_MCP_TOOLSET / CE_MCP_ALLOW / CE_MCP_DENY).

    Use it when a tool you expect is missing or a call comes back PERMISSION_DENIED. The profile is a security setting of
    the MCP server's environment, not something a client can change: readonly < analysis < patch < full.
    With details=true the names of the hidden tools are listed per group.
    """
    hidden = {"profile": [], "toolset": [], "denied": []}
    listed = {}
    for name in ALL_TOOLS:
        why = POLICY.hidden_reason(name)
        group = POLICY.group_of(name)
        if why:
            hidden[{"profile": "profile", "toolset": "toolset", "denied": "denied"}[why]].append(name)
        else:
            listed[group] = listed.get(group, 0) + 1
    out = {
        "success": True, "profile": POLICY.profile, "tier_ceiling": tool_policy.TIER_NAMES[POLICY.max_tier],
        "toolset": sorted(POLICY.groups) if POLICY.groups is not None else "all",
        "allow": sorted(POLICY.allow), "deny": sorted(POLICY.deny),
        "shell_tools_enabled": os.environ.get("CE_MCP_ALLOW_SHELL") == "1",
        "tools_listed": sum(listed.values()), "tools_hidden": {k: len(v) for k, v in hidden.items()},
        "listed_per_group": dict(sorted(listed.items())),
        "profiles": {"readonly": "observe only", "analysis": "+ breakpoints, symbols, structures, attach, host introspection",
                     "patch": "+ write memory / registers / protection / allocations", "full": "+ code execution, injection, shell, files, input automation"},
        "groups": list(tool_policy.GROUPS), "presets": {k: list(v) for k, v in tool_policy.PRESETS.items()},
    }
    if POLICY.warnings:
        out["warnings"] = POLICY.warnings
    if details:
        out["hidden_tools"] = {k: v for k, v in hidden.items() if v}
    return format_result(out)


_unlisted = POLICY.apply(mcp)
if POLICY.profile != "full" or POLICY.groups is not None or POLICY.allow or POLICY.deny:
    debug_log("policy: profile=%s toolset=%s -> %d tools listed, %d hidden"
              % (POLICY.profile, ",".join(sorted(POLICY.groups)) if POLICY.groups else "all", len(ALL_TOOLS) - len(_unlisted), len(_unlisted)))

# >>> END UNIT-29 <<<

if __name__ == "__main__":
    try:
        debug_log("Starting FastMCP server (v12/v99 compatible)...")
        mcp.run()
    except Exception as e:
        debug_log(f"Fatal Crash: {e}")
        traceback.print_exc(file=sys.stderr)
