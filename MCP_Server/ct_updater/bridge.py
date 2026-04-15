"""
CE MCP Bridge client — named pipe connection to ce_mcp_bridge.lua.
"""
import json
import struct
import time


PIPE_NAME = r'\\.\pipe\CE_MCP_Bridge_v99'


class BridgeError(Exception):
    pass


class BridgeClient:
    def __init__(self, pipe_name: str = PIPE_NAME):
        self.pipe_name = pipe_name
        self._handle = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self):
        import win32file, win32pipe, pywintypes
        try:
            self._handle = win32file.CreateFile(
                self.pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
        except pywintypes.error as e:
            raise BridgeError(f"Cannot open pipe {self.pipe_name}: {e}") from e
        try:
            win32pipe.SetNamedPipeHandleState(
                self._handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        except Exception:
            pass  # byte-stream pipe — framing via length prefix is fine

    def close(self):
        if self._handle:
            self._handle.close()
            self._handle = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _send_recv(self, method: str, params: dict | None = None) -> dict:
        import win32file
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": method, "params": params or {},
        }).encode()
        header = struct.pack('<I', len(payload))
        win32file.WriteFile(self._handle, header + payload)

        raw = b''
        while len(raw) < 4:
            _, chunk = win32file.ReadFile(self._handle, 4 - len(raw))
            raw += chunk
        size = struct.unpack('<I', raw)[0]

        body = b''
        while len(body) < size:
            _, chunk = win32file.ReadFile(self._handle, size - len(body))
            body += chunk

        resp = json.loads(body)
        if 'error' in resp:
            raise BridgeError(f"Bridge error: {resp['error']}")
        return resp.get('result', {})

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def lua(self, code: str) -> str | None:
        """Execute Lua in CE and return the string result, or None on failure."""
        r = self._send_recv('evaluate_lua', {'code': code})
        if isinstance(r, dict) and r.get('success'):
            return r.get('result')
        return None

    def ping(self) -> dict:
        return self._send_recv('ping')

    def get_symbol_addr(self, symbol: str) -> int | None:
        """Resolve a Mono symbol name to an address, or None if not found."""
        code = (
            f'local ok,v=pcall(getAddress,"{symbol}") '
            'if ok and v and v~=0 then return string.format("0x%X",v) '
            'else return "NOTFOUND" end'
        )
        val = self.lua(code)
        if not val or val in ('NOTFOUND', '0x0', '0'):
            return None
        try:
            return int(val, 16)
        except ValueError:
            return None

    def read_memory(self, addr: int, size: int) -> bytes | None:
        """Read `size` bytes from `addr`. Returns bytes or None on failure."""
        r = self._send_recv('read_memory', {'address': hex(addr), 'size': size})
        if not isinstance(r, dict) or not r.get('success'):
            return None
        raw = r.get('bytes')
        if isinstance(raw, list):
            return bytes(raw)
        data_str = r.get('data', '')
        if data_str:
            try:
                return bytes(int(x, 16) for x in data_str.split())
            except ValueError:
                pass
        return None

    def disassemble(self, addr: int, count: int = 40) -> list[dict]:
        """Return a list of instruction dicts from CE's disassembler."""
        r = self._send_recv('disassemble', {'address': hex(addr), 'count': count})
        if not isinstance(r, dict):
            return []
        return r.get('instructions') or r.get('disassembly') or []

    def init_mono(self, wait: float = 3.5):
        """Launch the Mono data collector so class/method symbols resolve."""
        self.lua('LaunchMonoDataCollector(); return "ok"')
        time.sleep(wait)

    def get_process_info(self) -> dict:
        return self._send_recv('get_process_info')
