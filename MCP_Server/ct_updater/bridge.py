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

    # ------------------------------------------------------------------
    # Address resolution
    # ------------------------------------------------------------------

    def resolve_address(self, addr_or_sym: 'str | int') -> int:
        """Accept 0x hex string, decimal string, int, or a CE symbol name."""
        if isinstance(addr_or_sym, int):
            return addr_or_sym
        s = str(addr_or_sym).strip()
        if s.startswith('0x') or s.startswith('0X'):
            return int(s, 16)
        if s.isdigit():
            return int(s)
        addr = self.get_symbol_addr(s)
        if addr is None:
            raise BridgeError(f"Cannot resolve symbol '{s}'")
        return addr

    # ------------------------------------------------------------------
    # Full-process value scan (single scan slot per session)
    # ------------------------------------------------------------------

    def scan_first(self, value, vtype: str = 'dword') -> int:
        """Start a new full-process scan. Returns hit count."""
        r = self._send_recv('scan_all', {'value': value, 'type': vtype})
        if not r.get('success'):
            raise BridgeError(f"scan_all: {r.get('error')}")
        return r['count']

    def scan_next(self, value=None, scan_type: str = 'exact') -> int:
        """Narrow the current scan. scan_type: exact|increased|decreased|changed|unchanged."""
        params: dict = {'scan_type': scan_type}
        if value is not None:
            params['value'] = value
        r = self._send_recv('next_scan', params)
        if not r.get('success'):
            raise BridgeError(f"next_scan: {r.get('error')}")
        return r['count']

    def scan_results(self, limit: int = 200, offset: int = 0) -> list:
        """Fetch result page from the current scan."""
        r = self._send_recv('get_scan_results', {'limit': limit, 'offset': offset})
        if not r.get('success'):
            raise BridgeError(f"get_scan_results: {r.get('error')}")
        return r.get('results', [])

    def scan_all_results(self, max_total: int = 100_000) -> list:
        """Return all scan result addresses (up to max_total) as integers."""
        addrs: list = []
        page = 500
        offset = 0
        while len(addrs) < max_total:
            batch = self.scan_results(limit=page, offset=offset)
            if not batch:
                break
            for r in batch:
                raw = r.get('address', '0')
                try:
                    addrs.append(int(raw, 16) if isinstance(raw, str) else int(raw))
                except (ValueError, TypeError):
                    pass
            offset += len(batch)
            if len(batch) < page:
                break
        return addrs

    # ------------------------------------------------------------------
    # Named persistent scans (run several in parallel)
    # ------------------------------------------------------------------

    def pscan_create(self, name: str) -> None:
        r = self._send_recv('create_persistent_scan', {'name': name})
        if not r.get('success'):
            raise BridgeError(f"create_persistent_scan: {r.get('error')}")

    def pscan_first(self, name: str, value, vtype: str = 'dword') -> int:
        r = self._send_recv('persistent_scan_first_scan',
                            {'name': name, 'value': value, 'type': vtype})
        if not r.get('success'):
            raise BridgeError(f"persistent_scan_first_scan: {r.get('error')}")
        return r['count']

    def pscan_next(self, name: str, value=None, scan_type: str = 'exact') -> int:
        params: dict = {'name': name, 'scan_option': scan_type}
        if value is not None:
            params['value'] = value
        r = self._send_recv('persistent_scan_next_scan', params)
        if not r.get('success'):
            raise BridgeError(f"persistent_scan_next_scan: {r.get('error')}")
        return r['count']

    def pscan_results(self, name: str, limit: int = 500, offset: int = 0) -> list:
        r = self._send_recv('persistent_scan_get_results',
                            {'name': name, 'limit': limit, 'offset': offset})
        if not r.get('success'):
            raise BridgeError(f"persistent_scan_get_results: {r.get('error')}")
        return r.get('results', [])

    def pscan_all_results(self, name: str, max_total: int = 100_000) -> list:
        """Fetch all addresses from a named persistent scan."""
        addrs: list = []
        page = 500
        offset = 0
        while len(addrs) < max_total:
            batch = self.pscan_results(name, limit=page, offset=offset)
            if not batch:
                break
            for r in batch:
                raw = r.get('address', '0')
                try:
                    addrs.append(int(raw, 16) if isinstance(raw, str) else int(raw))
                except (ValueError, TypeError):
                    pass
            offset += len(batch)
            if len(batch) < page:
                break
        return addrs

    def pscan_destroy(self, name: str) -> None:
        try:
            self._send_recv('persistent_scan_destroy', {'name': name})
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Memory write helpers
    # ------------------------------------------------------------------

    def write_int(self, addr: int, value: int, size: int = 4) -> None:
        method = {1: 'write_byte', 2: 'write_short', 4: 'write_integer',
                  8: 'write_qword'}.get(size, 'write_integer')
        r = self._send_recv(method, {'address': hex(addr), 'value': value})
        if not r.get('success'):
            raise BridgeError(f"{method}: {r.get('error')}")

    def write_float(self, addr: int, value: float) -> None:
        r = self._send_recv('write_float', {'address': hex(addr), 'value': value})
        if not r.get('success'):
            raise BridgeError(f"write_float: {r.get('error')}")

    # ------------------------------------------------------------------
    # Typed struct reads
    # ------------------------------------------------------------------

    def read_dword(self, addr: int) -> 'int | None':
        d = self.read_memory(addr, 4)
        return struct.unpack_from('<I', d)[0] if d else None

    def read_qword(self, addr: int) -> 'int | None':
        d = self.read_memory(addr, 8)
        return struct.unpack_from('<Q', d)[0] if d else None

    def read_float_val(self, addr: int) -> 'float | None':
        d = self.read_memory(addr, 4)
        return struct.unpack_from('<f', d)[0] if d else None
