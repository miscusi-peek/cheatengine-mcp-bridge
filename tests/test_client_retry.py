"""Exercise the MCP server's bridge client against a fake bridge on a real Windows named pipe:
retry policy, reconnect backoff, timeouts that must not hang, bad UTF-8 replies, RPC errors, id checks.

Usage: python tests/test_client_retry.py [path/to/mcp_cheatengine.py]
"""
import importlib.util, json, os, struct, sys, threading, time
import win32file, win32pipe, pywintypes

from testkit import arg_path, BRIDGE_PY, finish

path = str(arg_path(1, BRIDGE_PY))
spec = importlib.util.spec_from_file_location("mcp_cheatengine_under_test", path)
mod = importlib.util.module_from_spec(spec)
real_stdout = sys.stdout
spec.loader.exec_module(mod)
sys.stdout = real_stdout

NAME = r"\\.\pipe\CE_TEST_%d" % os.getpid()
mod.PIPE_NAME = NAME
mod.CE_MCP_CONNECT_WAIT = 2.0

seen = {}            # method -> number of requests the fake bridge received
lock = threading.Lock()
GAP = 0.3            # pipe is missing for this long after each disconnect (Lua: ~50ms+)
stop = False


def read_exact(h, n):
    buf = b""
    while len(buf) < n:
        _, chunk = win32file.ReadFile(h, n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send(h, raw):
    win32file.WriteFile(h, struct.pack("<I", len(raw)))
    win32file.WriteFile(h, raw)


def serve_one(h):
    while True:
        n = struct.unpack("<I", read_exact(h, 4))[0]
        req = json.loads(read_exact(h, n).decode())
        m, rid = req["method"], req["id"]
        with lock:
            seen[m] = seen.get(m, 0) + 1
            count = seen[m]
        if m == "hang_write_memory":
            continue                                   # never replies
        if m == "get_hang_once" and count == 1:
            continue
        if m == "get_badutf":
            raw = b'{"jsonrpc":"2.0","result":{"s":"a\xffb"},"id":%d}' % rid
        elif m == "get_rpcerr":
            raw = json.dumps({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found: x"}, "id": rid}).encode()
        elif m == "get_wrongid":
            raw = json.dumps({"jsonrpc": "2.0", "result": {"success": True}, "id": rid + 100}).encode()
        else:
            raw = json.dumps({"jsonrpc": "2.0", "result": {"success": True, "n": count}, "id": rid}).encode()
        send(h, raw)
        if m == "drop_after_reply":
            time.sleep(0.3)                             # let the client drain the reply first
            return                                      # bridge side hangs up


def server():
    while not stop:
        h = win32pipe.CreateNamedPipe(NAME, win32pipe.PIPE_ACCESS_DUPLEX,
                                      win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                                      1, 65536, 65536, 0, None)
        try:
            win32pipe.ConnectNamedPipe(h, None)
            serve_one(h)
        except Exception:
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h)
            except Exception:
                pass
            win32file.CloseHandle(h)
        time.sleep(GAP)   # like PipeWorker: destroy, sleep, re-create


results = []


def check(name, cond, extra=""):
    results.append(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(extra)))
    print(results[-1], flush=True)


def once(method):
    cl = new_client()
    try:
        return cl.send_command(method)
    finally:
        cl.close()
        time.sleep(0.5)


def new_client(timeout=1.0):
    c = mod.CENamedPipeBridgeClient()
    c.timeout_seconds = timeout
    return c


# --- before the pipe exists: fast, descriptive failure
c = new_client()
t0 = time.monotonic()
try:
    c.send_command("ping")
    check("no pipe -> ConnectionError", False)
except ConnectionError as e:
    dt = time.monotonic() - t0
    check("no pipe -> fails fast (<0.6s)", dt < 0.6, dt)
    check("no pipe -> message explains why", "pipe not found" in str(e), e)

threading.Thread(target=server, daemon=True).start()
time.sleep(0.2)

c = new_client()
r = c.send_command("ok_cmd")
check("basic call", r.get("success") is True and r.get("n") == 1, r)

# --- reconnect after the bridge hangs up (pipe re-created after GAP)
print("step: drop_after_reply", flush=True)
r = c.send_command("drop_after_reply")
check("call that precedes a hang-up still returns", r.get("success") is True, r)
time.sleep(0.4)   # bridge has hung up; its pipe is being re-created (missing for ~0.3s)
t0 = time.monotonic()
r = c.send_command("ok_cmd")        # NON-idempotent-looking name: only safe if it was never sent
dt = time.monotonic() - t0
check("reconnects across pipe re-creation", r.get("success") is True, r)
check("...waited for the pipe (backoff) rather than failing", 0.05 < dt < 2.5, dt)
check("...command executed exactly once", seen["ok_cmd"] == 2, seen)   # 1st call + this one
c.close(); time.sleep(0.5)

# --- non-idempotent command that never gets a reply must NOT be re-sent
c2 = new_client(timeout=0.8)
seen.pop("hang_write_memory", None)
try:
    c2.send_command("hang_write_memory", {"address": "0x1", "bytes": [1]})
    check("write timeout raises", False)
except ConnectionError as e:
    check("timed-out write -> error says outcome unknown", "may or may not have run" in str(e), e)
time.sleep(0.5)
check("timed-out write was sent exactly once", seen.get("hang_write_memory") == 1, seen)

# --- client is usable again right after that timeout (handle was closed/cancelled)
r = c2.send_command("ok_cmd")
check("usable after timeout", r.get("success") is True, r)
c2.close(); time.sleep(0.5)

# --- idempotent command IS retried after a timeout
c3 = new_client(timeout=0.8)
r = c3.send_command("get_hang_once")
check("read-only command retried after timeout", r.get("success") is True and seen["get_hang_once"] == 2, (r, seen))
c3.close(); time.sleep(0.5)

# --- invalid UTF-8 in a reply no longer kills the call
r = once("get_badutf")
check("invalid UTF-8 reply decoded with replacement", r.get("result", r).get("s") == "a\ufffdb" if isinstance(r, dict) else False, r)

# --- JSON-RPC error carries an error_code
r = once("get_rpcerr")
check("rpc error -> success False + NOT_FOUND", r.get("success") is False and r.get("error_code") == "NOT_FOUND", r)

# --- id mismatch is detected
try:
    once("get_wrongid")
    check("id mismatch detected", False)
except ConnectionError as e:
    check("id mismatch detected", "Out-of-sync" in str(e), e)

# --- pipe busy: second client while the first holds the single instance
holder = new_client()
holder.send_command("ok_cmd")
mod.CE_MCP_CONNECT_WAIT = 0.6
other = new_client()
t0 = time.monotonic()
try:
    other.send_command("ok_cmd")
    check("busy pipe -> ConnectionError", False)
except ConnectionError as e:
    dt = time.monotonic() - t0
    check("busy pipe -> waits ~CONNECT_WAIT then says why", 0.4 < dt < 1.5 and "busy" in str(e), (dt, e))
holder.close()

# --- idempotency table
for m, want in [("get_process_info", True), ("read_memory", True), ("aob_scan_unique", True), ("ping", True),
                ("get_breakpoint_hits", False), ("write_memory", False), ("auto_assemble", False),
                ("set_breakpoint", False), ("scan_all", False), ("next_scan", False), ("create_thread", False),
                ("read_region_from_file", False), ("show_message", False), ("clear_all_breakpoints", False)]:
    check("is_idempotent(%s)==%s" % (m, want), mod.is_idempotent(m) == want)

stop = True
finish()
