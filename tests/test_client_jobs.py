"""UNIT-25 tools (bridge_status, read_struct, batch, jobs, read_memory format): parameter forwarding, job wrappers and retry policy against a fake bridge.

Usage: python tests/test_client_jobs.py [path/to/mcp_cheatengine.py]
"""
import importlib.util, json, os, struct, sys, threading, time
import win32file, win32pipe

from testkit import arg_path, BRIDGE_PY, finish

path = str(arg_path(1, BRIDGE_PY))
spec = importlib.util.spec_from_file_location("mcp_cheatengine_under_test", path)
mod = importlib.util.module_from_spec(spec)
real_stdout = sys.stdout
spec.loader.exec_module(mod)
sys.stdout = real_stdout

NAME = "\\\\.\\pipe\\CE_OPS_%d" % os.getpid()
mod.PIPE_NAME = NAME
mod.CE_MCP_CONNECT_WAIT = 1.5
mod.ce_client.timeout_seconds = 1.0

seen = {}
params_seen = {}
lock = threading.Lock()
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


def reply(h, rid, result):
    send(h, json.dumps({"jsonrpc": "2.0", "result": result, "id": rid}).encode())


def serve_one(h):
    while True:
        n = struct.unpack("<I", read_exact(h, 4))[0]
        req = json.loads(read_exact(h, n).decode())
        m, rid, p = req["method"], req["id"], req.get("params", {})
        key = m
        if m == "batch":
            key = "batch:" + p["requests"][0]["method"]
        with lock:
            seen[key] = seen.get(key, 0) + 1
            count = seen[key]
            params_seen[m] = p
        if key == "batch:hang_write":
            continue                                    # never replies
        if key == "batch:get_hang_once" and count == 1:
            continue
        if m == "get_job":
            state = "running" if (p["job_id"] == "slow" or count <= 2) else "done"
            reply(h, rid, {"success": True, "job_id": p["job_id"], "state": state, "progress": {"current": count, "total": 10}})
        elif m == "bridge_status":
            reply(h, rid, {"success": True, "version": "12.0.0", "uptime_seconds": 5})
        else:
            reply(h, rid, {"success": True, "echo": m})


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
        time.sleep(0.1)


results = []


def check(name, cond, extra=""):
    results.append(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(extra)))
    print(results[-1], flush=True)


# ---- bridge_status while CE is unreachable (no pipe yet)
out = json.loads(mod.bridge_status())
check("offline bridge_status: reachable=false", out.get("reachable") is False and out.get("success") is False, out)
check("offline bridge_status: explains pipe not found", "pipe not found" in out["python_side"].get("last_connect_error", ""), out)
check("offline bridge_status: hint + python_side", "Cheat Engine" in out.get("hint", "") and out["python_side"]["server_pid"] == os.getpid(), out)

threading.Thread(target=server, daemon=True).start()
time.sleep(0.3)

out = json.loads(mod.bridge_status())
check("online bridge_status merges python_side", out.get("reachable") is True and out.get("version") == "12.0.0" and "transport" in out["python_side"], out)

# ---- read_memory defaults to compact hex
mod.read_memory("0x1000", 16)
check("read_memory sends format=hex by default", params_seen["read_memory"].get("format") == "hex", params_seen.get("read_memory"))
mod.read_memory("0x1000", 16, format="base64")
check("read_memory forwards explicit format", params_seen["read_memory"].get("format") == "base64")

# ---- read_struct / jobs tools forward their params
mod.read_struct("0x1000", [{"name": "hp", "type": "float", "offset": 4}])
check("read_struct forwards fields", params_seen["read_struct"]["fields"][0]["name"] == "hp")
mod.start_job("aob_scan", {"pattern": "90"})
check("start_job forwards kind+params", params_seen["start_job"] == {"kind": "aob_scan", "params": {"pattern": "90"}})
mod.start_job("find_references")
check("start_job params default to {}", params_seen["start_job"]["params"] == {})
mod.get_job_result("job_1", offset=5, limit=7)
check("get_job_result paging params", params_seen["get_job_result"] == {"job_id": "job_1", "offset": 5, "limit": 7})

# ---- wait_for_job
t0 = time.monotonic()
out = json.loads(mod.wait_for_job("fast", timeout_seconds=10, poll_interval=0.1))
check("wait_for_job returns when done", out.get("state") == "done" and not out.get("timed_out"), out)
check("wait_for_job did not wait for the timeout", time.monotonic() - t0 < 3, time.monotonic() - t0)
t0 = time.monotonic()
out = json.loads(mod.wait_for_job("slow", timeout_seconds=0.6, poll_interval=0.1))
check("wait_for_job times out cleanly", out.get("timed_out") is True and out.get("state") == "running", out)
check("wait_for_job honours its timeout", 0.5 < time.monotonic() - t0 < 2.5, time.monotonic() - t0)

# ---- batch_commands validation + retry policy
out = json.loads(mod.batch_commands([{"method": "batch"}, {"nomethod": 1}]))
check("batch rejects nested batch and missing method locally", out.get("error_code") == "INVALID_PARAMS" and "nested" in out["error"] and "needs a 'method'" in out["error"], out)
out = json.loads(mod.batch_commands([{"method": "read_integer", "params": {"address": "0x1"}}, {"method": "get_process_info"}]))
check("batch happy path", out.get("success") is True, out)
check("batch forwards stop_on_error", params_seen["batch"]["stop_on_error"] is False)

try:
    mod.batch_commands([{"method": "hang_write", "params": {}}])
    check("non-read-only batch times out with an error", False)
except ConnectionError as e:
    check("non-read-only batch: 'may or may not have run'", "may or may not have run" in str(e), e)
time.sleep(0.4)
check("non-read-only batch sent exactly once", seen.get("batch:hang_write") == 1, seen)

out = json.loads(mod.batch_commands([{"method": "get_hang_once"}, {"method": "read_memory", "params": {}}]))
check("all-read-only batch is retried after a timeout", out.get("success") is True and seen.get("batch:get_hang_once") == 2, (out, seen))

# ---- idempotency of the new tool names
for m, want in [("bridge_status", True), ("get_job", True), ("get_job_result", True), ("list_jobs", True), ("read_struct", True),
                ("start_job", False), ("cancel_job", False), ("batch", False)]:
    check("is_idempotent(%s)==%s" % (m, want), mod.is_idempotent(m) == want)

stop = True
finish()
