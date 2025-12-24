![repository-open-graph-template copy](https://github.com/user-attachments/assets/ff56c88c-5613-45c3-9228-644524fcd50e)

# Cheat Engine MCP Bridge

> **Let AI analyze the game memory for you.** Connect Claude, Cursor, or Copilot directly to Cheat Engine.

[![Version](https://img.shields.io/badge/version-11.4.0-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)

---

## The Problem

You're staring at gigabytes of memory. Millions of addresses. Thousands of functions. Finding *that one pointer*, *that one structure* takes **days or weeks** of manual work.

**What if you could just ask?**

> *"Find all functions that access the player health address."*  
> *"What's the structure at this pointer? Show me all the fields."*  
> *"Trace every instruction that writes to this memory: invisibly."*

**That's exactly what this does.**

---

## What You Get:

| Before (Manual) | After (AI-Assisted) |
|-----------------|---------------------|
| Day 1: Find health value | Minute 1: "Set breakpoint on health" |
| Day 2: Trace what writes to it | Minute 2: "What function wrote to it?" |
| Day 3: Find damage function | Minute 3: "Dissect the structure" |
| Day 4: Document structure | Minute 4: "Generate AOB signature" |
| Day 5: Game updates, start over | **Done.** |

**Your AI can now:**
- 🔍 Read any memory instantly (integers, floats, strings, pointers)
- 🔗 Follow pointer chains: `[[base+0x10]+0x20]+0x8` → resolved in ms
- 🧬 Auto-analyze structures with field types and values
- 🏷️ Identify C++ objects via RTTI: *"This is a CPlayer object"*
- 🔬 Disassemble and analyze functions
- 🕵️ Debug invisibly with hardware breakpoints + Ring -1 hypervisor

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AI Agent (Claude/Cursor/Copilot)                                      │
│       │                                                                 │
│       ▼ MCP Protocol (JSON-RPC over stdio)                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  mcp_cheatengine.py (Python MCP Server)                         │   │
│  │  - Translates MCP tools to JSON-RPC                             │   │
│  │  - Connects to \\.\pipe\CE_MCP_Bridge_v99                       │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │ Named Pipe (Async)                      │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  CheatEngine (Running, attached to .exe)                        │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │  ce_mcp_bridge.lua                                      │    │   │
│  │  │  ┌─────────────────┐      ┌─────────────────────┐       │    │   │
│  │  │  │ Worker Thread   │◄────►│ Main Thread (GUI)   │       │    │   │
│  │  │  │ (Blocking I/O)  │ Sync │ (Safe API Execution)│       │    │   │
│  │  │  └─────────────────┘      └─────────────────────┘       │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
pip install -r MCP_Server/requirements.txt
```
Or manually:
```bash
pip install mcp pywin32
```

> [!NOTE]
> **Windows only** - Uses Named Pipes (`pywin32`)

---

## Quick Start

### 1. Load Bridge in Cheat Engine
```
1. Enable DBVM in CheatEngine.
2. File → Execute Script → Open ce_mcp_bridge.lua → Execute
```
Look for: `[MCP v11.4.0] Server started on \\.\pipe\CE_MCP_Bridge_v99`

### 2. Configure MCP Client
Add to your MCP configuration (e.g., `mcp_config.json`):
```json
{
  "servers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:/path/to/MCP_Server/mcp_cheatengine.py"]
    }
  }
}
```
Don't forget to restart the IDE/RooCode/Cline/Cursor etc if it's not working.

### 3. Verify Connection
Use the `ping` tool to verify connectivity:
```json
{"success": true, "version": "11.4.0", "message": "CE MCP Bridge Active"}
```

### 4. Start Asking Questions
```
"What process is attached?"
"Read 16 bytes at the base address"
"Disassemble the entry point"
```

---

## 40+ Tools Available

### Memory
| Tool | Description |
|------|-------------|
| `read_memory`, `read_integer`, `read_string` | Read any data type |
| `read_pointer_chain` | Follow `[[base+0x10]+0x20]` paths |
| `scan_all`, `aob_scan` | Find values and byte patterns |

### Analysis
| Tool | Description |
|------|-------------|
| `disassemble`, `analyze_function` | Code analysis |
| `dissect_structure` | Auto-detect fields and types |
| `get_rtti_classname` | Identify C++ object types |
| `find_references`, `find_call_references` | Cross-references |

### Debugging
| Tool | Description |
|------|-------------|
| `set_breakpoint`, `set_data_breakpoint` | Hardware breakpoints |
| `start_dbvm_watch` | Ring -1 invisible tracing |

And many more at `AI_Context/MCP_Bridge_Command_Reference.md`

---

## Critical Configuration

### BSOD Prevention
> [!CAUTION]
> **You MUST disable:** Cheat Engine → Settings → Extra → **"Query memory region routines"**
> 
> Enabled: Causes `CLOCK_WATCHDOG_TIMEOUT` BSODs with DBVM/Anti-Cheat conflicts  
> Disabled: Scanning works perfectly and safely

### Anti-Cheat Safety Rules
- **DO NOT** use software breakpoints (0xCC/Int3)
- **DO NOT** write to memory
- **USE** Hardware Debug Registers (DR0-DR3) only
- **USE** DBVM for invisible Ring -1 tracing

---

## Example Workflows

**Finding a value:**
```
You: "Scan for gold: 15000"  →  AI finds 47 results
You: "Gold changed to 15100"  →  AI filters to 3 addresses
You: "What writes to the first one?"  →  AI sets hardware BP
You: "Disassemble that function"  →  Full AddGold logic revealed
```

**Understanding a structure:**
```
You: "What's at [[game.exe+0x1234]+0x10]?"
AI: "RTTI: CPlayerInventory"
AI: "0x00=vtable, 0x08=itemCount(int), 0x10=itemArray(ptr)..."
```

---

## Project Structure

```
MCP_Server/
├── mcp_cheatengine.py      # Python MCP Server (FastMCP)
├── ce_mcp_bridge.lua   # Cheat Engine Lua Bridge
└── test_mcp.py # Test Suite (36/37 passing)

AI_Context/
├── MCP_Bridge_Command_Reference.md   # MCP Commands reference
├── CE_LUA_Documentation.md   # Full CheatEngine 7.6 official documentation
└── AI_Guide_MCP_Server_Implementation.md  # Full technical documentation for AI agent
```

---

## Testing

Running the test:
```bash
python MCP_Server/test_mcp.py
```

Expected output:
```
✅ Memory Reading: 6/6 tests passed
✅ Process Info: 4/4 tests passed  
✅ Code Analysis: 8/8 tests passed
✅ Breakpoints: 4/4 tests passed
✅ DBVM Functions: 3/3 tests passed
✅ Utility Commands: 11/11 tests passed
⏭️ Skipped: 1 test (generate_signature)
────────────────────────────────────
Total: 36/37 PASSED (100% success)
```

---

## The Bottom Line

> **Stop clicking through hex dumps and start having conversations with the memory.**

You no longer need to be an expert. Just ask the right questions.

---

## License

MIT License - For educational and research purposes only.
