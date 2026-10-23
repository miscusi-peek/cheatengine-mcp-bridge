"""Capability profiles and tool groups for the Cheat Engine MCP server.

Two independent switches, both set through the environment of the MCP server process:

  CE_MCP_PROFILE   what a client may DO (a security control, enforced on every call)
      readonly  observe only: read memory, process/module info, scans, disassembly, PE/RTTI/xref analysis
      analysis  + debugging and CE-side state: breakpoints, DBVM watches, symbols, structures, attaching, host introspection
      patch     + changing the target: write memory, registers, protection, allocations
      full      + code execution and host access: Lua, AutoAssembler, injection, shell, files, input automation, kernel writes
      default: full (unchanged behaviour). An unknown value fails CLOSED (readonly) with a warning on stderr.
  CE_MCP_ALLOW / CE_MCP_DENY   comma separated tool names: lift one tool above the profile / remove one below it (deny wins)
  CE_MCP_TOOLSET   which tools are LISTED to the client (not a permission, it only shrinks the schema the model must read)
      comma separated groups and presets, e.g. "reverse" or "core,memory,analysis". Default: all.

Enforcement lives in CEBridgeClient.send_command (every tool, plus the methods tucked inside batch_commands and
start_job, passes through it); hiding tools from the list is defence in depth and context saving, not the gate.
Anything that has no entry in CATALOG is treated as the highest tier, so a new tool must be classified deliberately
(tests/test_policy.py fails until it is).
"""
import sys

READ, DEBUG, WRITE, EXEC = 0, 1, 2, 3
TIER_NAMES = {READ: "read", DEBUG: "analysis", WRITE: "patch", EXEC: "full"}
PROFILES = {"readonly": READ, "analysis": DEBUG, "patch": WRITE, "full": EXEC}

# name -> (group, tier). Names are MCP tool names and bridge wire methods (they coincide except for a few aliases).
CATALOG = {}


def _g(group, tier, names):
    for name in names.split():
        assert name not in CATALOG, "duplicate catalogue entry: " + name
        CATALOG[name] = (group, tier)


# ---- core: always listed
_g("core", READ, "ping bridge_status policy_info get_process_info enum_modules get_thread_list get_module_size get_opened_process_id "
                 "get_opened_process_handle get_process_list get_processid_from_name batch_commands batch start_job get_job get_job_result "
                 "wait_for_job cancel_job list_jobs")
_g("core", DEBUG, "open_process")

# ---- memory
_g("memory", READ, "read_memory read_bytes read_integer read_string read_pointer read_pointer_chain read_struct checksum_memory md5_memory "
                   "compare_memory get_memory_regions enum_memory_regions_full get_memory_protection")
_g("memory", READ, "list_patches")
_g("memory", WRITE, "write_integer write_memory write_string copy_memory allocate_memory free_memory set_memory_protection full_access "
                    "undo_patch drop_patches")

# ---- scanning
_g("scan", READ, "scan_all next_scan get_scan_results aob_scan pattern_scan aob_scan_unique aob_scan_module aob_scan_module_unique "
                 "search_string generate_signature create_persistent_scan persistent_scan_first_scan persistent_scan_next_scan "
                 "persistent_scan_get_results persistent_scan_destroy pointer_rescan validate_pointer_chains analyze_pointer_access")

# ---- static analysis
_g("analysis", READ, "disassemble get_instruction_info find_function_boundaries analyze_function find_references find_call_references "
                     "dissect_structure get_rtti_classname pe_info pe_imports pe_exports pe_tls_callbacks va_to_rva rva_to_va rebase_address "
                     "export_names export_structures rtti_scan_module find_string_refs find_xrefs find_code_caves find_pointer_path "
                     "snapshot_region list_snapshots delete_snapshot diff_snapshots pe_functions recover_struct "
                     "compare_pointer_paths list_pointer_sets get_pointer_set drop_pointer_set")

# ---- symbols
_g("symbols", READ, "get_symbol_address get_address_info get_symbol_info enum_registered_symbols")
_g("symbols", DEBUG, "register_symbol unregister_symbol delete_all_registered_symbols import_names enable_windows_symbols "
                     "enable_kernel_symbols load_new_symbols reinitialize_symbol_handler")

# ---- structures (CE structure definitions)
_g("structures", READ, "get_structure_by_name get_structure_elements export_structure_to_xml")
_g("structures", DEBUG, "create_structure add_element_to_structure delete_structure")

# ---- cheat table / address list
_g("table", READ, "get_address_list get_memory_record get_memory_record_value")
_g("table", DEBUG, "create_memory_record delete_memory_record")
_g("table", WRITE, "set_memory_record_value")
_g("table", EXEC, "load_table save_table")             # tables carry Lua that runs on load

# ---- debugging
_g("debug", DEBUG, "set_breakpoint set_data_breakpoint set_execution_breakpoint set_write_breakpoint remove_breakpoint list_breakpoints "
                   "clear_all_breakpoints get_breakpoint_hits get_halted_state debug_get_context debug_get_xmm_pointer "
                   "debug_set_last_branch_recording debug_get_last_branch_record debug_set_breakpoint_for_thread "
                   "debug_remove_breakpoint_for_thread debug_process debug_is_debugging debug_get_current_debugger_interface "
                   "debug_break_thread debug_continue debug_detach pause_process unpause_process start_dbvm_watch stop_dbvm_watch "
                   "poll_dbvm_watch find_what_accesses_safe find_what_writes_safe get_watch_results")
_g("debug", WRITE, "debug_set_context")

# ---- assembly helpers
_g("asm", READ, "assemble_instruction generate_api_hook_script generate_code_injection_script")
_g("asm", EXEC, "auto_assemble auto_assemble_check compile_c_code compile_cs_code")   # AutoAssembler scripts can contain {$lua}

# ---- code execution in CE or the target
_g("exec", EXEC, "evaluate_lua create_thread queue_to_main_thread set_global_variable execute_code execute_code_ex execute_method "
                 "execute_code_local execute_code_local_ex inject_dll inject_dotnet_dll create_process")
_g("exec", DEBUG, "get_global_variable check_synchronize")
_g("exec", READ, "in_main_thread")

# ---- host: shell, files, clipboard
_g("system", EXEC, "run_command shell_execute delete_file write_region_to_file read_region_from_file read_clipboard write_clipboard")
_g("system", DEBUG, "file_exists get_file_list get_directory_list get_temp_folder get_file_version md5_file")

# ---- host: screen, input, dialogs, sound
_g("gui", DEBUG, "get_pixel get_mouse_pos is_key_pressed get_screen_info find_window get_window_caption get_window_class_name "
                 "get_window_process_id get_foreground_process output_debug_string speak_text play_sound beep set_progress_state "
                 "set_progress_value")
_g("gui", EXEC, "set_mouse_pos key_down key_up do_key_press send_window_message show_message input_query show_selection_list")

# ---- kernel / physical memory / shared sections
_g("kernel", DEBUG, "dbk_get_cr0 dbk_get_cr3 dbk_get_cr4 get_physical_address get_physical_address_cr3 read_process_memory_cr3")
_g("kernel", WRITE, "create_section map_view_of_section allocate_shared_memory")
_g("kernel", EXEC, "write_process_memory_cr3 map_memory unmap_memory dbk_writes_ignore_write_protection allocate_kernel_memory")

GROUPS = ("core", "memory", "scan", "analysis", "symbols", "structures", "table", "debug", "asm", "exec", "system", "gui", "kernel")

PRESETS = {
    "all": GROUPS,
    "minimal": ("core", "memory", "scan"),
    "reverse": ("core", "memory", "scan", "analysis", "symbols", "structures", "debug"),
}

# start_job kinds (all of them read the target or CE's memory scanner and nothing else)
JOB_KIND_TIERS = {
    "scan_all": READ, "next_scan": READ, "aob_scan": READ, "find_references": READ, "find_call_references": READ,
    "rtti_scan": READ, "find_string_refs": READ, "find_code_caves": READ, "find_pointer_path": READ, "find_xrefs": READ,
}

# wire methods that reach the user through a differently named tool: CE_MCP_DENY=batch_commands must stop `batch`
DENY_ALIASES = {"batch": ("batch_commands",)}


def _names(text):
    return frozenset(n.strip() for n in (text or "").replace(";", ",").split(",") if n.strip())


class Policy:
    def __init__(self, profile="full", allow=(), deny=(), toolset=None, warn=None):
        self.warnings = []
        self.profile = profile if profile in PROFILES else "readonly"
        if profile not in PROFILES:
            self.warnings.append("unknown CE_MCP_PROFILE %r: using 'readonly' (valid: %s)" % (profile, ", ".join(PROFILES)))
        self.max_tier = PROFILES[self.profile]
        self.allow, self.deny = frozenset(allow), frozenset(deny)
        self.groups = None                                    # None = every group
        if toolset:
            chosen = set()
            for name in _names(toolset):
                if name in PRESETS:
                    chosen.update(PRESETS[name])
                elif name in GROUPS:
                    chosen.add(name)
                else:
                    self.warnings.append("unknown CE_MCP_TOOLSET entry %r ignored (groups: %s; presets: %s)" % (name, ", ".join(GROUPS), ", ".join(PRESETS)))
            if chosen:
                chosen.add("core")
                self.groups = frozenset(chosen)
        for w in self.warnings:
            (warn or (lambda m: print("[policy] " + m, file=sys.stderr)))(w)

    # ---- classification
    @staticmethod
    def tier_of(method):
        entry = CATALOG.get(method)
        return entry[1] if entry else EXEC                   # unknown = most dangerous

    @staticmethod
    def group_of(method):
        entry = CATALOG.get(method)
        return entry[0] if entry else "core"

    # ---- enforcement
    def _allowed(self, method):
        if method in self.deny or any(a in self.deny for a in DENY_ALIASES.get(method, ())):
            return False, "denied by CE_MCP_DENY"
        if method in self.allow:
            return True, None
        tier = self.tier_of(method)
        if tier > self.max_tier:
            return False, "needs the '%s' profile (this server runs '%s')" % (TIER_NAMES[tier], self.profile)
        return True, None

    def check(self, method, params=None):
        """None when the call may proceed, else a bridge-style error reply."""
        ok, why = self._allowed(method)
        if not ok:
            return self._denied(method, why)
        params = params if isinstance(params, dict) else {}
        if method == "batch":
            reqs = params.get("requests")
            for req in reqs if isinstance(reqs, list) else []:
                inner = req.get("method") if isinstance(req, dict) else None
                if not isinstance(inner, str):
                    continue
                if inner == "batch":
                    return self._denied(inner, "batches cannot be nested")
                denial = self.check(inner, req.get("params"))
                if denial:
                    denial["error"] = "inside batch_commands: " + denial["error"]
                    return denial
        elif method == "start_job":
            kind = params.get("kind")
            if kind in self.deny or (kind in JOB_KIND_TIERS and {"rtti_scan": "rtti_scan_module"}.get(kind, kind) in self.deny):
                return self._denied("start_job(%s)" % kind, "denied by CE_MCP_DENY")
            if JOB_KIND_TIERS.get(kind, EXEC) > self.max_tier:
                return self._denied("start_job(%s)" % kind, "needs the '%s' profile (this server runs '%s')" % (TIER_NAMES[JOB_KIND_TIERS.get(kind, EXEC)], self.profile))
        return None

    def _denied(self, method, why):
        return {"success": False, "error_code": "PERMISSION_DENIED", "error": "%s is blocked: %s." % (method, why),
                "profile": self.profile, "hint": "Set CE_MCP_PROFILE (readonly | analysis | patch | full) or CE_MCP_ALLOW=<tool> in the MCP server's environment."}

    # ---- listing
    def visible(self, tool):
        if tool in self.deny:
            return False
        if tool not in self.allow and self.tier_of(tool) > self.max_tier:
            return False
        return self.groups is None or self.group_of(tool) in self.groups

    def hidden_reason(self, tool):
        if tool in self.deny:
            return "denied"
        if tool not in self.allow and self.tier_of(tool) > self.max_tier:
            return "profile"
        if self.groups is not None and self.group_of(tool) not in self.groups:
            return "toolset"
        return None

    def apply(self, mcp):
        """Unlist every tool this policy hides from an MCP server object. Returns the names removed."""
        removed = []
        for tool in list(mcp._tool_manager.list_tools()):
            if not self.visible(tool.name):
                mcp.remove_tool(tool.name)
                removed.append(tool.name)
        return removed


def policy_from_env(env):
    return Policy(profile=(env.get("CE_MCP_PROFILE") or "full").strip().lower(), allow=_names(env.get("CE_MCP_ALLOW")),
                  deny=_names(env.get("CE_MCP_DENY")), toolset=env.get("CE_MCP_TOOLSET"))
