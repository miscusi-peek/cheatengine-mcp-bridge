"""Mutation check: break the bridge on purpose and make sure the offline suites notice.

Each mutant is a copy of ce_mcp_bridge.lua with one small, plausible bug applied. The matching suite must fail
(or crash) on it. A surviving mutant means a behaviour is not covered by a test.

    python tests/mutation_check.py

The mutations are anchored on exact source text; if the bridge code is edited and an anchor disappears the
mutant is reported as STALE - update the anchor here rather than ignoring it.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import testkit
from testkit import BRIDGE_LUA, EXIT_SKIP

TESTS = Path(__file__).resolve().parent

ROBUST, JOBS, ANALYSIS = "test_lua_robustness.py", "test_lua_jobs.py", "test_lua_analysis.py"
BREAKPOINTS = "test_lua_breakpoints.py"
XREFS = "test_lua_xrefs.py"
PATHSETS = "test_lua_pathsets.py"
LOAD = "test_lua_load.py"

# (name, suite, old text, new text, expected) - expected "caught" unless the bug cannot change any observable result
MUTANTS = [
    # --- JSON codec, replies and breakpoint recording
    ("int64_numbers_lossy", ROBUST, 'if math.type(val) == "integer" then return string.format("%d", val) end', 'if false then return string.format("%d", val) end', "caught"),
    ("invalid_utf8_not_sanitized", ROBUST, "sanitize_utf8(val):gsub('[%z\\1-\\31\\\\\"]', escape_char)", "val:gsub('[%z\\1-\\31\\\\\"]', escape_char)", "caught"),
    ("bp_callback_can_leave_target_halted", ROBUST, "local ok, result = pcall(body)", "local ok, result = true, body()", "caught"),
    ("bp_hit_buffer_uncapped", ROBUST, "if n >= MAX_HITS_PER_BP then", "if false then", "caught"),
    # --- UNIT-25 (jobs, reads, batch)
    ("scan_busy_guard_removed", JOBS, '    if serverState.scan_job_id then\n        return { success = false, error = "Scan job "', '    if false then\n        return { success = false, error = "Scan job "', "caught"),
    ("find_references_not_time_sliced", JOBS, 'if os.clock() >= deadline then jb.progress.current = jb._i; return false end\n            end\n            return finishList(jb, "references"', 'if false then jb.progress.current = jb._i; return false end\n            end\n            return finishList(jb, "references"', "caught"),
    ("poll_completion_disabled", JOBS, "and (p.CurrentlyScanned or 0) >= p.TotalAddressesToScan then", "and false then", "caught"),
    ("base64_padding_broken", JOBS, '(b and B64_CHARS[(n >> 6) & 63] or "=")', '(b and B64_CHARS[(n >> 6) & 63] or "")', "caught"),
    ("cleanup_skips_jobs", JOBS, "    if serverState.jobs then\n        for _, job in pairs(serverState.jobs) do\n            if job._fl then", "    if false then\n        for _, job in pairs(serverState.jobs) do\n            if job._fl then", "caught"),
    ("job_cap_removed", JOBS, "if running >= MAX_RUNNING_JOBS then", "if false then", "caught"),
    ("next_scan_job_destroys_shared_session", JOBS, "        j._ms = nil\n        j.progress = { current = 1, total = 1 }\n        jobFinish(j, \"done\", { result = { fields = { count = count } } })\n    end\n    ms.nextScan",
     "        j.progress = { current = 1, total = 1 }\n        j._temp = true\n        jobFinish(j, \"done\", { result = { fields = { count = count } } })\n    end\n    ms.nextScan", "caught"),
    ("batch_stop_on_error_ignored", JOBS, "if stopOnError then break end", "if false then break end", "caught"),
    # --- UNIT-26 (analysis)
    ("string_ref_carry_removed", ANALYSIS, "stages[#stages + 1] = { ranges = codeRanges, carry = 7, onStart", "stages[#stages + 1] = { ranges = codeRanges, carry = 0, onStart", "caught"),
    ("cave_run_not_continued_across_chunks", ANALYSIS, 'if run.nextAddr == dbase then\n                local s, e = data:find("^" .. pat)', 'if false then\n                local s, e = data:find("^" .. pat)', "caught"),
    ("cave_at_section_end_dropped", ANALYSIS, "stages = { { ranges = ranges, onDone = closeRun,", "stages = { { ranges = ranges,", "caught"),
    ("pointer_offsets_in_wrong_order", ANALYSIS, "local offs, cost = { entry.t - val }, entry.t - val\n                for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end",
     "local offs, cost = {}, entry.t - val\n                for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end\n                offs[#offs + 1] = entry.t - val", "caught"),
    ("diff_ignores_unchanged_pairs", ANALYSIS, 'if (pc[k] == "C" and same) or (pc[k] == "U" and not same) then ok = false; break end', 'if (pc[k] == "C" and same) then ok = false; break end', "caught"),
    ("export_forwarders_undetected", ANALYSIS, "local function isForwarder(rva) return rva >= dir.rva and rva < dir.rva + dir.size end", "local function isForwarder(rva) return false end", "caught"),
    ("rtti_base_classes_dropped", ANALYSIS, "for i = 0, math.min(nb, 64) - 1 do", "for i = 0, -1 do", "caught"),
    ("snapshot_budget_ignored", ANALYSIS, "if total + size > U26.SNAP_MAX_TOTAL then", "if false then", "caught"),
    ("string_match_start_ignored", ANALYSIS, "if anyMatch or s == 1 or data:byte(s - 1) == 0 then", "if true then", "caught"),
    ("import_ordinals_misread", ANALYSIS, "if (e.thunk & ordBit) ~= 0 then", "if false then", "caught"),
    ("section_flags_swapped", ANALYSIS, '((chars & 0x80000000) ~= 0 and "w" or "-") .. ((chars & 0x20000000) ~= 0 and "x" or "-")', '((chars & 0x20000000) ~= 0 and "w" or "-") .. ((chars & 0x80000000) ~= 0 and "x" or "-")', "caught"),
    # --- UNIT-27 part A (.pdata)
    ("pdata_end_treated_as_inclusive", ANALYSIS, "        elseif rva >= e then lo = mid + 1\n", "        elseif rva > e then lo = mid + 1\n", "caught"),
    ("pdata_chained_fragments_not_followed", ANALYSIS, "while primaryInfo and primaryInfo.chain and hops < 8 do", "while false do", "caught"),
    ("analyze_function_stops_at_first_ret", ANALYSIS, "if (b1 == 0xC3 or b1 == 0xC2) and not pd then", "if (b1 == 0xC3 or b1 == 0xC2) then", "caught"),
    ("find_function_boundaries_ignores_pdata", ANALYSIS, "        if okPd and pd then\n            return {\n                success = true, found = true, query_address", "        if false and pd then\n            return {\n                success = true, found = true, query_address", "caught"),
    ("exception_handler_not_read", ANALYSIS, "    elseif (flags & 3) ~= 0 then\n        local h = U26.u32(mod.base + tail)", "    elseif false then\n        local h = U26.u32(mod.base + tail)", "caught"),
    # --- UNIT-27 part B (struct recovery)
    ("recover_pointer_detection_off", ANALYSIS, "            if anyPtr and onlyPtrOrNull then", "            if false then", "caught"),
    ("recover_mixed_classes_accepted", ANALYSIS, "elseif one.raw_name ~= info.raw_name or one.vtable ~= info.vtable then", "elseif false then", "caught"),
    ("recover_tail_not_trimmed", ANALYSIS, "    size = math.max(P, ((last + 3) // 4) * 4)", "    size = size", "caught"),
    ("recover_floats_become_ints", ANALYSIS, "            elseif allFloat then", "            elseif false then", "caught"),
    ("recover_zero_runs_not_merged", ANALYSIS, 'if prev and prev.kind == "unknown" and prev.offset + prev.size == off then', "if false then", "caught"),
    ("recover_inline_text_missed", ANALYSIS, "            if len >= 4 and off + len < size and s1:byte(off + len + 1) == 0 then", "            if false then", "caught"),
    ("recover_string_pointers_untyped", ANALYSIS, "    local text = U26.printableAt(v)\n    if text then return \"string\", text end", "    local text = nil\n    if text then return \"string\", text end", "caught"),
    ("recover_int_next_to_float_read_as_double", ANALYSIS, "if low ~= 0 and (low <= 0xFFFF or low >= 0xFFFF0000) then return false end", "if false then return false end", "caught"),
    ("rtti_bases_offsets_ignored", ANALYSIS, 'bases[#bases + 1] = { name = U26.demangle(nm), offset = mdisp, virtual = (pdisp ~= -1), contained = contained }', 'bases[#bases + 1] = { name = U26.demangle(nm), offset = 99, virtual = true, contained = contained }', "caught"),
    # --- UNIT-27 part C (breakpoint control)
    ("bp_condition_ignored", BREAKPOINTS, "    local pass, condErr = BPX.test(bp)\n    if not pass then", "    local pass, condErr = true, nil\n    if not pass then", "caught"),
    ("bp_max_hits_not_enforced", BREAKPOINTS, "    if bp.max_hits and (bp.total_hits or 0) >= bp.max_hits then", "    if false then", "caught"),
    ("bp_break_mode_resumes_anyway", BREAKPOINTS, '        if ok and result == "halt" then return 1 end', "        if false then return 1 end", "caught"),
    ("bp_halt_returns_zero_which_ce_treats_as_resume", BREAKPOINTS, '        if ok and result == "halt" then return 1 end', '        if ok and result == "halt" then return 0 end', "caught"),
    ("bp_watchdog_never_resumes", BREAKPOINTS, "    if now >= h.deadline or now >= h.hard_deadline then", "    if false then", "caught"),
    ("bp_data_alignment_unchecked", BREAKPOINTS, "        if addr % size ~= 0 then", "        if false then", "caught"),
    ("bp_read_filter_removed", BREAKPOINTS, '        if accessType == "r" and prev ~= nil and value ~= prev then return nil end', "        if false then return nil end", "caught"),
    ("bp_detach_keeps_the_slot", BREAKPOINTS, "    if bp.slot then\n        serverState.hw_bp_slots[bp.slot] = nil\n        bp.slot = nil\n    end\n    bp.detached = true", "    bp.detached = true", "caught"),
    ("bp_debug_continue_keeps_halted", BREAKPOINTS, '        if method == "run" then\n            serverState.halted = nil', '        if false then\n            serverState.halted = nil', "caught"),
    ("bp_cleanup_leaves_thread_halted", BREAKPOINTS, "    if serverState.halted then\n        pcall(debug_continueFromBreakpoint, co_run)\n        serverState.halted = nil\n    end\n\n    -- 1. Remove all", "    if false then\n        pcall(debug_continueFromBreakpoint, co_run)\n        serverState.halted = nil\n    end\n\n    -- 1. Remove all", "caught"),
    ("bp_failed_install_leaks_state", BREAKPOINTS, '        serverState.breakpoints[bpId] = nil\n        serverState.breakpoint_hits[bpId] = nil\n        serverState.hw_bp_slots[slot] = nil\n        return { success = false, error = "debug_setBreakpoint failed: "', '        return { success = false, error = "debug_setBreakpoint failed: "', "caught"),
    ("bp_value_changed_lost", BREAKPOINTS, "            value_changed = changed,", "            value_changed = nil,", "caught"),
    ("bp_condition_failures_not_flagged", BREAKPOINTS, "    if condErr then hit.condition_error = condErr end", "    -- not flagged", "caught"),
    ("bp_outside_resume_not_noticed", BREAKPOINTS, "    if okB and not broken and not grace then", "    if false then", "caught"),
    ("bp_remove_does_not_resume", BREAKPOINTS, '        if serverState.halted and serverState.halted.id == bpId then BPX.resume("breakpoint removed") end', "", "caught"),
    ("bp_break_ignores_already_halted", BREAKPOINTS, "    if bp.mode == \"break\" and not serverState.halted then", "    if bp.mode == \"break\" then", "caught"),
    # --- UNIT-28 (cross-references)
    ("string_ref_modrm_class_loses_r12", ANALYSIS, "0x1D, 0x25, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value", "0x1D, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value", "caught"),
    ("xref_modrm_class_loses_r12", XREFS, "0x1D, 0x25, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value", "0x1D, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value", "caught"),
    ("byte_class_does_not_escape_punctuation", XREFS, 't[i] = c:match("%p") and ("%" .. c) or c', "t[i] = c", "caught"),
    ("xref_false_rip_candidates_kept", XREFS, "if not start then return nil end", "if not start then start = r.addr end", "caught"),
    ("xref_resync_starts_at_the_field", XREFS, "    local from = fieldStart - U26.XREF_RUNWAY\n    if floor then", "    local from = fieldStart - 1\n    if floor then", "caught"),
    ("xref_function_floor_ignored", XREFS, "if floor then from = math.max(floor, fieldStart - U26.XREF_RUNWAY_FROM_FUNCTION) end", "if false then from = math.max(floor, fieldStart - U26.XREF_RUNWAY_FROM_FUNCTION) end", "caught"),
    ("xref_function_floor_not_passed", XREFS, "local floor = fn and (mod.base + fn.primary.begin_rva) or nil", "local floor = nil", "caught"),
    ("xref_decoder_disagreement_accepted", XREFS, "if finish == e then return pos, e - pos end", "return pos, finish - pos", "caught"),
    ("xref_short_jump_boundary_unchecked", XREFS, 'if r.form == "rel8" and not U26.atBoundary(r.addr, floor) then return nil end', "if false then return nil end", "caught"),
    ("xref_short_jumps_missed", XREFS, "if want.jmp or want.jcc then\n                -- short jumps", "if false then\n                -- short jumps", "caught"),
    ("xref_pdata_rvas_reported", XREFS, 'if r.name ~= ".pdata" then ranges[#ranges + 1] = r end', "if true then ranges[#ranges + 1] = r end", "caught"),
    ("xref_unaligned_pointers_reported", XREFS, 'if a % P == 0 then add(mod, pe, a, "abs_data", nd.t) end', 'add(mod, pe, a, "abs_data", nd.t)', "caught"),
    ("xref_unaligned_rvas_reported", XREFS, 'if a % 4 == 0 then add(mod, pe, a, "rva", nd.t) end', 'add(mod, pe, a, "rva", nd.t)', "caught"),
    ("xref_code_carry_removed", XREFS, "stages[#stages + 1] = { ranges = execRanges, carry = 7, process = function(jb, data, dbase)", "stages[#stages + 1] = { ranges = execRanges, carry = 0, process = function(jb, data, dbase)", "caught"),
    ("xref_duplicates_not_filtered", XREFS, "        if seen[key] then return end\n        if #recs >= maxResults", "        if #recs >= maxResults", "caught"),
    ("xref_range_offset_missing", XREFS, "if st.size > 1 then item.offset_in_target = r.target - st.lo end", "if false then item.offset_in_target = r.target - st.lo end", "caught"),
    ("xref_range_ignored", XREFS, "hiEx = target + size, exact = size <= U26.XREF_NEEDLE_LIMIT", "hiEx = target + 1, exact = size <= U26.XREF_NEEDLE_LIMIT", "caught"),
    ("xref_truncation_unflagged", XREFS, "if st.ctx.truncated then fields.truncated = true;", "if false then fields.truncated = true;", "caught"),
    ("xref_memory_source_taken_for_destination", XREFS, 'if comma and br > comma then return "read" end', "", "caught"),
    ("xref_access_not_reported", XREFS, 'if r.kind == "rip" then item.access = U26.xrefAccess(text) end', "", "caught"),
    ("xref_default_module_is_always_main", XREFS, "picked = { U26.moduleFor(mods, target) or mods[1] }", "picked = { mods[1] }", "caught"),
    ("xref_function_not_reported", XREFS, '        if fn then\n            item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)\n            item.function_rva = fn.primary.begin_rva\n        end\n    end\n    return item, addr',
     '        if false then\n            item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)\n            item.function_rva = fn.primary.begin_rva\n        end\n    end\n    return item, addr', "caught"),
    ("xref_code_pointer_keeps_no_instruction", XREFS, "        if start then\n            addr = start\n            item.field_address = U26.hex(r.addr)", "        if false then\n            addr = start\n            item.field_address = U26.hex(r.addr)", "caught"),
    ("xref_trailing_immediate_ignored", XREFS, "for i, e in ipairs(U26.XREF_IMMS) do ends[i] = r.addr + r.width + e end", "for i, e in ipairs(U26.XREF_IMMS) do ends[i] = r.addr + r.width end", "caught"),
    # --- UNIT-30 (pointer path sets, two-run comparison)
    ("ps_hit_is_not_exact", PATHSETS, 'if status == "ok" and final == target then', 'if status == "ok" and math.abs(final - target) < 0x10 then', "caught"),
    ("ps_runs_not_counted", PATHSETS, "runs = r.runs + 1, idx = h.idx", "runs = r.runs, idx = h.idx", "caught"),
    ("ps_empty_set_stored", PATHSETS, 'if #chains == 0 then return nil, "nothing to store (an existing set is never overwritten with an empty one)" end', "", "caught"),
    ("ps_x86_addresses_not_wrapped", PATHSETS, "if not is64 then cur = cur & 0xFFFFFFFF end", "if false then cur = cur & 0xFFFFFFFF end", "caught"),
    ("ps_module_lookup_case_sensitive", PATHSETS, "local m = byName[rec.module:lower()]", "local m = byName[rec.module]", "caught"),
    ("ps_survivors_fewest_runs_first", PATHSETS, "if a.runs ~= b.runs then return a.runs > b.runs end", "if a.runs ~= b.runs then return a.runs < b.runs end", "caught"),
    ("ps_survivors_longest_first", PATHSETS, "if #a.offsets ~= #b.offsets then return #a.offsets < #b.offsets end", "if #a.offsets ~= #b.offsets then return #a.offsets > #b.offsets end", "caught"),
    ("ps_near_fix_wrong_sign", PATHSETS, "fix[#fix] = fix[#fix] - n.delta", "fix[#fix] = fix[#fix] + n.delta", "caught"),
    ("ps_near_misses_farthest_first", PATHSETS, "if da ~= db then return da < db end", "if da ~= db then return da > db end", "caught"),
    ("ps_near_delta_default_too_small", PATHSETS, "clampInt(params.near_delta or 0x100, 0, 0x10000)", "clampInt(params.near_delta or 0x10, 0, 0x10000)", "caught"),
    ("ps_same_process_inverted", PATHSETS, "local sameProcess = last ~= nil and last.pid ~= nil and last.pid == pr.pid", "local sameProcess = last ~= nil and last.pid ~= nil and last.pid ~= pr.pid", "caught"),
    ("ps_inline_duplicates_kept", PATHSETS, "if seenKey[key] then", "if false then", "caught"),
    ("ps_module_spelling_not_canonical", PATHSETS, "if m.name:lower() == lname then name = m.name; break end", "if false then name = m.name; break end", "caught"),
    ("ps_absolute_base_not_made_module_relative", PATHSETS, "if m then rec.module, rec.rva = m.name, base - m.base else rec.abs = base end", "rec.abs = base", "caught"),
    ("ps_history_unbounded", PATHSETS, "while #history > U26.PS_MAX_HISTORY do", "while false do", "caught"),
    ("ps_set_cap_missing", PATHSETS, "if not old and U26.psCount() >= U26.PS_MAX_SETS then", "if false then", "caught"),
    ("ps_saved_copy_shares_history", PATHSETS, "if src then for i, h in ipairs(src.history) do hist[i] = h end end", "if src then hist = src.history end", "caught"),
    ("ps_names_unchecked", PATHSETS, 'if type(v) == "string" and #v <= 48 and v:match("^[%w_%.%-]+$") then return v end', 'if type(v) == "string" then return v end', "caught"),
    ("ps_find_save_name_checked_after_the_scans", PATHSETS, "        if nerr then return nerr end\n    end\n    local mods = U26.listModules()\n    local st = {", "        if false then return nerr end\n    end\n    local mods = U26.listModules()\n    local st = {", "caught"),
    ("ps_survivors_not_paged", PATHSETS, "local limit, offset, page, total = paginate(params, survivors, 100)", "local limit, offset, page, total = paginate({}, survivors, 100)", "caught"),
    ("ps_fractional_offsets_accepted", PATHSETS, 'if math.type(v) == "float" then return math.tointeger(v) end', 'if math.type(v) == "float" then return v end', "caught"),
    ("ps_unreadable_pointer_read_as_null", PATHSETS, 'if not ptr then return "unreadable" end', "if not ptr then ptr = 0 end", "caught"),
    ("ps_found_set_starts_at_run_zero", PATHSETS, "return U26.psPut(name, recs, 1, { {", "return U26.psPut(name, recs, 0, { {", "caught"),
    # --- whole-file behaviour (the live smoke test found both of these)
    ("requireprocess_shadowed_by_the_boolean_variant", LOAD, "local function requireProcessBool()\n    local pid = getOpenedProcessID()\n    return pid and pid > 0\nend", "local function requireProcess()\n    local pid = getOpenedProcessID()\n    return pid and pid > 0\nend", "caught"),
    ("reload_leaves_the_previous_instance_running", LOAD, 'if type(StopMCPBridge) == "function" then\n    local okPrev', 'if false then\n    local okPrev', "caught"),
    # Defensive only: a false x86 locator is harmless unless something points at it, so no result changes.
    ("x86_locator_sanity_check_removed", ANALYSIS, "ok = nb >= 1 and nb <= 64 and arr >= mod.base and arr < mod.base + mod.size", "ok = true", "survives"),
]


def main():
    source = BRIDGE_LUA.read_bytes().decode("utf-8").replace("\r\n", "\n")
    stale = bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, suite, old, new, expected in MUTANTS:
            if source.count(old) != 1:
                print("STALE     %-40s anchor found %d times" % (name, source.count(old)))
                stale += 1
                continue
            mutant = Path(tmp) / ("mut_%s.lua" % name)
            mutant.write_bytes(source.replace(old, new, 1).encode("utf-8"))
            proc = subprocess.run([sys.executable, str(TESTS / suite), str(mutant)], capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", cwd=TESTS, timeout=600)
            if proc.returncode == EXIT_SKIP:
                print("SKIP      Lua DLL not available")
                sys.exit(EXIT_SKIP)
            caught = proc.returncode != 0
            verdict = {(True, "caught"): "caught   ", (False, "survives"): "survives*", (False, "caught"): "SURVIVED ", (True, "survives"): "caught(!)"}[(caught, expected)]
            if (caught, expected) in ((False, "caught"),):
                bad += 1
            print("%s %-40s [%s]" % (verdict, name, suite))
    total = len(MUTANTS)
    print("\n%d mutants: %d unexpected survivors, %d stale anchors  (* = documented survivor)" % (total, bad, stale))
    sys.exit(1 if bad or stale else 0)


if __name__ == "__main__":
    main()
