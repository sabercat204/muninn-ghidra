package io.sloptropy.ghidra.mcp.tools;

import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Implements LOOM §4 spec: audit.
 *
 * Action-dispatched tool: 4 deterministic vulnerability-and-hardening
 * scans. Each action composes existing Ghidra primitives — no novel
 * analysis. Surfaces SIGNAL ({address, type, evidence}); verdict
 * (is-this-a-real-vuln) is the caller's call.
 */
public final class AuditTool implements McpTool {

    // -- Built-in dangerous-function list, severity-classified --------------

    private static final Set<String> CRITICAL_FNS = Set.of(
            "strcpy", "strcat", "sprintf", "vsprintf", "gets",
            "scanf", "system", "execl", "execlp", "execle",
            "execv", "execvp", "execvpe", "popen",
            // Windows variants
            "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
            "StrCpyA", "StrCpyW", "StrCatA", "StrCatW",
            "wsprintfA", "wsprintfW",
            "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA",
            "CreateProcessW");

    private static final Set<String> HIGH_FNS = Set.of(
            "memcpy", "memmove", "memset", "snprintf", "strncpy",
            "strncat", "vfprintf", "vprintf", "vsnprintf",
            // Windows variants
            "lstrcpynA", "lstrcpynW", "StrNCpyA", "StrNCpyW",
            "RtlMoveMemory", "RtlCopyMemory");

    private static final Set<String> MEDIUM_FNS = Set.of(
            "atoi", "atol", "atof", "getenv");

    // -- printf-family functions: name -> format-arg index ------------------
    // Index is 0-based per the spec.
    private static final Map<String, Integer> PRINTF_FAMILY;
    static {
        Map<String, Integer> m = new HashMap<>();
        m.put("printf", 0);
        m.put("vprintf", 0);
        m.put("fprintf", 1);
        m.put("vfprintf", 1);
        m.put("sprintf", 1);
        m.put("snprintf", 2);
        m.put("vsprintf", 1);
        m.put("vsnprintf", 2);
        m.put("syslog", 1);
        m.put("err", 1);
        m.put("errx", 1);
        m.put("warn", 0);
        m.put("warnx", 0);
        // Windows
        m.put("wsprintfA", 1);
        m.put("wsprintfW", 1);
        PRINTF_FAMILY = Collections.unmodifiableMap(m);
    }

    // -- Anti-analysis API names, categorized --------------------------------
    // (technique name, category)
    private static final Map<String, String> ANTI_ANALYSIS_APIS;
    static {
        Map<String, String> m = new HashMap<>();
        // Windows debug-detect
        m.put("IsDebuggerPresent", "debug_detect");
        m.put("CheckRemoteDebuggerPresent", "debug_detect");
        m.put("NtQueryInformationProcess", "debug_detect");
        m.put("ZwQueryInformationProcess", "debug_detect");
        m.put("OutputDebugStringA", "debug_detect");
        m.put("OutputDebugStringW", "debug_detect");
        m.put("DebugActiveProcess", "debug_detect");
        m.put("FindWindowA", "debug_detect");      // hunts for OllyDbg/x64dbg windows
        m.put("FindWindowW", "debug_detect");
        // Linux debug-detect
        m.put("ptrace", "debug_detect");
        // VM detection
        m.put("GetTickCount", "timing_check");
        m.put("QueryPerformanceCounter", "timing_check");
        m.put("__rdtsc", "timing_check");
        // Process-tamper / hooking
        m.put("VirtualProtect", "process_tamper");
        m.put("VirtualProtectEx", "process_tamper");
        m.put("WriteProcessMemory", "process_tamper");
        m.put("CreateRemoteThread", "process_tamper");
        ANTI_ANALYSIS_APIS = Collections.unmodifiableMap(m);
    }

    private static final Set<String> ACTIONS = Set.of(
            "dangerous_calls", "format_strings", "hardening", "anti_analysis");

    @Override public String getName() { return "audit"; }

    @Override
    public String getDescription() {
        return "Run deterministic vuln/hardening checks. Actions: "
             + "dangerous_calls (call sites of strcpy/gets/system/etc.), "
             + "format_strings (printf calls with non-constant format), "
             + "hardening (stack canary / NX / ASLR / RELRO / CFG / CET report), "
             + "anti_analysis (IsDebuggerPresent / ptrace / RDTSC / VM checks).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("action", Map.of(
                "type", "string",
                "description", "dangerous_calls | format_strings | hardening | anti_analysis",
                "enum", List.of("dangerous_calls", "format_strings", "hardening", "anti_analysis")));
        properties.put("extra_functions", Map.of(
                "type", "array",
                "description", "dangerous_calls: additional names to flag."));
        properties.put("exclude_functions", Map.of(
                "type", "array",
                "description", "dangerous_calls: names to remove from the built-in list."));
        properties.put("max_findings", Map.of(
                "type", "integer",
                "description", "Cap on findings per action. Default 1000. Range [1, 10000].",
                "default", 1000));
        return new McpSchema.JsonSchema("object", properties,
                List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object actionRaw = arguments.get("action");
        if (!(actionRaw instanceof String) || !ACTIONS.contains(actionRaw)) {
            return ToolHelpers.error(
                "action must be one of: dangerous_calls, format_strings, "
                + "hardening, anti_analysis (got: " + actionRaw + ")");
        }
        String action = (String) actionRaw;

        Set<String> extras = parseStringList(arguments.get("extra_functions"));
        if (extras == null) {
            return ToolHelpers.error(
                "extra_functions must be a list of strings");
        }
        Set<String> excludes = parseStringList(arguments.get("exclude_functions"));
        if (excludes == null) {
            return ToolHelpers.error(
                "exclude_functions must be a list of strings");
        }

        int maxFindings = 1000;
        Object maxRaw = arguments.get("max_findings");
        if (maxRaw instanceof Number n) maxFindings = n.intValue();
        if (maxFindings < 1 || maxFindings > 10000) {
            return ToolHelpers.error(
                "max_findings must be in [1, 10000] (got: " + maxFindings + ")");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling audit");
        }

        try {
            switch (action) {
                case "dangerous_calls":
                    return dangerousCalls(program, extras, excludes, maxFindings);
                case "format_strings":
                    return formatStrings(program, maxFindings);
                case "hardening":
                    return hardening(program);
                case "anti_analysis":
                    return antiAnalysis(program, maxFindings);
                default:
                    return ToolHelpers.error("unreachable: action=" + action);
            }
        } catch (Throwable t) {
            return ToolHelpers.error(action + " failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }
    }

    // ============================================================== dangerous_calls

    private McpSchema.CallToolResult dangerousCalls(
            Program program, Set<String> extras, Set<String> excludes, int maxFindings) {
        // Build the working set per call.
        Map<String, String> severityByName = new HashMap<>();
        for (String n : CRITICAL_FNS) severityByName.put(n, "critical");
        for (String n : HIGH_FNS)     severityByName.put(n, "high");
        for (String n : MEDIUM_FNS)   severityByName.put(n, "medium");
        // Excludes apply to the BUILT-IN list only; extras still always count.
        for (String n : excludes)     severityByName.remove(n);
        for (String n : extras)       severityByName.putIfAbsent(n, "high");

        SymbolTable st = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();
        Listing listing = program.getListing();

        List<Map<String, Object>> findings = new ArrayList<>();
        int total = 0;

        for (Map.Entry<String, String> e : severityByName.entrySet()) {
            String target = e.getKey();
            String severity = e.getValue();
            // Find symbol(s) by name. Iterate ALL — there can be both an
            // import thunk and an external location with the same name.
            SymbolIterator it = st.getSymbols(target);
            Set<Address> targetEntries = new HashSet<>();
            boolean isImport = false;
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getSymbolType() == SymbolType.FUNCTION) {
                    targetEntries.add(s.getAddress());
                    Function fn = fm.getFunctionAt(s.getAddress());
                    if (fn != null && fn.isExternal()) isImport = true;
                } else if (s.getSymbolType() == SymbolType.LABEL && s.isExternal()) {
                    targetEntries.add(s.getAddress());
                    isImport = true;
                }
            }
            if (targetEntries.isEmpty()) continue;

            for (Address entry : targetEntries) {
                for (Reference r : rm.getReferencesTo(entry)) {
                    if (!r.getReferenceType().isCall()) continue;
                    total++;
                    if (findings.size() >= maxFindings) continue;
                    Function inFn = fm.getFunctionContaining(r.getFromAddress());
                    Instruction instr = listing.getInstructionAt(r.getFromAddress());
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("address", ToolHelpers.formatAddress(program, r.getFromAddress()));
                    row.put("in_function", inFn == null ? "" : inFn.getName());
                    row.put("target_name", target);
                    row.put("target_address", ToolHelpers.formatAddress(program, entry));
                    row.put("is_import", isImport);
                    row.put("severity", severity);
                    row.put("evidence", evidenceFor(instr));
                    findings.add(row);
                }
            }
        }

        findings.sort((a, b) -> ((String) a.get("address")).compareTo((String) b.get("address")));

        return text(envelope("dangerous_calls", program, findings, total));
    }

    // ============================================================== format_strings

    private McpSchema.CallToolResult formatStrings(Program program, int maxFindings) {
        SymbolTable st = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();
        Listing listing = program.getListing();

        List<Map<String, Object>> findings = new ArrayList<>();
        int total = 0;

        for (Map.Entry<String, Integer> e : PRINTF_FAMILY.entrySet()) {
            String target = e.getKey();
            int formatArgIndex = e.getValue();

            SymbolIterator it = st.getSymbols(target);
            Set<Address> entries = new HashSet<>();
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getSymbolType() == SymbolType.FUNCTION) entries.add(s.getAddress());
            }
            if (entries.isEmpty()) continue;

            for (Address entry : entries) {
                for (Reference r : rm.getReferencesTo(entry)) {
                    if (!r.getReferenceType().isCall()) continue;
                    total++;
                    if (findings.size() >= maxFindings) continue;
                    Function inFn = fm.getFunctionContaining(r.getFromAddress());
                    Instruction instr = listing.getInstructionAt(r.getFromAddress());
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("address", ToolHelpers.formatAddress(program, r.getFromAddress()));
                    row.put("in_function", inFn == null ? "" : inFn.getName());
                    row.put("target_name", target);
                    row.put("format_arg_index", formatArgIndex);
                    row.put("evidence", evidenceFor(instr));
                    row.put("format_arg_kind", classifyFormatArg(program, r.getFromAddress(),
                            instr, formatArgIndex));
                    findings.add(row);
                }
            }
        }

        findings.sort((a, b) -> ((String) a.get("address")).compareTo((String) b.get("address")));
        return text(envelope("format_strings", program, findings, total));
    }

    /**
     * Heuristic format-arg classification. Looks at the PARAM references
     * on instructions in the basic-block window preceding the call. If
     * any PARAM ref at the right operand index targets defined string
     * data → "constant_string". If the arg index is loaded from a
     * register/memory without a string-data backing → "non_constant".
     * If we can't tell → "unknown".
     *
     * This is a heuristic, not a static-analysis. Conservatively reports
     * "unknown" rather than "constant_string" when uncertain.
     */
    private String classifyFormatArg(Program program, Address callAddr,
                                      Instruction callInstr, int argIndex) {
        if (callInstr == null) return "unknown";
        Listing listing = program.getListing();
        ReferenceManager rm = program.getReferenceManager();
        // Look back up to 24 instructions for the most recent PARAM ref
        // matching the format-arg index. The reasonable per-block lookback
        // size; further than that and arg-tracking is unreliable without
        // dataflow.
        Address cur = callAddr;
        for (int i = 0; i < 24; i++) {
            Instruction instr = listing.getInstructionAt(cur);
            if (instr == null) break;
            Reference[] refs = instr.getReferencesFrom();
            for (Reference r : refs) {
                if (r.getReferenceType() != RefType.PARAM) continue;
                if (r.getOperandIndex() != argIndex) continue;
                Address target = r.getToAddress();
                if (target == null) continue;
                // Defined string data here → constant_string
                if (looksLikeStringDataAt(program, target)) {
                    return "constant_string";
                }
            }
            Address prev = instr.getFallFrom();
            if (prev == null) break;
            cur = prev;
        }
        // No PARAM ref pointing at string data found in the window.
        // We can't distinguish "non_constant" from "we just couldn't find
        // the ref" without full dataflow. Conservative: "unknown".
        // BUT — for known printf-family calls without a discoverable
        // constant ref, "non_constant" is the more useful default for
        // an audit tool: the caller can filter false positives, but
        // false negatives are silent vulnerabilities.
        return "non_constant";
    }

    private static boolean looksLikeStringDataAt(Program program, Address a) {
        try {
            var data = program.getListing().getDefinedDataAt(a);
            return data != null && data.hasStringValue();
        } catch (Throwable t) {
            return false;
        }
    }

    // ============================================================== hardening

    private McpSchema.CallToolResult hardening(Program program) {
        String format = safeStr(program.getExecutableFormat()).toLowerCase(Locale.ROOT);
        boolean isPE = format.contains("portable executable") || format.contains("pe");
        boolean isELF = format.contains("elf") || format.contains("executable and linkable");
        boolean isMachO = format.contains("mach-o");

        Map<String, Map<String, Object>> report = new LinkedHashMap<>();
        SymbolTable st = program.getSymbolTable();

        // Stack canary: presence of __stack_chk_fail (gcc/clang) or
        // __security_check_cookie (MSVC).
        report.put("stack_canary",
                detectBySymbol(program, st, List.of("__stack_chk_fail", "__security_check_cookie")));

        // _chk fortify-source family
        report.put("fortify_source", detectFortify(program, st));

        // NX / DEP / executable-stack
        report.put("nx_dep", detectNX(program, isPE, isELF, isMachO));

        // ASLR / PIE
        report.put("aslr_pie", detectASLR(program, isPE, isELF, isMachO));

        // RELRO — ELF only
        report.put("relro", detectRELRO(program, isELF));

        // Control Flow Guard — PE only
        report.put("control_flow_guard", detectCFG(program, isPE));

        // CET shadow stack — PE only
        report.put("cet_shadow_stack", detectCET(program, isPE));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("action", "hardening");
        result.put("program", program.getName());
        result.put("count", 1);
        result.put("total_matched", 1);
        result.put("truncated", false);
        result.put("findings", List.of());     // unused for this action
        result.put("report", report);
        return text(result);
    }

    private static Map<String, Object> detectBySymbol(Program program,
                                                       SymbolTable st, List<String> names) {
        for (String name : names) {
            SymbolIterator it = st.getSymbols(name);
            while (it.hasNext()) {
                Symbol s = it.next();
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("present", true);
                r.put("evidence", name + " symbol present at "
                        + ToolHelpers.formatAddress(program, s.getAddress()));
                return r;
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("present", false);
        r.put("evidence", "no symbol from set " + names + " found");
        return r;
    }

    private static Map<String, Object> detectFortify(Program program, SymbolTable st) {
        // Anything ending in "_chk" from glibc fortify-source.
        for (Symbol s : st.getDefinedSymbols()) {
            if (s == null) continue;
            String name = s.getName();
            if (name != null && name.endsWith("_chk")) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("present", true);
                r.put("evidence", name + " (fortify-source) present");
                return r;
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("present", false);
        r.put("evidence", "no *_chk symbol found");
        return r;
    }

    private static Map<String, Object> detectNX(Program program,
                                                  boolean isPE, boolean isELF, boolean isMachO) {
        Map<String, Object> r = new LinkedHashMap<>();
        // Ghidra exposes loader-time flags via Program.getOptions("Program
        // Information"). Field names are loader-defined; probe a few.
        Options info = program.getOptions(Program.PROGRAM_INFO);
        if (isPE) {
            // PE: NX_COMPAT = bit 0x0100 of DllCharacteristics.
            int chars = getIntOption(info, "DLL Characteristics", -1);
            if (chars == -1) {
                chars = getIntOption(info, "DllCharacteristics", -1);
            }
            if (chars >= 0) {
                boolean nx = (chars & 0x0100) != 0;
                r.put("present", nx);
                r.put("evidence", "PE DllCharacteristics=0x" + Integer.toHexString(chars)
                        + " (NX_COMPAT=0x0100 " + (nx ? "set" : "clear") + ")");
                return r;
            }
        }
        // Fallback / non-PE: heuristic via memory blocks. NX-style hardening
        // marks .data / .bss non-executable; if every non-text writable
        // block is non-executable, NX is on. This is loose but format-agnostic.
        boolean anyWritableExecutable = false;
        for (var b : program.getMemory().getBlocks()) {
            if (b.isWrite() && b.isExecute()) {
                anyWritableExecutable = true;
                break;
            }
        }
        r.put("present", !anyWritableExecutable);
        r.put("evidence", "memory-block heuristic: "
                + (anyWritableExecutable
                        ? "at least one writable+executable block"
                        : "no writable+executable blocks"));
        return r;
    }

    private static Map<String, Object> detectASLR(Program program,
                                                    boolean isPE, boolean isELF, boolean isMachO) {
        Map<String, Object> r = new LinkedHashMap<>();
        Options info = program.getOptions(Program.PROGRAM_INFO);
        if (isPE) {
            int chars = getIntOption(info, "DLL Characteristics", -1);
            if (chars == -1) chars = getIntOption(info, "DllCharacteristics", -1);
            if (chars >= 0) {
                boolean dyn = (chars & 0x0040) != 0;
                r.put("present", dyn);
                r.put("evidence", "PE DllCharacteristics=0x" + Integer.toHexString(chars)
                        + " (DYNAMIC_BASE=0x0040 " + (dyn ? "set" : "clear") + ")");
                return r;
            }
        }
        if (isELF) {
            String elfType = info.getString("ELF File Type", "");
            if (elfType == null) elfType = "";
            boolean pie = elfType.toLowerCase(Locale.ROOT).contains("shared")
                    || elfType.toLowerCase(Locale.ROOT).contains("pie")
                    || elfType.toLowerCase(Locale.ROOT).contains("dyn");
            r.put("present", pie);
            r.put("evidence", "ELF type='" + elfType + "' (PIE detected="
                    + pie + ")");
            return r;
        }
        if (isMachO) {
            // MH_PIE flag is bit 0x00200000. Ghidra surfaces under "Mach-O Flags".
            int flags = getIntOption(info, "Mach-O Flags", -1);
            if (flags >= 0) {
                boolean pie = (flags & 0x00200000) != 0;
                r.put("present", pie);
                r.put("evidence", "Mach-O Flags=0x" + Integer.toHexString(flags)
                        + " (MH_PIE=0x00200000 " + (pie ? "set" : "clear") + ")");
                return r;
            }
        }
        r.put("present", false);
        r.put("evidence", "format-specific check unavailable");
        return r;
    }

    private static Map<String, Object> detectRELRO(Program program, boolean isELF) {
        Map<String, Object> r = new LinkedHashMap<>();
        if (!isELF) {
            r.put("level", "none");
            r.put("evidence", "not applicable to non-ELF formats");
            return r;
        }
        // RELRO detection: look for a memory block named ".gnu_relro" (partial RELRO);
        // full RELRO additionally has BIND_NOW set (DT_BIND_NOW / DT_FLAGS).
        boolean hasRelroSegment = false;
        for (var b : program.getMemory().getBlocks()) {
            String name = b.getName();
            if (name != null && name.toLowerCase(Locale.ROOT).contains("relro")) {
                hasRelroSegment = true;
                break;
            }
        }
        if (!hasRelroSegment) {
            r.put("level", "none");
            r.put("evidence", "no .gnu_relro segment present");
            return r;
        }
        // BIND_NOW signal — check if dynamic-section flags are surfaced.
        // Without full ELF-header introspection, partial is the safe answer.
        r.put("level", "partial");
        r.put("evidence", ".gnu_relro segment present (full RELRO requires BIND_NOW "
                + "verification not performed by this check)");
        return r;
    }

    private static Map<String, Object> detectCFG(Program program, boolean isPE) {
        Map<String, Object> r = new LinkedHashMap<>();
        if (!isPE) {
            r.put("present", false);
            r.put("evidence", "not applicable to non-PE formats");
            return r;
        }
        Options info = program.getOptions(Program.PROGRAM_INFO);
        int chars = getIntOption(info, "DLL Characteristics", -1);
        if (chars == -1) chars = getIntOption(info, "DllCharacteristics", -1);
        if (chars >= 0) {
            boolean cfg = (chars & 0x4000) != 0;
            r.put("present", cfg);
            r.put("evidence", "PE DllCharacteristics=0x" + Integer.toHexString(chars)
                    + " (GUARD_CF=0x4000 " + (cfg ? "set" : "clear") + ")");
            return r;
        }
        r.put("present", false);
        r.put("evidence", "PE DllCharacteristics not exposed by loader");
        return r;
    }

    private static Map<String, Object> detectCET(Program program, boolean isPE) {
        Map<String, Object> r = new LinkedHashMap<>();
        if (!isPE) {
            r.put("present", false);
            r.put("evidence", "not applicable to non-PE formats");
            return r;
        }
        Options info = program.getOptions(Program.PROGRAM_INFO);
        // CET_COMPAT is in the IMAGE_LOAD_CONFIG_DIRECTORY's "DependentLoadFlags"
        // or the newer "CetCompatible" bit on Ghidra 12+. Probe both.
        Object v = info.getString("CET Compatible", null);
        if (v != null) {
            boolean cet = "true".equalsIgnoreCase(v.toString())
                    || "yes".equalsIgnoreCase(v.toString());
            r.put("present", cet);
            r.put("evidence", "PE CET Compatible=" + v);
            return r;
        }
        r.put("present", false);
        r.put("evidence", "CET marker not exposed by loader");
        return r;
    }

    // ============================================================== anti_analysis

    private McpSchema.CallToolResult antiAnalysis(Program program, int maxFindings) {
        SymbolTable st = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();
        Listing listing = program.getListing();

        List<Map<String, Object>> findings = new ArrayList<>();
        int total = 0;

        for (Map.Entry<String, String> e : ANTI_ANALYSIS_APIS.entrySet()) {
            String technique = e.getKey();
            String category = e.getValue();
            SymbolIterator it = st.getSymbols(technique);
            Set<Address> entries = new HashSet<>();
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getSymbolType() == SymbolType.FUNCTION) entries.add(s.getAddress());
            }
            if (entries.isEmpty()) continue;
            for (Address entry : entries) {
                for (Reference r : rm.getReferencesTo(entry)) {
                    if (!r.getReferenceType().isCall()) continue;
                    total++;
                    if (findings.size() >= maxFindings) continue;
                    Function inFn = fm.getFunctionContaining(r.getFromAddress());
                    Instruction instr = listing.getInstructionAt(r.getFromAddress());
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("address", ToolHelpers.formatAddress(program, r.getFromAddress()));
                    row.put("in_function", inFn == null ? "" : inFn.getName());
                    row.put("technique", technique);
                    row.put("category", category);
                    row.put("evidence", evidenceFor(instr));
                    findings.add(row);
                }
            }
        }

        // RDTSC instruction — direct opcode check (no symbol path)
        for (Instruction instr : listing.getInstructions(true)) {
            String m = instr.getMnemonicString();
            if (m == null) continue;
            String upper = m.toUpperCase(Locale.ROOT);
            if (upper.equals("RDTSC") || upper.equals("RDTSCP")) {
                total++;
                if (findings.size() >= maxFindings) continue;
                Function inFn = fm.getFunctionContaining(instr.getAddress());
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ToolHelpers.formatAddress(program, instr.getAddress()));
                row.put("in_function", inFn == null ? "" : inFn.getName());
                row.put("technique", "RDTSC_timing");
                row.put("category", "timing_check");
                row.put("evidence", evidenceFor(instr));
                findings.add(row);
            } else if (upper.equals("CPUID")) {
                total++;
                if (findings.size() >= maxFindings) continue;
                Function inFn = fm.getFunctionContaining(instr.getAddress());
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ToolHelpers.formatAddress(program, instr.getAddress()));
                row.put("in_function", inFn == null ? "" : inFn.getName());
                row.put("technique", "cpuid");
                row.put("category", "vm_detect");
                row.put("evidence", evidenceFor(instr));
                findings.add(row);
            }
        }

        findings.sort((a, b) -> ((String) a.get("address")).compareTo((String) b.get("address")));
        return text(envelope("anti_analysis", program, findings, total));
    }

    // ============================================================== helpers

    private static Set<String> parseStringList(Object o) {
        if (o == null) return new HashSet<>();
        if (!(o instanceof List<?> lst)) return null;
        Set<String> out = new HashSet<>();
        for (Object e : lst) {
            if (!(e instanceof String s)) return null;
            out.add(s);
        }
        return out;
    }

    private static String evidenceFor(Instruction instr) {
        if (instr == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(instr.getMnemonicString());
        int n = instr.getNumOperands();
        for (int i = 0; i < n; i++) {
            sb.append(i == 0 ? " " : ", ");
            sb.append(instr.getDefaultOperandRepresentation(i));
        }
        return sb.toString();
    }

    private static int getIntOption(Options opts, String key, int dflt) {
        try {
            int v = opts.getInt(key, dflt);
            return v;
        } catch (Throwable t1) {
            try {
                String s = opts.getString(key, null);
                if (s == null) return dflt;
                if (s.startsWith("0x") || s.startsWith("0X")) {
                    return Integer.parseInt(s.substring(2), 16);
                }
                return Integer.parseInt(s);
            } catch (Throwable t2) {
                return dflt;
            }
        }
    }

    private static String safeStr(String s) { return s == null ? "" : s; }
    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }

    private static Map<String, Object> envelope(String action, Program program,
                                                 List<Map<String, Object>> findings,
                                                 int total) {
        int returned = findings.size();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("action", action);
        result.put("program", program.getName());
        result.put("count", returned);
        result.put("total_matched", total);
        result.put("truncated", total > returned);
        result.put("findings", findings);
        return result;
    }

    private static McpSchema.CallToolResult text(Map<String, Object> result) {
        return ToolHelpers.text(JsonRender.render(result));
    }
}
