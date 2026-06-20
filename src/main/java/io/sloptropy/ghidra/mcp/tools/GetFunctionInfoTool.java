package io.sloptropy.ghidra.mcp.tools;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implements LOOM §4 spec: get_function_info.
 *
 * Per-entity detail tool. Read-only. Found-not-error pattern: function
 * not found returns found=false with isError=false. Opt-in decompile
 * via include_decompiled flag with bounded timeout.
 */
public final class GetFunctionInfoTool implements McpTool {

    @Override public String getName() { return "get_function_info"; }

    @Override
    public String getDescription() {
        return "Return detailed information about a single function: "
             + "signature, prototype, parameters, xref counts, analysis "
             + "flags, and optionally decompiled C-like source. "
             + "Use after list_functions to drill in.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("function", Map.of(
                "type", "string",
                "description", "Function entry address or globally-unique name. "
                             + "Address can be an interior body address; the "
                             + "tool falls back to containment resolution."));
        properties.put("include_decompiled", Map.of(
                "type", "boolean",
                "description", "If true, run Ghidra's decompiler and include "
                             + "the result. Default false; expensive.",
                "default", false));
        properties.put("decompile_timeout_seconds", Map.of(
                "type", "integer",
                "description", "Decompile timeout in seconds. Range 1-300. Default 30.",
                "default", 30));
        return new McpSchema.JsonSchema("object", properties,
                List.of("function"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // R-019: input validation first.
        Object fnRaw = arguments.get("function");
        if (!(fnRaw instanceof String) || ((String) fnRaw).isEmpty()) {
            return ToolHelpers.error(
                "function is required and must be a non-empty string");
        }
        String fnRef = (String) fnRaw;

        boolean includeDecompiled = Boolean.TRUE.equals(arguments.get("include_decompiled"));

        int timeout = 30;
        Object toRaw = arguments.get("decompile_timeout_seconds");
        if (toRaw instanceof Number n) {
            timeout = n.intValue();
        }
        if (timeout < 1 || timeout > 300) {
            return ToolHelpers.error(
                "decompile_timeout_seconds must be in [1, 300] (got: " + timeout + ")");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling get_function_info");
        }

        // Resolve.
        Resolution res;
        try {
            res = resolve(program, fnRef);
        } catch (AmbiguousNameException e) {
            return ToolHelpers.error(e.getMessage());
        } catch (Throwable t) {
            return ToolHelpers.error(
                "function inspection failed: " + t.getClass().getSimpleName()
                + ": " + (t.getMessage() == null ? "" : t.getMessage()));
        }

        if (res.function == null) {
            return ToolHelpers.text(JsonRender.render(notFoundResponse(includeDecompiled)));
        }

        Map<String, Object> result = buildResult(program, res, includeDecompiled, timeout);
        return ToolHelpers.text(JsonRender.render(result));
    }

    // ---------- resolution ----------

    private static final class Resolution {
        Function function;
        String mode;  // "entry_exact", "body_contains", "name_unique"
    }

    private static final class AmbiguousNameException extends RuntimeException {
        AmbiguousNameException(String msg) { super(msg); }
    }

    private static Resolution resolve(Program program, String ref) {
        Resolution r = new Resolution();
        FunctionManager fm = program.getFunctionManager();

        Address addr = ToolHelpers.parseAddress(program, ref);
        if (addr != null) {
            Function entry = fm.getFunctionAt(addr);
            if (entry != null) {
                r.function = entry;
                r.mode = "entry_exact";
                return r;
            }
            Function containing = fm.getFunctionContaining(addr);
            if (containing != null) {
                r.function = containing;
                r.mode = "body_contains";
                return r;
            }
            return r; // not found; r.function null, r.mode null
        }

        // Name resolution — must be unique among FUNCTION symbols.
        SymbolIterator it = program.getSymbolTable().getSymbols(ref);
        Function found = null;
        List<Function> all = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                Function f = fm.getFunctionAt(s.getAddress());
                if (f != null) all.add(f);
            }
        }
        if (all.isEmpty()) return r;
        if (all.size() > 1) {
            List<String> sample = new ArrayList<>();
            int limit = Math.min(5, all.size());
            for (int i = 0; i < limit; i++) {
                sample.add(ToolHelpers.formatAddress(program, all.get(i).getEntryPoint()));
            }
            throw new AmbiguousNameException(
                "function name is ambiguous; matches at addresses: " + sample
                + "; retry with an address");
        }
        r.function = all.get(0);
        r.mode = "name_unique";
        return r;
    }

    // ---------- response builders ----------

    private static Map<String, Object> notFoundResponse(boolean includeDecompiled) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("found", false);
        m.put("resolution_mode", "");
        m.put("name", "");
        m.put("entry", "");
        m.put("size_bytes", 0);
        m.put("namespace", "");
        m.put("signature", "");
        m.put("calling_convention", "");
        m.put("return_type", "");
        m.put("parameters", List.of());
        m.put("local_variable_count", 0);
        m.put("xref_in_count", 0);
        m.put("xref_out_count", 0);
        Map<String, Object> flags = new LinkedHashMap<>();
        flags.put("is_thunk", false);
        flags.put("is_external", false);
        flags.put("has_no_return", false);
        flags.put("has_custom_storage", false);
        flags.put("has_var_args", false);
        m.put("flags", flags);
        m.put("decompile_status", includeDecompiled ? "skipped" : "skipped");
        m.put("decompiled", "");
        return m;
    }

    private static Map<String, Object> buildResult(
            Program program, Resolution res, boolean includeDecompiled, int timeoutSeconds) {
        Function fn = res.function;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("found", true);
        m.put("resolution_mode", res.mode);
        m.put("name", fn.getName());
        m.put("entry", ToolHelpers.formatAddress(program, fn.getEntryPoint()));
        m.put("size_bytes", (int) fn.getBody().getNumAddresses());
        Namespace ns = fn.getParentNamespace();
        m.put("namespace", (ns == null || ns.isGlobal()) ? "" : ns.getName(true));

        m.put("signature", safeStr(fn.getPrototypeString(false, false)));
        m.put("calling_convention", safeStr(fn.getCallingConventionName()));
        m.put("return_type",
                fn.getReturnType() != null ? safeStr(fn.getReturnType().getDisplayName()) : "");

        List<Map<String, Object>> params = new ArrayList<>();
        Parameter[] parameters = fn.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            Parameter p = parameters[i];
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("index", i);
            row.put("name", safeStr(p.getName()));
            row.put("type", p.getDataType() != null ? safeStr(p.getDataType().getDisplayName()) : "");
            row.put("size_bytes", p.getLength());
            row.put("storage", p.getVariableStorage() != null ? safeStr(p.getVariableStorage().toString()) : "");
            params.add(row);
        }
        m.put("parameters", params);

        int localCount = 0;
        try {
            localCount = fn.getLocalVariables().length;
        } catch (Throwable t) { /* sentinel: 0 */ }
        m.put("local_variable_count", localCount);

        // xrefs
        int xrefIn = 0, xrefOut = 0;
        try {
            ReferenceManager rm = program.getReferenceManager();
            // Inbound: references TO the function entry. Count distinct
            // from-addresses.
            Set<Address> inFroms = new HashSet<>();
            for (Reference r : rm.getReferencesTo(fn.getEntryPoint())) {
                inFroms.add(r.getFromAddress());
            }
            xrefIn = inFroms.size();

            // Outbound: references FROM addresses inside the body that
            // resolve to function entries. Count distinct from-addresses
            // whose target is a function entry.
            Set<Address> outFroms = new HashSet<>();
            FunctionManager fm = program.getFunctionManager();
            for (Address bodyAddr : fn.getBody().getAddresses(true)) {
                Reference[] outs = rm.getReferencesFrom(bodyAddr);
                if (outs == null) continue;
                for (Reference r : outs) {
                    Address target = r.getToAddress();
                    if (target == null) continue;
                    Function targetFn = fm.getFunctionAt(target);
                    if (targetFn != null) {
                        outFroms.add(r.getFromAddress());
                        break; // one per from-address
                    }
                }
            }
            xrefOut = outFroms.size();
        } catch (Throwable t) {
            // sentinels: 0 / 0
        }
        m.put("xref_in_count", xrefIn);
        m.put("xref_out_count", xrefOut);

        Map<String, Object> flags = new LinkedHashMap<>();
        flags.put("is_thunk", fn.isThunk());
        flags.put("is_external", fn.isExternal());
        flags.put("has_no_return", fn.hasNoReturn());
        flags.put("has_custom_storage", fn.hasCustomVariableStorage());
        flags.put("has_var_args", fn.hasVarArgs());
        m.put("flags", flags);

        // Decompile (opt-in, bounded timeout)
        String decompileStatus = "skipped";
        String decompiled = "";
        if (includeDecompiled) {
            DecompInterface decomp = null;
            try {
                decomp = new DecompInterface();
                decomp.openProgram(program);
                DecompileResults dr = decomp.decompileFunction(fn, timeoutSeconds, TaskMonitor.DUMMY);
                if (dr == null) {
                    decompileStatus = "error";
                    decompiled = "decompiler returned no results";
                } else if (dr.isTimedOut()) {
                    decompileStatus = "timeout";
                    decompiled = "";
                } else if (!dr.decompileCompleted()) {
                    decompileStatus = "error";
                    decompiled = safeStr(dr.getErrorMessage());
                } else {
                    decompileStatus = "ok";
                    var decompiledFn = dr.getDecompiledFunction();
                    decompiled = decompiledFn != null ? safeStr(decompiledFn.getC()) : "";
                }
            } catch (Throwable t) {
                decompileStatus = "error";
                decompiled = t.getClass().getSimpleName()
                        + ": " + (t.getMessage() == null ? "" : t.getMessage());
            } finally {
                if (decomp != null) {
                    try { decomp.dispose(); } catch (Throwable ignored) {}
                }
            }
        }
        m.put("decompile_status", decompileStatus);
        m.put("decompiled", decompiled);

        return m;
    }

    private static String safeStr(String s) {
        return s == null ? "" : s;
    }
}
