package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.DuplicateNameException;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.Mutation;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implements LOOM §4 spec: rename_symbol.
 *
 * First mutating tool; uses {@link Mutation} for the EDT + transaction
 * boundary. Distinguishes tool-level isError=true (caller can't fix
 * without a different call shape) from renamed=false + isError=false
 * (semantic rejection the caller can retry on).
 */
public final class RenameSymbolTool implements McpTool {

    private static final Set<String> KINDS = Set.of(
            "function", "label", "global", "parameter", "local", "namespace");

    @Override public String getName() { return "rename_symbol"; }
    @Override public boolean isMutating() { return true; }

    @Override
    public String getDescription() {
        return "Rename a single symbol (function/label/global/parameter/"
             + "local/namespace) identified by name or address. "
             + "Validates new_name; aborts cleanly on duplicate-name "
             + "in the resolved namespace.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("target", Map.of(
                "type", "string",
                "description", "Address ('0x401000') or globally-unique "
                             + "symbol name. Empty string invalid."));
        properties.put("new_name", Map.of(
                "type", "string",
                "description", "New name. No whitespace, no '::' (namespace separator)."));
        properties.put("target_kind", Map.of(
                "type", "string",
                "description", "Optional disambiguator for multi-symbol "
                             + "addresses. One of: function, label, "
                             + "global, parameter, local, namespace."));
        properties.put("in_function", Map.of(
                "type", "string",
                "description", "Required when target_kind is parameter or "
                             + "local. Function name or address."));
        return new McpSchema.JsonSchema("object", properties,
                List.of("target", "new_name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // R-019: input validation first.
        Object targetRaw = arguments.get("target");
        if (!(targetRaw instanceof String) || ((String) targetRaw).isEmpty()) {
            return ToolHelpers.error(
                "target is required and must be a non-empty string");
        }
        String target = (String) targetRaw;

        Object newNameRaw = arguments.get("new_name");
        if (!(newNameRaw instanceof String) || ((String) newNameRaw).isEmpty()) {
            return ToolHelpers.error(
                "new_name is required and must be a non-empty string");
        }
        String newName = (String) newNameRaw;
        String newNameInvalidReason = validateNewName(newName);
        if (newNameInvalidReason != null) {
            return ToolHelpers.error("new_name is invalid: " + newNameInvalidReason);
        }

        Object kindRaw = arguments.get("target_kind");
        String targetKind = null;
        if (kindRaw != null) {
            if (!(kindRaw instanceof String)) {
                return ToolHelpers.error("target_kind must be a string");
            }
            targetKind = ((String) kindRaw).toLowerCase();
            if (!KINDS.contains(targetKind)) {
                return ToolHelpers.error(
                    "target_kind must be one of: function, label, global, "
                    + "parameter, local, namespace (got: " + kindRaw + ")");
            }
        }

        Object inFunctionRaw = arguments.get("in_function");
        String inFunction = null;
        if (inFunctionRaw != null) {
            if (!(inFunctionRaw instanceof String)) {
                return ToolHelpers.error("in_function must be a string");
            }
            inFunction = (String) inFunctionRaw;
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling rename_symbol");
        }

        // Resolve target on the caller's thread (read-only; thread-safe).
        ResolveResult rr = resolveTarget(program, target, targetKind);
        if (rr.error != null) {
            return ToolHelpers.error(rr.error);
        }

        // Parameter/local kinds require in_function; resolve it now.
        Function inFunctionResolved = null;
        if (rr.kind.equals("parameter") || rr.kind.equals("local")) {
            if (inFunction == null || inFunction.isEmpty()) {
                return ToolHelpers.error(
                    "in_function is required for target_kind=" + rr.kind);
            }
            inFunctionResolved = resolveFunction(program, inFunction);
            if (inFunctionResolved == null) {
                return ToolHelpers.error(
                    "in_function not found: " + inFunction);
            }
        }

        // Mutate inside an EDT-bridged transaction.
        String txName = "rename " + rr.kind + ": " + rr.oldName + " -> " + newName;
        final Function fnForVar = inFunctionResolved;
        final ResolveResult finalRR = rr;
        try {
            Object result = Mutation.run(program, txName, () -> {
                try {
                    if (finalRR.kind.equals("parameter") || finalRR.kind.equals("local")) {
                        Variable v = findVariable(fnForVar, finalRR.symbol);
                        if (v == null) {
                            return rejection(finalRR, newName,
                                "variable not found in function " + fnForVar.getName());
                        }
                        v.setName(newName, SourceType.USER_DEFINED);
                    } else {
                        finalRR.symbol.setName(newName, SourceType.USER_DEFINED);
                    }
                    return success(program, finalRR, newName);
                } catch (DuplicateNameException dne) {
                    return rejection(finalRR, newName,
                        "name '" + newName + "' already exists in namespace '"
                        + namespaceOf(finalRR.symbol) + "'");
                }
            });
            return ToolHelpers.text(JsonRender.render(result));
        } catch (Mutation.MutationException e) {
            Throwable cause = e.getCause();
            return ToolHelpers.error(
                "rename failed: " + cause.getClass().getSimpleName()
                + ": " + (cause.getMessage() == null ? "" : cause.getMessage()));
        }
    }

    private static String validateNewName(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) return "contains whitespace";
        }
        if (s.contains("::")) return "contains namespace separator '::'";
        return null;
    }

    /** Result of resolving the target string to a symbol + kind. */
    private static final class ResolveResult {
        Symbol symbol;
        String kind;       // canonical kind string
        String oldName;
        int secondariesIgnored;
        String error;      // non-null iff resolution failed
    }

    private static ResolveResult resolveTarget(Program program, String target, String requestedKind) {
        ResolveResult rr = new ResolveResult();
        SymbolTable st = program.getSymbolTable();

        // Try address first.
        Address addr = ToolHelpers.parseAddress(program, target);
        if (addr != null) {
            Symbol[] symbols = st.getSymbols(addr);
            if (symbols == null || symbols.length == 0) {
                rr.error = "target not found: " + target;
                return rr;
            }
            Symbol pick = null;
            if (requestedKind != null) {
                for (Symbol s : symbols) {
                    if (kindOf(s).equals(requestedKind)) {
                        pick = s;
                        break;
                    }
                }
                if (pick == null) {
                    List<String> have = new ArrayList<>();
                    for (Symbol s : symbols) have.add(kindOf(s));
                    rr.error = "no symbol of kind '" + requestedKind
                             + "' at " + target + "; kinds present: " + have;
                    return rr;
                }
            } else {
                // Primary symbol — Ghidra's primary marker.
                for (Symbol s : symbols) {
                    if (s.isPrimary()) { pick = s; break; }
                }
                if (pick == null) pick = symbols[0];
            }
            rr.symbol = pick;
            rr.kind = kindOf(pick);
            rr.oldName = pick.getName();
            rr.secondariesIgnored = Math.max(0, symbols.length - 1);
            return rr;
        }

        // Name resolution. Collect all matches; require unique.
        List<Symbol> matches = new ArrayList<>();
        SymbolIterator nameIter = st.getSymbols(target);
        while (nameIter.hasNext()) {
            matches.add(nameIter.next());
        }
        if (matches.isEmpty()) {
            rr.error = "target not found: " + target;
            return rr;
        }
        if (matches.size() > 1) {
            List<String> sample = new ArrayList<>();
            int limit = Math.min(5, matches.size());
            for (int i = 0; i < limit; i++) {
                Symbol s = matches.get(i);
                sample.add("(" + kindOf(s) + "@"
                        + ToolHelpers.formatAddress(program, s.getAddress()) + ")");
            }
            rr.error = "name is ambiguous; matches at: " + sample
                     + " — retry with an address";
            return rr;
        }
        rr.symbol = matches.get(0);
        rr.kind = kindOf(rr.symbol);
        rr.oldName = rr.symbol.getName();
        rr.secondariesIgnored = 0;
        return rr;
    }

    private static String kindOf(Symbol s) {
        SymbolType t = s.getSymbolType();
        if (t == SymbolType.FUNCTION) return "function";
        if (t == SymbolType.LABEL) return "label";
        if (t == SymbolType.PARAMETER) return "parameter";
        if (t == SymbolType.LOCAL_VAR) return "local";
        if (t == SymbolType.NAMESPACE || t == SymbolType.CLASS) return "namespace";
        // Treat everything else (GLOBAL, GLOBAL_VAR, etc.) as "global".
        return "global";
    }

    private static String namespaceOf(Symbol s) {
        var ns = s.getParentNamespace();
        if (ns == null || ns.isGlobal()) return "<global>";
        return ns.getName(true);
    }

    private static Function resolveFunction(Program program, String ref) {
        // Try address first.
        Address a = ToolHelpers.parseAddress(program, ref);
        FunctionManager fm = program.getFunctionManager();
        if (a != null) {
            Function f = fm.getFunctionAt(a);
            if (f != null) return f;
            return fm.getFunctionContaining(a);
        }
        // Name — must be unique.
        SymbolIterator it = program.getSymbolTable().getSymbols(ref);
        Function found = null;
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) continue;
                if (found != null) return null; // ambiguous
                found = f;
            }
        }
        return found;
    }

    private static Variable findVariable(Function fn, Symbol sym) {
        // Symbol address for params/locals maps to the variable storage
        // location. Walk parameters and locals, match by name.
        String name = sym.getName();
        for (Parameter p : fn.getParameters()) {
            if (p.getName().equals(name)) return p;
        }
        for (Variable v : fn.getLocalVariables()) {
            if (v.getName().equals(name)) return v;
        }
        return null;
    }

    private static Map<String, Object> success(Program program, ResolveResult rr, String newName) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("renamed", true);
        m.put("old_name", rr.oldName);
        m.put("new_name", newName);
        m.put("kind", rr.kind);
        m.put("address",
                rr.kind.equals("namespace")
                        ? ""
                        : ToolHelpers.formatAddress(program, rr.symbol.getAddress()));
        m.put("in_function", "");  // populated in caller when applicable
        m.put("secondary_symbols_ignored", rr.secondariesIgnored);
        m.put("reason", "");
        return m;
    }

    private static Map<String, Object> rejection(ResolveResult rr, String newName, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("renamed", false);
        m.put("old_name", rr.oldName);
        m.put("new_name", rr.oldName);  // unchanged
        m.put("kind", rr.kind);
        m.put("address", "");
        m.put("in_function", "");
        m.put("secondary_symbols_ignored", rr.secondariesIgnored);
        m.put("reason", reason);
        return m;
    }
}
