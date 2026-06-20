package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Implements LOOM §4 spec: list_symbols. */
public final class ListSymbolsTool implements McpTool {

    private static final Set<String> KINDS = Set.of(
            "function", "label", "global", "parameter", "local",
            "namespace", "class", "any");

    @Override public String getName() { return "list_symbols"; }

    @Override
    public String getDescription() {
        return "Enumerate symbols of any kind (function/label/global/"
             + "parameter/local/namespace/class). Generalizes list_functions. "
             + "Substring + kind + namespace filters; default-name exclusion toggle.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on name."));
        properties.put("kind", Map.of(
                "type", "string",
                "description", "function|label|global|parameter|local|namespace|class|any. Default any.",
                "default", "any"));
        properties.put("namespace_filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on qualified namespace."));
        properties.put("include_default_names", Map.of(
                "type", "boolean",
                "description", "Include FUN_/DAT_/LAB_/local_/param_ auto-names. Default true.",
                "default", true));
        properties.put("max_results", Map.of(
                "type", "integer",
                "description", "Cap on rows. Default 1000. Min 1.",
                "default", 1000));
        return new McpSchema.JsonSchema("object", properties, List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object filterRaw = arguments.get("filter");
        if (filterRaw != null && !(filterRaw instanceof String)) {
            return ToolHelpers.error("filter must be a string");
        }
        String filterLower = filterRaw == null
                ? ""
                : ((String) filterRaw).toLowerCase(Locale.ROOT);

        Object kindRaw = arguments.get("kind");
        String kind = "any";
        if (kindRaw != null) {
            if (!(kindRaw instanceof String)) {
                return ToolHelpers.error("kind must be a string");
            }
            kind = ((String) kindRaw).toLowerCase(Locale.ROOT);
            if (!KINDS.contains(kind)) {
                return ToolHelpers.error(
                    "kind must be one of: function, label, global, parameter, "
                    + "local, namespace, class, any (got: " + kindRaw + ")");
            }
        }

        Object nsRaw = arguments.get("namespace_filter");
        if (nsRaw != null && !(nsRaw instanceof String)) {
            return ToolHelpers.error("namespace_filter must be a string");
        }
        String nsLower = nsRaw == null
                ? ""
                : ((String) nsRaw).toLowerCase(Locale.ROOT);

        Object includeDefRaw = arguments.get("include_default_names");
        if (includeDefRaw != null && !(includeDefRaw instanceof Boolean)) {
            return ToolHelpers.error("include_default_names must be a boolean");
        }
        boolean includeDefault = includeDefRaw == null
                ? true
                : (Boolean) includeDefRaw;

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_symbols");
        }

        List<Map<String, Object>> matched = new ArrayList<>();
        try {
            SymbolTable st = program.getSymbolTable();
            // getAllSymbols(boolean): true = include dynamic auto-generated
            // symbols. We pass our include_default_names flag through.
            SymbolIterator it = st.getAllSymbols(includeDefault);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s == null) continue;
                String name = s.getName();
                if (!filterLower.isEmpty()
                        && !name.toLowerCase(Locale.ROOT).contains(filterLower)) {
                    continue;
                }
                String resolvedKind = kindOf(s);
                if (!"any".equals(kind) && !resolvedKind.equals(kind)) continue;

                Namespace ns = s.getParentNamespace();
                String nsPath = (ns == null || ns.isGlobal())
                        ? ""
                        : ns.getName(true);
                if (!nsLower.isEmpty()
                        && !nsPath.toLowerCase(Locale.ROOT).contains(nsLower)) {
                    continue;
                }

                // Belt-and-suspenders default-name exclusion: even with
                // getAllSymbols(false), Ghidra's "dynamic" filter doesn't
                // exclude statically-assigned default-shaped names. Apply
                // the prefix filter as a second pass when the caller
                // asked us to.
                if (!includeDefault && looksLikeDefaultName(name)) continue;

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", name);
                row.put("address",
                        resolvedKind.equals("namespace") || resolvedKind.equals("class")
                                ? ""
                                : ToolHelpers.formatAddress(program, s.getAddress()));
                row.put("kind", resolvedKind);
                row.put("namespace", nsPath);
                row.put("source", sourceName(s.getSource()));
                row.put("is_primary", s.isPrimary());
                matched.add(row);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("symbol iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        matched.sort(Comparator
                .comparing((Map<String, Object> m) -> (String) m.get("address"))
                .thenComparing(m -> (String) m.get("name")));

        int total = matched.size();
        int returned = Math.min(total, maxResults);
        List<Map<String, Object>> trimmed = total > returned
                ? matched.subList(0, returned)
                : matched;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("count", returned);
        result.put("total_matched", total);
        result.put("truncated", total > returned);
        result.put("program", program.getName());
        result.put("symbols", trimmed);
        return ToolHelpers.text(JsonRender.render(result));
    }

    private static String kindOf(Symbol s) {
        SymbolType t = s.getSymbolType();
        if (t == SymbolType.FUNCTION) return "function";
        if (t == SymbolType.LABEL) return "label";
        if (t == SymbolType.PARAMETER) return "parameter";
        if (t == SymbolType.LOCAL_VAR) return "local";
        if (t == SymbolType.CLASS) return "class";
        if (t == SymbolType.NAMESPACE) return "namespace";
        return "global";
    }

    private static String sourceName(SourceType st) {
        if (st == null) return "default";
        switch (st) {
            case USER_DEFINED: return "user";
            case IMPORTED:     return "imported";
            case ANALYSIS:     return "analysis";
            case DEFAULT:      return "default";
            default:           return "default";
        }
    }

    private static boolean looksLikeDefaultName(String name) {
        if (name == null) return true;
        // Ghidra's common auto-generated prefixes
        return name.startsWith("FUN_") || name.startsWith("DAT_")
                || name.startsWith("LAB_") || name.startsWith("SUB_")
                || name.startsWith("OFF_") || name.startsWith("UNK_")
                || name.startsWith("local_") || name.startsWith("param_")
                || name.startsWith("uVar") || name.startsWith("iVar")
                || name.startsWith("piVar") || name.startsWith("ppuVar");
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
