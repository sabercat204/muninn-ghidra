package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
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

/**
 * Implements LOOM §4 spec: list_functions.
 *
 * Read-only; structured-JSON output; deterministic by entry-address asc.
 */
public final class ListFunctionsTool implements McpTool {

    @Override public String getName() { return "list_functions"; }

    @Override
    public String getDescription() {
        return "List functions defined in the active program. "
             + "Supports name-substring filtering, max_results cap, and "
             + "thunk/external exclusion toggles. Returns deterministic, "
             + "entry-address-ordered structured JSON.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring filter on names. "
                             + "Empty string = no filter."));
        properties.put("max_results", Map.of(
                "type", "integer",
                "description", "Cap on returned rows. Default 1000. Min 1.",
                "default", 1000));
        properties.put("include_thunks", Map.of(
                "type", "boolean",
                "description", "Include thunk functions. Default false.",
                "default", false));
        properties.put("include_external", Map.of(
                "type", "boolean",
                "description", "Include externally-resolved functions. Default false.",
                "default", false));
        return new McpSchema.JsonSchema("object", properties, List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // R-019: input validation precedes environment checks. A caller
        // can fix an invalid argument without loading a program; can't
        // fix "no program" by adjusting an argument.
        Object filterRaw = arguments.get("filter");
        if (filterRaw != null && !(filterRaw instanceof String)) {
            return ToolHelpers.error(
                "filter must be a string (got: " + filterRaw.getClass().getSimpleName() + ")");
        }
        String filterLower = filterRaw == null
                ? ""
                : ((String) filterRaw).toLowerCase(Locale.ROOT);

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) {
            maxResults = n.intValue();
        }
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1 (got: " + maxResults + ")");
        }

        boolean includeThunks = Boolean.TRUE.equals(arguments.get("include_thunks"));
        boolean includeExternal = Boolean.TRUE.equals(arguments.get("include_external"));

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_functions");
        }

        FunctionManager fm;
        List<Function> matched = new ArrayList<>();
        try {
            fm = program.getFunctionManager();
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (!includeThunks && f.isThunk()) continue;
                if (!includeExternal && f.isExternal()) continue;
                if (!filterLower.isEmpty()
                        && !f.getName().toLowerCase(Locale.ROOT).contains(filterLower)) {
                    continue;
                }
                matched.add(f);
            }
        } catch (Throwable t) {
            return ToolHelpers.error(
                "function iteration failed: " + t.getClass().getSimpleName()
                + ": " + t.getMessage());
        }

        matched.sort(Comparator.comparing(Function::getEntryPoint));

        int totalMatched = matched.size();
        boolean truncated = totalMatched > maxResults;
        int returnCount = Math.min(totalMatched, maxResults);

        List<Map<String, Object>> rows = new ArrayList<>(returnCount);
        for (int i = 0; i < returnCount; i++) {
            Function f = matched.get(i);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", f.getName());
            row.put("entry", ToolHelpers.formatAddress(program, f.getEntryPoint()));
            row.put("size", (int) f.getBody().getNumAddresses());
            row.put("is_thunk", f.isThunk());
            row.put("is_external", f.isExternal());
            Namespace ns = f.getParentNamespace();
            row.put("namespace",
                    (ns == null || ns.isGlobal()) ? "" : ns.getName(true));
            rows.add(row);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("count", returnCount);
        result.put("total_matched", totalMatched);
        result.put("truncated", truncated);
        result.put("program", program.getName());
        result.put("functions", rows);

        return ToolHelpers.text(JsonRender.render(result));
    }
}
