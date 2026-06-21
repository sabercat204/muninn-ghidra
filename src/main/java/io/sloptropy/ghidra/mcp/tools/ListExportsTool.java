package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Implements behavior spec: list_exports. */
public final class ListExportsTool implements McpTool {

    @Override public String getName() { return "list_exports"; }

    @Override
    public String getDescription() {
        return "List externally-callable entry points this program exposes. "
             + "Dual of list_imports. Mostly populated for libraries.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on symbol name."));
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

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_exports");
        }

        List<Map<String, Object>> matched = new ArrayList<>();
        try {
            SymbolTable st = program.getSymbolTable();
            AddressIterator it = st.getExternalEntryPointIterator();
            while (it.hasNext()) {
                Address a = it.next();
                if (a == null) continue;
                // Primary symbol at the export address is the export's name.
                Symbol primary = st.getPrimarySymbol(a);
                String name = primary != null ? primary.getName() : "";
                if (name == null) name = "";
                if (!filterLower.isEmpty()
                        && !name.toLowerCase(Locale.ROOT).contains(filterLower)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("symbol_name", name);
                row.put("address", ToolHelpers.formatAddress(program, a));
                row.put("ordinal", -1);    // PE-specific; surface-detection
                                            // deferred to a later phase
                Function fn = program.getFunctionManager().getFunctionAt(a);
                row.put("is_function", fn != null);
                row.put("is_forwarded", false);    // PE-specific; deferred
                row.put("forward_target", "");
                matched.add(row);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("export iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        // Already in address-ascending order from getExternalEntryPointIterator.

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
        result.put("exports", trimmed);
        return ToolHelpers.text(JsonRender.render(result));
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
