package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
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

/** Implements LOOM §4 spec: list_imports. */
public final class ListImportsTool implements McpTool {

    @Override public String getName() { return "list_imports"; }

    @Override
    public String getDescription() {
        return "List external symbols this program imports from other "
             + "modules (DLLs / SOs / dylibs). Returns library_name, "
             + "symbol_name, thunk_address, is_function.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on symbol_name."));
        properties.put("library_filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on library_name."));
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

        Object libRaw = arguments.get("library_filter");
        if (libRaw != null && !(libRaw instanceof String)) {
            return ToolHelpers.error("library_filter must be a string");
        }
        String libLower = libRaw == null
                ? ""
                : ((String) libRaw).toLowerCase(Locale.ROOT);

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_imports");
        }

        List<Map<String, Object>> matched = new ArrayList<>();
        try {
            ExternalManager em = program.getExternalManager();
            ReferenceManager rm = program.getReferenceManager();
            for (String lib : em.getExternalLibraryNames()) {
                if (!libLower.isEmpty()
                        && !lib.toLowerCase(Locale.ROOT).contains(libLower)) {
                    continue;
                }
                ExternalLocationIterator it = em.getExternalLocations(lib);
                while (it.hasNext()) {
                    ExternalLocation loc = it.next();
                    String name = loc.getLabel();
                    if (name == null) continue;
                    if (!filterLower.isEmpty()
                            && !name.toLowerCase(Locale.ROOT).contains(filterLower)) {
                        continue;
                    }
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("library_name", lib == null ? "" : lib);
                    row.put("symbol_name", name);
                    row.put("thunk_address",
                            findThunkAddress(program, rm, loc));
                    row.put("is_function", loc.isFunction());
                    matched.add(row);
                }
            }
        } catch (Throwable t) {
            return ToolHelpers.error("import iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        matched.sort(Comparator
                .comparing((Map<String, Object> m) ->
                        ((String) m.get("library_name")).toLowerCase(Locale.ROOT))
                .thenComparing(m ->
                        ((String) m.get("symbol_name")).toLowerCase(Locale.ROOT)));

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
        result.put("imports", trimmed);
        return ToolHelpers.text(JsonRender.render(result));
    }

    /**
     * Find the in-program thunk address that forwards to this external.
     * Strategy: if the ExternalLocation knows its symbol address, use
     * that. Otherwise find the first thunk function targeting this
     * external; otherwise "".
     */
    private static String findThunkAddress(Program program, ReferenceManager rm,
                                            ExternalLocation loc) {
        if (loc.getAddress() != null) {
            return ToolHelpers.formatAddress(program, loc.getAddress());
        }
        // Walk thunk functions in the program for one matching this external.
        try {
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.isThunk()) {
                    Function thunked = f.getThunkedFunction(false);
                    if (thunked != null && thunked.isExternal()
                            && thunked.getName().equals(loc.getLabel())) {
                        return ToolHelpers.formatAddress(program, f.getEntryPoint());
                    }
                }
            }
        } catch (Throwable ignored) {}
        return "";
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
