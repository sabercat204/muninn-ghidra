package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Implements LOOM §4 spec: get_xrefs. */
public final class GetXrefsTool implements McpTool {

    private static final Set<String> DIRECTIONS = Set.of("to", "from", "both");
    private static final Set<String> SIMPLIFIED = Set.of(
            "call", "jump", "branch", "data_read", "data_write",
            "pointer", "indirect", "param", "thunk", "any");

    @Override public String getName() { return "get_xrefs"; }

    @Override
    public String getDescription() {
        return "Cross-references for an address: inbound (callers/accessors), "
             + "outbound (what this touches), or both. Reference-type filter. "
             + "Closes the count-only gap left by get_function_info.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("address", Map.of(
                "type", "string",
                "description", "Address to query. Round-trippable format."));
        properties.put("direction", Map.of(
                "type", "string",
                "description", "to | from | both. Default to.",
                "default", "to"));
        properties.put("ref_types", Map.of(
                "type", "array",
                "description", "Filter by simplified ref types: call, jump, "
                             + "branch, data_read, data_write, pointer, indirect, "
                             + "param, thunk, any. Default [any]."));
        properties.put("max_results", Map.of(
                "type", "integer",
                "description", "Cap per direction. Default 1000. Min 1.",
                "default", 1000));
        return new McpSchema.JsonSchema("object", properties,
                List.of("address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object addrRaw = arguments.get("address");
        if (!(addrRaw instanceof String) || ((String) addrRaw).isEmpty()) {
            return ToolHelpers.error(
                "address is required and must be a non-empty string");
        }
        String addrStr = (String) addrRaw;

        String direction = "to";
        Object dirRaw = arguments.get("direction");
        if (dirRaw != null) {
            if (!(dirRaw instanceof String)) {
                return ToolHelpers.error("direction must be a string");
            }
            direction = ((String) dirRaw).toLowerCase(Locale.ROOT);
            if (!DIRECTIONS.contains(direction)) {
                return ToolHelpers.error(
                    "direction must be one of: to, from, both (got: " + dirRaw + ")");
            }
        }

        Set<String> refTypeFilter = Set.of("any");
        Object rtRaw = arguments.get("ref_types");
        if (rtRaw != null) {
            if (!(rtRaw instanceof List<?> lst)) {
                return ToolHelpers.error("ref_types must be an array of strings");
            }
            java.util.HashSet<String> picked = new java.util.HashSet<>();
            for (Object e : lst) {
                if (!(e instanceof String s)) {
                    return ToolHelpers.error("ref_types entries must be strings");
                }
                String lower = s.toLowerCase(Locale.ROOT);
                if (!SIMPLIFIED.contains(lower)) {
                    return ToolHelpers.error(
                        "ref_types contains unknown value: " + s
                        + "; allowed: call, jump, branch, data_read, data_write, "
                        + "pointer, indirect, param, thunk, any");
                }
                picked.add(lower);
            }
            if (!picked.isEmpty()) refTypeFilter = picked;
        }

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling get_xrefs");
        }

        Address addr = ToolHelpers.parseAddress(program, addrStr);
        if (addr == null) {
            return ToolHelpers.error("invalid address: " + addrStr);
        }
        Memory mem = program.getMemory();
        if (!mem.contains(addr)) {
            return ToolHelpers.error(
                "address " + addrStr + " is not in any memory block");
        }

        ReferenceManager rm = program.getReferenceManager();
        FunctionManager fm = program.getFunctionManager();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", ToolHelpers.formatAddress(program, addr));
        result.put("program", program.getName());

        try {
            if (direction.equals("to") || direction.equals("both")) {
                result.put("to", buildToBlock(program, fm, rm, addr,
                        refTypeFilter, maxResults));
            }
            if (direction.equals("from") || direction.equals("both")) {
                result.put("from", buildFromBlock(program, fm, rm, addr,
                        refTypeFilter, maxResults));
            }
        } catch (Throwable t) {
            return ToolHelpers.error("xref iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }
        return ToolHelpers.text(JsonRender.render(result));
    }

    private static Map<String, Object> buildToBlock(
            Program program, FunctionManager fm, ReferenceManager rm,
            Address addr, Set<String> filter, int maxResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        int total = 0;
        for (Reference r : rm.getReferencesTo(addr)) {
            String simplified = simplifyRefType(r.getReferenceType());
            if (!filter.contains("any") && !filter.contains(simplified)) continue;
            total++;
            if (rows.size() >= maxResults) continue;
            Function fn = fm.getFunctionContaining(r.getFromAddress());
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("from_address",
                    ToolHelpers.formatAddress(program, r.getFromAddress()));
            row.put("from_function", fn == null ? "" : fn.getName());
            row.put("ref_type", simplified);
            row.put("raw_ref_type", r.getReferenceType().getName());
            row.put("is_primary", r.isPrimary());
            rows.add(row);
        }
        rows.sort((a, b) -> ((String) a.get("from_address"))
                .compareTo((String) b.get("from_address")));

        Map<String, Object> block = new LinkedHashMap<>();
        block.put("count", rows.size());
        block.put("total_matched", total);
        block.put("truncated", total > rows.size());
        block.put("refs", rows);
        return block;
    }

    private static Map<String, Object> buildFromBlock(
            Program program, FunctionManager fm, ReferenceManager rm,
            Address addr, Set<String> filter, int maxResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        int total = 0;
        Reference[] outs = rm.getReferencesFrom(addr);
        if (outs != null) {
            for (Reference r : outs) {
                String simplified = simplifyRefType(r.getReferenceType());
                if (!filter.contains("any") && !filter.contains(simplified)) continue;
                total++;
                if (rows.size() >= maxResults) continue;
                Function fn = fm.getFunctionAt(r.getToAddress());
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("to_address",
                        ToolHelpers.formatAddress(program, r.getToAddress()));
                row.put("to_function", fn == null ? "" : fn.getName());
                row.put("ref_type", simplified);
                row.put("raw_ref_type", r.getReferenceType().getName());
                row.put("is_primary", r.isPrimary());
                rows.add(row);
            }
        }
        rows.sort((a, b) -> ((String) a.get("to_address"))
                .compareTo((String) b.get("to_address")));

        Map<String, Object> block = new LinkedHashMap<>();
        block.put("count", rows.size());
        block.put("total_matched", total);
        block.put("truncated", total > rows.size());
        block.put("refs", rows);
        return block;
    }

    /**
     * Map Ghidra's RefType into the simplified 9-bucket taxonomy from
     * the spec. Uses RefType's classification predicates rather than a
     * hard switch on enum members so this survives Ghidra API drift.
     */
    private static String simplifyRefType(RefType rt) {
        if (rt == null) return "any";
        if (rt.isCall()) return "call";
        if (rt.isJump()) {
            return rt.isConditional() ? "branch" : "jump";
        }
        if (rt.isFlow() && rt.isConditional()) return "branch";
        if (rt.isRead()) return "data_read";
        if (rt.isWrite()) return "data_write";
        if (rt.isIndirect()) return "indirect";
        if (rt.isData()) return "pointer";
        // Heuristic last-resort: parameter and thunk
        String name = rt.getName().toLowerCase(Locale.ROOT);
        if (name.contains("param")) return "param";
        if (name.contains("thunk")) return "thunk";
        return "pointer";
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
