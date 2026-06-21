package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryBlockType;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Implements behavior spec: list_segments. */
public final class ListSegmentsTool implements McpTool {

    @Override public String getName() { return "list_segments"; }

    @Override
    public String getDescription() {
        return "Enumerate memory blocks (sections/segments) with r/w/x "
             + "permissions, initialized status, source type. The "
             + "format-agnostic memory map.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring filter on block name."));
        properties.put("include_uninitialized", Map.of(
                "type", "boolean",
                "description", "Include uninitialized blocks (default true).",
                "default", true));
        return new McpSchema.JsonSchema("object", properties, List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object filterRaw = arguments.get("filter");
        if (filterRaw != null && !(filterRaw instanceof String)) {
            return ToolHelpers.error("filter must be a string (got: "
                    + filterRaw.getClass().getSimpleName() + ")");
        }
        String filterLower = filterRaw == null
                ? ""
                : ((String) filterRaw).toLowerCase(Locale.ROOT);

        Object includeRaw = arguments.get("include_uninitialized");
        boolean includeUninit = true;
        if (includeRaw != null) {
            if (!(includeRaw instanceof Boolean)) {
                return ToolHelpers.error("include_uninitialized must be a boolean");
            }
            includeUninit = (Boolean) includeRaw;
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_segments");
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        try {
            Memory mem = program.getMemory();
            for (MemoryBlock b : mem.getBlocks()) {
                if (!includeUninit && !b.isInitialized()) continue;
                if (!filterLower.isEmpty()
                        && !b.getName().toLowerCase(Locale.ROOT).contains(filterLower)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", b.getName());
                row.put("start", ToolHelpers.formatAddress(program, b.getStart()));
                row.put("end", ToolHelpers.formatAddress(program, b.getEnd()));
                row.put("size_bytes", b.getSize());
                row.put("permissions", permString(b));
                row.put("initialized", b.isInitialized());
                row.put("overlay", b.isOverlay());
                row.put("source_type", sourceTypeName(b));
                rows.add(row);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("segment iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("count", rows.size());
        result.put("program", program.getName());
        result.put("segments", rows);
        return ToolHelpers.text(JsonRender.render(result));
    }

    private static String permString(MemoryBlock b) {
        StringBuilder sb = new StringBuilder(3);
        sb.append(b.isRead() ? 'r' : '-');
        sb.append(b.isWrite() ? 'w' : '-');
        sb.append(b.isExecute() ? 'x' : '-');
        return sb.toString();
    }

    private static String sourceTypeName(MemoryBlock b) {
        MemoryBlockType t = b.getType();
        if (t == null) return "other";
        switch (t) {
            case DEFAULT: return "default";
            case BIT_MAPPED: return "bit_mapped";
            case BYTE_MAPPED: return "byte_mapped";
            default: break;
        }
        // EXTERNAL_BLOCK isn't a MemoryBlockType in some Ghidra versions;
        // probe via MemoryBlock's source-info if available.
        try {
            List<MemoryBlockSourceInfo> infos = b.getSourceInfos();
            if (infos != null && !infos.isEmpty()) {
                String desc = infos.get(0).getDescription();
                if (desc != null && desc.toLowerCase(Locale.ROOT).contains("external")) {
                    return "external_block";
                }
            }
        } catch (Throwable ignored) {}
        return "other";
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
