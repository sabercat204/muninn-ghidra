package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Implements behavior spec: search_bytes. */
public final class SearchBytesTool implements McpTool {

    @Override public String getName() { return "search_bytes"; }

    @Override
    public String getDescription() {
        return "Search memory for a hex byte pattern with ?? wildcards. "
             + "Returns matching addresses with surrounding context bytes. "
             + "Memory-block-scoped; bounded pattern length and result count.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("pattern", Map.of(
                "type", "string",
                "description", "Hex pattern, e.g. '488d4538' or '48 8d ?? 38'. Length 1-256 bytes."));
        properties.put("address_range", Map.of(
                "type", "object",
                "description", "Optional {start, end} restriction."));
        properties.put("max_results", Map.of(
                "type", "integer",
                "description", "Cap on matches. Default 100. Range [1, 10000].",
                "default", 100));
        properties.put("context_bytes", Map.of(
                "type", "integer",
                "description", "Surrounding bytes returned per match. Default 16. Range [0, 256].",
                "default", 16));
        return new McpSchema.JsonSchema("object", properties,
                List.of("pattern"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object patternRaw = arguments.get("pattern");
        if (!(patternRaw instanceof String) || ((String) patternRaw).isEmpty()) {
            return ToolHelpers.error(
                "pattern is required and must be a non-empty string");
        }
        ParsedPattern parsed = parsePattern((String) patternRaw);
        if (parsed.error != null) {
            return ToolHelpers.error(parsed.error);
        }
        if (parsed.bytes.length < 1 || parsed.bytes.length > 256) {
            return ToolHelpers.error(
                "pattern length must be in [1, 256] bytes (got: " + parsed.bytes.length + ")");
        }

        int maxResults = 100;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1 || maxResults > 10000) {
            return ToolHelpers.error(
                "max_results must be in [1, 10000] (got: " + maxResults + ")");
        }

        int contextBytes = 16;
        Object ctxRaw = arguments.get("context_bytes");
        if (ctxRaw instanceof Number n) contextBytes = n.intValue();
        if (contextBytes < 0 || contextBytes > 256) {
            return ToolHelpers.error(
                "context_bytes must be in [0, 256] (got: " + contextBytes + ")");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling search_bytes");
        }

        // Optional address_range — validate and parse.
        Object rangeRaw = arguments.get("address_range");
        Address rangeStart = null;
        Address rangeEnd = null;
        if (rangeRaw != null) {
            if (!(rangeRaw instanceof Map<?, ?> rm)) {
                return ToolHelpers.error("address_range must be an object {start, end}");
            }
            Object sObj = rm.get("start");
            Object eObj = rm.get("end");
            if (!(sObj instanceof String) || !(eObj instanceof String)) {
                return ToolHelpers.error("address_range.start and .end must be strings");
            }
            rangeStart = ToolHelpers.parseAddress(program, (String) sObj);
            rangeEnd = ToolHelpers.parseAddress(program, (String) eObj);
            if (rangeStart == null || rangeEnd == null) {
                return ToolHelpers.error("address_range contains unparseable address(es)");
            }
            if (rangeEnd.compareTo(rangeStart) < 0) {
                return ToolHelpers.error(
                    "address_range.end (" + eObj + ") < start (" + sObj + ")");
            }
            Memory mem = program.getMemory();
            if (!mem.contains(rangeStart) || !mem.contains(rangeEnd)) {
                return ToolHelpers.error(
                    "address_range is not contained in any memory block");
            }
        }

        List<Map<String, Object>> matches = new ArrayList<>();
        int totalMatched = 0;
        FunctionManager fm = program.getFunctionManager();

        try {
            Memory mem = program.getMemory();
            for (MemoryBlock blk : mem.getBlocks()) {
                if (!blk.isInitialized()) continue;
                Address blockStart = blk.getStart();
                Address blockEnd = blk.getEnd();
                if (rangeStart != null) {
                    if (blockEnd.compareTo(rangeStart) < 0) continue;
                    if (blockStart.compareTo(rangeEnd) > 0) continue;
                }
                Address scanStart = (rangeStart != null
                        && rangeStart.compareTo(blockStart) > 0)
                        ? rangeStart : blockStart;
                Address scanEnd = (rangeEnd != null
                        && rangeEnd.compareTo(blockEnd) < 0)
                        ? rangeEnd : blockEnd;

                Address cursor = scanStart;
                while (cursor != null && cursor.compareTo(scanEnd) <= 0) {
                    Address hit = mem.findBytes(cursor, scanEnd,
                            parsed.bytes, parsed.mask, true, TaskMonitor.DUMMY);
                    if (hit == null) break;
                    totalMatched++;
                    if (matches.size() < maxResults) {
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("address", ToolHelpers.formatAddress(program, hit));
                        row.put("in_block", blk.getName());
                        Function fn = fm.getFunctionContaining(hit);
                        row.put("in_function", fn == null ? "" : fn.getName());
                        row.put("context_before",
                                readContext(mem, hit, contextBytes, true, blockStart));
                        row.put("match_bytes",
                                readBytesAsHex(mem, hit, parsed.bytes.length));
                        Address afterMatch;
                        try {
                            afterMatch = hit.add(parsed.bytes.length);
                        } catch (Exception e) { afterMatch = null; }
                        row.put("context_after",
                                afterMatch == null
                                        ? ""
                                        : readContext(mem, afterMatch,
                                                contextBytes, false, blockEnd));
                        matches.add(row);
                    }
                    try {
                        cursor = hit.add(1);
                    } catch (Exception e) {
                        cursor = null;
                    }
                }
            }
        } catch (Throwable t) {
            return ToolHelpers.error("search failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("pattern", parsed.normalized);
        result.put("pattern_length_bytes", parsed.bytes.length);
        result.put("program", program.getName());
        result.put("count", matches.size());
        result.put("total_matched", totalMatched);
        result.put("truncated", totalMatched > matches.size());
        result.put("matches", matches);
        return ToolHelpers.text(JsonRender.render(result));
    }

    /** Parse the hex pattern with ?? wildcards into bytes + mask. */
    private static final class ParsedPattern {
        byte[] bytes;
        byte[] mask;
        String normalized;
        String error;
    }

    private static ParsedPattern parsePattern(String raw) {
        ParsedPattern out = new ParsedPattern();
        // Strip whitespace.
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(c);
        }
        // Each byte is two chars; tolerate single '?' as '??'.
        // Walk in pairs, expanding lone '?' into "??" by lookahead.
        String stripped = sb.toString();
        List<Integer> byteVals = new ArrayList<>();
        List<Boolean> wildcardByte = new ArrayList<>();
        StringBuilder normalized = new StringBuilder(stripped.length());
        int i = 0;
        while (i < stripped.length()) {
            char c1 = stripped.charAt(i);
            char c2 = (i + 1 < stripped.length()) ? stripped.charAt(i + 1) : '\0';
            // Handle single '?' (treat as a wildcard byte; consume 1 char).
            if (c1 == '?' && (c2 == '\0' || (c2 != '?' && !isHex(c2)))) {
                wildcardByte.add(true);
                byteVals.add(0);
                normalized.append("??");
                i += 1;
                continue;
            }
            if (c2 == '\0') {
                out.error = "pattern has odd hex length";
                return out;
            }
            if (c1 == '?' && c2 == '?') {
                wildcardByte.add(true);
                byteVals.add(0);
                normalized.append("??");
                i += 2;
                continue;
            }
            if (!isHex(c1) || !isHex(c2)) {
                out.error = "pattern must contain only hex digits, '?', or whitespace";
                return out;
            }
            int hi = hexVal(c1);
            int lo = hexVal(c2);
            wildcardByte.add(false);
            byteVals.add((hi << 4) | lo);
            normalized.append(Character.toLowerCase(c1)).append(Character.toLowerCase(c2));
            i += 2;
        }

        int n = byteVals.size();
        out.bytes = new byte[n];
        out.mask = new byte[n];
        for (int k = 0; k < n; k++) {
            if (wildcardByte.get(k)) {
                out.bytes[k] = 0;
                out.mask[k] = 0;        // 0 mask = any byte matches
            } else {
                out.bytes[k] = (byte) (int) byteVals.get(k);
                out.mask[k] = (byte) 0xff;
            }
        }
        out.normalized = normalized.toString();
        return out;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    }

    /**
     * Read up to `count` context bytes from `mem`. If `before`, read
     * `count` bytes ending at `from - 1`; otherwise read forward from
     * `from`. Constrained by the block boundary.
     */
    private static String readContext(Memory mem, Address from, int count,
                                       boolean before, Address blockBoundary) {
        if (count <= 0) return "";
        try {
            if (before) {
                long offsetBack = Math.min(count, from.subtract(blockBoundary));
                if (offsetBack <= 0) return "";
                Address start = from.subtract(offsetBack);
                return readBytesAsHex(mem, start, (int) offsetBack);
            } else {
                long maxForward = blockBoundary.subtract(from) + 1;
                int read = (int) Math.min(count, maxForward);
                if (read <= 0) return "";
                return readBytesAsHex(mem, from, read);
            }
        } catch (Throwable t) {
            return "";
        }
    }

    private static String readBytesAsHex(Memory mem, Address from, int count) {
        if (count <= 0) return "";
        byte[] buf = new byte[count];
        int got;
        try {
            got = mem.getBytes(from, buf);
        } catch (MemoryAccessException e) {
            return "";
        }
        StringBuilder sb = new StringBuilder(got * 2);
        for (int i = 0; i < got; i++) {
            sb.append(String.format("%02x", buf[i] & 0xff));
        }
        return sb.toString();
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
