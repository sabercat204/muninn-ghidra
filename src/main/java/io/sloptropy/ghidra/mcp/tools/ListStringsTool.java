package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
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

/** Implements behavior spec: list_strings. */
public final class ListStringsTool implements McpTool {

    private static final int TEXT_TRUNCATE = 4096;
    private static final Set<String> ALLOWED_ENCODINGS =
            Set.of("ascii", "utf8", "utf16", "utf32", "any");

    @Override public String getName() { return "list_strings"; }

    @Override
    public String getDescription() {
        return "List defined strings (address, encoding, length, text). "
             + "Substring filter, min_length, address_range, encoding filter, "
             + "max_results cap. Fastest orientation signal on any binary.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("filter", Map.of(
                "type", "string",
                "description", "Case-insensitive substring on decoded text."));
        properties.put("min_length", Map.of(
                "type", "integer",
                "description", "Minimum character count. Default 4. Range [1, 1024].",
                "default", 4));
        properties.put("address_range", Map.of(
                "type", "object",
                "description", "Optional {start, end} restriction."));
        properties.put("max_results", Map.of(
                "type", "integer",
                "description", "Cap on rows. Default 1000. Min 1.",
                "default", 1000));
        properties.put("encoding", Map.of(
                "type", "string",
                "description", "ascii | utf8 | utf16 | utf32 | any. Default any.",
                "default", "any"));
        return new McpSchema.JsonSchema("object", properties, List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // R-019 input validation first.
        Object filterRaw = arguments.get("filter");
        if (filterRaw != null && !(filterRaw instanceof String)) {
            return ToolHelpers.error("filter must be a string (got: "
                    + filterRaw.getClass().getSimpleName() + ")");
        }
        String filterLower = filterRaw == null
                ? ""
                : ((String) filterRaw).toLowerCase(Locale.ROOT);

        int minLength = 4;
        Object minRaw = arguments.get("min_length");
        if (minRaw instanceof Number n) minLength = n.intValue();
        if (minLength < 1 || minLength > 1024) {
            return ToolHelpers.error(
                "min_length must be in [1, 1024] (got: " + minLength + ")");
        }

        int maxResults = 1000;
        Object maxRaw = arguments.get("max_results");
        if (maxRaw instanceof Number n) maxResults = n.intValue();
        if (maxResults < 1) {
            return ToolHelpers.error("max_results must be >= 1 (got: " + maxResults + ")");
        }

        String encodingFilter = "any";
        Object encRaw = arguments.get("encoding");
        if (encRaw != null) {
            if (!(encRaw instanceof String)) {
                return ToolHelpers.error("encoding must be a string");
            }
            encodingFilter = ((String) encRaw).toLowerCase(Locale.ROOT);
            if (!ALLOWED_ENCODINGS.contains(encodingFilter)) {
                return ToolHelpers.error(
                    "encoding must be one of: ascii, utf8, utf16, utf32, any (got: " + encRaw + ")");
            }
        }

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
            if (program == null) {
                // Defer to the env check below.
            } else {
                rangeStart = ToolHelpers.parseAddress(program, (String) sObj);
                rangeEnd = ToolHelpers.parseAddress(program, (String) eObj);
                if (rangeStart == null || rangeEnd == null) {
                    return ToolHelpers.error(
                        "address_range contains unparseable address(es)");
                }
                if (rangeEnd.compareTo(rangeStart) < 0) {
                    return ToolHelpers.error(
                        "address_range.end (" + eObj + ") < start (" + sObj + ")");
                }
            }
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling list_strings");
        }

        if (rangeStart != null) {
            Memory mem = program.getMemory();
            if (!mem.contains(rangeStart) || !mem.contains(rangeEnd)) {
                return ToolHelpers.error(
                    "address_range is not contained in any memory block");
            }
        }

        AddressSetView scopeSet = null;
        if (rangeStart != null) {
            scopeSet = new AddressSet(rangeStart, rangeEnd);
        }

        List<Map<String, Object>> matched = new ArrayList<>();
        try {
            Listing listing = program.getListing();
            DataIterator it = scopeSet == null
                    ? listing.getDefinedData(true)
                    : listing.getDefinedData(scopeSet, true);
            while (it.hasNext()) {
                Data d = it.next();
                if (!d.hasStringValue()) continue;
                Object val = d.getValue();
                if (val == null) continue;
                String text = val.toString();
                if (text.length() < minLength) continue;
                if (!filterLower.isEmpty()
                        && !text.toLowerCase(Locale.ROOT).contains(filterLower)) {
                    continue;
                }
                String enc = encodingOf(d);
                if (!"any".equals(encodingFilter) && !enc.equals(encodingFilter)) continue;

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ToolHelpers.formatAddress(program, d.getAddress()));
                row.put("encoding", enc);
                int fullLen = text.length();
                row.put("length_chars", fullLen);
                row.put("length_bytes", d.getLength());
                boolean truncated = fullLen > TEXT_TRUNCATE;
                String visible = truncated
                        ? text.substring(0, TEXT_TRUNCATE) + "..."
                        : text;
                row.put("text", visible);
                row.put("is_truncated", truncated);
                matched.add(row);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("string iteration failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

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
        result.put("strings", trimmed);
        return ToolHelpers.text(JsonRender.render(result));
    }

    /**
     * Normalize Ghidra's string-data-type names into the spec's encoding
     * buckets. Ghidra exposes types like StringDataType (ASCII),
     * UnicodeDataType (UTF-16), Unicode32DataType, etc. We classify by
     * type name with prefix matching.
     */
    private static String encodingOf(Data d) {
        DataType dt = d.getDataType();
        if (dt == null) return "other";
        String name = dt.getName().toLowerCase(Locale.ROOT);
        // Order matters: more specific first.
        if (name.contains("unicode32") || name.contains("utf32") || name.contains("utf-32")) {
            return "utf32";
        }
        if (name.contains("unicode") || name.contains("utf16") || name.contains("utf-16")) {
            return "utf16";
        }
        if (name.contains("utf8") || name.contains("utf-8")) {
            return "utf8";
        }
        if (name.contains("string") || name.contains("char")) {
            return "ascii";
        }
        return "other";
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
