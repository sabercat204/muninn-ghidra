package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.Mutation;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements behavior spec: set_comment.
 *
 * Mutating. Second mutating tool — validates the {@link Mutation}
 * helper's design (single body invocation, transaction by default,
 * SKIP_TRANSACTION sentinel for no-op clears).
 */
public final class SetCommentTool implements McpTool {

    @Override public String getName() { return "set_comment"; }
    @Override public boolean isMutating() { return true; }

    @Override
    public String getDescription() {
        return "Attach / replace / clear a comment of a given kind "
             + "(pre, post, eol, plate, repeatable) at an address. "
             + "Empty text clears. Returns previous_text + cleared "
             + "flag so callers can round-trip and detect overwrites.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("address", Map.of(
                "type", "string",
                "description", "Target address. Must be in a registered memory block."));
        properties.put("kind", Map.of(
                "type", "string",
                "description", "Comment slot. One of: pre, post, eol, plate, repeatable."));
        properties.put("text", Map.of(
                "type", "string",
                "description", "Comment body. Empty string CLEARS the slot. "
                             + "Use a single space (' ') for a visually-empty comment."));
        return new McpSchema.JsonSchema("object", properties,
                List.of("address", "kind", "text"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // R-019: inputs first.
        Object addrRaw = arguments.get("address");
        if (!(addrRaw instanceof String) || ((String) addrRaw).isEmpty()) {
            return ToolHelpers.error(
                "address is required and must be a non-empty string");
        }
        String addrStr = (String) addrRaw;

        Object kindRaw = arguments.get("kind");
        if (!(kindRaw instanceof String)) {
            return ToolHelpers.error(
                "kind is required and must be a string");
        }
        CommentType kind = parseKind((String) kindRaw);
        if (kind == null) {
            return ToolHelpers.error(
                "kind must be one of: pre, post, eol, plate, repeatable (got: "
                + kindRaw + ")");
        }

        Object textRaw = arguments.get("text");
        if (textRaw != null && !(textRaw instanceof String)) {
            return ToolHelpers.error(
                "text must be a string (got: " + textRaw.getClass().getSimpleName() + ")");
        }
        String text = textRaw == null ? "" : (String) textRaw;

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling set_comment");
        }

        Address addr = ToolHelpers.parseAddress(program, addrStr);
        if (addr == null) {
            return ToolHelpers.error("invalid address: " + addrStr);
        }
        Memory mem = program.getMemory();
        if (!mem.contains(addr)) {
            return ToolHelpers.error(
                "address " + addrStr + " is not in any memory block; "
                + "comments require a valid in-program location");
        }

        Listing listing = program.getListing();
        String previousText = listing.getComment(kind, addr);
        if (previousText == null) previousText = "";

        // No-op clear: text="" and no prior comment → skip transaction
        // entirely so the undo stack isn't polluted with an empty step.
        if (text.isEmpty() && previousText.isEmpty()) {
            return ToolHelpers.text(JsonRender.render(
                buildResponse(true, addr, program, kind, previousText, "", false, "")));
        }

        boolean isClearing = text.isEmpty();
        String txName = (isClearing ? "clear " : "set ")
                + kindLabel(kind) + " comment @ "
                + ToolHelpers.formatAddress(program, addr);
        final String finalText = text;
        final String finalPrev = previousText;
        try {
            Object result = Mutation.run(program, txName, () -> {
                // Ghidra's setComment treats "" the same way as null:
                // both clear the slot. Use null for clarity.
                listing.setComment(addr, kind, isClearing ? null : finalText);
                return buildResponse(true, addr, program, kind, finalPrev,
                        isClearing ? "" : finalText, isClearing, "");
            });
            return ToolHelpers.text(JsonRender.render(result));
        } catch (Mutation.MutationException e) {
            Throwable cause = e.getCause();
            return ToolHelpers.error(
                "setComment failed: " + cause.getClass().getSimpleName()
                + ": " + (cause.getMessage() == null ? "" : cause.getMessage()));
        }
    }

    private static CommentType parseKind(String s) {
        switch (s.toLowerCase()) {
            case "pre":        return CommentType.PRE;
            case "post":       return CommentType.POST;
            case "eol":        return CommentType.EOL;
            case "plate":      return CommentType.PLATE;
            case "repeatable": return CommentType.REPEATABLE;
            default:           return null;
        }
    }

    private static String kindLabel(CommentType k) {
        switch (k) {
            case PRE:        return "pre";
            case POST:       return "post";
            case EOL:        return "eol";
            case PLATE:      return "plate";
            case REPEATABLE: return "repeatable";
            default:         return k.name().toLowerCase();
        }
    }

    private static Map<String, Object> buildResponse(
            boolean set, Address addr, Program program, CommentType kind,
            String previousText, String newText, boolean cleared, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("set", set);
        m.put("address", ToolHelpers.formatAddress(program, addr));
        m.put("kind", kindLabel(kind));
        m.put("previous_text", previousText);
        m.put("new_text", newText);
        m.put("cleared", cleared);
        m.put("reason", reason);
        return m;
    }
}
