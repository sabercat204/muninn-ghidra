package io.sloptropy.ghidra.mcp.api;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Small shared helpers for tool implementations. Keep this surface tiny —
 * tool-specific logic lives in the tool class, not here.
 */
public final class ToolHelpers {

    private ToolHelpers() {}

    /** Wrap text in a non-error CallToolResult. */
    public static McpSchema.CallToolResult text(String s) {
        return McpSchema.CallToolResult.builder().addTextContent(s).build();
    }

    /**
     * Wrap text in a CallToolResult marked isError=true. Reserve for
     * tool-level failures (no program loaded, invalid input type, Ghidra
     * API threw). Per-spec rejections that the caller can recover from
     * (e.g. duplicate-name on rename) go in a structured payload with
     * isError=false.
     */
    public static McpSchema.CallToolResult error(String s) {
        return McpSchema.CallToolResult.builder().addTextContent(s).isError(true).build();
    }

    /**
     * Parse an address string. Accepts Ghidra's standard forms: bare hex
     * ("0x401000", "401000"), space-qualified ("ram:401000"). Returns null
     * on any parse failure or on a null/empty input.
     */
    public static Address parseAddress(Program program, String s) {
        if (program == null || s == null || s.isEmpty()) return null;
        try {
            return program.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Format an address relative to a program, including the space prefix
     * when the address is NOT in the program's default address space.
     * This is the round-trippable form the spec contract requires:
     * default-space addresses are "0xNNN...", non-default are
     * "<space>:0xNNN..." (firmware ROM/RAM splits, etc.).
     */
    public static String formatAddress(Program program, Address addr) {
        if (addr == null) return "";
        String hex = "0x" + Long.toHexString(addr.getOffset());
        var space = addr.getAddressSpace();
        var defaultSpace = program != null
                ? program.getAddressFactory().getDefaultAddressSpace()
                : null;
        if (defaultSpace == null || space.equals(defaultSpace)) {
            return hex;
        }
        return space.getName() + ":" + hex;
    }
}
