package io.sloptropy.ghidra.mcp.api;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.Map;

/**
 * Contract every tool in this MCP server implements.
 *
 * Implementations are stateless apart from per-call argument processing.
 * The server holds a single instance of each tool and dispatches concurrent
 * calls to it; any per-call state lives on the stack.
 *
 * Read-only tools may run on any thread. Mutating tools MUST dispatch their
 * Ghidra-database changes onto Swing via the server harness; the harness
 * provides the EDT bridge so individual tools don't reimplement it.
 */
public interface McpTool {

    /** Canonical tool name. Stable across versions; clients key on this. */
    String getName();

    /** One-line human-readable description. Surfaced in tools/list. */
    String getDescription();

    /** JSON schema describing the tool's argument shape. */
    McpSchema.JsonSchema getInputSchema();

    /**
     * Execute the tool against the currently-active program.
     *
     * @param arguments  caller-supplied arguments; never null, may be empty
     * @param program    the active program; null iff no program is loaded
     * @return tool result; isError=true distinguishes tool-level failures
     *         from structured rejections (which a tool encodes in its
     *         own response payload with isError=false)
     */
    McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program);

    /**
     * Whether the tool may mutate program state. Defaults to false.
     * Mutating tools opt in; the harness routes their execute() through
     * the EDT and program-transaction discipline.
     */
    default boolean isMutating() { return false; }

    /**
     * Whether tool results are cacheable. Defaults to true for read-only
     * tools; mutating tools MUST return false. Tools whose output depends
     * on time, randomness, or external state should also return false.
     */
    default boolean isCacheable() { return !isMutating(); }
}
