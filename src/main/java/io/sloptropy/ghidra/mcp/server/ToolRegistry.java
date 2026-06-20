package io.sloptropy.ghidra.mcp.server;

import io.sloptropy.ghidra.mcp.api.McpTool;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-process registry mapping tool names to implementations.
 *
 * Single instance per server. Inserts preserve order so tools/list returns
 * a stable order across calls — clients can rely on this for UI rendering
 * and for diffing-tool-surface across sessions.
 *
 * Registration is one-shot at server bootstrap; no add/remove after
 * startTransport(). The registry never blocks dispatch — it's a plain
 * LinkedHashMap snapshot taken at boot time. Adding hot-reload would
 * require a snapshot-on-read pattern; we don't need that yet.
 */
public final class ToolRegistry {

    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private boolean frozen = false;

    public void register(McpTool tool) {
        if (frozen) {
            throw new IllegalStateException(
                "ToolRegistry is frozen; cannot register " + tool.getName());
        }
        if (tools.containsKey(tool.getName())) {
            throw new IllegalArgumentException(
                "Duplicate tool name: " + tool.getName());
        }
        tools.put(tool.getName(), tool);
    }

    public void freeze() { frozen = true; }

    public McpTool get(String name) { return tools.get(name); }

    public Collection<McpTool> all() { return tools.values(); }

    public int size() { return tools.size(); }
}
