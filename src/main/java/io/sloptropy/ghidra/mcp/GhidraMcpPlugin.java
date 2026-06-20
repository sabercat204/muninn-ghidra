package io.sloptropy.ghidra.mcp;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import io.sloptropy.ghidra.mcp.server.McpServerBootstrap;
import io.sloptropy.ghidra.mcp.server.ProgramSource;
import io.sloptropy.ghidra.mcp.server.ToolRegistry;
import io.sloptropy.ghidra.mcp.tools.GetFunctionInfoTool;
import io.sloptropy.ghidra.mcp.tools.GetProgramInfoTool;
import io.sloptropy.ghidra.mcp.tools.ListFunctionsTool;
import io.sloptropy.ghidra.mcp.tools.RenameSymbolTool;
import io.sloptropy.ghidra.mcp.tools.SetCommentTool;

/**
 * Ghidra plugin entry point for the ghidra-mcp extension.
 *
 * On plugin init: builds the tool registry, starts the MCP server on a
 * fixed localhost port. The server lives for the lifetime of the plugin.
 *
 * Current behavior is auto-start at construction; a future iteration adds
 * a CodeBrowser-side toggle action and a port-config UI.
 */
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = ghidra.app.DeveloperPluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "MCP server for Ghidra",
        description = "Hosts a Model Context Protocol server inside Ghidra, "
                + "exposing reverse-engineering tools to MCP clients."
)
public final class GhidraMcpPlugin extends ProgramPlugin {

    private static final int DEFAULT_PORT = 8765;

    private McpServerBootstrap server;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();

        ToolRegistry registry = new ToolRegistry();
        registry.register(new ListFunctionsTool());
        registry.register(new GetProgramInfoTool());
        registry.register(new RenameSymbolTool());
        registry.register(new SetCommentTool());
        registry.register(new GetFunctionInfoTool());

        ProgramSource source = this::getCurrentProgram;
        server = new McpServerBootstrap(registry, source);

        try {
            server.start(DEFAULT_PORT);
        } catch (Throwable t) {
            Msg.error(this, "failed to start MCP server on port " + DEFAULT_PORT, t);
            server = null;
        }
    }

    @Override
    protected void dispose() {
        if (server != null) {
            try {
                server.stop();
            } catch (Throwable t) {
                Msg.error(this, "error stopping MCP server", t);
            }
            server = null;
        }
        super.dispose();
    }
}
