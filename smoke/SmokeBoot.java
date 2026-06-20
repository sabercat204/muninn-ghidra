// Standalone smoke harness — boots McpServerBootstrap without Ghidra.
//
// Compiled and run out-of-tree (not part of the extension zip). Use:
//   smoke/run.sh
//
// What it exercises:
//   - ToolRegistry register/freeze
//   - McpServerBootstrap.start (Jetty 12 binding, both transports)
//   - Tool spec list construction (input schema serialization through MCP SDK)
//   - Dispatch path: list_functions with no program → error CallToolResult
//
// What it does NOT exercise:
//   - Anything that requires a real Program (FunctionManager iteration etc.)
//   - Ghidra plugin lifecycle, EDT, GUI
//
// External smoke (curl) confirms the HTTP surface from outside the JVM.
package smoke;

import io.sloptropy.ghidra.mcp.server.McpServerBootstrap;
import io.sloptropy.ghidra.mcp.server.ProgramSource;
import io.sloptropy.ghidra.mcp.server.ToolRegistry;
import io.sloptropy.ghidra.mcp.tools.DisassembleRangeTool;
import io.sloptropy.ghidra.mcp.tools.GetFunctionInfoTool;
import io.sloptropy.ghidra.mcp.tools.GetProgramInfoTool;
import io.sloptropy.ghidra.mcp.tools.GetXrefsTool;
import io.sloptropy.ghidra.mcp.tools.ListExportsTool;
import io.sloptropy.ghidra.mcp.tools.ListFunctionsTool;
import io.sloptropy.ghidra.mcp.tools.ListImportsTool;
import io.sloptropy.ghidra.mcp.tools.ListSegmentsTool;
import io.sloptropy.ghidra.mcp.tools.ListStringsTool;
import io.sloptropy.ghidra.mcp.tools.ListSymbolsTool;
import io.sloptropy.ghidra.mcp.tools.RenameSymbolTool;
import io.sloptropy.ghidra.mcp.tools.SearchBytesTool;
import io.sloptropy.ghidra.mcp.tools.SetCommentTool;

public final class SmokeBoot {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8765;

        ToolRegistry registry = new ToolRegistry();
        registry.register(new ListFunctionsTool());
        registry.register(new GetProgramInfoTool());
        registry.register(new RenameSymbolTool());
        registry.register(new SetCommentTool());
        registry.register(new GetFunctionInfoTool());
        registry.register(new ListSegmentsTool());
        registry.register(new ListStringsTool());
        registry.register(new ListImportsTool());
        registry.register(new ListExportsTool());
        registry.register(new ListSymbolsTool());
        registry.register(new GetXrefsTool());
        registry.register(new DisassembleRangeTool());
        registry.register(new SearchBytesTool());

        ProgramSource noProgram = () -> null;
        McpServerBootstrap server = new McpServerBootstrap(registry, noProgram);

        System.out.println("[smoke] starting server on 127.0.0.1:" + port);
        server.start(port);
        System.out.println("[smoke] running, " + registry.size() + " tool(s); port=" + server.getPort());
        System.out.println("[smoke] sse=http://127.0.0.1:" + server.getPort() + "/sse");
        System.out.println("[smoke] streamable=http://127.0.0.1:" + server.getPort() + "/mcp");
        System.out.println("[smoke] press ctrl-c to stop");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { server.stop(); System.out.println("[smoke] stopped"); }
            catch (Exception e) { /* ignore */ }
        }));

        Thread.currentThread().join();
    }
}
