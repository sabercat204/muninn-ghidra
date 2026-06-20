package io.sloptropy.ghidra.mcp.server;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.util.Msg;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Boots a Jetty 12 server hosting the MCP Java SDK transport providers.
 *
 * Lifecycle:
 *   1. Construct with a registry and a program source.
 *   2. start(port) — binds Jetty on localhost:port, registers both
 *      SSE (/*) and streamable-HTTP (/mcp/*) transports, freezes the
 *      registry.
 *   3. stop() — gracefully shuts down Jetty.
 *
 * Threading: start() and stop() run on the caller's thread (typically the
 * Ghidra plugin lifecycle thread). Tool dispatch happens on Jetty's
 * servlet thread pool. Mutating tools are responsible for hopping to EDT
 * themselves; the bootstrap does not impose threading.
 */
public final class McpServerBootstrap {

    private final ToolRegistry registry;
    private final ProgramSource programSource;
    private Server jetty;
    private int port;

    public McpServerBootstrap(ToolRegistry registry, ProgramSource programSource) {
        this.registry = registry;
        this.programSource = programSource;
    }

    public void start(int requestedPort) throws Exception {
        if (jetty != null) {
            throw new IllegalStateException("server already started");
        }
        registry.freeze();

        ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(mapper);

        jetty = new Server();
        ServerConnector connector = new ServerConnector(jetty);
        connector.setHost("127.0.0.1");
        connector.setPort(requestedPort);
        jetty.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        jetty.setHandler(context);

        // Build the tool specs once; both transports share the same list.
        List<McpServerFeatures.SyncToolSpecification> specs = buildSpecs();

        // SSE transport at /* — legacy clients
        HttpServletSseServerTransportProvider sseProvider =
                HttpServletSseServerTransportProvider.builder()
                        .jsonMapper(jsonMapper)
                        .messageEndpoint("/message")
                        .sseEndpoint("/sse")
                        .build();
        McpServer.sync(sseProvider)
                .serverInfo("muninn-ghidra", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(specs)
                .build();
        context.addServlet(new ServletHolder(sseProvider), "/*");

        // Streamable-HTTP transport at /mcp/* — current MCP clients
        HttpServletStreamableServerTransportProvider streamableProvider =
                HttpServletStreamableServerTransportProvider.builder()
                        .jsonMapper(jsonMapper)
                        .mcpEndpoint("/mcp")
                        .build();
        McpServer.sync(streamableProvider)
                .serverInfo("muninn-ghidra", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(specs)
                .build();
        context.addServlet(new ServletHolder(streamableProvider), "/mcp/*");

        jetty.start();
        port = connector.getLocalPort();
        Msg.info(this, "muninn-ghidra listening on 127.0.0.1:" + port
                + " (sse=/sse, streamable=/mcp); " + registry.size() + " tool(s)");
    }

    public void stop() throws Exception {
        if (jetty != null) {
            jetty.stop();
            jetty = null;
        }
    }

    public int getPort() { return port; }

    public boolean isRunning() { return jetty != null && jetty.isStarted(); }

    private List<McpServerFeatures.SyncToolSpecification> buildSpecs() {
        List<McpServerFeatures.SyncToolSpecification> specs = new ArrayList<>();
        for (McpTool tool : registry.all()) {
            McpSchema.Tool sdkTool = McpSchema.Tool.builder()
                    .name(tool.getName())
                    .description(tool.getDescription())
                    .inputSchema(tool.getInputSchema())
                    .build();
            specs.add(McpServerFeatures.SyncToolSpecification.builder()
                    .tool(sdkTool)
                    .callHandler((exchange, request) -> dispatch(tool, request.arguments()))
                    .build());
        }
        return specs;
    }

    private McpSchema.CallToolResult dispatch(McpTool tool, Map<String, Object> arguments) {
        Map<String, Object> args = arguments != null ? arguments : new HashMap<>();
        try {
            return tool.execute(args, programSource.getCurrentProgram());
        } catch (Throwable t) {
            Msg.error(this, "tool " + tool.getName() + " threw", t);
            return ToolHelpers.error(
                    "tool execution failed: " + t.getClass().getSimpleName()
                            + ": " + t.getMessage());
        }
    }
}
