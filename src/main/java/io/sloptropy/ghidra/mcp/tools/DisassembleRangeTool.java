package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Implements behavior spec: disassemble_range. */
public final class DisassembleRangeTool implements McpTool {

    @Override public String getName() { return "disassemble_range"; }

    @Override
    public String getDescription() {
        return "Instruction-level disassembly over an address range or a "
             + "whole function. Returns bytes, mnemonic, operands, "
             + "flow_type, comments. Arch-portable through Ghidra's SLEIGH.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("start", Map.of(
                "type", "string",
                "description", "Start address. Required unless 'function' is supplied."));
        properties.put("end", Map.of(
                "type", "string",
                "description", "Inclusive end address. Optional."));
        properties.put("max_count", Map.of(
                "type", "integer",
                "description", "Max instructions. Default 64. Range [1, 10000].",
                "default", 64));
        properties.put("function", Map.of(
                "type", "string",
                "description", "Alternative: function name or address; "
                             + "disassembles the whole body."));
        return new McpSchema.JsonSchema("object", properties, List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        Object startRaw = arguments.get("start");
        Object fnRaw = arguments.get("function");
        boolean hasStart = startRaw instanceof String && !((String) startRaw).isEmpty();
        boolean hasFn    = fnRaw instanceof String    && !((String) fnRaw).isEmpty();
        if (!hasStart && !hasFn) {
            return ToolHelpers.error("either start or function is required");
        }
        if (hasStart && hasFn) {
            return ToolHelpers.error("supply either start or function, not both");
        }

        Object endRaw = arguments.get("end");
        if (endRaw != null && !(endRaw instanceof String)) {
            return ToolHelpers.error("end must be a string");
        }

        int maxCount = 64;
        Object maxRaw = arguments.get("max_count");
        if (maxRaw instanceof Number n) maxCount = n.intValue();
        if (maxCount < 1 || maxCount > 10000) {
            return ToolHelpers.error(
                "max_count must be in [1, 10000] (got: " + maxCount + ")");
        }

        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling disassemble_range");
        }

        AddressSetView range;
        try {
            if (hasFn) {
                FunctionResolution fr = resolveFunction(program, (String) fnRaw);
                if (fr.ambiguous) {
                    return ToolHelpers.error(
                        "function name is ambiguous; retry with an address");
                }
                if (fr.function == null) {
                    return ToolHelpers.error("function not found: " + fnRaw);
                }
                range = fr.function.getBody();
            } else {
                Address start = ToolHelpers.parseAddress(program, (String) startRaw);
                if (start == null) {
                    return ToolHelpers.error("invalid address: " + startRaw);
                }
                Memory mem = program.getMemory();
                if (!mem.contains(start)) {
                    return ToolHelpers.error(
                        "address " + startRaw + " is not in any memory block");
                }
                Address end;
                if (endRaw != null && !((String) endRaw).isEmpty()) {
                    end = ToolHelpers.parseAddress(program, (String) endRaw);
                    if (end == null) {
                        return ToolHelpers.error("invalid address: " + endRaw);
                    }
                    if (!mem.contains(end)) {
                        return ToolHelpers.error(
                            "address " + endRaw + " is not in any memory block");
                    }
                    if (end.compareTo(start) < 0) {
                        return ToolHelpers.error(
                            "end (" + endRaw + ") must be >= start (" + startRaw + ")");
                    }
                } else {
                    // No end: scan as far as needed for max_count instructions;
                    // use program max as upper bound.
                    end = program.getMaxAddress();
                    if (end == null) end = start;
                }
                range = new AddressSet(start, end);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("disassembly failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        FunctionManager fm = program.getFunctionManager();
        Listing listing = program.getListing();
        boolean truncated = false;
        Address firstAddr = null;
        Address lastAddr = null;
        int totalSeen = 0;

        try {
            InstructionIterator it = listing.getInstructions(range, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                totalSeen++;
                if (rows.size() >= maxCount) {
                    truncated = true;
                    break;
                }
                if (firstAddr == null) firstAddr = instr.getAddress();
                lastAddr = instr.getMaxAddress();

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ToolHelpers.formatAddress(program, instr.getAddress()));
                row.put("bytes", toHex(instr.getBytes()));
                row.put("mnemonic", instr.getMnemonicString());
                row.put("operands", operandsString(instr));
                row.put("comment_pre", safeStr(
                        listing.getComment(CommentType.PRE, instr.getAddress())));
                row.put("comment_eol", safeStr(
                        listing.getComment(CommentType.EOL, instr.getAddress())));
                row.put("flow_type", classifyFlow(instr.getFlowType()));
                Function in = fm.getFunctionContaining(instr.getAddress());
                row.put("is_in_function", in == null ? "" : in.getName());
                rows.add(row);
            }
        } catch (Throwable t) {
            return ToolHelpers.error("disassembly failed: "
                    + t.getClass().getSimpleName() + ": " + safeMsg(t));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("start", firstAddr == null
                ? "" : ToolHelpers.formatAddress(program, firstAddr));
        result.put("end", lastAddr == null
                ? "" : ToolHelpers.formatAddress(program, lastAddr));
        result.put("count", rows.size());
        result.put("truncated", truncated);
        result.put("instructions", rows);
        return ToolHelpers.text(JsonRender.render(result));
    }

    private static final class FunctionResolution {
        Function function;
        boolean ambiguous;
    }

    /**
     * Resolve a function by address or globally-unique name. Populates
     * `ambiguous` on multi-match (then function is null); populates
     * `function` on unique resolution; both null on not-found.
     */
    private static FunctionResolution resolveFunction(Program program, String ref) {
        FunctionResolution out = new FunctionResolution();
        FunctionManager fm = program.getFunctionManager();
        Address a = ToolHelpers.parseAddress(program, ref);
        if (a != null) {
            Function entry = fm.getFunctionAt(a);
            if (entry != null) { out.function = entry; return out; }
            out.function = fm.getFunctionContaining(a);
            return out;
        }
        SymbolIterator it = program.getSymbolTable().getSymbols(ref);
        Function found = null;
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) continue;
                if (found != null) { out.ambiguous = true; return out; }
                found = f;
            }
        }
        out.function = found;
        return out;
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String operandsString(Instruction instr) {
        int n = instr.getNumOperands();
        if (n == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(instr.getDefaultOperandRepresentation(i));
        }
        return sb.toString();
    }

    /**
     * Map Ghidra's FlowType to the 7-bucket simplified taxonomy from the
     * spec. Falls through to "other" on anything unrecognized.
     */
    private static String classifyFlow(FlowType ft) {
        if (ft == null) return "fallthrough";
        if (ft.isFallthrough()) return "fallthrough";
        if (ft.isTerminal()) return "return";
        if (ft.isCall()) return "call";
        if (ft.isJump()) {
            return ft.isConditional() ? "branch" : "jump";
        }
        if (ft.isFlow() && ft.isConditional()) return "branch";
        if (!ft.isFlow()) return "no_flow";
        return "other";
    }

    private static String safeStr(String s) {
        return s == null ? "" : s;
    }

    private static String safeMsg(Throwable t) {
        return t.getMessage() == null ? "" : t.getMessage();
    }
}
