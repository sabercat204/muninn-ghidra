package io.sloptropy.ghidra.mcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.spec.McpSchema;
import io.sloptropy.ghidra.mcp.api.JsonRender;
import io.sloptropy.ghidra.mcp.api.McpTool;
import io.sloptropy.ghidra.mcp.api.ToolHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements behavior spec: get_program_info.
 *
 * Zero-input metadata read. Sentinel-on-missing semantics: per-field
 * absence returns the field's sentinel ("" / 0 / []) and does NOT
 * raise isError=true — clients need orientation even from oddly-loaded
 * binaries.
 */
public final class GetProgramInfoTool implements McpTool {

    @Override public String getName() { return "get_program_info"; }

    @Override
    public String getDescription() {
        return "Return high-level metadata about the active program: "
             + "name, format, language, image base, entry points, "
             + "address spaces, memory size, function/symbol counts. "
             + "Per-field absence is silent (sentinel-on-missing).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(), List.of(),
                null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        // No inputs to validate. R-019 still applies in form: there's
        // nothing to fail-early on, so the next gate is the env check.
        if (program == null) {
            return ToolHelpers.error(
                "no program loaded: open a program in Ghidra before calling get_program_info");
        }

        Map<String, Object> result = new LinkedHashMap<>();

        result.put("name", safeStr(program.getName()));
        result.put("executable_path", safeStr(program.getExecutablePath()));
        result.put("executable_format", safeStr(program.getExecutableFormat()));

        Map<String, Object> lang = new LinkedHashMap<>();
        Language language = program.getLanguage();
        if (language != null) {
            lang.put("id", safeStr(language.getLanguageID().getIdAsString()));
            lang.put("processor", safeStr(language.getProcessor().toString()));
            lang.put("endian", language.isBigEndian() ? "big" : "little");
            lang.put("address_size_bits",
                    language.getDefaultSpace() != null
                            ? language.getDefaultSpace().getSize()
                            : 0);
        } else {
            lang.put("id", "");
            lang.put("processor", "");
            lang.put("endian", "");
            lang.put("address_size_bits", 0);
        }
        lang.put("compiler_spec_id",
                program.getCompilerSpec() != null
                        ? safeStr(program.getCompilerSpec().getCompilerSpecID().getIdAsString())
                        : "");
        result.put("language", lang);

        result.put("image_base",
                ToolHelpers.formatAddress(program, program.getImageBase()));

        // Entry points: the SymbolTable holds an "external entry points" set.
        List<String> entryPoints = new ArrayList<>();
        try {
            SymbolTable st = program.getSymbolTable();
            AddressIterator eit = st.getExternalEntryPointIterator();
            while (eit.hasNext()) {
                Address a = eit.next();
                if (a != null) entryPoints.add(ToolHelpers.formatAddress(program, a));
            }
        } catch (Throwable t) {
            // Sentinel: empty list. Don't fail the whole call.
        }
        result.put("entry_points", entryPoints);

        // Address spaces
        List<Map<String, Object>> spaces = new ArrayList<>();
        try {
            AddressFactory af = program.getAddressFactory();
            AddressSpace defaultSpace = af.getDefaultAddressSpace();
            for (AddressSpace s : af.getAddressSpaces()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", safeStr(s.getName()));
                row.put("size_bits", s.getSize());
                row.put("is_default", s.equals(defaultSpace));
                row.put("is_overlay", s.isOverlaySpace());
                spaces.add(row);
            }
        } catch (Throwable t) {
            // sentinel: empty list
        }
        result.put("address_spaces", spaces);

        // Memory: sum of initialized block sizes
        long memSize = 0;
        try {
            Memory mem = program.getMemory();
            for (MemoryBlock b : mem.getBlocks()) {
                if (b.isInitialized()) {
                    memSize += b.getSize();
                }
            }
        } catch (Throwable t) {
            // sentinel: 0
        }
        result.put("memory_size_bytes", memSize);

        // Counts: function + symbol
        int functionCount = 0;
        try {
            functionCount = program.getFunctionManager().getFunctionCount();
        } catch (Throwable t) {
            // sentinel: 0
        }
        result.put("function_count", functionCount);

        int symbolCount = 0;
        try {
            symbolCount = program.getSymbolTable().getNumSymbols();
        } catch (Throwable t) {
            // sentinel: 0
        }
        result.put("symbol_count", symbolCount);

        // Creation timestamp. Per the spec's flagged uncertainty, the
        // exact Ghidra API is unverified. Program.getCreationDate()
        // returns a Date on modern Ghidra. If unavailable for any
        // reason, fall back to "".
        String creationTimestamp = "";
        try {
            var d = program.getCreationDate();
            if (d != null) {
                // ISO-8601 UTC. Use java.time to avoid SimpleDateFormat.
                creationTimestamp = d.toInstant().toString();
            }
        } catch (Throwable t) {
            // sentinel: ""
        }
        result.put("creation_timestamp", creationTimestamp);

        return ToolHelpers.text(JsonRender.render(result));
    }

    private static String safeStr(String s) {
        return s == null ? "" : s;
    }
}
