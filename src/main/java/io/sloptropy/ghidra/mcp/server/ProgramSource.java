package io.sloptropy.ghidra.mcp.server;

import ghidra.program.model.listing.Program;

/**
 * Abstraction over "the currently active program."
 *
 * In production, this is wired to Ghidra's tool/plugin state. In tests,
 * a fixture supplies a fixed Program. Tools call getCurrentProgram() and
 * branch on null; they don't import any Ghidra plugin classes.
 */
@FunctionalInterface
public interface ProgramSource {
    /** @return the active program, or null if none. */
    Program getCurrentProgram();
}
