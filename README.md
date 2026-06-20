# ghidra-mcp

Single-process Java extension for Ghidra that hosts a Model Context Protocol (MCP) server. Exposes reverse-engineering tooling to MCP clients (Claude Code, custom integrations) for x64 / ARM firmware and game-binary analysis.

**Status:** pre-1.0, personal-research scope. Five tools implemented; spec-first methodology — every tool is authored against an in-tree behavior spec before implementation.

---

## Requirements

- Ghidra 12.x
- JDK 21 LTS
- Gradle (any 8.x or 9.x; tested against 9.5)
- `GHIDRA_INSTALL_DIR` environment variable pointing at the Ghidra install root (the directory containing `Ghidra/`, `support/`, etc.)

---

## Build

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_<ver>_PUBLIC
gradle buildExtension
```

Produces `dist/ghidra_<ver>_PUBLIC_<date>_ghidra-mcp.zip` (~8 MB; includes Jetty 12, Jackson 2.19, MCP Java SDK 0.17.1, and their transitive deps).

---

## Install

Two paths:

**1. Ghidra GUI** — `File → Install Extensions → +` → select the zip → restart Ghidra.

**2. File-system refresh** — unzip directly into Ghidra's user extensions directory, then restart Ghidra:

| OS | Path |
|---|---|
| macOS | `~/Library/ghidra/ghidra_<ver>_PUBLIC/Extensions/` |
| Linux | `$XDG_CONFIG_HOME/ghidra/ghidra_<ver>_PUBLIC/Extensions/` (default `~/.config/...`) |
| Windows | `%APPDATA%\ghidra\ghidra_<ver>_PUBLIC\Extensions\` |

The file-system path skips the GUI dance during iterative development.

After install: launch Ghidra → `File → Configure → Developer → check "Ghidra MCP Plugin"`.

---

## Run

The plugin auto-starts the MCP server on `127.0.0.1:8765` when enabled. Confirm in Ghidra's console:

```
ghidra-mcp listening on 127.0.0.1:8765 (sse=/sse, streamable=/mcp); 5 tool(s)
```

Two MCP transports are exposed simultaneously:

| Transport | Endpoint | Use when |
|---|---|---|
| Streamable-HTTP | `http://127.0.0.1:8765/mcp` | Current MCP clients (Claude Code, etc.) |
| SSE | `http://127.0.0.1:8765/sse` + `/message` | Legacy clients that expect SSE |

The server only binds to `127.0.0.1`. It is **not** a network service; reaching it from another machine requires a reverse proxy or tunnel that you set up yourself, after threat-modeling it.

---

## Connect (MCP client)

Example Claude Code client config:

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

Adjust to your client's configuration format. Confirm the connection with `tools/list` — it should return the 5 tool names below.

---

## Tools

Five behaviors are implemented today. Each has a full spec in `LOOM.md §4` (inputs, outputs, error modes, threat notes, acceptance tests).

| Name | Kind | Purpose |
|---|---|---|
| `list_functions` | read | List functions in the active program. Substring filter, max-results cap, thunk/external toggles. Deterministic by entry address. |
| `get_program_info` | read | High-level metadata: name, executable format, language ID, image base, entry points, address spaces, memory size, function/symbol counts. Sentinel-on-missing for oddly-loaded binaries. |
| `get_function_info` | read | Per-function detail: signature, prototype, parameters with storage, xref counts, analysis flags. Optional bounded-timeout decompile via Ghidra's `DecompInterface`. |
| `rename_symbol` | mutate | Rename a function / label / global / parameter / local / namespace by address or name. Distinguishes tool-level failure (`isError=true`) from caller-recoverable semantic rejection (`renamed=false`, e.g. duplicate name). |
| `set_comment` | mutate | Attach / replace / clear a comment at an address. All five Ghidra comment kinds (pre / post / eol / plate / repeatable). No-op clears do not pollute the undo stack. |

Mutations run on Ghidra's event-dispatch thread inside named transactions; each shows up as a single, readable entry in Ghidra's undo stack.

Untrusted-binary safety: tools only read parsed program state from Ghidra's symbol tables and listing — no binary content is interpreted or executed in the host process.

---

## Methodology

The project uses two harness files:

- **`CLAUDE.md`** — project rules for collaborative work (build / run, threat context, push discipline)
- **`LOOM.md`** — project state machinery (`§1` metadata, `§4` specs, `§6` rules, `§8` current phase)

A few load-bearing rules from `LOOM.md §6`:

- **R-013** — `git push` is destructive-class. Every push, every remote, runs through a pre-push scrub (paths, hostnames, env exports, secret-shaped tokens, fixture binaries).
- **R-014** — License attribution travels with every distribution boundary. Sharing a built zip outside the build machine triggers third-party Apache 2.0 §4 obligations on the bundled jars.
- **R-015** — Post-push audit checks what visitors actually see (default branch, inherited refs, license at the root URL), not just what was pushed.
- **R-016** — Clean-room discipline during the rewrite phase: tool implementations read only the in-tree behavior spec and public Ghidra / MCP API docs. No prior implementation is consulted.
- **R-017** — Spec-first: no implementation begins without a `§4` spec entry that has passed the every-WHEN-implies-a-NOT-WHEN and degenerate-case checks.
- **R-019** — Input validation precedes environment checks. A caller can fix an invalid argument without changing the environment; the error message should reflect that.

---

## Project Layout

```
src/main/java/io/sloptropy/ghidra/mcp/
├── GhidraMcpPlugin.java          Ghidra ProgramPlugin entry point
├── api/
│   ├── McpTool.java               tool contract
│   ├── ToolHelpers.java           text/error wrappers, address parse/format
│   ├── JsonRender.java            minimal JSON writer for tool responses
│   └── Mutation.java              EDT bridge + transaction discipline
├── server/
│   ├── ProgramSource.java         decouples tools from plugin state
│   ├── ToolRegistry.java          ordered, freeze-at-boot registry
│   └── McpServerBootstrap.java    Jetty 12 + MCP SDK transports
└── tools/
    ├── ListFunctionsTool.java
    ├── GetProgramInfoTool.java
    ├── GetFunctionInfoTool.java
    ├── RenameSymbolTool.java
    └── SetCommentTool.java
```

`smoke/` carries an out-of-tree harness for booting the server against a stubbed `ProgramSource` for protocol-level smoke testing without launching Ghidra. Not shipped in the extension zip.

---

## Configuration

Currently hard-coded:

- Bind address: `127.0.0.1`
- Bind port: `8765`
- Transports: both SSE and streamable-HTTP

Configuration UI is a future iteration. Override the port today by editing `GhidraMcpPlugin.DEFAULT_PORT` and rebuilding.

---

## License

Not yet selected. The tree contains only operator-authored code; license decision is deferred to the first public release (`LOOM.md` Q5). Until a `LICENSE` file is committed, treat this as "all rights reserved" by default.

---

## Status

| Phase | Focus | State |
|---|---|---|
| 0 | Spec authorship + build harness | done |
| 1 | Server bootstrap + first tool impl | done |
| 2 | Remaining 4 tool impls + shared mutation/json infra | done |
| 3 | (TBD) additional tools, runtime polish, configuration UI | open |

Single-author personal-research project. No contribution guide; issues and PRs may sit unanswered.
