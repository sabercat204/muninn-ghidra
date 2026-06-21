# muninn-ghidra

Memory of the binary. Named for Odin's raven of memory — the project recovers what compilers strip and obfuscators hide.

Single-process Java extension for Ghidra that hosts a Model Context Protocol (MCP) server. Exposes reverse-engineering tooling to MCP-compatible clients for x64 / ARM firmware and game-binary analysis.

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

Produces `dist/ghidra_<ver>_PUBLIC_<date>_muninn-ghidra.zip` (~8 MB; includes Jetty 12, Jackson 2.19, MCP Java SDK 0.17.1, and their transitive deps).

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
muninn-ghidra listening on 127.0.0.1:8765 (sse=/sse, streamable=/mcp); 14 tool(s)
```

Two MCP transports are exposed simultaneously:

| Transport | Endpoint | Use when |
|---|---|---|
| Streamable-HTTP | `http://127.0.0.1:8765/mcp` | Current MCP clients |
| SSE | `http://127.0.0.1:8765/sse` + `/message` | Legacy clients that expect SSE |

The server only binds to `127.0.0.1`. It is **not** a network service; reaching it from another machine requires a reverse proxy or tunnel that you set up yourself, after threat-modeling it.

---

## Connect (MCP client)

Example MCP client config:

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

Fourteen tools today. Each has a full behavior spec in the in-tree design docs (inputs, outputs, error modes, threat notes, acceptance tests).

**Read — orientation & inspection**

| Name | Purpose |
|---|---|
| `get_program_info` | High-level metadata: name, format, language ID, image base, entry points, address spaces, memory size, function/symbol counts. Sentinel-on-missing for oddly-loaded binaries. |
| `list_segments` | Memory map: each block's address range, r/w/x permissions, initialized status, source type. The format-agnostic section view. |
| `list_functions` | Functions in the active program. Substring filter, max-results cap, thunk/external toggles. Deterministic by entry address. |
| `list_symbols` | All symbol kinds (function / label / global / parameter / local / namespace / class). Substring + kind + namespace filters; default-name exclusion toggle. |
| `list_strings` | Defined strings with encoding (ASCII / UTF-8 / UTF-16 / UTF-32), length, address, text. min_length and address_range filters. Fastest binary-orientation signal. |
| `list_imports` | External symbols this program calls into — library, name, thunk address. |
| `list_exports` | External entry points this program exposes (PE / ELF / Mach-O). |
| `get_function_info` | Per-function detail: signature, parameters with storage, xref counts, analysis flags. Optional bounded-timeout decompile via Ghidra's `DecompInterface`. |
| `get_xrefs` | Unified cross-reference traversal — inbound, outbound, or both. 9-bucket simplified reference type filter. |
| `disassemble_range` | Instruction-level disassembly over an address range or whole function. Arch-portable through Ghidra's SLEIGH. |
| `search_bytes` | Hex pattern search with `??` wildcards, address range scoping, context bytes. |

**Audit — deterministic vulnerability and hardening signals**

| Name | Purpose |
|---|---|
| `audit` | Four actions. `dangerous_calls` flags call sites of strcpy/gets/system/exec*/etc. with caller-overridable lists. `format_strings` flags printf-family calls with non-constant format args. `hardening` reports stack-canary / NX / ASLR / RELRO / CFG / CET status across PE/ELF/Mach-O. `anti_analysis` finds debug/VM/timing checks (IsDebuggerPresent / ptrace / RDTSC / cpuid). Surfaces signal, not verdict. |

**Mutate — annotation**

| Name | Purpose |
|---|---|
| `rename_symbol` | Rename a function / label / global / parameter / local / namespace by address or name. Distinguishes tool-level failure (`isError=true`) from caller-recoverable semantic rejection (`renamed=false`, e.g. duplicate name). |
| `set_comment` | Attach / replace / clear a comment at an address. All five Ghidra comment kinds (pre / post / eol / plate / repeatable). No-op clears do not pollute the undo stack. |

Mutations run on Ghidra's event-dispatch thread inside named transactions; each shows up as a single, readable entry in Ghidra's undo stack.

Untrusted-binary safety: tools only read parsed program state from Ghidra's symbol tables and listing — no binary content is interpreted or executed in the host process.

---

## Methodology

A few load-bearing project rules:

- **R-013** — `git push` is destructive-class. Every push, every remote, runs through a pre-push scrub (paths, hostnames, env exports, secret-shaped tokens, fixture binaries).
- **R-014** — License attribution travels with every distribution boundary. Sharing a built zip outside the build machine triggers third-party Apache 2.0 §4 obligations on the bundled jars.
- **R-015** — Post-push audit checks what visitors actually see (default branch, inherited refs, license at the root URL), not just what was pushed.
- **R-016** — Clean-room discipline during the rewrite phase: tool implementations read only the in-tree behavior spec and public Ghidra / MCP API docs. No prior implementation is consulted.
- **R-017** — Spec-first: no implementation begins without a behavior-spec entry that has passed the every-WHEN-implies-a-NOT-WHEN and degenerate-case checks.
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

MIT — see [`LICENSE`](LICENSE). Use freely, preserve the copyright + license text in copies, and there's no warranty.

---

## Status

| Phase | Focus | State |
|---|---|---|
| 0 | Spec authorship + build harness | done |
| 1 | Server bootstrap + first tool impl | done |
| 2 | Remaining 4 tool impls + shared mutation/json infra | done |
| 3 | (TBD) additional tools, runtime polish, configuration UI | open |

Single-author personal-research project. No contribution guide; issues and PRs may sit unanswered.
