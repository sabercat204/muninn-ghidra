# Security

## Reporting issues

If you find a security issue in muninn-ghidra, please do **not** open a public issue.

Report privately via GitHub's "Report a vulnerability" button on the repository's Security tab. That keeps the discussion out of public view until a fix is ready.

## Scope

In scope:
- Vulnerabilities in the MCP server itself (request handling, transport, dispatch)
- Bugs that allow a hostile binary loaded into Ghidra to escape the read-only tool surface and affect host state outside what the tool's spec describes
- Memory-safety or crash issues in the plugin that could be triggered remotely (the server binds to `127.0.0.1` only, so "remotely" here means localhost-attainable)

Out of scope:
- Vulnerabilities in Ghidra itself — report those to NSA's ghidra repo
- Vulnerabilities in third-party dependencies (Jetty, Jackson, MCP Java SDK) — report upstream
- The fact that the audit tool can be used to find vulnerabilities in third-party binaries; that's its purpose

## Threat model

The server binds to localhost-only by design. There is no authentication; any process on the same machine can connect. Treat as equivalent to a local CLI tool — appropriate for a single-user workstation, not for a shared system.

The tool surface is read-mostly. Two tools mutate program state (`rename_symbol`, `set_comment`); both operate inside Ghidra transactions and produce undoable changes. There is no shell-execution, no file-write outside Ghidra's project database, and no network surface beyond the localhost MCP endpoint.

If you stand this up behind a network proxy or expose it across hosts: threat-model that yourself before doing it.
