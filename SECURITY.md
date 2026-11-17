# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Threat Model & Scope

`invariant-mcp` acts as a deterministic safety boundary between autonomous coding agents (OpenAI Codex, Claude Code, Gemini, Cursor) and production repositories. Security-critical components include:

1. **Diff & AST Invariant Engine (`src/invariant_mcp/engine.py`)**: Must never execute untrusted code during static inspection (`ast.parse` only, never `eval`/`exec`).
2. **Cryptographic Execution Verifier (`src/invariant_mcp/verifier.py`)**: Binds command strings, working directory, UTC timestamps, exit codes, and `stdout`/`stderr` streams via SHA-256 / HMAC-SHA256 to prevent verification spoofing or reward hacking by subagents.
3. **Remote Mutation Gate (`INV-006`)**: Blocks unapproved `git push`, force-pushes, and remote PR creation in automated agent loops unless an explicit human-in-the-loop token is present.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories at `https://github.com/infinity-009/invariant-mcp/security/advisories/new` or email `hello@mallikarjunreddy.com`. We acknowledge reports within 48 hours.
