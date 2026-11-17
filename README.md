# `invariant-mcp`: Deterministic Pre-Flight Invariant Gates & Cryptographic Execution Receipts for Autonomous Coding Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Stdio%20%7C%20Streamable%20HTTP-green.svg)](https://modelcontextprotocol.io/)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0003--7328--7946-A6CE39.svg)](https://orcid.org/0009-0003-7328-7946)

`invariant-mcp` is a zero-trust verification layer and **Model Context Protocol (MCP)** server for autonomous software engineering agents (**OpenAI Codex**, **Claude Code**, **Gemini**, **Cursor**).

Autonomous coding agents frequently introduce **syntactically valid, unit-test-passing patches that trigger catastrophic production failures**—such as passing string literals to `cache.delete_many()` (silent character-by-character cache misses), swallowing database exceptions inside `transaction.atomic()` without nested savepoints, issuing synchronous `CREATE INDEX` locks on live PostgreSQL tables, blocking `asyncio` event loops, or hallucinating test-suite execution in multi-agent handoffs.

`invariant-mcp` closes this reliability gap with three deterministic primitives:

1. **Pre-Flight AST & Unified-Diff Invariant Engine (`INV-001` – `INV-012`)**: Sub-5ms static analysis over staged/unstaged git diffs with zero-false-positive handling of deleted lines (`-`) and full **OASIS SARIF 2.1.0** export for GitHub Code Scanning & Codex Security.
2. **Tamper-Evident Cryptographic Execution Receipts**: Runs test/build suites via `shlex` vector execution (`shell=False`) and signs `{command, cwd, exit_code, timestamp, stdout/stderr SHA-256}` with **HMAC-SHA256**, preventing subagent verification spoofing.
3. **Cross-Agent Rule Compiler**: Compiles canonical repository safety invariants simultaneously into `AGENTS.md` (OpenAI Codex), `CLAUDE.md` (Claude Code), `GEMINI.md`, and `.cursorrules`.

---

## Quickstart

```bash
# Install via uv or pip
uv tool install invariant-mcp
# or
pip install invariant-mcp

# 1. Check uncommitted git diffs against all 12 production invariants
invariant-gate check .

# 2. Export OASIS SARIF 2.1.0 report for GitHub Code Scanning / CI
invariant-gate sarif . --output results.sarif

# 3. Execute test suite and mint an HMAC-SHA256 verification receipt
invariant-gate verify "pytest -q"

# 4. Sync safety invariants across AGENTS.md, CLAUDE.md, GEMINI.md, and .cursorrules
invariant-gate sync .
```

---

## MCP Server Configuration

### OpenAI Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.invariant]
command = "uvx"
args = ["invariant-mcp"]
```

### Claude Code (`~/.claude.json` / `.mcp.json`)

```json
{
  "mcpServers": {
    "invariant": {
      "command": "uvx",
      "args": ["invariant-mcp"]
    }
  }
}
```

### Exposed MCP Tools

| Tool | Description |
| :--- | :--- |
| `preflight_check_diff` | Analyze a unified git diff or patch hunk before applying or committing changes. |
| `preflight_scan_repo` | Scan a repository's working tree and return structured JSON or OASIS SARIF 2.1.0. |
| `verify_command_with_receipt` | Execute tests/builds (`shell=False`) and emit an HMAC-SHA256 `VerificationReceipt`. |
| `verify_receipt_integrity` | Cryptographically verify a subagent's `VerificationReceipt` against tampering. |
| `verify_output_constraints` | Deterministically check response formatting constraints (line counts, strict JSON, table count). |
| `list_invariant_rules` | Inspect all 12 built-in production safety invariants and upstream documentation links. |
| `sync_agent_configs` | Synchronize `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and `.cursorrules`. |

---

## Built-In Production Safety Invariants

| ID | Severity | Category | Failure Mode Prevented |
| :--- | :---: | :--- | :--- |
| `INV-001` | `CRITICAL` | Cache Correctness | `cache.delete_many("key")` iterating character-by-character instead of evicting `"key"`. |
| `INV-002` | `CRITICAL` | Database Safety | Catching `IntegrityError`/`Exception` inside `transaction.atomic()` without a nested savepoint. |
| `INV-003` | `HIGH` | Distributed Systems | `redis.keys("*")` stalling Redis's single-threaded event loop (`O(N)` scan). |
| `INV-004` | `HIGH` | Database Safety | Synchronous `CREATE INDEX` or `ALTER TABLE ADD COLUMN` without `CONCURRENTLY` / `lock_timeout`. |
| `INV-005` | `HIGH` | Distributed Systems | Unrouted Celery `apply_async(eta=...|countdown=...)` exhausting worker prefetch memory. |
| `INV-006` | `CRITICAL` | Agent Governance | Autonomous scripts invoking `git push` or `gh pr create` without explicit human approval. |
| `INV-007` | `HIGH` | Security | `subprocess.run(..., shell=True)` exposing shell metacharacter command injection. |
| `INV-008` | `HIGH` | Concurrency | Python AST detection of `time.sleep()` or sync `requests.*()` inside `async def` coroutines. |
| `INV-009` | `CRITICAL` | Security | Direct f-string interpolation inside `.execute(f"SELECT ...")` / `.raw(f"...")`. |
| `INV-010` | `WARNING` | Reliability | Outbound synchronous `requests.*()` calls missing bounded `timeout=`. |
| `INV-011` | `CRITICAL` | Security | Hardcoded API tokens (`sk-...`, `ghp_...`, `AKIA...`, `xoxb-...`) in staged diffs. |
| `INV-012` | `WARNING` | ML Systems | PyTorch `model.eval()` blocks missing `torch.inference_mode()` / `torch.no_grad()`. |

---

## Citation

See [`CITATION.cff`](CITATION.cff) and the accompanying technical report in [`paper/`](paper/) for architectural benchmarks and formal evaluation across autonomous coding workflows.

## License

MIT License — see [`LICENSE`](LICENSE).

## GitHub Actions Integration

```yaml
- uses: astral-sh/setup-uv@v4
- run: uvx invariant-mcp --help
- run: uvx --from invariant-mcp invariant-gate sarif . --output results.sarif
```
