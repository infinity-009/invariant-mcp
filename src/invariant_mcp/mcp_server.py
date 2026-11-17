from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerClass
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServerClass

from invariant_mcp.config_sync import AgentRuleCompiler
from invariant_mcp.engine import InvariantEngine
from invariant_mcp.rules import ALL_RULES
from invariant_mcp.verifier import ConstraintVerifier, ExecutionVerifier

mcp = _MCPServerClass(
    "invariant-mcp",
    instructions=(
        "Deterministic pre-flight invariant gates, SARIF 2.1.0 static verification, "
        "and HMAC-SHA256 tamper-evident execution receipts for autonomous coding agents."
    ),
)

_engine = InvariantEngine()
_verifier = ExecutionVerifier()


@mcp.tool()
def preflight_check_diff(diff_text: str, file_path: str = "unknown.py") -> str:
    """Scan a unified git diff or code snippet against all 12 production safety invariants."""
    report = _engine.check_diff(diff_text=diff_text, default_file=file_path)
    return json.dumps(report.to_dict(), indent=2)


@mcp.tool()
def preflight_scan_repo(repo_path: str = ".", format: str = "json") -> str:
    """Scan uncommitted git changes and untracked files in a repository (`json` or `sarif`)."""
    report = _engine.check_repository(repo_path=repo_path)
    if format.lower() == "sarif":
        return json.dumps(_engine.to_sarif(report), indent=2)
    return json.dumps(report.to_dict(), indent=2)


@mcp.tool()
def verify_command_with_receipt(command: str, cwd: str = "", timeout_seconds: int = 120) -> str:
    """Execute a test/build command and return a tamper-evident SHA-256 + HMAC-SHA256 receipt."""
    receipt = _verifier.execute_and_verify(
        command=command,
        cwd=cwd or None,
        timeout=timeout_seconds,
    )
    return json.dumps(receipt.to_dict(), indent=2)


@mcp.tool()
def verify_receipt_integrity(receipt_json: str) -> str:
    """Verify the HMAC-SHA256 signature of a previously issued VerificationReceipt."""
    data = json.loads(receipt_json)
    valid = _verifier.verify_receipt(data)
    return json.dumps({"receipt_id": data.get("receipt_id"), "valid_signature": valid}, indent=2)


@mcp.tool()
def verify_output_constraints(prompt: str, response: str) -> str:
    """Verify structural compliance (exact line count, single table, no bullets, strict JSON)."""
    result = ConstraintVerifier.verify(prompt=prompt, response=response)
    return json.dumps(result.to_dict(), indent=2)


@mcp.tool()
def list_invariant_rules() -> str:
    """List all active deterministic safety and reliability invariant rules."""
    payload = [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "severity": r.severity.value,
            "category": r.category,
            "description": r.description,
            "reference_url": r.reference_url,
        }
        for r in ALL_RULES
    ]
    return json.dumps(payload, indent=2)


@mcp.tool()
def sync_agent_configs(workspace_path: str = ".") -> str:
    """Compile canonical safety invariants into AGENTS.md, CLAUDE.md, GEMINI.md, and .cursorrules."""
    compiler = AgentRuleCompiler(workspace_root=Path(workspace_path))
    written = compiler.sync_all()
    return json.dumps({"synced_files": written}, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="invariant-mcp Model Context Protocol server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("INVARIANT_MCP_TRANSPORT", "stdio"),
    )
    args, _ = parser.parse_known_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
