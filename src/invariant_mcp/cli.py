from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from invariant_mcp.config_sync import AgentRuleCompiler
from invariant_mcp.engine import InvariantEngine
from invariant_mcp.rules import ALL_RULES
from invariant_mcp.verifier import ExecutionVerifier

app = typer.Typer(
    name="invariant-gate",
    help="Deterministic pre-flight invariant gates & cryptographic execution receipts for autonomous coding agents.",
    no_args_is_help=True,
)
console = Console()


@app.command("check")
def cmd_check(
    path: str = typer.Argument(".", help="Path to git repository or source directory"),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON report"),
) -> None:
    """Run deterministic pre-flight invariant checks on uncommitted changes or directory files."""
    engine = InvariantEngine()
    report = engine.check_repository(path)

    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
        raise typer.Exit(code=0 if report.passed else 1)

    if report.passed:
        console.print(
            Panel(
                f"[bold green]PRE-FLIGHT PASSED[/bold green]\n"
                f"Files checked: {len(report.files_checked)} | Critical/High violations: 0 | Warnings: {report.warning_count}",
                title="invariant-mcp Pre-Flight Gate",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]PRE-FLIGHT BLOCKED[/bold red]\n"
                f"Critical: {report.critical_count} | High: {report.high_count} | Warnings: {report.warning_count}",
                title="invariant-mcp Pre-Flight Gate",
                border_style="red",
            )
        )

    if report.violations:
        table = Table(show_lines=True)
        table.add_column("Rule", style="bold cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Location")
        table.add_column("Violation & Remediation")
        for v in report.violations:
            sev_color = "red" if v.severity.value == "critical" else ("yellow" if v.severity.value == "high" else "blue")
            loc = f"{v.file_path}:{v.line_number or 1}"
            detail = f"{v.message}\n[dim]Fix: {v.fix_suggestion}[/dim]"
            table.add_row(v.rule_id, f"[{sev_color}]{v.severity.value.upper()}[/{sev_color}]", loc, detail)
        console.print(table)

    raise typer.Exit(code=0 if report.passed else 1)


@app.command("sarif")
def cmd_sarif(
    path: str = typer.Argument(".", help="Repository or source directory path"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write SARIF 2.1.0 JSON to file"),
) -> None:
    """Export pre-flight invariant findings in OASIS SARIF 2.1.0 format for GitHub Code Scanning / Codex Security."""
    engine = InvariantEngine()
    report = engine.check_repository(path)
    sarif_doc = json.dumps(engine.to_sarif(report), indent=2)
    if output:
        output.write_text(sarif_doc, encoding="utf-8")
        console.print(f"[green]Wrote SARIF 2.1.0 report to {output}[/green]")
    else:
        typer.echo(sarif_doc)


@app.command("verify")
def cmd_verify(
    command: str = typer.Argument(..., help="Test or build command to execute and sign"),
    cwd: str | None = typer.Option(None, "--cwd", help="Working directory"),
    timeout: int = typer.Option(120, "--timeout", help="Execution timeout in seconds"),
) -> None:
    """Run a command and record a tamper-evident SHA-256 + HMAC-SHA256 verification receipt."""
    verifier = ExecutionVerifier()
    receipt = verifier.execute_and_verify(command=command, cwd=cwd, timeout=timeout)
    status = "[bold green]PASSED[/bold green]" if receipt.passed else "[bold red]FAILED[/bold red]"
    console.print(
        Panel(
            f"Status: {status} (exit={receipt.exit_code}, {receipt.duration_ms} ms)\n"
            f"Receipt ID: [cyan]{receipt.receipt_id}[/cyan]\n"
            f"Output SHA-256: [dim]{receipt.output_sha256}[/dim]\n"
            f"HMAC-SHA256: [dim]{receipt.receipt_hmac}[/dim]",
            title="Cryptographic Execution Receipt",
            border_style="green" if receipt.passed else "red",
        )
    )
    raise typer.Exit(code=receipt.exit_code)


@app.command("rules")
def cmd_rules() -> None:
    """Display the catalog of deterministic production safety invariants."""
    table = Table(title="invariant-mcp Rule Catalog")
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Rule")
    for r in ALL_RULES:
        table.add_row(r.rule_id, r.severity.value.upper(), r.category, f"[bold]{r.name}[/bold]\n{r.description}")
    console.print(table)


@app.command("sync")
def cmd_sync(
    workspace: Path = typer.Argument(Path("."), help="Target repository root"),
) -> None:
    """Generate synchronized AGENTS.md, CLAUDE.md, GEMINI.md, and .cursorrules safety files."""
    written = AgentRuleCompiler(workspace_root=workspace).sync_all()
    for name, dest in written.items():
        console.print(f"[green]Synced[/green] {name} -> {dest}")


if __name__ == "__main__":
    app()
