from __future__ import annotations

import os
import subprocess
from pathlib import Path

from invariant_mcp.models import InvariantRule, InvariantViolation, PreflightReport, Severity
from invariant_mcp.rules import ALL_RULES


class InvariantEngine:
    """Deterministic pre-flight invariant scanner over unified git diffs and source trees."""

    IGNORED_DIRS = frozenset(
        {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            ".invariant",
            "dist",
            "build",
            ".pytest_cache",
            ".ruff_cache",
            "tests",
        }
    )
    SCANNABLE_SUFFIXES = (".py", ".sql", ".sh", ".js", ".ts", ".tsx")

    def __init__(self, rules: list[InvariantRule] | None = None) -> None:
        self.rules = rules if rules is not None else list(ALL_RULES)

    def check_diff(self, diff_text: str, default_file: str = "unknown.py") -> PreflightReport:
        """Analyze a unified git diff or raw code snippet against all active invariant rules."""
        file_diffs = self._split_diff_by_file(diff_text, default_file)
        all_violations: list[InvariantViolation] = []
        files_checked = list(file_diffs.keys())

        for file_path, hunk_text in file_diffs.items():
            for rule in self.rules:
                all_violations.extend(rule.check_fn(file_path, hunk_text))

        return self._summarize(all_violations, files_checked)

    def check_repository(self, repo_path: str = ".") -> PreflightReport:
        """Scan staged/unstaged git diffs and untracked files, or fall back to bounded tree walk."""
        target = Path(repo_path).resolve()
        if target == Path("/"):
            return self._summarize([], [])

        is_git = (
            subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(target),
                capture_output=True,
                text=True,
                check=False,
            ).returncode
            == 0
        )

        if not is_git:
            return self._scan_directory_tree(target)

        diff_unstaged = subprocess.run(
            ["git", "diff"], cwd=str(target), capture_output=True, text=True, check=False
        ).stdout
        diff_staged = subprocess.run(
            ["git", "diff", "--cached"], cwd=str(target), capture_output=True, text=True, check=False
        ).stdout
        untracked_out = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
        ).stdout

        combined_diff = f"{diff_unstaged}\n{diff_staged}".strip()
        report = self.check_diff(combined_diff) if combined_diff else self._summarize([], [])

        extra_violations: list[InvariantViolation] = list(report.violations)
        checked_files: list[str] = list(report.files_checked)

        for rel_file in untracked_out.splitlines():
            rel_file = rel_file.strip()
            if not rel_file or any(part in self.IGNORED_DIRS for part in Path(rel_file).parts):
                continue
            full_path = target / rel_file
            if full_path.is_file() and full_path.suffix in self.SCANNABLE_SUFFIXES:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                pseudo_diff = "\n".join(f"+{ln}" for ln in content.splitlines())
                checked_files.append(rel_file)
                for rule in self.rules:
                    extra_violations.extend(rule.check_fn(rel_file, pseudo_diff))

        if not checked_files:
            return self._scan_directory_tree(target)

        return self._summarize(extra_violations, checked_files)

    def to_sarif(self, report: PreflightReport, tool_version: str = "0.2.0") -> dict[str, object]:
        """Export a PreflightReport to OASIS SARIF 2.1.0 JSON for GitHub Code Scanning & Codex Security."""
        sarif_rules = [
            {
                "id": r.rule_id,
                "name": r.name.replace(" ", ""),
                "shortDescription": {"text": r.name},
                "fullDescription": {"text": r.description},
                "helpUri": r.reference_url,
                "defaultConfiguration": {"level": r.severity.to_sarif_level()},
                "properties": {"category": r.category, "severity": r.severity.value},
            }
            for r in self.rules
        ]

        results = []
        for v in report.violations:
            results.append(
                {
                    "ruleId": v.rule_id,
                    "level": v.severity.to_sarif_level(),
                    "message": {
                        "text": f"{v.message}"
                        + (f" Suggested fix: {v.fix_suggestion}" if v.fix_suggestion else "")
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": v.file_path},
                                "region": {"startLine": max(1, v.line_number or 1)},
                            }
                        }
                    ],
                }
            )

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "invariant-mcp",
                            "version": tool_version,
                            "informationUri": "https://github.com/infinity-009/invariant-mcp",
                            "rules": sarif_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _scan_directory_tree(self, target: Path) -> PreflightReport:
        violations: list[InvariantViolation] = []
        files_checked: list[str] = []

        for dirpath, dirnames, filenames in os.walk(str(target), topdown=True, onerror=lambda _: None):
            dirnames[:] = [d for d in dirnames if d not in self.IGNORED_DIRS and not d.startswith(".")]
            rel_parts = Path(dirpath).relative_to(target).parts
            if len(rel_parts) > 5:
                dirnames.clear()
                continue

            for fname in filenames:
                if fname.startswith("."):
                    continue
                f_path = Path(dirpath) / fname
                if f_path.suffix in self.SCANNABLE_SUFFIXES and f_path.is_file():
                    rel_str = str(f_path.relative_to(target)).replace("\\", "/")
                    content = f_path.read_text(encoding="utf-8", errors="replace")
                    pseudo_diff = "\n".join(f"+{ln}" for ln in content.splitlines())
                    files_checked.append(rel_str)
                    for rule in self.rules:
                        violations.extend(rule.check_fn(rel_str, pseudo_diff))

        return self._summarize(violations, files_checked)

    @staticmethod
    def _split_diff_by_file(diff_text: str, default_file: str) -> dict[str, str]:
        if "diff --git " not in diff_text and "\n+++ b/" not in diff_text and not diff_text.startswith("+++ b/"):
            return {default_file: diff_text}

        chunks: dict[str, list[str]] = {}
        current_file = default_file
        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                chunks.setdefault(current_file, [])
            elif line.startswith("diff --git "):
                parts = line.split(" b/")
                if len(parts) >= 2:
                    current_file = parts[-1].strip()
                    chunks.setdefault(current_file, [])
            else:
                chunks.setdefault(current_file, []).append(line)

        return {k: "\n".join(v) for k, v in chunks.items() if v}

    @staticmethod
    def _summarize(violations: list[InvariantViolation], files_checked: list[str]) -> PreflightReport:
        critical = sum(1 for v in violations if v.severity == Severity.CRITICAL)
        high = sum(1 for v in violations if v.severity == Severity.HIGH)
        warning = sum(1 for v in violations if v.severity == Severity.WARNING)
        return PreflightReport(
            passed=(critical == 0 and high == 0),
            total_violations=len(violations),
            critical_count=critical,
            high_count=high,
            warning_count=warning,
            violations=violations,
            files_checked=sorted(set(files_checked)),
        )
