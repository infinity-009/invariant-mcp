from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from invariant_mcp.models import ConstraintResult, ConstraintViolation, VerificationReceipt


class ExecutionVerifier:
    """Zero-trust test & build command runner producing HMAC-SHA256 tamper-evident execution receipts."""

    def __init__(self, receipts_file: Path | None = None, signing_secret: str | None = None) -> None:
        self.receipts_file = receipts_file or Path(".invariant/receipts.jsonl")
        secret_str = signing_secret or os.environ.get("INVARIANT_RECEIPT_SECRET", "invariant-mcp-local-key")
        self._secret = secret_str.encode("utf-8")

    def execute_and_verify(
        self,
        command: str,
        cwd: str | None = None,
        timeout: int = 120,
    ) -> VerificationReceipt:
        work_dir = os.path.abspath(cwd or os.getcwd())
        start_time = time.perf_counter()
        utc_now = datetime.now(timezone.utc).isoformat()

        try:
            argv = shlex.split(command)
            if not argv:
                raise ValueError("Empty command string")
            res = subprocess.run(
                argv,
                shell=False,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            exit_code = res.returncode
            stdout = res.stdout or ""
            stderr = res.stderr or ""
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            exit_code = 124
            stdout = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = f"Command timed out after {timeout} seconds."
        except (OSError, ValueError) as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            exit_code = 1
            stdout = ""
            stderr = f"Execution failed to launch: {exc}"

        passed = exit_code == 0
        combined_output = f"{stdout}\n{stderr}"
        output_sha256 = hashlib.sha256(combined_output.encode("utf-8")).hexdigest()
        receipt_id = (
            f"rec_{hashlib.sha256(f'{command}:{utc_now}:{output_sha256}'.encode()).hexdigest()[:16]}"
        )
        canonical_payload = f"{receipt_id}|{command}|{work_dir}|{exit_code}|{utc_now}|{output_sha256}"
        receipt_hmac = hmac.new(self._secret, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        receipt = VerificationReceipt(
            receipt_id=receipt_id,
            command=command,
            cwd=work_dir,
            exit_code=exit_code,
            passed=passed,
            duration_ms=duration_ms,
            timestamp=utc_now,
            stdout_preview=stdout[-1500:] if len(stdout) > 1500 else stdout,
            stderr_preview=stderr[-1500:] if len(stderr) > 1500 else stderr,
            output_sha256=output_sha256,
            receipt_hmac=receipt_hmac,
        )
        self._append_ledger(receipt)
        return receipt

    def verify_receipt(self, receipt_data: dict[str, object]) -> bool:
        """Cryptographically verify that a VerificationReceipt dictionary has not been forged or mutated."""
        canonical_payload = (
            f"{receipt_data.get('receipt_id')}|{receipt_data.get('command')}|{receipt_data.get('cwd')}|"
            f"{receipt_data.get('exit_code')}|{receipt_data.get('timestamp')}|{receipt_data.get('output_sha256')}"
        )
        expected = hmac.new(self._secret, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        provided = str(receipt_data.get("receipt_hmac", ""))
        return hmac.compare_digest(expected, provided)

    def _append_ledger(self, receipt: VerificationReceipt) -> None:
        try:
            self.receipts_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.receipts_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(receipt.to_dict()) + "\n")
        except OSError:
            pass


class ConstraintVerifier:
    """Deterministic structural verifier checking agent outputs against explicit prompt formatting constraints."""

    WORD_TO_NUM: ClassVar[dict[str, int]] = {
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
    }

    @classmethod
    def verify(cls, prompt: str, response: str) -> ConstraintResult:
        violations: list[ConstraintViolation] = []
        prompt_lower = prompt.lower()
        clean_response = response.strip()

        global_match = re.search(
            r"(?:in\s+exactly|exactly|only)\s+(\b\w+\b|\d+)\s+lines?\b", prompt_lower
        )
        if global_match:
            raw_num = global_match.group(1)
            target = int(raw_num) if raw_num.isdigit() else cls.WORD_TO_NUM.get(raw_num)
            if target is not None:
                lines = [ln for ln in clean_response.splitlines() if ln.strip()]
                if len(lines) != target:
                    violations.append(
                        ConstraintViolation(
                            constraint_type="exact_line_count",
                            message=f"Output contains {len(lines)} non-empty lines; expected {target}.",
                            observed=f"{len(lines)} lines",
                            expected=f"{target} lines",
                        )
                    )

        if "single table" in prompt_lower or "one table" in prompt_lower:
            tables = re.findall(r"(?:\|[^\n]+\|\n)+\|[-:\s|]+\|\n(?:\|[^\n]+\|\n?)+", clean_response)
            if len(tables) != 1:
                violations.append(
                    ConstraintViolation(
                        constraint_type="single_markdown_table",
                        message=f"Expected exactly 1 Markdown table, found {len(tables)}.",
                        observed=f"{len(tables)} tables",
                        expected="1 table",
                    )
                )

        if any(phrase in prompt_lower for phrase in ("no bullets", "no bullet points", "without bullets")):
            bullets = re.findall(r"^\s*[-*+]\s+", clean_response, flags=re.MULTILINE)
            if bullets:
                violations.append(
                    ConstraintViolation(
                        constraint_type="no_bullet_points",
                        message=f"Prompt prohibited bullet points, but output contains {len(bullets)}.",
                        observed=f"{len(bullets)} bullets",
                        expected="0 bullets",
                    )
                )

        if "valid json only" in prompt_lower or "json only" in prompt_lower:
            try:
                json.loads(clean_response)
            except ValueError as exc:
                violations.append(
                    ConstraintViolation(
                        constraint_type="strict_json",
                        message=f"Response is not valid standalone JSON: {exc}",
                        observed="non-JSON prose or malformed JSON",
                        expected="valid JSON payload",
                    )
                )

        return ConstraintResult(passed=(len(violations) == 0), violations=violations)
