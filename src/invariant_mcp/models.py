from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"

    def to_sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        return "warning"


@dataclass
class InvariantViolation:
    rule_id: str
    name: str
    severity: Severity
    message: str
    file_path: str
    line_number: int | None = None
    line_snippet: str | None = None
    fix_suggestion: str | None = None
    reference_url: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_snippet": self.line_snippet,
            "fix_suggestion": self.fix_suggestion,
            "reference_url": self.reference_url,
        }


@dataclass
class InvariantRule:
    rule_id: str
    name: str
    severity: Severity
    category: str
    description: str
    check_fn: Callable[[str, str], list[InvariantViolation]]
    reference_url: str


@dataclass
class PreflightReport:
    passed: bool
    total_violations: int
    critical_count: int
    high_count: int
    warning_count: int
    violations: list[InvariantViolation] = field(default_factory=list)
    files_checked: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "total_violations": self.total_violations,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "warning_count": self.warning_count,
            "files_checked": self.files_checked,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass
class VerificationReceipt:
    receipt_id: str
    command: str
    cwd: str
    exit_code: int
    passed: bool
    duration_ms: int
    timestamp: str
    stdout_preview: str
    stderr_preview: str
    output_sha256: str
    receipt_hmac: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ConstraintViolation:
    constraint_type: str
    message: str
    observed: str
    expected: str


@dataclass
class ConstraintResult:
    passed: bool
    violations: list[ConstraintViolation] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "violations": [asdict(v) for v in self.violations],
        }
