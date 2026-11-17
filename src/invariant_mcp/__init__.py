"""invariant-mcp: Deterministic pre-flight invariant gates & cryptographic execution receipts for AI coding agents."""

from invariant_mcp.engine import InvariantEngine
from invariant_mcp.models import (
    ConstraintResult,
    ConstraintViolation,
    InvariantRule,
    InvariantViolation,
    PreflightReport,
    Severity,
    VerificationReceipt,
)
from invariant_mcp.rules import ALL_RULES
from invariant_mcp.verifier import ConstraintVerifier, ExecutionVerifier

__version__ = "0.2.0"

__all__ = [
    "ALL_RULES",
    "ConstraintResult",
    "ConstraintVerifier",
    "ConstraintViolation",
    "ExecutionVerifier",
    "InvariantEngine",
    "InvariantRule",
    "InvariantViolation",
    "PreflightReport",
    "Severity",
    "VerificationReceipt",
    "__version__",
]
