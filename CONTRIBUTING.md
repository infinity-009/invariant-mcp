# Contributing to invariant-mcp

Contributions adding deterministic production-hazard rules, framework adapters, or language-specific AST analyzers are welcome!

## Adding a New Invariant Rule

1. Define a pure check function `(file_path: str, diff_or_content: str) -> list[InvariantViolation]` in `src/invariant_mcp/rules.py`.
2. Ensure deleted diff lines (`line.startswith("-")`) are ignored so refactoring away hazardous code never triggers false positives.
3. Cite an upstream documentation URL (`reference_url`) explaining the underlying runtime failure mode.
4. Add positive (true-hazard) and negative (safe-idiom + deleted-diff-line) unit tests in `tests/test_invariant_mcp.py`.

## Running Tests & Self-Verification

```bash
uv sync --extra dev
uv run pytest -v
uv run ruff check src tests
uv run invariant-gate check .
```
