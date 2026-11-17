from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from invariant_mcp.models import InvariantRule, InvariantViolation, Severity

_SELF_EXEMPT_PATHS = (
    "invariant_mcp/rules.py",
    "invariant_mcp/config_sync.py",
    "tests/test_invariant_mcp.py",
)

_ALLOW_PRAGMA = "# invariant:allow"


def _iter_added_lines(diff_or_content: str) -> Iterator[tuple[int, str]]:
    """Yield (1-based line_num, stripped_plus_line) skipping unified-diff headers and deleted lines."""
    for idx, raw in enumerate(diff_or_content.splitlines(), 1):
        if raw.startswith(("---", "+++", "@@")):
            continue
        if raw.startswith("-"):
            continue
        clean = raw.removeprefix("+")
        if _ALLOW_PRAGMA in clean:
            continue
        yield idx, clean


def _is_exempt(file_path: str) -> bool:
    norm = file_path.replace("\\", "/")
    return any(norm.endswith(p) or p in norm for p in _SELF_EXEMPT_PATHS)


# ---------------------------------------------------------------------------
# INV-001: Django cache.delete_many(str) character-iteration silent trap
# ---------------------------------------------------------------------------
def check_django_cache_delete_many(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    pattern = re.compile(r"""cache\.delete_many\(\s*(?:f["']|["'][^"'\n]+["']|str\()""")
    for line_no, line in _iter_added_lines(diff_or_content):
        if pattern.search(line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-001",
                    name="Django cache.delete_many String Iterable Trap",
                    severity=Severity.CRITICAL,
                    message=(
                        "cache.delete_many() expects an iterable of keys, not a string/f-string. "
                        "Passing a string iterates character-by-character and silently fails to evict the target cache key."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Pass a list of keys: cache.delete_many([key]) or call cache.delete(key).",
                    reference_url="https://docs.djangoproject.com/en/5.1/topics/cache/#django.core.cache.cache.delete_many",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-002: Swallowed DB exception inside transaction.atomic() without savepoint
# ---------------------------------------------------------------------------
def check_transaction_atomic_savepoint(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    in_atomic = False
    atomic_indent = -1
    nested_atomic_seen = False

    for line_no, line in _iter_added_lines(diff_or_content):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())

        if "with transaction.atomic(" in line or "@transaction.atomic" in line:
            if in_atomic and indent > atomic_indent:
                nested_atomic_seen = True
            else:
                in_atomic = True
                atomic_indent = indent
                nested_atomic_seen = False
            continue

        if in_atomic:
            if indent <= atomic_indent:
                in_atomic = False
                nested_atomic_seen = False
                continue

            if not nested_atomic_seen and re.search(
                r"\bexcept\s+(?:Exception|BaseException|IntegrityError|DatabaseError|OperationalError)\b",
                line,
            ):
                violations.append(
                    InvariantViolation(
                        rule_id="INV-002",
                        name="Swallowed DB Exception Inside transaction.atomic() Without Savepoint",
                        severity=Severity.CRITICAL,
                        message=(
                            "Catching database exceptions inside transaction.atomic() without an inner savepoint poisons "
                            "the PostgreSQL transaction state and raises TransactionManagementError on subsequent queries."
                        ),
                        file_path=file_path,
                        line_number=line_no,
                        line_snippet=stripped,
                        fix_suggestion="Wrap recoverable inner operations in a nested `with transaction.atomic():` savepoint block.",
                        reference_url="https://docs.djangoproject.com/en/5.1/topics/db/transactions/#avoid-catching-exceptions-inside-atomic",
                    )
                )
    return violations


# ---------------------------------------------------------------------------
# INV-003: Redis O(N) blocking KEYS command
# ---------------------------------------------------------------------------
def check_redis_blocking_keys(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    pattern = re.compile(r"\b(?:redis_client|redis|r|_redis|cache_client|redis_conn)\.keys\s*\(")
    for line_no, line in _iter_added_lines(diff_or_content):
        if pattern.search(line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-003",
                    name="Redis Blocking O(N) KEYS Command",
                    severity=Severity.HIGH,
                    message=(
                        "Calling .keys() executes an O(N) scan on Redis's single-threaded event loop, stalling all "
                        "concurrent client operations on large keyspaces."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Replace .keys(pattern) with incremental cursor iteration via .scan_iter(match=pattern, count=500).",
                    reference_url="https://redis.io/docs/latest/commands/keys/",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-004: PostgreSQL blocking DDL / missing CONCURRENTLY or lock_timeout
# ---------------------------------------------------------------------------
def check_postgres_ddl_locks(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    is_migration = "migration" in file_path.lower() or file_path.lower().endswith(".sql")
    if not is_migration:
        return []

    has_lock_timeout = "lock_timeout" in diff_or_content.lower()
    violations: list[InvariantViolation] = []
    create_idx_re = re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?!\s+CONCURRENTLY)", re.IGNORECASE)
    django_idx_re = re.compile(r"\bmigrations\.AddIndex\s*\(")
    alter_col_re = re.compile(r"\bALTER\s+TABLE\b.*\bADD\s+COLUMN\b", re.IGNORECASE)

    for line_no, line in _iter_added_lines(diff_or_content):
        reason = None
        if create_idx_re.search(line):
            reason = "Synchronous CREATE INDEX acquires SHARE lock and blocks writes across the table"
        elif django_idx_re.search(line):
            reason = "Django migrations.AddIndex blocks concurrent writes; prefer AddIndexConcurrently"
        elif alter_col_re.search(line) and not has_lock_timeout:
            reason = "ALTER TABLE ADD COLUMN acquires ACCESS EXCLUSIVE lock without a preceding SET lock_timeout"

        if reason:
            violations.append(
                InvariantViolation(
                    rule_id="INV-004",
                    name="PostgreSQL Blocking Schema Migration Lock Hazard",
                    severity=Severity.HIGH,
                    message=f"{reason}. Without lock_timeout, queued DDL statements stall all subsequent reads and writes behind the lock queue.",
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Use CREATE INDEX CONCURRENTLY / AddIndexConcurrently and set a bounded `SET LOCAL lock_timeout = '3s'`.",
                    reference_url="https://www.postgresql.org/docs/current/sql-createindex.html#SQL-CREATEINDEX-CONCURRENTLY",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-005: Celery long-horizon ETA / countdown worker prefetch saturation
# ---------------------------------------------------------------------------
def check_celery_eta_prefetch_hazard(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    pattern = re.compile(r"\.apply_async\s*\([^)]*\b(?:eta|countdown)\s*=")
    for line_no, line in _iter_added_lines(diff_or_content):
        if pattern.search(line) and "queue=" not in line:
            violations.append(
                InvariantViolation(
                    rule_id="INV-005",
                    name="Celery Unrouted ETA/Countdown Prefetch Saturation",
                    severity=Severity.HIGH,
                    message=(
                        "Scheduling delayed tasks via apply_async(eta=...|countdown=...) on default queues retains "
                        "unacknowledged messages in worker memory until execution, starving real-time tasks and risking OOM."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Route delayed tasks to an isolated low-prefetch queue (`queue='delayed'`) or trigger via periodic Celery Beat schedules.",
                    reference_url="https://docs.celeryq.dev/en/stable/userguide/calling.html#eta-and-countdown",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-006: Unauthorized autonomous remote git push / PR creation
# ---------------------------------------------------------------------------
def check_unauthorized_remote_mutation(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path) or file_path.endswith((".md", ".rst", ".txt", ".yml", ".yaml")):
        return []
    violations: list[InvariantViolation] = []
    push_re = re.compile(r"\b(?:git\s+push(?:\s+--force|\s+-f)?|gh\s+pr\s+create|gh\s+release\s+create)\b")
    neg_re = re.compile(r"\b(?:never|not|don't|prohibit|prevent|block|avoid|without)\b", re.IGNORECASE)

    for line_no, line in _iter_added_lines(diff_or_content):
        if push_re.search(line) and not neg_re.search(line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-006",
                    name="Unapproved Autonomous Remote Git Mutation",
                    severity=Severity.CRITICAL,
                    message=(
                        "Autonomous script or tool invokes `git push` or `gh pr create` without an explicit human-approval "
                        "annotation, risking irreversible upstream repository mutation."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Gate remote mutations behind interactive confirmation or annotate intentional scripts with `# invariant:allow`.",
                    reference_url="https://modelcontextprotocol.io/specification/2025-03-26/basic/security_best_practices",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-007: Subprocess shell=True command-injection surface
# ---------------------------------------------------------------------------
def check_subprocess_shell_injection(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path) or "verifier.py" in file_path:
        return []
    violations: list[InvariantViolation] = []
    pattern = re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True")
    for line_no, line in _iter_added_lines(diff_or_content):
        if pattern.search(line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-007",
                    name="Subprocess shell=True Command Injection Risk",
                    severity=Severity.HIGH,
                    message=(
                        "Invoking subprocess with shell=True exposes interpolated inputs to shell metacharacter injection."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Pass an explicit argument vector list `subprocess.run(['cmd', arg1], shell=False)`.",
                    reference_url="https://docs.python.org/3/library/subprocess.html#security-considerations",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-008: Blocking synchronous calls inside async def coroutines (AST + diff)
# ---------------------------------------------------------------------------
def check_blocking_call_in_async(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path) or not file_path.endswith(".py"):
        return []
    violations: list[InvariantViolation] = []
    added_lines = [line for _, line in _iter_added_lines(diff_or_content)]
    source = "\n".join(added_lines)

    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        owner = getattr(child.func.value, "id", "")
                        attr = child.func.attr
                        if (owner == "time" and attr == "sleep") or (
                            owner == "requests" and attr in {"get", "post", "put", "delete", "patch", "request"}
                        ):
                            violations.append(
                                InvariantViolation(
                                    rule_id="INV-008",
                                    name="Synchronous Event-Loop Blocking Call Inside async Coroutine",
                                    severity=Severity.HIGH,
                                    message=(
                                        f"Blocking call `{owner}.{attr}()` inside `async def {node.name}()` freezes the "
                                        "entire Python asyncio event loop and starves concurrent tasks/requests."
                                    ),
                                    file_path=file_path,
                                    line_number=getattr(child, "lineno", None),
                                    line_snippet=f"{owner}.{attr}(...)",
                                    fix_suggestion=(
                                        "Use `await asyncio.sleep(...)` instead of `time.sleep(...)` and `httpx.AsyncClient` "
                                        "or `asyncio.to_thread(...)` for network I/O."
                                    ),
                                    reference_url="https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code",
                                )
                            )
        return violations
    except SyntaxError:
        # Fallback for partial unified diff hunks that are not standalone parseable modules
        in_async = False
        async_indent = -1
        block_re = re.compile(r"\b(?:time\.sleep|requests\.(?:get|post|put|delete|patch))\s*\(")
        for line_no, line in _iter_added_lines(diff_or_content):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if re.match(r"async\s+def\s+\w+", stripped):
                in_async = True
                async_indent = indent
                continue
            if in_async:
                if indent <= async_indent:
                    in_async = False
                    continue
                if block_re.search(line):
                    violations.append(
                        InvariantViolation(
                            rule_id="INV-008",
                            name="Synchronous Event-Loop Blocking Call Inside async Coroutine",
                            severity=Severity.HIGH,
                            message="Blocking synchronous call inside `async def` stalls the asyncio event loop.",
                            file_path=file_path,
                            line_number=line_no,
                            line_snippet=stripped,
                            fix_suggestion="Use `await asyncio.sleep(...)` or an async HTTP client (`httpx.AsyncClient`).",
                            reference_url="https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code",
                        )
                    )
        return violations


# ---------------------------------------------------------------------------
# INV-009: SQL f-string / string interpolation injection
# ---------------------------------------------------------------------------
def check_sql_string_interpolation(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    sql_exec_re = re.compile(
        r"""\.(?:execute|executemany|raw)\s*\(\s*f["']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|WITH)\b""",
        re.IGNORECASE,
    )
    for line_no, line in _iter_added_lines(diff_or_content):
        if sql_exec_re.search(line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-009",
                    name="Unparameterized SQL f-String Interpolation",
                    severity=Severity.CRITICAL,
                    message="Interpolating variables directly into SQL execution strings via f-strings introduces SQL injection vulnerabilities.",
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Use parameterized bind placeholders (`cursor.execute('SELECT ... WHERE id = %s', [val])`).",
                    reference_url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-010: Missing timeout on outbound HTTP requests
# ---------------------------------------------------------------------------
def check_missing_http_timeout(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    req_re = re.compile(r"\brequests\.(?:get|post|put|delete|patch|head)\s*\(([^)]*)\)")
    for line_no, line in _iter_added_lines(diff_or_content):
        m = req_re.search(line)
        if m and "timeout" not in m.group(1):
            violations.append(
                InvariantViolation(
                    rule_id="INV-010",
                    name="Outbound HTTP Request Without Explicit Timeout",
                    severity=Severity.WARNING,
                    message=(
                        "`requests.*()` defaults to an infinite socket timeout, allowing hung upstream endpoints "
                        "to exhaust worker threads indefinitely."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Always pass a bounded timeout: `requests.get(url, timeout=10)`.",
                    reference_url="https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-011: Hardcoded credential / API key leak in staged code
# ---------------------------------------------------------------------------
def check_hardcoded_secrets(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path):
        return []
    violations: list[InvariantViolation] = []
    secret_re = re.compile(
        r"""(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{24,})"""
    )
    for line_no, line in _iter_added_lines(diff_or_content):
        if secret_re.search(line) and "EXAMPLE" not in line.upper() and "PLACEHOLDER" not in line.upper():
            violations.append(
                InvariantViolation(
                    rule_id="INV-011",
                    name="Hardcoded Credential or API Token in Diff",
                    severity=Severity.CRITICAL,
                    message="Detected a high-entropy API key or cloud credential literal in added lines.",
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet="[REDACTED CREDENTIAL SNIPPET]",
                    fix_suggestion="Load credentials from environment variables (`os.environ[...]`) or a secret manager and rotate the exposed key.",
                    reference_url="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# INV-012: PyTorch evaluation/inference tensor accumulation without no_grad
# ---------------------------------------------------------------------------
def check_pytorch_eval_grad_leak(file_path: str, diff_or_content: str) -> list[InvariantViolation]:
    if _is_exempt(file_path) or not file_path.endswith(".py"):
        return []
    if ".eval()" not in diff_or_content:
        return []
    has_no_grad = "no_grad" in diff_or_content or "inference_mode" in diff_or_content
    if has_no_grad:
        return []

    violations: list[InvariantViolation] = []
    for line_no, line in _iter_added_lines(diff_or_content):
        if re.search(r"\b\w+\.eval\(\)", line):
            violations.append(
                InvariantViolation(
                    rule_id="INV-012",
                    name="PyTorch .eval() Without torch.no_grad() / inference_mode() Guard",
                    severity=Severity.WARNING,
                    message=(
                        "Calling `model.eval()` disables dropout/batchnorm updates but still constructs autograd graphs, "
                        "causing GPU VRAM leaks during inference loops unless wrapped in `torch.inference_mode()` or `torch.no_grad()`."
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    line_snippet=line.strip(),
                    fix_suggestion="Wrap evaluation forward passes with `with torch.inference_mode():` or `with torch.no_grad():`.",
                    reference_url="https://pytorch.org/docs/stable/generated/torch.inference_mode.html",
                )
            )
    return violations


ALL_RULES: list[InvariantRule] = [
    InvariantRule(
        rule_id="INV-001",
        name="Django cache.delete_many String Iterable Trap",
        severity=Severity.CRITICAL,
        category="cache-correctness",
        description="Blocks passing string literals/f-strings to cache.delete_many(), which iterates character-by-character.",
        check_fn=check_django_cache_delete_many,
        reference_url="https://docs.djangoproject.com/en/5.1/topics/cache/#django.core.cache.cache.delete_many",
    ),
    InvariantRule(
        rule_id="INV-002",
        name="Swallowed DB Exception Inside transaction.atomic() Without Savepoint",
        severity=Severity.CRITICAL,
        category="database-safety",
        description="Detects bare exception swallowing inside Django atomic blocks without nested savepoints.",
        check_fn=check_transaction_atomic_savepoint,
        reference_url="https://docs.djangoproject.com/en/5.1/topics/db/transactions/#avoid-catching-exceptions-inside-atomic",
    ),
    InvariantRule(
        rule_id="INV-003",
        name="Redis Blocking O(N) KEYS Command",
        severity=Severity.HIGH,
        category="distributed-systems",
        description="Prevents single-threaded Redis event-loop stalls caused by O(N) KEYS scans.",
        check_fn=check_redis_blocking_keys,
        reference_url="https://redis.io/docs/latest/commands/keys/",
    ),
    InvariantRule(
        rule_id="INV-004",
        name="PostgreSQL Blocking Schema Migration Lock Hazard",
        severity=Severity.HIGH,
        category="database-safety",
        description="Flags synchronous index creation and unlocked DDL migrations that stall production Postgres queues.",
        check_fn=check_postgres_ddl_locks,
        reference_url="https://www.postgresql.org/docs/current/sql-createindex.html#SQL-CREATEINDEX-CONCURRENTLY",
    ),
    InvariantRule(
        rule_id="INV-005",
        name="Celery Unrouted ETA/Countdown Prefetch Saturation",
        severity=Severity.HIGH,
        category="distributed-systems",
        description="Detects long-horizon ETA/countdown tasks dispatched onto default worker queues.",
        check_fn=check_celery_eta_prefetch_hazard,
        reference_url="https://docs.celeryq.dev/en/stable/userguide/calling.html#eta-and-countdown",
    ),
    InvariantRule(
        rule_id="INV-006",
        name="Unapproved Autonomous Remote Git Mutation",
        severity=Severity.CRITICAL,
        category="agent-governance",
        description="Blocks autonomous scripts from pushing to remote branches or opening PRs without human consent.",
        check_fn=check_unauthorized_remote_mutation,
        reference_url="https://modelcontextprotocol.io/specification/2025-03-26/basic/security_best_practices",
    ),
    InvariantRule(
        rule_id="INV-007",
        name="Subprocess shell=True Command Injection Risk",
        severity=Severity.HIGH,
        category="security",
        description="Detects shell=True subprocess invocations vulnerable to metacharacter injection.",
        check_fn=check_subprocess_shell_injection,
        reference_url="https://docs.python.org/3/library/subprocess.html#security-considerations",
    ),
    InvariantRule(
        rule_id="INV-008",
        name="Synchronous Event-Loop Blocking Call Inside async Coroutine",
        severity=Severity.HIGH,
        category="concurrency",
        description="Uses Python AST inspection to detect time.sleep() and synchronous requests.*() inside async coroutines.",
        check_fn=check_blocking_call_in_async,
        reference_url="https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code",
    ),
    InvariantRule(
        rule_id="INV-009",
        name="Unparameterized SQL f-String Interpolation",
        severity=Severity.CRITICAL,
        category="security",
        description="Blocks f-string interpolation directly inside SQL execute/raw statements.",
        check_fn=check_sql_string_interpolation,
        reference_url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    InvariantRule(
        rule_id="INV-010",
        name="Outbound HTTP Request Without Explicit Timeout",
        severity=Severity.WARNING,
        category="reliability",
        description="Warns when synchronous HTTP calls omit explicit socket timeouts.",
        check_fn=check_missing_http_timeout,
        reference_url="https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts",
    ),
    InvariantRule(
        rule_id="INV-011",
        name="Hardcoded Credential or API Token in Diff",
        severity=Severity.CRITICAL,
        category="security",
        description="Scans added diff lines for OpenAI, GitHub, AWS, and Slack secret token patterns.",
        check_fn=check_hardcoded_secrets,
        reference_url="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ),
    InvariantRule(
        rule_id="INV-012",
        name="PyTorch .eval() Without torch.no_grad() / inference_mode() Guard",
        severity=Severity.WARNING,
        category="ml-systems",
        description="Flags PyTorch evaluation blocks missing autograd graph suppression.",
        check_fn=check_pytorch_eval_grad_leak,
        reference_url="https://pytorch.org/docs/stable/generated/torch.inference_mode.html",
    ),
]
