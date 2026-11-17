from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from invariant_mcp import (
    ALL_RULES,
    ConstraintVerifier,
    ExecutionVerifier,
    InvariantEngine,
    Severity,
)
from invariant_mcp.cli import app
from invariant_mcp.config_sync import AgentRuleCompiler
from invariant_mcp.mcp_server import (
    list_invariant_rules,
    preflight_check_diff,
    preflight_scan_repo,
    sync_agent_configs,
    verify_command_with_receipt,
    verify_output_constraints,
    verify_receipt_integrity,
)

runner = CliRunner()


def test_rule_catalog_completeness() -> None:
    assert len(ALL_RULES) == 12
    ids = [r.rule_id for r in ALL_RULES]
    assert ids == [f"INV-{i:03d}" for i in range(1, 13)]
    for r in ALL_RULES:
        assert r.reference_url.startswith("https://")


def test_inv001_django_cache_delete_many_trap() -> None:
    engine = InvariantEngine()
    bad_diff = '+    cache.delete_many(f"user_profile:{user_id}")\n'
    rep = engine.check_diff(bad_diff, "app/cache_utils.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-001" and v.severity == Severity.CRITICAL for v in rep.violations)

    good_diff = '+    cache.delete_many([f"user_profile:{user_id}"])\n'
    assert engine.check_diff(good_diff, "app/cache_utils.py").passed


def test_deleted_diff_lines_never_trigger_false_positives() -> None:
    engine = InvariantEngine()
    cleanup_diff = (
        "--- a/app/cache_utils.py\n"
        "+++ b/app/cache_utils.py\n"
        "@@ -10,1 +10,1 @@\n"
        '-    cache.delete_many("legacy_key")\n'
        '+    cache.delete("legacy_key")\n'
    )
    rep = engine.check_diff(cleanup_diff)
    assert rep.passed
    assert rep.total_violations == 0


def test_inv002_transaction_atomic_savepoint() -> None:
    engine = InvariantEngine()
    bad_code = (
        "def sync_items(items):\n"
        "    with transaction.atomic():\n"
        "        for item in items:\n"
        "            try:\n"
        "                item.save()\n"
        "            except IntegrityError:\n"
        "                pass\n"
    )
    rep = engine.check_diff(bad_code, "app/services.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-002" for v in rep.violations)

    safe_code = (
        "def sync_items(items):\n"
        "    with transaction.atomic():\n"
        "        for item in items:\n"
        "            try:\n"
        "                with transaction.atomic():\n"
        "                    item.save()\n"
        "            except IntegrityError:\n"
        "                pass\n"
    )
    assert engine.check_diff(safe_code, "app/services.py").passed


def test_inv003_redis_keys_blocking() -> None:
    engine = InvariantEngine()
    rep = engine.check_diff('+keys = redis_client.keys("session:*")', "app/sessions.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-003" for v in rep.violations)


def test_inv004_postgres_migration_locks() -> None:
    engine = InvariantEngine()
    sql_bad = "+CREATE INDEX idx_orders_user ON orders(user_id);\n+ALTER TABLE orders ADD COLUMN meta jsonb;"
    rep = engine.check_diff(sql_bad, "migrations/0042_orders.sql")
    assert not rep.passed
    inv4 = [v for v in rep.violations if v.rule_id == "INV-004"]
    assert len(inv4) == 2

    sql_good = "+SET LOCAL lock_timeout = '3s';\n+CREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);"
    assert engine.check_diff(sql_good, "migrations/0042_orders.sql").passed


def test_inv005_celery_eta_unrouted() -> None:
    engine = InvariantEngine()
    bad = "+send_digest.apply_async(args=[uid], countdown=7200)"
    assert any(v.rule_id == "INV-005" for v in engine.check_diff(bad, "app/tasks.py").violations)

    routed = "+send_digest.apply_async(args=[uid], countdown=7200, queue='delayed')"
    assert engine.check_diff(routed, "app/tasks.py").passed


def test_inv006_unauthorized_remote_push() -> None:
    engine = InvariantEngine()
    bad = '+subprocess.run(["git", "push", "origin", "main"])\n# git push origin main'
    rep = engine.check_diff('+os.system("git push origin main")', "scripts/deploy.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-006" for v in rep.violations)
    assert bad  # sanity

    allowed = '+os.system("git push origin main")  # invariant:allow'
    assert engine.check_diff(allowed, "scripts/deploy.py").passed


def test_inv007_subprocess_shell_true() -> None:
    engine = InvariantEngine()
    rep = engine.check_diff('+subprocess.run(cmd, shell=True)', "app/runner.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-007" for v in rep.violations)


def test_inv008_blocking_in_async_ast_and_fallback() -> None:
    engine = InvariantEngine()
    code = (
        "import time, requests\n"
        "async def fetch_status(url: str):\n"
        "    time.sleep(1)\n"
        "    return requests.get(url, timeout=5)\n"
    )
    rep = engine.check_diff(code, "app/api.py")
    assert not rep.passed
    inv8 = [v for v in rep.violations if v.rule_id == "INV-008"]
    assert len(inv8) == 2


def test_inv009_sql_fstring_injection() -> None:
    engine = InvariantEngine()
    bad = '+cursor.execute(f"SELECT * FROM accounts WHERE email = \'{email}\'")'
    rep = engine.check_diff(bad, "app/db.py")
    assert not rep.passed
    assert any(v.rule_id == "INV-009" for v in rep.violations)


def test_inv010_missing_http_timeout() -> None:
    engine = InvariantEngine()
    warn_code = '+resp = requests.get("https://example.com/api")'
    rep = engine.check_diff(warn_code, "app/http_client.py")
    assert rep.passed  # WARNING does not block critical/high gate
    assert rep.warning_count == 1
    assert rep.violations[0].rule_id == "INV-010"


def test_inv011_hardcoded_secret_redaction() -> None:
    engine = InvariantEngine()
    fake_tok = "sk-" + "aB9xZ2mK4pQ7vN1wR8tY5uJ3cL6fH0dG"
    rep = engine.check_diff(f'+API_KEY = "{fake_tok}"', "app/config.py")
    assert not rep.passed
    v = next(x for x in rep.violations if x.rule_id == "INV-011")
    assert fake_tok not in (v.line_snippet or "")
    assert "REDACTED" in (v.line_snippet or "")


def test_inv012_pytorch_eval_without_no_grad() -> None:
    engine = InvariantEngine()
    code = "def evaluate(model, x):\n    model.eval()\n    return model(x)\n"
    rep = engine.check_diff(code, "ml/eval_loop.py")
    assert any(v.rule_id == "INV-012" for v in rep.violations)

    safe = "def evaluate(model, x):\n    model.eval()\n    with torch.inference_mode():\n        return model(x)\n"
    rep_safe = engine.check_diff(safe, "ml/eval_loop.py")
    assert not any(v.rule_id == "INV-012" for v in rep_safe.violations)


def test_sarif_export_schema() -> None:
    engine = InvariantEngine()
    rep = engine.check_diff('+cache.delete_many("abc")', "service/cache.py")
    sarif = engine.to_sarif(rep)
    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    assert len(runs[0]["results"]) == 1
    assert runs[0]["results"][0]["ruleId"] == "INV-001"


def test_execution_verifier_and_tamper_detection(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    verifier = ExecutionVerifier(receipts_file=ledger, signing_secret="unit-test-secret")
    cmd = f"{sys.executable} -c \"print('verified-ok')\""
    receipt = verifier.execute_and_verify(cmd, cwd=str(tmp_path))

    assert receipt.passed
    assert receipt.exit_code == 0
    assert "verified-ok" in receipt.stdout_preview
    assert ledger.exists()

    payload = receipt.to_dict()
    assert verifier.verify_receipt(payload) is True

    # Mutating exit_code or stdout hash must invalidate HMAC
    forged = dict(payload)
    forged["exit_code"] = 1
    assert verifier.verify_receipt(forged) is False


def test_constraint_verifier() -> None:
    res_ok = ConstraintVerifier.verify("Summarize in exactly three lines with no bullets.", "Line 1\nLine 2\nLine 3")
    assert res_ok.passed

    res_bad = ConstraintVerifier.verify("Summarize in exactly two lines with no bullets.", "- Bullet 1\n- Bullet 2\n- Bullet 3")
    assert not res_bad.passed
    types = {v.constraint_type for v in res_bad.violations}
    assert "exact_line_count" in types
    assert "no_bullet_points" in types

    json_bad = ConstraintVerifier.verify("Respond with valid JSON only.", "Here is your JSON: {}")
    assert not json_bad.passed


def test_config_sync_and_mcp_tools(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    (tmp_path / "clean.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    scan_out = json.loads(preflight_scan_repo(str(tmp_path)))
    assert scan_out["passed"] is True

    sarif_out = json.loads(preflight_scan_repo(str(tmp_path), format="sarif"))
    assert sarif_out["version"] == "2.1.0"

    diff_out = json.loads(preflight_check_diff('+cache.delete_many("k")', "app.py"))
    assert diff_out["passed"] is False

    rec_json = verify_command_with_receipt(f"{sys.executable} --version", cwd=str(tmp_path))
    integrity = json.loads(verify_receipt_integrity(rec_json))
    assert integrity["valid_signature"] is True

    rules_json = json.loads(list_invariant_rules())
    assert len(rules_json) == 12

    c_json = json.loads(verify_output_constraints("Reply in exactly 1 line.", "Single concise line."))
    assert c_json["passed"] is True

    sync_out = json.loads(sync_agent_configs(str(tmp_path)))
    for target in AgentRuleCompiler.TARGETS:
        assert target in sync_out["synced_files"]
        assert (tmp_path / target).exists()


def test_cli_commands(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 42\n", encoding="utf-8")
    r_check = runner.invoke(app, ["check", str(tmp_path)])
    assert r_check.exit_code == 0

    r_rules = runner.invoke(app, ["rules"])
    assert r_rules.exit_code == 0
    assert "INV-001" in r_rules.stdout

    sarif_file = tmp_path / "out.sarif"
    r_sarif = runner.invoke(app, ["sarif", str(tmp_path), "-o", str(sarif_file)])
    assert r_sarif.exit_code == 0
    assert sarif_file.exists()
