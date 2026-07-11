from __future__ import annotations

from pathlib import Path

import detection_lab.quality as quality
from detection_lab.sigma_tools import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def fake_sigma_ok(path: Path) -> CommandResult:
    return CommandResult(True, ["sigma", "check", str(path)], "passed", "", 0)


def test_validated_rule_passes_local_gates(monkeypatch) -> None:
    monkeypatch.setattr(quality, "run_sigma_check", fake_sigma_ok)
    report = quality.validate_rule(
        ROOT / "rules/validated/encoded_powershell.yml",
        ROOT / "tests/fixtures/encoded_powershell",
    )
    assert report.passed, report.to_dict()


def test_broken_rule_fails_multiple_gates(monkeypatch) -> None:
    monkeypatch.setattr(quality, "run_sigma_check", lambda path: CommandResult(False, [], "", "invalid", 1))
    report = quality.validate_rule(
        ROOT / "rules/broken/encoded_powershell.yml",
        ROOT / "tests/fixtures/encoded_powershell",
    )
    failed = {gate.name for gate in report.gates if not gate.passed}
    assert {"rule_uuid", "portable_fields", "attack_mapping", "broad_wildcards", "sigma_check"}.issubset(failed)


def test_content_audit_passes() -> None:
    assert quality.audit_content(ROOT) == []

