from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from detection_lab.config import settings
from detection_lab.sigma_tools import run_sigma_check


@dataclass
class Gate:
    name: str
    passed: bool
    details: str


@dataclass
class QualityReport:
    rule: str
    gates: list[Gate] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(gate.passed for gate in self.gates)

    def add(self, name: str, passed: bool, details: str) -> None:
        self.gates.append(Gate(name, passed, details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "passed": self.passed,
            "gates": [gate.__dict__ for gate in self.gates],
        }


def _field_names(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key != "condition" and not isinstance(child, (dict, list)):
                fields.add(str(key).split("|", 1)[0])
            elif key != "condition" and isinstance(child, list):
                fields.add(str(key).split("|", 1)[0])
            fields.update(_field_names(child))
    elif isinstance(value, list):
        for child in value:
            fields.update(_field_names(child))
    return fields


def validate_design(design_path: Path) -> list[str]:
    design = json.loads(design_path.read_text(encoding="utf-8"))
    schema = json.loads((settings.root / "schemas/detection_design.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [error.message for error in sorted(validator.iter_errors(design), key=lambda item: list(item.path))]


def validate_rule(rule_path: Path, fixture_dir: Path | None = None) -> QualityReport:
    report = QualityReport(str(rule_path))
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict):
            raise ValueError("Top-level YAML value must be a mapping.")
        report.add("yaml_parse", True, "YAML parsed successfully.")
    except Exception as exc:
        report.add("yaml_parse", False, str(exc))
        return report

    required = {"title", "id", "status", "description", "author", "logsource", "detection", "falsepositives", "level", "tags"}
    missing = sorted(required - set(rule))
    report.add("required_metadata", not missing, "All required keys are present." if not missing else f"Missing keys: {', '.join(missing)}")

    try:
        uuid.UUID(str(rule.get("id", "")))
        valid_uuid = True
    except ValueError:
        valid_uuid = False
    report.add("rule_uuid", valid_uuid, "Rule ID is a valid UUID." if valid_uuid else "Rule ID is not a valid UUID.")

    logsource = rule.get("logsource") or {}
    log_ok = logsource.get("product") == "windows" and logsource.get("category") == "process_creation"
    report.add("logsource", log_ok, f"Observed logsource: {logsource}")

    allowed_fields = set(json.loads((settings.root / "schemas/sigma_fields.json").read_text(encoding="utf-8"))["fields"])
    used_fields = _field_names(rule.get("detection", {}))
    unknown_fields = sorted(field for field in used_fields if field not in allowed_fields)
    report.add("portable_fields", not unknown_fields, f"Fields: {sorted(used_fields)}" if not unknown_fields else f"Unsupported fields: {unknown_fields}")

    catalog = json.loads((settings.root / "schemas/attack_catalog.json").read_text(encoding="utf-8"))["techniques"]
    attack_tags = [str(tag) for tag in rule.get("tags", []) if str(tag).startswith("attack.t")]
    unknown_tags = sorted(tag for tag in attack_tags if tag.removeprefix("attack.").upper() not in catalog)
    report.add("attack_mapping", bool(attack_tags) and not unknown_tags, f"ATT&CK tags: {attack_tags}" if not unknown_tags else f"Unknown ATT&CK tags: {unknown_tags}")

    condition = str((rule.get("detection") or {}).get("condition", "")).strip()
    report.add("condition", bool(condition), f"Condition: {condition}" if condition else "Detection condition is missing.")

    broad_values = []
    for section in (rule.get("detection") or {}).values():
        if isinstance(section, dict):
            for key, value in section.items():
                values = value if isinstance(value, list) else [value]
                if any(str(item).strip() in {"*", "**"} for item in values):
                    broad_values.append(key)
    report.add("broad_wildcards", not broad_values, "No standalone wildcard values." if not broad_values else f"Standalone wildcard in: {broad_values}")

    sigma = run_sigma_check(rule_path)
    sigma_details = "\n".join(part for part in [sigma.stdout, sigma.stderr] if part) or "sigma check passed."
    report.add("sigma_check", sigma.ok, sigma_details)

    if fixture_dir:
        positive = list((fixture_dir / "positive").glob("*.json"))
        negative = list((fixture_dir / "negative").glob("*.json"))
        report.add("positive_fixtures", len(positive) >= 2, f"Positive fixtures: {len(positive)}")
        report.add("negative_fixtures", len(negative) >= 3, f"Negative fixtures: {len(negative)}")

    return report


def audit_content(root: Path) -> list[str]:
    violations: list[str] = []
    forbidden_chars = {"\u2013": "en dash", "\u2014": "em dash", "\u2015": "horizontal bar"}
    text_extensions = {".md", ".txt", ".yml", ".yaml", ".json", ".ndjson", ".py", ".sh", ".example"}
    for path in root.rglob("*"):
        if not path.is_file() or (path.suffix.lower() not in text_extensions and path.name not in {"Dockerfile", "Makefile", "lab"}):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for char, label in forbidden_chars.items():
            if char in text:
                violations.append(f"{path.relative_to(root)} contains {label}.")
        blocked_role = "instr" + "uctor"
        if re.search(blocked_role + r"(?:'s)?\s+(?:note|notes|guide|debrief)", text, re.IGNORECASE):
            violations.append(f"{path.relative_to(root)} contains prohibited role-note wording.")
    return sorted(set(violations))
