from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import yaml
from streamlit.testing.v1 import AppTest

from detection_lab import elastic
from detection_lab.http_client import ServiceError


ROOT = Path(__file__).resolve().parents[1]


def test_compose_starts_pipeline_without_waiting_for_model_pull() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "ports" not in services["ollama"]
    assert services["ollama-init"]["depends_on"]["ollama"]["condition"] == "service_started"
    assert "ollama-init" not in services["pipeline"]["depends_on"]
    assert services["pipeline"]["depends_on"]["telemetry-init"]["condition"] == "service_completed_successfully"
    assert services["portal"]["ports"] == ["127.0.0.1:${PORTAL_PORT:-8501}:8501"]
    for service_name in ("telemetry-init", "pipeline", "portal"):
        service = services[service_name]
        assert service["working_dir"] == "/workspace"
        assert service["environment"]["PYTHONPATH"] == "/workspace"
        assert service["environment"]["LAB_ROOT"] == "/workspace"
    assert services["portal"]["entrypoint"] == ["python", "-m", "streamlit"]


def test_portal_can_import_project_packages_from_its_script_directory() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from detection_lab.config import settings; "
                "from portal.theme import apply_theme; "
                "from scripts.generate_telemetry import generate; "
                "print(settings.root)"
            ),
        ],
        cwd=ROOT / "portal",
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_ollama_status_is_nonblocking_when_api_is_unavailable(monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        raise ServiceError("not ready")

    monkeypatch.setattr(elastic, "request_json", unavailable)
    result = elastic.ollama_status()
    assert result["api_ready"] is False
    assert result["model_ready"] is False
    assert result["models"] == []


def test_dataset_evaluation_scopes_ground_truth_to_rule_scenario(monkeypatch, tmp_path) -> None:
    rule = tmp_path / "rule.yml"
    rule.write_text("title: test\n", encoding="utf-8")
    monkeypatch.setattr(elastic, "convert_to_lucene", lambda path: object())
    monkeypatch.setattr(elastic, "extract_query", lambda result: "process.executable:*wmic.exe")
    monkeypatch.setattr(
        elastic,
        "execute_query",
        lambda index, query: {"hits": {"hits": [{"_id": "wmic-positive"}]}},
    )

    def truth(*args, **kwargs):
        return {
            "hits": {
                "hits": [
                    {"_id": "powershell-positive", "_source": {"lab": {"event_uid": "powershell-positive", "expected": True, "scenario": "encoded_powershell_intrusion"}}},
                    {"_id": "wmic-positive", "_source": {"lab": {"event_uid": "wmic-positive", "expected": True, "scenario": "wmic_security_tool_tampering"}}},
                    {"_id": "benign", "_source": {"lab": {"event_uid": "benign", "expected": False, "scenario": "enterprise_baseline"}}},
                ]
            }
        }

    monkeypatch.setattr(elastic, "request_json", truth)
    report = elastic.evaluate_rule(rule, target_scenarios=["wmic_security_tool_tampering"])
    assert report["tp"] == 1
    assert report["fp"] == 0
    assert report["fn"] == 0
    assert report["tn"] == 2
    assert report["passed"] is True


def test_alert_verification_is_bound_to_fresh_replay(monkeypatch) -> None:
    captured = {}

    def response(method, url, **kwargs):
        captured.update(kwargs["json"])
        return {"hits": {"hits": [{"_source": {"lab": {"event_uid": "replay-123"}}}]}}

    monkeypatch.setattr(elastic, "request_json", response)
    report = elastic.verify_alert(
        "rule-123",
        1,
        after="2026-07-10T08:00:00Z",
        event_uid="replay-123",
    )
    filters = captured["query"]["bool"]["filter"]
    assert {"term": {"kibana.alert.rule.rule_id": "rule-123"}} in filters
    assert {"range": {"@timestamp": {"gte": "2026-07-10T08:00:00Z"}}} in filters
    assert {"term": {"lab.event_uid": "replay-123"}} in filters
    assert report["verified"] is True


def test_every_portal_page_renders_without_backend_services() -> None:
    pages = [
        "00  Range Overview",
        "01  Detection Research",
        "02  Detection Design",
        "03  Sigma Workbench",
        "04  Test and Tune",
        "05  Telemetry Explorer",
        "06  Deploy and Verify",
        "07  Capstone",
    ]
    app = AppTest.from_file(str(ROOT / "portal/app.py"), default_timeout=20).run()
    for page in pages:
        app.radio[0].set_value(page).run()
        assert not app.exception, f"{page}: {app.exception}"
