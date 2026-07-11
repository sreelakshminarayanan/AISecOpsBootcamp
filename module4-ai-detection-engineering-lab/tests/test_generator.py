from __future__ import annotations

import json
from pathlib import Path

from scripts.generate_telemetry import generate


def test_generator_creates_mixed_correlated_dataset(tmp_path: Path) -> None:
    output = tmp_path / "events.ndjson"
    summary = generate(output)
    events = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert summary["total"] >= 230
    assert summary["malicious"] >= 10
    assert summary["expected_target_matches"] == 2
    assert any(event["winlog"]["event_id"] == 3 for event in events)
    assert any(event["winlog"]["event_id"] == 11 for event in events)
    assert any(event["winlog"]["event_id"] == 13 for event in events)
    assert any(event.get("process", {}).get("parent", {}).get("entity_id") for event in events if event.get("event", {}).get("category") == "process")


def test_generator_uses_safe_network_indicators(tmp_path: Path) -> None:
    output = tmp_path / "events.ndjson"
    generate(output)
    text = output.read_text(encoding="utf-8")
    assert "203.0.113.77" in text
    assert "198.51.100.44" in text
    assert ".example.test" in text

