from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from detection_lab.config import settings
from detection_lab.http_client import ServiceError, request_json
from detection_lab.sigma_tools import convert_to_lucene, extract_query


INDEX_MAPPINGS = {
    "dynamic": True,
    "properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"category": {"type": "keyword"}, "type": {"type": "keyword"}, "code": {"type": "keyword"}, "action": {"type": "keyword"}}},
        "host": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}, "os": {"properties": {"type": {"type": "keyword"}}}}},
        "user": {"properties": {"name": {"type": "keyword"}, "domain": {"type": "keyword"}, "id": {"type": "keyword"}}},
        "process": {
            "properties": {
                "name": {"type": "wildcard"}, "executable": {"type": "wildcard"}, "command_line": {"type": "wildcard"},
                "entity_id": {"type": "keyword"}, "pid": {"type": "long"}, "hash": {"properties": {"sha256": {"type": "keyword"}}},
                "parent": {"properties": {"name": {"type": "wildcard"}, "executable": {"type": "wildcard"}, "command_line": {"type": "wildcard"}, "entity_id": {"type": "keyword"}, "pid": {"type": "long"}}},
            }
        },
        "winlog": {"properties": {"event_id": {"type": "long"}, "channel": {"type": "keyword"}, "provider_name": {"type": "keyword"}}},
        "network": {"properties": {"direction": {"type": "keyword"}, "transport": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
        "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}, "domain": {"type": "keyword"}}},
        "file": {"properties": {"path": {"type": "wildcard"}, "name": {"type": "wildcard"}, "hash": {"properties": {"sha256": {"type": "keyword"}}}}},
        "registry": {"properties": {"path": {"type": "wildcard"}, "value": {"type": "wildcard"}, "data": {"type": "wildcard"}}},
        "labels": {"type": "object", "dynamic": True},
        "lab": {"properties": {"expected": {"type": "boolean"}, "malicious": {"type": "boolean"}, "scenario": {"type": "keyword"}, "event_uid": {"type": "keyword"}}},
    },
}


def status() -> dict[str, Any]:
    es = request_json("GET", f"{settings.elastic_url}/_cluster/health")
    kibana = request_json("GET", f"{settings.kibana_url}/api/status")
    ollama = ollama_status()
    return {
        "elasticsearch": {"status": es.get("status"), "cluster": es.get("cluster_name")},
        "kibana": {"status": kibana.get("status", {}).get("overall", {}).get("level", "unknown")},
        "ollama": ollama,
        "lab_index": settings.lab_index,
    }


def ollama_status() -> dict[str, Any]:
    try:
        response = request_json("GET", f"{settings.ollama_url}/api/tags", timeout=3)
    except ServiceError as exc:
        return {"api_ready": False, "model_ready": False, "configured_model": settings.ollama_model, "models": [], "message": str(exc)}
    models = [str(item.get("name", "")) for item in response.get("models", [])]
    configured = settings.ollama_model
    ready = any(name == configured or name.split(":", 1)[0] == configured.split(":", 1)[0] for name in models)
    message = "Configured model is ready." if ready else "Ollama is running. The configured model is still downloading."
    return {"api_ready": True, "model_ready": ready, "configured_model": configured, "models": models, "message": message}


def dataset_stats(index: str | None = None) -> dict[str, Any]:
    target = index or settings.lab_index
    body = {
        "size": 0,
        "aggs": {
            "malicious": {"filter": {"term": {"lab.malicious": True}}},
            "expected": {"filter": {"term": {"lab.expected": True}}},
            "categories": {"terms": {"field": "event.category", "size": 20}},
            "scenarios": {"terms": {"field": "lab.scenario", "size": 20}},
        },
    }
    response = request_json("POST", f"{settings.elastic_url}/{target}/_search", json=body, expected=(200,))
    aggs = response.get("aggregations", {})
    return {
        "index": target,
        "total": response.get("hits", {}).get("total", {}).get("value", 0),
        "malicious": aggs.get("malicious", {}).get("doc_count", 0),
        "expected": aggs.get("expected", {}).get("doc_count", 0),
        "categories": {item["key"]: item["doc_count"] for item in aggs.get("categories", {}).get("buckets", [])},
        "scenarios": {item["key"]: item["doc_count"] for item in aggs.get("scenarios", {}).get("buckets", [])},
    }


def search_events(
    *,
    index: str | None = None,
    category: str | None = None,
    scenario: str | None = None,
    malicious: bool | None = None,
    text: str | None = None,
    size: int = 100,
) -> list[dict[str, Any]]:
    target = index or settings.lab_index
    filters: list[dict[str, Any]] = []
    if category:
        filters.append({"term": {"event.category": category}})
    if scenario:
        filters.append({"term": {"lab.scenario": scenario}})
    if malicious is not None:
        filters.append({"term": {"lab.malicious": malicious}})
    must: list[dict[str, Any]] = []
    if text:
        must.append({"query_string": {"query": f"*{text.replace('*', '')}*", "fields": ["process.command_line", "process.executable", "process.parent.executable", "host.name", "user.name", "destination.ip", "file.path", "registry.path"], "analyze_wildcard": True}})
    query = {"bool": {"filter": filters, "must": must}} if filters or must else {"match_all": {}}
    body = {"size": min(size, 500), "query": query, "sort": [{"@timestamp": "desc"}]}
    response = request_json("POST", f"{settings.elastic_url}/{target}/_search", json=body, expected=(200,))
    return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]


def list_deployed_rules() -> list[dict[str, Any]]:
    response = request_json(
        "GET",
        f"{settings.kibana_url}/api/detection_engine/rules/_find?per_page=100",
        headers={"kbn-xsrf": "true"},
        expected=(200,),
    )
    return list(response.get("data", []))


def list_alerts(size: int = 50) -> list[dict[str, Any]]:
    body = {"size": min(size, 200), "query": {"match_all": {}}, "sort": [{"@timestamp": "desc"}]}
    response = request_json(
        "POST",
        f"{settings.elastic_url}/.alerts-security.alerts-default/_search",
        json=body,
        expected=(200, 404),
    )
    return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]


def ensure_template() -> None:
    body = {"index_patterns": ["lab-security-events-*", "lab-fixtures-*"], "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": INDEX_MAPPINGS}}
    request_json("PUT", f"{settings.elastic_url}/_index_template/detection-lab-ecs", json=body, expected=(200,))


def read_ndjson(paths: Iterable[Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{number} is not a JSON object.")
            events.append(value)
    return events


def bulk_index(index: str, events: list[dict[str, Any]], recreate: bool = False) -> dict[str, Any]:
    ensure_template()
    if recreate:
        request_json("DELETE", f"{settings.elastic_url}/{index}", expected=(200, 404))
    request_json("PUT", f"{settings.elastic_url}/{index}", expected=(200, 400))
    lines: list[str] = []
    for event in events:
        doc_id = str(event.get("lab", {}).get("event_uid") or uuid.uuid4())
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(event))
    response = request_json(
        "POST", f"{settings.elastic_url}/_bulk?refresh=true", data="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"}, expected=(200,), timeout=120,
    )
    if response.get("errors"):
        failures = [item for item in response.get("items", []) if item.get("index", {}).get("error")]
        raise ServiceError(f"Bulk indexing failed: {failures[:3]}")
    return {"index": index, "indexed": len(events)}


def execute_query(index: str, query: str, size: int = 1000) -> dict[str, Any]:
    body = {"size": size, "query": {"query_string": {"query": query, "analyze_wildcard": True}}, "sort": [{"@timestamp": "asc"}]}
    return request_json("POST", f"{settings.elastic_url}/{index}/_search", json=body, expected=(200,), timeout=120)


def test_rule(rule_path: Path, fixture_dir: Path) -> dict[str, Any]:
    converted = convert_to_lucene(rule_path)
    query = extract_query(converted)
    paths = sorted((fixture_dir / "positive").glob("*.json")) + sorted((fixture_dir / "negative").glob("*.json"))
    events = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    index = f"lab-fixtures-{uuid.uuid4().hex[:10]}"
    bulk_index(index, events, recreate=True)
    response = execute_query(index, query)
    matched_ids = {hit["_id"] for hit in response.get("hits", {}).get("hits", [])}
    expected_positive = {str(event["lab"]["event_uid"]) for event in events if event["lab"]["expected"]}
    expected_negative = {str(event["lab"]["event_uid"]) for event in events if not event["lab"]["expected"]}
    tp = len(matched_ids & expected_positive)
    fp = len(matched_ids & expected_negative)
    fn = len(expected_positive - matched_ids)
    tn = len(expected_negative - matched_ids)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    request_json("DELETE", f"{settings.elastic_url}/{index}", expected=(200, 404))
    return {
        "rule": str(rule_path), "query": query, "total_fixtures": len(events),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "matched_ids": sorted(matched_ids), "passed": fn == 0 and fp == 0,
    }


def fixture_target_scenarios(fixture_dir: Path) -> list[str]:
    scenarios: set[str] = set()
    for path in (fixture_dir / "positive").glob("*.json"):
        event = json.loads(path.read_text(encoding="utf-8"))
        scenario = str(event.get("lab", {}).get("scenario", "")).strip()
        if scenario:
            scenarios.add(scenario)
    return sorted(scenarios)


def evaluate_rule(rule_path: Path, index: str | None = None, target_scenarios: list[str] | None = None) -> dict[str, Any]:
    target_index = index or settings.lab_index
    query = extract_query(convert_to_lucene(rule_path))
    response = execute_query(target_index, query)
    matched_ids = {hit["_id"] for hit in response.get("hits", {}).get("hits", [])}
    truth_body = {"size": 10000, "query": {"match_all": {}}, "_source": ["lab.expected", "lab.event_uid", "lab.scenario"]}
    truth = request_json("POST", f"{settings.elastic_url}/{target_index}/_search", json=truth_body, expected=(200,), timeout=120)
    expected_positive: set[str] = set()
    expected_negative: set[str] = set()
    for hit in truth.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        event_id = str(source.get("lab", {}).get("event_uid") or hit["_id"])
        event_scenario = str(source.get("lab", {}).get("scenario", ""))
        in_scope = not target_scenarios or event_scenario in target_scenarios
        if source.get("lab", {}).get("expected") and in_scope:
            expected_positive.add(event_id)
        else:
            expected_negative.add(event_id)
    tp = len(matched_ids & expected_positive)
    fp = len(matched_ids & expected_negative)
    fn = len(expected_positive - matched_ids)
    tn = len(expected_negative - matched_ids)
    return {
        "index": target_index, "query": query, "target_scenarios": target_scenarios or [], "events": len(expected_positive) + len(expected_negative),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "matched_ids": sorted(matched_ids), "passed": fp == 0 and fn == 0,
    }


def replay_event(source_path: Path, index: str | None = None) -> dict[str, Any]:
    event = json.loads(source_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    replay_id = f"replay-{uuid.uuid4().hex}"
    event["@timestamp"] = now
    event.setdefault("lab", {})["event_uid"] = replay_id
    event.setdefault("labels", {})["replayed"] = "true"
    return {**bulk_index(index or settings.lab_index, [event], recreate=False), "event_uid": replay_id, "timestamp": now}


def _rule_payload(rule_path: Path, query: str, enabled: bool) -> dict[str, Any]:
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    risk = {"informational": 10, "low": 21, "medium": 47, "high": 73, "critical": 99}
    level = str(rule.get("level", "medium")).lower()
    return {
        "rule_id": str(rule["id"]), "name": str(rule["title"]), "description": str(rule["description"]),
        "risk_score": risk.get(level, 47), "severity": level if level in risk else "medium",
        "type": "query", "language": "lucene", "index": [settings.lab_index], "query": query,
        "interval": "1m", "from": "now-5m", "to": "now", "enabled": enabled,
        "tags": [str(tag) for tag in rule.get("tags", [])] + ["AI SecOps Bootcamp", "Detection-as-Code"],
        "author": [str(rule.get("author", "AI SecOps Bootcamp"))], "false_positives": rule.get("falsepositives", []),
        "references": rule.get("references", []), "max_signals": 100,
    }


def deploy_rule(rule_path: Path, enabled: bool = True) -> dict[str, Any]:
    query = extract_query(convert_to_lucene(rule_path))
    payload = _rule_payload(rule_path, query, enabled)
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    existing = None
    try:
        existing = request_json("GET", f"{settings.kibana_url}/api/detection_engine/rules?rule_id={payload['rule_id']}", headers=headers)
    except ServiceError:
        pass
    history_path = settings.root / "deployments/history.jsonl"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    if existing:
        with history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"saved_at": datetime.now(timezone.utc).isoformat(), "rule_id": payload["rule_id"], "payload": existing}) + "\n")
        response = request_json("PUT", f"{settings.kibana_url}/api/detection_engine/rules", json=payload, headers=headers, expected=(200,))
        action = "updated"
    else:
        response = request_json("POST", f"{settings.kibana_url}/api/detection_engine/rules", json=payload, headers=headers, expected=(200,))
        action = "created"
    return {"action": action, "rule_id": payload["rule_id"], "enabled": response.get("enabled"), "query": query, "revision": response.get("revision")}


def rollback_rule(rule_id: str) -> dict[str, Any]:
    history_path = settings.root / "deployments/history.jsonl"
    if not history_path.exists():
        raise ValueError("No deployment history exists.")
    entries = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    candidates = [entry for entry in entries if entry.get("rule_id") == rule_id]
    if not candidates:
        raise ValueError(f"No previous version recorded for {rule_id}.")
    previous = candidates[-1]["payload"]
    allowed = {"rule_id", "name", "description", "risk_score", "severity", "type", "language", "index", "query", "interval", "from", "to", "enabled", "tags", "author", "false_positives", "references", "max_signals"}
    payload = {key: value for key, value in previous.items() if key in allowed}
    response = request_json("PUT", f"{settings.kibana_url}/api/detection_engine/rules", json=payload, headers={"kbn-xsrf": "true", "Content-Type": "application/json"}, expected=(200,))
    return {"rule_id": rule_id, "revision": response.get("revision"), "restored_query": response.get("query")}


def verify_alert(rule_id: str, timeout_seconds: int = 120, *, after: str | None = None, event_uid: str | None = None) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    filters: list[dict[str, Any]] = [{"term": {"kibana.alert.rule.rule_id": rule_id}}]
    if after:
        filters.append({"range": {"@timestamp": {"gte": after}}})
    if event_uid:
        filters.append({"term": {"lab.event_uid": event_uid}})
    body = {"size": 20, "query": {"bool": {"filter": filters}}, "sort": [{"@timestamp": "desc"}]}
    while time.time() < deadline:
        try:
            response = request_json("POST", f"{settings.elastic_url}/.alerts-security.alerts-default/_search", json=body, expected=(200, 404))
            hits = response.get("hits", {}).get("hits", [])
            if hits:
                return {"verified": True, "count": len(hits), "alerts": [hit.get("_source", {}) for hit in hits[:5]]}
        except ServiceError:
            pass
        time.sleep(5)
    return {"verified": False, "count": 0, "reason": f"No matching fresh alert found within {timeout_seconds} seconds."}
