from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st
import yaml

from detection_lab.config import settings
from detection_lab.elastic import (
    bulk_index,
    dataset_stats,
    deploy_rule,
    evaluate_rule,
    fixture_target_scenarios,
    list_alerts,
    list_deployed_rules,
    ollama_status,
    read_ndjson,
    replay_event,
    rollback_rule,
    search_events,
    status,
    test_rule,
    verify_alert,
)
from detection_lab.llm import create_detection_design, create_research_brief, draft_sigma_rule
from detection_lab.quality import validate_design, validate_rule
from detection_lab.sigma_tools import convert_to_lucene, extract_query
from portal.theme import apply_theme, status_line, step_card
from scripts.generate_telemetry import generate


st.set_page_config(page_title="Detection Engineering Workbench", page_icon="◈", layout="wide", initial_sidebar_state="expanded")
apply_theme()

ROOT = settings.root
WORKSPACE = ROOT / "workspace"
REPORTS = ROOT / "reports"
WORKSPACE.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)

PAGES = [
    "00  Range Overview",
    "01  Detection Research",
    "02  Detection Design",
    "03  Sigma Workbench",
    "04  Test and Tune",
    "05  Telemetry Explorer",
    "06  Deploy and Verify",
    "07  Capstone",
]


def _read(path: Path, default: str = "") -> str:
    return path.read_text(encoding="utf-8") if path.exists() else default


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _rule_options() -> list[Path]:
    options = list((WORKSPACE).glob("*.yml")) + list((WORKSPACE).glob("*.yaml"))
    options += list((ROOT / "rules/validated").glob("*.yml"))
    return sorted(set(options), key=lambda item: str(item))


def _design_options() -> list[Path]:
    return sorted(WORKSPACE.glob("*_design.json"))


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _fixture_dir(rule: Path) -> Path | None:
    stem = rule.stem
    candidates = [ROOT / "tests/fixtures" / stem]
    if "encoded_powershell" in stem:
        candidates.append(ROOT / "tests/fixtures/encoded_powershell")
    for candidate in candidates:
        if (candidate / "positive").is_dir() and (candidate / "negative").is_dir():
            return candidate
    return None


def _flatten_event(event: dict[str, Any]) -> dict[str, Any]:
    process = event.get("process", {})
    return {
        "timestamp": event.get("@timestamp", ""),
        "category": event.get("event", {}).get("category", ""),
        "event_id": event.get("winlog", {}).get("event_id", ""),
        "host": event.get("host", {}).get("name", ""),
        "user": event.get("user", {}).get("name", ""),
        "process": process.get("name", ""),
        "parent": process.get("parent", {}).get("name", ""),
        "command_line": process.get("command_line", ""),
        "destination": event.get("destination", {}).get("ip", ""),
        "file": event.get("file", {}).get("path", ""),
        "registry": event.get("registry", {}).get("path", ""),
        "scenario": event.get("lab", {}).get("scenario", ""),
        "malicious": event.get("lab", {}).get("malicious", False),
        "expected": event.get("lab", {}).get("expected", False),
        "event_uid": event.get("lab", {}).get("event_uid", ""),
    }


def _metric_row(report: dict[str, Any]) -> None:
    cols = st.columns(6)
    cols[0].metric("True positives", report.get("tp", 0))
    cols[1].metric("False positives", report.get("fp", 0))
    cols[2].metric("False negatives", report.get("fn", 0))
    cols[3].metric("True negatives", report.get("tn", 0))
    cols[4].metric("Precision", report.get("precision", 0))
    cols[5].metric("Recall", report.get("recall", 0))


def _llm_readiness() -> dict[str, Any]:
    state = ollama_status()
    if state["model_ready"]:
        st.success(f"LLM ready: {state['configured_model']}")
    elif state["api_ready"]:
        st.warning(f"Model initialization in progress: {state['configured_model']}")
        st.caption("The non LLM parts of the range are ready. Check progress with `docker compose logs -f ollama-init`.")
    else:
        st.error("Ollama API is not ready.")
        st.caption("Check the service with `docker compose logs ollama`.")
    return state


with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="brand-kicker">AI SecOps Bootcamp</div><div class="brand-title">Detection Engineering Workbench</div><div class="brand-meta">SIGMA / ELASTIC / OLLAMA / DAC</div></div>',
        unsafe_allow_html=True,
    )
    page = st.radio("Lab workflow", PAGES, label_visibility="collapsed")
    st.divider()
    st.link_button("Open Kibana", "http://localhost:5601", use_container_width=True)
    st.link_button("Open detection.fyi", "https://detection.fyi/", use_container_width=True)
    st.caption("All generated designs, rules, and reports are saved under the project workspace.")

status_line()


def overview_page() -> None:
    st.title("Detection Engineering Range")
    st.caption("One browser workflow backed by real local services and versionable artifacts.")
    try:
        service = status()
        stats = dataset_stats()
    except Exception as exc:
        st.error(f"The range is not ready: {exc}")
        st.info("Wait for the Docker initializer services to finish, then refresh this page.")
        return

    a, b, c, d = st.columns(4)
    a.metric("Elasticsearch", service["elasticsearch"]["status"])
    b.metric("Kibana", service["kibana"]["status"])
    c.metric("LLM model", "ready" if service["ollama"]["model_ready"] else "initializing")
    d.metric("Indexed events", stats["total"])

    st.markdown("### Operational workflow")
    cols = st.columns(4)
    cards = [
        ("01", "Research", "Compare real public detections and record reusable behavior."),
        ("02", "Design", "Ground the LLM in the scenario, ECS schema, and research evidence."),
        ("03", "Build and test", "Draft Sigma, run deterministic gates, convert, and execute."),
        ("04", "Deploy", "Create a Kibana rule, replay telemetry, verify an alert, and roll back."),
    ]
    for col, card in zip(cols, cards):
        with col:
            step_card(*card)

    st.markdown("### Dataset snapshot")
    e, f, g = st.columns(3)
    e.metric("Benign and background events", stats["total"] - stats["malicious"])
    f.metric("Malicious chain events", stats["malicious"])
    g.metric("Target ground-truth matches", stats["expected"])
    st.bar_chart(stats["categories"])

    with st.expander("Service details"):
        st.json(service)

    if st.button("Regenerate and reindex dataset", type="primary"):
        with st.spinner("Generating correlated telemetry and loading Elasticsearch..."):
            dataset = ROOT / "datasets/generated/production_simulation.ndjson"
            generated = generate(dataset)
            indexed = bulk_index(settings.lab_index, read_ndjson([dataset]), recreate=True)
        st.success(f"Indexed {indexed['indexed']} events. Malicious chain events: {generated['malicious']}.")


def research_page() -> None:
    st.title("Lab 4.1: Detection Research")
    st.caption("Use the LLM to compare analyst supplied research evidence, expose assumptions, and form testable hypotheses.")
    model = _llm_readiness()
    scenarios = sorted((ROOT / "scenarios").glob("*.yml"))
    scenario = st.selectbox("Research scenario", scenarios, format_func=lambda item: item.stem.replace("_", " ").title())
    refs = yaml.safe_load(_read(ROOT / "references/detections_fyi_research.yml"))
    with st.expander("Starter sources and links", expanded=True):
        for number, rule in enumerate(refs.get("rules", []), 1):
            st.markdown(f"**{number}. {rule['title']}**")
            if rule.get("original_repository"):
                c1, c2 = st.columns(2)
                c1.link_button("View on detection.fyi", rule["source_url"], use_container_width=True)
                c2.link_button("View original repository", rule["original_repository"], use_container_width=True)
            else:
                st.link_button("View on detection.fyi", rule["source_url"], use_container_width=True)

    starter = "\n\n".join(
        f"Source: {rule['source_url']}\nTitle: {rule['title']}\nAnalyst observations:\n"
        for rule in refs.get("rules", [])
    )
    source_notes = st.text_area(
        "Source notes for LLM analysis",
        st.session_state.get("research_sources", starter),
        height=300,
        help="Replace the starter content or add your own detection.fyi findings. Include evidence from the original rule source.",
    )
    brief_path = WORKSPACE / f"{scenario.stem}_research.json"
    if st.button("Generate evidence grounded research brief", type="primary", disabled=not model["model_ready"], use_container_width=True):
        try:
            with st.spinner("The LLM is comparing source evidence and forming test hypotheses..."):
                brief = create_research_brief(scenario, source_notes, brief_path)
            st.session_state["research_brief"] = json.dumps(brief, indent=2)
            st.success(f"Generated {_relative(brief_path)}")
        except Exception as exc:
            st.error(str(exc))

    brief_text = st.text_area(
        "Editable research brief",
        st.session_state.get("research_brief", _read(brief_path, "{}")),
        height=520,
    )
    if st.button("Save reviewed research brief"):
        try:
            parsed = json.loads(brief_text)
            _write(brief_path, json.dumps(parsed, indent=2))
            st.success(f"Saved {_relative(brief_path)}")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")


def design_page() -> None:
    st.title("Lab 4.2: Schema-Aware Detection Design")
    model = _llm_readiness()
    scenarios = sorted((ROOT / "scenarios").glob("*.yml"))
    scenario = st.selectbox("Scenario", scenarios, format_func=lambda item: item.stem.replace("_", " ").title())
    scenario_data = yaml.safe_load(_read(scenario))
    left, right = st.columns([1, 1])
    with left:
        st.markdown("### Scenario evidence")
        st.json(scenario_data)
    with right:
        st.markdown("### Available ECS fields")
        ecs = json.loads(_read(ROOT / "schemas/ecs_fields.json"))
        st.code("\n".join(ecs["fields"]), language="text")

    design_path = WORKSPACE / f"{scenario.stem}_design.json"
    research_path = WORKSPACE / f"{scenario.stem}_research.json"
    if research_path.exists():
        st.info(f"The design prompt will use the reviewed research artifact: {_relative(research_path)}")
    else:
        st.warning("No reviewed research artifact was found. Complete Detection Research first for a grounded design.")
    if st.button("Generate structured design with Ollama", type="primary", disabled=not model["model_ready"] or not research_path.exists(), use_container_width=True):
        with st.spinner("Ollama is reasoning over the scenario, schema, and research metadata..."):
            design = create_detection_design(scenario, design_path, research_path)
        st.session_state["design_editor"] = json.dumps(design, indent=2)
        st.success(f"Generated {_relative(design_path)}")

    current = st.session_state.get("design_editor", _read(design_path, "{}"))
    edited = st.text_area("Editable detection design", current, height=520, key="design_textarea")
    c1, c2 = st.columns(2)
    if c1.button("Save design", use_container_width=True):
        try:
            parsed = json.loads(edited)
            _write(design_path, json.dumps(parsed, indent=2))
            st.success(f"Saved {_relative(design_path)}")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")
    if c2.button("Validate design schema", use_container_width=True):
        try:
            parsed = json.loads(edited)
            _write(design_path, json.dumps(parsed, indent=2))
            errors = validate_design(design_path)
            if errors:
                for error in errors:
                    st.error(error)
            else:
                st.success("Design schema passed. Review assumptions before drafting Sigma.")
        except Exception as exc:
            st.error(str(exc))


def sigma_page() -> None:
    st.title("Lab 4.3 and 4.4: Sigma Workbench")
    model = _llm_readiness()
    designs = _design_options()
    if not designs:
        st.warning("Create and save a detection design first.")
        return
    design = st.selectbox("Approved design", designs, format_func=_relative)
    draft_path = WORKSPACE / design.name.replace("_design.json", ".yml")

    c1, c2 = st.columns(2)
    if c1.button("Draft Sigma with Ollama", type="primary", disabled=not model["model_ready"], use_container_width=True):
        with st.spinner("Generating a portable Sigma change proposal..."):
            draft_sigma_rule(design, draft_path)
        st.session_state["sigma_editor"] = _read(draft_path)
        st.success(f"Generated {_relative(draft_path)}")
    if c2.button("Load validated comparison rule", use_container_width=True):
        st.session_state["sigma_editor"] = _read(ROOT / "rules/validated/encoded_powershell.yml")

    current = st.session_state.get("sigma_editor", _read(draft_path))
    rule_text = st.text_area("Editable Sigma YAML", current, height=540, key="sigma_textarea")
    if st.button("Save Sigma draft"):
        try:
            yaml.safe_load(rule_text)
            _write(draft_path, rule_text)
            st.success(f"Saved {_relative(draft_path)}")
        except yaml.YAMLError as exc:
            st.error(f"Invalid YAML: {exc}")

    st.markdown("### Quality gates and conversion")
    g1, g2 = st.columns(2)
    if g1.button("Run deterministic gates", use_container_width=True):
        try:
            _write(draft_path, rule_text)
            report = validate_rule(draft_path, ROOT / "tests/fixtures/encoded_powershell")
            st.session_state["quality_report"] = report.to_dict()
            _write(REPORTS / "gui_quality_report.json", json.dumps(report.to_dict(), indent=2))
        except Exception as exc:
            st.error(str(exc))
    if g2.button("Convert with pySigma", use_container_width=True):
        try:
            _write(draft_path, rule_text)
            query = extract_query(convert_to_lucene(draft_path))
            st.session_state["converted_query"] = query
            _write(REPORTS / "gui_converted_query.txt", query)
        except Exception as exc:
            st.error(str(exc))

    report = st.session_state.get("quality_report")
    if report:
        passed = sum(1 for gate in report["gates"] if gate["passed"])
        st.metric("Gates passed", f"{passed} / {len(report['gates'])}")
        for gate in report["gates"]:
            icon = "PASS" if gate["passed"] else "FAIL"
            with st.expander(f"{icon}  {gate['name']}"):
                st.code(gate["details"], language="text")
    if st.session_state.get("converted_query"):
        st.markdown("**Generated ECS Lucene query**")
        st.code(st.session_state["converted_query"], language="text")


def test_page() -> None:
    st.title("Lab 4.5 and 4.6: Test and Tune")
    options = _rule_options()
    if not options:
        st.warning("No Sigma rules are available.")
        return
    rule = st.selectbox("Rule under test", options, format_func=_relative)
    fixtures = _fixture_dir(rule)
    if fixtures is None:
        st.warning(f"Create positive and negative fixtures under tests/fixtures/{rule.stem} before testing this rule.")
        return
    st.caption("Tests run in temporary Elasticsearch indexes. The full evaluation runs against the complete production-style dataset.")
    c1, c2 = st.columns(2)
    if c1.button("Run regression fixtures", type="primary", use_container_width=True):
        with st.spinner("Converting Sigma and executing positive and negative fixtures..."):
            try:
                result = test_rule(rule, fixtures)
                st.session_state["fixture_result"] = result
                _write(REPORTS / "gui_fixture_report.json", json.dumps(result, indent=2))
            except Exception as exc:
                st.error(str(exc))
    if c2.button("Evaluate complete dataset", use_container_width=True):
        with st.spinner("Executing the converted query against the full telemetry index..."):
            try:
                result = evaluate_rule(rule, target_scenarios=fixture_target_scenarios(fixtures))
                st.session_state["dataset_result"] = result
                _write(REPORTS / "gui_dataset_report.json", json.dumps(result, indent=2))
            except Exception as exc:
                st.error(str(exc))

    tabs = st.tabs(["Regression fixtures", "Complete dataset"])
    with tabs[0]:
        result = st.session_state.get("fixture_result")
        if result:
            _metric_row(result)
            st.success("Regression passed.") if result["passed"] else st.error("Regression failed. Tune the rule from evidence.")
            st.code(result["query"], language="text")
            st.json({"matched_ids": result["matched_ids"]})
        else:
            st.info("Run the fixture test to produce evidence.")
    with tabs[1]:
        result = st.session_state.get("dataset_result")
        if result:
            _metric_row(result)
            st.success("Dataset evaluation passed.") if result["passed"] else st.error("Dataset evaluation found false positives or false negatives.")
            st.json({"events": result["events"], "matched_ids": result["matched_ids"]})
        else:
            st.info("Run the full dataset evaluation to produce evidence.")


def telemetry_page() -> None:
    st.title("Telemetry Explorer")
    try:
        stats = dataset_stats()
    except Exception as exc:
        st.error(f"Elasticsearch telemetry is not ready: {exc}")
        st.info("Check `docker compose logs telemetry-init`, then refresh this page.")
        return
    a, b, c = st.columns(3)
    a.metric("Events", stats["total"])
    b.metric("Malicious chain", stats["malicious"])
    c.metric("Target matches", stats["expected"])

    categories = [""] + list(stats["categories"])
    scenarios = [""] + list(stats["scenarios"])
    f1, f2, f3, f4 = st.columns(4)
    category = f1.selectbox("Category", categories, format_func=lambda value: value or "All")
    scenario = f2.selectbox("Scenario", scenarios, format_func=lambda value: value or "All")
    truth = f3.selectbox("Ground truth", ["All", "Malicious", "Benign"])
    text = f4.text_input("Search telemetry", placeholder="powershell, host, IP, path")
    malicious = True if truth == "Malicious" else False if truth == "Benign" else None
    events = search_events(category=category or None, scenario=scenario or None, malicious=malicious, text=text or None, size=250)
    rows = [_flatten_event(event) for event in events]
    st.dataframe(rows, use_container_width=True, hide_index=True, height=520)
    st.caption(f"Showing {len(rows)} events from Elasticsearch.")

    with st.expander("Attack timeline"):
        attack = search_events(malicious=True, size=100)
        for event in reversed(attack):
            row = _flatten_event(event)
            detail = row["command_line"] or row["destination"] or row["file"] or row["registry"]
            st.markdown(f"`{row['timestamp']}` **{row['category']}** on `{row['host']}`")
            st.code(str(detail), language="text")


def deploy_page() -> None:
    st.title("Lab 4.7: Deploy, Alert, and Roll Back")
    options = _rule_options()
    if not options:
        st.warning("No Sigma rules are available.")
        return
    rule = st.selectbox("Validated rule", options, format_func=_relative)
    fixtures_path = _fixture_dir(rule)
    positives = sorted((fixtures_path / "positive").glob("*.json")) if fixtures_path else []
    replay_path = st.selectbox("Replay event", positives, format_func=_relative) if positives else None
    if fixtures_path is None:
        st.warning(f"Deployment is blocked until tests/fixtures/{rule.stem} contains positive and negative evidence.")
    c1, c2 = st.columns(2)
    if c1.button("Deploy through Kibana API", type="primary", disabled=fixtures_path is None, use_container_width=True):
        with st.spinner("Converting and deploying the rule..."):
            try:
                quality = validate_rule(rule, fixtures_path)
                if not quality.passed:
                    st.error("Deployment blocked because quality gates failed.")
                else:
                    fixtures = test_rule(rule, fixtures_path)
                    dataset = evaluate_rule(rule, target_scenarios=fixture_target_scenarios(fixtures_path))
                    if not fixtures["passed"] or not dataset["passed"]:
                        st.error("Deployment blocked because tests failed.")
                    else:
                        result = deploy_rule(rule, enabled=True)
                        st.session_state["deployment"] = result
                        st.session_state["active_rule_id"] = result["rule_id"]
                        st.success(f"Rule {result['action']}. Revision: {result['revision']}")
            except Exception as exc:
                st.error(str(exc))
    if c2.button("Replay fresh malicious event", disabled=replay_path is None, use_container_width=True):
        try:
            result = replay_event(replay_path)
            st.session_state["replay"] = result
            st.success(f"Replayed {result['event_uid']} at {result['timestamp']}")
        except Exception as exc:
            st.error(str(exc))

    st.markdown("### Alert verification")
    default_id = st.session_state.get("active_rule_id", "3ba9a8fd-8485-4f99-bda8-5f70c302286f")
    rule_id = st.text_input("Rule ID", default_id)
    timeout = st.slider("Wait time in seconds", 30, 240, 120, 30)
    c3, c4 = st.columns(2)
    if c3.button("Wait for real alert", use_container_width=True):
        with st.spinner("Waiting for the Kibana detection schedule..."):
            replay = st.session_state.get("replay", {})
            result = verify_alert(rule_id, timeout, after=replay.get("timestamp"), event_uid=replay.get("event_uid"))
        st.session_state["alert_result"] = result
        if result["verified"]:
            st.success(f"Verified {result['count']} alert record(s).")
        else:
            st.error(result["reason"])
    if c4.button("Roll back previous revision", use_container_width=True):
        try:
            result = rollback_rule(rule_id)
            st.success(f"Restored revision {result['revision']}")
            st.code(result["restored_query"], language="text")
        except Exception as exc:
            st.error(str(exc))

    st.markdown("### Deployed rules")
    try:
        rules = list_deployed_rules()
        st.dataframe([
            {"name": item.get("name"), "rule_id": item.get("rule_id"), "enabled": item.get("enabled"), "revision": item.get("revision"), "severity": item.get("severity"), "last_response": item.get("execution_summary", {}).get("last_execution", {}).get("status")}
            for item in rules
        ], use_container_width=True, hide_index=True)
    except Exception as exc:
        st.warning(f"Could not list rules: {exc}")

    st.markdown("### Recent alerts")
    try:
        alerts = list_alerts()
        st.dataframe([
            {"timestamp": item.get("@timestamp"), "rule": item.get("kibana.alert.rule.name"), "severity": item.get("kibana.alert.severity"), "host": item.get("host", {}).get("name"), "user": item.get("user", {}).get("name"), "status": item.get("kibana.alert.workflow_status")}
            for item in alerts
        ], use_container_width=True, hide_index=True)
    except Exception as exc:
        st.info(f"No alert index is available yet: {exc}")


def capstone_page() -> None:
    st.title("Lab 4.8: Capstone")
    st.caption("Build a new WMIC security-tool tampering detection through the complete lifecycle.")
    scenario = yaml.safe_load(_read(ROOT / "scenarios/wmic_security_tool_tampering.yml"))
    st.json(scenario)
    st.markdown(_read(ROOT / "labs/LAB_4_8_CAPSTONE.md"))
    st.info("Use the Research, Design, Sigma, Test, Telemetry, and Deployment pages to complete the capstone. Your artifacts remain visible throughout the workbench.")


ROUTES = {
    PAGES[0]: overview_page,
    PAGES[1]: research_page,
    PAGES[2]: design_page,
    PAGES[3]: sigma_page,
    PAGES[4]: test_page,
    PAGES[5]: telemetry_page,
    PAGES[6]: deploy_page,
    PAGES[7]: capstone_page,
}

ROUTES[page]()
