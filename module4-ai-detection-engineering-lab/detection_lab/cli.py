from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from detection_lab.config import settings


def _path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else settings.root / path


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab", description="AI assisted Detection-as-Code operational lab")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", help="Check Elasticsearch, Kibana, Ollama, and the lab index")

    research = sub.add_parser("research", help="Generate a grounded research brief with Ollama")
    research.add_argument("--scenario", required=True)
    research.add_argument("--notes", required=True)
    research.add_argument("--output", default="workspace/detection_research.json")

    design = sub.add_parser("design", help="Generate a structured detection design with Ollama")
    design.add_argument("--scenario", required=True)
    design.add_argument("--research")
    design.add_argument("--output", default="workspace/detection_design.json")

    draft = sub.add_parser("draft", help="Draft a Sigma rule from an approved design")
    draft.add_argument("--design", required=True)
    draft.add_argument("--output", default="workspace/draft_rule.yml")

    validate = sub.add_parser("validate", help="Run deterministic quality gates")
    validate.add_argument("--rule", required=True)
    validate.add_argument("--fixtures", default="tests/fixtures/encoded_powershell")
    validate.add_argument("--report", default="reports/quality_report.json")

    convert = sub.add_parser("convert", help="Convert Sigma to Lucene using pySigma")
    convert.add_argument("--rule", required=True)
    convert.add_argument("--output", default="reports/converted_query.txt")

    ingest = sub.add_parser("ingest", help="Ingest NDJSON telemetry into Elasticsearch")
    ingest.add_argument("paths", nargs="+")
    ingest.add_argument("--index", default=None)
    ingest.add_argument("--recreate", action="store_true")

    evtx = sub.add_parser("import-evtx", help="Convert authorized Sysmon EVTX into ECS and ingest it")
    evtx.add_argument("path")
    evtx.add_argument("--index", default="lab-security-events-evtx")
    evtx.add_argument("--recreate", action="store_true")

    test = sub.add_parser("test", help="Execute the converted rule against positive and negative fixtures in Elasticsearch")
    test.add_argument("--rule", required=True)
    test.add_argument("--fixtures", default="tests/fixtures/encoded_powershell")
    test.add_argument("--report", default="reports/test_report.json")

    evaluate = sub.add_parser("evaluate", help="Execute a rule against the complete production-style dataset")
    evaluate.add_argument("--rule", required=True)
    evaluate.add_argument("--index", default=None)
    evaluate.add_argument("--scenario", action="append", dest="scenarios")
    evaluate.add_argument("--report", default="reports/dataset_evaluation.json")

    replay = sub.add_parser("replay", help="Replay a fixture with a fresh timestamp for alert verification")
    replay.add_argument("--event", required=True)
    replay.add_argument("--index", default=None)

    deploy = sub.add_parser("deploy", help="Create or update a Kibana detection rule")
    deploy.add_argument("--rule", required=True)
    deploy.add_argument("--disabled", action="store_true")

    verify = sub.add_parser("verify-alert", help="Wait for an alert from a deployed rule")
    verify.add_argument("--rule-id", required=True)
    verify.add_argument("--timeout", type=int, default=120)
    verify.add_argument("--after")
    verify.add_argument("--event-uid")

    rollback = sub.add_parser("rollback", help="Restore the last recorded deployed version")
    rollback.add_argument("--rule-id", required=True)

    audit = sub.add_parser("audit", help="Check prohibited punctuation, wording, and project content")
    audit.add_argument("--root", default=".")

    pipeline = sub.add_parser("pipeline", help="Run validation, conversion, and live fixture tests")
    pipeline.add_argument("--rule", required=True)
    pipeline.add_argument("--fixtures", default="tests/fixtures/encoded_powershell")
    pipeline.add_argument("--deploy", action="store_true")

    acceptance = sub.add_parser("acceptance", help="Exercise validation, testing, deployment, alerting, and rollback")
    acceptance.add_argument("--rule", default="rules/validated/encoded_powershell.yml")
    acceptance.add_argument("--fixtures", default="tests/fixtures/encoded_powershell")
    acceptance.add_argument("--event", default="tests/fixtures/encoded_powershell/positive/word_spawn.json")
    acceptance.add_argument("--timeout", type=int, default=180)
    acceptance.add_argument("--report", default="reports/acceptance_report.json")
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    try:
        if args.command == "status":
            from detection_lab.elastic import status
            _print(status())
        elif args.command == "research":
            from detection_lab.llm import create_research_brief
            notes = _path(args.notes).read_text(encoding="utf-8")
            _print(create_research_brief(_path(args.scenario), notes, _path(args.output)))
        elif args.command == "design":
            from detection_lab.llm import create_detection_design
            research = _path(args.research) if args.research else None
            _print(create_detection_design(_path(args.scenario), _path(args.output), research))
        elif args.command == "draft":
            from detection_lab.llm import draft_sigma_rule
            draft_sigma_rule(_path(args.design), _path(args.output))
            _print({"created": str(_path(args.output))})
        elif args.command == "validate":
            from detection_lab.quality import validate_rule
            report = validate_rule(_path(args.rule), _path(args.fixtures))
            output = _path(args.report)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
            _print(report.to_dict())
            if not report.passed:
                raise SystemExit(2)
        elif args.command == "convert":
            from detection_lab.sigma_tools import convert_to_lucene, extract_query
            result = convert_to_lucene(_path(args.rule))
            query = extract_query(result)
            output = _path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(query + "\n", encoding="utf-8")
            _print({"query": query, "output": str(output)})
        elif args.command == "ingest":
            from detection_lab.elastic import bulk_index, read_ndjson
            events = read_ndjson([_path(path) for path in args.paths])
            _print(bulk_index(args.index or settings.lab_index, events, args.recreate))
        elif args.command == "import-evtx":
            from detection_lab.elastic import bulk_index
            from detection_lab.evtx_import import import_evtx
            events = import_evtx(_path(args.path))
            _print({**bulk_index(args.index, events, args.recreate), "source": str(_path(args.path))})
        elif args.command == "test":
            from detection_lab.elastic import test_rule
            report = test_rule(_path(args.rule), _path(args.fixtures))
            output = _path(args.report)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            _print(report)
            if not report["passed"]:
                raise SystemExit(3)
        elif args.command == "evaluate":
            from detection_lab.elastic import evaluate_rule
            report = evaluate_rule(_path(args.rule), args.index, args.scenarios)
            output = _path(args.report)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            _print(report)
            if not report["passed"]:
                raise SystemExit(3)
        elif args.command == "replay":
            from detection_lab.elastic import replay_event
            _print(replay_event(_path(args.event), args.index))
        elif args.command == "deploy":
            from detection_lab.elastic import deploy_rule
            _print(deploy_rule(_path(args.rule), enabled=not args.disabled))
        elif args.command == "verify-alert":
            from detection_lab.elastic import verify_alert
            report = verify_alert(args.rule_id, args.timeout, after=args.after, event_uid=args.event_uid)
            _print(report)
            if not report["verified"]:
                raise SystemExit(4)
        elif args.command == "rollback":
            from detection_lab.elastic import rollback_rule
            _print(rollback_rule(args.rule_id))
        elif args.command == "audit":
            from detection_lab.quality import audit_content
            violations = audit_content(_path(args.root))
            _print({"passed": not violations, "violations": violations})
            if violations:
                raise SystemExit(5)
        elif args.command == "pipeline":
            from detection_lab.elastic import deploy_rule, evaluate_rule, fixture_target_scenarios, test_rule
            from detection_lab.quality import validate_rule
            from detection_lab.sigma_tools import convert_to_lucene, extract_query
            rule = _path(args.rule)
            fixtures = _path(args.fixtures)
            quality = validate_rule(rule, fixtures)
            if not quality.passed:
                _print({"stage": "quality", **quality.to_dict()})
                raise SystemExit(2)
            query = extract_query(convert_to_lucene(rule))
            tests = test_rule(rule, fixtures)
            dataset = evaluate_rule(rule, target_scenarios=fixture_target_scenarios(fixtures))
            result: dict[str, Any] = {"quality": quality.to_dict(), "conversion": {"query": query}, "fixture_tests": tests, "dataset_evaluation": dataset}
            if not tests["passed"]:
                _print(result)
                raise SystemExit(3)
            if not dataset["passed"]:
                _print(result)
                raise SystemExit(3)
            if args.deploy:
                result["deployment"] = deploy_rule(rule, enabled=True)
            _print(result)
        elif args.command == "acceptance":
            import tempfile
            import yaml
            from detection_lab.elastic import deploy_rule, evaluate_rule, fixture_target_scenarios, replay_event, rollback_rule, test_rule, verify_alert
            from detection_lab.quality import validate_rule
            from detection_lab.sigma_tools import convert_to_lucene, extract_query
            rule = _path(args.rule)
            fixtures = _path(args.fixtures)
            quality = validate_rule(rule, fixtures)
            if not quality.passed:
                _print({"stage": "quality", **quality.to_dict()})
                raise SystemExit(2)
            query = extract_query(convert_to_lucene(rule))
            fixture_report = test_rule(rule, fixtures)
            dataset_report = evaluate_rule(rule, target_scenarios=fixture_target_scenarios(fixtures))
            if not fixture_report["passed"] or not dataset_report["passed"]:
                _print({"fixture_tests": fixture_report, "dataset_evaluation": dataset_report})
                raise SystemExit(3)
            first_deploy = deploy_rule(rule, enabled=True)
            replay = replay_event(_path(args.event))
            alert = verify_alert(first_deploy["rule_id"], args.timeout, after=replay["timestamp"], event_uid=replay["event_uid"])
            if not alert["verified"]:
                _print({"stage": "alert_verification", "deployment": first_deploy, "replay": replay, "alert": alert})
                raise SystemExit(4)
            changed = yaml.safe_load(rule.read_text(encoding="utf-8"))
            changed["description"] = str(changed["description"]) + " Acceptance revision."
            with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
                yaml.safe_dump(changed, handle, sort_keys=False)
                revision_path = Path(handle.name)
            second_deploy = deploy_rule(revision_path, enabled=True)
            rollback = rollback_rule(first_deploy["rule_id"])
            result = {
                "passed": True, "quality": quality.to_dict(), "conversion": {"query": query},
                "fixture_tests": fixture_report, "dataset_evaluation": dataset_report,
                "first_deployment": first_deploy, "replay": replay,
                "alert_verification": {"verified": True, "count": alert["count"]},
                "second_deployment": second_deploy, "rollback": rollback,
            }
            output = _path(args.report)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            _print(result)
    except SystemExit:
        raise
    except Exception as exc:
        _print({"error": str(exc), "command": args.command})
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
