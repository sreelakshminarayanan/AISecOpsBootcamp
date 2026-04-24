import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from rich import print


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

DEFAULT_MAPPING_CSV = OUTPUT_DIR / "lab2_2_latest_attack_mapping.csv"
DEFAULT_METADATA_JSON = OUTPUT_DIR / "attack_enterprise_metadata.json"

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

CONFIDENCE_SCORE = {
    "high": 100,
    "medium": 70,
    "low": 35,
}

CONFIDENCE_COLOR = {
    "high": "#d73027",
    "medium": "#fc8d59",
    "low": "#fee08b",
}

DEFAULT_GRADIENT = {
    "colors": [
        "#fff7bc",
        "#fec44f",
        "#d95f0e",
    ],
    "minValue": 0,
    "maxValue": 100,
}

ENTERPRISE_PLATFORM_FILTERS = [
    "PRE",
    "Windows",
    "Linux",
    "macOS",
    "Network",
    "AWS",
    "GCP",
    "Azure",
    "Azure AD",
    "Office 365",
    "SaaS",
]


def normalize_text(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def read_json_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_mapping_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Mapping CSV not found: {path}")

    try:
        df = pd.read_csv(path)
    except Exception as exc:
        raise RuntimeError(f"Failed to read mapping CSV: {path}. Error: {exc}") from exc

    required_columns = ["attack_id", "name", "tactics", "confidence"]

    missing = [column for column in required_columns if column not in df.columns]

    if missing:
        raise RuntimeError(f"Mapping CSV is missing required columns: {missing}")

    if df.empty:
        raise RuntimeError(
            "Mapping CSV is empty. Generate ATT&CK mappings first or approve at least one mapping."
        )

    df["attack_id"] = df["attack_id"].astype(str).str.upper().str.strip()
    df["confidence"] = df["confidence"].astype(str).str.lower().str.strip()

    valid_mask = df["attack_id"].apply(lambda value: bool(TECHNIQUE_ID_REGEX.match(value)))
    df = df[valid_mask].copy()

    if df.empty:
        raise RuntimeError("No valid ATT&CK technique IDs found in mapping CSV.")

    if "disposition" in df.columns:
        df = df[df["disposition"].astype(str).str.lower().str.strip() == "final"].copy()

    if df.empty:
        raise RuntimeError("No final mappings found in mapping CSV.")

    return df


def get_layer_domain(domain: str) -> str:
    normalized = domain.strip().lower()

    if normalized in {"enterprise", "enterprise-attack", "mitre-enterprise"}:
        return "enterprise-attack"

    if normalized in {"mobile", "mobile-attack"}:
        return "mobile-attack"

    if normalized in {"ics", "ics-attack"}:
        return "ics-attack"

    return normalized or "enterprise-attack"


def confidence_to_score(confidence: str) -> int:
    return CONFIDENCE_SCORE.get(confidence.lower().strip(), 50)


def confidence_to_color(confidence: str) -> str:
    return CONFIDENCE_COLOR.get(confidence.lower().strip(), "#91bfdb")


def build_comment(row: pd.Series) -> str:
    name = normalize_text(row.get("name"))
    confidence = normalize_text(row.get("confidence"))
    evidence = normalize_text(row.get("evidence"))
    rationale = normalize_text(row.get("rationale"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources"))
    validation_status = normalize_text(row.get("validation_status"))

    comment_parts = [
        f"Name: {name}" if name else "",
        f"Confidence: {confidence}" if confidence else "",
        f"Validation: {validation_status}" if validation_status else "",
        f"Evidence: {evidence}" if evidence else "",
        f"Rationale: {rationale}" if rationale else "",
        f"Hunting focus: {hunting_focus}" if hunting_focus else "",
        f"Suggested log sources: {log_sources}" if log_sources else "",
    ]

    comment = "\n".join(part for part in comment_parts if part)

    return comment[:4000]


def parse_tactics(tactics_raw: str) -> list[str]:
    tactics = [
        item.strip()
        for item in re.split(r"[;,]", normalize_text(tactics_raw))
        if item.strip()
    ]

    normalized = []

    for tactic in tactics:
        normalized_tactic = tactic.lower().replace(" ", "-")
        normalized.append(normalized_tactic)

    return sorted(set(normalized))


def build_technique_entry(row: pd.Series) -> dict[str, Any]:
    attack_id = normalize_text(row.get("attack_id")).upper()
    confidence = normalize_text(row.get("confidence")).lower()
    tactic_values = parse_tactics(normalize_text(row.get("tactics")))

    entry = {
        "techniqueID": attack_id,
        "score": confidence_to_score(confidence),
        "color": confidence_to_color(confidence),
        "comment": build_comment(row),
        "enabled": True,
        "metadata": [
            {
                "name": "Confidence",
                "value": confidence or "unknown",
            },
            {
                "name": "Source",
                "value": "Lab 2.2 AI-assisted ATT&CK mapping",
            },
        ],
        "links": [],
    }

    url = normalize_text(row.get("url"))

    if url:
        entry["links"].append(
            {
                "label": "MITRE ATT&CK",
                "url": url,
            }
        )

    # Do not force tactic on sub-techniques. Navigator can display sub-techniques
    # under the correct parent when expandedSubtechniques is annotated.
    if tactic_values and "." not in attack_id:
        entry["tactic"] = tactic_values[0]

    return entry


def dedupe_techniques(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_id: dict[str, dict[str, Any]] = {}

    for entry in entries:
        technique_id = entry["techniqueID"]
        existing = best_by_id.get(technique_id)

        if existing is None:
            best_by_id[technique_id] = entry
            continue

        if entry.get("score", 0) > existing.get("score", 0):
            best_by_id[technique_id] = entry
        else:
            existing_comment = existing.get("comment", "")
            new_comment = entry.get("comment", "")

            if new_comment and new_comment not in existing_comment:
                existing["comment"] = (existing_comment + "\n\nAdditional mapping:\n" + new_comment)[:4000]

    parent_ids_to_expand = set()

    for technique_id in list(best_by_id.keys()):
        if "." in technique_id:
            parent_id = technique_id.split(".", 1)[0]
            parent_ids_to_expand.add(parent_id)

    for parent_id in parent_ids_to_expand:
        if parent_id not in best_by_id:
            best_by_id[parent_id] = {
                "techniqueID": parent_id,
                "enabled": True,
                "showSubtechniques": True,
                "comment": (
                    "Parent technique added automatically so mapped sub-techniques "
                    "are expanded in ATT&CK Navigator."
                ),
                "metadata": [
                    {
                        "name": "Source",
                        "value": "Auto-added parent for mapped sub-technique",
                    }
                ],
                "links": [],
            }
        else:
            best_by_id[parent_id]["showSubtechniques"] = True

    return sorted(best_by_id.values(), key=lambda item: item["techniqueID"])


def build_layer(
    mapping_df: pd.DataFrame,
    layer_name: str,
    description: str,
    domain: str,
    attack_metadata: dict[str, Any],
    include_legend: bool,
) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()

    technique_entries = [
        build_technique_entry(row)
        for _, row in mapping_df.iterrows()
    ]

    technique_entries = dedupe_techniques(technique_entries)

    metadata = [
        {
            "name": "Generated By",
            "value": "AI SecOps Bootcamp Lab 2.2",
        },
        {
            "name": "Generated At UTC",
            "value": generated_at,
        },
        {
            "name": "Mapping Source",
            "value": "outputs/lab2_2_latest_attack_mapping.csv",
        },
    ]

    dataset_name = normalize_text(attack_metadata.get("dataset"))
    synced_at = normalize_text(attack_metadata.get("synced_at_utc"))
    technique_count = normalize_text(attack_metadata.get("technique_count"))

    if dataset_name:
        metadata.append({"name": "ATT&CK Dataset", "value": dataset_name})

    if synced_at:
        metadata.append({"name": "ATT&CK Cache Synced At", "value": synced_at})

    if technique_count:
        metadata.append({"name": "ATT&CK Cache Technique Count", "value": technique_count})

    layer = {
        "versions": {
            "attack": "18",
            "navigator": "5.2.0",
            "layer": "4.5",
        },
        "name": layer_name,
        "description": description,
        "domain": get_layer_domain(domain),
        "filters": {
            "platforms": ENTERPRISE_PLATFORM_FILTERS
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": True,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": technique_entries,
        "gradient": DEFAULT_GRADIENT,
        "legendItems": [],
        "metadata": metadata,
        "links": [
            {
                "label": "ATT&CK Navigator",
                "url": "https://mitre-attack.github.io/attack-navigator/",
            }
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    if include_legend:
        layer["legendItems"] = [
            {
                "label": "High confidence mapping",
                "color": CONFIDENCE_COLOR["high"],
            },
            {
                "label": "Medium confidence mapping",
                "color": CONFIDENCE_COLOR["medium"],
            },
            {
                "label": "Low confidence mapping",
                "color": CONFIDENCE_COLOR["low"],
            },
        ]

    return layer


def save_layer(layer: dict[str, Any]) -> dict[str, Path]:
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    layer_path = OUTPUT_DIR / f"lab2_2_attack_navigator_layer_{timestamp}.json"
    latest_layer_path = OUTPUT_DIR / "lab2_2_latest_attack_navigator_layer.json"

    layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    latest_layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")

    return {
        "layer": layer_path,
        "latest_layer": latest_layer_path,
    }


def validate_layer(layer: dict[str, Any]):
    required_top_level = [
        "versions",
        "name",
        "domain",
        "techniques",
    ]

    missing = [key for key in required_top_level if key not in layer]

    if missing:
        raise RuntimeError(f"Layer is missing required top-level keys: {missing}")

    techniques = layer.get("techniques", [])

    if not isinstance(techniques, list):
        raise RuntimeError("Layer 'techniques' field is not a list.")

    if not techniques:
        raise RuntimeError("Layer has zero techniques. Nothing to import into Navigator.")

    for item in techniques:
        technique_id = item.get("techniqueID", "")

        if not TECHNIQUE_ID_REGEX.match(str(technique_id)):
            raise RuntimeError(f"Invalid techniqueID in layer: {technique_id}")


def run(
    mapping_csv: str | None,
    layer_name: str,
    description: str,
    domain: str,
    include_legend: bool,
):
    mapping_path = Path(mapping_csv) if mapping_csv else DEFAULT_MAPPING_CSV

    print("=" * 90)
    print("[bold]Lab 2.2 Component 3: ATT&CK Navigator Layer Generator[/bold]")
    print("=" * 90)
    print(f"Mapping CSV: {mapping_path}")

    mapping_df = load_mapping_csv(mapping_path)

    attack_metadata = read_json_if_exists(DEFAULT_METADATA_JSON)

    layer = build_layer(
        mapping_df=mapping_df,
        layer_name=layer_name,
        description=description,
        domain=domain,
        attack_metadata=attack_metadata,
        include_legend=include_legend,
    )

    validate_layer(layer)

    paths = save_layer(layer)

    print("[bold green]ATT&CK Navigator layer generated successfully.[/bold green]")
    print(f"Techniques in layer: {len(layer['techniques'])}")
    print(f"Layer output: {paths['layer']}")
    print(f"Latest layer output: {paths['latest_layer']}")
    print("=" * 90)

    preview = [
        {
            "techniqueID": item.get("techniqueID"),
            "score": item.get("score", ""),
            "color": item.get("color", ""),
            "showSubtechniques": item.get("showSubtechniques", False),
            "comment_preview": normalize_text(item.get("comment"))[:120],
        }
        for item in layer["techniques"]
    ]

    print(pd.DataFrame(preview))


def main():
    parser = argparse.ArgumentParser(
        description="Generate an ATT&CK Navigator layer JSON from Lab 2.2 final ATT&CK mappings."
    )

    parser.add_argument(
        "--mapping-csv",
        default=None,
        help="Path to final ATT&CK mapping CSV. Defaults to outputs/lab2_2_latest_attack_mapping.csv.",
    )

    parser.add_argument(
        "--layer-name",
        default="Lab 2.2 AI-Mapped Threat Report Layer",
        help="Name shown in ATT&CK Navigator.",
    )

    parser.add_argument(
        "--description",
        default=(
            "ATT&CK Navigator layer generated from Lab 2.2 final mappings. "
            "Mappings are AI-assisted, validated against the current local ATT&CK cache, "
            "and should still be analyst-reviewed."
        ),
        help="Layer description shown in ATT&CK Navigator.",
    )

    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        help="Navigator domain. Usually enterprise-attack.",
    )

    parser.add_argument(
        "--no-legend",
        action="store_true",
        help="Disable legend items in the generated Navigator layer.",
    )

    args = parser.parse_args()

    try:
        run(
            mapping_csv=args.mapping_csv,
            layer_name=args.layer_name,
            description=args.description,
            domain=args.domain,
            include_legend=not args.no_legend,
        )
    except Exception as exc:
        print(f"[bold red]ERROR:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()