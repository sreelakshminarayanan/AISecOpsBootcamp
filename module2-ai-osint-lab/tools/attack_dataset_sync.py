import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from rich import print


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

DEFAULT_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TECHNIQUES_CSV = OUTPUT_DIR / "attack_enterprise_techniques.csv"
TECHNIQUES_JSON = OUTPUT_DIR / "attack_enterprise_techniques.json"
METADATA_JSON = OUTPUT_DIR / "attack_enterprise_metadata.json"
RAW_STIX_JSON = OUTPUT_DIR / "attack_enterprise_raw_stix.json"


def fetch_attack_stix(url: str) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            timeout=120,
            headers={
                "User-Agent": "AI-SecOps-Bootcamp-Lab2-ATTACK-Sync/1.0",
                "Accept": "application/json",
            },
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to download ATT&CK dataset: {exc}") from exc

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to download ATT&CK dataset. HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError("Downloaded ATT&CK dataset is not valid JSON.") from exc

    if not isinstance(data, dict) or "objects" not in data:
        raise RuntimeError("Unexpected ATT&CK STIX format. Missing top-level 'objects'.")

    if not isinstance(data["objects"], list):
        raise RuntimeError("Unexpected ATT&CK STIX format. 'objects' is not a list.")

    return data


def get_attack_version(stix_data: dict[str, Any]) -> str:
    """
    Return the ATT&CK release version (for example '19.1').

    The version lives on the x-mitre-collection object as x_mitre_version. This
    is the real ATT&CK version of the dataset and is what downstream artifacts
    (such as the Navigator layer) must report, rather than a hardcoded number.
    """
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version", "")).strip()
            if version:
                return version

    return ""


def get_external_attack_id(stix_object: dict[str, Any]) -> str:
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).strip()

    return ""


def get_attack_url(stix_object: dict[str, Any]) -> str:
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return str(ref["url"]).strip()

    attack_id = get_external_attack_id(stix_object)
    if attack_id:
        if "." in attack_id:
            parent, child = attack_id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parent}/{child}/"
        return f"https://attack.mitre.org/techniques/{attack_id}/"

    return ""


def get_tactics(stix_object: dict[str, Any]) -> list[str]:
    tactics = []

    for phase in stix_object.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
            tactics.append(str(phase["phase_name"]).strip())

    return sorted(set(tactics))


def get_platforms(stix_object: dict[str, Any]) -> list[str]:
    platforms = stix_object.get("x_mitre_platforms", [])

    if not isinstance(platforms, list):
        return []

    return sorted(set(str(item).strip() for item in platforms if str(item).strip()))


def get_data_sources(stix_object: dict[str, Any]) -> list[str]:
    data_sources = stix_object.get("x_mitre_data_sources", [])

    if not isinstance(data_sources, list):
        return []

    return sorted(set(str(item).strip() for item in data_sources if str(item).strip()))


def clean_text(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)
    text = " ".join(text.split())
    return text.strip()


def parse_enterprise_techniques(stix_data: dict[str, Any], include_deprecated: bool) -> list[dict[str, Any]]:
    techniques = []

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        attack_id = get_external_attack_id(obj)

        if not attack_id:
            continue

        revoked = bool(obj.get("revoked", False))
        deprecated = bool(obj.get("x_mitre_deprecated", False))

        if not include_deprecated and (revoked or deprecated):
            continue

        tactics = get_tactics(obj)
        platforms = get_platforms(obj)
        data_sources = get_data_sources(obj)

        technique = {
            "attack_id": attack_id,
            "name": clean_text(obj.get("name")),
            "tactics": "; ".join(tactics),
            "tactics_list": tactics,
            "description": clean_text(obj.get("description")),
            "detection": clean_text(obj.get("x_mitre_detection")),
            "platforms": "; ".join(platforms),
            "platforms_list": platforms,
            "data_sources": "; ".join(data_sources),
            "data_sources_list": data_sources,
            "url": get_attack_url(obj),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "revoked": revoked,
            "deprecated": deprecated,
            "stix_id": obj.get("id", ""),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
            "version": obj.get("x_mitre_version", ""),
        }

        techniques.append(technique)

    techniques.sort(key=lambda item: item["attack_id"])

    if not techniques:
        raise RuntimeError("No ATT&CK techniques were parsed from the STIX dataset.")

    return techniques


def build_metadata(stix_data: dict[str, Any], techniques: list[dict[str, Any]], source_url: str) -> dict[str, Any]:
    attack_spec_version = stix_data.get("spec_version", "")
    bundle_id = stix_data.get("id", "")
    bundle_type = stix_data.get("type", "")
    objects_count = len(stix_data.get("objects", []))

    modified_values = [
        item.get("modified", "")
        for item in techniques
        if item.get("modified")
    ]

    latest_modified = max(modified_values) if modified_values else ""

    attack_version = get_attack_version(stix_data)
    attack_version_major = attack_version.split(".", 1)[0] if attack_version else ""

    return {
        "dataset": "Enterprise ATT&CK",
        "source_url": source_url,
        "synced_at_utc": datetime.now(UTC).isoformat(),
        "attack_version": attack_version,
        "attack_version_major": attack_version_major,
        "stix_bundle_id": bundle_id,
        "stix_bundle_type": bundle_type,
        "stix_spec_version": attack_spec_version,
        "raw_object_count": objects_count,
        "technique_count": len(techniques),
        "subtechnique_count": sum(1 for item in techniques if item["is_subtechnique"]),
        "technique_count_without_subtechniques": sum(1 for item in techniques if not item["is_subtechnique"]),
        "latest_technique_modified": latest_modified,
        "output_csv": str(TECHNIQUES_CSV),
        "output_json": str(TECHNIQUES_JSON),
    }


def save_outputs(
    stix_data: dict[str, Any],
    techniques: list[dict[str, Any]],
    metadata: dict[str, Any],
    save_raw: bool,
):
    csv_rows = []

    for item in techniques:
        row = dict(item)
        row.pop("tactics_list", None)
        row.pop("platforms_list", None)
        row.pop("data_sources_list", None)
        csv_rows.append(row)

    df = pd.DataFrame(csv_rows)

    required_columns = [
        "attack_id",
        "name",
        "tactics",
        "description",
        "detection",
        "platforms",
        "data_sources",
        "url",
        "is_subtechnique",
        "revoked",
        "deprecated",
        "stix_id",
        "created",
        "modified",
        "version",
    ]

    missing_columns = [column for column in required_columns if column not in df.columns]

    if missing_columns:
        raise RuntimeError(f"Internal error. Missing expected columns: {missing_columns}")

    df = df[required_columns]
    df.to_csv(TECHNIQUES_CSV, index=False)

    TECHNIQUES_JSON.write_text(
        json.dumps(
            {
                "metadata": metadata,
                "techniques": techniques,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    METADATA_JSON.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    if save_raw:
        RAW_STIX_JSON.write_text(
            json.dumps(stix_data, indent=2),
            encoding="utf-8",
        )


def validate_outputs():
    if not TECHNIQUES_CSV.exists():
        raise RuntimeError("Technique CSV was not created.")

    if not TECHNIQUES_JSON.exists():
        raise RuntimeError("Technique JSON was not created.")

    df = pd.read_csv(TECHNIQUES_CSV)

    if df.empty:
        raise RuntimeError("Technique CSV is empty.")

    if "attack_id" not in df.columns:
        raise RuntimeError("Technique CSV missing attack_id column.")

    sample_ids = set(df["attack_id"].astype(str).head(20).tolist())

    if not any(value.startswith("T") for value in sample_ids):
        raise RuntimeError("Technique CSV does not appear to contain ATT&CK technique IDs.")


def sync_attack_dataset(
    url: str = DEFAULT_ENTERPRISE_ATTACK_URL,
    include_deprecated: bool = False,
    save_raw: bool = False,
) -> dict[str, Any]:
    """
    Download the current Enterprise ATT&CK dataset, parse it, and write the local
    technique cache. Returns the metadata dict. Importable so the unified app can
    run the sync in-process rather than shelling out to a subprocess.
    """
    stix_data = fetch_attack_stix(url)
    techniques = parse_enterprise_techniques(
        stix_data=stix_data,
        include_deprecated=include_deprecated,
    )
    metadata = build_metadata(
        stix_data=stix_data,
        techniques=techniques,
        source_url=url,
    )
    save_outputs(
        stix_data=stix_data,
        techniques=techniques,
        metadata=metadata,
        save_raw=save_raw,
    )
    validate_outputs()
    return metadata


def main():
    parser = argparse.ArgumentParser(
        description="Download and parse the latest Enterprise ATT&CK STIX dataset into a local technique cache."
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_ENTERPRISE_ATTACK_URL,
        help="Enterprise ATT&CK STIX JSON URL.",
    )

    parser.add_argument(
        "--include-deprecated",
        action="store_true",
        help="Include revoked or deprecated techniques in the output cache.",
    )

    parser.add_argument(
        "--save-raw",
        action="store_true",
        help="Save the full raw STIX JSON to outputs/attack_enterprise_raw_stix.json.",
    )

    args = parser.parse_args()

    print("=" * 90)
    print("[bold]Lab 2.2 Component 1: Dynamic ATT&CK Dataset Sync[/bold]")
    print("=" * 90)
    print(f"Source URL: {args.url}")
    print("Downloading Enterprise ATT&CK STIX dataset...")

    try:
        metadata = sync_attack_dataset(
            url=args.url,
            include_deprecated=args.include_deprecated,
            save_raw=args.save_raw,
        )
    except Exception as exc:
        print(f"[bold red]ERROR:[/bold red] {exc}")
        sys.exit(1)

    print("[bold green]ATT&CK dataset sync complete.[/bold green]")
    print(f"ATT&CK version: {metadata.get('attack_version') or 'unknown'}")
    print(f"Technique count: {metadata['technique_count']}")
    print(f"Sub-technique count: {metadata['subtechnique_count']}")
    print(f"Latest technique modified timestamp: {metadata['latest_technique_modified']}")
    print(f"CSV output: {TECHNIQUES_CSV}")
    print(f"JSON output: {TECHNIQUES_JSON}")
    print(f"Metadata output: {METADATA_JSON}")
    print("=" * 90)


if __name__ == "__main__":
    main()