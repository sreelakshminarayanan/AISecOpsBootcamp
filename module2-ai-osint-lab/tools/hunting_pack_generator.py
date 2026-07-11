import argparse
import json
import math
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
DEFAULT_REVIEW_CSV = OUTPUT_DIR / "lab2_2_latest_attack_mapping_review.csv"
DEFAULT_IOCS_CSV = OUTPUT_DIR / "lab2_1_latest_iocs.csv"

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

MISSING_TEXT_VALUES = {
    "",
    "nan",
    "none",
    "null",
    "nat",
    "<na>",
}


def is_missing_value(value: Any) -> bool:
    if value is None:
        return True

    try:
        if pd.isna(value):
            return True
    except Exception:
        pass

    if isinstance(value, float) and math.isnan(value):
        return True

    text = str(value).strip()

    if text.lower() in MISSING_TEXT_VALUES:
        return True

    return False


def normalize_text(value: Any) -> str:
    if is_missing_value(value):
        return ""

    text = str(value)
    text = re.sub(r"\s+", " ", text)
    text = text.strip()

    if text.lower() in MISSING_TEXT_VALUES:
        return ""

    return text


def human_text(value: Any, fallback: str) -> str:
    text = normalize_text(value)
    return text if text else fallback


def find_latest_file(pattern: str) -> Path | None:
    matches = sorted(
        OUTPUT_DIR.glob(pattern),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not matches:
        return None

    return matches[0]


def read_text_if_exists(path: Path | None) -> str:
    if not path or not path.exists():
        return ""

    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def load_csv_if_exists(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(path, keep_default_na=True)
        return df.fillna("")
    except Exception:
        return pd.DataFrame()


def validate_mapping_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise RuntimeError(
            "Final ATT&CK mapping CSV is empty. Run Component 2 first and ensure at least one final mapping exists."
        )

    required = ["attack_id", "name", "tactics", "confidence"]

    missing = [column for column in required if column not in df.columns]

    if missing:
        raise RuntimeError(f"Mapping CSV missing required columns: {missing}")

    df = df.copy()
    df = df.fillna("")
    df["attack_id"] = df["attack_id"].astype(str).str.upper().str.strip()

    valid_mask = df["attack_id"].apply(lambda value: bool(TECHNIQUE_ID_REGEX.match(value)))
    df = df[valid_mask].copy()

    if df.empty:
        raise RuntimeError("No valid ATT&CK IDs found in final mapping CSV.")

    return df


def extract_iocs(ioc_df: pd.DataFrame) -> dict[str, list[str]]:
    if ioc_df.empty or "type" not in ioc_df.columns or "value" not in ioc_df.columns:
        return {}

    result: dict[str, list[str]] = {}

    for _, row in ioc_df.iterrows():
        ioc_type = normalize_text(row.get("type")).lower()
        value = normalize_text(row.get("value"))

        if not ioc_type or not value:
            continue

        result.setdefault(ioc_type, [])

        if value not in result[ioc_type]:
            result[ioc_type].append(value)

    for key in list(result.keys()):
        result[key] = result[key][:100]

    return result


def markdown_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "_None._"

    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []

    for row in rows:
        values = []

        for column in columns:
            value = normalize_text(row.get(column, ""))
            value = value.replace("|", "\\|")
            values.append(value or "-")

        body.append("| " + " | ".join(values) + " |")

    return "\n".join([header, separator] + body)


def summarize_iocs_for_markdown(iocs: dict[str, list[str]]) -> str:
    if not iocs:
        return "_No IOCs were available from Lab 2.1._"

    sections = []

    for ioc_type in sorted(iocs.keys()):
        values = iocs[ioc_type]

        if not values:
            continue

        display_values = values[:25]
        extra_count = max(0, len(values) - len(display_values))

        section = [f"### {ioc_type}"]

        for value in display_values:
            section.append(f"- `{value}`")

        if extra_count:
            section.append(f"- ... plus {extra_count} more")

        sections.append("\n".join(section))

    return "\n\n".join(sections) if sections else "_No IOCs were available from Lab 2.1._"


def build_ioc_filter_text(iocs: dict[str, list[str]], ioc_types: list[str], max_values: int = 20) -> list[str]:
    values = []

    for ioc_type in ioc_types:
        for value in iocs.get(ioc_type, []):
            value = normalize_text(value)

            if value and value not in values:
                values.append(value)

    return values[:max_values]


def splunk_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def kql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def splunk_value_or_filter(field: str, values: list[str]) -> str:
    clean_values = [normalize_text(value) for value in values if normalize_text(value)]

    if not clean_values:
        return ""

    escaped = [splunk_escape(value) for value in clean_values]
    return "(" + " OR ".join([f'{field}="{value}"' for value in escaped]) + ")"


def build_splunk_filter(iocs: dict[str, list[str]]) -> str:
    domains = build_ioc_filter_text(iocs, ["domains"], 10)
    urls = build_ioc_filter_text(iocs, ["urls"], 10)
    ips = build_ioc_filter_text(iocs, ["ipv4s", "ips"], 10)
    hashes = build_ioc_filter_text(iocs, ["sha256", "sha1", "md5", "hashes"], 12)

    filters = []

    if domains:
        filters.append(splunk_value_or_filter("query", domains))
        filters.append(splunk_value_or_filter("dest", domains))
        filters.append(splunk_value_or_filter("url_domain", domains))

    if urls:
        filters.append(splunk_value_or_filter("url", urls))

    if ips:
        filters.append(splunk_value_or_filter("dest_ip", ips))
        filters.append(splunk_value_or_filter("src_ip", ips))

    if hashes:
        filters.append(splunk_value_or_filter("file_hash", hashes))
        filters.append(splunk_value_or_filter("sha256", hashes))

    filters = [item for item in filters if item]

    if not filters:
        return ""

    return " OR ".join(filters)


def build_kql_dynamic_array(values: list[str], placeholder: str) -> str:
    clean_values = [normalize_text(value) for value in values if normalize_text(value)]

    if not clean_values:
        return f'["{placeholder}"]'

    quoted = ", ".join([f'"{kql_escape(value)}"' for value in clean_values])
    return f"[{quoted}]"


def build_generic_splunk_hunt(row: pd.Series, iocs: dict[str, list[str]]) -> str:
    attack_id = normalize_text(row.get("attack_id"))
    name = normalize_text(row.get("name"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources")) or normalize_text(row.get("data_sources"))

    ioc_filter = build_splunk_filter(iocs)

    if ioc_filter:
        base_search = f"index=* earliest=-30d ({ioc_filter})"
    else:
        base_search = (
            f'index=* earliest=-30d ("{splunk_escape(attack_id)}" OR "{splunk_escape(name)}")'
        )

    query = f"""```spl
{base_search}
| eval attack_technique="{splunk_escape(attack_id)}", technique_name="{splunk_escape(name)}"
| stats count min(_time) as first_seen max(_time) as last_seen values(user) as users values(src_ip) as src_ips values(dest_ip) as dest_ips values(process_name) as processes values(url) as urls by attack_technique technique_name host
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```"""

    note = f"""**Splunk hunt starter for {attack_id} - {name}**

Suggested context:
- Hunting focus: {hunting_focus or "Review the mapped ATT&CK behavior, source report evidence, and related observables before running this hunt."}
- Suggested log sources from mapping: {log_sources or "Endpoint, identity, DNS, proxy, cloud audit, and application logs depending on the technique."}

{query}
"""

    return note


def build_generic_kql_hunt(row: pd.Series, iocs: dict[str, list[str]]) -> str:
    attack_id = normalize_text(row.get("attack_id"))
    name = normalize_text(row.get("name"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources")) or normalize_text(row.get("data_sources"))

    domains = build_ioc_filter_text(iocs, ["domains"], 10)
    urls = build_ioc_filter_text(iocs, ["urls"], 10)
    ips = build_ioc_filter_text(iocs, ["ipv4s", "ips"], 10)
    hashes = build_ioc_filter_text(iocs, ["sha256", "sha1", "md5", "hashes"], 12)

    domain_block = build_kql_dynamic_array(domains, "replace-with-domain")
    url_block = build_kql_dynamic_array(urls, "replace-with-url")
    ip_block = build_kql_dynamic_array(ips, "replace-with-ip")
    hash_block = build_kql_dynamic_array(hashes, "replace-with-hash")

    query = f"""```kql
let suspicious_domains = dynamic({domain_block});
let suspicious_urls = dynamic({url_block});
let suspicious_ips = dynamic({ip_block});
let suspicious_hashes = dynamic({hash_block});
union isfuzzy=true
    DeviceNetworkEvents,
    DeviceProcessEvents,
    DeviceFileEvents,
    DeviceEvents,
    SigninLogs,
    AuditLogs
| where Timestamp > ago(30d)
| where RemoteUrl has_any (suspicious_domains)
    or RemoteUrl has_any (suspicious_urls)
    or RemoteIP in (suspicious_ips)
    or SHA256 in (suspicious_hashes)
    or InitiatingProcessSHA256 in (suspicious_hashes)
| extend AttackTechnique="{kql_escape(attack_id)}", TechniqueName="{kql_escape(name)}"
| summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Users=make_set(AccountName, 20), Devices=make_set(DeviceName, 20), Processes=make_set(InitiatingProcessFileName, 20) by AttackTechnique, TechniqueName
| order by EventCount desc
```"""

    note = f"""**Microsoft Sentinel / Defender KQL hunt starter for {attack_id} - {name}**

Suggested context:
- Hunting focus: {hunting_focus or "Review the mapped ATT&CK behavior, source report evidence, and related observables before running this hunt."}
- Suggested log sources from mapping: {log_sources or "Endpoint, identity, DNS, proxy, cloud audit, and application logs depending on the technique."}

{query}
"""

    return note


def build_technique_section(row: pd.Series, iocs: dict[str, list[str]]) -> str:
    attack_id = normalize_text(row.get("attack_id"))
    name = normalize_text(row.get("name"))
    tactics = normalize_text(row.get("tactics"))
    confidence = normalize_text(row.get("confidence"))
    evidence = normalize_text(row.get("evidence"))
    rationale = normalize_text(row.get("rationale"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources")) or normalize_text(row.get("data_sources"))
    url = normalize_text(row.get("url"))

    hunting_questions = [
        f"Where in the environment do we have logs that can confirm or refute {attack_id} - {name}?",
        "Do the extracted IOCs appear in endpoint, DNS, proxy, identity, cloud, or application logs?",
        "Is the activity isolated to one host or user, or does it appear across multiple systems?",
        "Is there a sequence of events that matches the report narrative rather than a single IOC hit?",
        "Are there benign administrative activities that can explain the same behavior?",
    ]

    if hunting_focus:
        for item in [value.strip() for value in hunting_focus.split(";") if normalize_text(value)]:
            hunting_questions.append(f"Can we validate this hunting focus in logs: {item}?")

    section = f"""
## {attack_id} - {name}

**Tactics:** {tactics or "Not specified"}  
**Confidence:** {confidence or "Unknown"}  
**ATT&CK URL:** {url or "Not available"}

### Why this mapping matters

{rationale or "No detailed rationale was available in the mapping row. Analysts must validate this mapping against the original report before operational use."}

### Evidence from source report

> {evidence or "No direct evidence text was available in the mapping row. Analysts must review the source report and Lab 2.1 evidence before using this mapping."}

### Suggested log sources

{log_sources or "Endpoint telemetry, identity logs, DNS logs, proxy logs, cloud audit logs, and application logs depending on the environment."}

### Hunting questions

""" + "\n".join([f"- {question}" for question in hunting_questions]) + "\n\n"

    section += "### Splunk SPL starter\n\n"
    section += build_generic_splunk_hunt(row, iocs)
    section += "\n\n### Microsoft Sentinel / Defender KQL starter\n\n"
    section += build_generic_kql_hunt(row, iocs)

    return section


def build_review_section(review_df: pd.DataFrame) -> str:
    if review_df.empty:
        return "_No review mappings were generated._"

    review_df = review_df.fillna("")

    rows = []

    for _, row in review_df.iterrows():
        rows.append(
            {
                "attack_id": normalize_text(row.get("attack_id")),
                "name": normalize_text(row.get("name")),
                "confidence": normalize_text(row.get("confidence")),
                "review_reason": normalize_text(row.get("review_reason")),
                "evidence": normalize_text(row.get("evidence"))[:180],
            }
        )

    return markdown_table(
        rows,
        ["attack_id", "name", "confidence", "review_reason", "evidence"],
    )


def build_mapping_summary_table(mapping_df: pd.DataFrame) -> str:
    mapping_df = mapping_df.fillna("")
    rows = []

    for _, row in mapping_df.iterrows():
        rows.append(
            {
                "attack_id": normalize_text(row.get("attack_id")),
                "name": normalize_text(row.get("name")),
                "tactics": normalize_text(row.get("tactics")),
                "confidence": normalize_text(row.get("confidence")),
                "evidence": normalize_text(row.get("evidence"))[:180],
            }
        )

    return markdown_table(
        rows,
        ["attack_id", "name", "tactics", "confidence", "evidence"],
    )


def build_json_payload(
    mapping_df: pd.DataFrame,
    review_df: pd.DataFrame,
    iocs: dict[str, list[str]],
    markdown_report: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "metadata": metadata,
        "final_mappings": mapping_df.fillna("").to_dict(orient="records"),
        "review_mappings": review_df.fillna("").to_dict(orient="records") if not review_df.empty else [],
        "iocs": iocs,
        "markdown_report": markdown_report,
    }


def build_hunting_pack(
    mapping_df: pd.DataFrame,
    review_df: pd.DataFrame,
    ioc_df: pd.DataFrame,
    easy_summary: str,
    analyst_brief: str,
    source_url: str,
) -> tuple[str, dict[str, Any]]:
    mapping_df = mapping_df.fillna("")
    review_df = review_df.fillna("") if not review_df.empty else review_df

    iocs = extract_iocs(ioc_df)
    generated_at = datetime.now(UTC).isoformat()

    metadata = {
        "generated_at_utc": generated_at,
        "source_url": source_url,
        "final_mapping_count": int(len(mapping_df)),
        "review_mapping_count": int(len(review_df)),
        "ioc_type_count": int(len(iocs)),
        "generator": "AI SecOps Bootcamp Lab 2.2 Hunting Pack Generator",
    }

    sections = []

    sections.append(
        f"""# Lab 2.2 Hunting Pack

Generated at UTC: `{generated_at}`

Source report: {source_url or "Not available"}

## Purpose

This hunting pack converts Lab 2.1 threat report extraction and Lab 2.2 ATT&CK mapping into practical hunting questions and starter SIEM queries.

This is not production detection content. It is an analyst starter pack. Every query must be tuned to your environment, log sources, field names, indexes, tables, and false-positive conditions.

## Analyst safety note

- Do not treat AI-generated mapping as final truth.
- Validate the ATT&CK mapping against observed behavior.
- Validate every IOC against the source report and enrichment.
- Tune all SPL and KQL queries before operational use.
- No match does not mean safe. It only means no match in the searched logs and timeframe.
"""
    )

    if easy_summary:
        sections.append(
            "## Easy Summary From Lab 2.1\n\n"
            + easy_summary[:5000]
        )

    if analyst_brief:
        sections.append(
            "## Analyst Brief From Lab 2.1\n\n"
            + analyst_brief[:7000]
        )

    sections.append(
        "## Final ATT&CK Mappings Used For Hunting\n\n"
        + build_mapping_summary_table(mapping_df)
    )

    sections.append(
        "## Review Mappings Not Used As Final Hunts\n\n"
        + build_review_section(review_df)
    )

    sections.append(
        "## IOCs Available From Lab 2.1\n\n"
        + summarize_iocs_for_markdown(iocs)
    )

    sections.append(
        """## Environment Tuning Checklist

Before running the hunts, define:

- Splunk indexes and sourcetypes for endpoint, identity, DNS, proxy, cloud, and application logs.
- Sentinel or Defender tables available in your tenant.
- Standard field mappings for user, host, source IP, destination IP, URL, domain, process name, command line, and file hash.
- Approved administrative tools and known-good cloud account changes.
- Business-owned scanners, vulnerability tools, and deployment systems.
- Expected activity windows and maintenance windows.
"""
    )

    sections.append("## Technique-Specific Hunting Content")

    for _, row in mapping_df.iterrows():
        sections.append(build_technique_section(row, iocs))

    sections.append(
        """## Analyst Validation Checklist

Use this before presenting results:

1. Did the mapped ATT&CK technique match behavior described in the source report?
2. Did the query return events because of behavior, not only because of keyword matching?
3. Are the IOCs still relevant and correctly extracted?
4. Were known-good admin activities excluded?
5. Are field names correct for the target SIEM?
6. Are timestamps and time zones understood?
7. Are results correlated across more than one log source?
8. Is there enough evidence to escalate, or is more enrichment needed?
9. Did the hunt produce a reusable detection idea?
10. What false-positive conditions must be documented?
"""
    )

    sections.append(
        """## Recommended Next Steps

- Review the final ATT&CK mappings manually.
- Enrich IOCs with reputation and internal telemetry.
- Run the SPL and KQL starters in a lab or read-only hunt context.
- Tune field names and indexes.
- Convert high-signal hunts into detection engineering candidates.
- Feed validated detection ideas into Module 4 Detection Engineering.
"""
    )

    markdown_report = "\n\n".join(sections)
    payload = build_json_payload(
        mapping_df=mapping_df,
        review_df=review_df,
        iocs=iocs,
        markdown_report=markdown_report,
        metadata=metadata,
    )

    return markdown_report, payload


def save_outputs(markdown_report: str, json_payload: dict[str, Any]) -> dict[str, Path]:
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    md_path = OUTPUT_DIR / f"lab2_2_hunting_pack_{timestamp}.md"
    json_path = OUTPUT_DIR / f"lab2_2_hunting_pack_{timestamp}.json"

    latest_md_path = OUTPUT_DIR / "lab2_2_latest_hunting_pack.md"
    latest_json_path = OUTPUT_DIR / "lab2_2_latest_hunting_pack.json"

    md_path.write_text(markdown_report, encoding="utf-8")
    latest_md_path.write_text(markdown_report, encoding="utf-8")

    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")
    latest_json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    return {
        "markdown": md_path,
        "json": json_path,
        "latest_markdown": latest_md_path,
        "latest_json": latest_json_path,
    }


def run(
    mapping_csv: str | None,
    review_csv: str | None,
    iocs_csv: str | None,
    source_url: str,
):
    mapping_path = Path(mapping_csv) if mapping_csv else DEFAULT_MAPPING_CSV
    review_path = Path(review_csv) if review_csv else DEFAULT_REVIEW_CSV
    iocs_path = Path(iocs_csv) if iocs_csv else DEFAULT_IOCS_CSV

    print("=" * 90)
    print("[bold]Lab 2.2 Component 4: Hunting Pack Generator[/bold]")
    print("=" * 90)
    print(f"Final mapping CSV: {mapping_path}")
    print(f"Review mapping CSV: {review_path if review_path.exists() else 'not found'}")
    print(f"IOC CSV: {iocs_path if iocs_path.exists() else 'not found'}")

    mapping_df = validate_mapping_df(load_csv_if_exists(mapping_path))
    review_df = load_csv_if_exists(review_path)
    ioc_df = load_csv_if_exists(iocs_path)

    easy_summary_path = find_latest_file("lab2_1_easy_summary_*.md")
    analyst_brief_path = find_latest_file("lab2_1_ai_brief_*.md")

    easy_summary = read_text_if_exists(easy_summary_path)
    analyst_brief = read_text_if_exists(analyst_brief_path)

    if not source_url:
        evidence_path = find_latest_file("lab2_1_report_osint_*.json")

        if evidence_path:
            try:
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                source_url = normalize_text(evidence.get("final_url") or evidence.get("input_url"))
            except Exception:
                source_url = ""

    markdown_report, json_payload = build_hunting_pack(
        mapping_df=mapping_df,
        review_df=review_df,
        ioc_df=ioc_df,
        easy_summary=easy_summary,
        analyst_brief=analyst_brief,
        source_url=source_url,
    )

    paths = save_outputs(markdown_report, json_payload)

    print("[bold green]Hunting pack generated successfully.[/bold green]")
    print(f"Final mappings used: {len(mapping_df)}")
    print(f"Review mappings included: {len(review_df) if not review_df.empty else 0}")
    print(f"Markdown output: {paths['markdown']}")
    print(f"JSON output: {paths['json']}")
    print(f"Latest markdown output: {paths['latest_markdown']}")
    print(f"Latest JSON output: {paths['latest_json']}")
    print("=" * 90)

    return {
        "paths": paths,
        "final_count": len(mapping_df),
        "review_count": len(review_df) if not review_df.empty else 0,
        "markdown_length": len(markdown_report),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate a hunting pack from Lab 2.2 ATT&CK mappings and Lab 2.1 IOCs."
    )

    parser.add_argument(
        "--mapping-csv",
        default=None,
        help="Path to final mapping CSV. Defaults to outputs/lab2_2_latest_attack_mapping.csv.",
    )

    parser.add_argument(
        "--review-csv",
        default=None,
        help="Path to review mapping CSV. Defaults to outputs/lab2_2_latest_attack_mapping_review.csv.",
    )

    parser.add_argument(
        "--iocs-csv",
        default=None,
        help="Path to Lab 2.1 IOC CSV. Defaults to outputs/lab2_1_latest_iocs.csv.",
    )

    parser.add_argument(
        "--source-url",
        default="",
        help="Optional source report URL to include in the hunting pack.",
    )

    args = parser.parse_args()

    try:
        run(
            mapping_csv=args.mapping_csv,
            review_csv=args.review_csv,
            iocs_csv=args.iocs_csv,
            source_url=args.source_url,
        )
    except Exception as exc:
        print(f"[bold red]ERROR:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()