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
        return "[]"

    quoted = ", ".join([f'"{kql_escape(value)}"' for value in clean_values])
    return f"[{quoted}]"


BEHAVIOR_TEMPLATES = {
    "T1003": {
        "spl": '''index=* earliest=-30d (process_name IN ("procdump.exe","rundll32.exe","powershell.exe","pwsh.exe","mimikatz.exe") OR process="*lsass*")
| where like(lower(process), "%lsass%") OR like(lower(process), "%sekurlsa%") OR like(lower(process), "%comsvcs%")
| stats count min(_time) as first_seen max(_time) as last_seen values(parent_process_name) as parents values(process) as command_lines by host user process_name
| convert ctime(first_seen) ctime(last_seen)
| sort - count''',
        "kql": '''DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("procdump.exe", "rundll32.exe", "powershell.exe", "pwsh.exe", "mimikatz.exe")
    or ProcessCommandLine has_any ("lsass", "sekurlsa", "comsvcs.dll")
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "comsvcs.dll")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc''',
    },
    "T1059.001": {
        "spl": '''index=* earliest=-30d process_name IN ("powershell.exe","pwsh.exe")
| where match(lower(process), "(encodedcommand|frombase64string|downloadstring|invoke-expression|invoke-webrequest| iwr | iex )")
| stats count min(_time) as first_seen max(_time) as last_seen values(parent_process_name) as parents values(process) as command_lines by host user process_name
| convert ctime(first_seen) ctime(last_seen)
| sort - count''',
        "kql": '''DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("EncodedCommand", "FromBase64String", "DownloadString", "Invoke-Expression", "Invoke-WebRequest", " iwr ", " iex ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, SHA256
| order by Timestamp desc''',
    },
    "T1053.005": {
        "spl": '''index=* earliest=-30d (process_name="schtasks.exe" OR EventCode IN (4698,4702))
| stats count min(_time) as first_seen max(_time) as last_seen values(process) as command_lines values(TaskName) as task_names by host user EventCode
| convert ctime(first_seen) ctime(last_seen)
| sort - count''',
        "kql": '''DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe" or ProcessCommandLine has_all ("schtasks", "/create")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc''',
    },
    "T1505.003": {
        "spl": '''index=* earliest=-30d parent_process_name IN ("w3wp.exe","httpd.exe","apache2","nginx") process_name IN ("cmd.exe","powershell.exe","sh","bash")
| stats count min(_time) as first_seen max(_time) as last_seen values(parent_process_name) as parents values(process) as command_lines by host user
| convert ctime(first_seen) ctime(last_seen)
| sort - count''',
        "kql": '''DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "apache2", "nginx.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc''',
    },
    "T1566.002": {
        "spl": '''index=* earliest=-30d (sourcetype=*email* OR sourcetype=*mail*) url!=""
| stats count dc(recipient) as recipient_count values(sender) as senders values(subject) as subjects by url
| where recipient_count < 10 OR count < 20
| sort recipient_count count''',
        "kql": '''EmailUrlInfo
| where Timestamp > ago(30d)
| join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction) on NetworkMessageId
| summarize MessageCount=count(), Recipients=make_set(RecipientEmailAddress, 20), Senders=make_set(SenderFromAddress, 20), Subjects=make_set(Subject, 20) by Url, DeliveryAction
| order by MessageCount asc''',
    },
}


def get_behavior_template(attack_id: str) -> dict[str, str] | None:
    if attack_id in BEHAVIOR_TEMPLATES:
        return BEHAVIOR_TEMPLATES[attack_id]
    if attack_id.startswith("T1003."):
        return BEHAVIOR_TEMPLATES["T1003"]
    return None


def build_generic_splunk_hunt(row: pd.Series, iocs: dict[str, list[str]]) -> str:
    attack_id = normalize_text(row.get("attack_id"))
    name = normalize_text(row.get("name"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources")) or normalize_text(row.get("data_sources"))
    template = get_behavior_template(attack_id)

    if not template:
        return (
            f"**Splunk behavioral hunt for {attack_id} - {name}**\n\n"
            "No deterministic behavioral template is bundled for this technique. Use the cited source behavior and "
            "ATT&CK data components to author a query for your telemetry. The lab does not generate a fake keyword search."
        )

    return f"""**Splunk behavioral hunt starter for {attack_id} - {name}**

Suggested context:
- Hunting focus: {hunting_focus or "Validate the source behavior in endpoint or security telemetry."}
- Suggested log sources: {log_sources or "Tune this starter to the endpoint and security fields in your environment."}

```spl
{template['spl']}
```"""


def build_generic_kql_hunt(row: pd.Series, iocs: dict[str, list[str]]) -> str:
    attack_id = normalize_text(row.get("attack_id"))
    name = normalize_text(row.get("name"))
    hunting_focus = normalize_text(row.get("hunting_focus"))
    log_sources = normalize_text(row.get("log_sources")) or normalize_text(row.get("data_sources"))
    template = get_behavior_template(attack_id)

    if not template:
        return (
            f"**Microsoft behavioral hunt for {attack_id} - {name}**\n\n"
            "No deterministic Microsoft Defender or Sentinel template is bundled for this technique. Use the cited "
            "source behavior and ATT&CK data components to author a query for the tables available in your tenant."
        )

    return f"""**Microsoft Sentinel / Defender behavioral hunt starter for {attack_id} - {name}**

Suggested context:
- Hunting focus: {hunting_focus or "Validate the source behavior in endpoint or security telemetry."}
- Suggested log sources: {log_sources or "Tune this starter to the tables and fields available in your tenant."}

```kql
{template['kql']}
```"""


def build_ioc_hunt_section(iocs: dict[str, list[str]]) -> str:
    domains = build_ioc_filter_text(iocs, ["domains"], 20)
    urls = build_ioc_filter_text(iocs, ["urls"], 20)
    ips = build_ioc_filter_text(iocs, ["ipv4s", "ips"], 20)
    hashes = build_ioc_filter_text(iocs, ["sha256", "sha1", "md5", "hashes"], 30)

    if not any([domains, urls, ips, hashes]):
        return "_No network or file indicators are available for an IOC hunt._"

    sections = []
    spl_filter = build_splunk_filter(iocs)
    if spl_filter:
        sections.append(
            "### Splunk IOC starter\n\n"
            "```spl\n"
            f"index=* earliest=-30d ({spl_filter})\n"
            "| stats count min(_time) as first_seen max(_time) as last_seen values(user) as users values(process_name) as processes values(url) as urls by host src_ip dest_ip\n"
            "| convert ctime(first_seen) ctime(last_seen)\n"
            "| sort - count\n"
            "```"
        )

    kql_parts = []
    if domains or urls or ips:
        kql_parts.append(
            "let suspicious_domains = dynamic(" + build_kql_dynamic_array(domains, "") + ");\n"
            "let suspicious_urls = dynamic(" + build_kql_dynamic_array(urls, "") + ");\n"
            "let suspicious_ips = dynamic(" + build_kql_dynamic_array(ips, "") + ");\n"
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(30d)\n"
            "| where (array_length(suspicious_domains) > 0 and RemoteUrl has_any (suspicious_domains))\n"
            "    or (array_length(suspicious_urls) > 0 and RemoteUrl has_any (suspicious_urls))\n"
            "    or (array_length(suspicious_ips) > 0 and RemoteIP in (suspicious_ips))\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort"
        )
    if hashes:
        kql_parts.append(
            "let suspicious_hashes = dynamic(" + build_kql_dynamic_array(hashes, "") + ");\n"
            "union DeviceProcessEvents, DeviceFileEvents\n"
            "| where Timestamp > ago(30d)\n"
            "| where SHA256 in (suspicious_hashes) or SHA1 in (suspicious_hashes) or MD5 in (suspicious_hashes)\n"
            "| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, SHA1, MD5"
        )

    if kql_parts:
        sections.append(
            "### Microsoft Defender IOC starters\n\n"
            + "\n\n".join(f"```kql\n{query}\n```" for query in kql_parts)
        )

    return "\n\n".join(sections)


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
        "## Separate IOC Hunt\n\n"
        "This section searches extracted network and file indicators. It is separate from ATT&CK behavioral hunting. "
        "Validate report attribution and tune fields before use.\n\n"
        + build_ioc_hunt_section(iocs)
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
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")

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

    # Keep the hunting pack tied to approved mappings and cited source evidence.
    # AI summaries are intentionally not reused as evidence in downstream artifacts.
    easy_summary = ""
    analyst_brief = ""

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
