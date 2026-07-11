import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from rich import print

try:
    from tools.ollama_client import ask_ollama_json
except ModuleNotFoundError:
    from ollama_client import ask_ollama_json


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

ATTACK_TECHNIQUES_JSON = OUTPUT_DIR / "attack_enterprise_techniques.json"
LATEST_IOCS_CSV = OUTPUT_DIR / "lab2_1_latest_iocs.csv"

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TECHNIQUE_ID_FIND_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

FINAL_CONFIDENCE_VALUES = {"high", "medium"}
REVIEW_CONFIDENCE_VALUES = {"low"}

ATTACK_MAPPING_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "evidence": {"type": "string"},
                    "rationale": {"type": "string"},
                    "hunting_focus": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "log_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "technique_id",
                    "confidence",
                    "evidence",
                    "rationale",
                    "hunting_focus",
                    "log_sources",
                ],
            },
        },
        "rejected_or_uncertain": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_technique_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["candidate_technique_id", "reason"],
            },
        },
    },
    "required": ["mappings", "rejected_or_uncertain"],
}

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "using", "used",
    "were", "was", "are", "has", "have", "had", "not", "but", "you", "your",
    "their", "they", "them", "its", "our", "can", "will", "may", "also", "than",
    "then", "there", "about", "after", "before", "over", "under", "between",
    "report", "threat", "actor", "attack", "activity", "observed", "security",
    "system", "systems", "data", "file", "files", "network", "user", "users",
    "related", "associated", "malicious", "campaign", "analysis", "technique",
    "techniques", "vulnerability", "vulnerabilities", "exploitation",
}


def read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON file: {path}") from exc


def find_latest_file(pattern: str) -> Path:
    matches = sorted(
        OUTPUT_DIR.glob(pattern),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not matches:
        raise FileNotFoundError(f"No file found matching outputs/{pattern}")

    return matches[0]


def load_latest_lab2_1_evidence(path_arg: str | None) -> tuple[Path, dict[str, Any]]:
    if path_arg:
        evidence_path = Path(path_arg)
    else:
        evidence_path = find_latest_file("lab2_1_report_osint_*.json")

    evidence = read_json_file(evidence_path)
    return evidence_path, evidence


def load_latest_optional_text(pattern: str) -> tuple[Path | None, str]:
    matches = sorted(
        OUTPUT_DIR.glob(pattern),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not matches:
        return None, ""

    path = matches[0]

    try:
        return path, path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return path, ""


def load_ioc_csv(path_arg: str | None) -> tuple[Path | None, pd.DataFrame]:
    if path_arg:
        ioc_path = Path(path_arg)
    else:
        ioc_path = LATEST_IOCS_CSV

    if not ioc_path.exists():
        return None, pd.DataFrame()

    try:
        df = pd.read_csv(ioc_path)
    except Exception as exc:
        raise RuntimeError(f"Failed to read IOC CSV: {ioc_path}. Error: {exc}") from exc

    return ioc_path, df


def load_attack_cache(path_arg: str | None) -> tuple[Path, dict[str, Any], dict[str, dict[str, Any]]]:
    cache_path = Path(path_arg) if path_arg else ATTACK_TECHNIQUES_JSON
    attack_cache = read_json_file(cache_path)

    techniques = attack_cache.get("techniques")

    if not isinstance(techniques, list) or not techniques:
        raise RuntimeError(
            f"ATT&CK cache does not contain a non-empty 'techniques' list: {cache_path}"
        )

    lookup = {}

    for item in techniques:
        attack_id = str(item.get("attack_id", "")).upper().strip()

        if not TECHNIQUE_ID_REGEX.match(attack_id):
            continue

        lookup[attack_id] = item

    if not lookup:
        raise RuntimeError("No valid ATT&CK technique IDs found in cache.")

    return cache_path, attack_cache, lookup


def normalize_text(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def tokenize(text: str) -> set[str]:
    text = text.lower()
    text = re.sub(r"[^a-z0-9_.-]+", " ", text)

    tokens = set()

    for token in text.split():
        token = token.strip("._-")

        if len(token) < 3:
            continue

        if token in STOPWORDS:
            continue

        tokens.add(token)

    return tokens


def extract_explicit_technique_ids(text: str) -> list[str]:
    ids = sorted(set(match.upper() for match in TECHNIQUE_ID_FIND_REGEX.findall(text or "")))
    return [item for item in ids if TECHNIQUE_ID_REGEX.match(item)]


def extract_ioc_summary(ioc_df: pd.DataFrame) -> dict[str, list[str]]:
    summary: dict[str, list[str]] = {}

    if ioc_df.empty:
        return summary

    if "type" not in ioc_df.columns or "value" not in ioc_df.columns:
        return summary

    for _, row in ioc_df.iterrows():
        ioc_type = normalize_text(row.get("type"))
        value = normalize_text(row.get("value"))

        if not ioc_type or not value:
            continue

        summary.setdefault(ioc_type, [])

        if value not in summary[ioc_type]:
            summary[ioc_type].append(value)

    for key in list(summary.keys()):
        summary[key] = summary[key][:50]

    return summary


def build_report_context(
    evidence: dict[str, Any],
    ioc_df: pd.DataFrame,
    easy_summary: str,
    analyst_brief: str,
) -> dict[str, Any]:
    article = evidence.get("article", {})
    http = evidence.get("http", {})
    iocs_from_evidence = evidence.get("iocs", {})

    title = normalize_text(article.get("title"))
    meta = article.get("meta", {})
    description = normalize_text(
        meta.get("description") or meta.get("og:description") or ""
    )
    article_preview = normalize_text(article.get("article_text_preview"))

    ioc_summary = extract_ioc_summary(ioc_df)

    explicit_mitre_ids = set()

    for source_text in [
        title,
        description,
        article_preview,
        easy_summary,
        analyst_brief,
        json.dumps(iocs_from_evidence),
        json.dumps(ioc_summary),
    ]:
        explicit_mitre_ids.update(extract_explicit_technique_ids(source_text))

    combined_text = "\n\n".join(
        [
            f"Title: {title}",
            f"Description: {description}",
            f"Article Preview: {article_preview}",
            f"Easy Summary: {easy_summary[:4000]}",
            f"Analyst Brief: {analyst_brief[:6000]}",
            f"Validated IOCs: {json.dumps(ioc_summary, indent=2)}",
        ]
    )

    return {
        "source_url": evidence.get("final_url") or evidence.get("input_url") or "",
        "title": title,
        "description": description,
        "article_preview": article_preview[:8000],
        "http_status": http.get("status_code"),
        "validated_iocs": ioc_summary,
        "explicit_mitre_ids": sorted(explicit_mitre_ids),
        "combined_text": combined_text[:22000],
    }


def score_technique_against_report(
    technique: dict[str, Any],
    report_tokens: set[str],
    explicit_ids: set[str],
) -> float:
    attack_id = str(technique.get("attack_id", "")).upper().strip()

    if attack_id in explicit_ids:
        return 10000.0

    name = normalize_text(technique.get("name"))
    tactics = normalize_text(technique.get("tactics"))
    description = normalize_text(technique.get("description"))
    detection = normalize_text(technique.get("detection"))
    platforms = normalize_text(technique.get("platforms"))
    data_sources = normalize_text(technique.get("data_sources"))

    name_tokens = tokenize(name)
    tactic_tokens = tokenize(tactics)
    description_tokens = tokenize(description)
    detection_tokens = tokenize(detection)
    platform_tokens = tokenize(platforms)
    data_source_tokens = tokenize(data_sources)

    score = 0.0
    score += len(report_tokens.intersection(name_tokens)) * 8.0
    score += len(report_tokens.intersection(tactic_tokens)) * 2.0
    score += len(report_tokens.intersection(description_tokens)) * 1.4
    score += len(report_tokens.intersection(detection_tokens)) * 1.2
    score += len(report_tokens.intersection(platform_tokens)) * 1.0
    score += len(report_tokens.intersection(data_source_tokens)) * 1.5

    joined_report_tokens = " ".join(report_tokens)
    description_lower = description.lower()
    name_lower = name.lower()

    if "sharepoint" in report_tokens and "public-facing" in description_lower:
        score += 12.0

    if "webshell" in report_tokens and "web shell" in description_lower:
        score += 15.0

    if "powershell" in report_tokens and "powershell" in name_lower:
        score += 15.0

    if "cve" in report_tokens and "exploit" in description_lower:
        score += 8.0

    if "credential" in joined_report_tokens and "credential" in description_lower:
        score += 5.0

    if "persistence" in joined_report_tokens and "persistence" in description_lower:
        score += 5.0

    if "lateral" in joined_report_tokens and "lateral" in description_lower:
        score += 5.0

    return score


def select_candidate_techniques(
    attack_lookup: dict[str, dict[str, Any]],
    report_context: dict[str, Any],
    candidate_count: int,
) -> list[dict[str, Any]]:
    report_tokens = tokenize(report_context["combined_text"])
    explicit_ids = set(report_context.get("explicit_mitre_ids", []))

    scored = []

    for technique in attack_lookup.values():
        score = score_technique_against_report(
            technique=technique,
            report_tokens=report_tokens,
            explicit_ids=explicit_ids,
        )

        if score <= 0:
            continue

        scored.append((score, technique))

    scored.sort(key=lambda item: item[0], reverse=True)

    candidates = []

    for score, technique in scored[:candidate_count]:
        candidates.append(
            {
                "attack_id": str(technique.get("attack_id", "")).upper(),
                "name": normalize_text(technique.get("name")),
                "tactics": normalize_text(technique.get("tactics")),
                "description": normalize_text(technique.get("description"))[:900],
                "detection": normalize_text(technique.get("detection"))[:700],
                "platforms": normalize_text(technique.get("platforms")),
                "data_sources": normalize_text(technique.get("data_sources")),
                "url": normalize_text(technique.get("url")),
                "candidate_score": round(score, 2),
            }
        )

    explicit_missing = [
        attack_id
        for attack_id in explicit_ids
        if attack_id in attack_lookup and attack_id not in {item["attack_id"] for item in candidates}
    ]

    for attack_id in explicit_missing:
        technique = attack_lookup[attack_id]
        candidates.insert(
            0,
            {
                "attack_id": attack_id,
                "name": normalize_text(technique.get("name")),
                "tactics": normalize_text(technique.get("tactics")),
                "description": normalize_text(technique.get("description"))[:900],
                "detection": normalize_text(technique.get("detection"))[:700],
                "platforms": normalize_text(technique.get("platforms")),
                "data_sources": normalize_text(technique.get("data_sources")),
                "url": normalize_text(technique.get("url")),
                "candidate_score": 10000.0,
            },
        )

    return candidates[:candidate_count]


def build_mapping_prompt(
    report_context: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> str:
    candidate_json = json.dumps(candidates, indent=2)
    validated_iocs = json.dumps(report_context.get("validated_iocs", {}), indent=2)
    schema_json = json.dumps(ATTACK_MAPPING_JSON_SCHEMA, indent=2)

    return f"""
You are a defensive cyber threat intelligence analyst.

Return only a JSON object that matches the JSON schema below. No Markdown. No prose. No explanations outside JSON.

JSON schema:
{schema_json}

Task:
Map the threat report evidence to MITRE ATT&CK Enterprise techniques.

Rules:
1. Use only the report evidence and the candidate ATT&CK techniques provided.
2. Do not invent technique IDs.
3. Prefer techniques directly supported by observed adversary behavior.
4. If evidence is strong and direct, use high confidence.
5. If evidence is reasonable but not fully detailed, use medium confidence.
6. If evidence is weak, indirect, generic, or only keyword based, use low confidence or put the candidate in rejected_or_uncertain.
7. Every mapping must include a short evidence quote or paraphrase from the report evidence.
8. Do not map based only on a CVE number unless the report describes exploitation behavior.
9. Do not map generic "malware", "threat actor", or "campaign" wording unless behavior is described.
10. Only choose technique IDs from the candidate ATT&CK techniques list.
11. Be conservative. It is better to return fewer strong mappings than many weak mappings.

Report source URL:
{report_context.get("source_url", "")}

Report title:
{report_context.get("title", "")}

Report description:
{report_context.get("description", "")}

Validated IOCs:
{validated_iocs}

Report evidence:
{report_context.get("combined_text", "")}

Candidate ATT&CK techniques:
{candidate_json}
"""


def normalize_confidence(value: Any) -> str:
    confidence = normalize_text(value).lower()

    if confidence in {"high", "medium", "low"}:
        return confidence

    if confidence in {"med", "moderate"}:
        return "medium"

    return "low"


def safe_join_list(value: Any, max_len: int) -> str:
    if isinstance(value, list):
        joined = "; ".join(normalize_text(item) for item in value if normalize_text(item))
    else:
        joined = normalize_text(value)

    return joined[:max_len]


def build_validated_mapping_row(
    technique_id: str,
    item: dict[str, Any],
    technique: dict[str, Any],
    confidence: str,
    validation_note: str,
    mapping_source: str,
) -> dict[str, Any]:
    disposition = "final" if confidence in FINAL_CONFIDENCE_VALUES else "review"

    review_reason = ""

    if disposition == "review":
        review_reason = "low_confidence_mapping_requires_analyst_review"

    return {
        "attack_id": technique_id,
        "name": normalize_text(technique.get("name")),
        "tactics": normalize_text(technique.get("tactics")),
        "confidence": confidence,
        "disposition": disposition,
        "review_reason": review_reason,
        "evidence": normalize_text(item.get("evidence"))[:800],
        "rationale": normalize_text(item.get("rationale"))[:1000],
        "hunting_focus": safe_join_list(item.get("hunting_focus", []), 1200),
        "log_sources": safe_join_list(item.get("log_sources", []), 800),
        "mapping_source": mapping_source,
        "validation_status": validation_note,
        "url": normalize_text(technique.get("url")),
        "data_sources": normalize_text(technique.get("data_sources")),
        "detection": normalize_text(technique.get("detection"))[:1200],
    }


def validate_llm_mappings(
    llm_json: dict[str, Any],
    attack_lookup: dict[str, dict[str, Any]],
    candidate_ids: set[str],
    explicit_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    raw_mappings = llm_json.get("mappings", [])
    raw_rejections = llm_json.get("rejected_or_uncertain", [])

    if not isinstance(raw_mappings, list):
        raw_mappings = []

    if not isinstance(raw_rejections, list):
        raw_rejections = []

    final_mappings = []
    review_mappings = []
    rejected = []
    seen_valid_ids = set()

    for item in raw_mappings:
        if not isinstance(item, dict):
            rejected.append(
                {
                    "technique_id": "",
                    "validation_status": "rejected",
                    "reason": "mapping_item_not_object",
                    "raw_item": json.dumps(item)[:1000],
                }
            )
            continue

        technique_id = normalize_text(item.get("technique_id")).upper()

        if not TECHNIQUE_ID_REGEX.match(technique_id):
            rejected.append(
                {
                    "technique_id": technique_id,
                    "validation_status": "rejected",
                    "reason": "invalid_technique_id_format",
                    "raw_item": json.dumps(item)[:1000],
                }
            )
            continue

        if technique_id not in attack_lookup:
            rejected.append(
                {
                    "technique_id": technique_id,
                    "validation_status": "rejected",
                    "reason": "technique_id_not_found_in_current_attack_cache",
                    "raw_item": json.dumps(item)[:1000],
                }
            )
            continue

        if technique_id in seen_valid_ids:
            continue

        technique = attack_lookup[technique_id]
        confidence = normalize_confidence(item.get("confidence"))

        validation_note = "validated_against_attack_cache"

        if technique_id not in candidate_ids and technique_id not in explicit_ids:
            validation_note = "validated_but_outside_candidate_set"

        row = build_validated_mapping_row(
            technique_id=technique_id,
            item=item,
            technique=technique,
            confidence=confidence,
            validation_note=validation_note,
            mapping_source="llm_proposed_validated",
        )

        if row["disposition"] == "final":
            final_mappings.append(row)
        else:
            review_mappings.append(row)

        seen_valid_ids.add(technique_id)

    for explicit_id in sorted(explicit_ids):
        if explicit_id in seen_valid_ids:
            continue

        if explicit_id not in attack_lookup:
            rejected.append(
                {
                    "technique_id": explicit_id,
                    "validation_status": "rejected",
                    "reason": "explicit_report_technique_id_not_found_in_attack_cache",
                    "raw_item": "",
                }
            )
            continue

        technique = attack_lookup[explicit_id]

        explicit_item = {
            "evidence": "Technique ID explicitly appeared in Lab 2.1 evidence.",
            "rationale": "The report evidence explicitly contained this ATT&CK technique ID. Analyst should still validate whether the context is relevant.",
            "hunting_focus": [],
            "log_sources": [],
        }

        row = build_validated_mapping_row(
            technique_id=explicit_id,
            item=explicit_item,
            technique=technique,
            confidence="high",
            validation_note="validated_against_attack_cache",
            mapping_source="explicit_report_technique_id_validated",
        )

        final_mappings.append(row)
        seen_valid_ids.add(explicit_id)

    for item in raw_rejections:
        if not isinstance(item, dict):
            continue

        technique_id = normalize_text(item.get("candidate_technique_id")).upper()
        reason = normalize_text(item.get("reason"))

        if technique_id or reason:
            rejected.append(
                {
                    "technique_id": technique_id,
                    "validation_status": "llm_rejected_or_uncertain",
                    "reason": reason,
                    "raw_item": json.dumps(item)[:1000],
                }
            )

    return final_mappings, review_mappings, rejected


def make_dataframe(rows: list[dict[str, Any]], columns: list[str]) -> pd.DataFrame:
    if rows:
        df = pd.DataFrame(rows)

        for column in columns:
            if column not in df.columns:
                df[column] = ""

        return df[columns]

    return pd.DataFrame(columns=columns)


def save_mapping_outputs(
    final_mappings: list[dict[str, Any]],
    review_mappings: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    metadata: dict[str, Any],
    llm_raw_response: str,
    candidates: list[dict[str, Any]],
) -> dict[str, Path]:
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    final_csv = OUTPUT_DIR / f"lab2_2_attack_mapping_final_{timestamp}.csv"
    final_json = OUTPUT_DIR / f"lab2_2_attack_mapping_final_{timestamp}.json"

    review_csv = OUTPUT_DIR / f"lab2_2_attack_mapping_review_{timestamp}.csv"
    rejected_csv = OUTPUT_DIR / f"lab2_2_attack_mapping_rejected_{timestamp}.csv"

    latest_final_csv = OUTPUT_DIR / "lab2_2_latest_attack_mapping.csv"
    latest_final_json = OUTPUT_DIR / "lab2_2_latest_attack_mapping.json"

    latest_review_csv = OUTPUT_DIR / "lab2_2_latest_attack_mapping_review.csv"
    latest_rejected_csv = OUTPUT_DIR / "lab2_2_latest_attack_mapping_rejected.csv"

    mapping_columns = [
        "attack_id",
        "name",
        "tactics",
        "confidence",
        "disposition",
        "review_reason",
        "evidence",
        "rationale",
        "hunting_focus",
        "log_sources",
        "mapping_source",
        "validation_status",
        "url",
        "data_sources",
        "detection",
    ]

    rejected_columns = [
        "technique_id",
        "validation_status",
        "reason",
        "raw_item",
    ]

    final_df = make_dataframe(final_mappings, mapping_columns)
    review_df = make_dataframe(review_mappings, mapping_columns)
    rejected_df = make_dataframe(rejected, rejected_columns)

    final_df.to_csv(final_csv, index=False)
    final_df.to_csv(latest_final_csv, index=False)

    review_df.to_csv(review_csv, index=False)
    review_df.to_csv(latest_review_csv, index=False)

    rejected_df.to_csv(rejected_csv, index=False)
    rejected_df.to_csv(latest_rejected_csv, index=False)

    payload = {
        "metadata": metadata,
        "final_mappings": final_mappings,
        "review_mappings": review_mappings,
        "rejected_mappings": rejected,
        "candidate_techniques": candidates,
        "llm_raw_response": llm_raw_response,
    }

    final_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_final_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return {
        "final_csv": final_csv,
        "final_json": final_json,
        "review_csv": review_csv,
        "rejected_csv": rejected_csv,
        "latest_final_csv": latest_final_csv,
        "latest_final_json": latest_final_json,
        "latest_review_csv": latest_review_csv,
        "latest_rejected_csv": latest_rejected_csv,
    }


def run(
    evidence_path_arg: str | None,
    ioc_path_arg: str | None,
    attack_cache_arg: str | None,
    model: str,
    candidate_count: int,
    no_ai: bool,
):
    attack_cache_path, attack_cache, attack_lookup = load_attack_cache(attack_cache_arg)
    evidence_path, evidence = load_latest_lab2_1_evidence(evidence_path_arg)
    ioc_path, ioc_df = load_ioc_csv(ioc_path_arg)

    easy_summary_path, easy_summary = load_latest_optional_text("lab2_1_easy_summary_*.md")
    analyst_brief_path, analyst_brief = load_latest_optional_text("lab2_1_ai_brief_*.md")

    report_context = build_report_context(
        evidence=evidence,
        ioc_df=ioc_df,
        easy_summary=easy_summary,
        analyst_brief=analyst_brief,
    )

    candidates = select_candidate_techniques(
        attack_lookup=attack_lookup,
        report_context=report_context,
        candidate_count=candidate_count,
    )

    candidate_ids = {item["attack_id"] for item in candidates}
    explicit_ids = set(report_context.get("explicit_mitre_ids", []))

    print("=" * 90)
    print("[bold]Lab 2.2 Component 2: Hardened Evidence-to-ATT&CK Mapping Engine[/bold]")
    print("=" * 90)
    print(f"Evidence JSON: {evidence_path}")
    print(f"IOC CSV: {ioc_path if ioc_path else 'not found, continuing without IOC CSV'}")
    print(f"ATT&CK cache: {attack_cache_path}")
    print(f"ATT&CK technique count: {len(attack_lookup)}")
    print(f"Easy summary file: {easy_summary_path if easy_summary_path else 'not found'}")
    print(f"Analyst brief file: {analyst_brief_path if analyst_brief_path else 'not found'}")
    print(f"Candidate techniques selected: {len(candidates)}")
    print(f"Explicit ATT&CK IDs found in evidence: {sorted(explicit_ids) if explicit_ids else 'none'}")

    if not candidates:
        raise RuntimeError(
            "No candidate ATT&CK techniques were selected. Rerun Lab 2.1 on a richer report or increase extracted evidence."
        )

    if no_ai:
        llm_json = {"mappings": [], "rejected_or_uncertain": []}
        llm_raw_response = json.dumps(llm_json, indent=2)
    else:
        prompt = build_mapping_prompt(report_context, candidates)

        print("Asking local LLM to propose ATT&CK mappings using Ollama structured JSON output...")

        try:
            llm_json = ask_ollama_json(
                prompt=prompt,
                model=model,
                temperature=0.0,
                num_predict=4096,
                json_schema=ATTACK_MAPPING_JSON_SCHEMA,
            )
            llm_raw_response = json.dumps(llm_json, indent=2)
        except Exception as exc:
            raise RuntimeError(
                "Failed to get structured JSON from Ollama. "
                "Confirm your Ollama version supports structured outputs, or update Ollama. "
                f"Error: {exc}"
            ) from exc

    final_mappings, review_mappings, rejected = validate_llm_mappings(
        llm_json=llm_json,
        attack_lookup=attack_lookup,
        candidate_ids=candidate_ids,
        explicit_ids=explicit_ids,
    )

    metadata = {
        "created_at_utc": datetime.now(UTC).isoformat(),
        "model": model,
        "no_ai": no_ai,
        "evidence_json": str(evidence_path),
        "ioc_csv": str(ioc_path) if ioc_path else "",
        "attack_cache": str(attack_cache_path),
        "attack_cache_metadata": attack_cache.get("metadata", {}),
        "candidate_count_requested": candidate_count,
        "candidate_count_selected": len(candidates),
        "final_mapping_count": len(final_mappings),
        "review_mapping_count": len(review_mappings),
        "rejected_mapping_count": len(rejected),
        "source_url": report_context.get("source_url", ""),
        "report_title": report_context.get("title", ""),
        "final_confidence_values": sorted(FINAL_CONFIDENCE_VALUES),
        "review_confidence_values": sorted(REVIEW_CONFIDENCE_VALUES),
    }

    paths = save_mapping_outputs(
        final_mappings=final_mappings,
        review_mappings=review_mappings,
        rejected=rejected,
        metadata=metadata,
        llm_raw_response=llm_raw_response,
        candidates=candidates,
    )

    print("[bold green]ATT&CK mapping complete.[/bold green]")
    print(f"Final mappings: {len(final_mappings)}")
    print(f"Review mappings: {len(review_mappings)}")
    print(f"Rejected or uncertain mappings: {len(rejected)}")
    print(f"Final mapping CSV: {paths['final_csv']}")
    print(f"Final mapping JSON: {paths['final_json']}")
    print(f"Review mapping CSV: {paths['review_csv']}")
    print(f"Rejected CSV: {paths['rejected_csv']}")
    print(f"Latest final mapping CSV: {paths['latest_final_csv']}")
    print(f"Latest final mapping JSON: {paths['latest_final_json']}")
    print(f"Latest review mapping CSV: {paths['latest_review_csv']}")
    print(f"Latest rejected mapping CSV: {paths['latest_rejected_csv']}")
    print("=" * 90)

    if final_mappings:
        final_preview_df = pd.DataFrame(final_mappings)
        print("[bold]Final mappings preview[/bold]")
        print(final_preview_df[["attack_id", "name", "tactics", "confidence", "disposition"]])
    else:
        print("[yellow]No final mappings were produced. Review the review and rejected mapping CSV files.[/yellow]")

    if review_mappings:
        review_preview_df = pd.DataFrame(review_mappings)
        print("[bold yellow]Review mappings preview[/bold yellow]")
        print(review_preview_df[["attack_id", "name", "tactics", "confidence", "review_reason"]])

    return {
        "paths": paths,
        "final": final_mappings,
        "review": review_mappings,
        "rejected": rejected,
        "candidates": candidates,
        "metadata": metadata,
        "explicit_ids": sorted(explicit_ids),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Map Lab 2.1 report evidence to current MITRE ATT&CK Enterprise techniques."
    )

    parser.add_argument(
        "--evidence",
        default=None,
        help="Path to Lab 2.1 evidence JSON. Defaults to latest outputs/lab2_1_report_osint_*.json.",
    )

    parser.add_argument(
        "--iocs",
        default=None,
        help="Path to Lab 2.1 IOC CSV. Defaults to outputs/lab2_1_latest_iocs.csv.",
    )

    parser.add_argument(
        "--attack-cache",
        default=None,
        help="Path to attack_enterprise_techniques.json. Defaults to outputs/attack_enterprise_techniques.json.",
    )

    parser.add_argument(
        "--model",
        default=None,
        help="Local Ollama model name. Defaults to the first installed model.",
    )

    parser.add_argument(
        "--candidate-count",
        type=int,
        default=80,
        help="Number of ATT&CK candidate techniques to provide to the LLM.",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip LLM proposal and only validate explicit ATT&CK IDs found in Lab 2.1 evidence.",
    )

    args = parser.parse_args()

    try:
        model = args.model

        if not args.no_ai:
            try:
                from tools.ollama_client import resolve_model
            except ModuleNotFoundError:
                from ollama_client import resolve_model

            model = resolve_model(args.model)

        run(
            evidence_path_arg=args.evidence,
            ioc_path_arg=args.iocs,
            attack_cache_arg=args.attack_cache,
            model=model or "",
            candidate_count=args.candidate_count,
            no_ai=args.no_ai,
        )
    except Exception as exc:
        print(f"[bold red]ERROR:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()