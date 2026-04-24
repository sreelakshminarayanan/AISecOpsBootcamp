import argparse
import json
import ipaddress
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import iocextract
import pandas as pd
import requests
import tldextract
from bs4 import BeautifulSoup
from rich import print

try:
    from tools.ollama_client import ask_ollama
except ModuleNotFoundError:
    from ollama_client import ask_ollama


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

DEFAULT_USER_AGENT = "AI-SecOps-Bootcamp-OSINT-Lab/1.0"

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MITRE_TECHNIQUE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

NON_IOC_FILE_SUFFIXES = {
    "js",
    "css",
    "svg",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "map",
    "json",
    "xml",
    "txt",
    "pdf",
    "html",
    "htm",
    "php",
    "aspx",
    "jsp",
}

COMMON_BENIGN_DOMAINS = {
    "github.com",
    "gmpg.org",
    "schema.org",
    "w3.org",
    "wordpress.org",
    "google.com",
    "googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "gstatic.com",
    "recaptcha.net",
    "cloudflare.com",
    "cloudflareinsights.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "instagram.com",
    "paloaltonetworks.com",
}

KNOWN_VALID_TLDS = {
    "com",
    "net",
    "org",
    "io",
    "co",
    "edu",
    "gov",
    "mil",
    "info",
    "biz",
    "ru",
    "cn",
    "uk",
    "de",
    "jp",
    "in",
    "au",
    "ca",
    "us",
    "fr",
    "it",
    "nl",
    "br",
    "es",
    "ch",
    "se",
    "no",
    "fi",
    "pl",
    "kr",
    "tw",
    "hk",
    "sg",
    "dev",
    "app",
    "cloud",
    "site",
    "online",
    "xyz",
    "top",
    "shop",
    "live",
    "cc",
    "me",
    "tv",
    "pro",
}

CODE_ARTIFACT_TERMS = {
    "indexof",
    "execute",
    "prototype",
    "constructor",
    "buildname",
    "globalconfig",
    "function",
    "return",
    "window",
    "document",
    "frontend",
    "backend",
    "webpack",
    "chunk",
    "runtime",
    "polyfill",
    "localhost",
}


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    parsed = urlparse(url)

    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    if not parsed.netloc:
        raise ValueError("URL must include a valid hostname.")

    return url


def clean_text(text: str) -> str:
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)
    return text.strip()


def get_registered_domain(value: str) -> str:
    extracted = tldextract.extract(value)

    if not extracted.domain or not extracted.suffix:
        return ""

    return f"{extracted.domain}.{extracted.suffix}".lower()


def get_host_or_domain(value: str) -> str:
    value = refang_basic(value)

    parsed = urlparse(value)

    if parsed.netloc:
        return parsed.netloc.lower().strip(".")

    return value.lower().strip(".")


def get_robots_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    return f"{parsed.scheme}://{parsed.netloc}/robots.txt"


def check_robots(target_url: str, user_agent: str) -> dict:
    robots_url = get_robots_url(target_url)
    rp = RobotFileParser()
    rp.set_url(robots_url)

    try:
        rp.read()
        return {
            "robots_url": robots_url,
            "robots_checked": True,
            "allowed": rp.can_fetch(user_agent, target_url),
            "error": "",
        }
    except Exception as exc:
        return {
            "robots_url": robots_url,
            "robots_checked": False,
            "allowed": None,
            "error": str(exc),
        }


def fetch_html(url: str, user_agent: str) -> dict:
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=45,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch URL: {exc}") from exc

    content_type = response.headers.get("content-type", "")

    return {
        "input_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": content_type,
        "headers": dict(response.headers),
        "html": response.text or "",
    }


def extract_article_text(soup: BeautifulSoup) -> dict:
    soup_copy = BeautifulSoup(str(soup), "lxml")

    for tag in soup_copy(["script", "style", "noscript", "svg", "canvas"]):
        tag.extract()

    title = soup_copy.title.string.strip() if soup_copy.title and soup_copy.title.string else ""

    meta = {}

    for tag in soup_copy.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        value = tag.get("content")

        if key and value:
            meta[key.lower()] = clean_text(value)

    candidate_selectors = [
        "article",
        "main",
        "[role='main']",
        ".post-content",
        ".entry-content",
        ".article-content",
        ".blog-content",
        ".content",
        ".td-post-content",
        ".single-post-content",
    ]

    candidates = []

    for selector in candidate_selectors:
        for node in soup_copy.select(selector):
            text = clean_text(node.get_text(" ", strip=True))

            if len(text) > 500:
                candidates.append(
                    {
                        "selector": selector,
                        "length": len(text),
                        "text": text,
                    }
                )

    if candidates:
        candidates.sort(key=lambda item: item["length"], reverse=True)
        chosen = candidates[0]
        article_text = chosen["text"]
        selector_used = chosen["selector"]
    else:
        article_text = clean_text(soup_copy.get_text(" ", strip=True))
        selector_used = "body"

    return {
        "title": title,
        "meta": meta,
        "article_text": article_text[:70000],
        "article_text_length": len(article_text),
        "article_selector_used": selector_used,
    }


def extract_links(soup: BeautifulSoup, base_url: str) -> list:
    links = []

    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "").strip()

        if not href:
            continue

        if href.startswith("#") or href.lower().startswith(("javascript:", "mailto:", "tel:")):
            continue

        absolute_url = urljoin(base_url, href)
        parsed = urlparse(absolute_url)

        if parsed.scheme not in {"http", "https"}:
            continue

        links.append(
            {
                "url": absolute_url,
                "text": clean_text(tag.get_text(" ", strip=True))[:200],
                "host": parsed.netloc.lower(),
                "registered_domain": get_registered_domain(absolute_url),
            }
        )

    seen = set()
    deduped = []

    for link in links:
        if link["url"] in seen:
            continue

        seen.add(link["url"])
        deduped.append(link)

    return deduped


def refang_basic(value: str) -> str:
    if value is None:
        return ""

    replacements = {
        "hxxps://": "https://",
        "hxxp://": "http://",
        "HXXPS://": "https://",
        "HXXP://": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[dot]": ".",
        "(dot)": ".",
        " dot ": ".",
    }

    output = str(value).strip()

    for old, new in replacements.items():
        output = output.replace(old, new)

    return output.strip(".,;:'\"()[]{}<>")


def looks_like_file_artifact(value: str) -> bool:
    lowered = value.lower().strip()

    if not lowered or "." not in lowered:
        return False

    last_part = lowered.rsplit(".", 1)[-1]

    return last_part in NON_IOC_FILE_SUFFIXES


def looks_like_code_artifact(value: str) -> bool:
    lowered = value.lower().strip()

    if not lowered:
        return True

    if any(term in lowered for term in CODE_ARTIFACT_TERMS):
        return True

    parts = lowered.split(".")

    if len(parts) >= 3 and parts[-1] not in KNOWN_VALID_TLDS:
        return True

    if "_" in lowered:
        return True

    return False


def is_valid_ipv4(value: str) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False, "invalid_ip"

    if ip.version != 4:
        return False, "not_ipv4"

    if ip.is_loopback:
        return False, "loopback_ip"

    if ip.is_multicast:
        return False, "multicast_ip"

    if ip.is_unspecified:
        return False, "unspecified_ip"

    if ip.is_private:
        return False, "private_ip"

    if ip.is_reserved:
        return False, "reserved_ip"

    return True, "valid_public_ipv4"


def is_valid_domain_candidate(value: str) -> tuple[bool, str, str, str]:
    candidate = get_host_or_domain(value)

    if not candidate:
        return False, "empty", "", ""

    if len(candidate) > 253:
        return False, "too_long", "", ""

    if " " in candidate:
        return False, "contains_space", "", ""

    if "/" in candidate or "\\" in candidate:
        return False, "contains_path_separator", "", ""

    if candidate.startswith(".") or candidate.endswith("."):
        return False, "bad_dot_position", "", ""

    if looks_like_file_artifact(candidate):
        return False, "file_or_asset_artifact", "", ""

    if looks_like_code_artifact(candidate):
        return False, "code_artifact", "", ""

    extracted = tldextract.extract(candidate)

    if not extracted.domain or not extracted.suffix:
        return False, "missing_domain_or_suffix", "", ""

    if extracted.suffix.lower() in NON_IOC_FILE_SUFFIXES:
        return False, "suffix_is_file_extension", "", ""

    registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()

    if registered_domain in COMMON_BENIGN_DOMAINS:
        return False, "common_benign_domain", candidate, registered_domain

    return True, "valid_domain_candidate", candidate, registered_domain


def add_observable(
    rows: list,
    ioc_type: str,
    value: str,
    source: str,
    confidence: str,
    reason: str,
    registered_domain: str = "",
):
    rows.append(
        {
            "type": ioc_type,
            "value": value,
            "registered_domain": registered_domain,
            "source": source,
            "confidence": confidence,
            "reason": reason,
        }
    )


def extract_explicit_domain_candidates(text: str) -> set:
    candidates = set()

    defanged_patterns = [
        r"\b[a-zA-Z0-9-]+(?:\[\.\]|\(\.\)|\{\.\}|\.)(?:[a-zA-Z0-9-]+(?:\[\.\]|\(\.\)|\{\.\}|\.))*[a-zA-Z]{2,}\b",
        r"\b[a-zA-Z0-9-]+(?:\[dot\]|\(dot\)| dot )[a-zA-Z]{2,}\b",
    ]

    for pattern in defanged_patterns:
        for match in re.findall(pattern, text):
            candidates.add(refang_basic(match.lower()))

    return candidates


def extract_iocs_from_text(text: str) -> dict:
    text = text or ""

    raw_urls = sorted(set(refang_basic(value) for value in iocextract.extract_urls(text, refang=True)))
    raw_ipv4s = sorted(set(iocextract.extract_ipv4s(text, refang=True)))
    raw_emails = sorted(set(EMAIL_REGEX.findall(text)))
    raw_md5 = sorted(set(iocextract.extract_md5_hashes(text)))
    raw_sha1 = sorted(set(iocextract.extract_sha1_hashes(text)))
    raw_sha256 = sorted(set(iocextract.extract_sha256_hashes(text)))
    raw_cves = sorted(set(value.upper() for value in CVE_REGEX.findall(text)))
    raw_mitre_techniques = sorted(set(MITRE_TECHNIQUE_REGEX.findall(text)))
    raw_domains = sorted(extract_explicit_domain_candidates(text))

    accepted_rows = []
    rejected_rows = []
    accepted_domain_values = set()

    for url in raw_urls:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            add_observable(rejected_rows, "urls", url, "iocextract_url", "rejected", "unsupported_url_scheme")
            continue

        host = parsed.netloc.lower().strip(".")

        valid, reason, normalized_host, registered_domain = is_valid_domain_candidate(host)

        if not valid:
            add_observable(rejected_rows, "urls", url, "iocextract_url", "rejected", reason)
            continue

        accepted_domain_values.add(normalized_host)

        add_observable(
            accepted_rows,
            "urls",
            url,
            "iocextract_url",
            "high",
            "url_extracted_from_article_text",
            registered_domain,
        )

    for ip in raw_ipv4s:
        valid, reason = is_valid_ipv4(ip)

        if valid:
            add_observable(
                accepted_rows,
                "ipv4s",
                ip,
                "iocextract_ipv4",
                "high",
                "public_ipv4_extracted_from_article_text",
            )
        else:
            add_observable(
                rejected_rows,
                "ipv4s",
                ip,
                "iocextract_ipv4",
                "rejected",
                reason,
            )

    for email in raw_emails:
        add_observable(
            accepted_rows,
            "emails",
            email,
            "regex_email",
            "medium",
            "email_address_extracted_from_article_text",
            get_registered_domain(email.split("@")[-1]) if "@" in email else "",
        )

    for value in raw_md5:
        add_observable(
            accepted_rows,
            "md5",
            value.lower(),
            "iocextract_hash",
            "high",
            "md5_hash_extracted_from_article_text",
        )

    for value in raw_sha1:
        add_observable(
            accepted_rows,
            "sha1",
            value.lower(),
            "iocextract_hash",
            "high",
            "sha1_hash_extracted_from_article_text",
        )

    for value in raw_sha256:
        add_observable(
            accepted_rows,
            "sha256",
            value.lower(),
            "iocextract_hash",
            "high",
            "sha256_hash_extracted_from_article_text",
        )

    for cve in raw_cves:
        add_observable(
            accepted_rows,
            "cves",
            cve,
            "regex_cve",
            "high",
            "cve_pattern_extracted_from_article_text",
        )

    for technique in raw_mitre_techniques:
        add_observable(
            accepted_rows,
            "mitre_techniques",
            technique,
            "regex_mitre",
            "medium",
            "mitre_attack_technique_id_pattern",
        )

    for domain in raw_domains:
        valid, reason, normalized_domain, registered_domain = is_valid_domain_candidate(domain)

        if not valid:
            add_observable(
                rejected_rows,
                "domains",
                domain,
                "domain_pattern",
                "rejected",
                reason,
            )
            continue

        accepted_domain_values.add(normalized_domain)

    for domain in sorted(accepted_domain_values):
        valid, reason, normalized_domain, registered_domain = is_valid_domain_candidate(domain)

        if valid:
            add_observable(
                accepted_rows,
                "domains",
                normalized_domain,
                "url_host_or_explicit_domain_pattern",
                "medium",
                "domain_associated_with_extracted_observable",
                registered_domain,
            )
        else:
            add_observable(
                rejected_rows,
                "domains",
                domain,
                "url_host_or_explicit_domain_pattern",
                "rejected",
                reason,
            )

    accepted_rows = dedupe_observable_rows(accepted_rows)
    rejected_rows = dedupe_observable_rows(rejected_rows)

    def values_for(ioc_type: str) -> list:
        return sorted(
            set(row["value"] for row in accepted_rows if row["type"] == ioc_type)
        )

    return {
        "urls": values_for("urls"),
        "domains": values_for("domains"),
        "ipv4s": values_for("ipv4s"),
        "emails": values_for("emails"),
        "md5": values_for("md5"),
        "sha1": values_for("sha1"),
        "sha256": values_for("sha256"),
        "cves": values_for("cves"),
        "mitre_techniques": values_for("mitre_techniques"),
        "_accepted_rows": accepted_rows,
        "_rejected_rows": rejected_rows,
    }


def dedupe_observable_rows(rows: list) -> list:
    seen = set()
    deduped = []

    for row in rows:
        key = (
            row.get("type", ""),
            row.get("value", ""),
            row.get("source", ""),
            row.get("reason", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(row)

    return deduped


def build_ioc_rows(iocs: dict) -> list:
    rows = iocs.get("_accepted_rows")

    if rows is None:
        rows = []

        for ioc_type, values in iocs.items():
            if ioc_type.startswith("_"):
                continue

            for value in values:
                rows.append(
                    {
                        "type": ioc_type,
                        "value": value,
                        "registered_domain": get_registered_domain(value)
                        if ioc_type in {"urls", "domains", "emails"}
                        else "",
                        "source": "",
                        "confidence": "",
                        "reason": "",
                    }
                )

    return [
        {
            "type": row.get("type", ""),
            "value": row.get("value", ""),
            "registered_domain": row.get("registered_domain", ""),
            "source": row.get("source", ""),
            "confidence": row.get("confidence", ""),
            "reason": row.get("reason", ""),
        }
        for row in rows
    ]


def build_rejected_rows(iocs: dict) -> list:
    return [
        {
            "type": row.get("type", ""),
            "value": row.get("value", ""),
            "registered_domain": row.get("registered_domain", ""),
            "source": row.get("source", ""),
            "confidence": row.get("confidence", ""),
            "reason": row.get("reason", ""),
        }
        for row in iocs.get("_rejected_rows", [])
    ]


def sanitized_iocs_for_prompt(iocs: dict) -> dict:
    return {
        key: values
        for key, values in iocs.items()
        if not key.startswith("_")
    }


def build_ai_prompt(source_url: str, article: dict, iocs: dict, links: list) -> str:
    compact_iocs = json.dumps(sanitized_iocs_for_prompt(iocs), indent=2)
    compact_links = json.dumps(links[:80], indent=2)
    article_excerpt = article["article_text"][:18000]

    return f"""
You are a defensive cyber threat intelligence analyst.

Analyze the public threat report below.
Use only the evidence provided.
Do not invent IOCs, malware names, actor names, CVEs, victim details, or vendor claims.
If no IOC is found for a category, say "none observed in extracted text".
Separate confirmed observations from analyst hypotheses.
Do not call an observable malicious unless the provided article text or extracted indicators support that conclusion.

Required output:
1. Executive Summary
2. Report Topic and Threat Context
3. Extracted IOCs by Type
4. CVEs and Vulnerability Context
5. MITRE ATT&CK Behaviors Mentioned or Implied
6. Priority Assessment for SOC Teams
7. Detection and Hunting Ideas
8. Analyst Caveats
9. Recommended Next Actions

Source URL:
{source_url}

Page Title:
{article["title"]}

Meta Description:
{article["meta"].get("description", article["meta"].get("og:description", ""))}

Validated Extracted IOCs:
{compact_iocs}

Sample Links:
{compact_links[:6000]}

Article Text:
{article_excerpt}
"""
def build_easy_summary_prompt(source_url: str, article: dict, iocs: dict, links: list) -> str:
    compact_iocs = json.dumps(sanitized_iocs_for_prompt(iocs), indent=2)
    article_excerpt = article["article_text"][:18000]

    return f"""
You are a cyber security instructor explaining a threat intelligence report to junior SOC analysts.

Create an easy-to-understand summary of the report.
Use only the evidence provided.
Do not invent IOCs, malware names, actor names, CVEs, victim details, or claims.
If something is uncertain, clearly say it is uncertain.
Avoid jargon where possible. If jargon is necessary, explain it in simple language.

Required output format:

# Easy Threat Report Summary

## 1. What is this report about?
Explain the report in plain English.

## 2. Who or what is being targeted?
Summarize affected technologies, sectors, products, or users if mentioned. If not mentioned, say not clearly stated in the extracted text.

## 3. What did the attacker do?
Explain the attack flow in simple steps.

## 4. What vulnerabilities or CVEs are mentioned?
List CVEs from the extracted evidence and explain why they matter in simple words.

## 5. What IOCs were found?
Summarize extracted indicators by type:
- URLs
- Domains
- IP addresses
- Hashes
- Emails
- MITRE technique IDs

If a category has no indicators, say none observed in extracted text.

## 6. Why should a SOC analyst care?
Explain the security relevance in practical terms.

## 7. What should defenders do next?
Give practical next steps such as enrich IOCs, check logs, search EDR/SIEM, patch exposed systems, validate detections, and monitor for related activity.

## 8. What is uncertain?
List limitations and caveats.

Source URL:
{source_url}

Page Title:
{article["title"]}

Meta Description:
{article["meta"].get("description", article["meta"].get("og:description", ""))}

Validated Extracted IOCs:
{compact_iocs}

Article Text:
{article_excerpt}
"""

def save_outputs(source_url: str, evidence: dict, ai_brief: str, easy_summary: str = "") -> dict:
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    host = urlparse(source_url).netloc or "report"
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)

    json_path = OUTPUT_DIR / f"lab2_1_report_osint_{safe_host}_{timestamp}.json"
    ioc_csv_path = OUTPUT_DIR / f"lab2_1_iocs_{safe_host}_{timestamp}.csv"
    rejected_csv_path = OUTPUT_DIR / f"lab2_1_rejected_false_positives_{safe_host}_{timestamp}.csv"
    links_csv_path = OUTPUT_DIR / f"lab2_1_links_{safe_host}_{timestamp}.csv"
    brief_path = OUTPUT_DIR / f"lab2_1_ai_brief_{safe_host}_{timestamp}.md"
    easy_summary_path = OUTPUT_DIR / f"lab2_1_easy_summary_{safe_host}_{timestamp}.md"

    latest_iocs_path = OUTPUT_DIR / "lab2_1_latest_iocs.csv"
    latest_rejected_path = OUTPUT_DIR / "lab2_1_latest_rejected_false_positives.csv"
    latest_easy_summary_path = OUTPUT_DIR / "lab2_1_latest_easy_summary.md"

    json_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    brief_path.write_text(ai_brief or "", encoding="utf-8")
    easy_summary_path.write_text(easy_summary or "", encoding="utf-8")
    latest_easy_summary_path.write_text(easy_summary or "", encoding="utf-8")

    accepted_df = pd.DataFrame(build_ioc_rows(evidence["iocs"]))
    rejected_df = pd.DataFrame(build_rejected_rows(evidence["iocs"]))
    links_df = pd.DataFrame(evidence.get("links", []))

    accepted_df.to_csv(ioc_csv_path, index=False)
    accepted_df.to_csv(latest_iocs_path, index=False)

    rejected_df.to_csv(rejected_csv_path, index=False)
    rejected_df.to_csv(latest_rejected_path, index=False)

    links_df.to_csv(links_csv_path, index=False)

    return {
        "json": json_path,
        "ioc_csv": ioc_csv_path,
        "rejected_csv": rejected_csv_path,
        "links_csv": links_csv_path,
        "brief": brief_path,
        "easy_summary": easy_summary_path,
        "latest_iocs": latest_iocs_path,
        "latest_rejected": latest_rejected_path,
        "latest_easy_summary": latest_easy_summary_path,
    }

def build_evidence(url: str, fetched: dict, article: dict, links: list, iocs: dict, robots: dict) -> dict:
    clean_ioc_counts = {
        ioc_type: len(values)
        for ioc_type, values in iocs.items()
        if not ioc_type.startswith("_")
    }

    return {
        "scan_type": "threat_report_url_ioc_extraction",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "input_url": url,
        "final_url": fetched["final_url"],
        "http": {
            "status_code": fetched["status_code"],
            "content_type": fetched["content_type"],
            "server": fetched["headers"].get("Server"),
            "x_powered_by": fetched["headers"].get("X-Powered-By"),
        },
        "robots": robots,
        "article": {
            "title": article["title"],
            "meta": article["meta"],
            "article_text_length": article["article_text_length"],
            "article_selector_used": article["article_selector_used"],
            "article_text_preview": article["article_text"][:4000],
        },
        "iocs": iocs,
        "ioc_counts": clean_ioc_counts,
        "accepted_ioc_count": len(iocs.get("_accepted_rows", [])),
        "rejected_false_positive_count": len(iocs.get("_rejected_rows", [])),
        "links": links,
        "link_count": len(links),
    }


def run(url: str, model: str, user_agent: str, respect_robots: bool, generate_ai: bool = True):
    url = normalize_url(url)

    print(f"[bold]Source URL:[/bold] {url}")

    robots = check_robots(url, user_agent)
    print("[bold]robots.txt result:[/bold]")
    print(robots)

    if respect_robots and robots.get("allowed") is False:
        print("[red]robots.txt does not allow this fetch for the configured user agent. Stopping.[/red]")
        return

    print("[bold]Fetching report page...[/bold]")
    fetched = fetch_html(url, user_agent)

    if fetched["status_code"] >= 400:
        raise RuntimeError(f"HTTP error {fetched['status_code']}")

    if not fetched["html"]:
        raise RuntimeError("No HTML content returned. This MVP expects a public HTML threat report page.")

    soup = BeautifulSoup(fetched["html"], "lxml")

    print("[bold]Extracting article text...[/bold]")
    article = extract_article_text(soup)

    print("[bold]Extracting links...[/bold]")
    links = extract_links(soup, fetched["final_url"])

    print("[bold]Extracting and validating IOCs from article text...[/bold]")

    extraction_text = "\n".join(
        [
            article["title"],
            article["meta"].get("description", ""),
            article["meta"].get("og:description", ""),
            article["article_text"],
        ]
    )

    iocs = extract_iocs_from_text(extraction_text)
    evidence = build_evidence(url, fetched, article, links, iocs, robots)

    print("[bold]IOC counts:[/bold]")
    print(evidence["ioc_counts"])
    print(f"Accepted observables: {evidence['accepted_ioc_count']}")
    print(f"Rejected false positives: {evidence['rejected_false_positive_count']}")

    ai_brief = ""
    easy_summary = ""


    if generate_ai:
        print("[bold]Generating local AI report summary...[/bold]")
        ai_brief = ask_ollama(
            build_ai_prompt(fetched["final_url"], article, iocs, links),
            model=model,
            temperature=0.2,
            num_predict=1400,
        )

        print("[bold]Generating easy-to-understand threat report summary...[/bold]")
        easy_summary = ask_ollama(
            build_easy_summary_prompt(fetched["final_url"], article, iocs, links),
            model=model,
            temperature=0.2,
            num_predict=1400,
        )

    paths = save_outputs(fetched["final_url"], evidence, ai_brief, easy_summary)

    print("[bold green]Lab 2.1 threat report IOC extraction complete.[/bold green]")
    print(f"Evidence JSON: {paths['json']}")
    print(f"IOC CSV: {paths['ioc_csv']}")
    print(f"Rejected false positives CSV: {paths['rejected_csv']}")
    print(f"Latest IOC CSV: {paths['latest_iocs']}")
    print(f"Links CSV: {paths['links_csv']}")
    print(f"Easy summary: {paths['easy_summary']}")

    if easy_summary:
        print("\n[bold]Easy Summary Preview[/bold]\n")
        print(easy_summary)

    if ai_brief:
        print("\n[bold]AI Analyst Brief Preview[/bold]\n")
        print(ai_brief)


def main():
    parser = argparse.ArgumentParser(
        description="Lab 2.1 MVP: Extract and validate IOCs from a public threat report URL."
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Public threat report URL to analyze.",
    )

    parser.add_argument(
        "--model",
        default="llama3.2:3b",
        help="Ollama model name.",
    )

    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent used for passive page retrieval.",
    )

    parser.add_argument(
        "--respect-robots",
        action="store_true",
        help="Stop if robots.txt disallows fetching the page.",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip local AI brief generation.",
    )

    args = parser.parse_args()

    run(
        url=args.url,
        model=args.model,
        user_agent=args.user_agent,
        respect_robots=args.respect_robots,
        generate_ai=not args.no_ai,
    )


if __name__ == "__main__":
    main()