# AI OSINT and ATT&CK Mapping Workbench

A single, local, AI assisted workbench that turns a public threat intelligence report into extracted observables, evidence grounded MITRE ATT&CK proposals, an analyst approved Navigator layer, and a schema validated SOC hunting pack.

The governing rule of the lab is deliberate and non negotiable:

> The AI proposes. Deterministic code validates. The analyst approves. Model confidence alone can never make a mapping final.

Everything runs locally against Ollama. No report content or evidence leaves the machine.

---

## Overview

Threat intelligence work is repetitive but high context: read a long vendor report, pull the indicators, drop the false positives, summarise the behavior, map it to ATT&CK, and turn all of that into hunts. Traditional tooling is strong at extraction and enrichment. Local language models are useful for interpretation, summarisation, and drafting. This lab combines both without letting the model become the source of truth.

The workbench is a five tab Streamlit application that walks an analyst through the full pipeline:

1. **Report to IOCs.** Fetch a public report passively, extract article text, links, and observable candidates, and generate two AI summaries (an easy summary and an analyst brief).
2. **ATT&CK Mapping.** Sync the current Enterprise ATT&CK dataset, ask a local model to propose mappings grounded in exact source quotes, then approve or reject each one by hand.
3. **Navigator Layer.** Convert only the analyst approved mappings into an importable ATT&CK Navigator layer, tagged with the ATT&CK version that was actually synced.
4. **Hunting Pack.** Use a second, stronger local model to independently re validate the approved mappings against the original evidence and generate a schema validated hunting pack.
5. **Deliverables.** Download every artifact and walk the analyst quality gate.

The two model split is intentional. A first model does research and proposes mappings. A second, independent model validates those decisions and writes the hunts, which reduces single model bias and catches unsupported mappings.

---

## Architecture

### End to end flow

```text
Public threat report URL
  -> passive fetch (robots.txt check, SSRF guard, size cap)
  -> article text, links, and observable candidates (iocextract)
  -> false positive rejection
  -> stable evidence chunks (SRC-0001, SRC-0002, ...)
  -> local model A: easy summary + analyst brief
  -> sync current Enterprise ATT&CK dataset into a local cache
  -> local model A: propose ATT&CK mappings grounded in exact quotes
  -> code validates every technique ID and every quote
  -> ALL valid proposals land in Review, nothing auto promotes
  -> analyst approves mappings in the UI (optionally adds notes)
  -> approved mappings only -> ATT&CK Navigator layer
  -> local model B: independently validate approved mappings vs evidence
  -> local model B: generate schema validated hunts (SPL, KQL, hypotheses)
  -> downloads + analyst quality gate
```

### Design principles

- **Human in the loop by construction.** The mapping engine has an empty set of automatic final confidences. Every valid model proposal enters Review. Only an explicit analyst approval in the UI promotes a mapping to Final.
- **Evidence grounding.** The source article is split into numbered chunks. The model must return, for every mapping, an exact contiguous quote and the chunk ID it came from. The code checks that the quote actually appears in that chunk. Unverified quotes are flagged but kept reviewable, so nothing is silently dropped.
- **Two independent models.** Model A researches and proposes. Model B validates and hunts. They are selected separately in the sidebar and can be different models.
- **Model independence.** No model name is hardcoded anywhere. The sidebar reads the installed models from Ollama and lets you pick. The Ollama host is configurable with `OLLAMA_HOST`.
- **Current ATT&CK, not model memory.** Technique IDs are validated against a freshly synced Enterprise ATT&CK cache, and the real release version is recorded and carried into the Navigator layer.
- **Structured output enforcement.** Both the mapping proposals and the hunting pack are constrained to a JSON schema and validated with `jsonschema` before anything is saved.
- **Prompt injection awareness.** Report text is treated as untrusted. The mapping prompt wraps source chunks in explicit untrusted markers and instructs the model never to follow instructions found inside report content.
- **Safe retrieval.** Fetching is passive only. Hostnames are resolved and any target on a local, private, link local, or reserved network is rejected before a request is made. Response size is capped.

---

## Core code components

```text
module2-ai-osint-lab/
  app.py                                  Unified Streamlit interface (5 tabs)
  requirements.txt
  tools/
    ollama_client.py                      Local model client and model discovery
    threat_report_ioc_extractor.py        Safe fetch, extraction, evidence chunks
    attack_dataset_sync.py                Enterprise ATT&CK sync and versioning
    attack_mapping_engine.py              Grounded proposals and analyst decisions
    attack_navigator_layer_generator.py   Navigator layer from approved mappings
    ai_hunting_pack_generator.py          Second model validation and hunts
    hunting_pack_generator.py             Deterministic SPL/KQL starter pack
    cleanup_outputs.py                    Reset generated artifacts
  tests/                                  Unit tests for the safety guarantees
```

| Component | Responsibility |
|-----------|----------------|
| `app.py` | The single entry point. Renders the five tab workbench, exposes the two model selectors and controls, and orchestrates every stage in process. Persists artifact paths in session state so each tab consumes the previous stage. |
| `tools/ollama_client.py` | Talks to a local Ollama instance. Discovers installed models through the tags endpoint, exposes a reachability check, resolves a usable model, and provides plain text and structured JSON calls. Honors the `OLLAMA_HOST` environment variable and fails clearly when Ollama is down. |
| `tools/threat_report_ioc_extractor.py` | Passive report retrieval and evidence building. Performs the robots.txt check, the SSRF guard that blocks private and reserved networks, and a response size cap. Extracts article text, links, and observable candidates (CVEs, hashes, domains, URLs, IP addresses, emails, and ATT&CK IDs) using `iocextract`, rejects obvious false positives, and splits the source text into stable numbered evidence chunks. Also holds the summary and analyst brief prompts and the artifact writer. |
| `tools/attack_dataset_sync.py` | Downloads the current Enterprise ATT&CK STIX bundle (the always latest release), parses techniques and tactics, and records the true ATT&CK release version from the collection object into the cache metadata. Version aware by design, not pinned to a number. |
| `tools/attack_mapping_engine.py` | The heart of the mapping stage. Scores candidate techniques against the report, builds a prompt injection hardened prompt, requests schema constrained proposals, and verifies every returned quote against its source chunk. Keeps all valid technique IDs reviewable, hard rejects only malformed or unknown IDs, supports manual mapping recovery, and persists analyst approve or reject decisions with optional notes. |
| `tools/attack_navigator_layer_generator.py` | Converts the analyst approved mappings into an importable ATT&CK Navigator JSON layer, tagged with the ATT&CK version that was synced. Refuses to build a layer if the cache has no recorded version. |
| `tools/ai_hunting_pack_generator.py` | The second model stage. An independent, stronger model re validates each approved mapping against the original evidence, then generates technique specific hunts: hypotheses, Splunk SPL, Microsoft Sentinel or Defender KQL, log requirements, false positives, triage steps, and detection opportunities. Output is schema validated, and unapproved technique IDs are refused. |
| `tools/hunting_pack_generator.py` | A deterministic, template based SPL and KQL starter pack generator. Useful as an offline or CLI alternative to the AI hunting pack when no second model is available. |
| `tools/cleanup_outputs.py` | Clears generated Lab 2.1 and Lab 2.2 artifacts so a session can restart clean, with an option to keep the ATT&CK cache to avoid re downloading. |
| `tests/` | Unit tests that lock in the safety properties: analyst gated finals, out of candidate and unverified evidence staying reviewable, manual override auditing, SSRF blocking, stable chunk IDs, behavioral hunts, and refusal of unapproved technique IDs. |

### Generated artifacts

All output is written to `outputs/` (created at runtime, git ignored):

```text
outputs/lab2_1_report_osint_<host>_<timestamp>.json     Full evidence and chunks
outputs/lab2_1_iocs_<host>_<timestamp>.csv              Observable candidates
outputs/lab2_1_latest_iocs.csv                          Latest observables for mapping
outputs/lab2_1_easy_summary_<host>_<timestamp>.md
outputs/lab2_1_ai_brief_<host>_<timestamp>.md

outputs/attack_enterprise_techniques.json               Local ATT&CK cache
outputs/attack_enterprise_metadata.json                 Includes attack_version

outputs/lab2_2_latest_attack_mapping.csv                Approved final mappings
outputs/lab2_2_latest_attack_mapping_review.csv         Pending review mappings
outputs/lab2_2_latest_attack_mapping_rejected.csv       Malformed or unknown IDs
outputs/lab2_2_latest_attack_navigator_layer.json       Navigator import
outputs/lab2_2_latest_hunting_pack.md                   Hunting pack (Markdown)
outputs/lab2_2_latest_hunting_pack.json                 Hunting pack (JSON)
```

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Python | 3.11 or 3.12 |
| Ollama | Installed and running locally. See https://ollama.com |
| Models | At least one local model. Two are recommended: one research model for proposals and one stronger model for validation and hunting. |
| Network | Internet access for public report retrieval and the ATT&CK dataset sync. |
| Disk | A few GB for the local models plus the ATT&CK cache. |

Recommended model pairing (any two installed models work):

```text
Research and ATT&CK model:   llama3.1:8b
Validation and hunting model: qwen2.5:7b
```

Python dependencies (pinned in `requirements.txt`): `requests`, `beautifulsoup4`, `lxml`, `pandas`, `rich`, `tldextract`, `iocextract`, `jsonschema`, `streamlit`.

---

## How to run on Windows

Use PowerShell from inside the `module2-ai-osint-lab` folder.

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Pull at least one model (two recommended)
ollama pull llama3.1:8b
ollama pull qwen2.5:7b

# 4. Launch the workbench
streamlit run app.py
```

If PowerShell blocks the activation script, allow it for the current user and try the activation line again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If Ollama is not already running as a service, open a second PowerShell window and start it:

```powershell
ollama serve
```

Optional, point the app at a remote Ollama host:

```powershell
$env:OLLAMA_HOST = "http://192.168.1.10:11434"
```

Streamlit opens the app in your browser, usually at http://localhost:8501

---

## How to run on Linux

Use a terminal from inside the `module2-ai-osint-lab` folder.

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Pull at least one model (two recommended)
ollama pull llama3.1:8b
ollama pull qwen2.5:7b

# 4. Launch the workbench
streamlit run app.py
```

If Ollama is not already running, start it in a second terminal:

```bash
ollama serve
```

Optional, point the app at a remote Ollama host:

```bash
export OLLAMA_HOST="http://192.168.1.10:11434"
```

Streamlit prints a local URL, usually http://localhost:8501

---

## Using the workbench

1. In the sidebar, confirm Ollama is online and pick a research model and a validation and hunting model.
2. **Report to IOCs.** Paste a public report URL and click Analyze report. Review the observable candidates, rejected false positives, and the two AI summaries.
3. **ATT&CK Mapping.** Click Sync latest Enterprise ATT&CK dataset once, then Run AI ATT&CK mapping. Review each proposal, add any missing technique by hand, tick Approve for the mappings you accept, add optional notes, then Save analyst decisions.
4. **Navigator Layer.** Click Generate Navigator layer and download the JSON. Import it at https://mitre-attack.github.io/attack-navigator/
5. **Hunting Pack.** Click Generate hunting pack. The second model validates your approved mappings and writes the hunts.
6. **Deliverables.** Download every artifact and confirm the analyst quality gate.

A good starter report for testing:

```text
https://unit42.paloaltonetworks.com/ak47-activity-linked-to-sharepoint-vulnerabilities/
```

---

## Running the tests

The unit tests exercise the safety guarantees offline and do not require Ollama or network access.

```bash
python -m unittest discover -s tests -v
```

They cover analyst gated final mappings, out of candidate and unverified evidence staying reviewable, manual override auditing, SSRF blocking of private targets, stable evidence chunk IDs, behavioral rather than IOC only hunts, and refusal to hunt unapproved technique IDs.

---

## Operating notes and limits

- SPL and KQL are starter hunts, not production detections. Tune them to your SIEM field names before operational use.
- A valid ATT&CK ID does not mean a correct mapping. The analyst approval gate exists for exactly this reason.
- Observable candidates must be verified against the source report before they are treated as attributable indicators.
- Use public or authorized report sources only. Retrieval is passive: no scanning, no exploitation, no authentication bypass, and no private content.
