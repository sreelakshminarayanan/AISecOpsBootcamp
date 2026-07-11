# Module 2 - AI OSINT and ATT&CK Mapping Workbench

This lab turns a public threat report into extracted observables, grounded MITRE ATT&CK proposals, an analyst-approved Navigator layer, and a practical hunting pack.

The important rule is simple: the AI proposes, code validates, and the analyst approves. Model confidence can never make a mapping Final.

## What the lab does

1. Fetches a public HTML threat report using safe passive retrieval.
2. Extracts article text, links, CVEs, hashes, domains, URLs, IP addresses, emails, and ATT&CK IDs.
3. Saves the complete source text as numbered evidence chunks.
4. Uses a local Ollama model to propose ATT&CK mappings.
5. Flags weak evidence and out-of-candidate IDs for manual review while keeping valid ATT&CK IDs reviewable.
6. Requires the analyst to approve mappings in the Streamlit interface.
7. Generates a Navigator layer using approved mappings only.
8. Uses a second, stronger Ollama model to independently validate approved mappings and generate the hunting pack.
9. Schema-validates AI-generated SPL, KQL, hypotheses, log requirements, false positives, and triage steps.

## Requirements

- Python 3.11 or 3.12
- Ollama
- At least one Ollama model. Two models are recommended.
- Internet access for public report retrieval and ATT&CK dataset sync

## Linux setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
ollama pull llama3.1:8b
ollama pull qwen2.5:7b
streamlit run app.py
```

If Ollama is not already running, open another terminal and run:

```bash
ollama serve
```

## Windows PowerShell setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
ollama pull llama3.1:8b
ollama pull qwen2.5:7b
streamlit run app.py
```

If PowerShell blocks activation for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If Ollama is not already running, open another PowerShell window and run:

```powershell
ollama serve
```

## Lab workflow

### 1. Report to IOCs

- Paste a public threat report URL.
- Keep robots.txt enforcement enabled.
- Select whether you want the easy summary and analyst brief.
- Click `Analyze report`.
- Review the extracted observable candidates and rejected false positives.

Extracted values are candidates, not confirmed malicious indicators. Always check the source context.

### 2. ATT&CK Mapping

- Click `Sync latest Enterprise ATT&CK dataset` once.
- Click `Run AI ATT&CK mapping`.
- Review the exact source quote and evidence chunk for every proposal.
- Select `Approve for Final` only when the behavior supports the mapping.
- Add an analyst note when useful.
- Click `Save analyst decisions`.

Ungrounded and out-of-candidate mappings remain in Review with clear warnings. Malformed or unknown ATT&CK IDs are hard rejected. You can also add a valid ATT&CK ID manually and approve it. Analyst notes are optional.

### 3. Navigator Layer

- Click `Generate Navigator layer`.
- The layer uses approved mappings only.
- Download the JSON and import it into ATT&CK Navigator.

### 4. Hunting Pack

- Select a stronger `Validation and hunting model` in the sidebar.
- Click `Generate hunting pack`.
- Wait while the second model independently validates the approved mappings against the original source evidence.
- Review the AI-generated behavioral hypotheses, SPL, KQL, log requirements, false positives, triage steps, limitations, and detection opportunities.
- The output records which model generated the hunting pack.
- Tune indexes, sourcetypes, tables, fields, allowlists, and time windows before use.

### 5. Deliverables

Download the approved mapping, pending and rejected mappings, IOC CSV, Navigator layer, and hunting pack.

## Security controls

- Only public HTTP and HTTPS targets on standard ports are allowed.
- Local, private, link-local, and reserved destinations are blocked.
- Redirect destinations are checked before retrieval.
- HTML responses are limited to 5 MB.
- Report content is treated as untrusted prompt data.
- Exact source evidence is checked and clearly marked when it cannot be verified.
- Final status requires explicit analyst approval.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Important limitations

- This is passive retrieval only. It does not scan, exploit, authenticate, or bypass access controls.
- The summaries are AI-generated and must not be treated as source evidence.
- IOC extraction validates syntax and basic context only. It does not prove maliciousness.
- SPL and KQL are hunt starters. Tune and test them in your own telemetry.
- Use public or authorized sources only.
