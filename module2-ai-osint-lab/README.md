# Module 2 - AI OSINT and ATT&CK Mapping Workbench

One Streamlit interface for the full analyst workflow: turn a public threat report
into validated IOCs, map the behavior to current MITRE ATT&CK, build a Navigator
layer, and generate a SOC hunting pack. Every AI step runs on a local Ollama
model. The LLM proposes, the local ATT&CK cache validates every technique ID, and
the analyst decides.

## What runs where

| Stage | Tab | AI | Validation |
|-------|-----|----|-----------|
| Report to IOCs | 1 | Local model writes easy summary + analyst brief | IOC regex + false-positive rejection |
| ATT&CK mapping | 2 | Local model proposes technique mappings (structured JSON) | Every ID checked against the synced ATT&CK cache |
| Navigator layer | 3 | none (deterministic) | Layer tagged with the real synced ATT&CK version |
| Hunting pack | 4 | none (deterministic SPL/KQL scaffolding) | starter hunts, tune before production |
| Deliverables | 5 | none | analyst quality gate |

## Model independence

Nothing is tied to a specific model. The sidebar reads the installed models from
your Ollama instance (`/api/tags`) and lets you pick one. `resolve_model()` falls
back to the first installed model. Point at a remote Ollama with:

```bash
export OLLAMA_HOST=http://192.168.1.10:11434
```

If Ollama is not running, or no model is installed, AI steps fail with a clear
message instead of returning canned text.

## ATT&CK data

The dataset sync pulls the current Enterprise ATT&CK STIX bundle from
`mitre-attack/attack-stix-data` (the unversioned file, which is always the latest
release) and records the real ATT&CK version (for example 19.1) in the cache
metadata. Tactics come straight from each technique's `kill_chain_phases`, so the
v19 restructure (Defense Evasion split into Stealth and Defense Impairment) flows
through automatically. The Navigator layer reports whatever version was synced,
not a hardcoded number.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# have Ollama running with at least one model
ollama serve
ollama pull llama3.1:8b              # or any model you prefer

streamlit run app.py
```

Then, in the UI: run tab 1 on a public report, sync ATT&CK and run the mapping in
tab 2, generate the Navigator layer in tab 3 and the hunting pack in tab 4, and
collect everything in tab 5.

## Tools (also runnable standalone)

- `tools/threat_report_ioc_extractor.py` - passive fetch, IOC extraction, AI summaries
- `tools/attack_dataset_sync.py` - download and cache current Enterprise ATT&CK
- `tools/attack_mapping_engine.py` - AI-assisted, cache-validated ATT&CK mapping
- `tools/attack_navigator_layer_generator.py` - build an importable Navigator layer
- `tools/hunting_pack_generator.py` - build the SPL/KQL hunting pack
- `tools/ollama_client.py` - local model client + model discovery
- `tools/cleanup_outputs.py` - clear generated artifacts

Use public or authorized sources only. Passive retrieval and parsing only: no
scanning, exploitation, authentication bypass, or private content.
