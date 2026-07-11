# Module 5 LLM Architecture Security Lab

A compact Streamlit lab for inspecting LLM architecture and security behavior with local Ollama models.

## Included labs

- 00 Environment
- 5.1 Tokenization and Context
- 5.2 Prompt Trust Boundary
- 5.3 Attack Reliability
- 5.4 Tokenization Evasion
- 5.5 Best of N

The separate RAG Security Workbench is not included in this package.

## What changed

- Proper Ollama chat roles are used in the role separated prompt test
- Flattened prompt construction remains available for direct comparison
- Every prompt test uses a new dynamic canary
- A missing response marker is shown as evidence but is not treated as compromise by itself
- Target response, exact Ollama request, metadata, canary result, and judge result are visible
- Tokenization is available in the Streamlit interface
- Context budget estimates are included
- Reliability tests show individual trials and attack success rate
- Tokenization evasion separates guard bypass from downstream target compromise
- Best of N shows every executed variant and the first successful variant
- Current run results can be downloaded as JSON
- The interface uses a compact dark security console layout

## Quick start with Docker

Docker Compose starts Streamlit and an isolated Ollama container.

### Linux

```bash
cp .env.example .env
docker compose up --build -d
```

Install a model in the Ollama container:

```bash
docker compose exec ollama ollama pull qwen3:4b
```

Open:

```text
http://localhost:8501
```

### Windows PowerShell

Docker Desktop must be running with Linux containers.

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose exec ollama ollama pull qwen3:4b
```

Open:

```text
http://localhost:8501
```

### Additional models

```bash
docker compose exec ollama ollama pull llama3.1:8b
docker compose exec ollama ollama list
```

Refresh Ollama status from the left sidebar after a model download completes.

## Run with an existing host Ollama installation

Install the Python dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell activation:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the portal:

```bash
python -m streamlit run app.py
```

The default Ollama endpoint is:

```text
http://localhost:11434
```

A different endpoint can be configured with `OLLAMA_BASE_URL`.

## Docker data behavior

Downloaded models are stored in the `ollama-data` volume.

This keeps models:

```bash
docker compose down
```

This deletes downloaded models:

```bash
docker compose down -v
```

## Lab behavior

### 5.1 Tokenization and Context

The tokenizer view uses a local demonstration BPE tokenizer. It is not presented as the exact native tokenizer for every Ollama model.

### 5.2 Prompt Trust Boundary

The same attack can be tested against:

- Proper chat roles using Ollama `/api/chat`
- A flattened text prompt using Ollama `/api/generate`

A new canary is placed in the system prompt for each run.

### 5.3 Attack Reliability

One attack is repeated with the same architecture and model configuration. Attack success rate includes only confirmed leakage and judge identified attack compliance.

### 5.4 Tokenization Evasion

The input guard is a transparent demonstration classifier. The lab reports guard bypass and target compromise separately.

### 5.5 Best of N

Several deterministic variants of one attack are generated and tested within a fixed request budget. The first successful variant and request number are shown.

## Troubleshooting

Check services:

```bash
docker compose ps
docker compose logs --tail=100 portal
docker compose logs --tail=100 ollama
```

List models:

```bash
docker compose exec ollama ollama list
```

Restart the portal after code or environment changes:

```bash
docker compose up --build -d portal
```
