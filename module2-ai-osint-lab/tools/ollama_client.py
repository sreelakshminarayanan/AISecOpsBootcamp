"""
Local Ollama client for the AI SecOps Bootcamp Module 2 lab.

Every call in this module goes to a real, locally running Ollama instance. There
is no hardcoded or canned output anywhere: if Ollama is not running or no model
is installed, calls fail loudly instead of returning fabricated text.

Model independence: nothing in this lab is tied to a specific model. The UI and
CLIs discover whatever models are installed with `list_models()` and let you pick
one. `resolve_model()` falls back to the first installed model when a preferred
name is not given, so a fresh machine with any single `ollama pull` works.

The Ollama host can be overridden with the OLLAMA_HOST environment variable, e.g.
OLLAMA_HOST=http://192.168.1.10:11434
"""
import json
import os
import re
from typing import Any

import requests


OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "16384"))

GENERATE_URL = f"{OLLAMA_HOST}/api/generate"
TAGS_URL = f"{OLLAMA_HOST}/api/tags"
VERSION_URL = f"{OLLAMA_HOST}/api/version"


class OllamaError(RuntimeError):
    """Raised when Ollama is unreachable, has no models, or returns bad output."""


def _unreachable_message() -> str:
    return (
        f"Cannot reach Ollama at {OLLAMA_HOST}. "
        "Start it with `ollama serve` (or check OLLAMA_HOST), then try again."
    )


def ollama_up() -> bool:
    """Return True if the Ollama daemon answers on the configured host."""
    try:
        response = requests.get(VERSION_URL, timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False


def list_models() -> list[str]:
    """
    Return the names of every model installed in the local Ollama instance.

    Returns an empty list if Ollama is unreachable or has no models. This is the
    single source of truth for model choices in the UI and CLIs, so no model name
    is ever hardcoded.
    """
    try:
        response = requests.get(TAGS_URL, timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return []
    except json.JSONDecodeError:
        return []

    names = []
    for entry in data.get("models", []):
        name = entry.get("name") or entry.get("model")
        if name:
            names.append(str(name))

    return sorted(set(names))


def resolve_model(preferred: str | None = None) -> str:
    """
    Resolve a usable model name.

    Order of preference: the caller's choice if installed, then the caller's
    choice verbatim if the tag list could not be read, then the first installed
    model. Raises OllamaError if nothing is installed.
    """
    installed = list_models()

    if preferred and preferred in installed:
        return preferred

    if preferred and not installed:
        return preferred

    if installed:
        return installed[0]

    raise OllamaError(
        "No Ollama models are installed. Install one first, for example: "
        "`ollama pull llama3.1:8b`."
    )


def ask_ollama(
    prompt: str,
    model: str,
    temperature: float = 0.2,
    num_predict: int = 900,
) -> str:
    """Send a prompt to a local model and return the raw text response."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }

    try:
        response = requests.post(
            GENERATE_URL,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=180,
        )
    except requests.RequestException as exc:
        raise OllamaError(_unreachable_message()) from exc

    if response.status_code != 200:
        raise OllamaError(f"Ollama API error {response.status_code}: {response.text}")

    return response.json().get("response", "").strip()


def ask_ollama_json(
    prompt: str,
    model: str,
    temperature: float = 0.0,
    num_predict: int = 1800,
    json_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Send a prompt and parse a JSON object from a local model.

    Uses Ollama structured output: when a schema is supplied the model is
    constrained to it, otherwise plain JSON mode is requested.
    """
    formats = [json_schema, "json"] if json_schema else ["json"]
    errors = []

    for output_format in formats:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
                "num_ctx": OLLAMA_NUM_CTX,
                "seed": 42,
            },
            "format": output_format,
        }

        try:
            response = requests.post(
                GENERATE_URL,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=360,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            errors.append(str(exc))
            continue

        response_text = str(data.get("response", "")).strip()
        if not response_text:
            errors.append(
                "empty response "
                f"(done_reason={data.get('done_reason')}, "
                f"prompt_tokens={data.get('prompt_eval_count')}, "
                f"output_tokens={data.get('eval_count')})"
            )
            continue

        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", response_text, re.I | re.S)
        if fenced:
            response_text = fenced.group(1)

        try:
            parsed = json.loads(response_text)
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON: {exc}; preview={response_text[:500]}")
            continue

        if isinstance(parsed, dict):
            return parsed

        errors.append("valid JSON was returned, but it was not an object")

    raise OllamaError(
        "Ollama could not produce usable JSON after schema and plain-JSON attempts. "
        f"Model={model}, context={OLLAMA_NUM_CTX}, prompt_chars={len(prompt)}. "
        f"Details: {' | '.join(errors)}"
    )


if __name__ == "__main__":
    print(f"Ollama host: {OLLAMA_HOST}")
    print(f"Reachable: {ollama_up()}")
    models = list_models()
    print(f"Installed models: {models or 'none'}")
    if models:
        print(ask_ollama("Explain OSINT in one sentence.", model=models[0]))
