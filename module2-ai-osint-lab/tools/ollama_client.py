import json
from typing import Any

import requests


OLLAMA_URL = "http://localhost:11434/api/generate"


def ask_ollama(
    prompt: str,
    model: str = "llama3.2:3b",
    temperature: float = 0.2,
    num_predict: int = 900,
) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }

    response = requests.post(
        OLLAMA_URL,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=180,
    )

    if response.status_code != 200:
        raise RuntimeError(f"Ollama API error {response.status_code}: {response.text}")

    return response.json().get("response", "").strip()


def ask_ollama_json(
    prompt: str,
    model: str = "llama3.2:3b",
    temperature: float = 0.0,
    num_predict: int = 1800,
    json_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
        "format": json_schema if json_schema else "json",
    }

    response = requests.post(
        OLLAMA_URL,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=240,
    )

    if response.status_code != 200:
        raise RuntimeError(f"Ollama API error {response.status_code}: {response.text}")

    response_text = response.json().get("response", "").strip()

    if not response_text:
        raise RuntimeError("Ollama returned an empty JSON response.")

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Ollama did not return valid JSON even though structured output was requested. "
            f"Raw response preview: {response_text[:1500]}"
        ) from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama JSON response was valid JSON but not a JSON object.")

    return parsed


if __name__ == "__main__":
    print(ask_ollama("Explain OSINT in one sentence."))