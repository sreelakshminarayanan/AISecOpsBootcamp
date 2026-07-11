"""Check Ollama reachability and list installed models."""
from __future__ import annotations

import os
import sys

import requests

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_TAGS = f"{OLLAMA_BASE_URL}/api/tags"


def main() -> None:
    try:
        response = requests.get(OLLAMA_TAGS, timeout=5)
        response.raise_for_status()
    except Exception as exc:
        print(f"Ollama is not reachable at {OLLAMA_BASE_URL}: {exc}")
        sys.exit(1)

    models = [item.get("name") for item in response.json().get("models", []) if item.get("name")]
    print(f"Ollama is reachable at {OLLAMA_BASE_URL}.")
    if models:
        print("Installed models:")
        for model in models:
            print(f"  - {model}")
    else:
        print("No models are installed.")


if __name__ == "__main__":
    main()
