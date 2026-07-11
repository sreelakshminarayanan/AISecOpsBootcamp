"""Send one prompt to Ollama and print the response metadata."""
from __future__ import annotations

import argparse
import os

import requests

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/generate"


def ask(prompt: str, model: str, temperature: float) -> dict:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {"temperature": temperature},
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=300)
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send one prompt to an Ollama model.")
    parser.add_argument("prompt", help="Prompt text")
    parser.add_argument("--model", default="qwen3:4b", help="Ollama model name")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--show-stats", action="store_true")
    args = parser.parse_args()

    result = ask(args.prompt, args.model, args.temperature)
    print((result.get("response") or "").strip())

    if args.show_stats:
        print("\nMetadata")
        for key in ("model", "prompt_eval_count", "eval_count", "total_duration", "eval_duration"):
            print(f"{key}: {result.get(key)}")


if __name__ == "__main__":
    main()
