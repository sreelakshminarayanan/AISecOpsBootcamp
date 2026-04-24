import json
import sys
import requests


OLLAMA_BASE_URL = "http://localhost:11434"


def check_ollama_server():
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to Ollama at http://localhost:11434")
        print("Make sure Ollama is installed and running.")
        print("Try running: ollama serve")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[ERROR] Ollama server timed out.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Ollama returned HTTP error: {e}")
        sys.exit(1)


def main():
    print("=" * 70)
    print("Module 5 Lab — Ollama Health Check")
    print("=" * 70)

    data = check_ollama_server()
    models = data.get("models", [])

    if not models:
        print("[WARNING] Ollama is running, but no models are installed.")
        print("Install one model with:")
        print("  ollama pull llama3.2:3b")
        print("or:")
        print("  ollama pull llama3.1:8b")
        sys.exit(0)

    print("[OK] Ollama server is reachable.")
    print("\nInstalled models:")

    for model in models:
        name = model.get("name", "unknown")
        size = model.get("size", 0)
        size_gb = size / (1024 ** 3)
        print(f"  - {name} ({size_gb:.2f} GB)")

    print("\n[OK] Environment baseline looks good.")
    print("Next step: run tokenizer reconnaissance lab.")


if __name__ == "__main__":
    main()