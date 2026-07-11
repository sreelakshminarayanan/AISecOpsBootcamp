"""Display token IDs and token pieces using the local demonstration BPE tokenizer."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core


def show_tokens(text: str) -> None:
    rows = core.token_details(text)
    print("Local demonstration BPE tokenizer")
    print("This does not claim to match the selected Ollama model's native tokenizer.\n")
    print("Input text")
    print(text)
    print("\nToken IDs")
    print([row["token_id"] for row in rows])
    print("\nToken pieces")
    print([row["piece"] for row in rows])
    print(f"\nTotal tokens: {len(rows)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("text")
    args = parser.parse_args()
    show_tokens(args.text)


if __name__ == "__main__":
    main()
