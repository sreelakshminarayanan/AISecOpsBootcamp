import sys
from tiktoken import get_encoding

def show_tokens(text: str):
    # use a known good encoding
    enc = get_encoding("cl100k_base")
    token_ids = enc.encode(text)
    tokens = [enc.decode([tid]) for tid in token_ids]

    print("\n=== Input Text ===")
    print(text)
    print("\n=== Token IDs ===")
    print(token_ids)
    print("\n=== Tokens ===")
    print(tokens)
    print(f"\nTotal tokens: {len(token_ids)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tokenizer_lab.py \"Text to tokenize\"")
        sys.exit(1)

    # Model name is not used here; we use a shared encoding
    text = sys.argv[1]
    show_tokens(text)