import argparse
import json
import requests


OLLAMA_URL = "http://localhost:11434/api/generate"


def ask_ollama(
    prompt: str,
    model: str = "llama3.2:3b",
    temperature: float = 0.0,
    num_predict: int = 128,
):
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
        timeout=120,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Ollama API error {response.status_code}: {response.text}"
        )

    result = response.json()
    return {
        "response": result.get("response", ""),
        "model": result.get("model", model),
        "prompt_eval_count": result.get("prompt_eval_count"),
        "eval_count": result.get("eval_count"),
        "total_duration": result.get("total_duration"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Send a prompt to a local Ollama model."
    )

    parser.add_argument(
        "prompt",
        help="Prompt text to send to the model.",
    )

    parser.add_argument(
        "--model",
        default="llama3.2:3b",
        help="Ollama model name. Default: llama3.2:3b",
    )

    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature. Default: 0.0",
    )

    parser.add_argument(
        "--num-predict",
        type=int,
        default=128,
        help="Maximum number of tokens to generate. Default: 128",
    )

    parser.add_argument(
        "--show-stats",
        action="store_true",
        help="Show token and timing metadata returned by Ollama.",
    )

    args = parser.parse_args()

    result = ask_ollama(
        prompt=args.prompt,
        model=args.model,
        temperature=args.temperature,
        num_predict=args.num_predict,
    )

    print("Ollama response:")
    print(result["response"].strip())

    if args.show_stats:
        print("\nRun metadata:")
        print(f"Model: {result['model']}")
        print(f"Prompt tokens processed: {result['prompt_eval_count']}")
        print(f"Output tokens generated: {result['eval_count']}")
        print(f"Total duration ns: {result['total_duration']}")


if __name__ == "__main__":
    main()