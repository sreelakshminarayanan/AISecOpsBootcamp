from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    ok: bool
    command: list[str]
    stdout: str
    stderr: str
    returncode: int


def run_sigma_check(rule_path: Path) -> CommandResult:
    command = ["sigma", "check", str(rule_path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return CommandResult(
        ok=completed.returncode == 0,
        command=command,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        returncode=completed.returncode,
    )


def convert_to_lucene(rule_path: Path) -> CommandResult:
    command = ["sigma", "convert", "-t", "lucene", "-p", "ecs_windows", str(rule_path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return CommandResult(
        ok=completed.returncode == 0,
        command=command,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        returncode=completed.returncode,
    )


def extract_query(result: CommandResult) -> str:
    if not result.ok:
        raise RuntimeError(result.stderr or result.stdout or "Sigma conversion failed.")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    candidates = [line for line in lines if not line.startswith("Parsing") and not line.startswith("Loaded")]
    if not candidates:
        raise RuntimeError("Sigma conversion returned no query.")
    return candidates[-1]

