from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(os.getenv("LAB_ROOT", str(Path(__file__).resolve().parent.parent))).resolve()


@dataclass(frozen=True)
class Settings:
    elastic_url: str = os.getenv("ELASTIC_URL", "http://localhost:9200").rstrip("/")
    kibana_url: str = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
    lab_index: str = os.getenv("LAB_INDEX", "lab-security-events-v1")
    elastic_username: str = os.getenv("ELASTIC_USERNAME", "elastic")
    elastic_password: str = os.getenv("ELASTIC_PASSWORD", "DetectionLab2026")
    root: Path = ROOT


settings = Settings()


def service_auth(url: str) -> tuple[str, str] | None:
    if url.startswith(settings.elastic_url) or url.startswith(settings.kibana_url):
        return settings.elastic_username, settings.elastic_password
    return None
