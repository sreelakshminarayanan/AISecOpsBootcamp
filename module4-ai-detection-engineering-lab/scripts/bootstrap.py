from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

from detection_lab.config import settings
from detection_lab.elastic import bulk_index, read_ndjson
from detection_lab.http_client import request_json
from scripts.generate_telemetry import generate


def main() -> None:
    dataset = settings.root / "datasets/generated/production_simulation.ndjson"
    summary = generate(dataset)
    indexed = bulk_index(settings.lab_index, read_ndjson([dataset]), recreate=True)
    detection_index = request_json(
        "POST",
        f"{settings.kibana_url}/api/detection_engine/index",
        headers={"kbn-xsrf": "true"},
        expected=(200, 409),
    )
    print(json.dumps({"dataset": summary, "elasticsearch": indexed, "detection_engine": detection_index}, indent=2))


if __name__ == "__main__":
    main()

