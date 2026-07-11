import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from tools import ai_hunting_pack_generator as generator


def valid_payload():
    return {
        "executive_summary": "Validated PowerShell activity requires endpoint hunting.",
        "validation_summary": "The approved mapping is supported by the source.",
        "mapping_validation": [
            {
                "attack_id": "T1059.001",
                "status": "confirmed",
                "assessment": "Encoded PowerShell execution is directly described.",
                "evidence_used": "The attacker used PowerShell with an encoded command.",
            }
        ],
        "hunts": [
            {
                "attack_id": "T1059.001",
                "title": "Encoded PowerShell execution",
                "hypothesis": "A host executed suspicious encoded PowerShell.",
                "platform": "Windows",
                "required_log_sources": ["Endpoint process telemetry"],
                "splunk_spl": "index=endpoint process_name=powershell.exe process=*EncodedCommand*",
                "microsoft_kql": "DeviceProcessEvents | where ProcessCommandLine has 'EncodedCommand'",
                "false_positives": ["Approved administration scripts"],
                "triage_steps": ["Review the parent process and user context"],
                "detection_opportunity": "Alert on rare encoded PowerShell with unusual parents.",
                "limitations": "Requires process command-line telemetry.",
            }
        ],
        "cross_hunt_analysis": "Correlate process and network telemetry.",
        "recommended_next_steps": ["Tune known administrator exclusions"],
    }


class AIHuntingPackTests(unittest.TestCase):
    def test_second_model_generates_pack_and_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mapping = root / "mapping.csv"
            iocs = root / "iocs.csv"
            evidence = root / "evidence.json"
            pd.DataFrame(
                [
                    {
                        "attack_id": "T1059.001",
                        "name": "PowerShell",
                        "tactics": "execution",
                        "confidence": "high",
                        "evidence": "The attacker used PowerShell with an encoded command.",
                        "evidence_chunk_id": "SRC-0001",
                    }
                ]
            ).to_csv(mapping, index=False)
            pd.DataFrame([{"type": "domains", "value": "evil.example"}]).to_csv(iocs, index=False)
            evidence.write_text(
                json.dumps(
                    {
                        "article": {
                            "chunks": [
                                {
                                    "chunk_id": "SRC-0001",
                                    "text": "The attacker used PowerShell with an encoded command.",
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(generator, "OUTPUT_DIR", root), patch.object(
                generator, "ask_ollama_json", return_value=valid_payload()
            ) as model_call:
                result = generator.run(
                    str(mapping), str(iocs), str(evidence), "strong-model:latest", "https://example.test/report"
                )

            self.assertEqual(model_call.call_count, 1)
            self.assertEqual(result["model"], "strong-model:latest")
            self.assertEqual(result["hunt_count"], 1)
            markdown = result["paths"]["markdown"].read_text(encoding="utf-8")
            self.assertIn("Validation and hunting model: `strong-model:latest`", markdown)
            self.assertIn("Encoded PowerShell", markdown)

    def test_unapproved_attack_id_is_blocked(self):
        payload = valid_payload()
        payload["hunts"][0]["attack_id"] = "T1003"
        with self.assertRaisesRegex(RuntimeError, "unapproved ATT&CK ID"):
            generator.validate_ai_payload(payload, {"T1059.001"})


if __name__ == "__main__":
    unittest.main()
