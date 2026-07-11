import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from tools import attack_mapping_engine as engine


ATTACK_LOOKUP = {
    "T1003": {
        "attack_id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1003/",
        "data_sources": "",
        "detection": "",
    },
    "T1059.001": {
        "attack_id": "T1059.001",
        "name": "PowerShell",
        "tactics": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "data_sources": "",
        "detection": "",
    },
}


def mapping_item(technique_id="T1003", evidence="The attacker dumped LSASS memory"):
    return {
        "technique_id": technique_id,
        "confidence": "high",
        "evidence": evidence,
        "evidence_chunk_id": "SRC-0001",
        "rationale": "The source describes credential dumping behavior.",
        "hunting_focus": ["LSASS access"],
        "log_sources": ["Endpoint process telemetry"],
    }


def validate(item, candidate_ids):
    return engine.validate_llm_mappings(
        llm_json={"mappings": [item], "rejected_or_uncertain": []},
        attack_lookup=ATTACK_LOOKUP,
        candidate_ids=candidate_ids,
        explicit_ids=set(),
        source_chunk_lookup={"SRC-0001": "The attacker dumped LSASS memory with a credential dumping utility."},
    )


class MappingGroundingTests(unittest.TestCase):
    def test_out_of_candidate_mapping_remains_reviewable(self):
        final, review, rejected = validate(mapping_item(), {"T1059.001"})
        self.assertEqual(final, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(review), 1)
        self.assertIn("outside_candidate_set", review[0]["validation_status"])

    def test_unverified_evidence_remains_reviewable_with_warning(self):
        final, review, rejected = validate(mapping_item(evidence="procdump -ma lsass.exe"), {"T1003"})
        self.assertEqual(final, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(review), 1)
        self.assertIn("evidence_quote_not_verified", review[0]["validation_status"])

    def test_grounded_model_mapping_waits_for_analyst(self):
        final, review, rejected = validate(mapping_item(), {"T1003"})
        self.assertEqual(final, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0]["disposition"], "review")
        self.assertEqual(review[0]["review_reason"], "requires_analyst_approval")

    def test_only_explicit_analyst_approval_creates_final(self):
        row = engine.build_validated_mapping_row(
            technique_id="T1003",
            item=mapping_item(),
            technique=ATTACK_LOOKUP["T1003"],
            confidence="high",
            validation_note="grounded_in_source_and_validated_against_attack_cache",
            mapping_source="llm_proposed_validated",
        )
        df = pd.DataFrame([{**row, "approve": True, "analyst_notes": "Source behavior verified"}])

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(engine, "OUTPUT_DIR", Path(tmp)):
                result = engine.save_analyst_decisions(df)
                self.assertEqual(len(result["final"]), 1)
                self.assertEqual(
                    result["final"].iloc[0]["validation_status"],
                    "analyst_approved_grounded_mapping",
                )
                self.assertTrue(result["paths"]["final_csv"].exists())

    def test_manual_override_without_note_is_saved_with_audit_note(self):
        row = engine.build_validated_mapping_row(
            technique_id="T1003",
            item=mapping_item(evidence="unverified model text"),
            technique=ATTACK_LOOKUP["T1003"],
            confidence="high",
            validation_note="manual_review_required:evidence_quote_not_verified",
            mapping_source="llm_proposed_validated",
            review_reason="evidence_quote_not_verified",
        )
        df = pd.DataFrame([{**row, "approve": True, "analyst_notes": ""}])
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(engine, "OUTPUT_DIR", Path(tmp)):
                result = engine.save_analyst_decisions(df)
                self.assertEqual(len(result["final"]), 1)
                self.assertEqual(
                    result["final"].iloc[0]["validation_status"],
                    "analyst_approved_manual_override",
                )
                self.assertIn(
                    "Manually reviewed",
                    result["final"].iloc[0]["analyst_notes"],
                )

    def test_valid_llm_uncertain_mapping_is_reviewable(self):
        final, review, rejected = engine.validate_llm_mappings(
            llm_json={
                "mappings": [],
                "rejected_or_uncertain": [
                    {"candidate_technique_id": "T1003", "reason": "Evidence was indirect."}
                ],
            },
            attack_lookup=ATTACK_LOOKUP,
            candidate_ids={"T1003"},
            explicit_ids=set(),
            source_chunk_lookup={},
        )
        self.assertEqual(final, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0]["attack_id"], "T1003")


if __name__ == "__main__":
    unittest.main()
