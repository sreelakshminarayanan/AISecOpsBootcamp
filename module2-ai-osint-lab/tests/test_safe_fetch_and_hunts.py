import socket
import unittest
from unittest.mock import patch

import pandas as pd

from tools.hunting_pack_generator import build_generic_kql_hunt, build_generic_splunk_hunt
from tools.threat_report_ioc_extractor import build_article_chunks, validate_public_url


class SafeFetchAndHuntTests(unittest.TestCase):
    def test_private_url_is_blocked(self):
        response = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=response):
            with self.assertRaisesRegex(ValueError, "private"):
                validate_public_url("http://example.test/report")

    def test_public_url_is_allowed(self):
        response = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("socket.getaddrinfo", return_value=response):
            validate_public_url("https://example.test/report")

    def test_article_chunks_have_stable_ids(self):
        chunks = build_article_chunks("Sentence one. " * 300, chunk_size=300)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(chunks[0]["chunk_id"], "SRC-0001")
        self.assertEqual(chunks[1]["chunk_id"], "SRC-0002")

    def test_credential_dumping_hunt_is_behavioral_not_ioc_driven(self):
        row = pd.Series(
            {
                "attack_id": "T1003.001",
                "name": "LSASS Memory",
                "hunting_focus": "LSASS access",
                "log_sources": "Endpoint process telemetry",
            }
        )
        iocs = {"domains": ["unrelated.example"]}
        spl = build_generic_splunk_hunt(row, iocs)
        kql = build_generic_kql_hunt(row, iocs)
        self.assertIn("lsass", spl.lower())
        self.assertIn("lsass", kql.lower())
        self.assertNotIn("unrelated.example", spl)
        self.assertNotIn("unrelated.example", kql)

    def test_unknown_technique_does_not_get_fake_keyword_query(self):
        row = pd.Series({"attack_id": "T9999", "name": "Unknown"})
        output = build_generic_splunk_hunt(row, {})
        self.assertIn("No deterministic behavioral template", output)
        self.assertNotIn("index=*", output)


if __name__ == "__main__":
    unittest.main()

