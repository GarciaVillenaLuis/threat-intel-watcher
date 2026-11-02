#!/usr/bin/env python3
"""
Unit tests for CISA Watcher CLI tool.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from cisa_watcher import CISAWatcher, VulnerabilityRecord, format_table


class TestCISAWatcher(unittest.TestCase):
    def setUp(self):
        self.sample_data = {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2024.11.01",
            "dateReleased": "2024-11-01T00:00:00Z",
            "count": 3,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-3400",
                    "vendorProject": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "vulnerabilityName": "PAN-OS Command Injection",
                    "dateAdded": "2024-04-12",
                    "shortDescription": "Command injection vulnerability in GlobalProtect feature.",
                    "requiredAction": "Apply vendor updates.",
                    "dueDate": "2024-04-19",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
                },
                {
                    "cveID": "CVE-2024-21887",
                    "vendorProject": "Ivanti",
                    "product": "Connect Secure",
                    "vulnerabilityName": "Command Injection",
                    "dateAdded": "2024-01-12",
                    "shortDescription": "Command injection vulnerability in web components.",
                    "requiredAction": "Apply vendor mitigation.",
                    "dueDate": "2024-01-22",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": ""
                },
                {
                    "cveID": "CVE-2023-20198",
                    "vendorProject": "Cisco",
                    "product": "IOS XE",
                    "vulnerabilityName": "Web UI Privilege Escalation",
                    "dateAdded": "2023-10-18",
                    "shortDescription": "Privilege escalation vulnerability in web UI.",
                    "requiredAction": "Disable HTTP server feature.",
                    "dueDate": "2023-10-20",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": ""
                }
            ]
        }
        self.temp_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8")
        json.dump(self.sample_data, self.temp_file)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_load_from_local_file(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        self.assertEqual(len(watcher.vulnerabilities), 3)
        self.assertEqual(watcher.catalog_version, "2024.11.01")

    def test_filter_by_cve(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        res = watcher.filter_records(cve_id="CVE-2024-3400")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].cve_id, "CVE-2024-3400")
        self.assertEqual(res[0].vendor_project, "Palo Alto Networks")

    def test_filter_by_vendor(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        res = watcher.filter_records(vendor="cisco")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].cve_id, "CVE-2023-20198")

    def test_filter_ransomware_only(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        res = watcher.filter_records(ransomware_only=True)
        self.assertEqual(len(res), 2)
        cves = {r.cve_id for r in res}
        self.assertIn("CVE-2024-3400", cves)
        self.assertIn("CVE-2024-21887", cves)

    def test_compute_stats(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        stats = watcher.compute_stats()
        self.assertEqual(stats["total_records"], 3)
        self.assertEqual(stats["ransomware_linked"], 2)
        self.assertAlmostEqual(stats["ransomware_percentage"], 66.67, places=1)
        self.assertIn("Palo Alto Networks", stats["top_vendors"])

    def test_format_table(self):
        watcher = CISAWatcher(data_source=self.temp_file.name)
        watcher.load_data()
        table_out = format_table(watcher.vulnerabilities)
        self.assertIn("CVE-2024-3400", table_out)
        self.assertIn("Palo Alto Networks", table_out)


if __name__ == "__main__":
    unittest.main()
