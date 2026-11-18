
import unittest

from integrated_assessment import (
    normalize_finding,
    extract_findings,
    build_assessment,
    SEVERITIES,
)


class IntegratedAssessmentTests(unittest.TestCase):

    def test_normalize_finding(self):
        finding = {
            "category": "Prompt Injection",
            "severity": "HIGH",
            "description": "Suspicious input detected.",
            "recommendation": "Validate input.",
        }

        result = normalize_finding(
            finding,
            "Test Module",
            "test-report.json",
            "TEST-001",
        )

        self.assertEqual(result["category"], "Prompt Injection")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["module"], "Test Module")
        self.assertEqual(result["record_id"], "TEST-001")

    def test_extract_standalone_findings(self):
        data = {
            "findings": [
                {"name": "Weak Encryption", "severity": "HIGH"},
                {"name": "Weak Hashing", "severity": "MEDIUM"},
            ]
        }

        findings = extract_findings(data, "Crypto", "crypto.json")

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["category"], "Weak Encryption")

    def test_extract_nested_findings(self):
        data = {
            "results": [
                {
                    "id": "PROMPT-001",
                    "findings": [
                        {
                            "category": "Prompt Injection",
                            "severity": "HIGH",
                        }
                    ],
                }
            ]
        }

        findings = extract_findings(data, "AI Security", "ai.json")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["record_id"], "PROMPT-001")

    def test_extract_multiple_nested_records(self):
        data = {
            "results": [
                {
                    "scenario_id": "AGENT-001",
                    "findings": [
                        {"category": "Unauthorized Tool", "severity": "CRITICAL"}
                    ],
                },
                {
                    "scenario_id": "AGENT-002",
                    "findings": [
                        {"category": "Data Exposure", "severity": "HIGH"}
                    ],
                },
            ]
        }

        findings = extract_findings(data, "Agent", "agent.json")

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["record_id"], "AGENT-001")
        self.assertEqual(findings[1]["record_id"], "AGENT-002")

    def test_unknown_severity_is_preserved(self):
        finding = {"category": "Unknown Test", "severity": "INFO"}

        result = normalize_finding(
            finding, "Test Module", "test.json"
        )

        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(len(SEVERITIES), 4)

    def test_full_integrated_assessment(self):
        report = build_assessment()

        self.assertEqual(report["modules_expected"], 9)
        self.assertEqual(report["modules_processed"], 9)
        self.assertEqual(report["modules_failed"], 0)
        self.assertEqual(report["total_findings"], 53)
        self.assertEqual(report["severity_summary"]["CRITICAL"], 9)
        self.assertEqual(report["severity_summary"]["HIGH"], 37)
        self.assertEqual(report["severity_summary"]["MEDIUM"], 5)
        self.assertEqual(report["severity_summary"]["LOW"], 2)
        self.assertEqual(report["unknown_severity_findings"], 0)


if __name__ == "__main__":
    unittest.main()
