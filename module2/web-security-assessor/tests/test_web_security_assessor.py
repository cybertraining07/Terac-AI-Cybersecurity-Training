
import unittest

from web_security_assessor import (
    analyze_headers,
    analyze_cookies,
    SECURITY_HEADERS
)


class WebSecurityAssessorTests(unittest.TestCase):

    # HTTP security header tests

    def test_all_missing_headers_detected(self):
        findings = analyze_headers({})
        self.assertEqual(len(findings), 6)

    def test_present_headers_not_flagged(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()"
        }

        findings = analyze_headers(headers)
        self.assertEqual(len(findings), 0)

    def test_case_insensitive_header_matching(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff"
        }

        findings = analyze_headers(headers)
        finding_names = [item["header"] for item in findings]

        self.assertNotIn("Content-Security-Policy", finding_names)
        self.assertNotIn("X-Content-Type-Options", finding_names)

    def test_missing_header_severity(self):
        findings = analyze_headers({})

        for finding in findings:
            self.assertIn(
                finding["severity"],
                ["LOW", "MEDIUM", "HIGH"]
            )

    def test_findings_have_recommendations(self):
        findings = analyze_headers({})

        for finding in findings:
            self.assertTrue(finding["recommendation"])

    def test_security_header_configuration(self):
        self.assertEqual(len(SECURITY_HEADERS), 6)

    # Cookie security tests

    def test_cookie_missing_all_security_attributes(self):
        cookies = ["sessionId=abc123"]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 3)

    def test_cookie_with_all_security_attributes(self):
        cookies = [
            "sessionId=abc123; Secure; HttpOnly; SameSite=Strict"
        ]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 0)

    def test_cookie_missing_secure_attribute(self):
        cookies = [
            "sessionId=abc123; HttpOnly; SameSite=Strict"
        ]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["attribute"], "secure")

    def test_cookie_missing_httponly_attribute(self):
        cookies = [
            "sessionId=abc123; Secure; SameSite=Strict"
        ]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["attribute"], "httponly")

    def test_cookie_missing_samesite_attribute(self):
        cookies = [
            "sessionId=abc123; Secure; HttpOnly"
        ]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["attribute"], "samesite")

    def test_multiple_cookies_analyzed_independently(self):
        cookies = [
            "sessionId=abc123; Secure; HttpOnly; SameSite=Strict",
            "trackingId=xyz789"
        ]

        findings = analyze_cookies(cookies)

        self.assertEqual(len(findings), 3)
        self.assertTrue(
            all(item["cookie"] == "trackingId" for item in findings)
        )

    def test_no_cookies_returns_no_findings(self):
        findings = analyze_cookies([])
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
