
#!/usr/bin/env python3
"""
Web Security Assessor
Module 2 - Terac AI Cybersecurity Training

Checks HTTP security headers and cookie security attributes
on authorized web application targets.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Helps reduce cross-site scripting (XSS) risks.",
        "recommendation": "Implement a restrictive Content-Security-Policy."
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections in supporting browsers.",
        "recommendation": (
            "Configure HSTS after confirming HTTPS is correctly deployed."
        )
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Provides protection against clickjacking.",
        "recommendation": (
            "Set X-Frame-Options: DENY or SAMEORIGIN, "
            "or use CSP frame-ancestors."
        )
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information browsers send.",
        "recommendation": (
            "Set a suitable Referrer-Policy, such as "
            "strict-origin-when-cross-origin."
        )
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls access to selected browser features.",
        "recommendation": (
            "Configure Permissions-Policy for the application's "
            "required features."
        )
    }
}


def analyze_headers(headers):
    """Identify missing HTTP security headers."""
    findings = []

    existing_headers = {
        name.lower() for name in headers.keys()
    }

    for header, details in SECURITY_HEADERS.items():
        if header.lower() not in existing_headers:
            findings.append({
                "type": "HTTP Security Header",
                "header": header,
                "severity": details["severity"],
                "description": details["description"],
                "recommendation": details["recommendation"]
            })

    return findings


def analyze_cookies(cookie_headers):
    """Check Secure, HttpOnly, and SameSite cookie attributes."""
    findings = []

    checks = [
        (
            "secure",
            "HIGH",
            "Secure attribute is missing.",
            "Configure the Secure attribute and serve the cookie over HTTPS."
        ),
        (
            "httponly",
            "MEDIUM",
            "HttpOnly attribute is missing.",
            "Configure the HttpOnly attribute to restrict JavaScript access."
        ),
        (
            "samesite",
            "MEDIUM",
            "SameSite attribute is missing.",
            "Configure an appropriate SameSite attribute."
        )
    ]

    for cookie in cookie_headers:
        parts = cookie.split(";")

        if "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = set()

        for part in parts[1:]:
            attribute = part.strip().split("=", 1)[0].lower()
            attributes.add(attribute)

        for attribute, severity, description, recommendation in checks:
            if attribute not in attributes:
                findings.append({
                    "type": "Cookie Security",
                    "cookie": cookie_name,
                    "attribute": attribute,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation
                })

    return findings


def assess_target(url, timeout=10):
    """Request an authorized target and assess its response."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            "Target must begin with http:// or https://"
        )

    request = Request(
        url,
        headers={
            "User-Agent": "Terac-Web-Security-Assessor/1.0"
        },
        method="GET"
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = response.status
            response_headers = dict(response.headers.items())
            set_cookie_headers = (
                response.headers.get_all("Set-Cookie") or []
            )

    except HTTPError as error:
        status_code = error.code
        response_headers = dict(error.headers.items())
        set_cookie_headers = (
            error.headers.get_all("Set-Cookie") or []
        )
        error.close()

    except (URLError, TimeoutError, OSError) as error:
        raise ConnectionError(
            f"Unable to connect to target: {error}"
        ) from error

    header_findings = analyze_headers(response_headers)
    cookie_findings = analyze_cookies(set_cookie_headers)

    findings = header_findings + cookie_findings

    return {
        "target": url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "http_status": status_code,
        "headers_analyzed": len(response_headers),
        "cookies_analyzed": len(set_cookie_headers),
        "header_findings_count": len(header_findings),
        "cookie_findings_count": len(cookie_findings),
        "findings_count": len(findings),
        "findings": findings
    }


def save_report(report, output_file):
    """Save assessment results as a JSON report."""
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "HTTP security-header and cookie assessor "
            "for authorized targets."
        )
    )

    parser.add_argument(
        "target",
        help="Authorized HTTP or HTTPS target URL"
    )

    parser.add_argument(
        "--output",
        default="security-assessment.json",
        help="JSON report output filename"
    )

    args = parser.parse_args()

    try:
        report = assess_target(args.target)

        save_report(report, args.output)

        print("\n=== WEB SECURITY ASSESSMENT ===")
        print(f"Target: {report['target']}")
        print(f"HTTP Status: {report['http_status']}")
        print(f"Headers Analyzed: {report['headers_analyzed']}")
        print(f"Cookies Analyzed: {report['cookies_analyzed']}")
        print(f"Header Findings: {report['header_findings_count']}")
        print(f"Cookie Findings: {report['cookie_findings_count']}")
        print(f"Total Findings: {report['findings_count']}")

        for finding in report["findings"]:
            print("\n-----------------------------------")
            print(f"Type: {finding['type']}")

            if "header" in finding:
                print(f"Header: {finding['header']}")

            if "cookie" in finding:
                print(f"Cookie: {finding['cookie']}")
                print(f"Attribute: {finding['attribute']}")

            print(f"Severity: {finding['severity']}")
            print(f"Description: {finding['description']}")
            print(
                f"Recommendation: {finding['recommendation']}"
            )

        print(f"\nJSON report saved to: {args.output}")

    except (ValueError, ConnectionError, OSError) as error:
        print(
            f"Assessment error: {error}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
