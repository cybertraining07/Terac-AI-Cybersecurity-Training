
import json
import re
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
TEST_FILE = BASE_DIR / "tests" / "ai_security_events.json"
REPORT_FILE = BASE_DIR / "reports" / "ai-security-monitor-report.json"


def detect_prompt_injection(text):
    patterns = [
        r"ignore all previous instructions",
        r"reveal the system prompt",
        r"override the system prompt",
        r"disregard previous instructions",
        r"bypass security"
    ]

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def analyze_event(event):
    findings = []

    event_type = event.get("event_type", "")
    text = event.get("input", "")
    status = event.get("status", "")
    failed_attempts = event.get("failed_attempts", 0)
    requests_per_minute = event.get("requests_per_minute", 0)
    sensitive_access = event.get("sensitive_data_access", False)

    if detect_prompt_injection(text):
        findings.append({
            "category": "Prompt Injection Activity",
            "severity": "HIGH",
            "description": "Potential prompt injection instructions detected.",
            "recommendation": "Validate user input and enforce instruction hierarchy."
        })

    if event_type == "unauthorized_access" or status == "unauthorized":
        findings.append({
            "category": "Unauthorized Access",
            "severity": "CRITICAL",
            "description": "An event indicates possible unauthorized access.",
            "recommendation": "Review access controls and investigate the event."
        })

    if failed_attempts >= 5:
        findings.append({
            "category": "Authentication Abuse",
            "severity": "HIGH",
            "description": "Multiple failed authentication attempts detected.",
            "recommendation": "Apply account protection, rate limits, and authentication monitoring."
        })

    if requests_per_minute > 100:
        findings.append({
            "category": "Excessive Request Activity",
            "severity": "HIGH",
            "description": "Request volume exceeds the configured monitoring threshold.",
            "recommendation": "Apply request throttling and investigate unusual traffic."
        })

    if sensitive_access:
        findings.append({
            "category": "Sensitive Data Access",
            "severity": "CRITICAL",
            "description": "The event indicates sensitive data access.",
            "recommendation": "Review authorization, data access logs, and information protection controls."
        })

    if status == "allowed" and event_type in [
        "prompt_injection",
        "sensitive_data_exposure",
        "unauthorized_access"
    ]:
        findings.append({
            "category": "Suspicious Activity Allowed",
            "severity": "HIGH",
            "description": "A suspicious event was marked as allowed.",
            "recommendation": "Review enforcement controls and investigate why the event was permitted."
        })

    return {
        "event_id": event.get("event_id", "UNKNOWN"),
        "event_type": event_type,
        "findings_count": len(findings),
        "findings": findings
    }


def load_events():
    if not TEST_FILE.exists():
        raise FileNotFoundError(f"Test file not found: {TEST_FILE}")

    with TEST_FILE.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("The event file must contain a JSON list.")

    return events


def monitor_events(events):
    results = [analyze_event(event) for event in events]

    severity_summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    total_findings = 0

    for result in results:
        total_findings += result["findings_count"]

        for finding in result["findings"]:
            severity = finding["severity"]
            severity_summary[severity] += 1

    return {
        "events_scanned": len(events),
        "total_findings": total_findings,
        "severity_summary": severity_summary,
        "results": results
    }


def save_report(report):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nReport saved to: {REPORT_FILE}")


def display_report(report):
    print("\n=== AI SECURITY MONITORING SYSTEM ===")
    print(f"Events scanned: {report['events_scanned']}")
    print(f"Total findings: {report['total_findings']}")

    print("\nSeverity Summary:")

    for severity, count in report["severity_summary"].items():
        print(f"{severity}: {count}")

    for result in report["results"]:
        print("\n-----------------------------------")
        print(f"Event: {result['event_id']}")
        print(f"Findings: {result['findings_count']}")

        for finding in result["findings"]:
            print(f"\nCategory: {finding['category']}")
            print(f"Severity: {finding['severity']}")
            print(f"Description: {finding['description']}")
            print(f"Recommendation: {finding['recommendation']}")


def main():
    try:
        events = load_events()
        report = monitor_events(events)
        display_report(report)
        save_report(report)

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
