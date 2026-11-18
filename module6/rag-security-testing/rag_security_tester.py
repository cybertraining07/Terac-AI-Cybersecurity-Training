
#!/usr/bin/env python3
"""
RAG Security and Data Leakage Evaluator

A rule-based educational evaluator that analyzes simulated
Retrieval-Augmented Generation (RAG) security scenarios.

This tool does not connect to a live AI model, vector database,
or production application.
"""

import json
import re
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "rag-security-report.json"

SEVERITY_ORDER = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
}


def detect_document_injection(text):
    """Detect suspicious instructions embedded in retrieved documents."""

    patterns = [
        r"ignore (all )?(previous|prior) instructions",
        r"disregard (all )?(previous|prior) instructions",
        r"reveal (the )?(system prompt|hidden instructions)",
        r"override (the )?(system|security) instructions",
        r"send (all )?(data|documents|secrets) to",
        r"ignore your (safety|security) rules",
    ]

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def detect_sensitive_information(text):
    """Identify possible sensitive information in retrieved content."""

    patterns = {
        "Possible API key": r"\b(?:sk|api)[-_][A-Za-z0-9_-]{12,}\b",
        "Email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Possible password disclosure": (
            r"\b(password|passwd|secret)\s*[:=]\s*\S+"
        ),
        "Possible private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Possible credit card number": r"\b(?:\d[ -]*?){13,19}\b",
    }

    findings = []

    for description, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(description)

    return findings


def detect_unauthorized_retrieval(document):
    """Identify documents marked as restricted but retrieved by unauthorized users."""

    access_level = str(document.get("access_level", "public")).lower()
    user_role = str(document.get("user_role", "public")).lower()

    restricted_roles = {"admin", "authorized", "internal"}

    if access_level == "restricted" and user_role not in restricted_roles:
        return True

    if access_level == "internal" and user_role == "public":
        return True

    return False


def detect_data_poisoning(text):
    """Identify basic indicators of potentially poisoned document content."""

    patterns = [
        r"always trust this document",
        r"this document overrides all other sources",
        r"ignore verified sources",
        r"fabricated information",
        r"do not verify this information",
        r"replace the original source",
    ]

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def analyze_document(document):
    """Analyze one simulated retrieved document."""

    content = str(document.get("content", ""))
    document_id = document.get("document_id", "UNKNOWN")
    findings = []

    if detect_document_injection(content):
        findings.append({
            "category": "Document-Based Prompt Injection",
            "severity": "HIGH",
            "description": (
                "The document contains instructions that may attempt "
                "to manipulate the RAG system."
            ),
            "recommendation": (
                "Treat retrieved documents as untrusted data. "
                "Separate document content from system instructions."
            ),
        })

    sensitive_items = detect_sensitive_information(content)

    for item in sensitive_items:
        findings.append({
            "category": "Sensitive Information Exposure",
            "severity": "HIGH",
            "description": f"Potential sensitive information detected: {item}.",
            "recommendation": (
                "Review document access permissions and redact sensitive "
                "information when it is not required."
            ),
        })

    if detect_unauthorized_retrieval(document):
        findings.append({
            "category": "Unauthorized Document Retrieval",
            "severity": "CRITICAL",
            "description": (
                "A restricted document appears to have been retrieved "
                "by a user without the required role."
            ),
            "recommendation": (
                "Enforce authorization checks before retrieval and "
                "filter documents by user permissions."
            ),
        })

    if detect_data_poisoning(content):
        findings.append({
            "category": "Potential Data Poisoning",
            "severity": "MEDIUM",
            "description": (
                "The document contains suspicious instructions or "
                "content that may undermine source reliability."
            ),
            "recommendation": (
                "Validate document provenance, review changes, and "
                "compare content against trusted sources."
            ),
        })

    return {
        "document_id": document_id,
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_documents(documents):
    """Analyze all supplied documents and generate a report."""

    results = []
    total_findings = 0
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for document in documents:
        result = analyze_document(document)
        results.append(result)

        for finding in result["findings"]:
            total_findings += 1
            severity = finding["severity"]
            severity_counts[severity] += 1

    return {
        "tool": "RAG Security and Data Leakage Evaluator",
        "assessment_type": "Simulated Rule-Based Assessment",
        "documents_scanned": len(documents),
        "total_findings": total_findings,
        "severity_summary": severity_counts,
        "results": results,
    }


def load_test_cases():
    """Load simulated documents from the tests directory."""

    test_file = BASE_DIR / "tests" / "rag_security_cases.json"

    if not test_file.exists():
        print(f"Error: Test cases file not found: {test_file}")
        sys.exit(1)

    try:
        with test_file.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        print(f"Error: Invalid JSON in test cases: {error}")
        sys.exit(1)

    if not isinstance(data, list):
        print("Error: Test cases must contain a JSON list.")
        sys.exit(1)

    return data


def save_report(report):
    """Save assessment results as JSON."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nReport saved to: {REPORT_FILE}")


def display_report(report):
    """Display a readable summary of assessment results."""

    print("\n=== RAG SECURITY EVALUATOR ===")
    print(f"Documents scanned: {report['documents_scanned']}")
    print(f"Total findings: {report['total_findings']}")

    print("\nSeverity Summary:")

    for severity, count in report["severity_summary"].items():
        print(f"{severity}: {count}")

    for result in report["results"]:
        print("\n-----------------------------------")
        print(f"Document: {result['document_id']}")
        print(f"Findings: {result['findings_count']}")

        for finding in result["findings"]:
            print(f"\nCategory: {finding['category']}")
            print(f"Severity: {finding['severity']}")
            print(f"Description: {finding['description']}")
            print(f"Recommendation: {finding['recommendation']}")


def main():
    documents = load_test_cases()
    report = analyze_documents(documents)
    display_report(report)
    save_report(report)


if __name__ == "__main__":
    main()
