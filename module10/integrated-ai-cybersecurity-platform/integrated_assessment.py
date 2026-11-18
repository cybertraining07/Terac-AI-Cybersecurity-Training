
import json
from pathlib import Path
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = Path(__file__).resolve().parent / "reports"

REPORT_SOURCES = [
    {
        "module": "Module 1 - Cryptographic Security Evaluator",
        "path": "module1/crypto-evaluator/crypto-evaluation-report.json",
    },
    {
        "module": "Module 2 - Web Application Security Assessor",
        "path": "module2/web-security-assessor/reports/juice-shop-security-assessment.json",
    },
    {
        "module": "Module 3 - AI Security Evaluation Engine",
        "path": "module3/ai-security-evaluator/reports/ai-security-report.json",
    },
    {
        "module": "Module 4 - AI Red Team Security Testing",
        "path": "module4/ai-red-team-testing/reports/ai-red-team-report.json",
    },
    {
        "module": "Module 5 - OWASP LLM Security Testing",
        "path": "module5/llm-security-testing/reports/llm-security-report.json",
    },
    {
        "module": "Module 6 - RAG Security Testing",
        "path": "module6/rag-security-testing/reports/rag-security-report.json",
    },
    {
        "module": "Module 7 - AI Agent Security Testing",
        "path": "module7/ai-agent-security-testing/reports/ai-agent-security-report.json",
    },
    {
        "module": "Module 8 - AI Model Security Testing",
        "path": "module8/ai-model-security-testing/reports/ai-model-security-report.json",
    },
    {
        "module": "Module 9 - AI Security Monitoring",
        "path": "module9/ai-security-monitoring/reports/ai-security-monitor-report.json",
    },
]

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def normalize_finding(finding, module, report_path, record_id=None):
    """Convert a finding into a consistent structure."""

    return {
        "module": module,
        "source_report": report_path,
        "record_id": record_id,
        "category": (
            finding.get("category")
            or finding.get("type")
            or finding.get("name")
            or finding.get("header")
            or "Uncategorized Finding"
        ),
        "severity": str(finding.get("severity", "UNKNOWN")).upper(),
        "description": finding.get("description", "No description provided."),
        "recommendation": finding.get(
            "recommendation", "Manual security review recommended."
        ),
        "original_finding": finding,
    }


def extract_findings(data, module, report_path):
    """Extract findings from standalone and nested JSON report formats."""

    extracted = []

    def walk(node, record_id=None):
        if isinstance(node, dict):
            current_id = (
                node.get("id")
                or node.get("event_id")
                or node.get("document_id")
                or node.get("scenario_id")
                or record_id
            )

            for key, value in node.items():
                if key == "findings" and isinstance(value, list):
                    for finding in value:
                        if isinstance(finding, dict):
                            extracted.append(
                                normalize_finding(
                                    finding,
                                    module,
                                    report_path,
                                    current_id,
                                )
                            )
                elif isinstance(value, (dict, list)):
                    walk(value, current_id)

        elif isinstance(node, list):
            for item in node:
                walk(item, record_id)

    walk(data)
    return extracted


def load_report(source):
    """Load and validate one assessment report."""

    report_path = source["path"]
    full_path = ROOT / report_path

    if not full_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")

    with full_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object: {report_path}")

    findings = extract_findings(
        data,
        source["module"],
        report_path,
    )

    return {
        "module": source["module"],
        "source_report": report_path,
        "findings_count": len(findings),
        "findings": findings,
    }


def build_assessment():
    """Combine all available module assessment reports."""

    modules = []
    errors = []
    all_findings = []

    for source in REPORT_SOURCES:
        try:
            result = load_report(source)
            modules.append(result)
            all_findings.extend(result["findings"])

        except (OSError, json.JSONDecodeError, ValueError) as error:
            errors.append({
                "module": source["module"],
                "source_report": source["path"],
                "error": str(error),
            })

    severity_summary = {
        severity: sum(
            1 for finding in all_findings
            if finding["severity"] == severity
        )
        for severity in SEVERITIES
    }

    unknown_count = sum(
        1 for finding in all_findings
        if finding["severity"] not in SEVERITIES
    )

    return {
        "platform": "Integrated AI Cybersecurity Assessment Platform",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modules_expected": len(REPORT_SOURCES),
        "modules_processed": len(modules),
        "modules_failed": len(errors),
        "total_findings": len(all_findings),
        "severity_summary": severity_summary,
        "unknown_severity_findings": unknown_count,
        "modules": modules,
        "findings": all_findings,
        "errors": errors,
        "assessment_scope": (
            "Integration of existing educational, rule-based assessment "
            "reports. Findings are indicators for review, not proof of "
            "successful attacks or confirmed vulnerabilities."
        ),
    }


def save_report(report):
    """Save the consolidated assessment as JSON."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "integrated-security-report.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_path


def display_report(report):
    """Display a summary of the integrated assessment."""

    print("\n=== INTEGRATED AI CYBERSECURITY ASSESSMENT ===")
    print(f"Modules expected: {report['modules_expected']}")
    print(f"Modules processed: {report['modules_processed']}")
    print(f"Modules failed: {report['modules_failed']}")
    print(f"Total findings: {report['total_findings']}")

    print("\nSeverity Summary:")

    for severity, count in report["severity_summary"].items():
        print(f"{severity}: {count}")

    print(
        "UNKNOWN: "
        f"{report['unknown_severity_findings']}"
    )

    print("\nModule Summary:")

    for module in report["modules"]:
        print(
            f"{module['module']}: "
            f"{module['findings_count']} findings"
        )

    if report["errors"]:
        print("\nReport Loading Errors:")

        for error in report["errors"]:
            print(f"- {error['module']}: {error['error']}")

    print("\nAssessment scope:")
    print(report["assessment_scope"])


def main():
    report = build_assessment()
    output_path = save_report(report)
    display_report(report)

    print(f"\nConsolidated report saved to: {output_path}")

    if report["modules_failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
