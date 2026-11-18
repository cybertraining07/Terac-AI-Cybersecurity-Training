
import re
import sys
import json
import ast
import io
import tokenize

from pathlib import Path
from datetime import datetime


# ==========================================
# CRYPTOGRAPHIC SECURITY DETECTION RULES
# ==========================================

RULES = [
    {
        "name": "RSA encryption without secure padding",
        "pattern": r"pow\s*\(\s*ord\s*\(",
        "severity": "HIGH",
        "description": (
            "Possible textbook RSA encryption detected. "
            "Character-by-character RSA without randomized "
            "padding can leak patterns."
        ),
        "recommendation": (
            "Use RSA-OAEP for RSA encryption, or use "
            "authenticated hybrid encryption such as "
            "AES-GCM with RSA-OAEP."
        )
    },
    {
        "name": "Legacy RSA PKCS1 v1.5 encryption",
        "pattern": r"PKCS1_v1_5|PKCS1v15\s*\(",
        "severity": "HIGH",
        "description": "Legacy RSA PKCS#1 v1.5 encryption API detected.",
        "recommendation": "Prefer RSA-OAEP for new RSA encryption implementations."
    },
    {
        "name": "Weak hash algorithm",
        "pattern": r"\bMD5\b|\bmd5\s*\(|\bSHA1\b|\bsha1\s*\(",
        "severity": "MEDIUM",
        "description": (
            "MD5 or SHA-1 usage detected. These algorithms are "
            "unsuitable for many modern security purposes."
        ),
        "recommendation": (
            "Use SHA-256 or SHA-3 for general hashing. "
            "Use Argon2id, scrypt or bcrypt for password hashing."
        )
    },
    {
        "name": "Potential DES encryption",
        "pattern": r"\bDES\s*\(|\bDES\.new\s*\(",
        "severity": "HIGH",
        "description": "Potential use of the outdated DES encryption algorithm.",
        "recommendation": (
            "Replace DES with a modern authenticated encryption "
            "algorithm such as AES-GCM."
        )
    },
    {
        "name": "AES ECB mode",
        "pattern": r"AES\.MODE_ECB|modes\.ECB\s*\(",
        "severity": "HIGH",
        "description": (
            "AES Electronic Codebook (ECB) mode detected. "
            "ECB can reveal patterns in encrypted data."
        ),
        "recommendation": "Use AES-GCM or another secure authenticated encryption mode."
    },
    {
        "name": "Private key material",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "A private key header appears in the source file.",
        "recommendation": (
            "Never commit private keys to source code. "
            "Store them securely and rotate exposed keys."
        )
    },
    {
        "name": "Possible hardcoded secret",
        "pattern": (
            r"(?i)\b(?:password|passwd|secret|api_key|apikey|access_token)"
            r"\b\s*=\s*['\"][^'\"]{4,}['\"]"
        ),
        "severity": "HIGH",
        "description": (
            "A possible hardcoded password, API key or secret "
            "assignment was detected."
        ),
        "recommendation": (
            "Use environment variables or a secure secrets manager "
            "instead of hardcoding credentials."
        )
    }
]


# ==========================================
# SOURCE CODE SCANNER
# ==========================================

def scan_file(file_path):

    findings = []

    try:
        source = file_path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        lines = source.splitlines(keepends=True)

        # Parse Python source.
        tree = ast.parse(source, filename=str(file_path))

        # Tokenize source code.
        tokens = tokenize.generate_tokens(
            io.StringIO(source).readline
        )

        # Mask comments and strings to reduce false positives.
        for token in tokens:

            if token.type not in (
                tokenize.COMMENT,
                tokenize.STRING
            ):
                continue

            start_line, start_col = token.start
            end_line, end_col = token.end

            if start_line == end_line:

                line = lines[start_line - 1]

                lines[start_line - 1] = (
                    line[:start_col]
                    + " " * (end_col - start_col)
                    + line[end_col:]
                )

            else:

                for line_number in range(
                    start_line,
                    end_line + 1
                ):

                    index = line_number - 1
                    line = lines[index]

                    left = (
                        start_col
                        if line_number == start_line
                        else 0
                    )

                    right = (
                        end_col
                        if line_number == end_line
                        else len(line.rstrip("\r\n"))
                    )

                    lines[index] = (
                        line[:left]
                        + " " * max(0, right - left)
                        + line[right:]
                    )

        # Detect cryptographic patterns in executable code.
        for line_number, line in enumerate(lines, start=1):

            for rule in RULES:

                if re.search(rule["pattern"], line):

                    findings.append({
                        "file": str(file_path),
                        "line": line_number,
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommendation": rule["recommendation"]
                    })

        # Detect possible hardcoded secrets through AST.
        secret_names = {
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token"
        }

        for node in ast.walk(tree):

            if isinstance(node, ast.Assign):

                targets = node.targets
                value = node.value

            elif isinstance(node, ast.AnnAssign):

                targets = [node.target]
                value = node.value

            elif isinstance(node, ast.NamedExpr):

                targets = [node.target]
                value = node.value

            else:

                targets = []
                value = None

            for target in targets:

                if not isinstance(target, ast.Name):
                    continue

                if (
                    target.id.lower() in secret_names
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and len(value.value) >= 4
                ):

                    findings.append({
                        "file": str(file_path),
                        "line": node.lineno,
                        "name": "Possible hardcoded secret",
                        "severity": "HIGH",
                        "description": (
                            "A string value is assigned to "
                            "a sensitive variable name."
                        ),
                        "recommendation": (
                            "Use environment variables or "
                            "a secure secrets manager."
                        )
                    })

            # Detect private keys stored in string constants.
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "-----BEGIN " in node.value
                and "PRIVATE KEY-----" in node.value
            ):

                findings.append({
                    "file": str(file_path),
                    "line": node.lineno,
                    "name": "Private key material",
                    "severity": "CRITICAL",
                    "description": (
                        "A private key header appears in "
                        "a string constant."
                    ),
                    "recommendation": (
                        "Remove private keys from source code "
                        "and securely rotate exposed keys."
                    )
                })

    except (
        OSError,
        SyntaxError,
        tokenize.TokenError,
        IndentationError
    ) as error:

        print(f"Could not scan {file_path}: {error}")
        return findings

    return findings


# ==========================================
# SEVERITY SUMMARY
# ==========================================

def calculate_severity_summary(findings):

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:

        severity = finding["severity"]

        summary[severity] = summary.get(severity, 0) + 1

    return summary


# ==========================================
# TEXT REPORT GENERATOR
# ==========================================

def generate_report(findings, files_scanned):

    report_path = Path("crypto-evaluation-report.txt")

    severity_summary = calculate_severity_summary(findings)

    lines = [
        "CRYPTOGRAPHIC SECURITY EVALUATION REPORT",
        "=" * 45,
        f"Date: {datetime.now().isoformat(timespec='seconds')}",
        f"Files scanned: {files_scanned}",
        f"Total findings: {len(findings)}",
        "",
        "SEVERITY SUMMARY",
        "-" * 30
    ]

    for severity, count in severity_summary.items():

        lines.append(f"{severity}: {count}")

    lines.extend([
        "",
        "DETAILED FINDINGS",
        "-" * 30
    ])

    for finding in findings:

        lines.extend([
            f"File: {finding['file']}",
            f"Line: {finding['line']}",
            f"Finding: {finding['name']}",
            f"Severity: {finding['severity']}",
            f"Description: {finding['description']}",
            f"Recommendation: {finding['recommendation']}",
            ""
        ])

    report_path.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    return report_path


# ==========================================
# JSON REPORT GENERATOR
# ==========================================

def generate_json_report(findings, files_scanned):

    json_path = Path("crypto-evaluation-report.json")

    report = {
        "project": "Cryptographic Security Evaluator",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "severity_summary": calculate_severity_summary(findings),
        "findings": findings
    }

    json_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    return json_path


# ==========================================
# MAIN COMMAND-LINE FUNCTION
# ==========================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python3 crypto_evaluator.py "
            "<file_or_directory>"
        )

        sys.exit(1)

    target = Path(sys.argv[1]).expanduser()

    if not target.exists():

        print(f"Error: Target does not exist: {target}")
        sys.exit(1)

    if target.is_file():

        files = [target] if target.suffix == ".py" else []

    elif target.is_dir():

        files = [
            file
            for file in target.rglob("*.py")
            if file.resolve() != Path(__file__).resolve()
        ]

    else:

        files = []

    if not files:

        print("No Python files found to scan.")
        sys.exit(1)

    all_findings = []

    for file_path in files:

        print(f"Scanning: {file_path}")

        all_findings.extend(
            scan_file(file_path)
        )

    # Display scan summary.
    print("\n=== CRYPTOGRAPHIC SECURITY EVALUATOR ===")
    print(f"Files scanned: {len(files)}")
    print(f"Findings: {len(all_findings)}")

    # Display detailed findings.
    for finding in all_findings:

        print("\n-----------------------------------")
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Finding: {finding['name']}")
        print(f"Severity: {finding['severity']}")
        print(f"Description: {finding['description']}")
        print(f"Recommendation: {finding['recommendation']}")

    # Generate both reports.
    text_report = generate_report(
        all_findings,
        len(files)
    )

    json_report = generate_json_report(
        all_findings,
        len(files)
    )

    print("\n=== REPORTS GENERATED ===")
    print(f"Text report: {text_report.resolve()}")
    print(f"JSON report: {json_report.resolve()}")


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
