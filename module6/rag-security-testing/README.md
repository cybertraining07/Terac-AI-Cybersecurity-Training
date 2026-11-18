
# Module 6: RAG Security and Data Leakage Testing

## Project Overview

The RAG Security and Data Leakage Evaluator is an educational Python-based security assessment tool designed to identify common security risks associated with Retrieval-Augmented Generation (RAG) systems.

The evaluator analyzes simulated retrieved documents and identifies suspicious content, potential sensitive information exposure, unauthorized document retrieval scenarios, and possible data poisoning indicators.

## Objectives

- Understand Retrieval-Augmented Generation (RAG) security.
- Identify document-based prompt injection attempts.
- Detect potential sensitive information exposure.
- Identify unauthorized document retrieval scenarios.
- Recognize basic data poisoning indicators.
- Generate structured JSON security assessment reports.
- Apply automated Python unit testing.

## Security Checks

| Security Category | Description |
|---|---|
| Document-Based Prompt Injection | Detects suspicious instructions embedded in retrieved documents. |
| Sensitive Information Exposure | Identifies possible email addresses, passwords, API keys, private keys, and payment card numbers. |
| Unauthorized Document Retrieval | Identifies simulated access to restricted documents by unauthorized roles. |
| Potential Data Poisoning | Detects suspicious instructions that may undermine document reliability. |

## Project Structure

```text
rag-security-testing/
├── README.md
├── rag_security_tester.py
├── evidence/
├── reports/
│   └── rag-security-report.json
└── tests/
    ├── rag_security_cases.json
    └── test_rag_security_tester.py
```

## Technologies Used

- Python 3
- Python Regular Expressions
- JSON
- Python unittest framework
- Kali Linux
- Git and GitHub

## How to Run

Run the evaluator:

```bash
python3 module6/rag-security-testing/rag_security_tester.py
```

Run automated tests:

```bash
python3 -m unittest discover -s module6/rag-security-testing/tests -v
```

Validate the JSON report:

```bash
python3 -m json.tool module6/rag-security-testing/reports/rag-security-report.json
```

## Assessment Results

The simulated assessment analyzed seven documents.

| Metric | Result |
|---|---:|
| Documents scanned | 7 |
| Total findings | 6 |
| Critical findings | 1 |
| High findings | 4 |
| Medium findings | 1 |
| Low findings | 0 |

### Findings

- 2 document-based prompt injection findings.
- 2 sensitive information exposure findings.
- 1 unauthorized document retrieval finding.
- 1 potential data poisoning finding.

## Automated Testing

The project includes ten automated unit tests covering:

1. Document prompt injection detection.
2. Safe document handling.
3. Email address detection.
4. Password disclosure detection.
5. Unauthorized document retrieval.
6. Authorized document retrieval.
7. Data poisoning detection.
8. Safe document handling against poisoning indicators.
9. Document analysis.
10. Assessment report summary.

**Test result: 10/10 tests passed.**

## Security Recommendations

- Treat retrieved documents as untrusted input.
- Separate system instructions from retrieved document content.
- Enforce authorization checks before retrieving documents.
- Apply document-level access controls.
- Validate document sources and provenance.
- Redact sensitive information when appropriate.
- Monitor document changes and suspicious content.

## Limitations

This project is a simulated, rule-based educational security evaluator.

It does not connect to a live AI model, embedding service, vector database, or production RAG application.

Its findings are pattern-based indicators, not proof of successful exploitation or an actual security breach. The simulated authorization check evaluates supplied document metadata rather than enforcing real access controls.

The evaluator may produce false positives or miss threats that do not match its detection patterns.

## Learning Outcomes

- Understanding RAG architecture and common security risks.
- Applying Python to security assessment automation.
- Building rule-based detection mechanisms.
- Generating machine-readable security reports.
- Writing automated unit tests.
- Documenting security findings and recommendations.

## Disclaimer

This project is intended for educational purposes and authorized security testing only. All assessment scenarios use simulated data.
