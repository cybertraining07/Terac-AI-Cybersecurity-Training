# Module 5: OWASP LLM Application Security Testing

## Project Overview

The OWASP LLM Application Security Tester is a Python-based, rule-driven security evaluation tool designed to identify suspicious content associated with common Large Language Model (LLM) application security risks.

The project evaluates simulated security test cases against predefined detection patterns and generates structured JSON assessment reports.

This is a practical cybersecurity portfolio project. It does not connect to or perform penetration testing against a live AI model.

## Project Objectives

- Identify possible prompt injection attempts.
- Detect potential sensitive information disclosure.
- Identify system prompt extraction attempts.
- Detect potentially insecure HTML and JavaScript output.
- Identify excessive agency risks.
- Detect common jailbreak patterns.
- Generate structured security assessment reports.
- Validate detection logic through automated unit tests.

## Technologies

- Python 3
- Regular expressions
- JSON
- Python unittest
- Kali Linux

## Security Assessment Categories

| Security Category | Severity |
|---|---|
| Prompt Injection | HIGH |
| Sensitive Information Disclosure | CRITICAL |
| System Prompt Extraction | HIGH |
| Insecure Output Handling | HIGH |
| Excessive Agency | HIGH |
| Jailbreak Attempt | HIGH |

## Project Structure

```text
llm-security-testing/
├── llm_security_tester.py
├── README.md
├── evidence/
├── reports/
│   └── llm-security-report.json
└── tests/
    ├── llm_security_cases.json
    └── test_llm_security_tester.py
```

## How to Run

Run automated tests:

```bash
python3 -m unittest discover -s tests -v
```

Execute the security assessment:

```bash
python3 llm_security_tester.py tests/llm_security_cases.json
```

View the JSON assessment report:

```bash
python3 -m json.tool reports/llm-security-report.json
```

## Assessment Results

Seven simulated LLM security test cases were evaluated.

- Total test cases: 7
- Total findings: 6
- Critical findings: 1
- High findings: 5
- Safe test cases without rule matches: 1

### Findings Breakdown

| Test ID | Category | Severity |
|---|---|---|
| LLM-001 | Prompt Injection | HIGH |
| LLM-002 | Sensitive Information Disclosure | CRITICAL |
| LLM-003 | System Prompt Extraction | HIGH |
| LLM-004 | Insecure Output Handling | HIGH |
| LLM-005 | Excessive Agency | HIGH |
| LLM-006 | Jailbreak Attempt | HIGH |
| LLM-007 | Safe Prompt | No finding |

Note: LLM-005 and LLM-006 each matched two patterns within one security category. Each category is counted as one finding for that test case.

The sensitive-information test uses a fictional API key for detection testing, not a real credential.

## Automated Testing

- Total automated tests: 11
- Passed: 11
- Failed: 0

All eleven automated unit tests passed.

## Security Observations

The assessment demonstrated that predefined detection rules can identify selected patterns associated with common LLM application security risks.

The evaluator identified simulated prompt injection, sensitive information patterns, system prompt extraction attempts, potentially unsafe output, excessive agency instructions and jailbreak attempts.

The safe test case was not flagged by the configured rules.

## Limitations

- Detection relies on predefined regular expressions.
- The evaluator does not connect to a live LLM.
- It does not prove that an identified vulnerability is exploitable.
- It does not verify actual disclosure of confidential information.
- It does not execute JavaScript or test browser behavior.
- False positives and false negatives are possible.
- It is not a replacement for comprehensive LLM application security testing.

## Future Improvements

- Integrate an authorized LLM testing environment.
- Add multi-turn prompt injection scenarios.
- Test RAG application security.
- Introduce contextual risk analysis.
- Add configurable severity levels.
- Add HTML and CSV reporting.
- Evaluate actual model responses against expected security outcomes.

## Conclusion

This project demonstrates foundational LLM application security evaluation using Python.

It provides automated identification of selected security-related text patterns, structured findings, JSON reporting and automated testing.

The project provides a foundation for more advanced GenAI security assessment and red-team testing.
