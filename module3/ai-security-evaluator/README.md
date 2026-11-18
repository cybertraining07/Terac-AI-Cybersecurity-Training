# Module 3: AI Security Evaluation Engine

## Project Overview

The AI Security Evaluation Engine is a Python-based, rule-driven security assessment tool designed to identify potentially unsafe content in AI prompts and responses.

It evaluates text against predefined security patterns and classifies detected issues by category and severity.

This project is a practical cybersecurity portfolio exercise.

## Objectives

- Identify possible prompt injection attempts.
- Detect common jailbreak patterns.
- Identify possible sensitive information disclosure.
- Flag potentially unsafe cybersecurity instructions.
- Generate structured JSON security evaluation reports.
- Validate detection logic using automated unit tests.

## Technologies

- Python 3
- Regular expressions
- JSON
- Python unittest
- Kali Linux

## Security Categories

| Category | Severity |
|---|---|
| Prompt Injection | HIGH |
| Jailbreak Attempt | HIGH |
| Sensitive Information Disclosure | HIGH |
| Unsafe Cybersecurity Instructions | MEDIUM |

## Project Structure

```text
ai-security-evaluator/
├── ai_security_evaluator.py
├── README.md
├── evidence/
│   └── .gitkeep
├── reports/
│   ├── .gitkeep
│   └── ai-security-report.json
└── tests/
    ├── sample_prompts.json
    └── test_ai_security_evaluator.py
```

## How to Run

Run the automated tests:

```bash
python3 -m unittest discover -s tests -v
```

Evaluate sample prompts and responses:

```bash
python3 ai_security_evaluator.py tests/sample_prompts.json
```

Validate the generated JSON report:

```bash
python3 -m json.tool reports/ai-security-report.json
```

## Assessment Results

Sample evaluation completed successfully.

- Samples evaluated: 4
- Total findings: 3
- Prompt injection findings: 1
- Jailbreak findings: 1
- Sensitive information disclosure findings: 1
- Safe samples without findings: 1

## Automated Testing

- Total tests: 8
- Passed: 8
- Failed: 0

All eight automated tests passed.

## Limitations

- Detection is based on predefined regular-expression patterns.
- The engine does not connect to or test a live AI model.
- It cannot confirm whether a prompt injection or jailbreak would succeed.
- It may produce false positives and false negatives.
- It does not replace manual AI security testing or a comprehensive security assessment.
- Sample credentials are fictional test data.

## Future Improvements

- Add more prompt injection and jailbreak detection patterns.
- Introduce configurable severity levels.
- Add HTML and CSV reporting.
- Integrate with an AI model evaluation framework.
- Add more tests for false positives and false negatives.

## Conclusion

This project demonstrates a foundational approach to AI security evaluation using Python. It provides automated detection of selected suspicious prompt and response patterns and produces structured reports for further security review.
