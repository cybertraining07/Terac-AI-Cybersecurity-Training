# Module 4: Advanced AI Red Team Security Testing

## Project Overview

The Advanced AI Red Team Security Tester is a Python-based, rule-driven assessment tool designed to identify suspicious content associated with common AI security risks.

The project simulates adversarial test cases and evaluates them against predefined security detection patterns.

It generates structured JSON reports to support security review and documentation.

This is a practical cybersecurity portfolio project and does not connect to or attack a live AI model.

## Project Objectives

- Detect direct prompt injection attempts.
- Identify possible indirect prompt injection.
- Detect system-prompt extraction attempts.
- Identify common jailbreak patterns.
- Detect possible sensitive information exposure.
- Identify potentially insecure HTML and JavaScript output.
- Generate structured JSON security reports.
- Validate detection logic through automated unit tests.

## Technologies

- Python 3
- Regular expressions
- JSON
- Python unittest
- Kali Linux

## Security Assessment Categories

| Category | Severity |
|---|---|
| Direct Prompt Injection | HIGH |
| Indirect Prompt Injection | HIGH |
| System Prompt Extraction Attempt | HIGH |
| Jailbreak Attempt | HIGH |
| Sensitive Information Exposure | HIGH |
| Insecure Output Handling | MEDIUM |

## Project Structure

```text
ai-red-team-testing/
├── ai_red_team_tester.py
├── README.md
├── evidence/
│   └── .gitkeep
├── reports/
│   ├── .gitkeep
│   └── ai-red-team-report.json
└── tests/
    ├── red_team_cases.json
    └── test_ai_red_team_tester.py
```

## How to Run

Run automated tests:

```bash
python3 -m unittest discover -s tests -v
```

Execute the red-team evaluation:

```bash
python3 ai_red_team_tester.py tests/red_team_cases.json
```

Validate the JSON report:

```bash
python3 -m json.tool reports/ai-red-team-report.json
```

## Assessment Results

Seven simulated AI security test cases were evaluated.

- Test cases evaluated: 7
- Total findings: 7
- Direct prompt injection: 1
- Indirect prompt injection: 1
- System-prompt extraction attempts: 2
- Jailbreak attempts: 1
- Sensitive information exposure: 1
- Insecure output handling: 1
- Safe samples without findings: 1

Note: RT-001 generated two findings because it contained two separate suspicious patterns.

## Automated Testing

- Total automated tests: 10
- Passed: 10
- Failed: 0

All ten automated tests passed.

## Security Testing Observations

The evaluation demonstrated that predefined rules can identify several common patterns associated with AI security risks.

The test cases included simulated adversarial instructions, suspicious document content, sensitive-data patterns, and potentially unsafe HTML or JavaScript output.

The safe test case was not flagged by the configured rules.

## Limitations

- Detection relies on predefined regular expressions.
- The engine does not connect to a live AI model.
- It does not prove that a prompt injection or jailbreak succeeds.
- It does not verify whether confidential system instructions were actually disclosed.
- It does not execute or test JavaScript payloads.
- False positives and false negatives are possible.
- It is not a replacement for comprehensive AI red-team testing.

## Future Improvements

- Integrate an authorized AI model testing environment.
- Add multi-turn prompt injection scenarios.
- Evaluate model responses against expected security outcomes.
- Introduce configurable severity levels.
- Add HTML and CSV reporting.
- Improve detection using contextual analysis.
- Add additional false-positive and false-negative tests.

## Conclusion

This project demonstrates foundational AI red-team security evaluation using Python.

It provides automated identification of selected adversarial text patterns, structured findings, and JSON reporting.

The project establishes a foundation for more advanced AI security testing and GenAI security evaluation work.
