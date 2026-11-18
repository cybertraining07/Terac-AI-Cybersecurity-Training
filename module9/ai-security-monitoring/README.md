
# Module 9: AI Security Monitoring and Threat Detection

## Project Overview

This project implements a Python-based AI Security Monitoring and Threat Detection System.

It analyzes simulated AI application security events to identify suspicious activity, classify potential threats, and generate structured JSON security reports.

## Security Monitoring Capabilities

The system detects:

1. Prompt injection activity.
2. Unauthorized access indicators.
3. Repeated authentication failures.
4. Excessive request activity.
5. Sensitive data access.
6. Suspicious activity marked as allowed.

## Technologies Used

- Python 3
- JSON
- Regular expressions
- Python unittest framework
- Kali Linux

## Project Structure

```text
ai-security-monitoring/
├── ai_security_monitor.py
├── README.md
├── tests/
│   ├── ai_security_events.json
│   └── test_ai_security_monitor.py
├── reports/
│   └── ai-security-monitor-report.json
└── evidence/
```

## How to Run

Run the monitoring system:

```bash
python3 ai_security_monitor.py
```

Run the unit tests:

```bash
python3 -m unittest discover -s tests -v
```

Validate the simulated security events:

```bash
python3 -m json.tool tests/ai_security_events.json
```

## Assessment Results

Seven simulated security events were analyzed.

| Severity | Findings |
|---|---:|
| Critical | 3 |
| High | 5 |
| Medium | 0 |
| Low | 0 |
| **Total** | **8** |

The assessment detected prompt injection, unauthorized access indicators, authentication abuse, excessive request activity, and sensitive data access.

## Testing Results

- Total unit tests: 10
- Passed: 10
- Failed: 0

## Security Recommendations

- Validate untrusted input.
- Enforce access control and authorization.
- Monitor repeated authentication failures.
- Apply request throttling.
- Protect sensitive information.
- Investigate suspicious activity marked as allowed.

## Limitations

This is an educational, rule-based monitoring tool.

It analyzes predefined simulated events and does not connect to live AI applications, production security logs, or SIEM platforms.

Its findings are indicators for investigation, not proof of successful attacks or confirmed vulnerabilities.

## Learning Outcomes

This project demonstrates practical understanding of:

- AI application security monitoring.
- Threat detection and classification.
- Prompt injection indicators.
- Authentication abuse detection.
- Access control monitoring.
- Security event analysis.
- Automated JSON reporting.
- Python unit testing.
