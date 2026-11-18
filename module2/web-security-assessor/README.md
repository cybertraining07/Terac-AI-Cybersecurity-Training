# Module 2 – Web Application Security Assessor

## Terac AI Cybersecurity Training

### Project Overview

This project implements a Python-based Web Application Security Assessor designed to evaluate HTTP response security headers on authorized web applications.

The tool identifies missing security headers, assigns severity levels, provides remediation recommendations, and generates JSON assessment reports.

### Objectives

- Assess HTTP response security headers.
- Identify missing security controls.
- Classify findings by severity.
- Generate machine-readable JSON reports.
- Validate detection logic through automated unit tests.

### Technologies

- Python 3
- Kali Linux
- Docker
- OWASP Juice Shop
- Git and GitHub
- Python unittest
- JSON

### Security Headers Evaluated

| Header | Purpose |
|---|---|
| Content-Security-Policy | Helps mitigate XSS and content injection risks |
| Strict-Transport-Security | Enforces HTTPS in supporting browsers |
| X-Content-Type-Options | Helps prevent MIME-type sniffing |
| X-Frame-Options | Helps protect against clickjacking |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Restricts browser features |

### Project Structure

```text
web-security-assessor/
├── web_security_assessor.py
├── README.md
├── tests/
│   └── test_web_security_assessor.py
├── reports/
│   └── juice-shop-security-assessment.json
└── evidence/
```

### Lab Environment

Target: OWASP Juice Shop

URL: http://127.0.0.1:3000

Environment: Authorized local Docker lab

HTTP response status: 200 OK

### Assessment Results

The initial assessment identified four missing response headers:

| Finding | Severity |
|---|---|
| Content-Security-Policy | HIGH |
| Strict-Transport-Security | HIGH |
| Referrer-Policy | LOW |
| Permissions-Policy | LOW |

The application response included X-Content-Type-Options and X-Frame-Options.

**Important:** HSTS is intended for HTTPS deployments. Its absence on this HTTP-only local test endpoint is an observation, not proof of a production vulnerability. Findings require contextual and manual validation.

### Automated Testing

Six automated tests were executed successfully.

- Missing-header detection
- Present-header validation
- Case-insensitive header matching
- Severity validation
- Recommendation validation
- Security-header configuration validation

Test result: 6/6 passed.

### Report Generation

The assessor generates a JSON report containing:

- Target URL
- Assessment timestamp
- HTTP status
- Number of response headers analyzed
- Finding count
- Finding severity
- Descriptions
- Remediation recommendations

### Limitations

- This is a basic HTTP response-header assessment tool.
- It does not perform authenticated application testing.
- It does not prove that a vulnerability is exploitable.
- It does not assess application business logic.
- It does not replace a comprehensive penetration test.
- Findings require manual verification.

### Authorization and Ethics

Testing is restricted to systems for which explicit authorization has been obtained. This project was tested against a local OWASP Juice Shop environment.

### Future Improvements

- Cookie security attribute analysis
- HTTP method assessment
- TLS configuration checks
- Sensitive endpoint exposure checks
- HTML and PDF report generation
- Improved severity and confidence scoring

### Conclusion

Module 2 demonstrates practical Python security automation, HTTP protocol analysis, vulnerability documentation, automated testing, and professional security reporting.


## Cookie Security Analysis

The assessor checks HTTP response cookies for three security attributes:

- Secure: Restricts cookie transmission to HTTPS connections.
- HttpOnly: Prevents JavaScript access to the cookie.
- SameSite: Helps control cross-site cookie transmission.

The assessor supports multiple Set-Cookie response headers and evaluates
each cookie independently.

### Cookie Assessment Results

During the OWASP Juice Shop HTTP assessment:

- Cookies received: 0
- Cookie findings: 0

No Set-Cookie headers were returned in the tested response.
Therefore, cookie security could not be evaluated on this request.

This does not establish that all application cookies are secure.

## Assessment Results

Target: http://127.0.0.1:3000

- HTTP Status: 200
- Response headers analyzed: 14
- Missing-header observations: 4
- Cookie findings: 0
- Total findings: 4

The four missing-header observations were:

1. Content-Security-Policy — HIGH
2. Strict-Transport-Security — HIGH
3. Referrer-Policy — LOW
4. Permissions-Policy — LOW

HSTS requires HTTPS context. Its absence from this HTTP response
does not establish a production HTTPS vulnerability.

## Automated Testing

Total automated tests: 13

Result: 13 passed, 0 failed.

Test coverage includes:

- Missing HTTP security headers.
- Case-insensitive header matching.
- Header severity and recommendations.
- Cookie Secure attribute.
- Cookie HttpOnly attribute.
- Cookie SameSite attribute.
- Multiple cookies.
- Cookies with all required attributes.
- Empty cookie responses.

## Current Limitations

- Cookie analysis depends on cookies returned by the tested response.
- The assessor does not perform authenticated testing.
- It does not test application business logic.
- Missing headers are observations, not proof of exploitability.
- It is not a replacement for a full penetration test.
