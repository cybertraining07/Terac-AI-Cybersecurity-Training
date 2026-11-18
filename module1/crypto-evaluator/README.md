# Cryptographic Security Evaluator

## 1. Project Overview

The Cryptographic Security Evaluator is a Python-based static analysis tool developed to identify potentially insecure cryptographic implementations in Python source code.

The project demonstrates practical application security skills, secure coding analysis, vulnerability identification, automated testing, and security reporting.

It was developed as part of the Terac AI Cybersecurity Training project.

## 2. Project Objectives

- Identify potentially insecure cryptographic algorithms and implementations.
- Detect weak or outdated hashing algorithms.
- Identify insecure RSA encryption patterns.
- Detect possible hardcoded secrets and exposed private-key material.
- Reduce false positives through Python tokenization and AST analysis.
- Generate structured security reports in text and JSON formats.
- Validate detection logic using automated unit tests.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| Regular Expressions | Pattern-based security detection |
| Python AST | Source-code analysis |
| Tokenize | Handling comments and string literals |
| JSON | Structured security reporting |
| Unittest | Automated testing |
| Kali Linux | Development and testing environment |

The evaluator uses Python standard-library modules.

## 4. Security Detection Capabilities

The evaluator includes seven detection categories:

| Detection | Severity |
|---|---|
| Textbook RSA encryption without secure padding | HIGH |
| Legacy RSA PKCS#1 v1.5 padding | HIGH |
| MD5 hashing | MEDIUM |
| SHA-1 hashing | MEDIUM |
| DES encryption | HIGH |
| AES ECB mode | HIGH |
| Possible hardcoded secrets and private-key material | HIGH / CRITICAL |

These rules identify suspicious source-code patterns. Findings require manual review to establish whether the code is genuinely vulnerable.

## 5. Project Structure

```text
crypto-evaluator/
│
├── crypto_evaluator.py
├── secure_crypto_test.py
├── test_crypto_evaluator.py
├── test_false_positives.py
├── test_string_false_positives.py
├── crypto-evaluation-report.txt
├── crypto-evaluation-report.json
├── README.md
│
└── crypto_evaluator.py.backup
```

The backup file is retained for recovery and is not part of the evaluator's normal execution.

## 6. Running the Evaluator

Navigate to the project directory:

```bash
cd ~/Terac-AI-Cybersecurity-Training/module1/crypto-evaluator
```

Scan a Python source file:

```bash
python3 crypto_evaluator.py ../../source-review/encrypt.py
```

The evaluator displays detected findings and generates:

- `crypto-evaluation-report.txt`
- `crypto-evaluation-report.json`

To validate the JSON report:

```bash
python3 -m json.tool crypto-evaluation-report.json
```

## 7. Automated Testing

Run the complete test suite:

```bash
python3 -m unittest -v test_crypto_evaluator.py test_false_positives.py test_string_false_positives.py
```

### Test Results

**14 out of 14 tests passed.**

The tests cover:

- AES ECB detection.
- DES detection.
- Hardcoded secret detection.
- MD5 detection.
- Private-key detection.
- RSA-OAEP false-positive prevention.
- SHA-1 detection.
- Textbook RSA detection.
- Comment false-positive handling.
- Docstring and normal-string false-positive handling.

## 8. Practical Security Investigation

### Target

OWASP Juice Shop — authorized local lab and source-code review.

### Source reviewed

`source-review/encrypt.py`

### Finding

RSA encryption without secure padding.

### Location

Line 14.

### Severity

HIGH.

### Technical observation

The reviewed source contains character-by-character RSA encryption using:

```python
pow(ord(char), e, N)
```

This is a textbook RSA pattern without randomized padding.

Repeated plaintext characters produce repeated ciphertext values, potentially exposing frequency and equality patterns.

### Recommended remediation

Use RSA-OAEP for RSA encryption.

For larger data, use authenticated hybrid encryption, such as AES-GCM for the data and RSA-OAEP to protect the AES key.

## 9. Sample Evaluation Results

| Metric | Result |
|---|---:|
| Files scanned | 1 |
| Total findings | 1 |
| Critical findings | 0 |
| High findings | 1 |
| Medium findings | 0 |
| Low findings | 0 |
| Automated tests passed | 14/14 |

Both text and JSON reports were successfully generated and the JSON report passed validation.

## 10. Limitations

This evaluator is a heuristic static-analysis tool, not a complete cryptographic verification platform.

- Pattern matching can miss vulnerabilities.
- Some legitimate code may trigger findings.
- Static analysis does not establish runtime exploitability.
- A detected pattern does not prove that sensitive data was compromised.
- Human review is required to validate findings and assess their impact.

## 11. Future Improvements

Potential enhancements include:

- Additional cryptographic vulnerability rules.
- More advanced AST-based analysis.
- Configurable severity levels.
- SARIF report export.
- CI/CD pipeline integration.
- Improved test coverage.
- Support for additional programming languages.

## 12. Professional Skills Demonstrated

This project demonstrates practical experience with:

- Python security automation.
- Static application security testing.
- Cryptographic vulnerability identification.
- Secure coding recommendations.
- False-positive reduction.
- Automated testing and debugging.
- JSON and text-based security reporting.
- Technical security documentation.

## 13. Disclaimer

This project is intended for educational purposes and authorized security testing. Only analyze systems and source code for which you have permission.
