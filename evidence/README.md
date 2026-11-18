# Terac AI Cybersecurity Training — Evidence Index

## Module 1: Cryptographic Security Evaluation

This directory contains evidence collected during authorized OWASP Juice Shop lab testing and the development of the Python Cryptographic Security Evaluator.

### Evidence inventory

| File | Description |
|---|---|
| `legal.md` | Authorization and legal testing scope |
| `acquisitions.md` | Evidence acquisition notes |
| `ciphertext-analysis.txt` | Analysis of repeated ciphertext values |
| `rsa-oaep-comparison.txt` | RSA-OAEP randomization and decryption demonstration |
| `crypto-evaluation-report.txt` | Cryptographic scanner findings |
| `file-access-validation.txt` | Validation of file access |
| `gobuster-results.txt` | Directory discovery results |
| `gobuster-module1-final.txt` | Final directory discovery evidence |

## Key Security Finding

**Finding:** Deterministic character-by-character RSA encryption without randomized padding.

**Severity:** HIGH

**Evidence:** `ciphertext-analysis.txt` and the supporting analysis script in `source-review/analyze_ciphertext.py`.

The ciphertext analysis recorded 1,194 values, of which 43 were unique. This is consistent with repeated plaintext characters producing repeated ciphertext values.

This demonstrates pattern leakage. It does not establish plaintext recovery or private-key exposure.

## Secure Cryptography Demonstration

`rsa-oaep-comparison.txt` documents five RSA-OAEP encryptions of the same message.

Results:
- Five encryptions performed.
- Five unique ciphertexts produced.
- Original plaintext successfully recovered.

This demonstrates RSA-OAEP randomization and successful decryption.

## Python Security Evaluator

The evaluator source code and its supporting reports are maintained in:

`module1/crypto-evaluator/`

The automated test suite passed all 14 tests.

## Supporting Source Review

The `source-review/` directory contains:
- `analyze_ciphertext.py` — ciphertext pattern analysis.
- `rsa_comparison.py` — RSA encryption comparison.

## Evidence Handling

All testing was performed in an authorized local OWASP Juice Shop environment or through source-code review.

Evidence should be preserved in its original form. Any future modifications should be documented separately.
