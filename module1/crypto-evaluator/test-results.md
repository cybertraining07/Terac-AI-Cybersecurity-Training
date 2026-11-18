# Cryptographic Security Evaluator — Test Results

## 1. Project Overview

The Cryptographic Security Evaluator is a Python-based static analysis tool designed to identify potentially insecure cryptographic implementations in Python source code.

## 2. Automated Test Results

**Overall result: 14/14 tests passed.**

| Test | Result |
|---|---|
| AES ECB detection | PASS |
| DES detection | PASS |
| Hardcoded secret detection | PASS |
| MD5 detection | PASS |
| Private-key detection | PASS |
| RSA-OAEP false-positive prevention | PASS |
| SHA-1 detection | PASS |
| Textbook RSA detection | PASS |
| DES in comments | PASS |
| MD5 in comments | PASS |
| Password in comments | PASS |
| MD5 in docstrings | PASS |
| MD5 in normal strings | PASS |
| Password in normal strings | PASS |

## 3. Practical Security Evaluation

### Test 1: Insecure RSA Pattern

**Target:** `source-review/encrypt.py`

**Detection pattern:**
```python
pow(ord(char), e, N)
```

Expected result: HIGH severity finding.

Actual result: One finding detected at line 14.

Status: PASS

### Test 2: RSA-OAEP Example

**Target:** `secure_crypto_test.py`

**Encryption method:** RSA-OAEP with SHA-256.

Expected result: No textbook RSA finding.

Actual result: The automated RSA-OAEP false-positive prevention test passed.

Status: PASS

## 4. Report Validation

| Validation | Result |
|---|---|
| Python syntax check | PASS |
| Text report generated | PASS |
| JSON report generated | PASS |
| JSON format validation | PASS |
| Security finding generated | PASS |

## 5. Limitations

- Pattern-based detection may produce false positives and false negatives.
- No complete cryptographic data-flow analysis.
- Static analysis does not establish runtime exploitability.
- Manual security review is required.

## 6. Conclusion

The evaluator successfully identified the tested textbook RSA pattern and passed all 14 automated tests.

The project demonstrates practical skills in Python security automation, cryptographic vulnerability detection, static analysis, false-positive handling, automated testing, and security reporting.
