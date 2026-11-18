
import tempfile
import unittest
from pathlib import Path

from crypto_evaluator import scan_file


class CryptoEvaluatorTests(unittest.TestCase):

    def scan_code(self, code):
        """Write temporary Python code and scan it."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False
        ) as temp_file:
            temp_file.write(code)
            temp_path = Path(temp_file.name)

        try:
            return scan_file(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_textbook_rsa_detection(self):
        code = "ciphertext = pow(ord(char), e, N)"
        findings = self.scan_code(code)
        self.assertTrue(any(
            "RSA encryption" in item["name"] for item in findings
        ))

    def test_md5_detection(self):
        code = "digest = hashlib.md5(data)"
        findings = self.scan_code(code)
        self.assertTrue(any(
            "hash" in item["name"].lower() for item in findings
        ))

    def test_sha1_detection(self):
        code = "digest = hashlib.sha1(data)"
        findings = self.scan_code(code)
        self.assertTrue(any(
            "hash" in item["name"].lower() for item in findings
        ))

    def test_des_detection(self):
        code = "cipher = DES.new(key, DES.MODE_ECB)"
        findings = self.scan_code(code)
        self.assertTrue(any(
            "DES" in item["name"] for item in findings
        ))

    def test_aes_ecb_detection(self):
        code = "cipher = AES.new(key, AES.MODE_ECB)"
        findings = self.scan_code(code)
        self.assertTrue(any(
            "ECB" in item["name"] for item in findings
        ))

    def test_private_key_detection(self):
        code = 'key = "-----BEGIN PRIVATE KEY-----"'
        findings = self.scan_code(code)
        self.assertTrue(any(
            "Private key" in item["name"] for item in findings
        ))

    def test_hardcoded_secret_detection(self):
        code = 'password = "ExamplePassword123!"'
        findings = self.scan_code(code)
        self.assertTrue(any(
            "secret" in item["name"].lower() for item in findings
        ))

    def test_rsa_oaep_example_not_flagged_as_textbook_rsa(self):
        code = """
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
"""
        findings = self.scan_code(code)
        self.assertFalse(any(
            "RSA encryption" in item["name"] for item in findings
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
