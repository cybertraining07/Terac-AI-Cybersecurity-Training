import unittest
import tempfile
from pathlib import Path

from crypto_evaluator import scan_file


class FalsePositiveTests(unittest.TestCase):

    def scan_code(self, code):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False
        ) as temp:
            temp.write(code)
            path = Path(temp.name)

        try:
            return scan_file(path)
        finally:
            path.unlink(missing_ok=True)

    def test_md5_in_comment(self):
        code = "# MD5 is insecure and should not be used"
        findings = self.scan_code(code)
        self.assertEqual(len(findings), 0)

    def test_des_in_comment(self):
        code = "# DES is an outdated encryption algorithm"
        findings = self.scan_code(code)
        self.assertEqual(len(findings), 0)

    def test_password_in_comment(self):
        code = "# password = 'example12345'"
        findings = self.scan_code(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
