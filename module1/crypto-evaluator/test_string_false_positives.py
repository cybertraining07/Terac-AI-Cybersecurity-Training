import unittest
import tempfile
from pathlib import Path

from crypto_evaluator import scan_file


class StringFalsePositiveTests(unittest.TestCase):

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

    def test_md5_in_normal_string(self):
        findings = self.scan_code(
            'message = "MD5 is outdated"'
        )
        self.assertEqual(len(findings), 0)

    def test_password_in_normal_string(self):
        findings = self.scan_code(
            'message = "password = example12345"'
        )
        self.assertEqual(len(findings), 0)

    def test_md5_in_docstring(self):
        findings = self.scan_code(
            '"""MD5 should not be used for secure hashing."""'
        )
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
