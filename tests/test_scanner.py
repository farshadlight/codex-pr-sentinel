import unittest
from src.sentinel import DiffScanner

SAMPLE_DIFF = """diff --git a/app/auth.py b/app/auth.py
index 1234567..89abcdef 100644
--- a/app/auth.py
+++ b/app/auth.py
@@ -10,4 +10,6 @@ def authenticate(user):
-    return True
+    api_key = "sk-1234567890abcdef12345678"
+    eval(user.input_data)
+    return False
"""

class TestDiffScanner(unittest.TestCase):
    def test_detects_hardcoded_secret_and_eval(self):
        scanner = DiffScanner(SAMPLE_DIFF)
        findings = scanner.scan_static()
        self.assertEqual(len(findings), 2)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SEC-001", rule_ids)
        self.assertIn("SEC-002", rule_ids)

if __name__ == "__main__":
    unittest.main()
