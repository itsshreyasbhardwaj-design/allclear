import unittest

from allclear import allowlist
from allclear.verdict import Finding


def benign(fp, path="a.test.ts"):
    return Finding(repo="r", check="secret-scan", title="t", verdict="fixture",
                   reason="a test file", path=path, fingerprint=fp, severity="info")


def actionable(fp, path="src/config.ts"):
    return Finding(repo="r", check="secret-scan", title="t", verdict="real",
                   reason="unexplained", path=path, fingerprint=fp, severity="critical")


class AllowlistContents(unittest.TestCase):
    def test_only_benign_findings_are_listed(self):
        text = allowlist.build([benign("a.test.ts:jwt:1"), actionable("src/config.ts:key:9")])
        self.assertIn("a.test.ts:jwt:1", text)
        self.assertNotIn("src/config.ts:key:9", text)

    def test_every_entry_carries_its_reason(self):
        text = allowlist.build([benign("a.test.ts:jwt:1")])
        self.assertIn("fixture: a test file", text)

    def test_entries_are_fingerprints_not_globs(self):
        text = allowlist.build([benign("a.test.ts:jwt:1")])
        body = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertTrue(body)
        for line in body:
            self.assertNotIn("*", line, "a glob would hide future findings in the same file")

    def test_empty_input_still_produces_a_valid_file(self):
        text = allowlist.build([])
        self.assertIn("Nothing to allowlist", text)


class AllowlistSafety(unittest.TestCase):
    """`verify` is the guard that makes the allowlist trustworthy."""

    def test_silencing_an_actionable_finding_is_rejected(self):
        f = actionable("src/config.ts:key:9")
        problems = allowlist.verify("src/config.ts:key:9\n", [f])
        self.assertEqual(len(problems), 1)
        self.assertIn("must never be silenced", problems[0])

    def test_globs_are_rejected(self):
        problems = allowlist.verify("**/*.test.ts\n", [])
        self.assertEqual(len(problems), 1)
        self.assertIn("glob", problems[0])

    def test_a_clean_allowlist_has_no_problems(self):
        f = benign("a.test.ts:jwt:1")
        self.assertEqual(allowlist.verify(allowlist.build([f]), [f]), [])

    def test_new_secret_in_an_allowlisted_file_is_not_covered(self):
        """The property the whole design exists for."""
        known = benign("a.test.ts:jwt:1")
        text = allowlist.build([known])
        # same file, different line -> different fingerprint -> not allowlisted
        fresh = actionable("a.test.ts:aws-access-token:42", path="a.test.ts")
        self.assertNotIn(fresh.fingerprint, text)
        self.assertEqual(allowlist.verify(text, [known, fresh]), [])


if __name__ == "__main__":
    unittest.main()
