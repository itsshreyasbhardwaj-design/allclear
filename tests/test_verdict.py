import unittest

from allclear.verdict import Finding, masked, worst


class SeverityOrdering(unittest.TestCase):
    def test_worst_picks_the_most_severe(self):
        self.assertEqual(worst(["low", "critical", "high"]), "critical")
        self.assertEqual(worst(["medium", "low"]), "medium")

    def test_unknown_severities_do_not_win(self):
        self.assertEqual(worst(["banana", "low"]), "low")
        self.assertEqual(worst(["banana"]), "info")


class Masking(unittest.TestCase):
    def test_a_secret_is_never_reproduced(self):
        secret = "AKIA1234567890ABCDEF"
        out = masked(secret)
        self.assertNotIn(secret, out)
        self.assertNotIn(secret[4:], out)

    def test_prefix_and_length_are_kept(self):
        out = masked("sk_live_abcdefghijklmnop")
        self.assertTrue(out.startswith("sk_l"))
        self.assertIn("24", out)

    def test_empty(self):
        self.assertEqual(masked(None), "-")
        self.assertEqual(masked(""), "-")


class Actionability(unittest.TestCase):
    def test_real_and_unknown_are_actionable(self):
        for v in ("real", "unknown"):
            self.assertTrue(Finding(repo="r", check="c", title="t", verdict=v).actionable, v)

    def test_explained_verdicts_are_not(self):
        for v in ("fixture", "example", "vendored", "placeholder", "unreachable"):
            self.assertFalse(Finding(repo="r", check="c", title="t", verdict=v).actionable, v)

    def test_default_verdict_is_actionable(self):
        """A freshly-made Finding must not default to 'fine'."""
        self.assertTrue(Finding(repo="r", check="c", title="t").actionable)


if __name__ == "__main__":
    unittest.main()
