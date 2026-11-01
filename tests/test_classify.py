import unittest

from allclear.classify import classify, classify_path, classify_value, from_gitleaks, _segments
from allclear.verdict import Finding


class PathSegmentMatching(unittest.TestCase):
    """Regression tests for the two bugs this function actually had."""

    def test_root_level_docs_is_recognised(self):
        # The first implementation used the substring "/docs/", which has a
        # leading slash and therefore never matched a repository-root path.
        # That let a documentation example through unclassified and broke CI.
        self.assertEqual(classify_path("docs/api.md")[0], "example")

    def test_nested_docs_is_recognised(self):
        self.assertEqual(classify_path("packages/web/docs/api.md")[0], "example")

    def test_dotfile_keeps_its_leading_dot(self):
        # `lstrip("./")` strips a SET of characters, so it turned
        # ".env.example" into "env.example". Dotfiles are the whole point.
        self.assertEqual(_segments(".env.example"), [".env.example"])
        self.assertEqual(_segments("./.env.example"), [".env.example"])
        self.assertEqual(classify_path(".env.example")[0], "placeholder")

    def test_a_real_env_file_is_not_excused(self):
        self.assertIsNone(classify_path(".env"))
        self.assertIsNone(classify_path("config/.env.local"))

    def test_directory_named_like_a_marker_but_not_a_segment(self):
        # "fixtures" inside a filename must not count as the fixtures/ directory
        self.assertIsNone(classify_path("src/fixtures-loader.ts"))


class PathVerdicts(unittest.TestCase):
    def test_test_files(self):
        for p in ("src/lib/redact.test.ts", "a/b/thing.spec.js",
                  "tests/unit/x.ts", "pkg/__tests__/y.ts", "api/test_auth.py"):
            self.assertEqual(classify_path(p)[0], "fixture", p)

    def test_fixture_trees(self):
        self.assertEqual(classify_path("fixtures/vulnerable-shop/.env")[0], "fixture")

    def test_vendored_and_build_output(self):
        self.assertEqual(classify_path("node_modules/x/index.js")[0], "vendored")
        self.assertEqual(classify_path("vendor/upstream/key.py")[0], "vendored")
        self.assertEqual(classify_path("apps/web/.next/static/chunk.js")[0], "vendored")

    def test_source_file_is_not_excused(self):
        self.assertIsNone(classify_path("src/app/api/billing/route.ts"))


class ValueVerdicts(unittest.TestCase):
    def test_aws_documented_example(self):
        self.assertEqual(classify_value("AKIAIOSFODNN7EXAMPLE")[0], "example")

    def test_placeholder_words(self):
        for v in ("your-api-key-here", "changeme", "sk_live_PLACEHOLDER", "dummy-token"):
            self.assertEqual(classify_value(v)[0], "placeholder", v)

    def test_base64_of_filler(self):
        import base64
        v = base64.b64encode(b"test-encryption-key").decode()
        self.assertEqual(classify_value(v)[0], "placeholder")

    def test_high_entropy_unknown_value_is_not_excused(self):
        self.assertIsNone(classify_value("Zk3Qp7Wt2Lm9Rv4Xb8Nc5Yd1Hj6Fg0Ts"))


class ServiceRoleNeverExcused(unittest.TestCase):
    def test_service_role_in_a_test_file_is_still_real(self):
        """The strongest rule: a service-role key is real wherever it lives.

        Supabase anon keys are designed to ship to a browser; service-role keys
        bypass row-level security entirely. Excusing one because it sat in a
        test file would be the worst mistake this classifier could make.
        """
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="src/lib/db.test.ts", evidence="eyJhbGciOi")
        classify(f, context="SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi")
        self.assertEqual(f.verdict, "real")
        self.assertTrue(f.actionable)

    def test_anon_key_is_public_by_design(self):
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="src/lib/db.ts", evidence="eyJhbGciOi")
        classify(f, context="NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOi")
        self.assertEqual(f.verdict, "example")
        self.assertFalse(f.actionable)


class UnknownIsActionable(unittest.TestCase):
    def test_unclassified_finding_needs_a_human(self):
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="src/config.ts", evidence="Zk3Qp7Wt2Lm9Rv4Xb8Nc5Yd1Hj6Fg0")
        classify(f)
        self.assertEqual(f.verdict, "unknown")
        self.assertTrue(f.actionable, "an unexplained secret must never be silently dropped")


class GitleaksAdapter(unittest.TestCase):
    def test_benign_finding_is_downgraded_and_explained(self):
        rec = {"RuleID": "aws-access-token", "File": "src/lib/redact.test.ts",
               "StartLine": 6, "Secret": "AKIAIOSFODNN7EXAMPLE",
               "Fingerprint": "src/lib/redact.test.ts:aws-access-token:6",
               "Match": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}
        f = from_gitleaks(rec, "repo")
        self.assertFalse(f.actionable)
        self.assertEqual(f.severity, "info")
        self.assertTrue(f.reason)

    def test_unexplained_finding_stays_critical(self):
        rec = {"RuleID": "generic-api-key", "File": "src/server/config.ts",
               "StartLine": 3, "Secret": "Zq8Xv2Lp9Wm4Rt6Yb1Nc7Kd5Hj3Fg0Ss",
               "Fingerprint": "src/server/config.ts:generic-api-key:3",
               "Match": "API_KEY=Zq8Xv2Lp9Wm4Rt6Yb1Nc7Kd5Hj3Fg0Ss"}
        f = from_gitleaks(rec, "repo")
        self.assertTrue(f.actionable)
        self.assertEqual(f.severity, "critical")


if __name__ == "__main__":
    unittest.main()


class PrecedenceFoundByDogfooding(unittest.TestCase):
    """Running this tool on its own source found the ordering bug below.

    `sk_live_...` triggers the "never public" name rule. When that rule ran
    before the value rules, an obvious placeholder inside this very test suite
    was reported as a critical exposure.
    """

    def test_an_obvious_placeholder_secret_key_is_not_a_finding(self):
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="tests/test_classify.py", evidence="sk_live_PLACEHOLDER")
        classify(f, context="secret_key sk_live_PLACEHOLDER")
        self.assertEqual(f.verdict, "placeholder")
        self.assertFalse(f.actionable)

    def test_a_credible_secret_key_is_still_a_finding_in_a_test_file(self):
        # Assembled at runtime rather than written as a literal. A test that
        # needs a credential-shaped string should not commit one: the literal
        # would be indistinguishable from a real key to any scanner, including
        # this one, and allowlisting it would mean allowlisting an actionable
        # finding — which `allowlist.verify` refuses, correctly. Splitting it
        # keeps the test's meaning and leaves nothing for a scanner to match.
        credible = "sk_" + "live_" + "51QrZt9KmWp2Xv"
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="tests/test_billing.py", evidence=credible)
        classify(f, context="STRIPE_SECRET_KEY=" + credible)
        self.assertEqual(f.verdict, "real")
        self.assertTrue(f.actionable)

    def test_service_role_with_a_credible_value_still_wins_over_the_path(self):
        f = Finding(repo="r", check="secret-scan", title="t",
                    path="src/db.test.ts", evidence="eyJhbGciOiJIUzI1NiIsInR5cCI6")
        classify(f, context="SUPABASE_SERVICE_ROLE_KEY")
        self.assertEqual(f.verdict, "real")
