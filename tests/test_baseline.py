import tempfile
import unittest
from pathlib import Path

from allclear import baseline


class DependabotConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "package-lock.json").write_text("{}")
        (self.root / "requirements.txt").write_text("fastapi>=0.110")
        (self.root / ".github" / "workflows").mkdir(parents=True)
        fx = self.root / "fixtures"
        fx.mkdir()
        (fx / "requirements.txt").write_text("flask==2.0.1")

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_ecosystem_declares_the_limit(self):
        """Omitting the key does not mean zero — it means the default of five.

        A config that sets it on npm and forgets github-actions keeps raising
        version updates while looking security-only. That shipped once.
        """
        text = baseline.dependabot(self.root, security_only=True)
        blocks = text.count("- package-ecosystem:")
        limits = text.count("open-pull-requests-limit: 0")
        self.assertGreaterEqual(blocks, 3)
        # one per block, plus one mention in the header prose
        self.assertGreaterEqual(limits, blocks)

    def test_fixture_requirements_are_not_watched(self):
        text = baseline.dependabot(self.root)
        self.assertNotIn("fixtures", text)

    def test_version_updates_can_be_opted_into(self):
        text = baseline.dependabot(self.root, security_only=False)
        self.assertIn("open-pull-requests-limit: 5", text)

    def test_no_manifests_means_no_config(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(baseline.dependabot(Path(t)))


class SecurityWorkflow(unittest.TestCase):
    def test_no_third_party_actions(self):
        wf = baseline.security_workflow()
        uses = [l.strip() for l in wf.splitlines() if "uses:" in l]
        self.assertTrue(uses)
        for u in uses:
            self.assertIn("actions/checkout@", u,
                          "only actions/checkout is used; gitleaks runs as a verified binary")

    def test_checkout_is_pinned_to_a_sha(self):
        wf = baseline.security_workflow()
        self.assertIn(f"actions/checkout@{baseline.CHECKOUT_SHA}", wf)
        self.assertEqual(len(baseline.CHECKOUT_SHA), 40)

    def test_gitleaks_download_is_checksum_verified(self):
        wf = baseline.security_workflow()
        self.assertIn("sha256sum -c -", wf)
        self.assertIn(baseline.GITLEAKS_SHA256_LINUX_X64, wf)

    def test_permissions_are_read_only_at_the_top(self):
        wf = baseline.security_workflow()
        self.assertIn("permissions:\n  contents: read", wf)

    def test_github_expressions_survive_templating(self):
        wf = baseline.security_workflow()
        self.assertNotIn("${{{", wf)
        self.assertIn("${{ github.event_name ==", wf)


class WriteAll(unittest.TestCase):
    def test_existing_files_are_kept_not_clobbered(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "SECURITY.md").write_text("mine")
            actions = baseline.write_all(root)
            self.assertIn("kept", actions["SECURITY.md"])
            self.assertEqual((root / "SECURITY.md").read_text(), "mine")

    def test_existing_security_workflow_is_respected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "codeql.yml").write_text("name: CodeQL")
            actions = baseline.write_all(root)
            self.assertIn("skipped", actions[".github/workflows/security.yml"])


if __name__ == "__main__":
    unittest.main()
