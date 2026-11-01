import tempfile
import unittest
from pathlib import Path

from allclear import reachability as R


def write(root: Path, rel: str, text: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class StaticExportSite(unittest.TestCase):
    """The case that motivated this module.

    A marketing site built with `output: 'export'` has no server, so a CRITICAL
    unauthenticated RCE in the image optimiser cannot execute: the optimiser is
    never built or served.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        write(root, "package.json", '{"dependencies":{"next":"14.2.5"}}')
        write(root, "next.config.mjs",
              "export default {output:'export',images:{loader:'custom'}}")
        self.dep = R.detect(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detected_as_static(self):
        self.assertEqual(self.dep.framework, "nextjs")
        self.assertTrue(self.dep.static_export)
        self.assertFalse(self.dep.runs_a_server)
        self.assertFalse(self.dep.image_optimizer)

    def test_image_optimizer_rce_is_unreachable(self):
        a = R.assess("GHSA-2464-fhr4-w9xw", self.dep)
        self.assertEqual(a.verdict, "unreachable")
        self.assertEqual(R.downgrade("critical", a), "low")

    def test_middleware_bypass_is_unreachable(self):
        self.assertEqual(R.assess("GHSA-f82v-jwr5-mffw", self.dep).verdict, "unreachable")

    def test_advisory_id_is_case_insensitive(self):
        """A `.upper()` on a mixed-case GHSA id matched nothing and made every
        advisory look unknown — caution-shaped, but a dead code path."""
        lower = R.assess("ghsa-2464-fhr4-w9xw", self.dep)
        upper = R.assess("GHSA-2464-FHR4-W9XW", self.dep)
        self.assertEqual(lower.verdict, "unreachable")
        self.assertEqual(upper.verdict, "unreachable")

    def test_evidence_is_recorded(self):
        self.assertTrue(any("output: 'export'" in e for e in self.dep.evidence))


class ServerBackedApp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        write(root, "package.json", '{"dependencies":{"next":"14.2.35"}}')
        write(root, "next.config.mjs", "export default {}")
        write(root, "src/middleware.ts", "export function middleware() {}")
        write(root, "src/actions.ts", "'use server'\nexport async function a() {}")
        self.dep = R.detect(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_server_features_detected(self):
        self.assertTrue(self.dep.runs_a_server)
        self.assertTrue(self.dep.has_middleware)
        self.assertTrue(self.dep.has_server_actions)

    def test_the_same_advisories_are_live_here(self):
        for adv in ("GHSA-2464-fhr4-w9xw", "GHSA-f82v-jwr5-mffw", "GHSA-p3m5-59mp-jv5r"):
            a = R.assess(adv, self.dep)
            self.assertEqual(a.verdict, "real", adv)
            self.assertEqual(R.downgrade("critical", a), "critical", adv)


class Honesty(unittest.TestCase):
    def test_unknown_advisory_is_treated_as_reachable(self):
        dep = R.Deployment(framework="nextjs", static_export=True)
        a = R.assess("GHSA-zzzz-zzzz-zzzz", dep)
        self.assertEqual(a.verdict, "unknown")
        self.assertEqual(R.downgrade("critical", a), "critical")

    def test_unrecognised_framework_is_unknown_not_safe(self):
        dep = R.Deployment(framework="unknown")
        a = R.assess("GHSA-2464-fhr4-w9xw", dep)
        self.assertEqual(a.verdict, "unknown")
        self.assertEqual(R.downgrade("critical", a), "critical")

    def test_static_export_claim_is_distrusted_when_contradicted(self):
        """`output: 'export'` plus middleware cannot both be true — such a build
        fails — so the safe reading is that a server is present."""
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        write(root, "package.json", '{"dependencies":{"next":"15.0.0"}}')
        write(root, "next.config.mjs", "export default {output:'export'}")
        write(root, "src/middleware.ts", "export function middleware() {}")
        dep = R.detect(root)
        self.assertFalse(dep.static_export)
        self.assertEqual(R.assess("GHSA-f82v-jwr5-mffw", dep).verdict, "real")
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()


class CommentsAreNotConfiguration(unittest.TestCase):
    """Regression test for a false negative on a CRITICAL advisory.

    A real dashboard's next.config.mjs explained in a comment that *the public
    site* is `output: 'export'`. The regex matched inside that comment, the
    dashboard was classified static, and an image-optimiser remote code
    execution advisory was reported unreachable on an app that runs a server.
    """

    def _dashboard(self, root: Path):
        write(root, "package.json", '{"dependencies":{"next":"14.2.35"}}')
        write(root, "next.config.mjs", """
/**
 * This is a PRIVATE dashboard. Unlike the public site (which is
 * `output: 'export'`, a static export), this app needs a server runtime.
 */
// output: 'export' would be wrong here
export default { images: { remotePatterns: [] } }
""")
        write(root, "src/middleware.ts", "export function middleware() {}")

    def test_commented_output_export_does_not_make_it_static(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._dashboard(root)
            dep = R.detect(root)
            self.assertFalse(dep.static_export)
            self.assertTrue(dep.runs_a_server)

    def test_image_optimizer_rce_stays_critical_on_a_server_app(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._dashboard(root)
            dep = R.detect(root)
            a = R.assess("GHSA-2464-fhr4-w9xw", dep)
            self.assertEqual(a.verdict, "real")
            self.assertEqual(R.downgrade("critical", a), "critical")

    def test_a_genuine_custom_loader_is_still_honoured(self):
        """The fix must not break the true case it was protecting."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root, "package.json", '{"dependencies":{"next":"14.2.5"}}')
            write(root, "next.config.mjs",
                  "// a real static export\nexport default {output:'export',"
                  "images:{loader:'custom'}}")
            dep = R.detect(root)
            self.assertTrue(dep.static_export)
            self.assertFalse(dep.image_optimizer)
            self.assertEqual(R.assess("GHSA-2464-fhr4-w9xw", dep).verdict, "unreachable")
