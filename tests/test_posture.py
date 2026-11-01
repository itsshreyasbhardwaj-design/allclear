"""Posture checks, exercised against a stubbed GitHub.

These are stubbed rather than live on purpose: the point is to prove the check
fires when a control is off, and the only way to prove that against a real
account would be to turn a real control off.
"""

import unittest
from unittest import mock

from allclear import posture
from allclear.gh import GhError

REPO = {"nameWithOwner": "o/r", "name": "r", "isPrivate": False,
        "defaultBranchRef": {"name": "main"}}
PRIVATE = dict(REPO, isPrivate=True)


def run(repo=REPO, *, alerts=204, autofix=True, secret_scanning="enabled",
        push_protection="enabled", rulesets=None, wf=None, envs=None,
        rulesets_error=None):
    rulesets = rulesets if rulesets is not None else [{"enforcement": "active"}]
    wf = wf or {"default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False}
    envs = envs or {"environments": []}

    def fake_api(path, *a, **k):
        if path.endswith("/automated-security-fixes"):
            return {"enabled": autofix}
        if path.endswith("/rulesets"):
            if rulesets_error:
                raise rulesets_error
            return rulesets
        if path.endswith("/actions/permissions/workflow"):
            return wf
        if path.endswith("/environments"):
            return envs
        if path.startswith("repos/") and path.count("/") == 2:
            sa = {}
            if secret_scanning is not None:
                sa["secret_scanning"] = {"status": secret_scanning}
            if push_protection is not None:
                sa["secret_scanning_push_protection"] = {"status": push_protection}
            return {"security_and_analysis": sa}
        return {}

    with mock.patch.object(posture, "api", side_effect=fake_api), \
         mock.patch.object(posture, "status_code", return_value=alerts):
        return posture.check_repo(repo)


def checks(findings):
    return {f.check for f in findings if f.actionable}


class ControlsThatAreOff(unittest.TestCase):
    def test_disabled_alerts_are_reported_as_high(self):
        fs = run(alerts=404)
        hit = [f for f in fs if f.check == "dependabot-alerts"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].severity, "high")
        self.assertTrue(hit[0].actionable)
        self.assertIn("vulnerability-alerts", hit[0].remediation)

    def test_disabled_security_updates(self):
        self.assertIn("dependabot-security-updates", checks(run(autofix=False)))

    def test_disabled_secret_scanning_and_push_protection(self):
        got = checks(run(secret_scanning="disabled", push_protection="disabled"))
        self.assertIn("secret-scanning", got)
        self.assertIn("push-protection", got)

    def test_unprotected_default_branch(self):
        self.assertIn("branch-protection", checks(run(rulesets=[])))

    def test_write_default_token(self):
        fs = run(wf={"default_workflow_permissions": "write",
                     "can_approve_pull_request_reviews": True})
        self.assertIn("actions-token", checks(fs))
        self.assertEqual(len([f for f in fs if f.check == "actions-token"]), 2)

    def test_unprotected_production_environment(self):
        fs = run(envs={"environments": [
            {"name": "Production", "protection_rules": [], "deployment_branch_policy": None},
            {"name": "Preview", "protection_rules": [], "deployment_branch_policy": None},
        ]})
        hits = [f for f in fs if f.check == "environment"]
        self.assertEqual(len(hits), 1, "only Production is gated; Preview is left alone")
        self.assertEqual(hits[0].meta["environment"], "Production")


class NothingToSayWhenAllIsWell(unittest.TestCase):
    def test_a_hardened_repo_produces_no_actionable_findings(self):
        self.assertEqual(checks(run()), set())


class PlanLimitsAreNotFindings(unittest.TestCase):
    def test_plan_gated_branch_protection_is_not_actionable(self):
        """Telling someone to fix something their plan forbids trains them to
        ignore the tool."""
        err = GhError("403", status=403,
                      body="Upgrade to GitHub Pro or make this repository public")
        fs = run(PRIVATE, rulesets_error=err)
        hit = [f for f in fs if f.check == "branch-protection"]
        self.assertEqual(len(hit), 1)
        self.assertFalse(hit[0].actionable)
        self.assertEqual(hit[0].verdict, "unreachable")
        self.assertTrue(hit[0].meta.get("blocked_by_plan"))

    def test_a_real_error_is_still_surfaced_as_unknown(self):
        err = GhError("500", status=500, body="server error")
        fs = run(rulesets_error=err)
        hit = [f for f in fs if f.check == "branch-protection"]
        self.assertEqual(hit[0].verdict, "unknown")
        self.assertTrue(hit[0].actionable)

    def test_private_repo_without_secret_scanning_is_plan_gated(self):
        fs = run(PRIVATE, secret_scanning=None, push_protection=None)
        hit = [f for f in fs if f.check == "secret-scanning"]
        self.assertEqual(len(hit), 1)
        self.assertFalse(hit[0].actionable)
        self.assertTrue(hit[0].meta.get("blocked_by_plan"))


class SystemicDetection(unittest.TestCase):
    def test_a_control_off_everywhere_is_called_systemic(self):
        """The finding a per-repo tool cannot make.

        Stubbing the API rather than `check_repo` here: patching `check_repo`
        with a helper that itself calls `check_repo` recurses forever, which is
        how this test failed the first time it ran.
        """
        repos = [dict(REPO, nameWithOwner=f"o/r{i}") for i in range(5)]

        def fake_api(path, *a, **k):
            if path.endswith("/automated-security-fixes"):
                return {"enabled": True}
            if path.endswith("/rulesets"):
                return [{"enforcement": "active"}]
            if path.endswith("/actions/permissions/workflow"):
                return {"default_workflow_permissions": "read",
                        "can_approve_pull_request_reviews": False}
            if path.endswith("/environments"):
                return {"environments": []}
            return {"security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"}}}

        with mock.patch.object(posture, "api", side_effect=fake_api), \
             mock.patch.object(posture, "status_code", return_value=404):
            result = posture.check_account(repos, scopes=["repo"])

        self.assertEqual(result["systemic"].get("dependabot-alerts"), 5)
        self.assertEqual(len(result["actionable"]), 5)

    def test_one_repo_out_of_many_is_not_systemic(self):
        repos = [dict(REPO, nameWithOwner=f"o/r{i}") for i in range(5)]
        calls = {"n": 0}

        def fake_status(path):
            calls["n"] += 1
            return 404 if calls["n"] == 1 else 204

        def fake_api(path, *a, **k):
            if path.endswith("/automated-security-fixes"):
                return {"enabled": True}
            if path.endswith("/rulesets"):
                return [{"enforcement": "active"}]
            if path.endswith("/actions/permissions/workflow"):
                return {"default_workflow_permissions": "read",
                        "can_approve_pull_request_reviews": False}
            if path.endswith("/environments"):
                return {"environments": []}
            return {"security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"}}}

        with mock.patch.object(posture, "api", side_effect=fake_api), \
             mock.patch.object(posture, "status_code", side_effect=fake_status):
            result = posture.check_account(repos, scopes=["repo"])

        self.assertEqual(len(result["actionable"]), 1)
        self.assertNotIn("dependabot-alerts", result["systemic"])


if __name__ == "__main__":
    unittest.main()
