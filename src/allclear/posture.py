"""Account-wide GitHub configuration checks.

Per-repository scanners miss the finding that matters most at account scale:
the control that is off *everywhere*. The audit this package came from found
Dependabot vulnerability alerts disabled on 48 of 48 repositories — a free
feature, one API call each, and nobody had noticed because no per-repo tool
says "and also, none of your other repositories have this either".

Three ideas shape this module:

1. **Plan-aware.** A control that your plan cannot provide is reported as
   `blocked_by_plan`, not as a finding. Telling someone to enable branch
   protection on a private repository on the Free plan is telling them to do
   something impossible, and it trains them to ignore the tool.

2. **Honest coverage.** Where the token's scopes cannot see something, the
   check reports `unknown` and names the missing scope. Silence is not a pass.

3. **Reversible-first ordering.** Findings carry the exact command to fix them,
   and the generated fixes are additive — enabling alerts, adding a ruleset that
   blocks force-pushes while still allowing a direct push, because a solo
   maintainer required to open a pull request against themselves will simply
   turn the rule off.
"""

from __future__ import annotations

from .gh import GhError, api, status_code
from .verdict import Finding


def _finding(repo: str, check: str, title: str, severity: str, remediation: str,
             verdict: str = "real", reason: str = "", **meta) -> Finding:
    return Finding(repo=repo, check=check, title=title, severity=severity,
                   verdict=verdict, reason=reason, remediation=remediation, meta=meta)


def check_repo(repo: dict) -> "list[Finding]":
    """Every configuration check for one repository."""
    name = repo["nameWithOwner"]
    private = bool(repo.get("isPrivate"))
    out: list[Finding] = []

    # --- Dependabot vulnerability alerts -----------------------------------
    code = status_code(f"repos/{name}/vulnerability-alerts")
    if code == 404:
        out.append(_finding(
            name, "dependabot-alerts", "Dependabot vulnerability alerts are off", "high",
            f"gh api -X PUT repos/{name}/vulnerability-alerts",
            reason="free on every plan; without it no advisory for this repo is visible anywhere",
        ))
    elif code != 204:
        out.append(_finding(
            name, "dependabot-alerts", "Could not read alert status", "info",
            "Check the token has the `repo` scope.", verdict="unknown",
            reason=f"endpoint answered HTTP {code}",
        ))

    # --- Dependabot security updates ---------------------------------------
    try:
        fix = api(f"repos/{name}/automated-security-fixes")
        if isinstance(fix, dict) and not fix.get("enabled"):
            out.append(_finding(
                name, "dependabot-security-updates",
                "Dependabot security updates are off", "medium",
                f"gh api -X PUT repos/{name}/automated-security-fixes",
                reason="this is what opens the pull request that actually fixes an advisory",
            ))
    except GhError as e:
        out.append(_finding(name, "dependabot-security-updates",
                            "Could not read security-update status", "info",
                            "Verify repository admin access.", verdict="unknown",
                            reason=e.body[:120]))

    # --- secret scanning + push protection ---------------------------------
    try:
        full = api(f"repos/{name}") or {}
        sa = full.get("security_and_analysis") or {}
        ss = (sa.get("secret_scanning") or {}).get("status")
        pp = (sa.get("secret_scanning_push_protection") or {}).get("status")
        if ss == "disabled":
            out.append(_finding(
                name, "secret-scanning", "Secret scanning is off", "high",
                f"gh api -X PATCH repos/{name} "
                f"-f 'security_and_analysis[secret_scanning][status]=enabled'",
                reason="free for public repositories and enabled by default; off here means off deliberately or by accident",
            ))
        if pp == "disabled":
            out.append(_finding(
                name, "push-protection", "Push protection is off", "high",
                f"gh api -X PATCH repos/{name} "
                f"-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'",
                reason="push protection stops the secret reaching the remote at all, which is the only cheap moment to stop it",
            ))
        if ss is None and private:
            out.append(_finding(
                name, "secret-scanning", "Secret scanning unavailable on this plan", "info",
                "Either run the bundled gitleaks workflow, or make the repository public, "
                "or upgrade. The workflow is free and covers this.",
                verdict="unreachable",
                reason="GitHub gates secret scanning for private repositories behind Advanced Security",
                blocked_by_plan=True,
            ))
    except GhError as e:
        out.append(_finding(name, "secret-scanning", "Could not read security settings",
                            "info", "Verify admin access.", verdict="unknown", reason=e.body[:120]))

    # --- default-branch protection ------------------------------------------
    try:
        rs = api(f"repos/{name}/rulesets")
        active = [r for r in (rs or []) if r.get("enforcement") == "active"]
        if not active:
            out.append(_finding(
                name, "branch-protection",
                "Default branch is not protected against force-push or deletion", "medium",
                "allclear apply --branch-protection  # adds deletion + non_fast_forward, "
                "direct push still allowed",
                reason="nothing prevents an accidental force-push or branch deletion",
            ))
    except GhError as e:
        if e.plan_gated:
            out.append(_finding(
                name, "branch-protection", "Branch protection unavailable on this plan", "info",
                "No free server-side equivalent exists. The options are: make the repository "
                "public, upgrade, or accept the risk knowingly.",
                verdict="unreachable",
                reason="GitHub gates rulesets and classic branch protection for private "
                       "repositories behind Pro",
                blocked_by_plan=True,
            ))
        else:
            out.append(_finding(name, "branch-protection", "Could not read rulesets", "info",
                                "Verify admin access.", verdict="unknown", reason=e.body[:120]))

    # --- Actions token permissions -----------------------------------------
    try:
        wf = api(f"repos/{name}/actions/permissions/workflow")
        if isinstance(wf, dict):
            if wf.get("default_workflow_permissions") == "write":
                out.append(_finding(
                    name, "actions-token", "GITHUB_TOKEN defaults to write", "high",
                    f"gh api -X PUT repos/{name}/actions/permissions/workflow "
                    f"-f default_workflow_permissions=read",
                    reason="every workflow in the repository gets write access it probably "
                           "does not need, including on untrusted contributions",
                ))
            if wf.get("can_approve_pull_request_reviews"):
                out.append(_finding(
                    name, "actions-token", "Actions can approve pull requests", "medium",
                    f"gh api -X PUT repos/{name}/actions/permissions/workflow "
                    f"-F can_approve_pull_request_reviews=false",
                    reason="a workflow able to approve a pull request can satisfy its own review gate",
                ))
    except GhError:
        pass

    # --- deployment environments -------------------------------------------
    try:
        envs = api(f"repos/{name}/environments") or {}
        for env in (envs.get("environments") or []):
            ename = env.get("name", "")
            if "prod" not in ename.lower():
                continue
            rules = env.get("protection_rules") or []
            policy = env.get("deployment_branch_policy")
            if not rules and not policy:
                out.append(_finding(
                    name, "environment", f"Production environment '{ename}' is unprotected",
                    "high",
                    "allclear apply --environments  # restricts deployments to the default branch",
                    reason="any branch can deploy to production and no approval is required",
                    environment=ename,
                ))
    except GhError:
        pass

    return out


def check_account(repos: "list[dict]", scopes: "list[str]" | None = None) -> dict:
    """Run every check across every repository and summarise."""
    findings: list[Finding] = []
    for r in repos:
        findings.extend(check_repo(r))

    by_check: dict[str, int] = {}
    for f in findings:
        if f.actionable:
            by_check[f.check] = by_check.get(f.check, 0) + 1

    total = len(repos)
    systemic = {c: n for c, n in by_check.items() if total and n >= max(2, int(total * 0.8))}

    gaps = []
    for needed, why in (("security_events", "code scanning alerts cannot be read"),
                        ("admin:public_key", "SSH keys cannot be reviewed")):
        if scopes is not None and needed not in scopes:
            gaps.append(f"missing `{needed}` scope — {why}")

    return {
        "repos": total,
        "findings": findings,
        "actionable": [f for f in findings if f.actionable],
        "blocked_by_plan": [f for f in findings if f.meta.get("blocked_by_plan")],
        "by_check": by_check,
        "systemic": systemic,
        "coverage_gaps": gaps,
    }
