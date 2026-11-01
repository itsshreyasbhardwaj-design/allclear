"""allclear command line.

Read-only by default. The only subcommand that changes anything is `apply`,
and it refuses to run without `--yes`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, allowlist, baseline, gh, posture, reachability, report, scan
from .verdict import Finding

EPILOGUE = """\
examples:
  allclear audit                      every repository you administer
  allclear audit --repo owner/name    just one
  allclear secrets .                  scan this checkout and classify findings
  allclear secrets . --write-allowlist
  allclear reachable . --advisory GHSA-2464-fhr4-w9xw
  allclear baseline .                 write dependabot/security.yml/SECURITY.md
  allclear apply --alerts --yes       turn on Dependabot alerts account-wide
"""


def _require_gh() -> None:
    ok, msg = gh.authenticated()
    if not ok:
        sys.exit(f"allclear: {msg}")


def _select(args) -> list[dict]:
    repos = gh.repos(owner=args.owner, include_archived=not args.skip_archived)
    if args.repo:
        wanted = set(args.repo)
        repos = [r for r in repos
                 if r["nameWithOwner"] in wanted or r["name"] in wanted]
        missing = wanted - {r["nameWithOwner"] for r in repos} - {r["name"] for r in repos}
        if missing:
            sys.exit(f"allclear: no such repository: {', '.join(sorted(missing))}")
    return repos


def cmd_audit(args) -> int:
    _require_gh()
    repos = _select(args)
    print(f"allclear: examining {len(repos)} repositories…", file=sys.stderr)
    result = posture.check_account(repos, scopes=gh.token_scopes())
    findings = result["findings"]
    if args.json:
        print(json.dumps({**result,
                          "findings": [f.as_dict() for f in findings],
                          "actionable": [f.as_dict() for f in result["actionable"]],
                          "blocked_by_plan": [f.as_dict() for f in result["blocked_by_plan"]]},
                         indent=2))
    else:
        print(report.text(findings, len(repos), show_quiet=args.show_explained))
        if result["systemic"]:
            print("SYSTEMIC (the same control is off nearly everywhere)")
            print("-" * 52)
            for check, n in sorted(result["systemic"].items(), key=lambda kv: -kv[1]):
                print(f"  {check}: {n} of {len(repos)} repositories")
            print("\n  A control that is off everywhere is one nobody has looked at,")
            print("  not one that was considered and declined.\n")
        for gap in result["coverage_gaps"]:
            print(f"  coverage: {gap}")
    if args.markdown:
        Path(args.markdown).write_text(
            report.markdown(findings, len(repos),
                            coverage_gaps=result["coverage_gaps"],
                            blocked=result["blocked_by_plan"]), encoding="utf-8")
        print(f"\nwrote {args.markdown}", file=sys.stderr)
    return 1 if result["actionable"] else 0


def cmd_secrets(args) -> int:
    path = Path(args.path)
    if not path.is_dir():
        sys.exit(f"allclear: {path} is not a directory")
    try:
        findings = scan.run(path, gitleaks=args.gitleaks, history=args.history)
    except RuntimeError as e:
        sys.exit(f"allclear: {e}")
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(report.text(findings, 1, show_quiet=args.show_explained))
        # Without this line a repository that already has an allowlist reports
        # "0 findings, 0 explained", which reads as though nothing was scanned.
        # The audited exceptions are part of the result, so they are stated.
        existing = path / ".gitleaksignore"
        if existing.exists():
            n = sum(1 for line in existing.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#"))
            if n:
                print(f"  {n} finding(s) are already recorded in .gitleaksignore as audited "
                      f"exceptions, so the scanner did not re-report them.")
                print("  Review them with: grep -v '^#' .gitleaksignore\n")
    if args.write_allowlist:
        text = allowlist.build(findings)
        problems = allowlist.verify(text, findings)
        if problems:
            for p in problems:
                print(f"allclear: refusing to write allowlist — {p}", file=sys.stderr)
            return 2
        dest = path / ".gitleaksignore"
        dest.write_text(text, encoding="utf-8")
        kept = sum(1 for f in findings if not f.actionable)
        print(f"wrote {dest} with {kept} audited exception(s)", file=sys.stderr)
    return 1 if any(f.actionable for f in findings) else 0


def cmd_reachable(args) -> int:
    dep = reachability.detect(args.path)
    print(f"framework      : {dep.framework}")
    print(f"runs a server  : {dep.runs_a_server}")
    print(f"middleware     : {dep.has_middleware}")
    print(f"server actions : {dep.has_server_actions}")
    print(f"image optimiser: {dep.image_optimizer}")
    print("evidence:")
    for e in dep.evidence:
        print(f"  - {e}")
    if not args.advisory:
        return 0
    print("\nadvisories:")
    worst = 0
    for adv in args.advisory:
        a = reachability.assess(adv, dep)
        sev = reachability.downgrade("critical", a)
        print(f"  {adv:24} {a.verdict:12} severity→{sev:9} {a.reason}")
        if a.verdict != "unreachable":
            worst = 1
    return worst


def cmd_baseline(args) -> int:
    actions = baseline.write_all(args.path,
                                 security_only=not args.allow_version_updates,
                                 force=args.force)
    for rel, what in sorted(actions.items()):
        print(f"  {what:38} {rel}")
    print("\nDependabot is configured for security updates only."
          if not args.allow_version_updates else
          "\nDependabot will also raise version updates.")
    return 0


def cmd_apply(args) -> int:
    _require_gh()
    if not (args.alerts or args.security_updates or args.branch_protection or args.environments):
        sys.exit("allclear: pick at least one of --alerts --security-updates "
                 "--branch-protection --environments")
    repos = _select(args)
    if not args.yes:
        print("allclear: this would change settings on "
              f"{len(repos)} repositories. Re-run with --yes to proceed.")
        return 2
    changed = failed = blocked = 0
    for r in repos:
        name = r["nameWithOwner"]
        if args.alerts:
            try:
                gh.api(f"repos/{name}/vulnerability-alerts", method="PUT"); changed += 1
            except gh.GhError:
                failed += 1
        if args.security_updates:
            try:
                gh.api(f"repos/{name}/automated-security-fixes", method="PUT"); changed += 1
            except gh.GhError:
                failed += 1
        if args.branch_protection:
            body = {"name": "Protect default branch", "target": "branch",
                    "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
                    "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]}
            try:
                existing = gh.api(f"repos/{name}/rulesets") or []
                if not any(x.get("name") == body["name"] for x in existing):
                    gh.api(f"repos/{name}/rulesets", method="POST", body=body); changed += 1
            except gh.GhError as e:
                if e.plan_gated:
                    blocked += 1
                    print(f"  blocked by plan: {name} (branch protection needs Pro for "
                          f"private repositories)")
                else:
                    failed += 1
        if args.environments:
            try:
                envs = (gh.api(f"repos/{name}/environments") or {}).get("environments") or []
            except gh.GhError:
                envs = []
            for env in envs:
                ename = env.get("name", "")
                if "prod" not in ename.lower():
                    continue
                from urllib.parse import quote
                enc = quote(ename, safe="")
                try:
                    gh.api(f"repos/{name}/environments/{enc}", method="PUT",
                           body={"deployment_branch_policy": {
                               "protected_branches": False, "custom_branch_policies": True}})
                    gh.api(f"repos/{name}/environments/{enc}/deployment-branch-policies",
                           method="POST", body={"name": r.get("defaultBranchRef", {}).get("name", "main"),
                                                "type": "branch"})
                    changed += 1
                except gh.GhError:
                    failed += 1
    print(f"\nchanged {changed}, blocked by plan {blocked}, failed {failed}")
    return 0 if failed == 0 else 1


def cmd_selftest(args) -> int:
    """Check the pinned digests still describe the real upstream assets."""
    import hashlib
    import urllib.request
    bad = 0
    for key, digest in scan.GITLEAKS_DIGESTS.items():
        asset = f"gitleaks_{baseline.GITLEAKS_VERSION}_{key}.tar.gz"
        url = (f"https://github.com/gitleaks/gitleaks/releases/download/"
               f"v{baseline.GITLEAKS_VERSION}/{asset}")
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
                actual = hashlib.sha256(resp.read()).hexdigest()
        except Exception as e:
            print(f"  {key}: could not fetch ({e})")
            bad += 1
            continue
        ok = actual == digest
        print(f"  {key}: {'ok' if ok else 'MISMATCH'}")
        if not ok:
            print(f"      pinned {digest}\n      actual {actual}")
            bad += 1
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="allclear",
        description="Account-wide GitHub exposure audit that tells you which findings are real.",
        epilog=EPILOGUE, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"allclear {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def repo_args(sp):
        sp.add_argument("--owner", help="limit to one owner")
        sp.add_argument("--repo", action="append", help="repeatable; name or owner/name")
        sp.add_argument("--skip-archived", action="store_true")

    a = sub.add_parser("audit", help="check GitHub configuration across your repositories")
    repo_args(a)
    a.add_argument("--json", action="store_true")
    a.add_argument("--markdown", metavar="FILE", help="also write a markdown report")
    a.add_argument("--show-explained", action="store_true", help="list the non-actionable findings too")
    a.set_defaults(func=cmd_audit)

    s = sub.add_parser("secrets", help="scan a checkout for secrets and classify the findings")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--history", action="store_true", help="scan all commits on all branches")
    s.add_argument("--gitleaks", help="use this gitleaks binary instead of downloading one")
    s.add_argument("--write-allowlist", action="store_true", help="write .gitleaksignore")
    s.add_argument("--json", action="store_true")
    s.add_argument("--show-explained", action="store_true")
    s.set_defaults(func=cmd_secrets)

    r = sub.add_parser("reachable", help="is an advisory actually reachable as this is deployed?")
    r.add_argument("path", nargs="?", default=".")
    r.add_argument("--advisory", action="append", help="repeatable GHSA id")
    r.set_defaults(func=cmd_reachable)

    b = sub.add_parser("baseline", help="write the preventive files into a repository")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("--allow-version-updates", action="store_true",
                   help="also raise Dependabot version updates (off by default, on purpose)")
    b.add_argument("--force", action="store_true", help="overwrite files that already exist")
    b.set_defaults(func=cmd_baseline)

    ap = sub.add_parser("apply", help="turn on the controls that are off (the only writing command)")
    repo_args(ap)
    ap.add_argument("--alerts", action="store_true")
    ap.add_argument("--security-updates", action="store_true")
    ap.add_argument("--branch-protection", action="store_true")
    ap.add_argument("--environments", action="store_true")
    ap.add_argument("--yes", action="store_true", help="required; without it nothing is changed")
    ap.set_defaults(func=cmd_apply)

    st = sub.add_parser("selftest", help="verify the pinned tool digests against upstream")
    st.set_defaults(func=cmd_selftest)
    return p


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
