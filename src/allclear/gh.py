"""A thin wrapper over the `gh` CLI.

`gh` is used rather than raw HTTPS for one reason: it already holds the user's
credentials. This package never asks for a token, never reads one from the
environment and never writes one anywhere. If `gh` is not authenticated, the
tool says so and stops.

Every call is read-only unless the caller is `apply`.
"""

from __future__ import annotations

import json
import shutil
import subprocess

#: GitHub's wording when a feature exists but the plan does not include it.
PLAN_GATE_MARKERS = (
    "upgrade to github pro",
    "advanced security",
    "billing plan",
    "not available for this repository",
)


class GhError(RuntimeError):
    """A `gh` invocation failed in a way the caller should see."""

    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body

    @property
    def plan_gated(self) -> bool:
        """True when the failure is 'your plan does not include this'.

        Worth a type of its own. During the audit this package came out of,
        branch protection was simply unavailable on ten private repositories —
        not misconfigured, not missed, impossible. Reporting that as a finding
        would be telling someone to fix something they cannot fix.
        """
        low = self.body.lower()
        return self.status == 403 and any(m in low for m in PLAN_GATE_MARKERS)


def available() -> bool:
    return shutil.which("gh") is not None


def authenticated() -> tuple[bool, str]:
    if not available():
        return False, "the `gh` CLI is not installed (see https://cli.github.com)"
    p = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if p.returncode != 0:
        return False, "`gh` is installed but not logged in — run `gh auth login`"
    return True, (p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else "ok"


def token_scopes() -> list[str]:
    """The scopes the current token carries, for honest coverage reporting."""
    p = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    text = p.stdout + p.stderr
    for line in text.splitlines():
        if "Token scopes" in line:
            return [s.strip().strip("'\"") for s in line.split(":", 1)[1].split(",") if s.strip()]
    return []


def api(path: str, method: str = "GET", fields: dict | None = None,
        body: dict | None = None, paginate: bool = False):
    """Call the GitHub REST API through `gh`. Returns parsed JSON, or None."""
    cmd = ["gh", "api"]
    if method != "GET":
        cmd += ["-X", method]
    if paginate:
        cmd += ["--paginate", "--slurp"]
    cmd.append(path)
    for k, v in (fields or {}).items():
        cmd += ["-f", f"{k}={v}"]
    inp = None
    if body is not None:
        cmd += ["--input", "-"]
        inp = json.dumps(body)
    p = subprocess.run(cmd, capture_output=True, text=True, input=inp)
    if p.returncode != 0:
        status = None
        for tok in p.stderr.split():
            if tok.startswith("(HTTP") or tok.rstrip(")").isdigit():
                try:
                    status = int(tok.strip("(HTTP)").strip(")"))
                except ValueError:
                    pass
        if status is None:
            if "HTTP 403" in p.stderr:
                status = 403
            elif "HTTP 404" in p.stderr or "Not Found" in p.stderr:
                status = 404
        raise GhError(f"gh api {path} failed", status=status, body=p.stderr + p.stdout)
    out = p.stdout.strip()
    if not out:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return out
    if paginate and isinstance(data, list) and data and isinstance(data[0], list):
        return [item for page in data for item in page]
    return data


def status_code(path: str) -> int:
    """The HTTP status of a GET, for endpoints whose meaning *is* the status.

    `GET /repos/{owner}/{repo}/vulnerability-alerts` answers 204 for enabled
    and 404 for disabled, with no body either way.
    """
    p = subprocess.run(["gh", "api", path, "-i"], capture_output=True, text=True)
    first = (p.stdout or p.stderr).splitlines()[0] if (p.stdout or p.stderr) else ""
    for tok in first.split():
        if tok.isdigit() and len(tok) == 3:
            return int(tok)
    return 0


def repos(owner: str | None = None, include_archived: bool = True) -> list[dict]:
    """Every repository the authenticated user can administer."""
    args = ["gh", "repo", "list"]
    if owner:
        args.append(owner)
    args += ["--limit", "1000", "--json",
             "nameWithOwner,name,owner,visibility,isPrivate,isArchived,isFork,"
             "defaultBranchRef,pushedAt,primaryLanguage,diskUsage"]
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode != 0:
        raise GhError("could not list repositories", body=p.stderr)
    data = json.loads(p.stdout or "[]")
    if not include_archived:
        data = [r for r in data if not r.get("isArchived")]
    return data
