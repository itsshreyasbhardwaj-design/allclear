"""The vocabulary every check speaks.

A finding is never just a severity. It carries where it came from, why this
tool believes what it believes, and — crucially — whether the thing is actually
reachable. Severity without reachability is how a static site with no server
ends up labelled CRITICAL for a remote code execution bug it cannot run.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Ordered worst-first so `min()` on this mapping is a severity comparison.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def worst(severities: "list[str]") -> str:
    """The most severe of the given severities, or 'info' if none are known."""
    known = [s for s in severities if s in SEVERITY_ORDER]
    if not known:
        return "info"
    return min(known, key=SEVERITY_ORDER.index)


@dataclass
class Finding:
    """One thing worth saying, with the reasoning attached.

    `verdict` is the part that makes this package different from a scanner:

      real        — believed to be a genuine exposure. Act on it.
      fixture     — deliberate test input (a redaction test's own sample).
      example     — documentation or an API example.
      vendored    — third-party code committed into the tree, not yours.
      placeholder — an obvious stand-in: `your-api-key`, `changeme`.
      unreachable — genuine in the abstract, not reachable as deployed.
      unknown     — could not be classified. Treated as real, deliberately.

    Anything this tool cannot explain is `unknown` and counted as real. A
    classifier that guesses "probably fine" is how real credentials get missed.
    """

    repo: str
    check: str
    title: str
    severity: str = "info"
    verdict: str = "unknown"
    reason: str = ""
    path: str | None = None
    line: int | None = None
    fingerprint: str | None = None
    # Never a credential value. See `masked()`.
    evidence: str | None = None
    remediation: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def actionable(self) -> bool:
        """Does a human need to do something about this?"""
        return self.verdict in ("real", "unknown")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def masked(secret: str | None) -> str:
    """Describe a secret without disclosing it.

    Four leading characters are kept because a prefix is what makes a key
    identifiable to its owner (`AKIA`, `sk_live`, `ghp_`) and four characters
    is not enough to use. The length is kept because it is often the fastest way
    to tell a real token from a placeholder.
    """
    if not secret:
        return "-"
    head = secret[:4]
    return f"{head}…[{len(secret)} chars]"
