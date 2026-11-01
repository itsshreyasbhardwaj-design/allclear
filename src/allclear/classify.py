"""Deciding which findings are real.

This is the part that earns the package its existence. Running gitleaks across
48 repositories during the audit that prompted this tool produced 139 findings.
Every single one turned out to be a deliberate test fixture, a documentation
example, or vendored upstream code. Zero were live credentials.

A tool that reports 139 findings when the answer is zero has not helped. So the
job here is classification, and the rules below are the ones that actually did
the work on real repositories — not a generic list.

Two principles:

1. **Unknown is treated as real.** A classifier that guesses "probably fine"
   is how a real credential gets missed. Only an affirmative, explainable
   reason downgrades a finding.

2. **Every verdict carries its reason.** If this tool tells you something is a
   fixture, it says which rule fired, so you can disagree with it.
"""

from __future__ import annotations

import base64
import posixpath
import re

from .verdict import Finding

# ---------------------------------------------------------------------------
# Path rules
#
# A hard-won detail: these match PATH SEGMENTS, not raw substrings.
#
# The first version of this logic (written by hand during the audit) used the
# substring "/docs/" to recognise documentation. That has a leading slash, so it
# matched "packages/web/docs/api.md" and silently failed to match a
# repository-root "docs/api.md" — which meant a documentation example went
# unclassified, and the CI secret scan that shipped with it failed on day one in
# the one repository where the finding sat at the root.
#
# Segment matching removes that whole class of mistake.
# ---------------------------------------------------------------------------

#: directory names that mean "this is test input"
TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "testdata", "e2e"})
#: directory names that mean "deliberately insecure sample"
FIXTURE_DIRS = frozenset({"fixtures", "fixture", "__fixtures__", "examples", "sample", "samples"})
#: directory names that mean "not our code"
VENDOR_DIRS = frozenset({"node_modules", "vendor", "vendored", "third_party", "thirdparty",
                         "external", "site-packages", ".venv", "venv"})
#: directory names that mean "generated, not authored"
BUILD_DIRS = frozenset({".next", "dist", "build", "out", "target", ".output", "coverage",
                        ".turbo", ".svelte-kit", "__pycache__"})
#: directory names that mean "documentation"
DOC_DIRS = frozenset({"doc", "docs", "documentation", "website"})

#: filename suffixes that mean "test file"
TEST_FILE_RE = re.compile(r"\.(test|spec)\.[a-z]+$|_test\.[a-z]+$|^test_.*\.py$")
#: filenames that are templates by convention, never real values
TEMPLATE_FILE_RE = re.compile(
    r"\.env\.(example|sample|template|dist|local\.example)$"
    r"|^\.env\.example$|^env\.template$|^\.env\.sample$"
    r"|\.example$|\.template$|\.dist$",
    re.IGNORECASE,
)
DOC_FILE_RE = re.compile(r"\.(md|mdx|rst|txt|adoc)$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Value rules
# ---------------------------------------------------------------------------

#: AWS publishes this exact key in its own documentation.
AWS_DOC_EXAMPLE_KEYS = frozenset({"AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"})

#: words that only ever appear in a stand-in
PLACEHOLDER_WORDS = (
    "your-", "your_", "yourkey", "youraccount", "changeme", "change-me",
    "placeholder", "example", "dummy", "fake", "sample", "redacted",
    "xxxxx", "<your", "insert", "todo", "replace-me", "notarealkey",
    "secret-goes-here", "abcdef", "foobar", "deadbeef",
)

#: a value made only of a repeated short pattern is a human typing filler
REPEATED_PATTERN_RE = re.compile(
    r"^(?:(0123456789abcdef|0123456789|abcdefgh|deadbeef|aaaa|1234)\1*|"
    r"(.)\2{7,}|(?:ab|xy|12)+)$",
    re.IGNORECASE,
)

#: Supabase and similar: these are designed to be shipped to a browser.
PUBLIC_BY_DESIGN = (
    ("supabase", "anon"),
    ("supabase", "publishable"),
    ("next_public", ""),
    ("vite_", ""),
    ("expo_public", ""),
    ("stripe", "pk_"),
    ("stripe", "pk_test"),
)

#: ...but these never are, whatever their prefix suggests.
NEVER_PUBLIC = ("service_role", "service-role", "secret_key", "sk_live", "private_key")


def _segments(path: str) -> list[str]:
    """Normalise a repo-relative path into lowercase segments.

    `lstrip("./")` is wrong here and was the second bug this function had:
    `str.lstrip` takes a SET of characters, so it eats the leading dot of a
    dotfile and turns ".env.example" into "env.example". Dotfiles are exactly
    the files a secret scanner cares about, so the prefix is removed as a
    prefix.
    """
    raw = path.replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    norm = posixpath.normpath(raw)
    return [s.lower() for s in norm.split("/") if s not in ("", ".")]


def _looks_base64_of_filler(value: str) -> str | None:
    """If the value decodes to printable filler, say what it decoded to."""
    candidate = value.strip()
    if len(candidate) < 8:
        return None
    try:
        raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
        text = raw.decode("utf-8")
    except Exception:
        return None
    if not text or not all(32 <= ord(c) < 127 for c in text):
        return None
    low = text.lower()
    for word in ("test", "dummy", "example", "placeholder", "changeme", "0123456789abcdef", "secret"):
        if word in low:
            return text[:40]
    return None


def classify_path(path: str | None) -> tuple[str, str] | None:
    """Classify purely from where the finding lives.

    Returns `(verdict, reason)` or None when the path says nothing.
    """
    if not path:
        return None
    segs = _segments(path)
    if not segs:
        return None
    name = segs[-1]
    dirs = set(segs[:-1])

    if dirs & VENDOR_DIRS:
        hit = sorted(dirs & VENDOR_DIRS)[0]
        return ("vendored", f"lives under '{hit}/', which holds third-party code, not this project's")
    if dirs & BUILD_DIRS:
        hit = sorted(dirs & BUILD_DIRS)[0]
        return ("vendored", f"lives under '{hit}/', which is build output rather than source")
    if TEMPLATE_FILE_RE.search(name):
        return ("placeholder", f"'{name}' is a template file by convention; its values are stand-ins")
    if dirs & FIXTURE_DIRS:
        hit = sorted(dirs & FIXTURE_DIRS)[0]
        return ("fixture", f"lives under '{hit}/', a deliberately-constructed sample tree")
    if dirs & TEST_DIRS or TEST_FILE_RE.search(name):
        return ("fixture", "a test file: the value is the test's own input")
    if dirs & DOC_DIRS or (DOC_FILE_RE.search(name) and name.startswith("readme")):
        return ("example", "documentation, where credentials are illustrative")
    if DOC_FILE_RE.search(name) and dirs & DOC_DIRS:
        return ("example", "documentation, where credentials are illustrative")
    return None


def classify_value(value: str | None, context: str = "") -> tuple[str, str] | None:
    """Classify from the matched string itself (never echoed back)."""
    if not value:
        return None
    v = value.strip()
    low = v.lower()
    ctx = (context or "").lower()

    if v in AWS_DOC_EXAMPLE_KEYS:
        return ("example", "the access key id AWS publishes in its own documentation")
    if "example" in low and re.match(r"^AKIA[A-Z0-9]{16}$", v):
        return ("example", "an AWS-shaped key whose body spells EXAMPLE")
    for word in PLACEHOLDER_WORDS:
        if word in low:
            return ("placeholder", f"the value contains '{word}', which only appears in a stand-in")
    if REPEATED_PATTERN_RE.match(v):
        return ("placeholder", "the value is a short pattern repeated to length, i.e. typed filler")
    decoded = _looks_base64_of_filler(v)
    if decoded:
        return ("placeholder", f"base64 of printable filler text ({decoded!r})")

    # public-by-design keys, unless the name says otherwise
    if not any(n in ctx for n in NEVER_PUBLIC):
        for family, marker in PUBLIC_BY_DESIGN:
            if family in ctx and (not marker or marker in ctx or marker in low):
                return ("example",
                        f"a {family} key that is public by design (it ships to the browser); "
                        "the confidential counterpart is the service-role/secret key")
    return None


def classify(finding: Finding, context: str = "") -> Finding:
    """Attach a verdict and a reason to a finding, in place, and return it.

    `context` is any surrounding text available — the variable name, the line,
    the enclosing function. It is used for signals that the value alone cannot
    give, such as telling a Supabase anon key from a service-role key.
    """
    # Precedence matters, and this order was wrong on the first attempt.
    #
    # The "never public" rule below is evidence about a NAME: a variable called
    # SUPABASE_SERVICE_ROLE_KEY should never hold a public value, and that
    # outranks any excuse based on which file it sits in. But it does not
    # outrank definitive evidence about the VALUE itself. Running it first made
    # this tool report `sk_live_PLACEHOLDER` in its own test suite as a critical
    # exposure — the exact false positive it exists to remove.
    #
    # So: what the value demonstrably IS, then what the name implies, then
    # where it lives, then give up and call it real.
    value_rule = classify_value(finding.evidence, context)
    if value_rule and value_rule[0] in ("placeholder", "example"):
        finding.verdict, finding.reason = value_rule
        return finding

    if any(n in (context or "").lower() for n in NEVER_PUBLIC):
        finding.verdict = "real"
        finding.reason = ("names a service-role or secret key, which must never be public "
                          "whatever the surrounding file is")
        return finding

    for rule in (value_rule, classify_path(finding.path)):
        if rule:
            finding.verdict, finding.reason = rule
            return finding

    finding.verdict = "unknown"
    finding.reason = ("no rule matched, so this is treated as real: an unexplained "
                      "credential-shaped string is the case worth a human's attention")
    return finding


def from_gitleaks(record: dict, repo: str) -> Finding:
    """Turn one gitleaks JSON record into a classified Finding."""
    path = record.get("File") or record.get("file")
    secret = record.get("Secret") or record.get("secret")
    context = " ".join(str(record.get(k, "")) for k in ("Match", "match", "RuleID", "File")) or ""
    f = Finding(
        repo=repo,
        check="secret-scan",
        title=f"{record.get('RuleID') or record.get('ruleID') or 'secret'} in {path}",
        severity="critical",
        path=path,
        line=record.get("StartLine") or record.get("startLine"),
        fingerprint=record.get("Fingerprint") or record.get("fingerprint"),
        evidence=secret,
        remediation="Rotate the credential at its provider, then remove it from the repository.",
        meta={"rule": record.get("RuleID") or record.get("ruleID"),
              "commit": (record.get("Commit") or "")[:12],
              "date": (record.get("Date") or "")[:10]},
    )
    classify(f, context)
    if not f.actionable:
        f.severity = "info"
        f.remediation = "No action needed. Record it in .gitleaksignore so the scan stays green."
    return f
