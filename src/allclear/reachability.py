"""Severity is not exposure.

The single most useful conclusion of the audit this package came from was that
a CRITICAL, unauthenticated remote code execution advisory in Next.js was **not
reachable** in three of the affected repositories, because those sites are
static exports. There is no server. The vulnerable code was downloaded into
`node_modules`, shipped nothing, and ran never.

That distinction changes what you do on a Tuesday afternoon. One of those
repositories was a live business site where a breaking major upgrade carried
real risk; the other was a private dashboard with middleware, server actions
and a service-role database key, where the same advisory was entirely live. A
scanner that calls both CRITICAL has told you nothing about which to do first.

This module is deliberately narrow. It covers Next.js, because that is where
the evidence was, and it reports `None` — unknown — for anything it has not
been taught. An honest "I don't know" ranks above a confident guess.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

#: What each advisory needs in order to be exploitable.
#:
#: Curated by hand from the advisory text. Everything here was read, not
#: inferred, and anything absent is treated as reachable.
REQUIREMENTS: dict[str, str] = {
    "GHSA-2464-fhr4-w9xw": "image-optimizer",
    "GHSA-2xp9-vwfh-vxw4": "image-optimizer",
    "GHSA-cjq9-62q9-8jv4": "image-optimizer",
    "GHSA-vcvr-r3jv-pc5j": "image-response",
    "GHSA-f82v-jwr5-mffw": "middleware",
    "GHSA-36qx-fr4f-26g5": "middleware",
    "GHSA-9qr9-h5gf-34mp": "server",
    "GHSA-p293-qw3h-jr36": "server",
    "GHSA-673q-mjm6-r5xr": "server",
    "GHSA-p3m5-59mp-jv5r": "server-actions",
    "GHSA-4jqv-mc3x-m676": "server",
    "GHSA-mcj8-r9mp-w47p": "server",
}

REQUIREMENT_PROSE = {
    "image-optimizer": "the /_next/image optimisation endpoint",
    "image-response": "next/og ImageResponse rendering at request time",
    "middleware": "Next.js middleware",
    "server": "a running Next.js server",
    "server-actions": "React Server Actions",
}


@dataclass
class Deployment:
    """What a repository actually runs, as far as its files admit."""

    framework: str = "unknown"
    static_export: bool = False
    has_middleware: bool = False
    has_route_handlers: bool = False
    has_server_actions: bool = False
    image_optimizer: bool = True
    uses_image_response: bool = False
    evidence: list[str] = field(default_factory=list)

    @property
    def runs_a_server(self) -> bool:
        return not self.static_export

    def provides(self, requirement: str) -> bool | None:
        """Does this deployment provide the thing an advisory needs?"""
        if self.framework != "nextjs":
            return None
        return {
            "server": self.runs_a_server,
            "middleware": self.has_middleware,
            "server-actions": self.has_server_actions,
            "image-optimizer": self.image_optimizer and self.runs_a_server,
            "image-response": self.uses_image_response and self.runs_a_server,
        }.get(requirement)


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments before pattern-matching a JS/TS config.

    Found by running this tool on a real repository: a dashboard's
    next.config.mjs carried a comment explaining that *the other site* is
    `output: 'export'`. The regex matched inside the comment, the dashboard was
    classified as a static export, and a CRITICAL image-optimiser RCE was
    reported as unreachable on an app that very much runs a server.

    A false negative on a remote code execution advisory is the worst mistake
    available to this module, and it came from trusting a regex over a parser.
    Stripping comments is the cheap part of the fix; the second part is that
    `image_optimizer` is no longer derived from `static_export` until after the
    contradiction check below has had its say.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"(?m)^\s*//.*$", " ", text)
    text = re.sub(r"(?<![:\w])//.*$", " ", text, flags=re.M)
    return text


def _read(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def detect(root: str | Path) -> Deployment:
    """Work out the deployment model of a checked-out repository."""
    root = Path(root)
    d = Deployment()

    configs = [p for p in root.glob("next.config.*") if p.is_file()]
    configs += [p for p in root.glob("*/next.config.*") if p.is_file()]
    configs += [p for p in root.glob("apps/*/next.config.*") if p.is_file()]
    if not configs:
        pkg = root / "package.json"
        if pkg.exists() and '"next"' in _read(pkg):
            d.framework = "nextjs"
            d.evidence.append("package.json depends on next, but no next.config was found")
        return d

    d.framework = "nextjs"
    cfg_text = _strip_comments("\n".join(_read(c) for c in configs))
    d.evidence.append(f"found {len(configs)} next.config file(s)")

    if re.search(r"output\s*:\s*['\"]export['\"]", cfg_text):
        d.static_export = True
        d.evidence.append("next.config sets output: 'export' — the build emits static files only")

    # A custom loader or `unoptimized` means Next's own optimiser is not served.
    if re.search(r"unoptimized\s*:\s*true", cfg_text):
        d.image_optimizer = False
        d.evidence.append("images.unoptimized is true — no /_next/image endpoint is served")
    elif re.search(r"loader\s*:\s*['\"]custom['\"]", cfg_text):
        d.image_optimizer = False
        d.evidence.append("images.loader is 'custom' — image URLs bypass /_next/image")
    search_roots = [root / "src", root / "app", root / "pages", root]
    def _any(patterns: "list[str]", globs: "list[str]") -> Path | None:
        for base in search_roots:
            if not base.is_dir():
                continue
            for g in globs:
                for p in base.glob(g):
                    if "node_modules" in p.parts:
                        continue
                    if not patterns:
                        return p
                    text = _read(p)
                    if any(re.search(pat, text) for pat in patterns):
                        return p
        return None

    mw = _any([], ["middleware.ts", "middleware.js", "*/middleware.ts"])
    if mw:
        d.has_middleware = True
        d.evidence.append(f"middleware present ({mw.name})")

    rh = _any([], ["**/route.ts", "**/route.js", "**/route.tsx"])
    if rh:
        d.has_route_handlers = True
        d.evidence.append("route handlers present")

    sa = _any([r"['\"]use server['\"]"], ["**/*.ts", "**/*.tsx"])
    if sa:
        d.has_server_actions = True
        d.evidence.append("a file declares 'use server'")

    ir = _any([r"from\s+['\"]next/og['\"]", r"ImageResponse"], ["**/*.ts", "**/*.tsx"])
    if ir:
        d.uses_image_response = True
        d.evidence.append("next/og ImageResponse is used")

    if d.static_export and (d.has_middleware or d.has_route_handlers or d.has_server_actions):
        d.evidence.append(
            "NOTE: output:'export' alongside server-only features — the build would fail, "
            "so treat this detection as unreliable and assume a server is present"
        )
        d.static_export = False

    # Only now, once the static-export claim has survived contradiction, may it
    # be used to conclude that no optimisation endpoint is served.
    if d.static_export:
        d.image_optimizer = False

    return d


#: GHSA identifiers are mixed-case, so lookups are normalised once here rather
#: than per call. An earlier version upper-cased the id and silently matched
#: nothing, which made every advisory look unknown — a failure that reads as
#: caution but is really a dead code path.
_REQ_LOOKUP = {k.lower(): v for k, v in REQUIREMENTS.items()}


@dataclass
class Assessment:
    advisory: str
    reachable: bool | None
    requirement: str | None
    reason: str

    @property
    def verdict(self) -> str:
        if self.reachable is None:
            return "unknown"
        return "real" if self.reachable else "unreachable"


def assess(advisory: str, deployment: Deployment) -> Assessment:
    """Decide whether one advisory is reachable in this deployment."""
    req = _REQ_LOOKUP.get(advisory.strip().lower())
    if req is None:
        return Assessment(advisory, None, None,
                          "no reachability rule for this advisory, so it is treated as reachable")
    provided = deployment.provides(req)
    prose = REQUIREMENT_PROSE.get(req, req)
    if provided is None:
        return Assessment(advisory, None, req,
                          f"needs {prose}; this project's framework was not recognised")
    if provided:
        return Assessment(advisory, True, req, f"needs {prose}, and this deployment has it")
    why = "; ".join(deployment.evidence[-3:]) or "no server-side surface detected"
    return Assessment(advisory, False, req,
                      f"needs {prose}, which this deployment does not serve ({why})")


def downgrade(severity: str, assessment: Assessment) -> str:
    """Severity adjusted for reachability, never raised."""
    if assessment.reachable is False:
        return "low"
    return severity
