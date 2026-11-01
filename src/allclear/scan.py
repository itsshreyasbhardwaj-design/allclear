"""Running gitleaks and classifying what it returns.

The binary is fetched from the official release and verified against a pinned
digest before it is executed. A security tool that silently runs an unverified
download is not one.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from .baseline import GITLEAKS_VERSION
from .classify import from_gitleaks
from .verdict import Finding

#: sha256 of each official release asset this package is willing to execute.
GITLEAKS_DIGESTS = {
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
}


def platform_key() -> str:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    if sysname == "darwin":
        return "darwin_arm64" if machine in ("arm64", "aarch64") else "darwin_x64"
    if sysname == "linux":
        return "linux_arm64" if machine in ("arm64", "aarch64") else "linux_x64"
    return f"{sysname}_{machine}"


def ensure_gitleaks(cache: str | Path | None = None) -> Path:
    """Return a path to a verified gitleaks binary, downloading if needed."""
    key = platform_key()
    digest = GITLEAKS_DIGESTS.get(key)
    cache_dir = Path(cache or (Path.home() / ".cache" / "allclear"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    binary = cache_dir / f"gitleaks-{GITLEAKS_VERSION}-{key}"
    if binary.exists():
        return binary
    if digest is None:
        raise RuntimeError(
            f"no pinned gitleaks digest for platform '{key}'. Install gitleaks yourself "
            f"and pass --gitleaks /path/to/gitleaks."
        )
    asset = f"gitleaks_{GITLEAKS_VERSION}_{key}.tar.gz"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{asset}"
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset
        with urllib.request.urlopen(url, timeout=120) as resp, open(archive, "wb") as fh:  # noqa: S310
            fh.write(resp.read())
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != digest:
            raise RuntimeError(
                f"gitleaks download digest mismatch for {asset}\n"
                f"  expected {digest}\n  actual   {actual}\n"
                "Refusing to execute it."
            )
        with tarfile.open(archive) as tf:
            member = tf.getmember("gitleaks")
            extracted = Path(tmp) / "gitleaks"
            with tf.extractfile(member) as src, open(extracted, "wb") as dst:
                dst.write(src.read())
        binary.write_bytes(extracted.read_bytes())
    binary.chmod(0o755)
    return binary


def run(repo_path: str | Path, gitleaks: str | Path | None = None,
        history: bool = False, repo_name: str | None = None) -> "list[Finding]":
    """Scan a checkout and return classified findings."""
    repo_path = Path(repo_path)
    binary = Path(gitleaks) if gitleaks else ensure_gitleaks()
    name = repo_name or repo_path.name
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gitleaks.json"
        mode = ["git", ".", "--log-opts=--all"] if history else ["dir", "."]
        cmd = [str(binary), *mode, "--report-format", "json",
               "--report-path", str(out), "--no-banner", "--exit-code", "0"]
        subprocess.run(cmd, cwd=str(repo_path), capture_output=True, text=True)
        if not out.exists():
            return []
        try:
            records = json.loads(out.read_text() or "[]")
        except json.JSONDecodeError:
            return []
    return [from_gitleaks(r, name) for r in records]
