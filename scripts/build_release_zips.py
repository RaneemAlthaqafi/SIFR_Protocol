"""Build the v0.3.x release zips:
  - sifr-{VERSION}-research-artifact.zip   (full artifact for review)
  - sifr-{VERSION}-overleaf-ready.zip      (paper sources + figures only)

Version is taken from $SIFR_RELEASE_VERSION (default: v0.3.1).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RELEASE_VERSION = os.environ.get("SIFR_RELEASE_VERSION", "v0.3.1")
ARTIFACT_ZIP = REPO / f"sifr-{RELEASE_VERSION}-research-artifact.zip"
OVERLEAF_ZIP = REPO / f"sifr-{RELEASE_VERSION}-overleaf-ready.zip"

# What goes into the research artifact zip (relative to repo root).
ARTIFACT_INCLUDE = [
    "sifr/",
    "tests/",
    "examples/",
    "benchmarks/",
    "wasm/",
    "scripts/",
    "docker/Dockerfile.quic_node",
    "docker/quic_node.py",
    "docker/quic_runner.py",
    "docker/compose_quic_netem.yml",
    "formal/sifr_capability.tla",
    "formal/MC.cfg",
    "formal/run_tlc.sh",
    "formal/run_tlc.ps1",
    "formal/output/tlc_output.txt",
    "formal/output/tlc_metadata.json",
    "formal/output/model_hashes.json",
    "docs/",
    "paper/",
    "review/",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "LICENSE",
    ".github/workflows/test.yml",
    ".gitignore",
]
ARTIFACT_EXCLUDE = {
    ".pyc", ".pyo", ".pyd",
}
ARTIFACT_EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".venv", "node_modules",
    "formal/tools", "formal/states", "docker/out",
}

OVERLEAF_INCLUDE = [
    "paper/",
]
OVERLEAF_EXCLUDE_DIRS = {
    "paper/__pycache__",
}


def _walk(roots: list[str], exclude_dirs: set[str], exclude_exts: set[str]) -> list[Path]:
    out: list[Path] = []
    for root in roots:
        p = REPO / root
        if p.is_file():
            out.append(p)
            continue
        if not p.is_dir():
            continue
        for child in p.rglob("*"):
            if not child.is_file():
                continue
            rel = child.relative_to(REPO).as_posix()
            if any(part in exclude_dirs for part in rel.split("/")):
                continue
            if any(rel.startswith(d + "/") for d in exclude_dirs):
                continue
            if child.suffix in exclude_exts:
                continue
            out.append(child)
    return out


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()
    except Exception:
        return "unknown"


def build_zip(name: str, paths: list[Path], zip_path: Path) -> dict:
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(paths):
            arc = p.relative_to(REPO).as_posix()
            z.write(p, arcname=f"sifr-{RELEASE_VERSION}/{arc}")
    return {
        "zip": zip_path.name,
        "sha256": sha256(zip_path),
        "files": len(paths),
        "bytes": zip_path.stat().st_size,
    }


def main() -> None:
    artifact_files = _walk(ARTIFACT_INCLUDE, ARTIFACT_EXCLUDE_DIRS, ARTIFACT_EXCLUDE)
    overleaf_files = _walk(OVERLEAF_INCLUDE, OVERLEAF_EXCLUDE_DIRS, ARTIFACT_EXCLUDE)

    art = build_zip("artifact", artifact_files, ARTIFACT_ZIP)
    ovl = build_zip("overleaf", overleaf_files, OVERLEAF_ZIP)

    manifest = {
        "version": RELEASE_VERSION,
        "git_commit": git("rev-parse", "HEAD"),
        "git_describe": git("describe", "--always", "--tags"),
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifact": art,
        "overleaf": ovl,
    }
    out = REPO / "review" / "v0_3_release_manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"artifact zip: {ARTIFACT_ZIP.relative_to(REPO)}  ({art['files']} files, {art['bytes']:,} bytes)")
    print(f"overleaf zip: {OVERLEAF_ZIP.relative_to(REPO)}  ({ovl['files']} files, {ovl['bytes']:,} bytes)")
    print(f"manifest:     {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
