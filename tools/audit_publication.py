# SPDX-License-Identifier: MIT
"""Audit the Git index for artifacts and machine-specific/private data."""
import argparse
import json
from pathlib import Path
import re
import subprocess

MAX_FILE_BYTES = 1024 * 1024
ROOT_FILES = {"README.md", "LICENSE", "CONTRIBUTING.md", ".gitignore", ".gitattributes", "requirements.txt"}
ROOT_DIRS = {"docs", "evidence", "tools", "tests", ".github"}
BINARY_SUFFIXES = {".bin", ".raw", ".img", ".zip", ".7z", ".gz", ".xz", ".gzf", ".gpr", ".exe", ".dll", ".pyd", ".so", ".ko", ".pyc", ".class", ".elf", ".o", ".obj", ".a", ".lib"}
PRIVATE_TEXT = [
    (re.compile(r"[A-Za-z]:[\\/]+Users[\\/]", re.IGNORECASE), "machine-specific Windows home path"),
    (re.compile(r"/home/[A-Za-z0-9._-]+/"), "machine-specific Unix home path"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key block"),
    (re.compile(r"(?m)^H[0-9A-Fa-f]{3}[ :].*(?:[0-9A-Fa-f]{4},){8}"), "ROM-export data row"),
]


def inspect_file(root, relative):
    root, relative = Path(root).resolve(), Path(relative)
    issues = []
    target = root / relative
    if relative.is_absolute() or ".." in relative.parts or not target.resolve().is_relative_to(root):
        return ["path escapes repository"]
    if target.is_symlink() or not target.is_file():
        return ["not a regular source file"]
    if len(relative.parts) == 1:
        if relative.name not in ROOT_FILES:
            issues.append("unexpected repository-root file")
    elif relative.parts[0] not in ROOT_DIRS:
        issues.append("unexpected source directory")
    if target.suffix.lower() in BINARY_SUFFIXES:
        issues.append("binary, firmware, capture or generated artifact extension")
    if re.fullmatch(r"g9[afu]\.txt", target.name, re.IGNORECASE):
        issues.append("camera ROM-export filename")
    if "decompiled" in target.name.lower() or target.name.lower().endswith("-disassembly.asm"):
        issues.append("generated vendor-code artifact")
    if target.stat().st_size > MAX_FILE_BYTES:
        return issues + ["file exceeds source-only size limit"]
    raw = target.read_bytes()
    if b"\0" in raw:
        return issues + ["binary NUL bytes"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return issues + ["not UTF-8 source text"]
    for pattern, label in PRIVATE_TEXT:
        if pattern.search(text):
            issues.append(label)
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tree", action="store_true", help="Audit a fresh source tree before git init")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if args.tree:
        ignored = {".git", "__pycache__", ".pytest_cache", ".venv"}
        files = [p.relative_to(root) for p in root.rglob("*")
                 if p.is_file() and not any(part in ignored for part in p.relative_to(root).parts)]
    else:
        result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True)
        files = [Path(p.decode("utf-8")) for p in result.stdout.split(b"\0") if p]
    if not files:
        raise ValueError("No indexed source files; stage the intended files before auditing")
    findings = [{"file": p.as_posix(), "issues": issues} for p in sorted(files)
                if (issues := inspect_file(root, p))]
    print(json.dumps({"files_checked": len(files), "findings": findings}, indent=2))
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
