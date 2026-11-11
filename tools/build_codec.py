# SPDX-License-Identifier: MIT
"""Build the host-only CBC encoder with the already-tested portable compiler."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def build(zig, out):
    executable = shutil.which(str(zig))
    if executable is None:
        raise ValueError("Zig executable not found")
    executable = str(Path(executable).resolve())
    out = Path(out).resolve()
    if out.exists():
        raise ValueError("Output directory must be new")
    version = subprocess.run([executable, "version"], check=True, capture_output=True, text=True).stdout.strip()
    if version != "0.17.1":
        raise ValueError("This recipe is pinned to Zig 0.17.1")
    source = ROOT / "tools/cipher-codec/cbc.c"
    out.mkdir(parents=True)
    target = out / ("g9-cbc.exe" if os.name == "nt" else "g9-cbc")
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / ".zig-global-cache"),
               ZIG_LOCAL_CACHE_DIR=str(out / ".zig-cache"))
    arguments = [executable, "cc", "-std=c11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-command-line-argument", str(source), "-o", str(target)]
    result = subprocess.run(arguments, env=env, capture_output=True, text=True)
    (out / "compiler-log.json").write_text(json.dumps({"arguments": arguments,
        "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n", encoding="utf-8")
    if result.returncode:
        raise ValueError("Host encoder compilation failed: " + result.stderr[-3000:])
    report = {"zig": version, "scope": "host CBC encoder; not camera code",
              "source_SHA256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "executable": target.name,
              "executable_SHA256": hashlib.sha256(target.read_bytes()).hexdigest()}
    (out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.zig, args.out), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
