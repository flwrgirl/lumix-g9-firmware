# SPDX-License-Identifier: MIT
"""Re-hash decoded output against this repository's expected release metadata."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(directory):
    directory = Path(directory).resolve(strict=True)
    expected = json.loads((ROOT / "evidence/expected-components.json").read_text())
    if len(expected["sections"]) != 49:
        raise ValueError("Unexpected expected component count")
    for section in expected["sections"]:
        target = (directory / section["file"]).resolve()
        if not target.is_relative_to(directory) or not target.is_file():
            raise ValueError(f"Missing or invalid component: {section['file']}")
        with target.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if target.stat().st_size != section["bytes"] or actual != section["SHA256"]:
            raise ValueError(f"Component size or SHA-256 mismatch: {section['name']}")
    program = directory / "03_program.bin"
    with program.open("rb") as handle:
        handle.seek(0x009C8F10)
        if handle.read(16).hex() != expected["key_hex"]:
            raise ValueError("Documented key location does not match the program")
    return {"verified_components": 49, "all_plaintext_hashes_match": True,
            "documented_key_location_matches": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
