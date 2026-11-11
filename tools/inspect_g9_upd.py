# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
"""Read-only Panasonic MC471/G9 UPD inspection and raw section extraction.

Python 3.10+, standard library only. Does not decrypt, patch, repack or flash.
The offsets below were validated against the supplied G9___V27.bin. Other
models/versions are not supported unless they pass every structural check.

Examples:
  python inspect_g9_upd.py G9___V27.zip --json g9-layout.json
  python inspect_g9_upd.py G9___V27.bin --extract-dir raw-sections
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import zipfile
import zlib

LIMIT = 256 * 1024 * 1024
PAYLOAD_BASE = 0x200
TABLE = 0x2EC
ENTRY_SIZE = 0x5C


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    n = len(data)
    return round(-sum((v / n) * math.log2(v / n)
                      for v in Counter(data).values()), 8) if n else 0.0


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_input(path: Path) -> tuple[bytes, dict]:
    require(path.stat().st_size <= LIMIT, "Input exceeds 256 MiB limit")
    source = path.read_bytes()
    metadata = {"filename": path.name, "size": len(source), "sha256": digest(source)}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            require(len(members) == 1, "Expected exactly one BIN member")
            item = members[0]
            require(not item.is_dir() and item.filename.lower().endswith(".bin"),
                    "Expected one firmware BIN member")
            require(item.file_size <= LIMIT, "Uncompressed member exceeds 256 MiB limit")
            data = archive.read(item)  # validates the ZIP member CRC
            metadata["zip_member"] = item.filename
            metadata["zip_member_crc32"] = f"{item.CRC:08x}"
            metadata["zip_member_crc_verified"] = True
            metadata["zip_member_timestamp"] = list(item.date_time)
    else:
        data = source
    return data, metadata


def inspect(data: bytes, source: dict) -> dict:
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    require(len(data) >= 0x400, "Truncated UPD image")
    require(data[:4] == b"UPD\0", "Missing UPD magic")
    require(u32(4) == 512 and u32(8) == 512, "Unexpected block-size fields")
    require(data[0x200:0x209] == b"panasonic", "Missing Panasonic envelope")
    require(data[0x2A0:0x2E0] == data[:0x40], "Secondary UPD header differs")
    model = data[0x0C:0x1C].split(b"\0")[0].decode("ascii")
    require(model == "MC471", f"This inspector is validated only for MC471, got {model!r}")
    require(u32(0x3C) + PAYLOAD_BASE == len(data), "Declared image size differs")
    expected_crc = u32(0x40)
    actual_crc = zlib.crc32(data[PAYLOAD_BASE:])
    require(expected_crc == actual_crc, "Image CRC32 mismatch")
    count = u32(0x2E8)
    first_payload = u32(0x2E0) + PAYLOAD_BASE
    payload_size = u32(0x2E4)
    require(0 < count <= 512, "Invalid section count")
    require(TABLE + count * ENTRY_SIZE <= first_payload <= len(data), "Invalid table bounds")
    require(first_payload + payload_size == len(data), "Invalid payload length")

    sections = []
    next_offset = first_payload
    names = set()
    for index in range(count):
        pos = TABLE + index * ENTRY_SIZE
        raw = data[pos:pos + ENTRY_SIZE]
        name = raw[:12].split(b"\0")[0].decode("ascii")
        require(re.fullmatch(r"[A-Za-z0-9_]{1,12}", name) is not None, "Invalid section name")
        require(name not in names, "Duplicate section name")
        names.add(name)
        stored_offset, size, logical_field, flags = struct.unpack_from("<IIII", raw, 12)
        offset = stored_offset + PAYLOAD_BASE
        require(offset == next_offset, f"Non-contiguous payload at {name}")
        require(offset + size <= len(data), f"Section {name} is out of bounds")
        require(flags in (2, 3), f"Unknown section flags in {name}")
        section = data[offset:offset + size]
        stored_hash = raw[28:60].hex()
        section_hash = digest(section)
        known_hashes = {
            "all_zero": digest(bytes(size)),
            "all_ff": digest(b"\xff" * size),
        }
        ent = entropy(section)
        state = ("empty" if not size else "raw_sha256_matches" if stored_hash == section_hash
                 else "opaque_high_entropy" if ent > 7.5 else "opaque_other")
        sections.append({
            "index": index, "name": name, "table_entry_offset": pos,
            "stored_relative_offset": stored_offset, "absolute_file_offset": offset,
            "size": size, "logical_address_field_unconfirmed": logical_field, "flags": flags,
            "table_digest_sha256": stored_hash, "raw_sha256": section_hash,
            "raw_matches_table_digest": section_hash == stored_hash,
            "table_digest_matches_known_pattern": [key for key, value in known_hashes.items()
                                                   if value == stored_hash],
            "metadata_bytes_3c_to_4c": raw[60:76].hex(),
            "metadata_bytes_4c_to_5c": raw[76:92].hex(),
            "entropy_bits_per_byte": ent, "state": state,
            "prefix_32_hex": section[:32].hex(),
        })
        next_offset = offset + size
    require(next_offset == len(data), "Sections do not cover the full image tail")

    repeated_digests = []
    groups = {}
    for section in sections:
        groups.setdefault(section["table_digest_sha256"], []).append(section["name"])
    for hash_hex, section_names in groups.items():
        if len(section_names) > 1:
            repeated_digests.append({"table_digest": hash_hex, "sections": section_names})

    markers = {"ELF": b"\x7fELF", "FDT": b"\xd0\x0d\xfe\xed", "SquashFS_LE": b"hsqs",
               "XZ": b"\xfd7zXZ\x00", "ZIP": b"PK\x03\x04", "uImage": b"\x27\x05\x19\x56"}
    magic_hits = {}
    for name, marker in markers.items():
        offsets = [match.start() for match in re.finditer(re.escape(marker), data)]
        magic_hits[name] = offsets
    gzip_candidates = []
    for match in re.finditer(b"\x1f\x8b\x08", data):
        start = match.start()
        decoder = zlib.decompressobj(31)
        try:
            decoded = decoder.decompress(data[start:start + 1024 * 1024], 4 * 1024 * 1024)
            status = "complete_stream" if decoder.eof else "incomplete_or_output_limit"
            gzip_candidates.append({"offset": start, "status": status, "output_bytes": len(decoded)})
        except zlib.error as error:
            gzip_candidates.append({"offset": start, "status": "invalid", "error": str(error)})

    return {
        "source": source,
        "image": {"size": len(data), "sha256": digest(data), "model_id": model,
                  "magic": "UPD", "block_size": 512, "relative_offset_base": PAYLOAD_BASE,
                  "section_count": count, "table_offset": TABLE, "table_entry_size": ENTRY_SIZE,
                  "first_payload_absolute_offset": first_payload, "payload_size": payload_size,
                  "crc32_stored": f"{expected_crc:08x}", "crc32_computed": f"{actual_crc:08x}",
                  "crc32_valid": True, "secondary_header_prefix_matches": True,
                  "sections_are_contiguous": True,
                  "unidentified_64_byte_field_at_0x220": data[0x220:0x260].hex(),
                  "signature_algorithm_and_enforcement": "not evaluated by this inspector",
                  "encryption_algorithm_and_keys": "not evaluated by this stored-byte inspector; see the V2.7 decoder"},
        "summary": dict(Counter(section["state"] for section in sections)),
        "repeated_table_digests": repeated_digests,
        "format_magic_hits_unvalidated": magic_hits,
        "gzip_candidate_validation": gzip_candidates,
        "sections": sections,
    }


def write_new_or_identical(path: Path, data: bytes, input_path: Path) -> None:
    require(path.resolve() != input_path.resolve(), "Refusing to overwrite input")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == data, f"Refusing to replace different existing file: {path}")
    else:
        with path.open("xb") as output:
            output.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--extract-dir", type=Path, help="Extracts RAW STORED BYTES, not decrypted code")
    args = parser.parse_args()
    data, source = load_input(args.image)
    result = inspect(data, source)
    print(f"Model {result['image']['model_id']} | {len(data):,} bytes | CRC32 verified")
    print(f"SHA256 {result['image']['sha256']}")
    print("idx name           file offset       size  flags entropy raw-hash=table")
    for section in result["sections"]:
        print(f"{section['index']:3} {section['name']:13} 0x{section['absolute_file_offset']:08x} "
              f"{section['size']:10,} {section['flags']:5} "
              f"{section['entropy_bits_per_byte']:7.4f} {section['raw_matches_table_digest']}")
    print(json.dumps(result["summary"]))
    if args.extract_dir:
        rebuilt = hashlib.sha256()
        rebuilt.update(data[:result["image"]["first_payload_absolute_offset"]])
        for section in result["sections"]:
            offset, size = section["absolute_file_offset"], section["size"]
            destination = args.extract_dir / f"{section['index']:02d}_{section['name']}.raw.bin"
            write_new_or_identical(destination, data[offset:offset + size], args.image)
            extracted = destination.read_bytes()
            require(digest(extracted) == section["raw_sha256"], "Extracted bytes differ")
            rebuilt.update(extracted)
        require(rebuilt.hexdigest() == result["image"]["sha256"], "Reassembly hash mismatch")
        result["extraction_verification"] = {
            "files": len(result["sections"]), "read_back_hashes_match": True,
            "reassembly_sha256_matches_original": True,
        }
        print("Raw extraction verified by read-back hashes and full image reassembly hash")
    if args.json:
        write_new_or_identical(args.json, (json.dumps(result, indent=2) + "\n").encode(), args.image)
    if args.csv:
        import io
        buffer = io.StringIO(newline="")
        columns = ["index", "name", "absolute_file_offset", "size", "flags",
                   "entropy_bits_per_byte", "state", "raw_sha256", "table_digest_sha256"]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(result["sections"])
        write_new_or_identical(args.csv, buffer.getvalue().encode(), args.image)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
