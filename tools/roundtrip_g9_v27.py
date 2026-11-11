# SPDX-License-Identifier: MIT
"""Re-encrypt unchanged verified components and reproduce the exact input BIN.

This is a packaging control, not a modified-image builder or a firmware installer.
All inputs must match the pinned release. No existing output is overwritten.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile
import zlib

try:
    from .decode_g9_v27 import IMAGE_SHA256, KEY, decode, require
    from .verify_decoded import verify
except ImportError:
    from decode_g9_v27 import IMAGE_SHA256, KEY, decode, require
    from verify_decoded import verify

IMAGE_BYTES = 81952256


def encode(executable, data, key, iv, rounds=5):
    require(len(data) % 16 == 0 and len(key) == len(iv) == 16, "Invalid encoder block/key/IV length")
    require(rounds in (5, 10), "Unsupported AES round count")
    result = subprocess.run([str(executable), key.hex(), iv.hex(), str(rounds)], input=data,
                            capture_output=True, timeout=120)
    require(result.returncode == 0, "Encoder failed: " + result.stderr.decode("utf-8", "replace")[:1000])
    require(len(result.stdout) == len(data), "Encoder changed component length")
    return result.stdout


def controls(executable):
    # NIST SP 800-38A F.2.1, all four CBC blocks (standard ten-round AES).
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                             "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
    require(encode(executable, plain, bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), bytes(range(16)), 10)
            == expected, "Native encoder NIST CBC control failed")
    # Published older-model five-round block, with a zero CBC IV.
    require(encode(executable, bytes.fromhex("cd6a60a6c34c6893a76ad12db4d8bdf2"),
                   bytes.fromhex("350481b566d22d5b89dc46775e644622"), bytes(16), 5)
            == bytes.fromhex("147069b0d8d7a35b439688d2b8e59278"), "Native encoder five-round control failed")
    # Cross a native streaming buffer boundary and independently decrypt it.
    large = bytes(range(256)) * 257
    iv = bytes(reversed(range(16)))
    require(decode(encode(executable, large, KEY, iv), iv) == large, "Encoder streaming CBC chain control failed")
    return {"NIST_four_block_CBC": True, "independent_five_round_vector": True,
            "streaming_boundary_independent_decryption": True}


def read_image(path):
    path = Path(path)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            require(archive.namelist() == ["G9___V27.bin"], "Unexpected archive contents")
            require(archive.getinfo("G9___V27.bin").file_size == IMAGE_BYTES, "Unexpected uncompressed firmware size")
            image = archive.read("G9___V27.bin")
    else:
        require(path.stat().st_size == IMAGE_BYTES, "Not the pinned G9 V2.7 input")
        image = path.read_bytes()
    require(len(image) == IMAGE_BYTES and hashlib.sha256(image).hexdigest() == IMAGE_SHA256,
            "Not the pinned G9 V2.7 input")
    require(zlib.crc32(image[0x200:]) & 0xffffffff == struct.unpack_from("<I", image, 0x40)[0], "Bad input CRC32")
    return image


def rebuild(input_path, decoded, encoder, out):
    out = Path(out).resolve()
    require(not out.exists(), "Output directory must be new")
    image = read_image(input_path)
    decoded = Path(decoded).resolve(strict=True)
    verify(decoded)  # Refuse any changed/missing plaintext before executing encoder.
    encoder = Path(encoder).resolve(strict=True)
    control_results = controls(encoder)
    rebuilt = bytearray(image[:0x1600])
    rows = []
    for index in range(49):
        entry = 0x2ec + index * 0x5c
        name = image[entry:entry + 12].rstrip(b"\0").decode("ascii")
        require(name and all(c.isascii() and (c.isalnum() or c == "_") for c in name), "Invalid component name")
        relative, size, destination, flags = struct.unpack_from("<IIII", image, entry + 12)
        require(relative + 0x200 == len(rebuilt), "Unexpected non-contiguous payload layout")
        require(flags in (2, 3) and image[entry + 76:entry + 92] == bytes(16), "Unexpected component metadata")
        target = decoded / f"{index:02d}_{name}.bin"
        require(not target.is_symlink() and target.is_file(), "Invalid plaintext file")
        plain = target.read_bytes()
        digest = hashlib.sha256(plain).digest()
        require(len(plain) == size and digest == image[entry + 28:entry + 60], "Changed plaintext component")
        iv = image[entry + 60:entry + 76]
        stored = encode(encoder, plain, KEY, iv) if flags == 3 and size else plain
        require(stored == image[len(rebuilt):len(rebuilt) + size], "Re-encrypted component differs: " + name)
        record = name.encode("ascii").ljust(12, b"\0") + struct.pack("<IIII", len(rebuilt) - 0x200, size, destination, flags)
        record += digest + iv + bytes(16)
        require(record == image[entry:entry + 92], "Reconstructed directory entry differs")
        rebuilt[entry:entry + 92] = record
        rebuilt.extend(stored)
        rows.append({"index": index, "name": name, "bytes": size, "encrypted": flags == 3,
                     "plain_SHA256": digest.hex(), "stored_SHA256": hashlib.sha256(stored).hexdigest(),
                     "directory_and_stored_bytes_identical": True})
        print(json.dumps({"component": name, "reconstructed_identically": True}), flush=True)
    struct.pack_into("<I", rebuilt, 0x40, zlib.crc32(memoryview(rebuilt)[0x200:]) & 0xffffffff)
    digest = hashlib.sha256(rebuilt).hexdigest()
    require(len(rebuilt) == len(image) and digest == IMAGE_SHA256 and rebuilt == image, "Whole-image roundtrip failed")
    report = {"scope": "unchanged release reconstruction only", "bytes": len(rebuilt),
              "BIN_SHA256": digest, "matches_pinned_original_byte_for_byte": True,
              "components_reconstructed": len(rows), "encrypted_components": sum(r["encrypted"] for r in rows),
              "directory_entries_reconstructed": True, "outer_CRC32_recomputed": True,
              "authentication_field_preserved_unchanged": True, "encoder_controls": control_results,
              "encoder_executable_SHA256": hashlib.sha256(encoder.read_bytes()).hexdigest(),
              "components": rows, "modified_update_acceptance_established": False,
              "camera_accessed": False}
    # Create output only after complete byte equality; inputs are never written.
    out.mkdir(parents=True)
    (out / "G9-V27-roundtrip.bin").write_bytes(rebuilt)
    (out / "roundtrip-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--encoder", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = rebuild(args.input, args.decoded, args.encoder, args.out)
        print(json.dumps({k: v for k, v in report.items() if k != "components"}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
