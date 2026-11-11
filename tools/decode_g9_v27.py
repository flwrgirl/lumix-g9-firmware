# SPDX-License-Identifier: MIT
"""Decode the exact Panasonic DC-G9 V2.7 update; validate every component.

Requires Python 3 and numpy. Reads a pinned ZIP/BIN, writes a NEW directory.
No USB, camera commands, repacking, firmware modification, or installation.
The key was recovered from this G9's read-only memory capture and validated by
the complete 49152-byte loader3 SHA-256, not merely plausible instructions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib
import numpy as np

IMAGE_SHA256 = "9316958735c19fa0a04415c75faf97edff9be042a42c115ac1622d6c6379e7c3"
KEY = bytes.fromhex("e30b70e1bdc61dacc7057545d85d0b1d")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def multiply(a, b):
    value = 0
    for _ in range(8):
        if b & 1:
            value ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return value


def rotate(a, n):
    return ((a << n) | (a >> (8 - n))) & 255


def sbox_entry(a):
    inv = 1 if a else 0
    for _ in range(254):
        inv = multiply(inv, a)
    return inv ^ rotate(inv, 1) ^ rotate(inv, 2) ^ rotate(inv, 3) ^ rotate(inv, 4) ^ 0x63


SBOX = np.array([sbox_entry(a) for a in range(256)], dtype=np.uint8)
INV = np.argsort(SBOX).astype(np.uint8)
MUL = {n: np.array([multiply(a, n) for a in range(256)], dtype=np.uint8) for n in (9, 11, 13, 14)}
SHIFT = np.array([(i + 16 - 4 * (i % 4)) % 16 for i in range(16)])


def schedule(key, rounds):
    out = np.zeros(16 * (rounds + 1), dtype=np.uint8)
    out[:16] = np.frombuffer(key, dtype=np.uint8)
    rc = 1
    for p in range(16, len(out), 4):
        temp = out[p - 4:p].copy()
        if p % 16 == 0:
            temp = SBOX[np.roll(temp, -1)]
            temp[0] ^= rc
            rc = multiply(rc, 2)
        out[p:p + 4] = out[p - 16:p - 12] ^ temp
    return out


def decrypt_ecb(data, key, rounds):
    blocks = np.frombuffer(data, dtype=np.uint8).reshape(-1, 16)
    rk = schedule(key, rounds)
    state = blocks ^ rk[16 * rounds:16 * (rounds + 1)]
    for r in range(rounds - 1, -1, -1):
        temp = INV[state[:, SHIFT]] ^ rk[16 * r:16 * (r + 1)]
        if r == 0:
            state = temp
        else:
            cols = temp.reshape(-1, 4, 4)
            state = (MUL[14][cols] ^ MUL[11][np.roll(cols, -1, axis=2)]
                     ^ MUL[13][np.roll(cols, -2, axis=2)]
                     ^ MUL[9][np.roll(cols, -3, axis=2)]).reshape(-1, 16)
    return state


def decode(data, iv):
    blocks = np.frombuffer(data, dtype=np.uint8).reshape(-1, 16)
    plain = decrypt_ecb(data, KEY, 5)
    plain ^= np.vstack((np.frombuffer(iv, dtype=np.uint8), blocks[:-1]))
    return plain.tobytes()


def controls():
    tests = [
        (10, "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a", "00112233445566778899aabbccddeeff"),
        (5, "350481b566d22d5b89dc46775e644622", "147069b0d8d7a35b439688d2b8e59278", "cd6a60a6c34c6893a76ad12db4d8bdf2"),
    ]
    for rounds, key, cipher, expected in tests:
        require(decrypt_ecb(bytes.fromhex(cipher), bytes.fromhex(key), rounds).tobytes().hex() == expected, "AES positive control failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="A new directory; existing directories are refused")
    args = parser.parse_args()
    controls()
    if zipfile.is_zipfile(args.input):
        with zipfile.ZipFile(args.input) as archive:
            require(archive.namelist() == ["G9___V27.bin"], "Unexpected archive contents")
            require(archive.getinfo("G9___V27.bin").file_size == 81952256,
                    "Unexpected uncompressed firmware size")
            image = archive.read("G9___V27.bin")
    else:
        image = args.input.read_bytes()
    require(len(image) == 81952256 and hashlib.sha256(image).hexdigest() == IMAGE_SHA256, "Not the pinned G9 V2.7 input")
    require(image[:4] == b"UPD\0" and struct.unpack_from("<I", image, 0x2e8)[0] == 49, "Unexpected image structure")
    require(zlib.crc32(image[0x200:]) & 0xffffffff == struct.unpack_from("<I", image, 0x40)[0], "UPD CRC32 mismatch")
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for index in range(49):
        entry = 0x2ec + index * 0x5c
        name = image[entry:entry + 12].rstrip(b"\0").decode("ascii")
        require(name and all(c.isascii() and (c.isalnum() or c == "_") for c in name), "Invalid section name")
        relative, size, destination, flags = struct.unpack_from("<IIII", image, entry + 12)
        offset = relative + 0x200
        require(0x1600 <= offset <= len(image) and offset + size <= len(image), "Invalid section bounds")
        expected = image[entry + 28:entry + 60].hex()
        iv = image[entry + 60:entry + 76]
        raw = image[offset:offset + size]
        require(flags in (2, 3), "Unsupported section flags")
        plain = decode(raw, iv) if flags == 3 and size else raw
        actual = hashlib.sha256(plain).hexdigest()
        require(actual == expected, f"Decoded component digest mismatch: {name}")
        target = args.out / f"{index:02d}_{name}.bin"
        target.write_bytes(plain)
        row = {"index": index, "name": name, "file": target.name, "bytes": size,
               "flags": flags, "SHA256": actual, "matches_directory": True,
               "directory_destination_field": hex(destination), "CBC_IV": iv.hex() if flags == 3 else None}
        rows.append(row)
        print(json.dumps({"component": name, "bytes": size, "verified": True}), flush=True)
    report = {"model": "Panasonic DC-G9", "firmware": "2.7", "input_SHA256": IMAGE_SHA256,
              "cipher": "AES-128-CBC with five rounds; standard AES key expansion truncated to five rounds",
              "key_hex": KEY.hex(), "IV_source": "16 bytes at directory entry offset 0x3c",
              "padding": "No padding removed; whole declared components are hashed",
              "sections": rows, "all_component_SHA256_values_match": True,
              "limits": ["This recovers compiled firmware, not original source code or original symbols.",
                         "Decryption does not establish signature bypass, a flashing method, or brick recovery.",
                         "No modified or re-encrypted update is produced."]}
    (args.out / "decoded-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"verified_components": len(rows), "output_directory": str(args.out)}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
