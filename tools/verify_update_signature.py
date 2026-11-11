# SPDX-License-Identifier: MIT
"""Read-only verification of the pinned G9 update-directory signature.

Public-key verification only. No private key, signing operation or camera access.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

try:
    from .roundtrip_g9_v27 import read_image
except ImportError:
    from roundtrip_g9_v27 import read_image

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
PROGRAM_SHA256 = "76e83497c7ae11d9b1e1fe56a3bf11be6931709667b454503e272d5e4f8dd324"
KEY_SHA256 = "3586201218ceed68666470175aea0f6011a22c0be265cff6aa5de7012d81d1a3"
KEY_OFFSET = 0x887e62
PROFILE_OFFSET = 0x887ea4
PROGRAM_BASE = 0x60a0000


def point_add(a, c):
    if a is None:
        return c
    if c is None:
        return a
    x, y = a
    u, v = c
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if a == c
             else (v - y) * pow(u - x, -1, P)) % P
    q = (slope * slope - x - u) % P
    return q, (slope * (x - q) - y) % P


def point_multiply(k, point):
    out = None
    while k:
        if k & 1:
            out = point_add(out, point)
        point = point_add(point, point)
        k >>= 1
    return out


def verify_digest(digest, signature, public_key):
    """G9 raw fields: little-endian x/y, r/s and hash-as-integer."""
    if len(digest) != 32 or len(signature) != 64 or len(public_key) != 64:
        return False
    q = tuple(int.from_bytes(public_key[i:i + 32], "little") for i in (0, 32))
    if not all(0 <= v < P for v in q) or (q[1] ** 2 - q[0] ** 3 + 3 * q[0] - B) % P:
        return False
    r, s = (int.from_bytes(signature[i:i + 32], "little") for i in (0, 32))
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    result = point_add(point_multiply(int.from_bytes(digest, "little") * w % N, G),
                       point_multiply(r * w % N, q))
    return result is not None and result[0] % N == r


def signature_der(signature):
    parts = []
    for part in (signature[:32], signature[32:]):
        raw = int.from_bytes(part, "little").to_bytes(32, "big").lstrip(b"\0") or b"\0"
        if raw[0] & 0x80:
            raw = b"\0" + raw
        parts.append(b"\x02" + bytes([len(raw)]) + raw)
    body = b"".join(parts)
    return b"\x30" + bytes([len(body)]) + body


def openssl_check(executable, digest, signature, key):
    # Encode the public point as standard id-ecPublicKey / prime256v1 SPKI.
    der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    der += key[:32][::-1] + key[32:][::-1]
    encoded = base64.b64encode(der).decode("ascii")
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64))
    pem += "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="g9-signature-") as directory:
        root = Path(directory)
        (root / "public.pem").write_text(pem, encoding="ascii")
        (root / "signature.der").write_bytes(signature_der(signature))
        # Prehashed input is reversed to present G9's little-endian integer to OpenSSL.
        (root / "digest.bin").write_bytes(digest[::-1])
        result = subprocess.run([str(executable), "pkeyutl", "-verify", "-pubin",
                                 "-inkey", str(root / "public.pem"), "-sigfile", str(root / "signature.der"),
                                 "-in", str(root / "digest.bin"), "-pkeyopt", "digest:sha256"],
                                capture_output=True, timeout=30)
        return result.returncode == 0


def verify_release(input_path, program_path, openssl=None):
    image = read_image(input_path)
    program = Path(program_path).read_bytes()
    if hashlib.sha256(program).hexdigest() != PROGRAM_SHA256:
        raise ValueError("Not the verified G9 main program")
    key = program[KEY_OFFSET:KEY_OFFSET + 64]
    if hashlib.sha256(key).hexdigest() != KEY_SHA256:
        raise ValueError("Unexpected G9 public key")
    if struct.unpack_from("<II", program, PROFILE_OFFSET + 0x54) != (64, PROGRAM_BASE + KEY_OFFSET):
        raise ValueError("Public-key profile fields differ")
    count = struct.unpack_from("<I", image, 0x2e8)[0]
    end = 0x2ec + count * 0x5c
    directory = image[0x2a0:end]
    digest = hashlib.sha256(directory).digest()
    signature = image[0x220:0x260]
    changed_directory = bytearray(directory)
    changed_directory[0x2ec - 0x2a0 + 0x1c] ^= 1  # First component's signed plaintext hash.
    changed_digest = hashlib.sha256(changed_directory).digest()
    changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
    valid = verify_digest(digest, signature, key)
    controls = {"changed_directory_hash_rejected": not verify_digest(changed_digest, signature, key),
                "changed_signature_rejected": not verify_digest(digest, changed_signature, key),
                "wrong_hash_byte_order_rejected": not verify_digest(digest[::-1], signature, key)}
    if not valid or not all(controls.values()):
        raise ValueError("ECDSA verification or negative controls failed")
    report = {"scope": "mathematical G9 release-directory authentication; not hardware acceptance",
              "algorithm": "ECDSA P-256 / SHA-256; raw coordinates, r, s and digest integer little endian",
              "input_BIN_SHA256": hashlib.sha256(image).hexdigest(),
              "public_key": {"component": "program", "component_offset": hex(KEY_OFFSET),
                             "CPU_address": hex(PROGRAM_BASE + KEY_OFFSET), "bytes": 64, "SHA256": KEY_SHA256,
                             "profile_CPU_address": hex(PROGRAM_BASE + PROFILE_OFFSET)},
              "directory": {"start": "0x2a0", "end_exclusive": hex(end), "bytes": end - 0x2a0,
                            "component_count": count, "SHA256": digest.hex()},
              "signature": {"offset": "0x220", "bytes": 64, "SHA256": hashlib.sha256(signature).hexdigest()},
              "independent_math_valid": valid, "controls": controls,
              "modified_update_acceptance_established": False, "camera_accessed": False}
    if openssl is not None:
        executable = Path(openssl).resolve(strict=True)
        independent = {"valid": openssl_check(executable, digest, signature, key),
                       "changed_hash_rejected": not openssl_check(executable, changed_digest, signature, key),
                       "changed_signature_rejected": not openssl_check(executable, digest, changed_signature, key)}
        if not all(independent.values()):
            raise ValueError("Independent OpenSSL verification controls failed")
        version = subprocess.run([str(executable), "version"], check=True, capture_output=True, text=True).stdout.strip()
        report["OpenSSL"] = {"version": version, **independent}
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("program", type=Path)
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--report", type=Path, help="New report file; existing files are refused")
    args = parser.parse_args()
    try:
        if args.report and args.report.exists():
            raise ValueError("Report path already exists")
        report = verify_release(args.input, args.program, args.openssl)
        output = json.dumps(report, indent=2) + "\n"
        if args.report:
            with args.report.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(output)
        print(output, end="")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
