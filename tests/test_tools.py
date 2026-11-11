# SPDX-License-Identifier: MIT
"""Firmware-free controls and publication/input-boundary checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from tools import audit_publication, decode_g9_v27, inspect_g9_upd, verify_decoded

ROOT = Path(__file__).resolve().parents[1]


class CipherControls(unittest.TestCase):
    def test_nist_standard_aes128_block(self):
        actual = decode_g9_v27.decrypt_ecb(
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"), 10,
        ).tobytes()
        self.assertEqual(actual.hex(), "00112233445566778899aabbccddeeff")

    def test_independent_gm1_reduced_round_control(self):
        actual = decode_g9_v27.decrypt_ecb(
            bytes.fromhex("147069b0d8d7a35b439688d2b8e59278"),
            bytes.fromhex("350481b566d22d5b89dc46775e644622"), 5,
        ).tobytes()
        self.assertEqual(actual.hex(), "cd6a60a6c34c6893a76ad12db4d8bdf2")

    def test_multiblock_standard_control(self):
        cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a") * 3
        actual = decode_g9_v27.decrypt_ecb(cipher, bytes(range(16)), 10).tobytes()
        self.assertEqual(actual, bytes.fromhex("00112233445566778899aabbccddeeff") * 3)


class FileBoundaries(unittest.TestCase):
    def test_wrong_input_creates_no_output_even_optimized(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            original = base / "wrong-input.bin"
            original.write_bytes(b"not a G9 update")
            for i, flags in enumerate(([], ["-O"])):
                out = base / f"output-{i}"
                result = subprocess.run(
                    [sys.executable, *flags, str(ROOT / "tools/decode_g9_v27.py"), str(original), "--out", str(out)],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Not the pinned G9 V2.7 input", result.stderr)
                self.assertFalse(out.exists())
            self.assertEqual(original.read_bytes(), b"not a G9 update")

    def test_unexpected_zip_member_size_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / "sample.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("G9___V27.bin", b"not firmware")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/decode_g9_v27.py"), str(archive), "--out", str(base / "out")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unexpected uncompressed firmware size", result.stderr)
            self.assertFalse((base / "out").exists())

    def test_inspector_never_overwrites_input_or_different_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            original, target = base / "original", base / "report"
            original.write_bytes(b"original")
            target.write_bytes(b"existing")
            with self.assertRaises(ValueError):
                inspect_g9_upd.write_new_or_identical(original, b"changed", original)
            with self.assertRaises(ValueError):
                inspect_g9_upd.write_new_or_identical(target, b"changed", original)
            self.assertEqual(original.read_bytes(), b"original")
            self.assertEqual(target.read_bytes(), b"existing")

    def test_incomplete_decoded_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Missing or invalid component"):
                verify_decoded.verify(directory)


class PublicationChecks(unittest.TestCase):
    def test_expected_manifest_is_complete_and_consistent(self):
        data = json.loads((ROOT / "evidence/expected-components.json").read_text())
        self.assertEqual(len(data["sections"]), 49)
        self.assertEqual(sum(s["flags"] == 3 for s in data["sections"]), 45)
        self.assertEqual(data["input_SHA256"], decode_g9_v27.IMAGE_SHA256)
        self.assertEqual(data["key_hex"], decode_g9_v27.KEY.hex())
        self.assertTrue(all(s["matches_directory"] for s in data["sections"]))

    def test_publication_audit_rejects_capture_and_personal_path(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "capture.raw").write_bytes(b"\0\x01")
            self.assertTrue(audit_publication.inspect_file(base, Path("capture.raw")))
            home_path = "C" + ":" + chr(92) + "Users" + chr(92) + "Example" + chr(92) + "file"
            (base / "README.md").write_text(home_path)
            self.assertIn("machine-specific Windows home path", audit_publication.inspect_file(base, Path("README.md")))
            (base / "README.md").write_text("Source-only research notes.\n")
            self.assertEqual(audit_publication.inspect_file(base, Path("README.md")), [])


if __name__ == "__main__":
    unittest.main()
