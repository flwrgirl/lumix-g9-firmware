# SPDX-License-Identifier: MIT
"""Independent cipher/signature vectors and packaging input boundaries."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from tools import roundtrip_g9_v27 as package
from tools import verify_update_signature as signature


@unittest.skipUnless(os.environ.get("G9_CBC_ENCODER"), "Set G9_CBC_ENCODER to the compiled host encoder")
class NativeCipherControls(unittest.TestCase):
    def test_standard_reduced_and_streaming_vectors(self):
        self.assertTrue(all(package.controls(Path(os.environ["G9_CBC_ENCODER"])).values()))

    def test_encoder_rejects_truncated_block_and_invalid_arguments(self):
        executable = os.environ["G9_CBC_ENCODER"]
        for key, iv, rounds, data in [("00" * 16, "00" * 16, "5", b"short"),
                                      ("xx" * 16, "00" * 16, "5", b""),
                                      ("00" * 16, "00" * 16, "6", b"")]:
            with self.subTest(key=key, rounds=rounds):
                result = subprocess.run([executable, key, iv, rounds], input=data, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_empty_input_remains_empty_without_padding(self):
        self.assertEqual(package.encode(os.environ["G9_CBC_ENCODER"], b"", bytes(16), bytes(16)), b"")


class PackagingBoundaries(unittest.TestCase):
    def test_wrong_input_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "wrong.bin"
            original.write_bytes(b"not firmware")
            out = root / "out"
            with self.assertRaisesRegex(ValueError, "Not the pinned"):
                package.rebuild(original, root / "missing", root / "missing-encoder", out)
            self.assertFalse(out.exists())
            self.assertEqual(original.read_bytes(), b"not firmware")

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "keep"
            marker.write_text("keep")
            with self.assertRaisesRegex(ValueError, "directory must be new"):
                package.rebuild(root / "missing", root / "missing", root / "missing", root)
            self.assertEqual(marker.read_text(), "keep")

    def test_bad_zip_member_size_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("G9___V27.bin", b"too short")
            with self.assertRaisesRegex(ValueError, "uncompressed firmware size"):
                package.read_image(path)


class SignatureControls(unittest.TestCase):
    @staticmethod
    def vector():
        # RFC 6979 A.2.5, P-256 / SHA-256 / message "sample". Public values only.
        coordinates = ["60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                       "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"]
        scalars = ["EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                   "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"]
        key = b"".join(int(v, 16).to_bytes(32, "little") for v in coordinates)
        raw = b"".join(int(v, 16).to_bytes(32, "little") for v in scalars)
        return hashlib.sha256(b"sample").digest()[::-1], raw, key

    def test_independent_p256_known_answer(self):
        self.assertTrue(signature.verify_digest(*self.vector()))

    def test_modified_digest_signature_and_wrong_endian_fail(self):
        digest, raw, key = self.vector()
        self.assertFalse(signature.verify_digest(bytes([digest[0] ^ 1]) + digest[1:], raw, key))
        self.assertFalse(signature.verify_digest(digest, bytes([raw[0] ^ 1]) + raw[1:], key))
        self.assertFalse(signature.verify_digest(digest[::-1], raw, key))

    def test_bad_points_scalars_and_lengths_fail(self):
        digest, raw, key = self.vector()
        for candidate_digest, candidate_raw, candidate_key in [(digest, raw, bytes(64)),
                (digest, raw, b"\xff" * 64), (digest, bytes(64), key),
                (digest, signature.N.to_bytes(32, "little") + raw[32:], key),
                (digest[:-1], raw, key), (digest, raw[:-1], key), (digest, raw, key[:-1])]:
            self.assertFalse(signature.verify_digest(candidate_digest, candidate_raw, candidate_key))


if __name__ == "__main__":
    unittest.main()
