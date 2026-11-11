# SPDX-License-Identifier: MIT
"""Firmware-free checks for wrong architecture, entry state and dependencies."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from tools import audit_publication, build_probe


def example_elf(mode="arm", extra=None):
    """Synthetic headers only; no vendor firmware or executable test payload."""
    text = b"\0" * 12
    names = b"\0.text\0.shstrtab\0.data\0.rel.text\0"
    shoff = (52 + len(text) + len(names) + 3) & ~3
    sections = [(0,) * 10,
                (1, 1, 6, 0x10000, 52, len(text), 0, 0, 4, 0),
                (7, 3, 0, 0, 52 + len(text), len(names), 0, 0, 1, 0)]
    if extra:
        sections.append(extra)
    data = bytearray(shoff + 40 * len(sections))
    data[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 40, 1,
                     0x10000 + (mode == "thumb"), 0, shoff, 0x5000200,
                     52, 0, 0, 40, len(sections), 2)
    data[52:52 + len(text)] = text
    data[52 + len(text):52 + len(text) + len(names)] = names
    for index, section in enumerate(sections):
        struct.pack_into("<IIIIIIIIII", data, shoff + index * 40, *section)
    return data


class BuildBoundaryChecks(unittest.TestCase):
    def test_wrong_architecture_entry_or_float_abi_is_rejected(self):
        for offset, format_, value in [(18, "<H", 62), (24, "<I", 0x10001), (36, "<I", 0x5000400)]:
            with self.subTest(offset=offset):
                data = example_elf()
                struct.pack_into(format_, data, offset, value)
                with self.assertRaises(ValueError):
                    build_probe.inspect_elf(data, "arm")
        metadata, _ = build_probe.inspect_elf(example_elf("thumb"), "thumb")
        self.assertEqual(metadata["entry"], "0x10001")

    def test_runtime_data_and_relocations_are_rejected(self):
        for extra in [(17, 8, 3, 0x10010, 0, 4, 0, 0, 4, 0),
                      (23, 9, 0, 0, 52, 8, 0, 1, 4, 8)]:
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    build_probe.inspect_elf(example_elf(extra=extra), "arm")
        with self.assertRaises(ValueError):
            build_probe.inspect_elf(example_elf()[:-1], "arm")

    def test_existing_build_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "keep.txt"
            marker.write_text("keep")
            with self.assertRaisesRegex(ValueError, "directory must be new"):
                build_probe.build(sys.executable, directory)
            self.assertEqual(marker.read_text(), "keep")

    def test_compiler_artifact_is_rejected_even_if_printable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "tools" / "probe.elf"
            target.parent.mkdir()
            target.write_text("not a source file")
            self.assertIn("binary, firmware, capture or generated artifact extension",
                          audit_publication.inspect_file(directory, Path("tools/probe.elf")))


if __name__ == "__main__":
    unittest.main()
