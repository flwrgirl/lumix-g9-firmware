# SPDX-License-Identifier: MIT
"""Firmware-free validation of the UI/QEMU probe's input and transport bounds."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import probe_g9_ui as ui
from tools import qemu_g9_probe as qemu


class ModuleDescriptorControls(unittest.TestCase):
    @staticmethod
    def fixture():
        raw = bytearray(4096)
        raw[:4] = b"LOAD"
        struct.pack_into("<6I", raw, 4, 0x0a280100, 0x0a281000, 0x0a280000,
                         0x0a280100, 0x06ba0100, 0x06ba0200)
        return raw

    def test_copy_source_size_and_bss_bounds_are_preserved(self):
        descriptor = ui.load_descriptor(self.fixture(), 0x06ba0000)
        self.assertEqual(descriptor["RAM_data_end"]-descriptor["RAM_data_start"],
                         descriptor["ROM_data_end"]-descriptor["ROM_data_start"])
        self.assertGreater(descriptor["RAM_BSS_end"], descriptor["RAM_data_end"])

    def test_bad_magic_lengths_and_out_of_module_copy_are_rejected(self):
        for offset, value in ((0, 0), (4, 0x0a280104), (8, 0x0a270000),
                              (12, 0x0a100000), (20, 0x06b90000), (24, 0x06bc0000)):
            raw = self.fixture()
            struct.pack_into("<I", raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                ui.load_descriptor(raw, 0x06ba0000)
        with self.assertRaises(ValueError):
            ui.load_descriptor(b"LOAD", 0x06ba0000)

    def test_unverified_images_never_start_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "03_program.bin").write_bytes(b"not firmware")
            with mock.patch.object(qemu.subprocess, "Popen") as spawn, mock.patch.object(qemu.subprocess, "run") as version:
                with self.assertRaisesRegex(ValueError, "verified G9 component"):
                    qemu.run(root / "qemu", root, root / "report.json")
                spawn.assert_not_called(); version.assert_not_called()
            self.assertFalse((root / "report.json").exists())


class GdbTransportControls(unittest.TestCase):
    def test_escaped_bytes_and_repeat_counts_decode_exactly(self):
        self.assertEqual(qemu.decode_rsp(b"a}]b"), b"a}b")
        self.assertEqual(qemu.decode_rsp(b"0* "), b"0000")
        self.assertEqual(qemu.decode_rsp(b"01234567"), b"01234567")

    def test_malformed_escape_and_repeat_encodings_fail(self):
        for raw in (b"}", b"* ", b"0*", b"0*\x1e"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                qemu.decode_rsp(raw)

    def test_host_writes_are_limited_to_fixture_scratch(self):
        pipe = qemu.GdbPipe.__new__(qemu.GdbPipe)
        pipe.command = mock.Mock(return_value=b"OK")
        for address, data in ((0x06baa33a, b"x"), (0, b"x"), (0x010fffff, b"xx"), (0x01000000, b"x"*4097)):
            with self.assertRaises(ValueError):
                pipe.write(address, data)
        pipe.command.assert_not_called()
        pipe.write(0x01002000, b"fixture")
        pipe.command.assert_called_once()

    def test_qemu_fixture_attaches_no_host_devices_or_network_listener(self):
        command = qemu.qemu_command(Path("qemu-system-arm"), Path("decoded"))
        self.assertEqual(command[command.index("-machine")+1], "none")
        self.assertEqual(command[command.index("-gdb")+1], "stdio")
        self.assertEqual(command[command.index("-nic")+1], "none")
        self.assertIn("-nodefaults", command)
        self.assertEqual(command[command.index("-display")+1], "none")
        for option in ("-drive", "-netdev", "-usb", "-s"):
            self.assertNotIn(option, command)


if __name__ == "__main__":
    unittest.main()
