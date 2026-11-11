# SPDX-License-Identifier: MIT
"""Firmware-free controls for protection, partial writes and emulator fixtures."""
import hashlib
import struct
import unittest
import zlib

from tools.emulate_install_job import program_fixture
from tools.emulate_update_decoder import small_unsigned_fixture
from tools.g9_emulator import G9Machine
from tools.virtual_flash import LogicalFlash, ProtectedWrite, SimulatedPowerCut


class LogicalStorageControls(unittest.TestCase):
    def test_boot_and_calibration_writes_are_blocked_without_mutation(self):
        storage = LogicalFlash(8192)
        for name in ("bootloaders", "calibration"):
            before = bytes(storage.slots[name])
            with self.assertRaises(ProtectedWrite):
                storage.write(name, b"changed")
            self.assertEqual(bytes(storage.slots[name]), before)
        self.assertTrue(storage.summary()["protected_region_canaries_intact"])

    def test_complete_program_write_matches_candidate(self):
        storage = LogicalFlash(8192)
        candidate = bytes(range(256)) * 32
        storage.prepare_program([0, 110])
        self.assertTrue(storage.write_program(candidate))
        report = storage.summary(candidate)
        self.assertTrue(report["program_matches_candidate"])
        self.assertEqual(report["sectors_written"], 16)
        self.assertTrue(report["protected_region_canaries_intact"])
        self.assertFalse(report["boot_or_recovery_emulated"])

    def test_interruption_leaves_partial_image_and_no_rollback(self):
        storage = LogicalFlash(8192, interrupt_after_sectors=2)
        candidate = b"\xa5" * 8192
        storage.prepare_program([0, 110])
        with self.assertRaises(SimulatedPowerCut):
            storage.write_program(candidate)
        self.assertEqual(storage.slots["program"][:1024], candidate[:1024])
        self.assertEqual(storage.slots["program"][1024:], b"\xff" * (8192 - 1024))
        self.assertFalse(storage.summary(candidate)["program_matches_candidate"])
        self.assertTrue(storage.summary()["protected_region_canaries_intact"])

    def test_reported_write_error_commits_no_candidate_sectors(self):
        storage = LogicalFlash(8192, fail_write=True)
        storage.prepare_program([0, 110])
        self.assertFalse(storage.write_program(b"\xa5" * 8192))
        self.assertEqual(storage.sectors_written, 0)
        self.assertEqual(storage.slots["program"], b"\xff" * 8192)

    def test_length_mismatch_does_not_modify_storage(self):
        storage = LogicalFlash(8192)
        before = bytes(storage.slots["program"])
        with self.assertRaises(ValueError):
            storage.write_program(b"\xa5" * 512)
        self.assertEqual(storage.slots["program"], before)

    def test_bad_slot_sizes_and_interruption_points_are_rejected(self):
        for size in (0, 513, 11534336 + 512):
            with self.assertRaises(ValueError):
                LogicalFlash(size)
        with self.assertRaises(ValueError):
            LogicalFlash(8192, interrupt_after_sectors=-1)


class FixtureControls(unittest.TestCase):
    @staticmethod
    def template():
        image = bytearray(0x2600)
        image[:4] = b"UPD\0"
        return image

    def test_program_data_fixture_records_and_crc_are_consistent(self):
        template = self.template()
        before = bytes(template)
        data = bytes(range(256)) * 32
        image = program_fixture(template, data)
        self.assertEqual(template, before)
        self.assertEqual(image[0x1600:], data)
        self.assertEqual(struct.unpack_from("<I", image, 0x2e8)[0], 1)
        self.assertEqual(image[0x2ec:0x2f8], b"program".ljust(12, b"\0"))
        self.assertEqual(image[0x2ec + 28:0x2ec + 60], hashlib.sha256(data).digest())
        self.assertEqual(image[0x2a0:0x2e0], image[:0x40])
        self.assertEqual(struct.unpack_from("<I", image, 0x40)[0], zlib.crc32(image[0x200:]) & 0xffffffff)

    def test_small_unsigned_fixture_is_in_memory_and_checksized(self):
        original = self.template()
        before = bytes(original)
        image = small_unsigned_fixture(original)
        self.assertEqual(original, before)
        self.assertEqual(len(image), 0x2600)
        self.assertEqual(image[0x200], 0)
        self.assertEqual(struct.unpack_from("<I", image, 0x3c)[0], len(image) - 0x200)
        with self.assertRaises(ValueError):
            program_fixture(original, b"short")

    def test_wrong_program_is_rejected_before_loading_emulator(self):
        with self.assertRaisesRegex(ValueError, "verified G9 main program"):
            G9Machine(b"not firmware", bytes(512))


if __name__ == "__main__":
    unittest.main()
