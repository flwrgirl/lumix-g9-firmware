# SPDX-License-Identifier: MIT
"""Logical storage model for updater tests; not a G9 chip/controller model."""
import hashlib


class ProtectedWrite(RuntimeError):
    pass


class SimulatedPowerCut(RuntimeError):
    pass


class LogicalFlash:
    """Separate logical slots, with explicit assumptions about preparation/writes.

    No filenames, device handles, physical addresses or recovery/boot behavior.
    """
    SECTOR = 512

    def __init__(self, program_bytes, interrupt_after_sectors=None, fail_write=False):
        if not 512 <= program_bytes <= 11534336 or program_bytes % self.SECTOR:
            raise ValueError("Invalid logical program-slot size")
        if interrupt_after_sectors is not None and interrupt_after_sectors < 0:
            raise ValueError("Negative interruption point")
        self.slots = {"bootloaders": bytearray(b"BOOT-GUARD" * 64),
                      "calibration": bytearray(b"CALIBRATION-GUARD" * 64),
                      "program": bytearray(b"\x55" * program_bytes)}
        self.protected = {"bootloaders", "calibration"}
        self.initial_protected = {name: hashlib.sha256(self.slots[name]).hexdigest() for name in self.protected}
        self.interrupt_after_sectors, self.fail_write = interrupt_after_sectors, fail_write
        self.events, self.sectors_written = [], 0

    def _writable(self, region):
        if region not in self.slots:
            raise ValueError("Unknown logical storage region")
        if region in self.protected:
            self.events.append({"operation": "protected_write_blocked", "region": region})
            raise ProtectedWrite("Blocked a request to program " + region)

    def prepare_program(self, raw_arguments):
        self._writable("program")
        # Explicit model assumption: the native prepare service erases this slot.
        # Its true hardware erase scope and partition mapping remain unverified.
        self.slots["program"][:] = b"\xff" * len(self.slots["program"])
        self.events.append({"operation": "prepare_program_modeled_as_erase", "region": "program",
                            "raw_native_arguments": [hex(v) for v in raw_arguments]})

    def write_program(self, data):
        return self.write("program", data)

    def write(self, region, data):
        self._writable(region)
        if len(data) != len(self.slots[region]) or len(data) % self.SECTOR:
            raise ValueError("Program data does not fit the logical slot")
        if self.fail_write:
            self.events.append({"operation": "injected_write_error", "region": "program"})
            return False
        for at in range(0, len(data), self.SECTOR):
            if self.interrupt_after_sectors is not None and self.sectors_written >= self.interrupt_after_sectors:
                self.events.append({"operation": "simulated_power_cut", "sectors_written": self.sectors_written})
                raise SimulatedPowerCut("Simulated interruption during logical program write")
            self.slots[region][at:at + self.SECTOR] = data[at:at + self.SECTOR]
            self.sectors_written += 1
        self.events.append({"operation": "program_write_completed", "bytes": len(data),
                            "sectors_written": self.sectors_written,
                            "SHA256": hashlib.sha256(data).hexdigest()})
        return True

    def protect_bootstrap(self):
        self._writable("bootloaders")

    def summary(self, candidate=None):
        protected_intact = all(hashlib.sha256(self.slots[name]).hexdigest() == expected
                               for name, expected in self.initial_protected.items())
        return {"model": "logical slots; physical partition/erase behavior unverified",
                "protected_region_canaries_intact": protected_intact,
                "program_SHA256": hashlib.sha256(self.slots["program"]).hexdigest(),
                "program_matches_candidate": bytes(self.slots["program"]) == candidate if candidate is not None else None,
                "sectors_written": self.sectors_written, "events": self.events,
                "boot_or_recovery_emulated": False}
