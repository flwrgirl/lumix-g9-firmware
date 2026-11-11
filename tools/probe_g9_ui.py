# SPDX-License-Identifier: MIT
"""Probe real G9 UI-module code; this does not emulate the camera display.

Maps verified postboot code/data and OSD/font resources. Unknown accesses stop
execution. No OS, display, GPU, input, camera or storage service is stubbed.
"""
import argparse
from collections import deque
import ctypes
import hashlib
import json
from pathlib import Path
import struct

try:
    from .g9_emulator import G9Machine, EmulationFault
except ImportError:
    from g9_emulator import G9Machine, EmulationFault

ROOT = Path(__file__).resolve().parents[1]
ROM_MODULES = [("05_postboot1.bin", 0x06ba0000), ("06_postboot2.bin", 0x07020000),
               ("07_postboot3.bin", 0x07760000), ("08_postboot4.bin", 0x07780000),
               ("09_postboot5.bin", 0x077a0000)]
RESOURCE_MAP = [("16_osdover.bin", 0x41100000), ("17_osddata.bin", 0x07860000)]
NAMES = ["03_program.bin", *[n for n, _ in ROM_MODULES], *[n for n, _ in RESOURCE_MAP]]


def load_descriptor(raw, base):
    """Validate a LOAD copy/BSS descriptor before mapping its RAM."""
    if len(raw) < 28 or raw[:4] != b"LOAD":
        raise ValueError("Missing LOAD module descriptor")
    data_end, bss_end, data_start, repeated_end, source, source_end = struct.unpack_from("<6I", raw, 4)
    if (data_end != repeated_end or not 0x0a200000 <= data_start <= data_end <= bss_end <= 0x0b200000
            or not base + 28 <= source <= source_end <= base + len(raw)
            or data_end - data_start != source_end - source):
        raise ValueError("Invalid module copy/BSS bounds")
    return {"RAM_data_start": data_start, "RAM_data_end": data_end, "RAM_BSS_end": bss_end,
            "ROM_data_start": source, "ROM_data_end": source_end}


def read_components(directory):
    expected = json.loads((ROOT / "evidence/expected-components.json").read_text())
    records = {row["file"]: row for row in expected["sections"]}
    result = {}
    for name in NAMES:
        path = Path(directory) / name
        raw = path.read_bytes()
        if len(raw) != records[name]["bytes"] or hashlib.sha256(raw).hexdigest() != records[name]["SHA256"]:
            raise ValueError(f"Not the verified G9 component: {name}")
        result[name] = raw
    return result


def check_module_table(program, components):
    pointer = struct.unpack_from("<I", program, 0x062a5584 - 0x060a0000)[0]
    if pointer != 0x069272f0:
        raise ValueError("Unexpected postboot module table")
    result = []
    for index, (name, base) in enumerate(ROM_MODULES):
        source, destination, header, size = struct.unpack_from("<4I", program, pointer - 0x060a0000 + index * 16)
        if destination != base or header != base or size != len(components[name]):
            raise ValueError("Postboot load table disagrees with the selected map")
        result.append({"component": name, "storage_source": hex(source), "ROM_base": hex(base), "bytes": size,
                       "descriptor": {key: hex(value) for key, value in load_descriptor(components[name], base).items()}})
    return result


class UiProbeMachine(G9Machine):
    """UI-module memory preparation, without pretending to boot the camera OS."""
    def __init__(self, components):
        super().__init__(components["03_program.bin"], bytes(512))
        # OS helpers read privileged ARM CPU registers (including MPIDR).
        # Use a declared supervisor-mode/core-zero fixture, rather than
        # replacing those instructions or returning guessed OS values.
        self.engine.reg_write(self.arm.UC_ARM_REG_CPSR, 0x33)
        self.buffers = []
        self.blocks = deque(maxlen=24)
        self.module_map = check_module_table(components["03_program.bin"], components)
        main_ram = self.read(0x081a0000, 0x720000)
        self.engine.mem_unmap(0x081a0000, 0x720000)
        self._ram_alias(0x081a0000, 0x720000, main_ram)
        for name, base in ROM_MODULES:
            raw = components[name]
            self.engine.mem_map(base, len(raw), self.uc.UC_PROT_ALL)
            self.engine.mem_write(base, raw)
            self.engine.mem_protect(base, len(raw), self.uc.UC_PROT_READ | self.uc.UC_PROT_EXEC)
            descriptor = load_descriptor(raw, base)
            start, end = descriptor["RAM_data_start"], descriptor["RAM_BSS_end"]
            if start != end:
                size = ((end + 0xfff) & ~0xfff) - start
                initialized = raw[descriptor["ROM_data_start"]-base:descriptor["ROM_data_end"]-base]
                self._ram_alias(start, size, initialized)
        for name, base in RESOURCE_MAP:
            raw = components[name]
            self.engine.mem_map(base, len(raw), self.uc.UC_PROT_ALL)
            self.engine.mem_write(base, raw)
            self.engine.mem_protect(base, len(raw), self.uc.UC_PROT_READ)
        self._hook_handles.append(self.engine.hook_add(self.uc.UC_HOOK_BLOCK, self._block))

    def _ram_alias(self, start, size, initial):
        # The native LOAD routine at 0x062a54fc writes the 0x8... RAM alias.
        # Shared host storage keeps that alias and ordinary firmware pointers
        # coherent. This is a memory fixture, not a model of the camera MMU.
        if start & 0xfff or size & 0xfff or len(initial) > size:
            raise ValueError("Unaligned or oversized RAM fixture")
        buffer = ctypes.create_string_buffer(size)
        ctypes.memmove(ctypes.addressof(buffer), initial, len(initial))
        self.buffers.append(buffer)
        for address in (start, start + 0x80000000):
            self.engine.mem_map_ptr(address, size, self.uc.UC_PROT_READ | self.uc.UC_PROT_WRITE,
                                    ctypes.addressof(buffer))

    def _block(self, _engine, address, size, _user):
        self.blocks.append({"address": hex(address), "bytes": size})


def run_probe(directory):
    components = read_components(directory)
    machine = UiProbeMachine(components)
    descriptor, scratch = 0x20002000, 0x20003000
    controls = []
    for name, payload, address, expected in [
            ("release_font_resource", None, 0x41100000, 0),
            ("embedded_release_font", None, 0x06d404c4, 0),
            ("synthetic_BDF_type_control", b"STARTFONT 2.1\n", scratch, 1),
            ("synthetic_unknown_type_control", b"not a font file\0", scratch, 4),
            ("short_length_control", b"FDL Font", scratch, 4)]:
        if payload is not None:
            machine.engine.mem_write(scratch, payload)
        length = len(payload) if payload is not None else (len(components["16_osdover.bin"]) if address == 0x41100000 else 32)
        machine.engine.mem_write(descriptor, struct.pack("<II", address, length))
        actual = machine.call(0x06baa33a, descriptor, seconds=5)
        if actual != expected:
            raise ValueError(f"Native font-type control failed: {name}")
        controls.append({"case": name, "entry": "0x06baa33a", "native_return": actual, "expected_return": expected})

    attempts = []
    for name, address in [("native_font_system_initialization", 0x06bae078),
                          ("first_postboot1_task_candidate", 0x06ba0024)]:
        # Each attempt starts with fresh .data/BSS so earlier faults do not
        # manufacture initialized runtime state for a later experiment.
        candidate = UiProbeMachine(components)
        try:
            value = candidate.call(address, seconds=5)
            result = {"returned": hex(value), "stopped": False}
        except (EmulationFault, candidate.uc.UcError) as error:
            result = {"stopped": True, "fault": str(error)}
        attempts.append({"case": name, "entry": hex(address), **result,
                         "invalid_accesses": candidate.invalid_accesses,
                         "recent_native_basic_blocks": list(candidate.blocks),
                         "environment_stubs": candidate.environment_calls})
    return {"scope": "native UI-module probes; not a working UI emulator", "module_map": machine.module_map,
            "native_font_type_controls": controls, "native_font_type_controls_passed": True,
            "initialization_attempts": attempts, "camera_accessed": False,
            "OS_runtime_initialized": False, "graphics_hardware_emulated": False,
            "supervisor_mode_core_zero_fixture": True,
            "native_input_bridge_connected": False, "original_framebuffer_produced": False,
            "ROM_images_modified": False, "services_stubbed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory of the verified decoded release")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Report path already exists")
    report = run_probe(args.directory)
    with args.report.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2); handle.write("\n")
    print(json.dumps({"native_font_type_controls_passed": True, "original_framebuffer_produced": False,
                      "initialization_attempts": [{k: a[k] for k in ("case", "stopped", "invalid_accesses")} for a in report["initialization_attempts"]]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
