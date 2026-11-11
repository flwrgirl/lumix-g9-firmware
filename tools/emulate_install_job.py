# SPDX-License-Identifier: MIT
"""Native G9 install decisions with modeled environment/storage gateways.

The original release is stopped at its first protected bootstrap write request.
Small data-only fixtures exercise logical program writes and injected failures.
No fixture is exported and no device is accessed. This is not a boot emulator.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

try:
    from .g9_emulator import G9Machine
    from .emulate_update_decoder import repair_crc
    from .roundtrip_g9_v27 import read_image
    from .virtual_flash import LogicalFlash, ProtectedWrite, SimulatedPowerCut
except ImportError:
    from g9_emulator import G9Machine
    from emulate_update_decoder import repair_crc
    from roundtrip_g9_v27 import read_image
    from virtual_flash import LogicalFlash, ProtectedWrite, SimulatedPowerCut


ENVIRONMENT = {
    0x0636a2c8: "board_status_fixture", 0x0646a8a0: "cache_and_OS_fixture",
    0x06295ff4: "peripheral_pause_fixture", 0x06233d34: "calibration_merge_fixture",
    0x06233fc4: "activation_merge_fixture", 0x063f68b4: "delay_fixture",
}


def program_fixture(original, data):
    """Synthetic nonbootable data as a single clear program entry, RAM only."""
    if len(data) < 1024 or len(data) % 512:
        raise ValueError("Fixture payload must be sector-aligned and at least 1 KiB")
    image = bytearray(original[:0x1600])
    image.extend(data)
    struct.pack_into("<I", image, 0x3c, len(image) - 0x200)
    image[0x2a0:0x2e0] = image[:0x40]
    struct.pack_into("<I", image, 0x2e8, 1)
    record = b"program".ljust(12, b"\0") + struct.pack("<IIII", 0x1400, len(data), 0x80000, 2)
    record += hashlib.sha256(data).digest() + bytes(32)
    image[0x2ec:0x2ec + 0x5c] = record
    image[0x200] = 0
    repair_crc(image)
    return image


def run_job(program, image, program_bytes, policy_fixture=False, interrupt=None, fail_write=False, progress=None):
    machine = G9Machine(program, image, image_address=0xb0000000, progress=progress)
    storage = LogicalFlash(program_bytes, interrupt_after_sectors=interrupt, fail_write=fail_write)
    if policy_fixture:
        # Changes emulated RAM only; not an instruction or camera operation.
        machine.engine.mem_write(0x081c3444, b"\0")
    for address, name in ENVIRONMENT.items():
        machine.hook_service(address, name, lambda *_: 0)
    machine.hook_service(0x0622d5e2, "charger_preflight_ready_fixture", lambda *_: 1)

    def bootstrap(m, args, event):
        sp = m.engine.reg_read(m.arm.UC_ARM_REG_SP)
        event["stack_arguments"] = [hex(m.word(sp)), hex(m.word(sp + 4))]
        rows = []
        count = struct.unpack_from("<I", image, 0x2e8)[0]
        for index in range(count):
            entry = 0x2ec + index * 0x5c
            name = image[entry:entry + 12].rstrip(b"\0").decode("ascii")
            if name not in ("loader1", "loader2", "loader3"):
                continue
            relative, size = struct.unpack_from("<II", image, entry + 12)
            actual = hashlib.sha256(m.read(m.image_address + 0x200 + relative, size)).hexdigest()
            rows.append({"name": name, "bytes": size, "matches_unchanged_release": actual == image[entry + 28:entry + 60].hex()})
        event["bootloader_payloads"] = rows
        storage.protect_bootstrap()
        return 0

    def prepare(_m, args, event):
        storage.prepare_program(args[:2])
        event["model_assumption"] = "prepare erases logical program slot; physical mapping unverified"
        return 0

    written_payload = []
    def write(m, args, event):
        size, pointer = args[:2]
        if size != program_bytes:
            raise ValueError("Unexpected native program write size")
        data = m.read(pointer, size)
        event["payload_bytes"], event["payload_SHA256"] = len(data), hashlib.sha256(data).hexdigest()
        written_payload.append(data)
        return 0 if storage.write_program(data) else 0xffffffff

    def unexpected(_m, _args, _event):
        raise ProtectedWrite("Unmodeled secondary-component storage write")

    machine.hook_service(0x064511dc, "protected_bootstrap_program_request", bootstrap)
    machine.hook_service(0x06451116, "logical_program_prepare", prepare)
    machine.hook_service(0x064512e6, "logical_program_write", write)
    machine.hook_service(0x06451354, "unmodeled_secondary_write_blocked", unexpected)
    params = 0x20002000
    # Older-version eligibility and ready peripheral state are explicit fixtures.
    for index, value in {1: 0, 3: 0, 4: 0, 6: 0, 7: machine.image_address,
                         8: len(image), 9: machine.POOL, 10: machine.POOL_BYTES}.items():
        machine.write_word(params + index * 4, value)
    native_return, stopped = None, None
    try:
        native_return = machine.call(0x0622cda0, params, 0, seconds=600)
    except ProtectedWrite:
        stopped = "protected_write_request"
    except SimulatedPowerCut:
        stopped = "simulated_power_cut"
    if machine.invalid_accesses:
        raise ValueError("Install job required an unmapped access")
    report = {"native_return": hex(native_return) if native_return is not None else None,
              "controlled_stop": stopped, "native_visits": dict(machine.visits),
              "emulated_RAM_policy_zero_fixture": policy_fixture,
              "older_version_and_peripheral_readiness_are_fixtures": True,
              "environment_calls": machine.environment_calls,
              "storage": storage.summary(written_payload[0] if written_payload else None),
              "cryptographic_and_decoder_stubs": False, "unmapped_accesses": 0,
              "physical_partition_mapping_verified": False, "recovery_path_tested": False}
    return report


def run_suite(original, program, selected=None, progress=None):
    data = bytes((i * 29 + 7) & 255 for i in range(8192))
    fixture = program_fixture(original, data)
    controls = [("original_bootstrap_request_blocked", original, 11534336, False, None, False),
                ("program_only_data_fixture", fixture, len(data), True, None, False),
                ("program_write_error_fixture", fixture, len(data), True, None, True),
                ("power_cut_after_two_sectors_fixture", fixture, len(data), True, 2, False)]
    results = []
    for name, image, size, policy, interruption, failure in controls:
        if selected and name not in selected:
            continue
        if progress:
            progress({"starting_install_case": name})
        report = run_job(program, image, size, policy, interruption, failure, progress)
        if name == "original_bootstrap_request_blocked":
            events = [e for e in report["environment_calls"] if e["service"] == "protected_bootstrap_program_request"]
            if report["controlled_stop"] != "protected_write_request" or len(events) != 1:
                raise ValueError("Original updater did not reach the expected protected bootstrap request")
            rows = events[0]["bootloader_payloads"]
            if len(rows) != 3 or not all(r["matches_unchanged_release"] for r in rows) or report["native_visits"].get("SHA256_finalize") != 50:
                raise ValueError("Original did not pass full verification with unchanged loader payloads")
        elif name == "program_only_data_fixture":
            if report["native_return"] != "0x0" or not report["storage"]["program_matches_candidate"]:
                raise ValueError("Program-only logical storage control failed")
        elif failure:
            if report["native_return"] in (None, "0x0") or report["storage"]["sectors_written"] != 0:
                raise ValueError("Injected storage error was not propagated")
        else:
            if report["controlled_stop"] != "simulated_power_cut" or report["storage"]["sectors_written"] != 2:
                raise ValueError("Interruption was not injected at the requested logical sector")
        if not report["storage"]["protected_region_canaries_intact"]:
            raise ValueError("Protected logical-region canary changed")
        results.append({"case": name, **report})
        if progress:
            progress({"completed_install_case": name, "native_return": report["native_return"], "controlled_stop": report["controlled_stop"]})
    if selected and set(selected) != {r["case"] for r in results}:
        raise ValueError("Unknown installation control name")
    return {"scope": "native install decisions with modeled environment/logical storage; not complete hardware",
            "input_BIN_SHA256": hashlib.sha256(original).hexdigest(), "cases": results,
            "all_expected_results_observed": True, "data_fixtures_are_nonbootable": True,
            "modified_image_exported": False, "camera_accessed": False,
            "physical_modified_update_acceptance_or_recovery_established": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("program", type=Path)
    parser.add_argument("--case", action="append", dest="selected")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.report.exists():
            raise ValueError("Report path already exists")
        report = run_suite(read_image(args.input), args.program.read_bytes(), args.selected,
                           progress=lambda value: print(json.dumps(value), flush=True))
        with args.report.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2); handle.write("\n")
        print(json.dumps({"install_controls_passed": len(report["cases"])}))
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
