# SPDX-License-Identifier: MIT
"""Run the G9's actual in-memory update decoder with controlled mutations.

All fixtures exist only in emulated RAM. No modified update file is exported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

try:
    from .g9_emulator import G9Machine
    from .roundtrip_g9_v27 import read_image
except ImportError:
    from g9_emulator import G9Machine
    from roundtrip_g9_v27 import read_image


def repair_crc(image):
    struct.pack_into("<I", image, 0x40, zlib.crc32(memoryview(image)[0x200:]) & 0xffffffff)


def small_unsigned_fixture(original):
    # One unchanged encrypted loader payload; invalid for the signed policy.
    image = bytearray(original[:0x2600])
    struct.pack_into("<I", image, 0x3c, len(image) - 0x200)
    image[0x2a0:0x2e0] = image[:0x40]
    struct.pack_into("<I", image, 0x2e8, 1)
    image[0x200] = 0
    repair_crc(image)
    return image


def cases(original):
    yield "original_signed_release", bytes(original), False, True, True
    image = bytearray(original); image[0] ^= 1
    yield "wrong_outer_magic", image, False, False, None
    yield "truncated_input", original[:-1], False, False, None
    image = bytearray(original); image[0x40] ^= 1
    yield "bad_outer_CRC", image, False, False, None
    image = bytearray(original); image[0x220] ^= 1; repair_crc(image)
    yield "bad_signature_repaired_CRC", image, False, False, None
    image = bytearray(original); image[0x2ec + 0x1c] ^= 1; repair_crc(image)
    yield "changed_signed_component_hash_repaired_CRC", image, False, False, None
    image = bytearray(original); image[0x1600] ^= 1; repair_crc(image)
    yield "bad_payload_repaired_CRC", image, False, False, None
    image = bytearray(original); image[0x2ac] ^= 1; repair_crc(image)
    yield "mismatched_repeated_header", image, False, False, None
    image = bytearray(original); image[0x200] = 0; repair_crc(image)
    yield "zero_marker_default_policy", image, False, False, None
    small = small_unsigned_fixture(original)
    yield "small_unsigned_default_denied", small, False, False, None
    yield "small_unsigned_allowance_fixture", small, True, True, True
    altered = bytearray(small); altered[0x1600] ^= 1; repair_crc(altered)
    yield "small_unsigned_corruption_not_authenticated", altered, True, True, False


def run_suite(original, program, selected=None, progress=None):
    results = []
    for name, image, allowance, expected_success, expected_hashes in cases(original):
        if selected and name not in selected:
            continue
        if progress:
            progress({"starting_case": name})
        machine = G9Machine(program, image, progress=progress)
        header = machine.initialize_decoder(allowance)
        value = machine.call(0x06233c3e, machine.CONTEXT, 0) if header == 0 else header
        success = value == 0
        if success != expected_success:
            raise ValueError("Unexpected native decoder result for " + name + ": " + hex(value))
        rows = machine.component_hashes(image) if success else []
        hashes_match = all(r["matches_directory"] for r in rows) if rows else None
        if expected_hashes is not None and hashes_match != expected_hashes:
            raise ValueError("Unexpected decoded component hashes for " + name)
        if name == "original_signed_release" and (machine.visits.get("ECDSA") != 1 or machine.visits.get("SHA256_finalize") != 50):
            raise ValueError("Original did not traverse full native signature/component-hash checks")
        if machine.invalid_accesses or machine.environment_calls:
            raise ValueError("Decoder required an unmodeled access or environment stub")
        result = {"case": name, "guest_input_bytes": len(image),
                  "unsigned_context_allowance_fixture": allowance,
                  "native_header_return": hex(header), "native_return": hex(value),
                  "native_success": success, "expected_success": expected_success,
                  "all_decoded_hashes_match": hashes_match, "native_visits": dict(machine.visits),
                  "native_calls": machine.calls, "components": rows,
                  "environment_stubs": 0, "unmapped_accesses": 0,
                  "callee_saved_registers_and_SP_preserved": True}
        results.append(result)
        if progress:
            progress({"completed_case": name, "native_return": hex(value), "hashes_match": hashes_match})
        del machine
    if selected and set(selected) != {r["case"] for r in results}:
        raise ValueError("Unknown decoder control name")
    return {"scope": "native in-memory update decoder; not installation/boot or physical camera",
            "input_BIN_SHA256": hashlib.sha256(original).hexdigest(),
            "CPU": "cortex-a7", "VFP_NEON_enabled": True, "cases": results,
            "all_expected_results_observed": True, "cryptographic_or_decoder_stubs": False,
            "hardware_memory_mapped": False, "modified_image_exported": False,
            "camera_accessed": False, "physical_modified_update_acceptance_established": False}


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
        print(json.dumps({"cases_passed": len(report["cases"]), "all_expected_results_observed": True}))
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
