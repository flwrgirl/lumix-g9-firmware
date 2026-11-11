# SPDX-License-Identifier: MIT
"""Bounded, isolated emulation of the hash-verified G9 signature wrapper.

Requires the optional Unicorn dependency. Maps release code, initialized data and
scratch RAM only. It does not emulate the complete updater, flash or any device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

try:
    from .roundtrip_g9_v27 import read_image
    from .verify_update_signature import KEY_OFFSET, KEY_SHA256, PROGRAM_BASE, PROGRAM_SHA256
except ImportError:
    from roundtrip_g9_v27 import read_image
    from verify_update_signature import KEY_OFFSET, KEY_SHA256, PROGRAM_BASE, PROGRAM_SHA256


def emulate(input_path, program_path):
    image = read_image(input_path)
    program = Path(program_path).read_bytes()
    if hashlib.sha256(program).hexdigest() != PROGRAM_SHA256:
        raise ValueError("Not the verified G9 main program")
    key = program[KEY_OFFSET:KEY_OFFSET + 64]
    if hashlib.sha256(key).hexdigest() != KEY_SHA256:
        raise ValueError("Unexpected G9 public key")
    try:
        import unicorn as uc
        from unicorn import arm_const as arm
    except ImportError as error:
        raise ValueError("Install tools/build-probe/requirements.txt for optional emulation") from error
    directory = image[0x2a0:0x1488]
    digest = hashlib.sha256(directory).digest()
    changed_directory = bytearray(directory)
    changed_directory[0x2ec - 0x2a0 + 0x1c] ^= 1
    changed_digest = hashlib.sha256(changed_directory).digest()
    signature = image[0x220:0x260]
    cases = [("original", digest, signature, 0),
             ("changed_component_hash_in_directory", changed_digest, signature, 1),
             ("changed_signature", digest, bytes([signature[0] ^ 1]) + signature[1:], 1)]
    results = []
    saved_registers = [arm.UC_ARM_REG_R4, arm.UC_ARM_REG_R5, arm.UC_ARM_REG_R6, arm.UC_ARM_REG_R7,
                       arm.UC_ARM_REG_R8, arm.UC_ARM_REG_R9, arm.UC_ARM_REG_R10, arm.UC_ARM_REG_R11]
    saved_vfp = [getattr(arm, "UC_ARM_REG_D" + str(i)) for i in range(8, 16)]
    for name, hash_bytes, sig_bytes, expected in cases:
        engine = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB)
        engine.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
        # The real memory helpers use VFP/NEON. Enable those in the emulator.
        engine.reg_write(arm.UC_ARM_REG_C1_C0_2, 0x00f00000)
        engine.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
        engine.mem_map(PROGRAM_BASE, len(program), uc.UC_PROT_ALL)
        engine.mem_write(PROGRAM_BASE, program)
        engine.mem_protect(PROGRAM_BASE, len(program), uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        engine.mem_map(0x081a0000, 0x720000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        source, target, length, routine = struct.unpack_from("<IIII", program, 0x100)
        if (source, target, length, routine) != (0x06a3aa94, 0x081a0000, 0x34ee4, 0x060a00c8):
            raise ValueError("Unexpected startup copy descriptor")
        engine.mem_write(target, program[source - PROGRAM_BASE:source - PROGRAM_BASE + length])
        engine.mem_map(0x20000000, 0x20000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        engine.mem_write(0x20000100, key)
        engine.mem_write(0x20000200, hash_bytes)
        engine.mem_write(0x20000300, sig_bytes)
        engine.reg_write(arm.UC_ARM_REG_CPSR, 0x30)
        engine.reg_write(arm.UC_ARM_REG_R0, 0x20000100)
        engine.reg_write(arm.UC_ARM_REG_R1, 0x20000200)
        engine.reg_write(arm.UC_ARM_REG_R2, 0x20000300)
        engine.reg_write(arm.UC_ARM_REG_SP, 0x20010000)
        engine.reg_write(arm.UC_ARM_REG_LR, 0x2001f001)
        for index, register in enumerate(saved_registers):
            engine.reg_write(register, 0x48480000 + index)
        for index, register in enumerate(saved_vfp):
            engine.reg_write(register, 0x4848000048480000 + index)
        unmapped = []
        def invalid(_engine, access, address, size, _value, _user_data):
            unmapped.append({"access": access, "address": hex(address), "bytes": size})
            return False
        engine.hook_add(uc.UC_HOOK_MEM_INVALID, invalid)
        try:
            engine.emu_start(0x0652633f, 0x2001f000, timeout=5000000, count=200000000)
        except uc.UcError as error:
            raise ValueError("Native verification emulation failed: " + str(error)) from error
        returned = engine.reg_read(arm.UC_ARM_REG_PC) == 0x2001f000
        value = engine.reg_read(arm.UC_ARM_REG_R0)
        preserved = engine.reg_read(arm.UC_ARM_REG_SP) == 0x20010000
        preserved &= all(engine.reg_read(r) == 0x48480000 + i for i, r in enumerate(saved_registers))
        preserved &= all(engine.reg_read(r) == 0x4848000048480000 + i for i, r in enumerate(saved_vfp))
        if not returned or value != expected or not preserved or unmapped:
            raise ValueError("Native verification control failed: " + name)
        results.append({"case": name, "returned": True, "return_value": value,
                        "expected_return_value": expected, "callee_saved_registers_and_SP_preserved": True,
                        "unmapped_memory_accesses": 0})
    return {"scope": "isolated recovered ECDSA wrapper; not complete update/install/boot emulation",
            "program_SHA256": PROGRAM_SHA256, "wrapper_CPU_address": "0x0652633e",
            "unicorn": uc.__version__, "CPU": "cortex-a7", "VFP_NEON_enabled": True,
            "instruction_budget_per_case": 200000000, "timeout_microseconds_per_case": 5000000,
            "code_hooks_or_return_stubs": False, "ROM_writable_during_execution": False,
            "hardware_memory_mapped": False, "cases": results, "all_controls_passed": True,
            "camera_accessed": False, "modified_update_acceptance_established": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("program", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        if args.report and args.report.exists():
            raise ValueError("Report path already exists")
        report = emulate(args.input, args.program)
        output = json.dumps(report, indent=2) + "\n"
        if args.report:
            with args.report.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(output)
        print(output, end="")
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
