# SPDX-License-Identifier: MIT
"""Emulate the isolated build controls. No camera, firmware loader or hardware."""
import argparse
import hashlib
import json
from pathlib import Path
import random

try:
    from .build_probe import DEMO_ADDRESS, inspect_elf, require
except ImportError:
    from build_probe import DEMO_ADDRESS, inspect_elf, require


def sample_values():
    rng = random.Random(0x4739)
    return [*range(256), 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff,
            *(rng.getrandbits(32) for _ in range(1024))]


def emulate(text, address, mode, values):
    try:
        import unicorn as uc
        from unicorn import arm_const as arm
    except ImportError as error:
        raise ValueError("Install tools/build-probe/requirements.txt for optional emulation") from error
    require(mode in ("arm", "thumb") and 0 < len(text) <= 256, "Unexpected leaf control")
    require(address % (2 if mode == "thumb" else 4) == 0, "Unaligned control entry")
    engine = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB if mode == "thumb" else uc.UC_MODE_ARM)
    engine.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
    page = address & ~0xfff
    require(address + len(text) <= page + 0x1000, "Control crosses emulator page")
    engine.mem_map(page, 0x1000, uc.UC_PROT_ALL)
    engine.mem_write(address, text)
    engine.mem_protect(page, 0x1000, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
    stop, stack = 0x200000, 0x300000
    # No mapped hardware or writable memory. A pure leaf must not need either.
    protected = [arm.UC_ARM_REG_R4, arm.UC_ARM_REG_R5, arm.UC_ARM_REG_R6, arm.UC_ARM_REG_R7,
                 arm.UC_ARM_REG_R8, arm.UC_ARM_REG_R9, arm.UC_ARM_REG_R10, arm.UC_ARM_REG_R11]
    results = []
    for value in values:
        engine.reg_write(arm.UC_ARM_REG_CPSR, 0x10 | (0x20 if mode == "thumb" else 0))
        engine.reg_write(arm.UC_ARM_REG_R0, value)
        for i, register in enumerate(protected):
            engine.reg_write(register, 0x48480000 + i)
        engine.reg_write(arm.UC_ARM_REG_SP, stack)
        engine.reg_write(arm.UC_ARM_REG_LR, stop | (mode == "thumb"))
        # The instruction budget bounds every call without spawning a timer thread.
        engine.emu_start(address | (mode == "thumb"), stop, count=100)
        require(engine.reg_read(arm.UC_ARM_REG_PC) == stop, "Control did not return within its instruction budget")
        require(engine.reg_read(arm.UC_ARM_REG_SP) == stack, "Control changed stack pointer")
        for i, register in enumerate(protected):
            require(engine.reg_read(register) == 0x48480000 + i, "Control changed a callee-saved register")
        result = engine.reg_read(arm.UC_ARM_REG_R0)
        expected = value if value < 0x80000000 else ((-value) & 0xffffffff)
        require(result == expected, "Wrong emulated result for " + hex(value))
        results.append(result)
    return {"cases": len(values), "all_results_match": True, "callee_saved_registers_preserved": True,
            "no_stack_or_hardware_memory_access": True, "unicorn": uc.__version__,
            "results_SHA256": hashlib.sha256(b"".join(v.to_bytes(4, "little") for v in results)).hexdigest()}


def verify(directory):
    directory = Path(directory)
    values = sample_values()
    rows = []
    for mode in ("arm", "thumb"):
        stem = "probe-" + mode
        metadata, text = inspect_elf((directory / (stem + ".elf")).read_bytes(), mode)
        require((directory / (stem + ".bin")).read_bytes() == text, "Raw text differs from linked ELF")
        rows.append({**metadata, **emulate(text, DEMO_ADDRESS, mode, values)})
    return {"scope": "isolated integer control; not whole-camera emulation", "artifacts": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
