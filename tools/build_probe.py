# SPDX-License-Identifier: MIT
"""Compile a standalone Cortex-A7 C control; no firmware is read or changed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools/build-probe"
DEMO_ADDRESS = 0x10000  # Emulator only; not an approved camera address.


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_elf(data, mode):
    """Check this small linked control, not arbitrary firmware ELF layouts."""
    require(len(data) >= 52 and data[:7] == b"\x7fELF\x01\x01\x01", "Expected ELF32 little endian")
    fields = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    etype, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names_index = fields
    require((etype, machine, version, ehsize, shsize) == (2, 40, 1, 52, 40), "Expected linked ARM ELF32")
    require(mode in ("arm", "thumb"), "Unknown instruction mode")
    require(entry == DEMO_ADDRESS + (mode == "thumb"), "Unexpected probe entry or ARM/Thumb bit")
    require(flags >> 24 == 5 and not (flags & 0x400), "Expected EABI5 without hard-float calling convention")
    require(shnum > 0 and names_index < shnum and shoff + shnum * shsize <= len(data), "Invalid ELF section table")
    require(phoff + phnum * phsize <= len(data), "Invalid ELF program headers")
    require(not phnum or phsize == 32, "Unexpected program header size")
    for i in range(phnum):
        kind = struct.unpack_from("<I", data, phoff + i * phsize)[0]
        require(kind not in (2, 3), "Probe must have no dynamic loader or dynamic segment")
    sections = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shsize) for i in range(shnum)]
    ns = sections[names_index]
    require(ns[4] + ns[5] <= len(data), "Invalid ELF section names")
    names = data[ns[4]:ns[4] + ns[5]]
    text = None
    for s in sections:
        require(s[0] < len(names), "Invalid ELF section name offset")
        name = names[s[0]:].split(b"\0", 1)[0]
        kind, attrs, address, offset, size = s[1:6]
        require(kind == 8 or offset + size <= len(data), "ELF section exceeds file")
        require(kind not in (4, 9) or size == 0, "Unresolved relocation section")
        if attrs & 2 and size:
            require(name == b".text" and kind == 1 and attrs == 6 and address == DEMO_ADDRESS,
                    "Unexpected loadable section in standalone probe")
            require(0 < size <= 256 and text is None, "Unexpected probe size or duplicate text")
            text = data[offset:offset + size]
        if kind == 2:  # SHT_SYMTAB
            require(s[9] == 16 and size % 16 == 0, "Invalid symbol table")
            for at in range(offset + 16, offset + size, 16):
                symbol = struct.unpack_from("<IIIBBH", data, at)
                require(symbol[5] != 0, "Undefined probe symbol")
    require(text is not None, "Probe has no executable text")
    return {"ELF_class": 32, "endian": "little", "machine": "ARM", "EABI": 5,
            "entry": hex(entry), "text_address": hex(DEMO_ADDRESS), "mode": mode,
            "text_bytes": len(text), "text_SHA256": hashlib.sha256(text).hexdigest()}, text


def build(zig, out):
    executable = shutil.which(str(zig))
    require(executable is not None, "Zig executable not found; pass --zig with its full path")
    executable = str(Path(executable).resolve())
    out = Path(out).resolve()
    require(not out.exists(), "Output directory must be new")
    version = subprocess.run([executable, "version"], check=True, capture_output=True, text=True).stdout.strip()
    require(version == "0.17.1", "This build recipe is pinned to Zig 0.17.1")
    compiler = subprocess.run([executable, "cc", "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    out.mkdir(parents=True)
    environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / ".zig-global-cache"),
                       ZIG_LOCAL_CACHE_DIR=str(out / ".zig-cache"))
    rows = []
    for mode in ("arm", "thumb"):
        target = mode + "-freestanding-eabi"
        common = ["cc", "-target", target, "-mcpu=cortex_a7", "-m" + mode,
                  "-mfloat-abi=soft", "-std=c11", "-Os", "-g0", "-ffreestanding", "-fno-builtin",
                  "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                  "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror",
                  "-Wno-unused-command-line-argument"]
        stem = "probe-" + mode
        commands = [
            common + ["-S", "probe.c", "-o", str(out / (stem + ".s"))],
            common + ["-c", "probe.c", "-o", str(out / (stem + ".o"))],
            ["cc", "-target", target, "-mcpu=cortex_a7", "-m" + mode,
             "-mfloat-abi=soft", "-nostdlib", str(out / (stem + ".o")), "-Wl,-T,probe.ld",
             "-Wl,--entry=g9_build_probe,--build-id=none,--no-undefined,--gc-sections,--fatal-warnings",
             "-o", str(out / (stem + ".elf"))],
        ]
        log = []
        for arguments in commands:
            # Invoke an executable directly; no shell interpolation.
            result = subprocess.run([executable, *arguments], cwd=PROBE, env=environment,
                                    capture_output=True, text=True)
            log.append({"arguments": arguments, "returncode": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr})
            (out / (stem + "-commands.json")).write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
            require(result.returncode == 0, "Compiler failed: " + result.stderr[-3000:])
        raw = (out / (stem + ".elf")).read_bytes()
        metadata, text = inspect_elf(raw, mode)
        (out / (stem + ".bin")).write_bytes(text)
        rows.append({**metadata, "ELF_SHA256": hashlib.sha256(raw).hexdigest()})
    report = {"scope": "standalone offline compiler control; not firmware", "zig": version,
              "compiler": compiler, "CPU": "cortex-a7", "float_ABI": "soft",
              "linked_address_is_emulator_only": True,
              "source_SHA256": hashlib.sha256((PROBE / "probe.c").read_bytes()).hexdigest(),
              "linker_script_SHA256": hashlib.sha256((PROBE / "probe.ld").read_bytes()).hexdigest(),
              "artifacts": rows}
    (out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", default="zig", help="Zig 0.17.1 executable")
    parser.add_argument("--out", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    print(json.dumps(build(args.zig, args.out), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
