# Compiling code for the G9

We can compile and link **new, isolated Cortex-A7 C routines**. We cannot rebuild
the complete Panasonic firmware from the recovered decompiler listings.
No modified update or camera installation is produced by the build tools here.

## What the recovered binaries tell us

| Area | Evidence in the verified release | Build implications |
| --- | --- | --- |
| Main program | String at component offset `0x009C8E78`: `ThreadX SMP/Cortex-A7/RVDS Version G5.6.1.5.1 / v2.0rel2.6` | Cortex-A7 / ARMv7-A, with ARM and Thumb instructions observed. The ThreadX/RVDS marker identifies a port; it does not establish the exact compiler version or all compiler flags. |
| Linux programs and libraries | 416 ELF32 little-endian ARM files; 101 interpreter entries name `/lib/ld-linux.so.3` | Linux EABI environment, separate from the ThreadX program. Matching target headers, libraries and startup files are needed for dynamically linked applications. |
| Linux compiler metadata | 247 `.comment` entries name `GCC: (Buildroot 2017.02-svn195143) 4.8.5`; other entries identify Buildroot 2017.02 / GCC 4.8.5 and Sourcery 2014.05-29 / GCC 4.8.3 | Useful toolchain leads, not a complete original SDK. |
| Linux modules | 63 module metadata entries contain `vermagic=3.18.18 SMP mod_unload ARMv7 ` | Kernel modules need the matching kernel source, configuration, exported symbols and compatible toolchain. |

The non-module ELF flags identify EABI5 with the soft-float calling convention
(`0x05000200`, or `0x05000202` for four files). This does not rule out hardware
floating-point instructions using the softfp convention, and it does not establish
the ThreadX program's complete ABI. The build control below uses integer arguments
and return values only.

## Reproduce the working standalone build

Download and extract **Zig 0.17.1** from its [official downloads](https://ziglang.org/download/).
Its portable package provides the Clang C compiler and linker; the probe source
is C, with no Zig language code. The tested Windows compiler reports Clang 22.1.8.

The tested `zig-x86_64-windows-0.17.1.zip` has 100,343,666 bytes and SHA-256:

```text
b03f477a1943673e02aca0f570e8030dffd536ce1f45cbc4d3326ec31159562e
```

This was matched against the official [download index](https://ziglang.org/download/index.json).
Keep the compiler outside the repository, or in its ignored `local/` folder.

From the repository root, using the full path to your extracted Zig executable:

```sh
python tools/build_probe.py --zig path/to/zig --out local/build-probe
python -m pip install -r tools/build-probe/requirements.txt
python tools/verify_build_probe.py local/build-probe
```

On Windows the executable is `zig.exe`; quote paths containing spaces. Choose a
new output directory for each build. The build puts both compiler caches inside
that output directory and writes assembly, an object file, a linked ELF, raw text,
the exact command logs and a JSON report. It does not require an ARM compiler
installed system-wide, camera connection, Linux sysroot or proprietary SDK.

The recipe uses explicit `arm-freestanding-eabi` and `thumb-freestanding-eabi`
targets, Cortex-A7, integer soft-float calling convention, freestanding C,
optimization for size, and no standard library or startup runtime. It passes an
explicit linker entry symbol. With the tested Zig wrapper, changing `-mthumb`
alone while retaining the ARM target did not select Thumb output; the explicit
target and subsequent entry-state check are significant.

[probe.ld](../tools/build-probe/probe.ld) places the control at `0x00010000`
**only in emulated memory**. That address has not been allocated or approved for
camera code. The ELF checks reject an unexpected architecture, entry state,
hard-float ABI flag, runtime data dependency, unresolved symbol or relocation.

## What has actually passed

The independently written [C control](../tools/build-probe/probe.c) computes an
integer magnitude without signed-overflow undefined behavior. It compiled to
12 bytes of ARM instructions and 8 bytes of Thumb instructions. Both builds
passed 1,285 deterministic Unicorn cases, including zero, sign boundaries,
`0x80000000`, and pseudorandom 32-bit values. The emulator also checked return,
stack pointer and callee-saved registers, with no mapped stack or hardware memory.

A private comparison extracted the 8-byte Thumb leaf at program CPU address
`0x06500E7E` (component offset `0x00460E7E`) from the hash-verified release. Its
SHA-256 is `6bd23bca9701848a50fff2c0ea8a3f90fcde10c27e9294a5e279b58d357a95ae`.
It produced the same return values on those 1,285 cases. The rebuilt instructions
differ from the original. This establishes a limited semantic control, not
exhaustive equivalence, a feature patch or compatibility of arbitrary routines.
Vendor instructions and generated binaries are not included in this repository.

## Why the full listing does not compile

A syntax-only compiler check of `G9-program-decompiled.c` failed immediately on
Ghidra's `code`, `undefined4`, `uint`, address-derived globals and
`coproc_movefrom_Identification_registers`. These are decompiler representations,
not recovered Panasonic headers or C compiler intrinsics. Adding typedefs would
only clear the first layer of errors. The analysis also contains provisional
function boundaries, signatures and types, warning-bearing functions and one
function that did not finish decompiling.

A complete source rebuild would require recovered or reimplemented program
semantics, exact data and structure layouts, firmware service interfaces,
startup/exception assembly, ThreadX and vendor support libraries, linker/scatter
layout, initialization tables, and each auxiliary component's build inputs.
No complete source tree, SDK or original build configuration has been recovered.
The existing raw component bytes remain the authoritative implementation.

Panasonic's [G9 manual](https://www.panasonic.com/content/dam/Panasonic/MEA/pdf-download/cameras-camcorders/DC-G9L.pdf)
describes a GPL/LGPL source distribution route. That is a useful lead for the
Linux portion; it does not establish availability of the proprietary application
and imaging stack. No matching source archive has been obtained in this work.

## Route toward a real modification

1. Trace the desired feature in the original disassembly, confirming its callers,
   data, ARM/Thumb state and calling convention.
2. Reconstruct and test only the routine that needs changing. Where practical,
   compare original and rebuilt behavior in isolation before changing it.
3. Establish a valid placement, size budget and hook/branch strategy; preserve
   live registers, stack alignment, data layout and any initialization behavior.
4. Validate packaging and acceptance separately. The [unchanged container now
   reproduces byte for byte](packaging.md), and [directory authentication is
   verified](authentication.md). Modified-image acceptance remains unproven.
5. Establish an adequate recovery method before attempting an installation.

Steps 1–5 have not been completed for a recording-limit, bitrate or menu patch.
The current build helper deliberately creates a standalone control only.

References: [Clang cross-compilation](https://clang.llvm.org/docs/CrossCompilation.html),
[Arm ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst),
and [Unicorn programming tutorial](https://www.unicorn-engine.org/docs/tutorial.html).
