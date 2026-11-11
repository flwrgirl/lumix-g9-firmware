# Flashing and experimental use

**Any firmware installation or hardware experiment is entirely at your own risk.**
An invalid image, an interrupted write or an incorrect device address can leave
the camera unusable and can destroy device-specific calibration. The tools are
provided without warranty under the [MIT license](../LICENSE). This project is
independent of Panasonic and does not provide manufacturer support.

## What you can reproduce

1. Obtain your own DC-G9 V2.7 update from the Panasonic page linked in the README.
2. Decode and verify its 49 components using the [quick start](../README.md#quick-start).
3. Generate your own C-like listings and disassembly with the [Ghidra instructions](ghidra.md).
4. Compile and emulate an isolated C routine using the [build control](building.md).
5. Re-encrypt the unchanged components and reproduce the original update byte for
   byte using the [roundtrip instructions](packaging.md).

Decompiled C-like listings are analysis outputs, not a complete compilable source
tree. The roundtrip is reconstruction of an unchanged release, not compilation
of the full firmware. Changed components are deliberately rejected by that tool.

## Current installation limits

No camera has been flashed as part of this research. No modified update has
been shown to pass the camera's authentication or install successfully. Editing
a component changes its directory hash and invalidates the original directory
signature; rebuilding the outer CRC does not solve authentication. See the
[authentication findings](authentication.md).

The storage emulator is a limited logical model, not a hardware flashing or
recovery tool. In the observed full-update path, the job requests loader
programming even when loader payloads are unchanged. Neither an offline test
pass nor a byte-identical roundtrip demonstrates safe installation on a camera.

For an official, unmodified update, follow Panasonic's instructions supplied
with the exact model's update. This repository does not provide an experimental
flashing procedure because modified-image acceptance and reliable recovery
have not been established. An "at your own risk" disclaimer does not remove
those technical gaps.

Keep serial numbers, calibration, ROM backups and raw memory captures private.
A firmware update file is not a substitute for device-specific recovery data.
Contributions claiming successful modification or hardware installation should
include reproducible evidence and describe the exact model and version tested,
without publishing private camera data.
