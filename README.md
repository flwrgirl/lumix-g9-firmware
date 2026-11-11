# Lumix G9 firmware research

Reproducible, offline tools and findings for **Panasonic Lumix DC-G9 firmware 2.7** (`MC471`).

**Use at your own risk.** Firmware experiments can permanently brick a camera or
destroy calibration data. This independent project is not affiliated with
Panasonic. No modified firmware, hardware flasher, signing key or proven
hard-brick recovery procedure is provided. Read the [flashing and risk notes](docs/flashing.md)
before considering any camera installation.

**Status:** all 49 components of the tested update decode successfully and match their complete directory SHA-256 values. No camera firmware patch or flash was performed.

The unchanged update also rebuilds byte for byte. Its directory signature passes independent ECDSA arithmetic, OpenSSL, and the recovered G9 verifier in emulation. Modified-update acceptance remains unproven.

The full in-memory decoder now passes 12 native controls, including all 49 release components. Installation decisions are also tested against an explicitly limited logical storage model. The full-update job requests loader programming even when the loader payloads are unchanged; see the [emulation findings](docs/emulation.md).

**UI status:** the original text rasterizer runs in both Unicorn and QEMU.
Its pixels have been checked against QEMU's native graphical console. The
camera's menus and input handling have **not** booted. See
[native QEMU bring-up](docs/native-ui.md) for the working controls and remaining
runtime dependencies.

## What is included

- A decoder for the exact tested `G9___V27.bin` / `G9___V27.zip` sample.
- A stored-byte UPD inspector with CRC32, bounds and extraction checks.
- Ghidra scripts for ARM/Thumb analysis at independently corroborated addresses.
- Component hashes, cipher parameters and a documented recovery method.
- Firmware-free tests, a publication audit and a GitHub Actions workflow.
- A standalone Cortex-A7 C build control, checked in ARM and Thumb emulation.
- A native host encoder and unchanged-image roundtrip control.
- Read-only directory-signature verification and isolated native-verifier emulation.
- Complete native in-memory decoder controls and modeled storage/failure tests.
- Native QEMU execution controls and original UI-module investigation.

Vendor firmware, generated decompilations, raw memory captures, calibration exports and downloaded analysis software are kept outside this repository. Obtain the input from [Panasonic's DC-G9 download page](https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/g9.html).

## Quick start

Use Python 3.11 or newer:

```sh
git clone https://github.com/flwrgirl/lumix-g9-firmware.git
cd lumix-g9-firmware
python -m pip install -r requirements.txt
python tools/decode_g9_v27.py path/to/G9___V27.zip --out local/decoded
python tools/verify_decoded.py local/decoded
```

The output directory must be new. The decoder pins the input BIN hash, checks the update CRC32, and checks each complete plaintext component before saving it. It does not contact the camera, repack an update or install firmware. `local/` is ignored by Git.

Inspect the original container without decrypting it:

```sh
python tools/inspect_g9_upd.py path/to/G9___V27.zip --json local/layout.json
```

The current UI work uses [native QEMU probes](docs/native-ui.md):

```sh
python tools/qemu_g9_probe.py --qemu /path/to/qemu-system-arm --decoded local/decoded --report local/qemu-control.json --window
```

This requests a native developer monitor window. It does not boot or display
the G9 menus. No camera is accessed.

## Verified sample

These hashes identify the sample used in this research; they are not presented as hashes independently published by Panasonic.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| `G9___V27.zip` | 81,685,592 | `5fd2f5c212b5101dd25171e53cdb435b450db1869cf86a00aebe238c7b84445d` |
| `G9___V27.bin` | 81,952,256 | `9316958735c19fa0a04415c75faf97edff9be042a42c115ac1622d6c6379e7c3` |

The 45 encrypted components use **five-round AES-128-CBC**. Each directory entry provides its own IV; no padding is removed. The recovered key is also present in the verified main program at file offset `0x009C8F10`. See [the format notes](docs/format.md) and [expected component manifest](evidence/expected-components.json).

## Documentation

- [Recovery method and evidence](docs/recovery.md)
- [UPD layout and cipher](docs/format.md)
- [All verified components](docs/components.md)
- [Ghidra reproduction](docs/ghidra.md)
- [Flashing risks and current limitations](docs/flashing.md)
- [Compilation: working control and full-rebuild requirements](docs/building.md)
- [Byte-identical update reconstruction](docs/packaging.md)
- [Directory signature and native verification](docs/authentication.md)
- [Decoder, install decisions and storage-model limits](docs/emulation.md)
- [Original UI investigation and native QEMU bring-up](docs/native-ui.md)
- [Validation and publication scope](docs/verification.md)

Compiled firmware can be inspected and disassembled after decoding. Generated C-like output has inferred names and types. The recorded main-program pass produced output for 24,627 of 24,628 identified functions; one large function timed out. This work does not establish signature bypass, acceptance of a modified update, or a hard-brick recovery method.

## Development

```sh
python -m unittest discover -s tests -v
python tools/audit_publication.py
```

The audit checks the Git index. Stage intended source files before running it. Tests do not download or redistribute camera firmware. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits and license

The [older-model Lumix research](https://github.com/flickering-star/lumix-firmware-research) supplied service-framing and five-round cipher controls. G9-specific memory controls, key location and component matches were established separately on the tested build. Ghidra scripts target [Ghidra 12.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build).

The original tools and documentation in this repository use the [MIT license](LICENSE). This license does not cover Panasonic firmware or third-party analysis software, which are not bundled here.
