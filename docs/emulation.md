# Native decoder and modeled installation

The full in-memory G9 update decoder now executes in a Cortex-A7 emulator.
The untouched release returns success and produces the correct plaintext hashes
for **all 49 components**. Its original signature, decryption and hash routines
run without replacement return values or cryptographic stubs.

The install-job experiment extends this to the original job's software decisions,
with explicit models for board/OS services and storage gateways. It is not a
complete virtual camera or a verified physical flash-controller model.

For the actual UI modules, original-code probes and the native QEMU route, see
[UI bring-up](native-ui.md). No original G9 screen has been rendered yet.

## Reproduce

Install the optional emulator dependency and supply the locally decoded release:

```sh
python -m pip install -r tools/build-probe/requirements.txt
python tools/emulate_update_decoder.py path/to/G9___V27.zip local/decoded/03_program.bin --report local/decoder-controls.json
python tools/emulate_install_job.py path/to/G9___V27.zip local/decoded/03_program.bin --report local/install-controls.json
```

Report files must be new and their parent directory must exist. `--case NAME`
selects individual controls and can be repeated. Full-release cases can take
several minutes. Progress is printed during long native calls.

The tools pin both original firmware and main-program hashes. Controlled variants
exist only in emulated RAM; no modified update, flash image or installable patch
is exported. They never open a camera interface or storage device.

## Decoder controls

The native API sequence initializes the context and workspace, selects memory
input, copies the release key, selects its verification profile, parses the header
and calls the complete decoder at `0x06233C3E`. The signed fixture uses the release
initializer state, zero context allowance, and the release boot-information value.

| Control | Observed result |
| --- | --- |
| Untouched signed release | Success; all 49 plaintext hashes match |
| Wrong outer magic | Rejected, `0x80000064` |
| Truncated input | Rejected, `0x8000000B` |
| Wrong outer CRC32 | Rejected, `0x80000064` |
| Changed signature, CRC repaired | Rejected, `0x80000066` |
| Changed signed component hash, CRC repaired | Rejected, `0x80000066` |
| Changed first payload, CRC repaired | Rejected after its plaintext hash check, `0x80000066` |
| Mismatched repeated header | Rejected, `0x80000064` |
| Zero marker with default allowance | Rejected, `0x80000065` |
| Small unsigned fixture with default allowance | Rejected, `0x80000065` |
| Small unsigned fixture with explicit context allowance | Success; independently checked plaintext matches |
| Corrupted unsigned fixture with explicit allowance | Native success, but independent plaintext hash fails |

The signed release visits ECDSA once and SHA-256 finalization 50 times: the signed
directory and 49 component records. The changed-payload case reaches signature
verification and then its first plaintext hash check. No OS/hardware stubs or
unmapped accesses are needed for this decoder path. SP and callee-saved CPU/VFP
registers are checked after calls.

The last two controls deliberately change an **emulated context**. They demonstrate
that the unsigned allowance skips both ECDSA and plaintext-hash authentication.
They do not establish access to that mode on a physical camera. See the complete
[decoder evidence](../evidence/decoder-emulation.json).

## What the install job does with unchanged loaders

The original job at `0x0622CDA0` is run using memory input and an explicitly older
version fixture. It performs the real decoder and verification checks. Board/OS,
peripheral readiness and device-specific EEPROM merges are modeled and listed in
the report; cryptographic and decoder functions remain native.

After successful verification the job calls `0x064511DC`, the bootstrap-programming
service, **even though loader1, loader2 and loader3 still match their complete
original hashes**. The logical storage guard blocks that request before committing
any protected-region changes. Its observed arguments are:

```text
r0 = 1
r1 = 0x1000
r2 = 0x11800
r3 = guest pointer to loader1
stack[0] = guest pointer to loader2
stack[4] = 0x72
```

The service's recovered code processes the loader buffers through the storage
driver. Thus keeping loader payload bytes unchanged does not establish that a
full update avoids requesting loader programming. This observation concerns the
modeled execution path, not a measured physical update or every possible path.

## Logical storage and failure injection

Three additional cases use a small **nonbootable data fixture**, a single `program`
entry, and policy zero in emulated RAM. They are not edited G9 feature firmware.

| Case | Result |
| --- | --- |
| Complete program-data write | Native job returns 0; model contains all 16 sectors |
| Injected program write error | Native job returns `0x8000000C`; no candidate sector committed |
| Simulated interruption after two sectors | Execution stops with a partial logical image |

Bootloader and calibration canaries remain intact in these controls. Their storage
is separate **in the model**. The program-prepare service is modeled as erasing
the logical program slot, and writes use 512-byte model sectors. The real prepare
command's physical erase scope, partition aliasing, controller behavior, flash
geometry, ECC/bad-block handling and power-loss behavior have not been established.
The canary result therefore does not prove physical protection on the camera.

All modeled services and raw native call arguments are included in the
[installation evidence](../evidence/install-emulation.json). The emulator does not
boot the resulting slot, provide rollback, or demonstrate restoration after an
unbootable main program. Running the preserved original code directly from the PC
must not be confused with a recovery path inside the camera.

## Boundaries and next work

Program code is mapped read/execute. Input, workspace, modeled runtime data and
scratch memory are mapped read/write without execute permission. Unknown memory
accesses fail rather than silently creating peripherals. Long calls run in bounded
instruction chunks with wall-clock limits. The test suite includes storage guards,
partial writes, error propagation and fixture layout checks.

The next hardware-modeling work is to resolve the actual storage-controller
commands and erase/partition mapping, and trace an independent boot/recovery route.
Filesystem/SD input, UI transitions, physical installation and camera startup have
not been emulated end to end. No claim of zero-risk modified firmware follows from
the current controls.

References: [Unicorn](https://www.unicorn-engine.org/) for CPU instrumentation and
[QEMU's board-model explanation](https://www.qemu.org/docs/master/system/target-arm.html#choosing-a-board-model)
for the distinction between a CPU emulator and a complete hardware model.
