# Original UI bring-up and native QEMU

The target is to execute the G9's own UI code, display the pixels it produces,
and deliver button/touch events to that code in a native application window.
**That target is not achieved.** Development uses native QEMU bring-up. No
original camera menu or screen has been booted.

## What now executes

The hash-verified main program contains a five-entry postboot load table at
`0x069272F0`, used by the loader at `0x062A54FC`:

| Module | Code image address | Bytes |
| --- | --- | ---: |
| postboot1 | `0x06BA0000` | 4,718,592 |
| postboot2 | `0x07020000` | 7,602,176 |
| postboot3 | `0x07760000` | 131,072 |
| postboot4 | `0x07780000` | 131,072 |
| postboot5 | `0x077A0000` | 786,432 |

Each `LOAD` header provides initialized-data copy and BSS bounds. The native
loader uses the `0x8...` RAM alias while ordinary pointers use the lower alias.
The strict UI probe maps both aliases onto shared host storage, copies the
verified initial data and leaves BSS zeroed. This is a declared memory fixture;
it does not initialize the operating system or model the camera's MMU.

postboot1 contains font handling and application/graphics routines. OSD
resources include fonts, translated strings and layout data. The routine at
`0x06BAA33A` recognizes FDL, BDF and other font resource types and passes five
controls in both CPU engines.

## Original text rendering

The original font initialization at `0x06BAE078` and CPU rasterizer at
`0x06BAE8D8` now execute unchanged. A startup descriptor at main-program file
offset `0x140` declares the low SRAM clear that earlier strict probes lacked.
The font heap, temporary bitmap, layout object and font slots have also been
mapped from their native declarations.

For the text control `DC-G9` at 512 by 80 pixels, both engines produce the same
40,960-byte 4-bit-gray bitmap:

- SHA-256: `04742939af3dc7a27b2abb76a6082c518b1ccab22e54e044c0c78c3f3936aa47`
- 321 nonzero pixels; maximum gray value 15.
- Workspace, SRAM and bitmap boundary canaries remain intact.
- The QEMU console capture matches every converted bitmap pixel.

See [rasterization evidence](../evidence/native-font-rasterization.json).
This control uses a single-thread fixture. Native locking returns `E_NOEXS`
until the OS objects exist; that observed failure is recorded, not replaced
with success. A rendered text control is not a menu screen.

```sh
python tools/render_g9_font.py /path/to/decoded --out /new/private/font-control
python tools/render_g9_font.py /path/to/decoded --qemu /path/to/qemu-system-arm --native-display --out /new/private/qemu-font
```

The second command verifies the native graphical console headlessly. Add
`--window` to keep QEMU's native window open; desktop interaction is not needed
for the pixel comparison. The PL110 controller is a presentation adapter from
QEMU's VersatilePB board, not an emulation of the G9 LCD controller. No menus,
camera image or sound assets are supplied by this adapter.

## Application runtime work

Private experiments now execute the original ThreadX initialization and object
configuration, creating 257 firmware threads with successful native constructor
returns. Three QEMU CPU cores, shared memory aliases, GIC interrupts and a timer
adapter are running. The original module-loader task can load all five postboot
modules through a read-only virtual firmware partition; each copied module is
compared byte for byte with its verified source.

These application experiments remain incomplete. They use declared peripheral
fixtures, including a zero-reset virtual auxiliary controller, and explicitly
bypass the native physical-storage initialization and sector-read routines.
They do not establish the real hardware's reset state or timing. Unknown device
accesses still stop execution. The next dependencies include the remaining
board devices, original graphics output and original button/touch events.

No original camera menu has been drawn, and the input bridge is not connected.
The reproducible public controls above remain separate from those unfinished
application experiments.

## Reproduce the strict probes

Install the optional dependency described in [emulation.md](emulation.md), then:

```sh
python tools/probe_g9_ui.py /path/to/decoded --report /new/path/ui-probe.json
```

All eight required components are pinned to the verified release hashes before
mapping. Unknown memory accesses stop execution. The supervisor/core-zero CPU
context is explicit. ROM data is read-only; initialized and scratch RAM is not
executable. The probe attaches no camera or physical storage.

## Native QEMU

QEMU has native GTK and SDL display backends. This work uses a Windows 11.1.0
build linked from [QEMU's download page](https://www.qemu.org/download/#windows).
The private tool package was checked against its publisher's SHA-512 and
extracted locally; no system installation is required. QEMU binaries and DLLs
are not bundled in this source-only repository.

Run the CPU control with your own QEMU executable and decoded release:

```sh
python tools/qemu_g9_probe.py --qemu /path/to/qemu-system-arm --decoded /path/to/decoded --report /new/path/qemu-control.json
```

Add `--window` to keep a native QEMU monitor window open after the controls.
**This is a developer bring-up window, not the G9 screen.** Its title says the
camera display is not implemented. Graphical-window operation is not yet
visually verified; desktop control remains paused at the owner's request.

The QEMU probe uses `-machine none`, Cortex-A7 and 256 MiB of flat fixture RAM.
The GDB link is an owned process pipe, with no listening TCP port. No default
devices, NIC, host USB or disk are attached. This fixture is deliberately
different from the strict map: it does not reproduce G9 physical memory
permissions or reject every unknown device address. Only the bounded native
leaf-routine controls are validated; it is not a camera board model.

An ordinary QEMU ARM board does not become a G9 by loading this BIN. A G9 device
model and its real framebuffer/input path are still needed. See
[QEMU's board-model explanation](https://www.qemu.org/docs/master/system/target-arm.html#choosing-a-board-model).
An empty QEMU window is not treated as successful camera emulation.
