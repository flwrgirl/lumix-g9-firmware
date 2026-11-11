# SPDX-License-Identifier: MIT
"""Bounded original G9 font-runtime setup and CPU rasterization controls.

This runs the firmware's own font code. It does not initialize the camera OS,
boot its menu controller, or emulate the physical display controller.
"""
import hashlib
import struct

try:
    from .probe_g9_ui import UiProbeMachine, load_descriptor
except ImportError:
    from probe_g9_ui import UiProbeMachine, load_descriptor

SRAM_RECORD = (0x00020000, 0x00020000, 0x9cc, 0x060a00e4)
FONT_INIT = 0x06bae078
FONT_DRAW = 0x06bae8d8
FONT_WORK_BASE = 0x09b20000
FONT_WORK_BYTES = 0x6a000
FONT_HEAP_BASE = 0x09b207cc
FONT_HEAP_BYTES = 0x60000
FONT_LAYOUT = 0x09b87cfc
FONT_TABLE = 0x09b89870
FONT_TEXT_TEMP = 0x09b898c0
FONT_WORK_END = FONT_TEXT_TEMP + 100


def validate_font_layout(components):
    program, post1 = components["03_program.bin"], components["05_postboot1.bin"]
    if struct.unpack_from("<4I", program, 0x140) != SRAM_RECORD:
        raise ValueError("Unexpected native startup SRAM descriptor")
    literals = {0x21ae0: 0x0a2829fc, 0x21ae4: FONT_HEAP_BASE, 0xe33c: FONT_TABLE,
                0xec5c: FONT_TEXT_TEMP, 0xec60: FONT_LAYOUT}
    for offset, expected in literals.items():
        if struct.unpack_from("<I", post1, offset)[0] != expected:
            raise ValueError("Unexpected native font-workspace declaration")
    descriptor = load_descriptor(post1, 0x06ba0000)
    state_offset = descriptor["ROM_data_start"]-0x06ba0000 + 0x0a2829fc-descriptor["RAM_data_start"]
    if struct.unpack_from("<4I", post1, state_offset) != (FONT_HEAP_BYTES, 1, 0, 0):
        raise ValueError("Unexpected initialized font-heap state")
    if FONT_HEAP_BASE+FONT_HEAP_BYTES+30000 != FONT_LAYOUT or FONT_LAYOUT+0x1b74 != FONT_TABLE:
        raise ValueError("Font workspace ranges disagree")


def text_arguments(text, width, height):
    if not isinstance(text, str) or not text or "\0" in text:
        raise ValueError("A nonempty NUL-free text control is required")
    encoded = text.encode("utf-16-le")
    if len(encoded) > 100:
        raise ValueError("Text controls are limited to 50 UTF-16 code units")
    if (not isinstance(width, int) or not isinstance(height, int)
            or not 16 <= width <= 720 or not 16 <= height <= 480):
        raise ValueError("Bitmap dimensions exceed the declared control bounds")
    return encoded + b"\0\0"


class FontRuntime(UiProbeMachine):
    def __init__(self, components):
        validate_font_layout(components)
        super().__init__(components)
        self.engine.mem_map(0x20000, 0x1000, self.uc.UC_PROT_READ | self.uc.UC_PROT_WRITE)
        self.engine.mem_write(0x20000, b"\xa5" * 0x1000)
        # The scatter zero helper uses its own ABI and clobbers r3-r6. Fresh
        # fixture r4-r6 are zero; preserve the host call context explicitly.
        saved = [self.engine.reg_read(getattr(self.arm, "UC_ARM_REG_R"+str(i))) for i in range(4, 7)]
        for i in range(4, 7):
            self.engine.reg_write(getattr(self.arm, "UC_ARM_REG_R"+str(i)), 0)
        try:
            self.call(SRAM_RECORD[3], *SRAM_RECORD[:3], seconds=5)
        finally:
            for i, value in zip(range(4, 7), saved):
                self.engine.reg_write(getattr(self.arm, "UC_ARM_REG_R"+str(i)), value)
        if self.read(0x20000, 0x9cc) != bytes(0x9cc) or self.read(0x209cc, 0x634) != b"\xa5" * 0x634:
            raise ValueError("Native SRAM clear or its boundary canary failed")
        self._ram_alias(FONT_WORK_BASE, FONT_WORK_BYTES, b"\xa5" * FONT_WORK_BYTES)
        self.lock_observations = []
        self._hook_handles.append(self.engine.hook_add(self.uc.UC_HOOK_CODE, self._lock_result,
                                                       begin=0x06bae094, end=0x06bae094))
        value = self.call(FONT_INIT, seconds=8)
        if value != 0 or any(self.word(0x0a28555c+4*i) == 0 for i in range(3)):
            raise ValueError("Original font initialization did not create its three native objects")

    def _lock_result(self, _engine, _address, _size, _user):
        self.lock_observations.append({"native_return": hex(self.engine.reg_read(self.arm.UC_ARM_REG_R0)),
                                       "meaning": "observed lock result; OS synchronization is not initialized"})

    def call_with_stack(self, entry, *arguments):
        if len(arguments) > 12:
            raise ValueError("Too many fixture arguments")
        if len(arguments) > 4:
            self.engine.mem_write(self.STACK, struct.pack("<"+"I"*(len(arguments)-4), *arguments[4:]))
        return self.call(entry, *arguments[:4], seconds=8)

    def rasterize(self, text="DC-G9", width=512, height=80):
        encoded = text_arguments(text, width, height)
        text_pointer, bitmap = 0x20004000, self.POOL+0x1000
        self.engine.mem_write(text_pointer, encoded)
        self.engine.mem_write(bitmap, bytes(width*height)+b"\xa5"*64)
        result = self.call_with_stack(FONT_DRAW, 0, text_pointer, bitmap, width, height)
        raw = self.read(bitmap, width*height)
        if result != 0 or self.invalid_accesses or self.read(bitmap+len(raw),64) != b"\xa5"*64:
            raise ValueError("Native text rasterization or its boundary check failed")
        canaries = {"SRAM_suffix": self.read(0x209cc,0x634)==b"\xa5"*0x634,
                    "font_workspace_prefix": self.read(FONT_WORK_BASE,FONT_HEAP_BASE-FONT_WORK_BASE)==b"\xa5"*(FONT_HEAP_BASE-FONT_WORK_BASE),
                    "font_workspace_suffix": self.read(FONT_WORK_END,FONT_WORK_BASE+FONT_WORK_BYTES-FONT_WORK_END)==b"\xa5"*(FONT_WORK_BASE+FONT_WORK_BYTES-FONT_WORK_END)}
        if not all(canaries.values()):
            raise ValueError("A native font workspace boundary canary changed")
        return raw, {"native_return": result, "text_control": text, "width": width, "height": height,
                     "bitmap_SHA256": hashlib.sha256(raw).hexdigest(), "nonzero_pixels": sum(bool(x) for x in raw),
                     "maximum_gray_value": max(raw), "boundary_canaries": canaries,
                     "native_lock_observations": self.lock_observations,
                     "services_stubbed": False, "camera_accessed": False, "camera_menu_running": False}
