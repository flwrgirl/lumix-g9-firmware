# SPDX-License-Identifier: MIT
"""Present guest-produced grayscale pixels on QEMU's native PL110 console.

This presentation adapter uses VersatilePB's controller. It is not the G9 LCD
controller, a menu implementation, or an input bridge.
"""
import struct

FRAMEBUFFER = 0x0f000000
FRAMEBUFFER_BYTES = 0x200000
PL110 = 0x10120000


def gray_to_xrgb(raw, width, height):
    if (not isinstance(width, int) or not isinstance(height, int)
            or not 16 <= width <= 720 or width % 16 or not 16 <= height <= 480
            or len(raw) != width*height or max(raw) > 15):
        raise ValueError("Expected bounded 4-bit native pixels and a PL110-aligned width")
    pixels = bytearray(len(raw)*4)
    for index, value in enumerate(raw):
        gray = value*17
        pixels[index*4:index*4+4] = bytes((gray,gray,gray,0))
    return bytes(pixels)


def controller_registers(width, height):
    if (not isinstance(width,int) or not isinstance(height,int)
            or not 16 <= width <= 720 or width % 16 or not 16 <= height <= 480):
        raise ValueError("Unsupported presentation dimensions")
    # VersatilePB uses the modified PL110 control register at +0x18.
    return ((0,((width//16)-1)<<2),(4,height-1),(0x10,FRAMEBUFFER),
            (0x14,FRAMEBUFFER),(0x18,0x82b))


def present(pipe, raw, width, height):
    pixels = gray_to_xrgb(raw,width,height)
    if len(pixels) > FRAMEBUFFER_BYTES:
        raise ValueError("Framebuffer exceeds the presentation allocation")
    for offset in range(0,len(pixels),4096):
        data = pixels[offset:offset+4096]
        if pipe.command(f"M{FRAMEBUFFER+offset:x},{len(data):x}:"+data.hex()) != b"OK":
            raise ValueError("QEMU rejected presentation pixels")
    for offset,value in controller_registers(width,height):
        if pipe.command(f"M{PL110+offset:x},4:"+struct.pack("<I",value).hex()) != b"OK":
            raise ValueError("QEMU rejected the presentation controller configuration")
    return {"controller":"VersatilePB PL110 presentation adapter", "width":width,
            "height":height,"camera_LCD_controller_emulated":False}
