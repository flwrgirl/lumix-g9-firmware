# SPDX-License-Identifier: MIT
"""Produce a bitmap with the original G9 CPU text rasterizer.

This is a text-rendering control, not the camera menu UI. Both CPU engines use
declared single-thread fixtures; the real OS synchronization is not initialized.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib

try:
    from .font_runtime import (FontRuntime, FONT_INIT, FONT_DRAW, FONT_WORK_BASE, FONT_WORK_BYTES,
                               FONT_HEAP_BASE, FONT_WORK_END, SRAM_RECORD, text_arguments, validate_font_layout)
    from .probe_g9_ui import read_components, load_descriptor
    from .qemu_g9_probe import GdbPipe, qemu_command
    from .qemu_display import present
except ImportError:
    from font_runtime import (FontRuntime, FONT_INIT, FONT_DRAW, FONT_WORK_BASE, FONT_WORK_BYTES,
                              FONT_HEAP_BASE, FONT_WORK_END, SRAM_RECORD, text_arguments, validate_font_layout)
    from probe_g9_ui import read_components, load_descriptor
    from qemu_g9_probe import GdbPipe, qemu_command
    from qemu_display import present


def png_grayscale(raw, width, height):
    if len(raw) != width*height or not width or not height or max(raw) > 15:
        raise ValueError("Expected a complete 4-bit native gray bitmap")
    def chunk(kind, data):
        return struct.pack(">I",len(data)) + kind + data + struct.pack(">I",zlib.crc32(kind+data)&0xffffffff)
    pixels = bytes(value*17 for value in raw)
    scanlines = b"".join(b"\0"+pixels[row*width:(row+1)*width] for row in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR",struct.pack(">IIBBBBB",width,height,8,0,0,0,0))
            + chunk(b"IDAT",zlib.compress(scanlines)) + chunk(b"IEND",b""))


def ram_initializers(components):
    """Derived initial RAM bytes; these are not modified camera update files."""
    validate_font_layout(components)
    program, post1 = components["03_program.bin"], components["05_postboot1.bin"]
    source, target, length, copy = struct.unpack_from("<4I", program, 0x100)
    if (source,target,length,copy) != (0x06a3aa94,0x081a0000,0x34ee4,0x060a00c8):
        raise ValueError("Unexpected main data-copy descriptor")
    descriptor = load_descriptor(post1,0x06ba0000)
    return [("main-initial-data.ram",target,program[source-0x060a0000:source-0x060a0000+length]),
            ("postboot1-initial-data.ram",descriptor["RAM_data_start"],
             post1[descriptor["ROM_data_start"]-0x06ba0000:descriptor["ROM_data_end"]-0x06ba0000]),
            ("low-SRAM-canaries.ram",0x00020000,b"\xa5"*0x1000),
            ("font-workspace.ram",FONT_WORK_BASE,b"\xa5"*FONT_WORK_BYTES)]


def read_bytes(pipe, address, length):
    return b"".join(pipe.read(address+offset,min(4096,length-offset)) for offset in range(0,length,4096))


def qemu_rasterize(executable, decoded, components, directory, text, width, height, native_display=False, window=False):
    encoded = text_arguments(text,width,height)
    command = qemu_command(executable,decoded)
    if native_display or window:
        command[command.index("-machine")+1] = "versatilepb"
        command[command.index("-display")+1] = "gtk,gl=off" if window else "none"
        command[command.index("-name")+1] = "G9 native font control - menus not booted"
        command += ["-audiodev","none,id=g9silent","-global","pl041.audiodev=g9silent"]
    for name,address,data in ram_initializers(components):
        path = (directory/name).resolve()
        if "," in str(path):
            raise ValueError("A loader path containing a comma is unsupported")
        with path.open("xb") as handle:
            handle.write(data)
        command += ["-device",f"loader,file={path},addr={hex(address)},force-raw=on"]
    with (directory/"qemu.log").open("xb") as log:
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
        try:
            pipe = GdbPipe(process)
            pipe.check_register_layout()
            # Host CPU fixture, not replacement firmware: enable CP10/CP11 and
            # FPEXC before entering native code, matching the strict engine.
            fpu_fixture = struct.pack("<8I",0xee110f50,0xe380060f,0xee010f50,0xf57ff06f,
                                      0xeef80a10,0xe3800101,0xeee80a10,0xe12fff1e)
            pipe.write(0x01000000,fpu_fixture)
            pipe.call(0x01000000,thumb=False)
            code_before = pipe.read(FONT_DRAW,96)
            if code_before != components["05_postboot1.bin"][FONT_DRAW-0x06ba0000:FONT_DRAW-0x06ba0000+96]:
                raise ValueError("QEMU code bytes do not match the original rasterizer")
            print(json.dumps({"starting":"native_SRAM_clear"}),flush=True)
            pipe.call(SRAM_RECORD[3],SRAM_RECORD[:3],preserve_core=False)
            if read_bytes(pipe,0x20000,0x9cc) != bytes(0x9cc):
                raise ValueError("QEMU native SRAM clear failed")
            print(json.dumps({"starting":"native_font_initialization"}),flush=True)
            result = pipe.call(FONT_INIT)
            handles = [struct.unpack("<I",pipe.read(0x0a28555c+i*4,4))[0] for i in range(3)]
            if result or not all(handles):
                raise ValueError("QEMU original font initialization failed")
            mutex_id = struct.unpack_from("<I",components["03_program.bin"],0x06894ce0-0x060a0000)[0]
            lock_result = pipe.call(0x063f7098,(mutex_id,))
            text_pointer,bitmap = 0x01002000,0x01010000
            pipe.write(text_pointer,encoded)
            pipe.write(bitmap+width*height,b"\xa5"*64)
            print(json.dumps({"starting":"native_font_rasterizer"}),flush=True)
            result = pipe.call(FONT_DRAW,(0,text_pointer,bitmap,width,height))
            raw = read_bytes(pipe,bitmap,width*height)
            canaries = {"SRAM_suffix":read_bytes(pipe,0x209cc,0x634)==b"\xa5"*0x634,
                        "bitmap_suffix":pipe.read(bitmap+len(raw),64)==b"\xa5"*64,
                        "font_workspace_prefix":read_bytes(pipe,FONT_WORK_BASE,FONT_HEAP_BASE-FONT_WORK_BASE)==b"\xa5"*(FONT_HEAP_BASE-FONT_WORK_BASE),
                        "font_workspace_suffix":read_bytes(pipe,FONT_WORK_END,FONT_WORK_BASE+FONT_WORK_BYTES-FONT_WORK_END)==b"\xa5"*(FONT_WORK_BASE+FONT_WORK_BYTES-FONT_WORK_END)}
            if result or not all(canaries.values()) or pipe.read(FONT_DRAW,96)!=code_before:
                raise ValueError("QEMU rasterizer return, boundaries or code-byte control failed")
            report={"native_return":result,"text_control":text,"width":width,"height":height,
                        "bitmap_SHA256":hashlib.sha256(raw).hexdigest(),"nonzero_pixels":sum(bool(x) for x in raw),
                        "maximum_gray_value":max(raw),"boundary_canaries":canaries,
                        "native_lock_observations":[{"native_return":hex(lock_result),"meaning":"OS synchronization remains uninitialized"}],
                        "services_stubbed":False,"camera_accessed":False,"camera_menu_running":False,
                        "fixture_RAM_model":"Flat fixture RAM; no camera hardware model"}
            if native_display or window:
                report["native_presentation"] = present(pipe,raw,width,height)
                capture=(directory/"display.ppm").resolve()
                if '"' in str(capture): raise ValueError("Unsupported capture path")
                monitor_output=pipe.monitor(f'screendump "{capture.as_posix()}"')
                if monitor_output or not capture.is_file():
                    raise ValueError("QEMU did not capture its native graphical console")
                observed=capture.read_bytes()
                expected=(f"P6\n{width} {height}\n255\n".encode()
                          + b"".join(bytes((value*17,)*3) for value in raw))
                if observed != expected:
                    raise ValueError("QEMU console pixels do not match the original rasterizer bitmap")
                report["native_display_pixel_equality"] = True
                if window:
                    print("Native font pixels are on QEMU's graphical console. Camera menus are not booted. Close QEMU to finish.",flush=True)
                    process.wait()
            return raw,report
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdin.close(); process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded",type=Path)
    parser.add_argument("--out",type=Path,required=True,help="New private output directory")
    parser.add_argument("--qemu",type=Path,help="Use this QEMU executable; otherwise use Unicorn")
    parser.add_argument("--native-display",action="store_true",help="Verify native QEMU console pixels headlessly")
    parser.add_argument("--window",action="store_true",help="Keep the native QEMU graphical console open")
    parser.add_argument("--text",default="DC-G9")
    parser.add_argument("--width",type=int,default=512)
    parser.add_argument("--height",type=int,default=80)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Output directory already exists")
    if (args.native_display or args.window) and not args.qemu:
        parser.error("Native display requires --qemu")
    if (args.native_display or args.window) and args.width % 16:
        parser.error("The presentation controller requires a width divisible by 16")
    text_arguments(args.text,args.width,args.height)
    components = read_components(args.decoded)
    validate_font_layout(components)
    args.out.mkdir(parents=True,exist_ok=False)
    if args.qemu:
        raw,report = qemu_rasterize(args.qemu,args.decoded,components,args.out,args.text,args.width,args.height,
                                   args.native_display,args.window)
        report["engine"]="QEMU"
    else:
        raw,report = FontRuntime(components).rasterize(args.text,args.width,args.height)
        report["engine"]="Unicorn"
    report["scope"]="Original G9 text rasterization control; not a running camera menu"
    (args.out/"bitmap.raw").write_bytes(raw)
    (args.out/"bitmap.png").write_bytes(png_grayscale(raw,args.width,args.height))
    with (args.out/"report.json").open("x",encoding="utf-8",newline="\n") as handle:
        json.dump(report,handle,indent=2); handle.write("\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    try:
        main()
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
