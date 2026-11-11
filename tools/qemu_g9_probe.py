# SPDX-License-Identifier: MIT
"""Run verified G9 font-type routines inside QEMU, optionally with a native window.

This is a CPU bring-up probe using QEMU's empty machine and flat fixture RAM.
It does not boot the G9, emulate its devices, or display its original menus.
The owned QEMU process has no network, disks or camera interfaces attached.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

try:
    from .probe_g9_ui import read_components
except ImportError:
    from probe_g9_ui import read_components


def decode_rsp(raw):
    result = bytearray()
    index = 0
    while index < len(raw):
        value = raw[index]
        if value == 0x7d:
            index += 1
            if index == len(raw):
                raise ValueError("Truncated GDB escape")
            result.append(raw[index] ^ 0x20)
        elif value == 0x2a:
            index += 1
            if not result or index == len(raw) or not 3 <= raw[index] - 29 <= 97:
                raise ValueError("Invalid GDB repetition")
            result.extend(bytes([result[-1]]) * (raw[index] - 29))
        else:
            result.append(value)
        index += 1
    return bytes(result)


class GdbPipe:
    def __init__(self, process):
        self.process = process
        self.incoming = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while value := self.process.stdout.read(1):
            self.incoming.put(value)
        self.incoming.put(None)

    def _byte(self, deadline):
        try:
            value = self.incoming.get(timeout=max(0.001, deadline-time.monotonic()))
        except queue.Empty as error:
            raise TimeoutError("Owned QEMU GDB response timed out") from error
        if value is None:
            raise RuntimeError("Owned QEMU GDB pipe closed")
        return value

    def command(self, payload, timeout=8):
        if isinstance(payload, str):
            payload = payload.encode("ascii")
        if any(value in payload for value in (b"#", b"$", b"}")):
            raise ValueError("Unexpected binary GDB request")
        packet = b"$" + payload + b"#" + f"{sum(payload)&255:02x}".encode("ascii")
        self.process.stdin.write(packet); self.process.stdin.flush()
        return self.receive(timeout)

    def receive(self, timeout=8):
        deadline = time.monotonic() + timeout
        while self._byte(deadline) != b"$":
            if time.monotonic() > deadline:
                raise TimeoutError("Owned QEMU did not start a GDB response")
        raw = bytearray()
        while (value := self._byte(deadline)) != b"#":
            raw.extend(value)
            if len(raw) > 256 * 1024:
                raise ValueError("Oversized GDB response")
        checksum = self._byte(deadline) + self._byte(deadline)
        if int(checksum, 16) != sum(raw) & 255:
            raise ValueError("GDB response checksum mismatch")
        self.process.stdin.write(b"+"); self.process.stdin.flush()
        return decode_rsp(raw)

    def interrupt(self):
        self.process.stdin.write(b"\x03"); self.process.stdin.flush()
        return self.receive(timeout=3)

    def monitor(self, request):
        """Collect QEMU monitor output over the existing owned GDB pipe."""
        if not isinstance(request, str) or any(ch in request for ch in "\r\n\0"):
            raise ValueError("Expected one monitor request")
        response = self.command("qRcmd," + request.encode("utf-8").hex())
        output = bytearray()
        while response.startswith(b"O") and response != b"OK":
            output.extend(bytes.fromhex(response[1:].decode("ascii")))
            if len(output) > 65536:
                raise ValueError("Oversized monitor response")
            response = self.receive()
        if response != b"OK":
            raise ValueError("QEMU rejected the monitor request")
        return output.decode("utf-8", errors="replace")

    def select_stop_thread(self, stop):
        match=re.search(rb"(?:^|;)thread:([^;]+);",stop[3:] if stop.startswith(b"T") else stop)
        if match:
            thread=match.group(1).decode("ascii")
            if not re.fullmatch(r"p[0-9a-f]+\.[0-9a-f]+",thread):
                raise ValueError("Unexpected QEMU thread identifier")
            if self.command("Hg"+thread)!=b"OK":raise ValueError("QEMU rejected the stopped CPU selection")
            self.current_thread=thread

    def feature(self, name):
        data, offset = bytearray(), 0
        while True:
            response = self.command(f"qXfer:features:read:{name}:{offset:x},1000")
            if not response or response[:1] not in (b"m", b"l"):
                raise ValueError("QEMU did not supply the expected register description")
            data.extend(response[1:]); offset += len(response)-1
            if len(data) > 65536:
                raise ValueError("Oversized QEMU feature description")
            if response[:1] == b"l":
                return bytes(data)

    def check_register_layout(self):
        supported = self.command("qSupported:multiprocess+;qXfer:features:read+")
        if b"qXfer:features:read+" not in supported:
            raise ValueError("QEMU GDB XML register descriptions are unavailable")
        description = self.feature("target.xml")
        # GDB supplies the XInclude namespace from its own DTD. ElementTree
        # does not load that external DTD, so declare the known namespace.
        if b"xi:include" in description and b"xmlns:xi=" not in description:
            description = description.replace(b"<target", b'<target xmlns:xi="http://www.w3.org/2001/XInclude"', 1)
        root = ET.fromstring(description)
        features = [root]
        for node in root.iter():
            if node.tag.endswith("include"):
                name = node.attrib["href"]
                if "/" in name or "\\" in name or not name.endswith(".xml"):
                    raise ValueError("Unexpected QEMU register feature name")
                features.append(ET.fromstring(self.feature(name)))
        registers, current = {}, 0
        for feature in features:
            for node in feature.iter("reg"):
                current = int(node.attrib.get("regnum", current))
                registers[node.attrib["name"]] = (current, int(node.attrib["bitsize"]))
                current += 1
        for name, index in (("r0", 0), ("sp", 13), ("lr", 14), ("pc", 15), ("cpsr", 25)):
            if registers.get(name) != (index, 32):
                raise ValueError(f"Unexpected QEMU ARM register: {name}")
        self.register_layout = registers
        current=self.command("qC")
        if not current.startswith(b"QC") or not re.fullmatch(rb"p[0-9a-f]+\.[0-9a-f]+",current[2:]):
            raise ValueError("QEMU did not identify the selected CPU")
        self.current_thread=current[2:].decode("ascii")

    def set_register(self, index, value):
        if self.command(f"P{index:x}=" + struct.pack("<I", value).hex()) != b"OK":
            raise ValueError("QEMU rejected a fixture register")

    def register(self, index):
        response = self.command(f"p{index:x}")
        if len(response) != 8:
            raise ValueError("Unexpected QEMU ARM register size")
        return struct.unpack("<I", bytes.fromhex(response.decode("ascii")))[0]

    def write(self, address, data):
        if not 0x01000000 <= address <= 0x010fffff or len(data) > 4096:
            raise ValueError("GDB host writes are limited to the declared scratch fixture")
        if address + len(data) > 0x01100000:
            raise ValueError("Scratch write exceeds the fixture")
        if self.command(f"M{address:x},{len(data):x}:" + data.hex()) != b"OK":
            raise ValueError("QEMU rejected fixture memory")

    def read(self, address, length):
        if not 0 < length <= 4096:
            raise ValueError("Read outside probe size bounds")
        response = self.command(f"m{address:x},{length:x}")
        if len(response) != length * 2:
            raise ValueError("QEMU memory read failed")
        return bytes.fromhex(response.decode("ascii"))

    def call(self, entry, arguments=(), *, thumb=True, preserve_core=True):
        if len(arguments) > 12:
            raise ValueError("Too many register/stack fixture arguments")
        return_address, stack = 0x010ff000, 0x010f0000
        if not getattr(self,"_call_breakpoints_installed",False):
            if self.command(f"Z0,{return_address:x},2") != b"OK":
                raise ValueError("QEMU could not set the fixture return breakpoint")
            for vector in (4,8,12,16,24,28):
                if self.command(f"Z0,{vector:x},4") != b"OK":
                    raise ValueError("QEMU could not guard the unmodeled exception vectors")
            self._call_breakpoints_installed = True
        self.set_register(25, 0x33 if thumb else 0x13)
        self.set_register(13, stack)
        for index in range(4, 12):
            self.set_register(index, 0x55aa0000 + index)
        for index, value in enumerate((*arguments[:4], *([0] * (4-len(arguments[:4]))))):
            self.set_register(index, value)
        if len(arguments) > 4:
            self.write(stack, struct.pack("<"+"I"*(len(arguments)-4), *arguments[4:]))
        self.set_register(14, return_address | 1)
        self.set_register(15, entry)
        try:
            stop = self.command("vCont;c:"+self.current_thread, timeout=8)
            self.select_stop_thread(stop)
        except TimeoutError as error:
            self.interrupt()
            faults = {}
            for name,(number,bits) in self.register_layout.items():
                if bits == 32 and any(key in name.lower() for key in ("dfar","dfsr","ifar","ifsr")):
                    faults[name] = hex(self.register(number))
            raise TimeoutError(f"Native QEMU call {hex(entry)} exceeded its budget at PC {hex(self.register(15))}, LR {hex(self.register(14))}, SP {hex(self.register(13))}, CPSR {hex(self.register(25))}, fault registers {faults}") from error
        if stop[:3] not in (b"T05", b"S05") or self.register(15) != return_address:
            raise ValueError(f"Native QEMU call stopped outside its return breakpoint: PC={hex(self.register(15))}, LR={hex(self.register(14))}, CPSR={hex(self.register(25))}")
        if self.register(13) != stack or (preserve_core and any(self.register(i) != 0x55aa0000+i for i in range(4, 12))):
            raise ValueError("Native QEMU call changed SP or core callee-saved registers")
        return self.register(0)

    def call_font_type(self, descriptor):
        return self.call(0x06baa33a, (descriptor,))


def qemu_command(executable, directory, window=False):
    # 'none' gives a CPU and fixture RAM. It is explicitly not a G9 board.
    command = [str(executable), "-machine", "none", "-cpu", "cortex-a7", "-m", "256M",
               "-S", "-nodefaults", "-nic", "none", "-serial", "none", "-gdb", "stdio",
               "-name", "G9 CPU bring-up - camera display not implemented"]
    command += ["-display", "gtk,gl=off" if window else "none", "-monitor", "vc" if window else "none"]
    for name, base in (("03_program.bin", 0x060a0000), ("05_postboot1.bin", 0x06ba0000)):
        image = str((Path(directory) / name).resolve())
        if "," in image:
            raise ValueError("A loader path containing a comma is unsupported")
        command += ["-device", f"loader,file={image},addr={hex(base)},force-raw=on"]
    return command


def run(executable, directory, output, window=False):
    components = read_components(directory)  # Validate before starting QEMU.
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=True,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0).stdout.splitlines()[0]
    log_path = output.with_suffix(".qemu.log")
    if log_path.exists():
        raise ValueError("QEMU log path already exists")
    with log_path.open("xb") as log:
        process = subprocess.Popen(qemu_command(executable, directory, window), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=log,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            pipe = GdbPipe(process)
            pipe.check_register_layout()
            descriptor, scratch = 0x01001000, 0x01002000
            original_code = pipe.read(0x06baa33a, 96)
            if original_code != components["05_postboot1.bin"][0xa33a:0xa33a+96]:
                raise ValueError("QEMU did not load the verified native code at its intended address")
            controls = []
            for name, payload, pointer, expected in [
                    ("embedded_release_font", None, 0x06d404c4, 0),
                    ("release_font_header_in_scratch", components["16_osdover.bin"][:64], scratch, 0),
                    ("synthetic_BDF_type_control", b"STARTFONT 2.1\n", scratch, 1),
                    ("synthetic_unknown_type_control", b"not a font file\0", scratch, 4),
                    ("short_length_control", b"FDL Font", scratch, 4)]:
                if payload is not None:
                    pipe.write(scratch, payload)
                pipe.write(descriptor, struct.pack("<II", pointer, len(payload) if payload is not None else 32))
                actual = pipe.call_font_type(descriptor)
                if actual != expected:
                    raise ValueError(f"Native QEMU type-control mismatch: {name}: {actual}")
                controls.append({"case": name, "native_return": actual, "expected_return": expected})
                print(json.dumps(controls[-1]), flush=True)
            if pipe.read(0x06baa33a, 96) != original_code:
                raise ValueError("The probed QEMU code bytes changed")
            report = {"scope": "actual G9 routine execution in QEMU; no camera board or UI emulation",
                      "QEMU": version, "machine": "none", "CPU": "cortex-a7", "fixture_RAM_bytes": 268435456,
                      "native_entry": "0x06baa33a", "controls": controls, "all_expected_results_observed": True,
                      "core_callee_saved_registers_and_SP_preserved": True, "probed_code_bytes_unchanged": True,
                      "camera_accessed": False, "host_devices_attached": False, "network_attached": False,
                      "display_controller_emulated": False, "camera_booted": False,
                      "original_framebuffer_produced": False, "native_window_requested": window}
            with output.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(report, handle, indent=2); handle.write("\n")
            if window:
                print("QEMU's native monitor window is open. The G9 display hardware is not implemented; this is not a camera UI. Close the QEMU window to finish.", flush=True)
                process.wait()
            return report
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdin.close(); process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--decoded", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--window", action="store_true", help="Keep a native QEMU monitor window open after the CPU controls")
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Report path already exists")
    if not args.qemu.is_file():
        parser.error("QEMU executable was not found")
    report = run(args.qemu, args.decoded, args.report, args.window)
    print(json.dumps({"controls_passed": len(report["controls"]), "camera_booted": False,
                      "original_framebuffer_produced": False}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
