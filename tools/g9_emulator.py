# SPDX-License-Identifier: MIT
"""Isolated native G9 routines with bounded execution and explicit memory maps."""
import hashlib
import struct
import time

try:
    from .verify_update_signature import PROGRAM_BASE, PROGRAM_SHA256
except ImportError:
    from verify_update_signature import PROGRAM_BASE, PROGRAM_SHA256


class EmulationFault(RuntimeError):
    pass


class G9Machine:
    CONTEXT = 0x20001000
    POOL = 0x10000000
    POOL_BYTES = 0x100000
    STACK = 0x201f0000
    RETURN = 0x201ff000
    OBSERVERS = {0x06544600: "directory_SHA256", 0x0652633e: "ECDSA",
                 0x065445ca: "SHA256_finalize", 0x06233d04: "progress"}

    def __init__(self, program, image, image_address=0x30000000, progress=None):
        if hashlib.sha256(program).hexdigest() != PROGRAM_SHA256:
            raise ValueError("Not the verified G9 main program")
        if not 512 <= len(image) <= 81952256:
            raise ValueError("Guest image size outside control bounds")
        if image_address not in (0x30000000, 0xb0000000):
            raise ValueError("Unsupported guest image fixture address")
        try:
            import unicorn as uc
            from unicorn import arm_const as arm
        except ImportError as error:
            raise ValueError("Install tools/build-probe/requirements.txt for optional emulation") from error
        self.uc, self.arm, self.image_address, self.image_bytes = uc, arm, image_address, len(image)
        self.engine = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB)
        e = self.engine
        e.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
        e.reg_write(arm.UC_ARM_REG_C1_C0_2, 0x00f00000)
        e.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
        e.mem_map(PROGRAM_BASE, len(program), uc.UC_PROT_ALL)
        e.mem_write(PROGRAM_BASE, program)
        e.mem_protect(PROGRAM_BASE, len(program), uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        e.mem_map(0x081a0000, 0x720000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        source, target, length, routine = struct.unpack_from("<IIII", program, 0x100)
        if (source, target, length, routine) != (0x06a3aa94, 0x081a0000, 0x34ee4, 0x060a00c8):
            raise ValueError("Unexpected startup copy descriptor")
        e.mem_write(target, program[source - PROGRAM_BASE:source - PROGRAM_BASE + length])
        e.mem_map(self.POOL, self.POOL_BYTES, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        e.mem_map(0x20000000, 0x200000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        e.mem_map(image_address, (len(image) + 0xfff) & ~0xfff, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        e.mem_write(image_address, bytes(image))
        e.reg_write(arm.UC_ARM_REG_CPSR, 0x30)
        self.visits, self.invalid_accesses, self.environment_calls = {}, [], []
        self.progress, self.calls, self.callback_fault = progress, [], None
        self._hook_handles = []
        e.hook_add(uc.UC_HOOK_MEM_INVALID, self._invalid)
        for address, label in self.OBSERVERS.items():
            def observe(_e, _a, _s, _u, name=label):
                self.visits[name] = self.visits.get(name, 0) + 1
            self._hook_handles.append(e.hook_add(uc.UC_HOOK_CODE, observe, begin=address, end=address))

    def _invalid(self, _e, access, address, size, _value, _user_data):
        self.invalid_accesses.append({"PC": hex(self.engine.reg_read(self.arm.UC_ARM_REG_PC)),
                                      "access": access, "address": hex(address), "bytes": size})
        return False

    def read(self, address, size):
        return bytes(self.engine.mem_read(address, size)) if size else b""

    def word(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def write_word(self, address, value):
        self.engine.mem_write(address, struct.pack("<I", value))

    def hook_service(self, address, name, callback):
        """Explicitly model an external service; never install hidden fallbacks."""
        def dispatch(_e, _a, _s, _u):
            registers = [self.arm.UC_ARM_REG_R0, self.arm.UC_ARM_REG_R1,
                         self.arm.UC_ARM_REG_R2, self.arm.UC_ARM_REG_R3]
            args = [self.engine.reg_read(r) for r in registers]
            event = {"service": name, "address": hex(address), "arguments": [hex(v) for v in args]}
            self.environment_calls.append(event)
            try:
                value = callback(self, args, event)
            except Exception as error:
                self.callback_fault = error
                self.engine.emu_stop()
                return
            self.engine.reg_write(self.arm.UC_ARM_REG_R0, value & 0xffffffff)
            self.engine.reg_write(self.arm.UC_ARM_REG_PC, self.engine.reg_read(self.arm.UC_ARM_REG_LR))
        handle = self.engine.hook_add(self.uc.UC_HOOK_CODE, dispatch, begin=address, end=address)
        self._hook_handles.append(handle)

    def call(self, address, *args, seconds=240):
        e, arm = self.engine, self.arm
        if len(args) > 4:
            raise ValueError("Only register arguments are supported by this host call helper")
        for register, value in zip((arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3),
                                   [*args, *([0] * (4 - len(args)))]):
            e.reg_write(register, value)
        e.reg_write(arm.UC_ARM_REG_SP, self.STACK)
        e.reg_write(arm.UC_ARM_REG_LR, self.RETURN | 1)
        saved = [getattr(arm, "UC_ARM_REG_R" + str(i)) for i in range(4, 12)]
        saved += [getattr(arm, "UC_ARM_REG_D" + str(i)) for i in range(8, 16)]
        values = [e.reg_read(r) for r in saved]
        start = last = time.monotonic()
        pc, chunks = address | 1, 0
        while True:
            try:
                e.emu_start(pc, self.RETURN, timeout=5000000, count=100000000)
            except self.uc.UcError as error:
                raise EmulationFault(f"Native execution failed at {hex(e.reg_read(arm.UC_ARM_REG_PC))}: {error}; {self.invalid_accesses}") from error
            chunks += 1
            if self.callback_fault is not None:
                raise self.callback_fault
            pc = e.reg_read(arm.UC_ARM_REG_PC)
            if pc == self.RETURN:
                break
            now = time.monotonic()
            if now - start > seconds or chunks > 300:
                raise EmulationFault("Native execution exceeded its time/instruction budget")
            if self.progress and now - last >= 10:
                self.progress({"function": hex(address), "seconds": round(now - start, 1),
                               "instruction_chunks": chunks, "PC": hex(pc), "native_visits": dict(self.visits)})
                last = now
            pc |= (e.reg_read(arm.UC_ARM_REG_CPSR) >> 5) & 1
        if e.reg_read(arm.UC_ARM_REG_SP) != self.STACK or any(e.reg_read(r) != v for r, v in zip(saved, values)):
            raise EmulationFault("Native call did not preserve SP/callee-saved registers")
        value = e.reg_read(arm.UC_ARM_REG_R0)
        self.calls.append({"address": hex(address), "return_value": hex(value),
                           "seconds": round(time.monotonic() - start, 3), "instruction_chunks": chunks})
        return value

    def initialize_decoder(self, unsigned_allowance=False):
        context = self.CONTEXT
        setup = [(0x06233344, (context,)),
                 (0x0623339a, (context, self.POOL, self.POOL_BYTES)),
                 (0x0623337e, (context, self.image_address, self.image_bytes)),
                 (0x062333b8, (context, 0x081ce47c, 16)),
                 (0x06233c72, (context, 0x06927ea4))]
        for address, args in setup:
            if self.call(address, *args) != 0:
                raise EmulationFault("Native decoder initialization failed")
        if unsigned_allowance:
            self.engine.mem_write(context + 0x68, b"\x01")
        return self.call(0x062333e2, context)

    def component_hashes(self, source_image):
        count = struct.unpack_from("<I", source_image, 0x2e8)[0]
        if not 1 <= count <= 49:
            raise ValueError("Unexpected fixture component count")
        rows = []
        for index in range(count):
            entry = 0x2ec + index * 0x5c
            name = source_image[entry:entry + 12].rstrip(b"\0").decode("ascii")
            relative, size = struct.unpack_from("<II", source_image, entry + 12)
            offset = relative + 0x200
            if offset > len(source_image) or size > len(source_image) - offset:
                raise ValueError("Fixture component escapes guest input")
            digest = hashlib.sha256(self.read(self.image_address + offset, size)).hexdigest()
            rows.append({"index": index, "name": name, "bytes": size, "SHA256": digest,
                         "matches_directory": digest == source_image[entry + 28:entry + 60].hex()})
        return rows
