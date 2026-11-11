// SPDX-License-Identifier: MIT
// @category G9
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.DWordDataType;

public class G9SeedLoader extends GhidraScript {
    public void run() throws Exception {
        long[] entries = {0, 4, 8, 12, 16, 20, 24, 28, 0x74};
        for (long entry : entries) {
            currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
            disassemble(toAddr(entry));
        }
        // These words are proven PC-relative constants, not fall-through code.
        // The fault-handler store at 0x484 has hardware-dependent continuation.
        clearListing(toAddr(0x488), toAddr(0x4f3));
        for (long p = 0x488; p < 0x4f4; p += 4) createData(toAddr(p), DWordDataType.dataType);
        setEOLComment(toAddr(0x484), "Hardware-dependent continuation; the following verified literal pool is data.");
        if (getFunctionAt(toAddr(0x74)) == null) createFunction(toAddr(0x74), "g9_arm_reset_entry");
        else getFunctionAt(toAddr(0x74)).setName("g9_arm_reset_entry", SourceType.USER_DEFINED);
        createLabel(toAddr(0), "g9_reset_vector", true);
        setEOLComment(toAddr(0), "Physical G9 loader3 readback. Complete SHA-256 matches the V2.7 directory.");
        setEOLComment(toAddr(0x70), "Indirect ARM branch to 0x060A0000 via literal 0x488; external target not acquired here.");
        setEOLComment(toAddr(0x130), "Zero-init range 0xD1C4..0xE304 from verified startup instructions.");
        setEOLComment(toAddr(0x170), "Copies initialized data from 0xA2A0 to 0xD000..0xD1C4.");
        println("G9 ARM reset/vector entry points seeded; no emulation or hardware access.");
    }
}
