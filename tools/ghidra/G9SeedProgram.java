// SPDX-License-Identifier: MIT
// @category G9
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;

public class G9SeedProgram extends GhidraScript {
    public void run() throws Exception {
        long[] entries = {0x060a0000L, 0x060a0004L, 0x060a008cL, 0x0659c2acL};
        for (long entry : entries) {
            currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
            disassemble(toAddr(entry));
        }
        clearListing(toAddr(0x060a007c), toAddr(0x060a008b));
        for (long p = 0x060a007c; p < 0x060a008c; p += 4) createData(toAddr(p), DWordDataType.dataType);
        createLabel(toAddr(0x060a0000), "g9_program_irq_vector", true);
        if (getFunctionAt(toAddr(0x060a0004)) == null) createFunction(toAddr(0x060a0004), "g9_program_cpu_startup");
        else getFunctionAt(toAddr(0x060a0004)).setName("g9_program_cpu_startup", SourceType.USER_DEFINED);
        setEOLComment(toAddr(0x060a0000), "Full decoded UPD program SHA-256 verified. Base corroborated by captured loader3 PC literal and live code prefix.");
        setEOLComment(toAddr(0x060a008c), "ARM BLX transitions into Thumb code; automatic interworking analysis follows calls.");
        println("G9 program ARM/Thumb entry points seeded at verified runtime base 0x060A0000.");
    }
}
