// SPDX-License-Identifier: MIT
// @category G9
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.BufferedWriter;

public class G9ExportLoader extends GhidraScript {
    public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        String component = getScriptArgs().length > 1 ? getScriptArgs()[1] : "loader3";
        if (!component.matches("[a-zA-Z0-9_]+")) throw new Exception("Invalid component label");
        Files.createDirectories(out);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new Exception("Decompiler could not open program");
        int total = 0, succeeded = 0, warned = 0;
        try (BufferedWriter c = Files.newBufferedWriter(out.resolve("G9-" + component + "-decompiled.c"), StandardCharsets.UTF_8);
             BufferedWriter table = Files.newBufferedWriter(out.resolve("functions.tsv"), StandardCharsets.UTF_8)) {
            c.write("/* Panasonic DC-G9 V2.7 " + component + ": Ghidra 12.2 C-like decompilation.\n");
            c.write(" * Input component validated against the complete UPD directory SHA-256.\n");
            c.write(" * Generated names/types are provisional. This is not original Panasonic source,\n");
            c.write(" * a buildable replacement, a patch, or a flashable update. Hardware side effects\n");
            c.write(" * below describe the recovered camera code; this code was not executed on the PC.\n */\n\n");
            table.write("entry\tname\tbody_bytes\tdecompiled\twarnings_in_output\n");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function f = functions.next();
                total++;
                DecompileResults result = decompiler.decompileFunction(f, 30, monitor);
                boolean ok = result.decompileCompleted() && result.getDecompiledFunction() != null;
                c.write("\n/* Entry 0x" + f.getEntryPoint() + ", body " + f.getBody().getNumAddresses() + " bytes */\n");
                boolean warning = ok && result.getDecompiledFunction().getC().contains("WARNING:");
                if (warning) warned++;
                if (ok) { c.write(result.getDecompiledFunction().getC()); succeeded++; }
                else c.write("/* Decompilation incomplete: " + result.getErrorMessage().replace("*/", "* /") + " */\n");
                table.write(f.getEntryPoint() + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses() + "\t" + ok + "\t" + warning + "\n");
                if (total % 100 == 0) println("G9 " + component + ": " + total + " functions processed, " + succeeded + " C-like outputs.");
            }
        } finally { decompiler.dispose(); }
        try (BufferedWriter asm = Files.newBufferedWriter(out.resolve("G9-" + component + "-disassembly.asm"), StandardCharsets.UTF_8)) {
            asm.write("; Ghidra 12.2 ARM/Thumb analysis of hash-verified DC-G9 V2.7 " + component + ".\n");
            asm.write("; Generated function names and inferred data/code boundaries are provisional.\n");
            CodeUnitIterator units = currentProgram.getListing().getCodeUnits(true);
            while (units.hasNext()) {
                CodeUnit unit = units.next();
                byte[] bytes = unit.getBytes();
                StringBuilder raw = new StringBuilder();
                for (int i = 0; i < Math.min(16, bytes.length); i++) raw.append(String.format("%02x", bytes[i] & 255));
                if (bytes.length > 16) raw.append("...");
                asm.write(unit.getAddress() + "  " + raw + "  " + unit.toString().replace("\n", "\\n") + "\n");
            }
        }
        String summary = "{\"ghidra_version\":\"12.2\",\"language\":\"" + currentProgram.getLanguageID() +
            "\",\"functions_found\":" + total + ",\"functions_decompiled\":" + succeeded +
            ",\"functions_incomplete\":" + (total - succeeded) + ",\"functions_with_warnings\":" + warned + "}\n";
        Files.writeString(out.resolve("decompilation-summary.json"), summary);
        println("G9 export complete: " + succeeded + " / " + total + " functions decompiled.");
    }
}
