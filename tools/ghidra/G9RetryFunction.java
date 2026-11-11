// SPDX-License-Identifier: MIT
// @category G9
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.nio.file.*;

public class G9RetryFunction extends GhidraScript {
    public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        Function f = getFunctionAt(toAddr(0x0618013c));
        if (f == null) throw new Exception("Expected timed-out function missing");
        DecompInterface d = new DecompInterface();
        boolean ok = false, warning = false;
        try {
            if (!d.openProgram(currentProgram)) throw new Exception("Cannot open decompiler");
            println("Retrying the single timed-out function with a 120-second limit.");
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            ok = r.decompileCompleted() && r.getDecompiledFunction() != null;
            if (ok) {
                String code = r.getDecompiledFunction().getC();
                warning = code.contains("WARNING:");
                Files.writeString(out.resolve("g9-retried-0618013c.c"), code);
            } else Files.writeString(out.resolve("g9-retried-0618013c-error.txt"), r.getErrorMessage());
        } finally { d.dispose(); }
        Files.writeString(out.resolve("g9-retried-0618013c.json"), "{\"entry\":\"0618013c\",\"completed\":" + ok + ",\"warnings\":" + warning + ",\"timeout_seconds\":120}\n");
        println("Single-function retry completed: " + ok);
    }
}
