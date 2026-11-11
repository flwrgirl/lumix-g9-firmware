// SPDX-License-Identifier: MIT
// @category G9
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import java.io.File;

public class G9PackProgram extends GhidraScript {
    public void run() throws Exception {
        File target = new File(getScriptArgs()[0]);
        if (target.exists()) throw new Exception("Refusing to overwrite packed program");
        GzfExporter exporter = new GzfExporter();
        if (!exporter.export(target, currentProgram.getDomainFile(), monitor)) throw new Exception("Packed export failed: " + exporter.getMessageLog());
        println("Saved portable Ghidra analysis: " + target);
    }
}
