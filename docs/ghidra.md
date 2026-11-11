# Reproducing Ghidra analysis

The recorded runs used Ghidra 12.2, JDK 25, language `ARM:LE:32:v7` and compiler specification `default`. Obtain Ghidra from its [official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build); analysis software is not bundled.

First decode and verify your own local input. Import these raw components at their corroborated CPU bases:

| Component | File | CPU base | Seed script |
| --- | --- | --- | --- |
| Main program | `03_program.bin` | `0x060A0000` | `G9SeedProgram.java` |
| Bootstrap loader3 | `02_loader3.bin` | `0x00000000` | `G9SeedLoader.java` |

Keep the distinction between CPU bases and the UPD directory destination fields. The seed scripts label actual startup/interrupt entry points and define known literal pools as data. ARM-to-Thumb interworking is followed by Ghidra's analysis.

Example PowerShell command from the repository root, using new local output paths:

```powershell
$ghidraPath = 'C:\tools\ghidra_12.2_PUBLIC'
New-Item -ItemType Directory -Force local/ghidra-projects | Out-Null
& "$ghidraPath/support/analyzeHeadless.bat" local/ghidra-projects G9-program `
  -import local/decoded/03_program.bin -loader BinaryLoader `
  -loader-baseAddr 0x060A0000 -processor ARM:LE:32:v7 -cspec default `
  -analysisTimeoutPerFile 600 -scriptPath tools/ghidra `
  -preScript G9SeedProgram.java `
  -postScript G9ExportLoader.java local/program-analysis program
```

The exporter produces C-like text, a native listing, a function table and a summary. Use a new output folder; generated vendor code and databases belong under ignored `local/` paths. For loader3, change the input, base, seed script, project name and output directory; the exporter's component label defaults to `loader3`.

After the first process has saved and closed the project, a separate read-only pass can produce a portable Ghidra file:

```powershell
& "$ghidraPath/support/analyzeHeadless.bat" local/ghidra-projects G9-program `
  -process 03_program.bin -readOnly -noanalysis -scriptPath tools/ghidra `
  -postScript G9PackProgram.java local/program-analysis/G9-program.gzf
```

The pack script exports the saved domain file. Exporting the live domain object from an active script transaction failed in the recorded run.

## Recorded coverage

The main-program analysis identified 24,628 functions and produced C-like output for 24,627; 832 outputs contained warnings. The function at `0x0618013C` exceeded both the initial 30-second and extended 120-second limits. Its instructions remain available for manual analysis. Loader3 produced output for all 123 identified functions, with warnings in 17.

Function names, types and boundaries are inferred. Missing references may point to overlay modules outside a single imported component. These outputs are not original Panasonic source files or a buildable replacement. See [the recorded counts](../evidence/recovery-summary.json).
