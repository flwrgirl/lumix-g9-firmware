# Verification and publication scope

## Reproduce the release decode

1. Obtain the update from [Panasonic](https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/g9.html).
2. Check the tested input hashes in [the recovery summary](../evidence/recovery-summary.json).
3. Run the decoder into a new local directory.
4. Run `python tools/verify_decoded.py local/decoded`.

The decoder checks the pinned BIN, outer CRC32 and every complete component digest. The independent verifier re-hashes the output files against the repository's expected manifest and checks the key bytes at their recorded main-program offset. The physical loader3 comparison provides an additional independent anchor for the decoded data.

The firmware-free tests use public block controls and synthetic invalid inputs. They check standard and reduced-round AES behavior, rejection of wrong inputs even under Python optimization, and refusal to overwrite different inspector outputs. Full-image integration requires the user's local update and is deliberately excluded from CI downloads.

## What is published

The repository contains original tools, documentation and release-level verification metadata. The component manifest contains sizes, hashes and IVs, not component contents. The documented AES key is verified against the release image and is not a per-body calibration value.

Keep these files local:

- Original or modified firmware images and decoded vendor binaries.
- Generated C-like decompilations, disassemblies and Ghidra databases.
- Camera ROM exports, calibration, serial numbers and raw memory captures.
- Extracted vendor filesystems and downloaded third-party software.

These are kept out of the prepared repository and covered by `.gitignore` for future local runs. The publication audit inspects files in the Git index for binary artifacts, oversized files, machine-specific home paths and recognizable ROM-export data. It is a focused check, not proof that arbitrary future contributions contain no private information.

## Limits of the result

Whole-component hash agreement establishes byte identity with the tested directory entries. It does not establish that generated C types are correct, that every native routine is understood, or that a modified update will be accepted. The authentication field and the camera's complete update policy remain separate research topics.
