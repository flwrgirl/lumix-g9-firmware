# G9 update-directory authentication

The later [emulation checkpoint](emulation.md) extends the isolated wrapper below
to the full in-memory decoder and install decisions with modeled storage. Physical
update acceptance, boot and recovery remain unproven.

The 64-byte field at `0x220` is an **ECDSA P-256 signature**. The original passes
three checks: independent point arithmetic, OpenSSL, and emulation of the
recovered G9 verification routine.

| Item | G9 V2.7 value |
| --- | --- |
| Signed range | `[0x2A0, 0x1488)`, 4,584 bytes |
| Signed contents | Repeated header, directory header and all 49 records |
| Digest | SHA-256 `c4292299398a8c9192d2e0991f36822feb62ec30f3016638cbf147a6a31b2a6b` |
| Public key | Main-program offset `0x00887E62`, linked address `0x06927E62`, 64 bytes |
| Key SHA-256 | `3586201218ceed68666470175aea0f6011a22c0be265cff6aa5de7012d81d1a3` |
| Profile | Linked address `0x06927EA4`; length/pointer at profile `+0x54/+0x58` |
| Representation | Little-endian 32-byte `x`, `y`, `r`, `s`; digest integer also little endian |

The profile references `ecdsa-p256` and `panasonic` and is passed by the actual
update job. The tools extract the key and signature from the local verified
release. Vendor code is not bundled here.

## Reproduce

```sh
python tools/verify_update_signature.py path/to/G9___V27.zip local/decoded/03_program.bin --report local/signature-proof.json
```

Add `--openssl path/to/openssl` for the independent implementation. OpenSSL gets
a standard P-256 public key and DER signature, with the precomputed digest
reversed to preserve the G9 integer convention. The tested version is 3.5.5.
The original passes; an actual bit change in the first component's signed hash,
and a signature bit change, both fail. Point arithmetic also passes the public
P-256/SHA-256 `sample` vector from [RFC 6979 A.2.5](https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5).
See [signature evidence](../evidence/signature-summary.json).

For the recovered native wrapper:

```sh
python -m pip install -r tools/build-probe/requirements.txt
python tools/emulate_update_signature.py path/to/G9___V27.zip local/decoded/03_program.bin --report local/native-signature-proof.json
```

This maps release code read/execute, initialized data, zeroed RAM and scratch
memory. Emulated VFP/NEON is enabled because the real memory helpers use it.
There are no instruction patches, return stubs or hardware memory mappings.
Each case has five-second and 200-million-instruction limits.

| Control | Native wrapper return | Caller interpretation |
| --- | ---: | --- |
| Original hash/signature | 0 | Success |
| Changed signed component hash | 1 | Failure |
| Changed signature | 1 | Failure |

All calls returned normally, preserved SP, `r4`–`r11` and `d8`–`d15`, and made no
unmapped accesses. This is isolated crypto-routine emulation, not complete
updater, installation or boot emulation. See [native evidence](../evidence/native-signature-summary.json).

## Static path and remaining limits

```text
update job 0x0622CDA0
  -> decoder call 0x0622CEB6 -> 0x06233C3E
     -> directory hash call 0x06233A04 -> 0x06544600
     -> signature call 0x06233A1E -> 0x0652633E
        -> elliptic-curve verification 0x065711BE
```

The decoder hashes `count * 0x5C + 0x4C` bytes from inner offset `0xA0`, copies
the profile's public key, and checks the signature at inner offset `0x20`.
These operands agree with the independently verified file ranges. Plaintext
component hashes are checked later on the signed path.

The job samples a policy byte at `0x081C3444`. Its startup copy maps release
offset `0x009BDED8` to this RAM byte, initially one. The same descriptor maps the
proven AES key at offset `0x009C8F10` to the job's key pointer `0x081CE47C`,
corroborating the mapping. A zero sampled policy enables a context allowance,
and the decoder has a zero-marker branch gated by that allowance. Another
boot-information condition also affects verification. Those branches and later
installation/boot requirements have not been fully modeled or physically tested.

This establishes the signed format and native crypto behavior. It does not
establish an accepted modified update, complete bypass or hard-brick recovery.
No camera RAM, firmware, EEPROM or settings were changed. See [static trace metadata](../evidence/authentication-trace.json).

References: [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) and the
[older-model signature research](https://github.com/flickering-star/lumix-firmware-research/blob/main/evidence/gm5-directory-signature.json),
which supplied the endian/range lead. The G9 key and original signature were
independently checked against this build.
