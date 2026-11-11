# Recovery method

## Establishing a G9 read control

The tested body reported DC-G9 firmware 2.7. Its temporary diagnostic USB identity was `04DA:2370`, interface zero, alternate zero, class/subclass/protocol `FF/A0/B0`. The observed endpoints were bulk OUT `01`, bulk IN `82` and interrupt IN `83`. Microsoft's WinUSB driver was used for the diagnostic identity.

Legacy word-read operation `38`, fixed area `22`, was checked against the camera's own saved settings export. A 64-byte manufacturer/model window at words `E000..E01F` matched byte for byte. Device-specific exports and calibration bytes are not included here.

Absolute halfword operation `9B` and class-one block operation `5C` were then compared at the same addresses. A one-kilobyte page at `0x00080000` was stable but patterned; it was not accepted as executable firmware. Older program-relative reads from the `0x40000000` region returned zeros. Neither result supplied a G9 program mapping.

## Recovering a complete component

CPU address zero contained a valid little-endian ARM reset-vector table. The initial word and block readers agreed. A 48 KiB interval was acquired in forward and reverse block order; both copies were identical, and their prefix matched the separate word reader.

The complete result matched the UPD **loader3** digest:

```text
bytes:  49152
SHA256: be158aec37e74a3d528304f583eea42144bcc0365a8ef7a7f76ce811d9950f95
```

This component hash established identity independently of whether the instructions merely looked plausible. A shorter four-kilobyte read had not matched loader1; CPU address zero and a directory destination of zero do not establish that those two files are the same.

## Following actual code

The verified loader3 instruction at `0x70` loads PC from the literal at `0x488`, whose value is `0x060A0000`. A word/block control at that target returned ARM/Thumb code with direct calls into the same program region.

The larger runtime image contained real program code, but its complete hash differed from the release component. Differences were confined to reserved settings/working-data areas, including a fixed-data bank matching the body's export. Runtime memory must not be substituted blindly for an unchanged release image.

A literal-key scan of that runtime image produced the AES candidate. It was accepted only after decrypting the complete independently known loader3 to its expected SHA-256. The same key and each component's directory IV then decoded every entry of the original update successfully. The key's location was confirmed in the verified decoded program itself.

## Scope

This was read-only acquisition followed by offline decoding. No camera RAM, EEPROM or firmware write, settings restore, feature patch or flash was performed. Once the key was recovered, further decoding required only the saved update.

Addresses describe this G9 build, not a universal Lumix profile. No accepted modified update, signature-enforcement bypass or hard-brick recovery method is demonstrated. The offline tools do not require a camera or install a USB driver.

The [older-model service and porting research](https://github.com/flickering-star/lumix-firmware-research/blob/main/docs/porting-to-other-models.md) supplied useful framing controls. G9 addresses, key and component identities were established separately. See [the machine-readable summary](../evidence/recovery-summary.json).
