# UPD format and decoder

These observations are validated for the pinned DC-G9 V2.7 `MC471` image. The inspector checks structural consistency; the decoder additionally requires the exact tested BIN SHA-256.

## Container

| Field | File offset | Meaning in the tested image |
| --- | --- | --- |
| Magic | `0x000` | `UPD\0` |
| Outer CRC32 | `0x040` | Little-endian CRC32 over `[0x200, EOF)` |
| Inner marker | `0x200` | `panasonic` |
| ECDSA P-256 signature | `0x220` | 64 bytes; verifies over `[0x2A0, 0x1488)` with the G9 public key |
| Repeated header | `0x2A0` | First 64 bytes match the outer header |
| Component count | `0x2E8` | 49 |
| Component directory | `0x2EC` | Records of `0x5C` bytes |
| First stored payload | `0x1600` | Payloads are contiguous through EOF |

Directory integers are little endian:

| Record offset | Size | Meaning |
| --- | ---: | --- |
| `0x00` | 12 | NUL-padded component name |
| `0x0C` | 4 | Stored offset relative to file offset `0x200` |
| `0x10` | 4 | Complete stored/plaintext component length |
| `0x14` | 4 | Destination/logical field; not a demonstrated CPU address |
| `0x18` | 4 | Flags: clear `2`, encrypted `3` in this image |
| `0x1C` | 32 | SHA-256 of the complete plaintext component |
| `0x3C` | 16 | CBC IV for encrypted components |
| `0x4C` | 16 | Reserved bytes, zero in this sample |

The decoder retains every byte of each declared component, including padding. The empty `storage` entry is checked against SHA-256 of empty bytes.

The unchanged container now reproduces byte for byte. See [packaging](packaging.md)
and [authentication](authentication.md) for the signed format and remaining
hardware-acceptance limits.

## Cipher

The tested cipher is AES-128-CBC with **five rounds**, using the normal AES key expansion truncated to the required round keys. Standard ten-round AES-128-CBC will not decode these components.

```text
key: e30b70e1bdc61dacc7057545d85d0b1d
IV:  the component record's bytes 0x3C..0x4B
```

The implementation passes a standard AES-128 block vector and a published five-round GM1 control. More decisively, the G9 key decrypts the independently acquired 49,152-byte loader3 exactly, and all 49 update entries subsequently match their whole-component hashes.

The key appears in the decoded main program at offset `0x009C8F10`, corresponding to CPU address `0x06A68F10` for its observed base `0x060A0000`. This is a release-level decoder key, not a per-camera calibration value.

References: [older-model cipher analysis and controls](https://github.com/flickering-star/lumix-firmware-research/blob/main/docs/gm1-program-analysis.md), [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf), and this repository's [G9 verification metadata](../evidence/recovery-summary.json).
