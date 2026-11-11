# Rebuilding the unchanged update

The pinned G9 V2.7 update was reconstructed **byte for byte** from all 49 verified
plaintext components. This includes newly encrypting 45 components, rebuilding
each directory record and recomputing the outer CRC32. The complete output has
81,952,256 bytes and SHA-256:

```text
9316958735c19fa0a04415c75faf97edff9be042a42c115ac1622d6c6379e7c3
```

[Roundtrip evidence](../evidence/roundtrip-summary.json) records every plaintext
and stored-component hash. Other header fields, including the signature, are
preserved from the original. This is not a source rebuild or a modified update.

## Reproduce

Use the portable compiler described in [building.md](building.md), then run:

```sh
python tools/build_codec.py --zig path/to/zig --out local/host-codec
python tools/roundtrip_g9_v27.py path/to/G9___V27.zip local/decoded --encoder local/host-codec/g9-cbc --out local/roundtrip
```

On Windows the encoder is `g9-cbc.exe`. Decode the release first using the README
commands. Both output directories must be new. The encoder runs on the PC.

The driver checks the input BIN hash and all plaintext hashes before running the
encoder. It tests standard ten-round CBC, the independent five-round GM1 vector,
and chaining across the native streaming-buffer boundary. Every reconstructed
payload and directory record must equal the original. Output is written only
after complete image equality succeeds. Changed plaintext is refused and inputs
are never written.

The original C encoder implements AES round operations and CBC without padding.
Five-round AES is used only for firmware-format compatibility and is unsuitable
for new encryption designs. Controls use [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)
and the round operations follow [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).

## What this establishes

Encryption and container reconstruction are reproducible. An edited component
would need a new plaintext hash, changing the signed directory and invalidating
its original signature. See [authentication.md](authentication.md). No signing
operation, private signing key, feature patch or installer is provided.

The GitHub workflow compiles the host encoder with the runner's C compiler.
Locally set `G9_CBC_ENCODER` to the compiled encoder's full path to include its
three integration tests. Without it those tests are explicitly skipped. The
complete local run, including the later storage-model controls, passed **31 tests**,
with none skipped.
