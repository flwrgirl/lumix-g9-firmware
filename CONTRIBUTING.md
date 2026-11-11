# Contributing

Keep changes reproducible for the exact camera model and firmware build. Include the input hash, tool version, command and expected result when reporting a decoding issue.

Run the firmware-free tests before submitting a change:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
git add <intended-source-files>
python tools/audit_publication.py
```

Use your own local copy of the pinned update for integration checks. Run the decoder into a new ignored `local/` directory and verify all 49 components with `tools/verify_decoded.py`.

Contribute original code, documentation, hashes and small reproducible test cases. Keep firmware images, decompiled vendor code, raw camera memory, ROM exports, serial numbers, calibration data and analysis-tool installations out of commits, issues and attachments. A hash, error message or minimal synthetic test case is usually sufficient.

Model-specific addresses need their own evidence. A valid reply frame or plausible instruction is weaker evidence than an independent read control and a complete component digest. Keep negative results scoped to the hypotheses actually tested.

This project currently documents decoding and offline analysis. Firmware modification, update acceptance and recovery require separate evidence. Do not describe a patch as tested on hardware unless that test actually occurred.
