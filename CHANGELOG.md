# Changelog

All notable changes to Shahin Extractor are recorded here, newest first.

## v9.3

Fixes for four reliability/coverage weaknesses found in an internal review
of v9.2. All changes are minimal and scoped to a single module each; no
public API or overall workflow changed. Full regression suite (46 tests)
passes.

**Fixed**

- **Deobfuscator coverage** (`modules/deobfuscator.py`) — XOR/Base64
  scanning only ever covered the first 250 KB / 350 KB of a file. A real
  ESP flash dump is 4–16 MB, so roughly 94–98% of a dump was never
  checked. Replaced the per-byte Python XOR loop with `bytes.translate()`
  against precomputed 256-byte tables for all 255 keys (~80–100× faster),
  removed the size caps entirely, and now scan the full buffer on every
  key.
- **Console-probe wait times** (`modules/serial_session.py`) — the
  serial port's fixed 1.0 s timeout overrode the caller's shorter
  requested wait, so silent probes always took ~1 s instead of the
  intended ~0.3–0.8 s. `read_for(seconds)` now clamps the port timeout
  per read iteration to respect the caller's deadline, and always
  restores the original timeout afterward.
- **Filesystem unpack parameters** (`modules/region_extractor.py`) —
  carved SPIFFS/LittleFS images were unpacked without the `-s size`
  parameter `mkspiffs`/`mklittlefs` need for reliable results. Known
  partition sizes are now passed through; heuristically carved candidates
  fall back to the previous best-effort behavior if the sized attempt is
  rejected.
- **Raw-file name collisions** (`modules/storage.py`) — filenames used
  only second-resolution timestamps, so a fast bootloader-sync retry
  sequence could silently overwrite a previous capture within the same
  second. Filenames now include microseconds plus an atomic per-session
  counter, protected by a lock for concurrent saves.

**Added**

- `tests/test_weakness_fixes.py` — regression tests for all four fixes
  above.
- `e2e_smoke.py` — a quick end-to-end sanity check of the analysis
  pipeline against synthetic data.

**Fixed (publish cleanup)**

- `tests/__init__.py` imported a class, `RegressionTests`, that does not
  exist in `test_regressions.py` (that file defines four separate
  `TestCase` classes instead), which broke `import tests` entirely —
  `run_tests.py` and `python -m unittest discover` both failed before
  reaching a single test. `tests/__init__.py` is now empty, and the
  runner imports the real class names directly.

**Known issues**

- `tests/test_integration.py`'s `ShahinIntegrationTests` is **not** a
  `unittest.TestCase` subclass (no inheritance) and instantiates
  `BootloaderProbe`/`SecurityAudit` against a hardcoded `/dev/ttyUSB0`,
  so it cannot currently be collected or run by `run_tests.py` or
  `pytest`. It is excluded from the runner for now. Making it a real,
  hardware-independent test (mocking the serial port) is tracked as
  follow-up work.

## v9.2 and earlier

Initial tool: bootloader-stage extraction, fallback console probing,
static/binary analysis stage, correlation engine, and diagnosis
reporting.
