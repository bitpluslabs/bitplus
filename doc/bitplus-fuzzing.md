# Bitplus Fuzzing

Bitplus adds a dedicated fuzz target for native asset payload parsing:

```text
bitplus_asset_payloads
```

The target exercises raw payload decoders, script commitment decoders, and
round-trip encoding/hash stability for generated valid commitments.

## Seed Corpus

Generate a local seed corpus:

```powershell
python contrib/devtools/bitplus_asset_fuzz_seed_corpus.py fuzz-corpus
```

This creates:

```text
fuzz-corpus/bitplus_asset_payloads/
```

with valid and malformed `BTPASSET`, `BTPMETA`, `BTPWLST`, and `BTPWPROOF`
payloads. The proof seeds include maximum-depth and too-deep Merkle proof
payloads to exercise parser boundary checks.

## Build And Run

A fuzz-enabled build is required:

```powershell
cmake -B build_fuzz -S . -DBUILD_FUZZ_BINARY=ON -DBUILD_FOR_FUZZING=ON -DBUILD_TESTS=OFF
cmake --build build_fuzz --config Release --target fuzz --parallel 2
python test/fuzz/test_runner.py --par 1 fuzz-corpus bitplus_asset_payloads
```

On machines without the required fuzz/test dependencies installed, configure may
need vcpkg dependency installation first.
