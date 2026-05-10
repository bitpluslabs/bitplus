#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate a small seed corpus for the bitplus_asset_payloads fuzz target."""

from pathlib import Path
import argparse
import hashlib


def u256(value: int) -> bytes:
    return value.to_bytes(32, "little")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def write_seed(target_dir: Path, name: str, payload: bytes) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(payload).hexdigest()[:16]
    (target_dir / f"{name}-{digest}").write_bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_dir", type=Path, help="Corpus root directory.")
    args = parser.parse_args()

    target_dir = args.corpus_dir / "bitplus_asset_payloads"

    asset_payload = (
        b"BTPASSET"
        + b"\x01"
        + b"\x02"
        + u256(1)
        + u64(1_000_000)
        + u256(2)
        + u256(3)
    )
    metadata_payload = b"BTPMETA" + b"\x01" + u256(4) + u256(5) + u256(6)
    whitelist_payload = b"BTPWLST" + b"\x01" + u256(7) + u256(8) + u256(9) + u32(1)
    proof_payload = (
        b"BTPWPROOF"
        + b"\x01"
        + u32(2)
        + u256(3)
        + u32(0)
        + b"\x02"
        + u256(10)
        + u256(11)
    )
    max_depth_proof_payload = b"BTPWPROOF" + b"\x01" + u32(2) + u256(3) + u32(0) + b"\x20" + b"".join(u256(i) for i in range(32))
    too_deep_proof_payload = b"BTPWPROOF" + b"\x01" + u32(2) + u256(3) + u32(0) + b"\x21" + b"".join(u256(i) for i in range(33))

    write_seed(target_dir, "asset-transfer", asset_payload)
    write_seed(target_dir, "metadata", metadata_payload)
    write_seed(target_dir, "whitelist", whitelist_payload)
    write_seed(target_dir, "whitelist-proof", proof_payload)
    write_seed(target_dir, "whitelist-proof-max-depth", max_depth_proof_payload)
    write_seed(target_dir, "whitelist-proof-too-deep", too_deep_proof_payload)

    # Malformed reserved-prefix seeds catch parser robustness around magic/version
    # boundaries without needing huge random corpora.
    write_seed(target_dir, "truncated-asset", asset_payload[:-1])
    write_seed(target_dir, "truncated-proof", proof_payload[:-1])
    write_seed(target_dir, "wrong-version-asset", asset_payload[:8] + b"\x02" + asset_payload[9:])
    write_seed(target_dir, "unknown-type-asset", asset_payload[:9] + b"\xff" + asset_payload[10:])


if __name__ == "__main__":
    main()
