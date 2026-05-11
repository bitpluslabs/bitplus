# Bitplus Known Limitations

These limitations apply before external audit and before any real-funds launch.

- Institutional contracts deployment is intentionally inactive by default.
- `-bitplusassetindex=1` enables a non-consensus live asset UTXO index for
  `scanbitplusassetutxos`. Asset stats RPCs still use the correctness-first
  active UTXO scan path and are not low-latency for very large ledgers.
- Wallet UX is not production-complete. Current flows are raw transaction and
  PSBT oriented.
- External legal/business records are not interpreted by consensus. The chain
  commits to hashes only.
- RPC readiness checks are operator policy tools, not consensus rules.
- Report hashes rely on documented schema versions. Future schema changes must
  bump versions or hash domains.
- Long-duration multi-node soak testing is still required.
- Independent security audit is required before real funds.
