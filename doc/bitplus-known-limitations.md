# Bitplus Known Limitations

These limitations apply before external audit and before any real-funds launch.

- Institutional contracts deployment is intentionally inactive by default.
- There is no production asset index yet. Current asset scan and stats RPCs walk
  the active UTXO set. This is correctness-first and useful for reconciliation,
  but not low-latency for very large ledgers.
- Wallet UX is not production-complete. Current flows are raw transaction and
  PSBT oriented.
- External legal/business records are not interpreted by consensus. The chain
  commits to hashes only.
- RPC readiness checks are operator policy tools, not consensus rules.
- Report hashes rely on documented schema versions. Future schema changes must
  bump versions or hash domains.
- Long-duration multi-node soak testing is still required.
- Independent security audit is required before real funds.
