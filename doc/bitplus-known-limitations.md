# Bitplus Known Limitations

These limitations apply before external audit and before any real-funds launch.

- Institutional contracts deployment is intentionally inactive by default.
- `-bitplusassetindex=1` enables a non-consensus live asset UTXO index for
  `scanbitplusassetutxos`, `getbitplusassetstats`, and
  `getbitplusmemberassetstats`. The RPCs fall back to correctness-first active
  UTXO scans when the index is disabled or not synced. Reports expose
  `query_backend` and backend-specific `searched_txouts`; reconciliation hashes
  and compact summary hashes intentionally exclude backend search cost. If an
  initially selected index cannot be read consistently, reports fall back to UTXO
  scanning and expose `index_fallback_reason`.
- Wallet UX is not production-complete. Current flows are raw transaction and
  PSBT oriented.
- External legal/business records are not interpreted by consensus. The chain
  commits to hashes only.
- RPC readiness checks are operator policy tools, not consensus rules.
- Report hashes rely on documented fields, deterministic ordering, and explicit
  Bitplus hash domains.
- Long-duration multi-node soak testing is still required.
- Independent security audit is required before real funds.
