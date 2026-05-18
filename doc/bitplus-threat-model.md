# Bitplus Threat Model

Bitplus targets fixed institutional settlement primitives on a Bitplus UTXO
chain. It does not add EVM-style arbitrary execution.

## Assets Protected

- BTP consensus integrity.
- Native asset issuance, transfer, burn, whitelist, and metadata commitments.
- Atomic settlement templates such as DvP, PvP, collateral release, vaults, HTLCs,
  and expiry/refund paths.
- Operator approval evidence: review hashes, readiness hashes, chain snapshots,
  reconciliation hashes, and paginated scan cursors.

## Main Threats

- Consensus divergence from ambiguous serialization, soft-fork activation bugs,
  or incompatible node behavior.
- Asset inflation through invalid issuance anchors, unbalanced transfer/burn
  flows, duplicate issuance, malformed commitments, or missing whitelist proofs.
- Settlement breakage through wrong output indexes, wrong output amounts, stale
  chain snapshots, incomplete prevout data, or unsigned/incomplete PSBTs.
- Operator mistakes from misspelled RPC fields, reused stale cursors, mixed
  pagination snapshots, or approval hashes computed over different reports.
- Reorg and restart risk causing reports to silently mix chain states.
- Denial of service through very large UTXO scans when optional asset indexes
  are disabled or lagging.
- Silent asset underreporting from inconsistent non-consensus asset-index
  secondary keys.

## Trust Boundaries

- Consensus validation must depend only on block/transaction data, spent outputs,
  and active deployment state.
- RPC analyzers and readiness checks are operator tools, not consensus.
- Asset-index reads must fail closed if secondary keys do not resolve to the
  expected indexed outpoint entry.
- Native asset whitelist policy applies to issued assets that commit to it; it
  does not permission BTP itself.
- Legal documents, participant identities, and business records are off-chain;
  Bitplus commits to their hashes.

## Required Controls

- Soft-fork deployment remains inactive until activation is intentionally planned.
- All commitment formats use fixed magic bytes, fixed field layouts, and stable
  endian rules.
- Readiness checks require complete prevout review and include chain snapshot and
  confirmation evidence.
- Reconciliation cursors bind to asset id, filters, height, and best block.
- Unknown filter/cursor fields are rejected.
- External security review is required before real funds.
