# Bitplus Institutional Contracts

Bitplus contracts extend the Bitcoin Script and UTXO model. They are not an EVM,
Solidity, account-state, or arbitrary-computation system.

The institutional contract scope is fixed to these primitives:

- Multisig / threshold custody
- Timelocks
- HTLCs
- Covenants
- Vaults
- Native assets
- Asset metadata commitments
- Whitelisted asset transfers
- DvP settlement
- PvP settlement
- Collateral lock/release
- Expiry/refund paths

## Design Rules

- Preserve Bitcoin-style validation: every spend is locally verifiable from the
  transaction, the spent outputs, and the active consensus rules.
- Prefer Taproot/Tapscript-compatible extensions.
- Prefer narrowly scoped opcodes and transaction templates over general-purpose
  computation.
- Keep BTP itself permissionless. Permission rules apply only to issued assets
  that explicitly opt into those rules.
- Keep legal or business records off-chain and commit to them on-chain with
  hashes or structured metadata commitments.

## Activation

Institutional contracts are represented by the dormant activation deployment
`institutional_contracts`.

The deployment is intentionally set to `NEVER_ACTIVE` on all networks until the
contract semantics, test vectors, wallet behavior, and migration notes are
implemented and reviewed.

Functional coverage includes an inactive-deployment test that mines a mismatched
`OP_CHECKOUTPUTVERIFY` spend while `institutional_contracts` is inactive. This
keeps the soft-fork boundary explicit: before activation, the opcode byte remains
dormant and does not enforce the new covenant rule.

## Production Hardening Checklist

These items must be complete before any real-money institutional deployment:

- [x] More adversarial tests and fuzz-style edge cases, including malformed RPC
  parameters, stale cursors, missing cursor fields, invalid cursor outpoints,
  inactive deployment checks, invalid asset commitments, conservation failures,
  whitelist proof failures, HTLC failure paths, and covenant mismatch paths.
- [x] RPC/API cleanup and consistency review for the Bitplus construction,
  analysis, readiness, scan, and stats RPCs.
- [x] Better error taxonomy and operator documentation.
- [x] Reorg and load-style reconciliation tests, including active-chain
  invalidation/reconsideration and paginated scans over larger asset UTXO sets.
- [x] Consensus-safety and serialization-stability review.
- [x] Asset index design review for large production asset sets.
- [ ] External security review/audit before real funds.

The external audit is a release gate, not an in-repo task. It must be performed
by independent reviewers after the implementation and test suite stabilize.

Audit-prep companion documents:

- `doc/bitplus-threat-model.md`
- `doc/bitplus-testnet-runbook.md`
- `doc/bitplus-known-limitations.md`
- `doc/bitplus-audit-checklist.md`
- `doc/bitplus-fuzzing.md`

## Error Taxonomy

Bitplus uses three broad error classes:

- RPC parameter errors use `RPC_INVALID_PARAMETER` and indicate malformed API
  input, unsupported enum values, missing cursor fields, null identifiers, or
  locally invalid construction requests. Operators should fix the request before
  retrying.
- Analyzer issues appear inside Bitplus analysis/readiness `issues` arrays and
  indicate a transaction or PSBT review problem, such as missing prevout context,
  missing whitelist proof, unbalanced asset conservation, or inactive deployment.
  Operators should treat these as signing or broadcast blockers unless a venue
  policy explicitly allows the warning class involved.
- Consensus/policy rejects appear in `testmempoolaccept`, block validation, or
  readiness mempool fields. These are node-enforced rejects for active rules or
  standardness policy. Operators should not assume a transaction can settle until
  these rejects are gone on the intended network policy.

Cursor-based reconciliation RPCs intentionally reject stale or incomplete cursors
with explicit parameter errors. A cursor is bound to `height` and `bestblock` so
pages from different active-chain snapshots cannot be silently mixed.
Unknown filter or cursor object fields are rejected rather than ignored, so
operator typos cannot silently widen or alter a reconciliation query.
UTXO-derived reconciliation RPCs also verify that the active chain tip is still
the same after the scan finishes. If a block connect, disconnect, or reorg races
the scan, the RPC returns a retryable error instead of publishing a report from
a moving snapshot.

## Serialization Stability Review

Consensus-facing Bitplus data must remain byte-stable. The current native asset
format follows these rules:

- Every commitment family has a fixed ASCII magic prefix: `BTPASSET`, `BTPMETA`,
  `BTPWLST`, or `BTPWPROOF`.
- Integer fields are serialized in one fixed form: asset amounts are little-endian
  64-bit values, whitelist flags are little-endian 32-bit values, and whitelist
  proof indexes are little-endian 32-bit values.
- Hashes commit to the encoded payload bytes or to explicit domain-separated
  `HashWriter` records. Asset ids commit to the metadata hash and the issuing
  input outpoint.
- Operator report hashes use explicit Bitplus domains, deterministic field
  ordering, and documented payloads so approvals and audit records can compare
  the same bytes across nodes.

The consensus rule is intentionally narrow: nodes validate locally from the
transaction, spent outputs, and active deployment state. Bitplus does not add
account state, external databases, or arbitrary program execution to consensus.

## Asset Index Design Review

The asset scan and stats RPCs have an optional non-consensus live UTXO index
enabled with `-bitplusassetindex=1`. The original active UTXO scan remains the
fallback when the index is disabled or temporarily not synced to the active tip.

The current index:

- Keys live outputs by `asset_id`, member hash, and outpoint.
- Stores outpoint, amount, commitment fields, creating height, locking script,
  and coinbase status.
- Updates with block connect and disconnect so reorg behavior matches the active
  chain once the index catches up.
- Stays outside consensus. A node without the index validates every block and
  transaction with the same rules.

Large production venues should extend the index before operating at scale. The
next index work should:

- Add secondary keys by metadata hash and asset type if those become dominant
  query dimensions.
- Keep equivalent reconciliation/report hashes so operator workflows do not
  depend on whether the backend is UTXO scanning or indexed lookup.

The index is still optional and non-consensus. Operators should monitor
`getindexinfo("bitplusassetindex")`; RPCs use the active UTXO scan fallback if
the index is unavailable or not synced.

## Covenant Primitive

`OP_CHECKOUTPUTVERIFY` is the first Bitplus covenant opcode. It is a
Tapscript-only opcode guarded by `SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS`, which
is enabled only when the `institutional_contracts` deployment is active.

Stack form:

```text
<scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
```

The opcode succeeds only when:

- `output_index` exists in the spending transaction.
- The output amount equals `amount`.
- `SHA256(serialized scriptPubKey)` equals `scriptPubKeyHash`.

When the institutional-contract rules are inactive, the opcode byte remains an
`OP_SUCCESSx` for Tapscript spends, preserving the soft-fork activation model.

## Vault Templates

Vaults are built as Tapscript leaves rather than as a separate consensus object.
The initial helper functions live in `src/script/bitplus_contracts.*`.

The recovery leaf has this shape:

```text
<authorization_script> OP_VERIFY
<recovery_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

The delayed spend leaf has this shape:

```text
<authorization_script> OP_VERIFY
<relative_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<destination_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

This gives institutions two clear paths:

- Immediate recovery to a precommitted safe output.
- Delayed withdrawal to a precommitted destination output.

The authorization script can be a Taproot threshold script, a single key, or a
future policy fragment. It must consume its own witness data and leave exactly
one truthy stack item for `OP_VERIFY`, with no extra stack items left over for
the final cleanstack check. The covenant keeps the value bound to the intended
output, and the delay gives recovery systems time to react before withdrawal.

## HTLC Templates

HTLCs are built as paired Tapscript leaves. The claim path requires a SHA256
preimage and an exact claim output:

```text
<authorization_script> OP_VERIFY
OP_SHA256 <secret_hash> OP_EQUALVERIFY
<claim_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

The refund path opens after an absolute CLTV expiry and still requires the exact
refund output:

```text
<authorization_script> OP_VERIFY
<absolute_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
<refund_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

This gives institutions a fixed hashlock/timelock primitive without adding a
general-purpose VM. Functional tests cover wrong-preimage rejection, successful
claim with the preimage, premature refund rejection, and successful refund at
expiry.

## Native Asset Commitment Format

Native assets use stable commitment payloads embedded in spendable UTXOs.
Consensus validation recognizes these payloads when the institutional contracts
deployment is active; wallet, index, and operator tooling use the same bytes for
review and reconciliation.

The payload is:

```text
"BTPASSET" || type || asset_id || amount || metadata_hash || member_hash
```

Fields:

- `type`: 1 byte. `1` issuance, `2` transfer, `3` burn.
- `asset_id`: 32 bytes. For issuance, this must equal the issuance-anchored
  asset id described below.
- `amount`: 8 byte little-endian unsigned integer.
- `metadata_hash`: 32 bytes.
- `member_hash`: 32 bytes. This binds the asset state transition to the
  settlement member or beneficiary authorized by the asset rules.

The script wrapper for asset state is spendable:

```text
<asset_commitment_payload> OP_DROP <locking_script>
```

The helper functions live in `src/script/bitplus_assets.*`. The asset payload is
part of the UTXO's `scriptPubKey`, while `<locking_script>` controls who can
spend that asset state. This keeps asset outputs in the UTXO set so follow-up
transactions can spend them and active rules can enforce asset conservation.
The default helper builds an executable member hashlock:

```text
OP_SHA256 <member_hash> OP_EQUAL
```

A spender must provide the member preimage in `scriptSig`. Callers that need a
different custody policy can pass an explicit legacy locking script.
Nested asset carrier scripts are invalid as `<locking_script>` values.

## Asset Validation Plumbing

The first validation layer is output extraction, not yet consensus enforcement.
`src/script/bitplus_assets.*` provides helpers to:

- Decode a single `CTxOut` as an asset commitment output.
- Extract all asset commitment outputs from a transaction.
- Extract spent asset commitment outputs from the UTXO view.
- Summarize issued, transferred, and burned amounts for a given `asset_id`.
- Validate basic asset output structure.
- Check asset conservation over explicit spent and created asset outputs.
- Check conservation for a full transaction when its spent outputs are present
  in a `CCoinsViewCache`.

This gives validation, wallet code, and operator tooling a deterministic way to
inspect native-asset commitments before enforcing conservation against
spent-output asset state.

The conservation rule is:

```text
spent_transfers + issuance == created_transfers + burns
```

Issuance adds supply, burns remove supply, and normal transfers must be backed by
previously spent transfer outputs. The helper takes explicit spent asset outputs
or derives them from the UTXO view.

`ConnectBlock` calls the transaction conservation helper when
`institutional_contracts` is active. Because the deployment is currently
`NEVER_ACTIVE`, this is dormant consensus wiring until activation parameters are
set and the rule set is reviewed.

When active, `ConnectBlock` also rejects malformed asset commitment outputs
before checking conservation:

- Asset carrier outputs must carry `0` BTP.
- `asset_id` must be non-null.
- `metadata_hash` must be non-null.
- `member_hash` must be non-null.
- `amount` must be greater than zero.
- Spent asset UTXOs must satisfy the same asset-output validation rules before
  they can contribute to conservation.

It also rejects malformed metadata and whitelist commitment outputs:

- Metadata `issuer_id`, `document_hash`, and `rules_hash` must be non-null.
- Whitelist `list_id`, `admin_key_hash`, and `members_root` must be non-null.

When active, issuance outputs must also be linked to policy data in the same
transaction:

- An `ISSUANCE` asset output's `metadata_hash` must match a `BTPMETA` output.
- An `ISSUANCE` asset output must be anchored to the transaction's first input
  outpoint.
- An `ISSUANCE` asset output's `asset_id` must equal:

```text
SHA256(metadata_hash || first_input_prevout)
```

- A transaction may contain only one `ISSUANCE` output for a given `asset_id`.
- A `BTPMETA` output's `rules_hash` must match a `BTPWLST` output.
- Every `TRANSFER` asset output must include same-transaction metadata,
  same-transaction whitelist rules, and a valid whitelist membership proof.

Burn outputs may reference existing metadata by hash. Transfer outputs must
include same-transaction metadata, whitelist rules, and proof data so block
validation can verify the transfer against the committed whitelist root without
external state.

## Mempool Enforcement

When the `institutional_contracts` deployment will be active for the next
block, mempool admission runs the same institutional asset checks used by block
validation after normal input validation succeeds. Invalid asset commitments,
missing metadata, missing whitelist rules, invalid whitelist proofs, and asset
conservation failures are rejected before relay or mining.

Standard relay policy treats valid asset carrier scripts as standard when their
inner `<locking_script>` is either the default member hashlock or another
standard legacy locking script, and excludes valid asset carrier outputs from
ordinary BTP dust counting because their BTP amount must be zero.

## RPC Decoding

Transaction decoding exposes Bitplus institutional commitments directly inside
`scriptPubKey` objects:

- `bitplus_asset` for spendable `BTPASSET` carrier outputs.
- `bitplus_asset_metadata` for `BTPMETA` outputs.
- `bitplus_asset_whitelist` for `BTPWLST` outputs.
- `bitplus_asset_whitelist_proof` for `BTPWPROOF` outputs.

This is shared by transaction-formatting RPCs such as `decoderawtransaction`,
`getrawtransaction`, block transaction verbosity, `gettxout`, and PSBT decode
paths that use the common script formatter.

## RPC Construction Helpers

Raw transaction tooling exposes helper RPCs for constructing institutional
commitment scripts without wallet support:

- `createbitplusassetid`
- `decodebitplusscript`
- `analyzebitplustransaction`
- `analyzebitpluspsbt`
- `createbitplusscripttransaction`
- `createbitpluspsbt`
- `preparebitpluspsbt`
- `checkbitplussettlement`
- `scanbitplusassetutxos`
- `getbitplusassetstats`
- `getbitplusmemberassetstats`
- `createbitplusassetmetadata`
- `createbitplusassetwhitelist`
- `createbitplusassetwhitelistroot`
- `createbitplusassetissuance`
- `createbitplusasset`
- `createbitplusassettransfer`
- `createbitplusassetburn`
- `createbitplusassetwhitelistproof`
- `createbitplusdvp`
- `createbitpluspvp`
- `createbitplusvault`
- `createbitplushtlc`
- `createbitpluscollateral`
- `createbitplusrefundpaths`
- `createbitpluscovleaf`
- `createbitplusvaultrecoveryleaf`
- `createbitplusvaultdelayedleaf`
- `createbitplushtlcclaimleaf`
- `createbitplushtlcrefundleaf`
- `createbitplusdvpleaf`
- `createbitpluspvpleaf`
- `createbitpluscollateralreleaseleaf`
- `createbitpluscollateralreturnleaf`
- `createbitplusrefundabsoluteleaf`
- `createbitplusrefundrelativeleaf`

These return raw payloads, `scriptPubKey` hex, and commitment hashes that can be
used with raw transaction construction flows.

`decodebitplusscript` decodes one scriptPubKey before it is placed in a
transaction. It reports whether the script is a recognized Bitplus commitment,
which commitment type it carries, and whether the commitment is structurally
valid for the supplied output amount and index. This gives operators and
independent signing systems a direct pre-flight check before assembling or
approving settlement transactions.

`analyzebitplustransaction` performs the same style of pre-flight check over a
whole raw transaction. It reports all recognized Bitplus outputs and flags
same-transaction linkage issues such as missing metadata, missing whitelist
rules, missing proofs, duplicate issuance, invalid issuance anchors, and orphan
proofs. If the caller supplies the previous outputs being spent, it also checks
asset conservation and reports per-asset spent, issued, transferred, and burned
amounts. Without those previous outputs, mempool and block validation remain the
authoritative conservation checks when institutional rules are active.
Operators can also pass `lookup_spent_outputs=true`; in that mode the RPC fills
missing prevouts from the node's UTXO set and mempool, reports
`input_utxos_available` and `missing_input_utxos`, and marks the analysis
invalid if any required prevout cannot be independently inspected. The analysis
also includes `participant_movements`, which summarizes each member's per-asset
spent amount, received live amount, burn attribution, and live balance delta.
`bitplus_review_hash` commits to the transaction and the spent asset context
used by the analyzer, while `bitplus_review_complete` tells operators whether
the package included enough prevout data for a complete conservation review.

`analyzebitpluspsbt` applies the same institutional pre-flight checks to the
unsigned transaction inside a PSBT. When PSBT inputs include `witness_utxo` or
`non_witness_utxo`, the RPC decodes spent Bitplus asset UTXOs and checks asset
conservation before signatures are collected. It also reports
`psbt_utxos_available` and `missing_psbt_utxos`, so an operator can reject a
signing package that lacks the data needed for independent asset-conservation
review. The same participant movement summary is available before signing when
the PSBT carries the required input UTXO data, and the PSBT analysis exposes the
same deterministic review hash so separate signers can compare the exact package
they approved.

`createbitplusscripttransaction` creates a raw unsigned transaction from normal
inputs and an ordered list of exact `scriptPubKey` outputs. Each output may
include an expected `index`; the RPC rejects the transaction if the expected
index does not match the array position. This is useful for covenant
transactions where `OP_CHECKOUTPUTVERIFY` commits to exact output indexes.

`createbitpluspsbt` uses the same exact-output builder but returns a base64 PSBT
and unsigned transaction id. This lets an operations desk assemble a deterministic
settlement package, run `analyzebitpluspsbt`, circulate it for threshold signing,
and only then finalize and broadcast.

`preparebitpluspsbt` updates a PSBT with UTXO data available from the node,
optionally using descriptors for script metadata enrichment, and returns the
updated PSBT together with the post-update Bitplus analysis. It reports
`missing_utxos_before`, `missing_utxos_after`, and `utxos_fully_available`, so
operators can distinguish an unsigned-but-reviewable PSBT from one that is
missing prevout data needed for independent asset-conservation checks.

`checkbitplussettlement` is the operator readiness gate. It accepts either raw
transaction hex or a base64 PSBT, runs the Bitplus analyzer, checks whether the
institutional contracts deployment is active, reports final transaction
weight/vsize when available, checks final-transaction input confirmation depth,
and runs mempool test-accept for final transactions. The default
`min_input_confirmations` is 6, matching a one-hour operational security policy
for 10-minute blocks; operators can set it to 0 for dry runs or stricter/lower
values for venue policy.
The result includes `ready_to_broadcast`, `issues`, `warnings`, and the detailed
`bitplus_analysis` object. `readiness_policy` records the operator policy knobs
used by the gate: input format, mempool-check requirement,
`maxfeerate`, `min_input_confirmations`, and the fixed requirements that
institutional contracts are active and Bitplus prevout review is complete. It
also reports `chain_snapshot` with the active chain height and best block hash,
plus `input_confirmations_available`, `input_confirmation_summary`,
`input_confirmations`, and `inputs_below_min_confirmations`, so signers can see
the exact chain state, aggregate confirmation counts, and per-input evidence
used by the readiness decision. `bitplus_analysis_summary` gives a compact
operator view over the detailed analyzer output: recognized output counts by
commitment family, spent asset input count, conservation row counts, participant
movement row count, analyzer issue count, and review validity/completeness.
`readiness_issue_summary` groups blocking issues and warnings into operator
categories such as finalization, activation, prevout context, confirmation,
mempool, and fee policy, while separating analyzer issues from issues added by
the readiness gate itself. `readiness_report_hash` commits to the compact
operator report fields: chain snapshot, readiness policy, input confirmation
summary, Bitplus analysis summary, issue summary, issues, warnings, ready flag,
and the full `settlement_readiness_hash`.
`settlement_readiness_hash` commits to the whole gate decision: transaction id,
finalization state, chain snapshot, deployment state, confirmation policy and
evidence, Bitplus review hash, `maxfeerate`, mempool-check setting/result,
readiness result, issues, and warnings. It also lifts `bitplus_review_hash` and
`recognized_outputs`, `conservation_checked`, `bitplus_review_complete`,
`prevout_context_available`, `missing_prevout_indexes`, `asset_conservation`,
and `participant_movements` to top level so signers and operators can compare
the exact reviewed package and its asset effects without digging through nested
analysis. Unsigned or incomplete PSBTs are intentionally not ready to broadcast;
they remain useful review packages until finalized.

`scanbitplusassetutxos` scans confirmed live Bitplus asset outputs matching an
`asset_id`. With `-bitplusassetindex=1`, it uses the live asset index when that
index is synced to the active tip; otherwise it falls back to the confirmed UTXO
set. Optional filters can narrow results by asset `type`, `metadata_hash`,
`member_hash`, and `min_confirmations`. It returns bounded results with
outpoint, amount, confirmation, block, script, and decoded commitment fields.
All reconciliation-style reports return top-level `report_type`, so operator
systems can route the response before inspecting nested summaries.
If the result is truncated, `complete` is false and `next_cursor` can be passed
back as the fourth argument to continue from the last returned outpoint. The
cursor is bound to the returned `bestblock`, `height`, `asset_id`, and
`filters_hash`; the node rejects it if the active chain tip changed or if the
caller tries to reuse it with a different asset id or filter set. This prevents
operators from accidentally reconciling pages from different chain snapshots or
different scan queries.
`reconciliation_hash` commits to the active-chain snapshot, filters, completion
flag, continuation cursor, and returned UTXO rows for the bounded result page.
This lets two operators compare the exact scan result they reviewed.
`scan_summary` mirrors the page-level review fields such as filters, optional
cursor, chain snapshot, `max_results`, cursor use, completion status, match
count, and `reconciliation_hash`; `scan_summary_hash` commits to that compact
page summary for approvals that do not need every returned UTXO row. The summary
includes `filters_hash` so operators can compare the applied filters directly.
`chain_snapshot` is also returned as a first-class object with `height` and
`bestblock`, matching `checkbitplussettlement`; `chain_snapshot_hash` commits to
that object.
This remains a reconciliation tool; the optional asset index reduces scan cost
for large production operators without becoming part of consensus. RPCs return
`query_backend` (`asset_index` or `utxo_scan`) and `searched_txouts` for
operations, but `reconciliation_hash` and `scan_summary_hash` do not commit to
backend-specific search costs so indexed and scan-backed nodes can compare the
same ledger result. If a synced optional index is selected but cannot be read
consistently, the RPC falls back to the active UTXO scan and returns
`index_fallback_reason`.

`getbitplusassetstats` uses the same indexed-or-scan backend and optional
filters, but returns aggregate reconciliation totals instead of individual
outpoints. It reports live matching UTXO count, total asset units, and
count/amount breakdowns by asset type, metadata hash, and member hash.
`min_confirmations` lets
operators reconcile only balances that have reached venue-required security
depth, such as six confirmations for one-hour Bitcoin-style finality. Matching
stats include `min_confirmations_observed` and `max_confirmations_observed`, and
those values are part of the reconciliation hash, so the reviewed balance report
commits to the confirmation range behind it. It also reports
`issued_amount`, `held_amount`, and `burned_amount` so operators can distinguish
raw live carrier totals from the transfer units currently held by members.
`holder_count` and `by_holder_member_hash` are transfer-only views for custody
and participant reconciliation; issuance and burn carriers are excluded from
those holder totals. `outstanding_amount`, `supply_underflow`, and
`holder_supply_balanced` compare the lifecycle view (`issued_amount` minus
`burned_amount`) with live holder balances. `holder_supply_delta` is the signed
held-minus-outstanding amount: zero means balanced, negative means holder
balances are short, and positive means holders exceed lifecycle supply. These
are most meaningful on an unfiltered asset view; type-specific lifecycle filters
can intentionally show an unbalanced partial view. `reconciliation_hash` commits
to the active-chain snapshot, applied filters, aggregate totals, and deterministic
breakdowns so two operators can compare the exact same reconciliation result.
`reconciliation_summary` mirrors the applied filters, key top-level totals,
chain snapshot, confirmation range, and `reconciliation_hash` in a compact
operator-facing object for approvals and audit records.
`reconciliation_summary_hash` commits to that compact summary alone, while
`reconciliation_hash` commits to the full breakdown. The summary includes
`filters_hash` for direct comparison of the filtered view and
`chain_snapshot_hash` for direct comparison of the active-chain snapshot.
`query_backend`, `searched_txouts`, and `index_fallback_reason` are top-level
operational fields; they can differ between indexed and scan-backed nodes
without changing the reconciliation hash or compact summary hash.

`getbitplusmemberassetstats` summarizes confirmed live asset UTXOs for one
member hash, grouped by `asset_id`. Optional filters can restrict the view by
`asset_id`, asset `type`, `metadata_hash`, or `min_confirmations`. This gives a custody desk or
settlement venue a direct participant-level reconciliation view across all
assets without first knowing every asset id the member currently holds. Like the
asset-level stats, it separates `held_amount` from issuance and burn carrier
amounts to avoid double-counting lifecycle commitments as member balances.
`holder_asset_count` and each asset's `is_holder` flag are transfer-only holder
signals, so lifecycle-only matches do not imply custody balance. The member view
also returns a `reconciliation_hash` over the chain snapshot, member hash,
filters, totals, confirmation ranges, and per-asset breakdowns. Its
`reconciliation_summary` gives the same compact approval view, including
filters, for participant reconciliation, and `reconciliation_summary_hash` lets
operators compare that compact view directly. Participant summaries include
`filters_hash` and `chain_snapshot_hash`.
As with asset-level stats, participant `query_backend`, `searched_txouts`, and
`index_fallback_reason` describe how the report was produced and are top-level
operational fields, not part of the reconciliation hash or compact summary hash.

`createbitplusassetwhitelistroot` computes the whitelist `members_root` from an
ordered list of member hashes. If `proof_index` is provided, it also returns the
member hash and Merkle sibling path needed by `createbitplusassetwhitelistproof`.

`createbitplusassetissuance` builds a consistent issuance package from one call:
the whitelist commitment, metadata commitment, deterministic `asset_id`, and
spendable issuance carrier script. This avoids hand-linking the whitelist hash
into metadata and the metadata hash into the issuance asset id.

`createbitplusassettransfer` builds the spendable transfer carrier and its
matching whitelist proof output together. It checks the supplied Merkle path
against the expected `members_root` before returning scripts.

`createbitplusassetburn` builds a spendable zero-BTP `BURN` asset carrier for
asset lifecycle reductions. The burn is accounted for by native asset
conservation when institutional rules are active.

`createbitplusdvp` builds a complete delivery-versus-payment construction
package: transfer carrier, matching whitelist proof, and DvP settlement leaf. It
verifies the whitelist proof root before producing the leaf. Callers may provide
an optional asset locking script so the asset leg settles directly into a
specific custody or control script rather than the default member hashlock.

`createbitpluspvp` builds a complete payment-versus-payment construction
package: two transfer carriers, their matching whitelist proofs, and a PvP
settlement leaf. Each leg can use its own whitelist root and optional asset
locking script.

`createbitplusvault`, `createbitplushtlc`, `createbitpluscollateral`, and
`createbitplusrefundpaths` return paired Tapscript leaves for the common
two-path workflows: immediate vault recovery plus delayed spend, HTLC claim plus
absolute-expiry refund, collateral release plus delayed return, and absolute
plus relative refund.

The contract leaf helpers return raw Tapscript leaf hex plus a `script_hash`.
They expect hex-encoded authorization scripts and output scriptPubKeys, exact
BTP amounts, and exact output indexes. DvP/PvP helpers build `TRANSFER` asset
legs and bind them to zero-BTP asset carrier outputs. If no asset locking script
is supplied, the helpers use the default `OP_SHA256 <member_hash> OP_EQUAL`
asset lock. DvP/PvP leaf checks only prove that the exact committed outputs are
present; native asset conservation, metadata, and whitelist rules are enforced
by the separate Bitplus asset consensus checks when institutional contracts are
active.

The raw C++ template builders are intentionally small script constructors.
Checked builder variants are available for RPC and integration use; they reject
empty authorization/output scripts, negative or out-of-range amounts, negative
lock values, null HTLC secrets, and invalid custom asset locking scripts before
returning a leaf.

## Asset Metadata Commitment Format

Asset metadata is committed separately from asset transfer records. The asset
commitment stores only `metadata_hash`, where:

```text
metadata_hash = SHA256(asset_metadata_commitment_payload)
```

The metadata payload is:

```text
"BTPMETA" || issuer_id || document_hash || rules_hash
```

Fields:

- `issuer_id`: 32 bytes. This identifies the issuing institution or policy root.
- `document_hash`: 32 bytes. This commits to legal, offering, or operational
  documents kept off-chain.
- `rules_hash`: 32 bytes. This commits to transfer restrictions, whitelist
  policy, or settlement rules interpreted by Bitplus validation and wallet
  logic.

The initial script wrapper is:

```text
OP_RETURN <asset_metadata_commitment_payload>
```

Keeping metadata separate lets the same asset format support regulated
instruments without putting large documents or mutable business records directly
in consensus data.

## Whitelist Rule Commitment Format

Whitelisted transfers are represented by a rules commitment that asset metadata
can reference through `rules_hash`:

```text
rules_hash = SHA256(asset_whitelist_commitment_payload)
```

The whitelist payload is:

```text
"BTPWLST" || list_id || admin_key_hash || members_root || flags
```

Fields:

- `list_id`: 32 bytes. This identifies the whitelist or compliance program.
- `admin_key_hash`: 32 bytes. This commits to the key or key policy allowed to
  update or attest to the whitelist.
- `members_root`: 32 bytes. This commits to an off-chain whitelist member set,
  such as a Merkle root over approved settlement addresses or identities.
- `flags`: 4 byte little-endian bitfield for future transfer-rule options.

The initial script wrapper is:

```text
OP_RETURN <asset_whitelist_commitment_payload>
```

## Whitelist Membership Proof Format

Asset transfers are whitelisted by a proof commitment that points at the asset
transfer output it authorizes:

```text
"BTPWPROOF" || asset_output_index || member_hash || proof_index || path_count ||
merkle_path
```

Fields:

- `asset_output_index`: 4 byte little-endian index of the `TRANSFER` output.
- `member_hash`: 32 bytes. This commits to the approved settlement member.
- `proof_index`: 4 byte little-endian Merkle leaf index.
- `path_count`: 1 byte, maximum `32`.
- `merkle_path`: `path_count` sibling hashes, each 32 bytes.

The member leaf is:

```text
SHA256("BTPWLSTMEMBER\0" || member_hash)
```

The proof recomputes the Merkle root from that leaf and `merkle_path`. A transfer
is valid only when:

- The transfer's `metadata_hash` matches a same-transaction `BTPMETA` output.
- That metadata's `rules_hash` matches a same-transaction `BTPWLST` output.
- A same-transaction `BTPWPROOF` output names the transfer output index.
- The proof's `member_hash` equals the transfer commitment's `member_hash`.
- The proof index is canonical for the path depth.
- The proof root equals the whitelist's `members_root`.

The initial script wrapper is:

```text
OP_RETURN <asset_whitelist_proof_payload>
```

## DvP Settlement Templates

Delivery-versus-payment settlement is represented as a Tapscript leaf that
requires both legs to appear in the same transaction:

```text
<authorization_script> OP_VERIFY
<asset_commitment_scriptPubKeyHash> 0 <asset_output_index> OP_CHECKOUTPUTVERIFY
<payment_scriptPubKeyHash> <payment_amount> <payment_output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

The asset leg is a spendable asset carrier output where the payload type is
normally `TRANSFER`. Its inner locking script can be the default member hashlock
or a caller-supplied custody/control script. The payment leg is a normal BTP
output to the seller or settlement account.

This template makes the spend valid only if:

- The exact asset-transfer commitment output is present.
- The exact BTP payment output is present.
- The authorization script succeeds.

Changing either leg changes the checked output hash or amount and causes
`OP_CHECKOUTPUTVERIFY` to fail. Later native-asset consensus rules can enforce
asset conservation and whitelist membership against the same commitment.

Functional tests exercise both successful atomic DvP spends and failed spends
where the BTP payment amount is wrong or the required whitelist proof is absent.

## PvP Settlement Templates

Payment-versus-payment settlement is represented as a Tapscript leaf that
requires two asset-transfer legs to appear in the same transaction:

```text
<authorization_script> OP_VERIFY
<first_asset_commitment_scriptPubKeyHash> 0 <first_asset_output_index> OP_CHECKOUTPUTVERIFY
<second_asset_commitment_scriptPubKeyHash> 0 <second_asset_output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

Both legs are spendable asset carrier outputs, normally with payload type
`TRANSFER`. Each leg can use the default member hashlock or a caller-supplied
custody/control script.

This template makes the spend valid only if:

- The exact first asset-transfer commitment output is present.
- The exact second asset-transfer commitment output is present.
- The authorization script succeeds.

Changing either asset id, amount, metadata hash, output index, or script wrapper
changes the checked output hash and causes `OP_CHECKOUTPUTVERIFY` to fail.

Functional tests exercise both successful atomic PvP spends and failed spends
where an asset leg is at the wrong output index or a required whitelist proof is
absent.

## Collateral Lock/Release Templates

Collateral lock/release is represented as two Tapscript leaves over the same
locked output.

The release leaf has this shape:

```text
<authorization_script> OP_VERIFY
<release_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

The delayed return leaf has this shape:

```text
<authorization_script> OP_VERIFY
<relative_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<return_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

This gives institutions two clear collateral paths:

- Immediate release to a precommitted secured-party output after authorization.
- Delayed return to a precommitted pledgor output after the lock period.

The same template locks BTP collateral directly. Native-asset collateral is
represented by the asset output templates and settlement checks described above.

## Expiry/Refund Templates

Expiry/refund paths are represented as Tapscript leaves that combine timelocks
with exact refund-output covenants.

The absolute-expiry refund leaf has this shape:

```text
<authorization_script> OP_VERIFY
<absolute_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
<refund_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

The relative-expiry refund leaf has this shape:

```text
<authorization_script> OP_VERIFY
<relative_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<refund_scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY
OP_TRUE
```

This gives settlement templates a deterministic unwind path:

- Absolute expiry for calendar/block-height deadlines.
- Relative expiry for delays measured from confirmation or lock creation.

In both cases, expiry only opens the refund path; the covenant still requires
the refund to go to the precommitted output with the precommitted amount.
