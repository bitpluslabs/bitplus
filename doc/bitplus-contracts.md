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

Institutional contracts are represented by the dormant versionbits deployment
`institutional_contracts`.

The deployment is intentionally set to `NEVER_ACTIVE` on all networks until the
contract semantics, test vectors, wallet behavior, and migration notes are
implemented and reviewed.

Functional coverage includes an inactive-deployment test that mines a mismatched
`OP_CHECKOUTPUTVERIFY` spend while `institutional_contracts` is inactive. This
keeps the soft-fork boundary explicit: before activation, the opcode byte remains
dormant and does not enforce the new covenant rule.

## Implementation Order

1. Covenants - started with `OP_CHECKOUTPUTVERIFY`
2. Vault templates - started with script construction helpers
3. Native asset commitment format - started with `BTPASSET` commitments
4. Asset metadata commitments - started with `BTPMETA` commitments
5. Whitelist rule commitments - started with `BTPWLST` commitments
6. DvP templates - started with script construction helpers
7. PvP templates - started with script construction helpers
8. Collateral lock/release templates - started with script construction helpers
9. Expiry/refund templates - started with script construction helpers

Each consensus change must include tests, activation notes, and documentation of
the difference from Bitcoin Core.

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
future policy fragment. The covenant keeps the value bound to the intended
output, and the delay gives recovery systems time to react before withdrawal.

## Native Asset Commitment Format

The first native-asset step is a stable commitment payload. This does not yet
enforce asset balances in consensus; it defines the bytes that later consensus
rules, wallets, indexers, and settlement templates will share.

The payload is:

```text
"BTPASSET" || version || type || asset_id || amount || metadata_hash ||
member_hash
```

Fields:

- `version`: 1 byte, currently `1`.
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
spend that asset state. This keeps asset outputs in the UTXO set so later
transactions can spend them and consensus can enforce asset conservation.
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

This gives later consensus code a deterministic way to inspect native-asset
commitments before enforcing conservation against spent-output asset state.
Until that spent-output state is tracked, these helpers are intentionally
non-consensus plumbing.

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
- `createbitplusscripttransaction`
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
- `createbitpluscollateral`
- `createbitplusrefundpaths`
- `createbitpluscovleaf`
- `createbitplusvaultrecoveryleaf`
- `createbitplusvaultdelayedleaf`
- `createbitplusdvpleaf`
- `createbitpluspvpleaf`
- `createbitpluscollateralreleaseleaf`
- `createbitpluscollateralreturnleaf`
- `createbitplusrefundabsoluteleaf`
- `createbitplusrefundrelativeleaf`

These return raw payloads, `scriptPubKey` hex, and commitment hashes that can be
used with raw transaction construction flows.

`createbitplusscripttransaction` creates a raw unsigned transaction from normal
inputs and an ordered list of exact `scriptPubKey` outputs. Each output may
include an expected `index`; the RPC rejects the transaction if the expected
index does not match the array position. This is useful for covenant
transactions where `OP_CHECKOUTPUTVERIFY` commits to exact output indexes.

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
verifies the whitelist proof root before producing the leaf.

`createbitpluspvp` builds a complete payment-versus-payment construction
package: two transfer carriers, their matching whitelist proofs, and a PvP
settlement leaf. Each leg can use its own whitelist root.

`createbitplusvault`, `createbitpluscollateral`, and `createbitplusrefundpaths`
return paired Tapscript leaves for the common two-path workflows: immediate
vault recovery plus delayed spend, collateral release plus delayed return, and
absolute plus relative refund.

The contract leaf helpers return raw Tapscript leaf hex plus a `script_hash`.
They expect hex-encoded authorization scripts and output scriptPubKeys, exact
BTP amounts, and exact output indexes. DvP/PvP helpers build `TRANSFER` asset
legs and bind them to zero-BTP asset carrier outputs.

## Asset Metadata Commitment Format

Asset metadata is committed separately from asset transfer records. The asset
commitment stores only `metadata_hash`, where:

```text
metadata_hash = SHA256(asset_metadata_commitment_payload)
```

The metadata payload is:

```text
"BTPMETA" || version || issuer_id || document_hash || rules_hash
```

Fields:

- `version`: 1 byte, currently `1`.
- `issuer_id`: 32 bytes. This identifies the issuing institution or policy root.
- `document_hash`: 32 bytes. This commits to legal, offering, or operational
  documents kept off-chain.
- `rules_hash`: 32 bytes. This commits to transfer restrictions, whitelist
  policy, or settlement rules interpreted by later consensus and wallet logic.

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
"BTPWLST" || version || list_id || admin_key_hash || members_root || flags
```

Fields:

- `version`: 1 byte, currently `1`.
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
"BTPWPROOF" || version || asset_output_index || member_hash || proof_index ||
path_count || merkle_path
```

Fields:

- `version`: 1 byte, currently `1`.
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
normally `TRANSFER`. The payment leg is a normal BTP output to the seller or
settlement account.

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
`TRANSFER`.

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

The same template can lock BTP collateral today, and later native-asset consensus
rules can extend the checked output to asset collateral commitments.

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
