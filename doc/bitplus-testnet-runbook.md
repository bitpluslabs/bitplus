# Bitplus Private Testnet Runbook

This runbook is for private/internal testing before external audit. Do not use it
for real funds.

## Build

```powershell
cmake --build build_node --config Release --target bitplusd bitplus-cli --parallel 2
```

Use low parallelism on small laptops to avoid memory pressure.

## Start Regtest With Institutional Contracts

```powershell
build_node\bin\Release\bitplusd.exe -regtest -datadir=<path> -acceptnonstdtxn=1 -vbparams=institutional_contracts:0:999999999999:0
```

Mine until `getblockchaininfo` reports `institutional_contracts` active.

## Operator Checks

- Use `createbitpluspsbt` or `createbitplusscripttransaction` to build exact
  settlement outputs.
- Use `analyzebitpluspsbt` before signing.
- Use `preparebitpluspsbt` when node UTXO enrichment is needed.
- Use `checkbitplussettlement` before broadcast. Default policy requires six
  confirmations for final inputs.
- Use `scanbitplusassetutxos`, `getbitplusassetstats`, and
  `getbitplusmemberassetstats` for reconciliation.

## Reorg Testing

- Mine asset issuance/transfer blocks.
- Use `invalidateblock` and `reconsiderblock`.
- Confirm reconciliation hashes and `chain_snapshot` values change on rollback
  and restore when the original chain is reconsidered.
- Confirm stale cursors fail instead of continuing.

## Exit Criteria For External Audit Prep

- Focused functional tests pass.
- Unit serialization tests pass.
- Fuzz target builds and can run locally.
- `bitplus_asset_payloads` seed corpus has been generated with
  `contrib/devtools/bitplus_asset_fuzz_seed_corpus.py`.
- Known limitations are documented.
- Audit checklist maps each primitive to implementation and tests.
