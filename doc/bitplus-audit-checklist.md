# Bitplus Audit Checklist

This checklist maps fixed institutional primitives to implementation and test
coverage for external reviewers.

| Primitive | Implementation Surface | Current Coverage |
| --- | --- | --- |
| Multisig / threshold custody | Bitcoin Script/Tapscript, PSBT workflows | Existing Bitcoin script coverage; Bitplus PSBT analysis/readiness tests |
| Timelocks | CLTV/CSV in fixed templates | `feature_bitplus_covenants.py`, contract leaf construction tests |
| HTLCs | `BuildHtlcClaimLeaf`, `BuildHtlcRefundLeaf`, RPC helpers | Wrong preimage, valid claim, premature refund, valid refund |
| Covenants | `OP_CHECKOUTPUTVERIFY` under deployment flag | Active/inactive deployment, wrong amount/index, exact spend |
| Vaults | Recovery and delayed-spend leaves | Wrong recovery output, valid recovery, premature/valid delayed spend |
| Native assets | `BTPASSET` payloads, validation, conservation | C++ serialization tests, functional validation, fuzz target |
| Asset metadata commitments | `BTPMETA` payloads and linkage | C++ serialization tests, missing/invalid metadata tests, fuzz target |
| Whitelisted asset transfers | `BTPWLST`, `BTPWPROOF`, proof verification | Missing/duplicate/wrong-member/wrong-root proof tests |
| DvP settlement | Asset transfer plus exact payment covenant | Wrong payment, missing proof, valid atomic DvP |
| PvP settlement | Two asset legs plus exact index covenants | Wrong second index, missing proof, valid atomic PvP |
| Collateral lock/release | Release and delayed-return leaves | Wrong release output, valid release, premature/valid return |
| Expiry/refund paths | Absolute and relative refund leaves | Premature/valid CLTV refund, premature/valid CSV refund |

## Reviewer Focus Areas

- Serialization stability and version/domain strategy.
- Consensus activation boundaries.
- Asset conservation and issuance anchor rules.
- Whitelist proof linkage and duplicate/orphan handling.
- Reorg behavior for reconciliation reports.
- RPC readiness hash completeness.
- Denial-of-service profile of UTXO scans before asset indexing.
- Upgrade plan for cursor/report schema versions.
- Fuzz corpus coverage for valid and malformed Bitplus asset payloads.
