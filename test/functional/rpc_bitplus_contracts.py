#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Bitplus institutional contract construction RPCs."""

from decimal import Decimal

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.psbt import (
    PSBT,
    PSBT_IN_WITNESS_UTXO,
)
from test_framework.test_framework import BitplusTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32
HASH_D = "44" * 32
HASH_E = "55" * 32
NULL_HASH = "00" * 32
AUTH_SCRIPT = "51"
OUTPUT_SCRIPT = "51"
CUSTOM_ASSET_LOCK_A = "51"
CUSTOM_ASSET_LOCK_B = "52"


def assert_hex_hash(value):
    assert_equal(len(value), 64)
    int(value, 16)


def assert_contract_leaf(result):
    assert_greater_than(len(result["script"]), 0)
    int(result["script"], 16)
    assert_hex_hash(result["script_hash"])


def build_decode_tx(*script_pub_keys):
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(1, 0))]
    tx.vout = [CTxOut(0, bytes.fromhex(script_pub_key)) for script_pub_key in script_pub_keys]
    return tx.serialize().hex()


class BitplusContractsRPCTest(BitplusTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Test whitelist root and proof RPCs")
        root = node.createbitplusassetwhitelistroot([HASH_A, HASH_B, HASH_C], 2)
        assert_hex_hash(root["members_root"])
        assert_equal(root["member_count"], 3)
        assert_equal(root["proof_index"], 2)
        assert_equal(root["member_hash"], HASH_C)
        assert_equal(len(root["merkle_path"]), 2)

        proof = node.createbitplusassetwhitelistproof(0, HASH_C, 2, root["merkle_path"])
        assert_equal(proof["members_root"], root["members_root"])
        assert_hex_hash(proof["commitment_hash"])
        assert_greater_than(len(proof["payload"]), 0)
        assert_greater_than(len(proof["scriptPubKey"]), 0)

        whitelist = node.createbitplusassetwhitelist(HASH_A, HASH_B, root["members_root"])
        assert_hex_hash(whitelist["commitment_hash"])

        self.log.info("Test asset construction RPCs")
        metadata = node.createbitplusassetmetadata(HASH_A, HASH_B, whitelist["commitment_hash"])
        assert_hex_hash(metadata["commitment_hash"])

        asset_id = node.createbitplusassetid(metadata["commitment_hash"], HASH_D, 0)
        assert_hex_hash(asset_id)

        asset = node.createbitplusasset("transfer", asset_id, 100, metadata["commitment_hash"], HASH_E)
        assert_equal(asset["asset_id"], asset_id)
        assert_hex_hash(asset["commitment_hash"])
        assert_greater_than(len(asset["scriptPubKey"]), 0)

        transfer = node.createbitplusassettransfer(asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"])
        assert_equal(transfer["members_root"], root["members_root"])
        assert_equal(transfer["transfer"]["asset_id"], asset_id)
        assert_hex_hash(transfer["transfer"]["commitment_hash"])
        assert_equal(transfer["proof"]["members_root"], root["members_root"])
        assert_hex_hash(transfer["proof"]["commitment_hash"])

        dvp = node.createbitplusdvp(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"], OUTPUT_SCRIPT, "1.00000000", 1)
        assert_equal(dvp["members_root"], root["members_root"])
        assert_equal(dvp["transfer"]["asset_id"], asset_id)
        assert_hex_hash(dvp["transfer"]["commitment_hash"])
        assert_equal(dvp["proof"]["members_root"], root["members_root"])
        assert_hex_hash(dvp["proof"]["commitment_hash"])
        assert_contract_leaf(dvp["settlement_leaf"])

        custom_dvp = node.createbitplusdvp(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"], OUTPUT_SCRIPT, "1.00000000", 1, CUSTOM_ASSET_LOCK_A)
        assert_equal(custom_dvp["transfer"]["asset_id"], asset_id)
        assert_contract_leaf(custom_dvp["settlement_leaf"])
        assert custom_dvp["transfer"]["scriptPubKey"] != dvp["transfer"]["scriptPubKey"]

        pvp = node.createbitpluspvp(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"], asset_id, 50, metadata["commitment_hash"], HASH_C, 1, 2, root["merkle_path"], root["members_root"])
        assert_equal(pvp["first_transfer"]["asset_id"], asset_id)
        assert_hex_hash(pvp["first_transfer"]["commitment_hash"])
        assert_equal(pvp["first_proof"]["members_root"], root["members_root"])
        assert_hex_hash(pvp["first_proof"]["commitment_hash"])
        assert_equal(pvp["second_transfer"]["asset_id"], asset_id)
        assert_hex_hash(pvp["second_transfer"]["commitment_hash"])
        assert_equal(pvp["second_proof"]["members_root"], root["members_root"])
        assert_hex_hash(pvp["second_proof"]["commitment_hash"])
        assert_contract_leaf(pvp["settlement_leaf"])

        custom_pvp = node.createbitpluspvp(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"], asset_id, 50, metadata["commitment_hash"], HASH_C, 1, 2, root["merkle_path"], root["members_root"], CUSTOM_ASSET_LOCK_A, CUSTOM_ASSET_LOCK_B)
        assert_contract_leaf(custom_pvp["settlement_leaf"])
        assert custom_pvp["first_transfer"]["scriptPubKey"] != pvp["first_transfer"]["scriptPubKey"]
        assert custom_pvp["second_transfer"]["scriptPubKey"] != pvp["second_transfer"]["scriptPubKey"]

        burn = node.createbitplusassetburn(asset_id, 25, metadata["commitment_hash"], HASH_C)
        assert_equal(burn["asset_id"], asset_id)
        assert_hex_hash(burn["commitment_hash"])

        issuance = node.createbitplusassetissuance(HASH_D, 0, 500, HASH_A, HASH_B, HASH_A, HASH_B, root["members_root"], HASH_E)
        assert_equal(issuance["whitelist"]["commitment_hash"], whitelist["commitment_hash"])
        assert_equal(issuance["metadata"]["commitment_hash"], metadata["commitment_hash"])
        assert_equal(issuance["asset_id"], asset_id)
        assert_equal(issuance["issuance"]["asset_id"], asset_id)
        assert_hex_hash(issuance["issuance"]["commitment_hash"])

        self.log.info("Test decoderawtransaction exposes Bitplus commitments")
        decoded = node.decoderawtransaction(build_decode_tx(
            asset["scriptPubKey"],
            metadata["scriptPubKey"],
            whitelist["scriptPubKey"],
            proof["scriptPubKey"],
            issuance["issuance"]["scriptPubKey"],
            transfer["transfer"]["scriptPubKey"],
            transfer["proof"]["scriptPubKey"],
            burn["scriptPubKey"],
            custom_dvp["transfer"]["scriptPubKey"],
            custom_pvp["first_transfer"]["scriptPubKey"],
            custom_pvp["second_transfer"]["scriptPubKey"],
        ))
        decoded_asset = decoded["vout"][0]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_asset["format"], "BTPASSET")
        assert_equal(decoded_asset["type"], "transfer")
        assert_equal(decoded_asset["asset_id"], asset_id)
        assert_equal(decoded_asset["amount"], 100)
        assert_equal(decoded_asset["metadata_hash"], metadata["commitment_hash"])
        assert_equal(decoded_asset["member_hash"], HASH_E)
        assert_equal(decoded_asset["commitment_hash"], asset["commitment_hash"])
        assert_equal(decoded_asset["locking_script"]["hex"], "a820" + HASH_E + "87")

        decoded_custom_dvp_asset = decoded["vout"][8]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_custom_dvp_asset["locking_script"]["hex"], CUSTOM_ASSET_LOCK_A)

        decoded_custom_pvp_first_asset = decoded["vout"][9]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_custom_pvp_first_asset["locking_script"]["hex"], CUSTOM_ASSET_LOCK_A)

        decoded_custom_pvp_second_asset = decoded["vout"][10]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_custom_pvp_second_asset["locking_script"]["hex"], CUSTOM_ASSET_LOCK_B)

        decoded_metadata = decoded["vout"][1]["scriptPubKey"]["bitplus_asset_metadata"]
        assert_equal(decoded_metadata["format"], "BTPMETA")
        assert_equal(decoded_metadata["issuer_id"], HASH_A)
        assert_equal(decoded_metadata["document_hash"], HASH_B)
        assert_equal(decoded_metadata["rules_hash"], whitelist["commitment_hash"])
        assert_equal(decoded_metadata["commitment_hash"], metadata["commitment_hash"])

        decoded_whitelist = decoded["vout"][2]["scriptPubKey"]["bitplus_asset_whitelist"]
        assert_equal(decoded_whitelist["format"], "BTPWLST")
        assert_equal(decoded_whitelist["list_id"], HASH_A)
        assert_equal(decoded_whitelist["admin_key_hash"], HASH_B)
        assert_equal(decoded_whitelist["members_root"], root["members_root"])
        assert_equal(decoded_whitelist["commitment_hash"], whitelist["commitment_hash"])

        decoded_proof = decoded["vout"][3]["scriptPubKey"]["bitplus_asset_whitelist_proof"]
        assert_equal(decoded_proof["format"], "BTPWPROOF")
        assert_equal(decoded_proof["asset_output_index"], 0)
        assert_equal(decoded_proof["member_hash"], HASH_C)
        assert_equal(decoded_proof["proof_index"], 2)
        assert_equal(decoded_proof["merkle_path"], root["merkle_path"])
        assert_equal(decoded_proof["members_root"], root["members_root"])
        assert_equal(decoded_proof["commitment_hash"], proof["commitment_hash"])

        decoded_issuance = decoded["vout"][4]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_issuance["type"], "issuance")
        assert_equal(decoded_issuance["asset_id"], asset_id)
        assert_equal(decoded_issuance["amount"], 500)
        assert_equal(decoded_issuance["metadata_hash"], metadata["commitment_hash"])
        assert_equal(decoded_issuance["member_hash"], HASH_E)
        assert_equal(decoded_issuance["commitment_hash"], issuance["issuance"]["commitment_hash"])

        decoded_transfer = decoded["vout"][5]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_transfer["type"], "transfer")
        assert_equal(decoded_transfer["asset_id"], asset_id)
        assert_equal(decoded_transfer["amount"], 100)
        assert_equal(decoded_transfer["metadata_hash"], metadata["commitment_hash"])
        assert_equal(decoded_transfer["member_hash"], HASH_C)
        assert_equal(decoded_transfer["commitment_hash"], transfer["transfer"]["commitment_hash"])

        decoded_transfer_proof = decoded["vout"][6]["scriptPubKey"]["bitplus_asset_whitelist_proof"]
        assert_equal(decoded_transfer_proof["asset_output_index"], 0)
        assert_equal(decoded_transfer_proof["member_hash"], HASH_C)
        assert_equal(decoded_transfer_proof["proof_index"], 2)
        assert_equal(decoded_transfer_proof["merkle_path"], root["merkle_path"])
        assert_equal(decoded_transfer_proof["members_root"], root["members_root"])
        assert_equal(decoded_transfer_proof["commitment_hash"], transfer["proof"]["commitment_hash"])

        decoded_burn = decoded["vout"][7]["scriptPubKey"]["bitplus_asset"]
        assert_equal(decoded_burn["type"], "burn")
        assert_equal(decoded_burn["asset_id"], asset_id)
        assert_equal(decoded_burn["amount"], 25)
        assert_equal(decoded_burn["metadata_hash"], metadata["commitment_hash"])
        assert_equal(decoded_burn["member_hash"], HASH_C)
        assert_equal(decoded_burn["commitment_hash"], burn["commitment_hash"])

        self.log.info("Test standalone Bitplus script decoding")
        decoded_script_asset = node.decodebitplusscript(transfer["transfer"]["scriptPubKey"], "0.00000000", 5)
        assert_equal(decoded_script_asset["recognized"], True)
        assert_equal(decoded_script_asset["bitplus_type"], "asset")
        assert_equal(decoded_script_asset["valid"], True)
        assert_equal(decoded_script_asset["commitment"]["commitment_hash"], transfer["transfer"]["commitment_hash"])

        decoded_script_nonzero = node.decodebitplusscript(transfer["transfer"]["scriptPubKey"], "0.00000001", 5)
        assert_equal(decoded_script_nonzero["recognized"], True)
        assert_equal(decoded_script_nonzero["valid"], False)
        assert_equal(decoded_script_nonzero["validation_error"], "asset-carrier-nonzero")

        decoded_script_metadata = node.decodebitplusscript(metadata["scriptPubKey"])
        assert_equal(decoded_script_metadata["recognized"], True)
        assert_equal(decoded_script_metadata["bitplus_type"], "metadata")
        assert_equal(decoded_script_metadata["valid"], True)

        decoded_script_plain = node.decodebitplusscript(OUTPUT_SCRIPT)
        assert_equal(decoded_script_plain["recognized"], False)

        self.log.info("Test standalone Bitplus transaction analysis")
        analysis_tx = build_decode_tx(
            transfer["transfer"]["scriptPubKey"],
            metadata["scriptPubKey"],
            whitelist["scriptPubKey"],
            transfer["proof"]["scriptPubKey"],
        )
        analysis = node.analyzebitplustransaction(analysis_tx)
        assert_equal(analysis["recognized_outputs"], 4)
        assert_hex_hash(analysis["bitplus_review_hash"])
        assert_equal(analysis["bitplus_review_complete"], False)
        assert_equal(analysis["conservation_checked"], False)
        assert_equal(analysis["valid"], True)
        assert_equal(len(analysis["issues"]), 0)
        assert_equal(analysis["asset_outputs"][0]["commitment"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(analysis["metadata_outputs"][0]["commitment"]["commitment_hash"], metadata["commitment_hash"])
        assert_equal(analysis["whitelist_outputs"][0]["commitment"]["commitment_hash"], whitelist["commitment_hash"])
        assert_equal(analysis["whitelist_proof_outputs"][0]["commitment"]["commitment_hash"], transfer["proof"]["commitment_hash"])

        conservation_analysis = node.analyzebitplustransaction(analysis_tx, [{
            "input_index": 0,
            "scriptPubKey": transfer["transfer"]["scriptPubKey"],
            "amount": "0.00000000",
        }])
        assert_hex_hash(conservation_analysis["bitplus_review_hash"])
        assert_equal(conservation_analysis["bitplus_review_complete"], True)
        assert conservation_analysis["bitplus_review_hash"] != analysis["bitplus_review_hash"]
        assert_equal(conservation_analysis["conservation_checked"], True)
        assert_equal(conservation_analysis["valid"], True)
        assert_equal(conservation_analysis["spent_asset_outputs"][0]["commitment"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(conservation_analysis["asset_conservation"][0]["asset_id"], asset_id)
        assert_equal(conservation_analysis["asset_conservation"][0]["balanced"], True)
        conservation_movement = next(movement for movement in conservation_analysis["participant_movements"] if movement["asset_id"] == asset_id and movement["member_hash"] == HASH_C)
        assert_equal(conservation_movement["spent"], 100)
        assert_equal(conservation_movement["received"], 100)
        assert_equal(conservation_movement["burned"], 0)
        assert_equal(conservation_movement["net"], 0)
        assert_equal(conservation_movement["overflow"], False)

        self.log.info("Test Bitplus PSBT analysis with input UTXO conservation")
        psbt = PSBT.from_base64(node.converttopsbt(analysis_tx))
        psbt.i[0].map[PSBT_IN_WITNESS_UTXO] = CTxOut(0, bytes.fromhex(transfer["transfer"]["scriptPubKey"])).serialize()
        psbt_analysis = node.analyzebitpluspsbt(psbt.to_base64())
        assert_hex_hash(psbt_analysis["bitplus_review_hash"])
        assert_equal(psbt_analysis["bitplus_review_complete"], True)
        assert_equal(psbt_analysis["bitplus_review_hash"], conservation_analysis["bitplus_review_hash"])
        assert_equal(psbt_analysis["psbt_utxos_available"], True)
        assert_equal(len(psbt_analysis["missing_psbt_utxos"]), 0)
        assert_equal(psbt_analysis["conservation_checked"], True)
        assert_equal(psbt_analysis["valid"], True)
        assert_equal(psbt_analysis["spent_asset_outputs"][0]["input_index"], 0)
        assert_equal(psbt_analysis["spent_asset_outputs"][0]["commitment"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(psbt_analysis["asset_conservation"][0]["balanced"], True)
        psbt_movement = next(movement for movement in psbt_analysis["participant_movements"] if movement["asset_id"] == asset_id and movement["member_hash"] == HASH_C)
        assert_equal(psbt_movement["spent"], 100)
        assert_equal(psbt_movement["received"], 100)
        assert_equal(psbt_movement["net"], 0)

        missing_utxo_psbt_analysis = node.analyzebitpluspsbt(node.converttopsbt(analysis_tx))
        assert_hex_hash(missing_utxo_psbt_analysis["bitplus_review_hash"])
        assert_equal(missing_utxo_psbt_analysis["bitplus_review_complete"], False)
        assert_equal(missing_utxo_psbt_analysis["psbt_utxos_available"], False)
        assert_equal(missing_utxo_psbt_analysis["missing_psbt_utxos"], [0])
        assert_equal(missing_utxo_psbt_analysis["conservation_checked"], False)
        assert_equal(missing_utxo_psbt_analysis["valid"], False)
        assert "psbt-input-utxo-missing" in missing_utxo_psbt_analysis["issues"]

        unbalanced_analysis = node.analyzebitplustransaction(build_decode_tx(burn["scriptPubKey"]), [{
            "input_index": 0,
            "scriptPubKey": transfer["transfer"]["scriptPubKey"],
            "amount": "0.00000000",
        }])
        assert_equal(unbalanced_analysis["conservation_checked"], True)
        assert_equal(unbalanced_analysis["valid"], False)
        assert "bad-txns-asset-conservation" in unbalanced_analysis["issues"]
        assert_equal(unbalanced_analysis["asset_conservation"][0]["balanced"], False)
        burn_movement = next(movement for movement in unbalanced_analysis["participant_movements"] if movement["asset_id"] == asset_id and movement["member_hash"] == HASH_C)
        assert_equal(burn_movement["spent"], 100)
        assert_equal(burn_movement["received"], 0)
        assert_equal(burn_movement["burned"], 25)
        assert_equal(burn_movement["net"], -100)

        missing_proof_analysis = node.analyzebitplustransaction(build_decode_tx(
            transfer["transfer"]["scriptPubKey"],
            metadata["scriptPubKey"],
            whitelist["scriptPubKey"],
        ))
        assert_equal(missing_proof_analysis["valid"], False)
        assert "asset-whitelist-proof-missing" in missing_proof_analysis["issues"]

        self.log.info("Test Bitplus transaction analysis with node UTXO lookup")
        lookup_tx = wallet.create_self_transfer()["tx"]
        lookup_analysis = node.analyzebitplustransaction(lookup_tx.serialize().hex(), [], True)
        assert_hex_hash(lookup_analysis["bitplus_review_hash"])
        assert_equal(lookup_analysis["bitplus_review_complete"], True)
        assert_equal(lookup_analysis["input_utxos_available"], True)
        assert_equal(len(lookup_analysis["missing_input_utxos"]), 0)
        assert_equal(lookup_analysis["conservation_checked"], True)
        assert_equal(lookup_analysis["valid"], True)
        assert_equal(len(lookup_analysis["asset_conservation"]), 0)

        missing_lookup_analysis = node.analyzebitplustransaction(analysis_tx, [], True)
        assert_equal(missing_lookup_analysis["input_utxos_available"], False)
        assert_equal(missing_lookup_analysis["missing_input_utxos"], [0])
        assert_equal(missing_lookup_analysis["valid"], False)
        assert "input-utxo-missing" in missing_lookup_analysis["issues"]

        self.log.info("Test zero-BTP asset carrier output is standard and not dust")
        asset_policy_tx = wallet.create_self_transfer()["tx"]
        asset_policy_tx.vout.append(CTxOut(0, bytes.fromhex(transfer["transfer"]["scriptPubKey"])))
        asset_policy_tx.vout.append(CTxOut(0, bytes.fromhex(transfer["proof"]["scriptPubKey"])))
        asset_policy_tx.vout.append(CTxOut(0, bytes.fromhex(burn["scriptPubKey"])))
        mempool_result = node.testmempoolaccept([asset_policy_tx.serialize().hex()])[0]
        assert_equal(mempool_result["allowed"], True)

        self.log.info("Test exact script transaction assembly")
        script_tx = node.createbitplusscripttransaction(
            [{"txid": HASH_D, "vout": 0}],
            [
                {"scriptPubKey": transfer["transfer"]["scriptPubKey"], "amount": "0.00000000", "index": 0},
                {"scriptPubKey": transfer["proof"]["scriptPubKey"], "amount": "0.00000000", "index": 1},
                {"scriptPubKey": OUTPUT_SCRIPT, "amount": "1.00000000", "index": 2},
            ],
        )
        assert_hex_hash(script_tx["txid"])
        assembled = node.decoderawtransaction(script_tx["hex"])
        assert_equal(assembled["txid"], script_tx["txid"])
        assert_equal(assembled["vout"][0]["scriptPubKey"]["bitplus_asset"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(assembled["vout"][1]["scriptPubKey"]["bitplus_asset_whitelist_proof"]["commitment_hash"], transfer["proof"]["commitment_hash"])
        assert_equal(assembled["vout"][2]["scriptPubKey"]["hex"], OUTPUT_SCRIPT)

        self.log.info("Test exact script PSBT assembly")
        script_psbt = node.createbitpluspsbt(
            [{"txid": HASH_D, "vout": 0}],
            [
                {"scriptPubKey": transfer["transfer"]["scriptPubKey"], "amount": "0.00000000", "index": 0},
                {"scriptPubKey": transfer["proof"]["scriptPubKey"], "amount": "0.00000000", "index": 1},
                {"scriptPubKey": OUTPUT_SCRIPT, "amount": "1.00000000", "index": 2},
            ],
        )
        assert_equal(script_psbt["txid"], script_tx["txid"])
        decoded_psbt = node.decodepsbt(script_psbt["psbt"])
        assert_equal(decoded_psbt["tx"]["txid"], script_tx["txid"])
        assert_equal(decoded_psbt["tx"]["vout"][0]["scriptPubKey"]["bitplus_asset"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(decoded_psbt["tx"]["vout"][1]["scriptPubKey"]["bitplus_asset_whitelist_proof"]["commitment_hash"], transfer["proof"]["commitment_hash"])
        assert_equal(decoded_psbt["tx"]["vout"][2]["scriptPubKey"]["hex"], OUTPUT_SCRIPT)
        script_psbt_analysis = node.analyzebitpluspsbt(script_psbt["psbt"])
        assert_equal(script_psbt_analysis["recognized_outputs"], 2)
        assert_equal(script_psbt_analysis["psbt_utxos_available"], False)
        assert_equal(script_psbt_analysis["missing_psbt_utxos"], [0])

        self.log.info("Test settlement readiness check")
        ready_plain = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw")
        assert_equal(ready_plain["format"], "raw")
        assert_equal(ready_plain["final_transaction_available"], True)
        assert_equal(ready_plain["bitplus_valid"], True)
        assert_equal(ready_plain["recognized_outputs"], ready_plain["bitplus_analysis"]["recognized_outputs"])
        assert_equal(ready_plain["bitplus_analysis_summary"]["recognized_outputs"], ready_plain["recognized_outputs"])
        assert_equal(ready_plain["bitplus_analysis_summary"]["output_commitment_counts"]["asset_outputs"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["output_commitment_counts"]["metadata_outputs"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_outputs"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_proof_outputs"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["spent_asset_outputs"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["asset_conservation_entries"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["unbalanced_asset_conservation_entries"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["participant_movement_entries"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["issue_count"], 0)
        assert_equal(ready_plain["bitplus_analysis_summary"]["valid"], True)
        assert_equal(ready_plain["bitplus_analysis_summary"]["review_complete"], True)
        assert_equal(ready_plain["bitplus_analysis_summary"]["conservation_checked"], True)
        assert_equal(ready_plain["conservation_checked"], ready_plain["bitplus_analysis"]["conservation_checked"])
        assert_equal(ready_plain["prevout_context_available"], ready_plain["bitplus_analysis"]["input_utxos_available"])
        assert_equal(ready_plain["missing_prevout_indexes"], ready_plain["bitplus_analysis"]["missing_input_utxos"])
        assert_hex_hash(ready_plain["bitplus_review_hash"])
        assert_equal(ready_plain["bitplus_review_hash"], ready_plain["bitplus_analysis"]["bitplus_review_hash"])
        assert_equal(ready_plain["bitplus_review_complete"], True)
        assert_equal(ready_plain["bitplus_review_complete"], ready_plain["bitplus_analysis"]["bitplus_review_complete"])
        assert_equal(ready_plain["asset_conservation"], ready_plain["bitplus_analysis"]["asset_conservation"])
        assert_equal(ready_plain["participant_movements"], ready_plain["bitplus_analysis"]["participant_movements"])
        assert_hex_hash(ready_plain["settlement_readiness_hash"])
        assert_hex_hash(ready_plain["readiness_report_hash"])
        assert_greater_than(ready_plain["chain_snapshot"]["height"], 0)
        assert_hex_hash(ready_plain["chain_snapshot"]["bestblock"])
        assert_equal(ready_plain["readiness_policy"]["version"], "BitplusSettlementReadinessV1")
        assert_equal(ready_plain["readiness_policy"]["format"], "raw")
        assert_equal(ready_plain["readiness_policy"]["check_mempool"], True)
        assert_greater_than(ready_plain["readiness_policy"]["maxfeerate"], 0)
        assert_equal(ready_plain["readiness_policy"]["min_input_confirmations"], 6)
        assert_equal(ready_plain["readiness_policy"]["require_institutional_contracts_active"], True)
        assert_equal(ready_plain["readiness_policy"]["require_complete_bitplus_review"], True)
        assert_greater_than(ready_plain["maxfeerate"], 0)
        assert_equal(ready_plain["min_input_confirmations"], 6)
        assert_equal(ready_plain["input_confirmations_available"], True)
        assert_equal(ready_plain["input_confirmation_summary"]["total_inputs"], 1)
        assert_equal(ready_plain["input_confirmation_summary"]["available_inputs"], 1)
        assert_equal(ready_plain["input_confirmation_summary"]["missing_inputs"], 0)
        assert_equal(ready_plain["input_confirmation_summary"]["confirmed_inputs"], 1)
        assert_equal(ready_plain["input_confirmation_summary"]["mempool_inputs"], 0)
        assert_equal(ready_plain["input_confirmation_summary"]["required_confirmations"], 6)
        assert_equal(ready_plain["input_confirmation_summary"]["below_min_confirmations"], 0)
        assert_greater_than(ready_plain["input_confirmation_summary"]["min_observed_confirmations"], 5)
        assert_equal(len(ready_plain["input_confirmations"]), 1)
        assert_equal(ready_plain["input_confirmations"][0]["available"], True)
        assert_equal(ready_plain["input_confirmations"][0]["source"], "chain")
        assert_greater_than(ready_plain["input_confirmations"][0]["confirmations"], 5)
        assert_equal(ready_plain["inputs_below_min_confirmations"], [])
        assert_equal(ready_plain["mempool_allowed"], True)
        assert_equal(ready_plain["ready_to_broadcast"], True)
        assert_equal(ready_plain["readiness_issue_summary"]["blocking_issue_count"], 0)
        assert_equal(ready_plain["readiness_issue_summary"]["warning_count"], 0)
        assert_equal(ready_plain["readiness_issue_summary"]["analyzer_issue_count"], 0)
        assert_equal(ready_plain["readiness_issue_summary"]["readiness_issue_count"], 0)
        assert_equal(ready_plain["readiness_issue_summary"]["has_blocking_issues"], False)
        assert_equal(ready_plain["readiness_issue_summary"]["has_warnings"], False)
        assert_equal(len(ready_plain["issues"]), 0)
        assert_greater_than(ready_plain["weight"], 0)
        assert_greater_than(ready_plain["vsize"], 0)
        ready_plain_repeat = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw")
        assert_equal(ready_plain_repeat["chain_snapshot"], ready_plain["chain_snapshot"])
        assert_equal(ready_plain_repeat["settlement_readiness_hash"], ready_plain["settlement_readiness_hash"])
        assert_equal(ready_plain_repeat["readiness_report_hash"], ready_plain["readiness_report_hash"])
        no_max_fee_check = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw", True, 0, 6)
        assert_equal(no_max_fee_check["ready_to_broadcast"], True)
        assert_equal(no_max_fee_check["maxfeerate"], 0)
        assert_equal(no_max_fee_check["readiness_policy"]["maxfeerate"], 0)
        assert no_max_fee_check["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert no_max_fee_check["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        no_mempool_check = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw", False)
        assert_equal(no_mempool_check["ready_to_broadcast"], True)
        assert_equal(no_mempool_check["readiness_policy"]["check_mempool"], False)
        assert "mempool-check-skipped" in no_mempool_check["warnings"]
        assert_equal(no_mempool_check["readiness_issue_summary"]["blocking_issue_count"], 0)
        assert_equal(no_mempool_check["readiness_issue_summary"]["warning_count"], 1)
        assert_equal(no_mempool_check["readiness_issue_summary"]["has_warnings"], True)
        assert "mempool_allowed" not in no_mempool_check
        assert no_mempool_check["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert no_mempool_check["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        strict_confirmations = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw", True, 0, 1000000)
        assert_hex_hash(strict_confirmations["settlement_readiness_hash"])
        assert_hex_hash(strict_confirmations["readiness_report_hash"])
        assert strict_confirmations["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert strict_confirmations["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        assert_equal(strict_confirmations["ready_to_broadcast"], False)
        assert_equal(strict_confirmations["min_input_confirmations"], 1000000)
        assert_equal(strict_confirmations["input_confirmations_available"], True)
        assert_equal(strict_confirmations["input_confirmation_summary"]["required_confirmations"], 1000000)
        assert_equal(strict_confirmations["input_confirmation_summary"]["below_min_confirmations"], 1)
        assert_equal(strict_confirmations["readiness_issue_summary"]["blocking_issue_count"], 1)
        assert_equal(strict_confirmations["readiness_issue_summary"]["analyzer_issue_count"], 0)
        assert_equal(strict_confirmations["readiness_issue_summary"]["readiness_issue_count"], 1)
        assert_equal(strict_confirmations["readiness_issue_summary"]["confirmation_issues"], 1)
        assert_equal(len(strict_confirmations["inputs_below_min_confirmations"]), 1)
        assert "input-confirmations-too-low" in strict_confirmations["issues"]

        psbt_check = node.checkbitplussettlement(script_psbt["psbt"], "psbt")
        assert_equal(psbt_check["format"], "psbt")
        assert_equal(psbt_check["chain_snapshot"], ready_plain["chain_snapshot"])
        assert_equal(psbt_check["readiness_policy"]["format"], "psbt")
        assert_equal(psbt_check["readiness_policy"]["check_mempool"], True)
        assert_equal(psbt_check["recognized_outputs"], psbt_check["bitplus_analysis"]["recognized_outputs"])
        assert_equal(psbt_check["bitplus_analysis_summary"]["recognized_outputs"], 2)
        assert_equal(psbt_check["bitplus_analysis_summary"]["output_commitment_counts"]["asset_outputs"], 1)
        assert_equal(psbt_check["bitplus_analysis_summary"]["output_commitment_counts"]["metadata_outputs"], 0)
        assert_equal(psbt_check["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_outputs"], 0)
        assert_equal(psbt_check["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_proof_outputs"], 1)
        assert_equal(psbt_check["bitplus_analysis_summary"]["issue_count"], 2)
        assert_equal(psbt_check["bitplus_analysis_summary"]["valid"], False)
        assert_equal(psbt_check["bitplus_analysis_summary"]["review_complete"], False)
        assert_equal(psbt_check["conservation_checked"], psbt_check["bitplus_analysis"]["conservation_checked"])
        assert_equal(psbt_check["prevout_context_available"], psbt_check["bitplus_analysis"]["psbt_utxos_available"])
        assert_equal(psbt_check["missing_prevout_indexes"], psbt_check["bitplus_analysis"]["missing_psbt_utxos"])
        assert_hex_hash(psbt_check["bitplus_review_hash"])
        assert_equal(psbt_check["bitplus_review_hash"], psbt_check["bitplus_analysis"]["bitplus_review_hash"])
        assert_equal(psbt_check["bitplus_review_complete"], False)
        assert_equal(psbt_check["bitplus_review_complete"], psbt_check["bitplus_analysis"]["bitplus_review_complete"])
        assert_equal(psbt_check["asset_conservation"], psbt_check["bitplus_analysis"]["asset_conservation"])
        assert_equal(psbt_check["participant_movements"], psbt_check["bitplus_analysis"]["participant_movements"])
        assert_hex_hash(psbt_check["settlement_readiness_hash"])
        assert_hex_hash(psbt_check["readiness_report_hash"])
        assert psbt_check["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert psbt_check["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        assert_equal(psbt_check["final_transaction_available"], False)
        assert_equal(psbt_check["ready_to_broadcast"], False)
        assert_equal(psbt_check["readiness_issue_summary"]["blocking_issue_count"], 4)
        assert_equal(psbt_check["readiness_issue_summary"]["analyzer_issue_count"], 2)
        assert_equal(psbt_check["readiness_issue_summary"]["readiness_issue_count"], 2)
        assert_equal(psbt_check["readiness_issue_summary"]["finalization_issues"], 1)
        assert_equal(psbt_check["readiness_issue_summary"]["activation_issues"], 1)
        assert_equal(psbt_check["readiness_issue_summary"]["prevout_context_issues"], 1)
        assert "psbt-not-finalized" in psbt_check["issues"]
        assert "psbt-input-utxo-missing" in psbt_check["issues"]

        missing_input_check = node.checkbitplussettlement(analysis_tx, "raw")
        assert_equal(missing_input_check["recognized_outputs"], missing_input_check["bitplus_analysis"]["recognized_outputs"])
        assert_equal(missing_input_check["bitplus_analysis_summary"]["recognized_outputs"], 4)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["output_commitment_counts"]["asset_outputs"], 1)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["output_commitment_counts"]["metadata_outputs"], 1)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_outputs"], 1)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["output_commitment_counts"]["whitelist_proof_outputs"], 1)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["issue_count"], 1)
        assert_equal(missing_input_check["bitplus_analysis_summary"]["valid"], False)
        assert_equal(missing_input_check["conservation_checked"], missing_input_check["bitplus_analysis"]["conservation_checked"])
        assert_equal(missing_input_check["prevout_context_available"], False)
        assert_equal(missing_input_check["missing_prevout_indexes"], [0])
        assert_hex_hash(missing_input_check["bitplus_review_hash"])
        assert_equal(missing_input_check["bitplus_review_complete"], False)
        assert_equal(missing_input_check["asset_conservation"], missing_input_check["bitplus_analysis"]["asset_conservation"])
        assert_equal(missing_input_check["participant_movements"], missing_input_check["bitplus_analysis"]["participant_movements"])
        assert_hex_hash(missing_input_check["settlement_readiness_hash"])
        assert_hex_hash(missing_input_check["readiness_report_hash"])
        assert missing_input_check["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert missing_input_check["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        assert_equal(missing_input_check["input_confirmations_available"], False)
        assert_equal(missing_input_check["input_confirmation_summary"]["total_inputs"], 1)
        assert_equal(missing_input_check["input_confirmation_summary"]["available_inputs"], 0)
        assert_equal(missing_input_check["input_confirmation_summary"]["missing_inputs"], 1)
        assert_equal(missing_input_check["input_confirmation_summary"]["confirmed_inputs"], 0)
        assert_equal(missing_input_check["input_confirmation_summary"]["mempool_inputs"], 0)
        assert_equal(missing_input_check["input_confirmation_summary"]["below_min_confirmations"], 0)
        assert_equal(missing_input_check["input_confirmations"][0]["available"], False)
        assert_equal(missing_input_check["ready_to_broadcast"], False)
        assert_equal(missing_input_check["readiness_issue_summary"]["blocking_issue_count"], 4)
        assert_equal(missing_input_check["readiness_issue_summary"]["analyzer_issue_count"], 1)
        assert_equal(missing_input_check["readiness_issue_summary"]["readiness_issue_count"], 3)
        assert_equal(missing_input_check["readiness_issue_summary"]["activation_issues"], 1)
        assert_equal(missing_input_check["readiness_issue_summary"]["prevout_context_issues"], 1)
        assert_equal(missing_input_check["readiness_issue_summary"]["confirmation_issues"], 1)
        assert_equal(missing_input_check["readiness_issue_summary"]["mempool_issues"], 1)
        assert "input-utxo-missing" in missing_input_check["issues"]
        assert "input-confirmations-unavailable" in missing_input_check["issues"]
        assert "mempool-missing-inputs" in missing_input_check["issues"]

        self.log.info("Test Bitplus PSBT preparation with node UTXO enrichment")
        blank_lookup_psbt = node.converttopsbt(lookup_tx.serialize().hex(), True)
        prepared_psbt = node.preparebitpluspsbt(blank_lookup_psbt)
        assert_equal(prepared_psbt["txid"], lookup_tx.txid_hex)
        assert_equal(prepared_psbt["missing_utxos_before"], 1)
        assert_equal(prepared_psbt["missing_utxos_after"], 0)
        assert_equal(prepared_psbt["utxos_fully_available"], True)
        assert_equal(prepared_psbt["bitplus_analysis"]["psbt_utxos_available"], True)
        prepared_check = node.checkbitplussettlement(prepared_psbt["psbt"], "psbt")
        assert_equal(prepared_check["recognized_outputs"], prepared_check["bitplus_analysis"]["recognized_outputs"])
        assert_equal(prepared_check["bitplus_analysis_summary"]["review_complete"], True)
        assert_equal(prepared_check["bitplus_analysis_summary"]["issue_count"], 0)
        assert_equal(prepared_check["conservation_checked"], prepared_check["bitplus_analysis"]["conservation_checked"])
        assert_equal(prepared_check["prevout_context_available"], prepared_check["bitplus_analysis"]["psbt_utxos_available"])
        assert_equal(prepared_check["missing_prevout_indexes"], prepared_check["bitplus_analysis"]["missing_psbt_utxos"])
        assert_hex_hash(prepared_check["bitplus_review_hash"])
        assert_equal(prepared_check["bitplus_review_complete"], True)
        assert_equal(prepared_check["asset_conservation"], prepared_check["bitplus_analysis"]["asset_conservation"])
        assert_equal(prepared_check["participant_movements"], prepared_check["bitplus_analysis"]["participant_movements"])
        assert_hex_hash(prepared_check["settlement_readiness_hash"])
        assert_hex_hash(prepared_check["readiness_report_hash"])
        assert_equal(prepared_check["ready_to_broadcast"], False)
        assert_equal(prepared_check["readiness_issue_summary"]["blocking_issue_count"], 1)
        assert_equal(prepared_check["readiness_issue_summary"]["analyzer_issue_count"], 0)
        assert_equal(prepared_check["readiness_issue_summary"]["readiness_issue_count"], 1)
        assert_equal(prepared_check["readiness_issue_summary"]["finalization_issues"], 1)
        assert "psbt-not-finalized" in prepared_check["issues"]
        assert "psbt-input-utxo-missing" not in prepared_check["issues"]

        self.log.info("Test settlement readiness commits to chain snapshot changes")
        self.generate(wallet, 1)
        advanced_ready = node.checkbitplussettlement(lookup_tx.serialize().hex(), "raw")
        assert_equal(advanced_ready["ready_to_broadcast"], True)
        assert_equal(advanced_ready["chain_snapshot"]["height"], ready_plain["chain_snapshot"]["height"] + 1)
        assert advanced_ready["chain_snapshot"]["bestblock"] != ready_plain["chain_snapshot"]["bestblock"]
        assert advanced_ready["settlement_readiness_hash"] != ready_plain["settlement_readiness_hash"]
        assert advanced_ready["readiness_report_hash"] != ready_plain["readiness_report_hash"]
        assert_equal(
            advanced_ready["input_confirmations"][0]["confirmations"],
            ready_plain["input_confirmations"][0]["confirmations"] + 1,
        )

        self.log.info("Test Bitplus asset UTXO scanning")
        asset_utxo_tx = wallet.send_to(from_node=node, scriptPubKey=bytes.fromhex(transfer["transfer"]["scriptPubKey"]), amount=0)
        second_asset_utxo_tx = wallet.send_to(from_node=node, scriptPubKey=bytes.fromhex(transfer["transfer"]["scriptPubKey"]), amount=0)
        bulk_asset_utxos = [
            wallet.send_to(from_node=node, scriptPubKey=bytes.fromhex(transfer["transfer"]["scriptPubKey"]), amount=0)
            for _ in range(10)
        ]
        asset_utxo_block = self.generate(wallet, 1)[0]
        scanned = node.scanbitplusassetutxos(asset_id, 20)
        assert_equal(scanned["report_type"], "asset_utxo_scan")
        assert_equal(scanned["report_version"], 1)
        assert_equal(scanned["asset_id"], asset_id)
        assert_hex_hash(scanned["reconciliation_hash"])
        assert_hex_hash(scanned["scan_summary_hash"])
        assert_equal(scanned["scan_summary"]["report_type"], "asset_utxo_scan")
        assert_equal(scanned["scan_summary"]["summary_version"], 1)
        assert_equal(scanned["scan_summary"]["asset_id"], scanned["asset_id"])
        assert_equal(scanned["scan_summary"]["filters"], scanned["filters"])
        assert_hex_hash(scanned["scan_summary"]["filters_hash"])
        assert "cursor" not in scanned["scan_summary"]
        assert_equal(scanned["scan_summary"]["height"], scanned["height"])
        assert_equal(scanned["scan_summary"]["bestblock"], scanned["bestblock"])
        assert_equal(scanned["chain_snapshot"]["height"], scanned["height"])
        assert_equal(scanned["chain_snapshot"]["bestblock"], scanned["bestblock"])
        assert_equal(scanned["scan_summary"]["chain_snapshot"], scanned["chain_snapshot"])
        assert_hex_hash(scanned["scan_summary"]["chain_snapshot_hash"])
        assert_equal(scanned["scan_summary"]["max_results"], 20)
        assert_equal(scanned["scan_summary"]["searched_txouts"], scanned["searched_txouts"])
        assert_equal(scanned["scan_summary"]["cursor_applied"], False)
        assert_equal(scanned["scan_summary"]["reconciliation_hash"], scanned["reconciliation_hash"])
        assert_equal(scanned["complete"], True)
        assert_equal(scanned["scan_summary"]["complete"], scanned["complete"])
        assert_equal(scanned["scan_summary"]["has_next_cursor"], False)
        assert_equal(scanned["scan_summary"]["matches"], scanned["matches"])
        repeated_scan = node.scanbitplusassetutxos(asset_id, 20)
        assert_equal(repeated_scan["reconciliation_hash"], scanned["reconciliation_hash"])
        assert_equal(repeated_scan["scan_summary_hash"], scanned["scan_summary_hash"])
        assert_equal(repeated_scan["scan_summary"]["filters_hash"], scanned["scan_summary"]["filters_hash"])
        assert_equal(repeated_scan["scan_summary"]["chain_snapshot_hash"], scanned["scan_summary"]["chain_snapshot_hash"])
        assert_greater_than(scanned["searched_txouts"], 0)
        found = [utxo for utxo in scanned["utxos"] if utxo["txid"] == asset_utxo_tx["txid"] and utxo["vout"] == asset_utxo_tx["sent_vout"]]
        assert_equal(len(found), 1)
        assert_equal(found[0]["commitment"]["commitment_hash"], transfer["transfer"]["commitment_hash"])
        assert_equal(found[0]["commitment"]["type"], "transfer")
        assert_equal(found[0]["amount"], Decimal("0E-8"))
        assert_greater_than(found[0]["confirmations"], 0)
        second_found = [utxo for utxo in scanned["utxos"] if utxo["txid"] == second_asset_utxo_tx["txid"] and utxo["vout"] == second_asset_utxo_tx["sent_vout"]]
        assert_equal(len(second_found), 1)
        for bulk_utxo in bulk_asset_utxos[:3]:
            assert_equal(len([utxo for utxo in scanned["utxos"] if utxo["txid"] == bulk_utxo["txid"] and utxo["vout"] == bulk_utxo["sent_vout"]]), 1)
        first_page = node.scanbitplusassetutxos(asset_id, 1)
        assert_hex_hash(first_page["reconciliation_hash"])
        assert_hex_hash(first_page["scan_summary_hash"])
        assert_equal(first_page["scan_summary"]["summary_version"], 1)
        assert_equal(first_page["complete"], False)
        assert_equal(first_page["scan_summary"]["complete"], False)
        assert_equal(first_page["scan_summary"]["has_next_cursor"], True)
        assert_equal(first_page["matches"], 1)
        assert "next_cursor" in first_page
        assert_equal(first_page["next_cursor"]["cursor_version"], 1)
        assert_equal(first_page["next_cursor"]["asset_id"], asset_id)
        assert_equal(first_page["next_cursor"]["filters_hash"], first_page["scan_summary"]["filters_hash"])
        second_page = node.scanbitplusassetutxos(asset_id, 1, {}, first_page["next_cursor"])
        assert_hex_hash(second_page["reconciliation_hash"])
        assert_hex_hash(second_page["scan_summary_hash"])
        assert_equal(second_page["scan_summary"]["summary_version"], 1)
        assert_equal(second_page["cursor"], first_page["next_cursor"])
        assert_equal(second_page["scan_summary"]["cursor_applied"], True)
        assert_equal(second_page["scan_summary"]["cursor"], second_page["cursor"])
        assert second_page["reconciliation_hash"] != first_page["reconciliation_hash"]
        assert second_page["scan_summary_hash"] != first_page["scan_summary_hash"]
        assert (first_page["utxos"][0]["txid"], first_page["utxos"][0]["vout"]) != (second_page["utxos"][0]["txid"], second_page["utxos"][0]["vout"])
        full_scan = node.scanbitplusassetutxos(asset_id, 100)
        full_outpoints = {(utxo["txid"], utxo["vout"]) for utxo in full_scan["utxos"]}
        paged_outpoints = set()
        page = node.scanbitplusassetutxos(asset_id, 3)
        while True:
            paged_outpoints.update((utxo["txid"], utxo["vout"]) for utxo in page["utxos"])
            if page["complete"]:
                break
            page = node.scanbitplusassetutxos(asset_id, 3, {}, page["next_cursor"])
        assert_equal(paged_outpoints, full_outpoints)
        expected_outpoints = {(asset_utxo_tx["txid"], asset_utxo_tx["sent_vout"]), (second_asset_utxo_tx["txid"], second_asset_utxo_tx["sent_vout"])}
        expected_outpoints.update((utxo["txid"], utxo["sent_vout"]) for utxo in bulk_asset_utxos)
        assert expected_outpoints.issubset(full_outpoints)
        stale_cursor = dict(first_page["next_cursor"])
        stale_cursor["height"] += 1
        assert_raises_rpc_error(-8, "cursor does not match the active chain tip", node.scanbitplusassetutxos, asset_id, 1, {}, stale_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["cursor_version"] = 2
        assert_raises_rpc_error(-8, "cursor_version must be 1", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        mismatched_cursor = dict(first_page["next_cursor"])
        mismatched_cursor["asset_id"] = HASH_D
        assert_raises_rpc_error(-8, "cursor asset_id does not match requested asset_id", node.scanbitplusassetutxos, asset_id, 1, {}, mismatched_cursor)
        mismatched_cursor = dict(first_page["next_cursor"])
        mismatched_cursor["filters_hash"] = HASH_D
        assert_raises_rpc_error(-8, "cursor filters_hash does not match requested filters", node.scanbitplusassetutxos, asset_id, 1, {}, mismatched_cursor)
        assert_raises_rpc_error(-8, "cursor filters_hash does not match requested filters", node.scanbitplusassetutxos, asset_id, 1, {"type": "transfer"}, first_page["next_cursor"])
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["cursor_version"]
        assert_raises_rpc_error(-8, "cursor cursor_version is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["unexpected"] = 1
        assert_raises_rpc_error(-8, "unknown cursor field: unexpected", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["bestblock"]
        assert_raises_rpc_error(-8, "cursor bestblock is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["height"]
        assert_raises_rpc_error(-8, "cursor height is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["asset_id"]
        assert_raises_rpc_error(-8, "cursor asset_id is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["filters_hash"]
        assert_raises_rpc_error(-8, "cursor filters_hash is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["txid"]
        assert_raises_rpc_error(-8, "cursor txid is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        missing_cursor_field = dict(first_page["next_cursor"])
        del missing_cursor_field["vout"]
        assert_raises_rpc_error(-8, "cursor vout is required", node.scanbitplusassetutxos, asset_id, 1, {}, missing_cursor_field)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["bestblock"] = NULL_HASH
        assert_raises_rpc_error(-8, "cursor bestblock must not be null", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["asset_id"] = NULL_HASH
        assert_raises_rpc_error(-8, "cursor asset_id must not be null", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["filters_hash"] = NULL_HASH
        assert_raises_rpc_error(-8, "cursor filters_hash must not be null", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["txid"] = NULL_HASH
        assert_raises_rpc_error(-8, "cursor txid must not be null", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["height"] = -1
        assert_raises_rpc_error(-8, "cursor height must be non-negative", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["vout"] = -1
        assert_raises_rpc_error(-8, "cursor vout out of range", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        bad_cursor = dict(first_page["next_cursor"])
        bad_cursor["txid"] = HASH_D
        assert_raises_rpc_error(-8, "cursor outpoint was not found in the active UTXO set", node.scanbitplusassetutxos, asset_id, 1, {}, bad_cursor)
        filtered = node.scanbitplusassetutxos(asset_id, 20, {
            "type": "transfer",
            "metadata_hash": metadata["commitment_hash"],
            "member_hash": HASH_C,
        })
        assert_equal(filtered["filters"]["type"], "transfer")
        assert_equal(filtered["filters"]["metadata_hash"], metadata["commitment_hash"])
        assert_equal(filtered["filters"]["member_hash"], HASH_C)
        assert_equal(filtered["scan_summary"]["filters"], filtered["filters"])
        assert_hex_hash(filtered["scan_summary"]["filters_hash"])
        assert filtered["scan_summary"]["filters_hash"] != scanned["scan_summary"]["filters_hash"]
        assert_hex_hash(filtered["reconciliation_hash"])
        assert_hex_hash(filtered["scan_summary_hash"])
        assert filtered["reconciliation_hash"] != scanned["reconciliation_hash"]
        assert filtered["scan_summary_hash"] != scanned["scan_summary_hash"]
        assert_equal(len([utxo for utxo in filtered["utxos"] if utxo["txid"] == asset_utxo_tx["txid"]]), 1)
        reordered_filtered = node.scanbitplusassetutxos(asset_id, 20, {
            "member_hash": HASH_C,
            "metadata_hash": metadata["commitment_hash"],
            "type": "transfer",
        })
        assert_equal(reordered_filtered["filters"], filtered["filters"])
        assert_equal(reordered_filtered["scan_summary"]["filters_hash"], filtered["scan_summary"]["filters_hash"])
        assert_equal(reordered_filtered["reconciliation_hash"], filtered["reconciliation_hash"])
        assert_equal(reordered_filtered["scan_summary_hash"], filtered["scan_summary_hash"])
        confirmed_scan = node.scanbitplusassetutxos(asset_id, 20, {"min_confirmations": 1})
        assert_equal(confirmed_scan["filters"]["min_confirmations"], 1)
        assert_equal(confirmed_scan["scan_summary"]["filters"], confirmed_scan["filters"])
        assert_hex_hash(confirmed_scan["scan_summary"]["filters_hash"])
        assert confirmed_scan["scan_summary"]["filters_hash"] != scanned["scan_summary"]["filters_hash"]
        assert_equal(confirmed_scan["matches"], scanned["matches"])
        assert_hex_hash(confirmed_scan["reconciliation_hash"])
        assert_hex_hash(confirmed_scan["scan_summary_hash"])
        assert confirmed_scan["reconciliation_hash"] != scanned["reconciliation_hash"]
        assert confirmed_scan["scan_summary_hash"] != scanned["scan_summary_hash"]
        mature_scan = node.scanbitplusassetutxos(asset_id, 10, {"min_confirmations": 1000000})
        assert_equal(mature_scan["filters"]["min_confirmations"], 1000000)
        assert_equal(mature_scan["matches"], 0)
        assert_equal(node.scanbitplusassetutxos(asset_id, 10, {"type": "issuance"})["matches"], 0)

        stats = node.getbitplusassetstats(asset_id)
        assert_equal(stats["report_type"], "asset_stats")
        assert_equal(stats["report_version"], 1)
        assert_equal(stats["asset_id"], asset_id)
        assert_hex_hash(stats["reconciliation_hash"])
        assert_hex_hash(stats["reconciliation_summary_hash"])
        assert_equal(stats["reconciliation_summary"]["report_type"], "asset_stats")
        assert_equal(stats["reconciliation_summary"]["summary_version"], 1)
        assert_equal(stats["reconciliation_summary"]["asset_id"], stats["asset_id"])
        assert_equal(stats["reconciliation_summary"]["filters"], stats["filters"])
        assert_hex_hash(stats["reconciliation_summary"]["filters_hash"])
        assert_equal(stats["reconciliation_summary"]["height"], stats["height"])
        assert_equal(stats["reconciliation_summary"]["bestblock"], stats["bestblock"])
        assert_equal(stats["chain_snapshot"]["height"], stats["height"])
        assert_equal(stats["chain_snapshot"]["bestblock"], stats["bestblock"])
        assert_equal(stats["reconciliation_summary"]["chain_snapshot"], stats["chain_snapshot"])
        assert_hex_hash(stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert_equal(stats["reconciliation_summary"]["reconciliation_hash"], stats["reconciliation_hash"])
        assert_greater_than(stats["searched_txouts"], 0)
        assert_greater_than(stats["utxo_count"], 0)
        assert_equal(stats["reconciliation_summary"]["searched_txouts"], stats["searched_txouts"])
        assert_equal(stats["reconciliation_summary"]["utxo_count"], stats["utxo_count"])
        assert_greater_than(stats["min_confirmations_observed"], 0)
        assert_greater_than(stats["max_confirmations_observed"], 0)
        assert_equal(stats["reconciliation_summary"]["min_confirmations_observed"], stats["min_confirmations_observed"])
        assert_equal(stats["reconciliation_summary"]["max_confirmations_observed"], stats["max_confirmations_observed"])
        assert stats["max_confirmations_observed"] >= stats["min_confirmations_observed"]
        assert_greater_than(stats["total_amount"], 0)
        assert_equal(stats["reconciliation_summary"]["total_amount"], stats["total_amount"])
        assert_equal(stats["issued_amount"], 0)
        assert_equal(stats["held_amount"], stats["total_amount"])
        assert_equal(stats["burned_amount"], 0)
        assert_equal(stats["outstanding_amount"], 0)
        assert_equal(stats["supply_underflow"], False)
        assert_equal(stats["holder_supply_balanced"], False)
        assert_equal(stats["holder_supply_delta"], stats["held_amount"])
        assert_equal(stats["holder_count"], 1)
        assert_equal(stats["overflow"], False)
        assert_equal(stats["reconciliation_summary"]["issued_amount"], stats["issued_amount"])
        assert_equal(stats["reconciliation_summary"]["held_amount"], stats["held_amount"])
        assert_equal(stats["reconciliation_summary"]["burned_amount"], stats["burned_amount"])
        assert_equal(stats["reconciliation_summary"]["outstanding_amount"], stats["outstanding_amount"])
        assert_equal(stats["reconciliation_summary"]["supply_underflow"], stats["supply_underflow"])
        assert_equal(stats["reconciliation_summary"]["holder_supply_balanced"], stats["holder_supply_balanced"])
        assert_equal(stats["reconciliation_summary"]["holder_count"], stats["holder_count"])
        assert_equal(stats["reconciliation_summary"]["overflow"], stats["overflow"])
        repeated_stats = node.getbitplusassetstats(asset_id)
        assert_equal(repeated_stats["reconciliation_hash"], stats["reconciliation_hash"])
        assert_equal(repeated_stats["reconciliation_summary_hash"], stats["reconciliation_summary_hash"])
        assert_equal(repeated_stats["reconciliation_summary"]["filters_hash"], stats["reconciliation_summary"]["filters_hash"])
        assert_equal(repeated_stats["reconciliation_summary"]["chain_snapshot_hash"], stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert_greater_than(stats["by_type"]["transfer"]["count"], 0)
        assert_greater_than(stats["by_type"]["transfer"]["amount"], 0)
        assert_equal(stats["by_metadata_hash"][metadata["commitment_hash"]]["amount"], stats["total_amount"])
        assert_greater_than(stats["by_member_hash"][HASH_C]["count"], 0)
        assert_equal(stats["by_holder_member_hash"][HASH_C]["amount"], stats["held_amount"])
        filtered_stats = node.getbitplusassetstats(asset_id, {
            "type": "transfer",
            "metadata_hash": metadata["commitment_hash"],
            "member_hash": HASH_C,
        })
        assert_equal(filtered_stats["filters"]["type"], "transfer")
        assert_equal(filtered_stats["filters"]["metadata_hash"], metadata["commitment_hash"])
        assert_equal(filtered_stats["filters"]["member_hash"], HASH_C)
        assert_equal(filtered_stats["reconciliation_summary"]["filters"], filtered_stats["filters"])
        assert_hex_hash(filtered_stats["reconciliation_summary"]["filters_hash"])
        assert filtered_stats["reconciliation_summary"]["filters_hash"] != stats["reconciliation_summary"]["filters_hash"]
        assert_hex_hash(filtered_stats["reconciliation_hash"])
        assert_hex_hash(filtered_stats["reconciliation_summary_hash"])
        assert filtered_stats["reconciliation_hash"] != stats["reconciliation_hash"]
        assert filtered_stats["reconciliation_summary_hash"] != stats["reconciliation_summary_hash"]
        assert_equal(filtered_stats["utxo_count"], stats["utxo_count"])
        assert_equal(filtered_stats["held_amount"], stats["held_amount"])
        assert_equal(filtered_stats["holder_count"], 1)
        reordered_filtered_stats = node.getbitplusassetstats(asset_id, {
            "member_hash": HASH_C,
            "metadata_hash": metadata["commitment_hash"],
            "type": "transfer",
        })
        assert_equal(reordered_filtered_stats["filters"], filtered_stats["filters"])
        assert_equal(reordered_filtered_stats["reconciliation_summary"]["filters_hash"], filtered_stats["reconciliation_summary"]["filters_hash"])
        assert_equal(reordered_filtered_stats["reconciliation_hash"], filtered_stats["reconciliation_hash"])
        assert_equal(reordered_filtered_stats["reconciliation_summary_hash"], filtered_stats["reconciliation_summary_hash"])
        confirmed_stats = node.getbitplusassetstats(asset_id, {"min_confirmations": 1})
        assert_equal(confirmed_stats["filters"]["min_confirmations"], 1)
        assert_equal(confirmed_stats["reconciliation_summary"]["filters"], confirmed_stats["filters"])
        assert_hex_hash(confirmed_stats["reconciliation_summary"]["filters_hash"])
        assert confirmed_stats["reconciliation_summary"]["filters_hash"] != stats["reconciliation_summary"]["filters_hash"]
        assert_equal(confirmed_stats["utxo_count"], stats["utxo_count"])
        assert_equal(confirmed_stats["min_confirmations_observed"], stats["min_confirmations_observed"])
        assert_equal(confirmed_stats["max_confirmations_observed"], stats["max_confirmations_observed"])
        assert_hex_hash(confirmed_stats["reconciliation_hash"])
        assert_hex_hash(confirmed_stats["reconciliation_summary_hash"])
        assert confirmed_stats["reconciliation_hash"] != stats["reconciliation_hash"]
        assert confirmed_stats["reconciliation_summary_hash"] != stats["reconciliation_summary_hash"]
        mature_stats = node.getbitplusassetstats(asset_id, {"min_confirmations": 1000000})
        assert_equal(mature_stats["filters"]["min_confirmations"], 1000000)
        assert_equal(mature_stats["utxo_count"], 0)
        assert "min_confirmations_observed" not in mature_stats
        assert "max_confirmations_observed" not in mature_stats
        assert "min_confirmations_observed" not in mature_stats["reconciliation_summary"]
        assert "max_confirmations_observed" not in mature_stats["reconciliation_summary"]
        assert_equal(node.getbitplusassetstats(asset_id, {"type": "issuance"})["utxo_count"], 0)

        member_stats = node.getbitplusmemberassetstats(HASH_C)
        assert_equal(member_stats["report_type"], "member_asset_stats")
        assert_equal(member_stats["report_version"], 1)
        assert_equal(member_stats["member_hash"], HASH_C)
        assert_hex_hash(member_stats["reconciliation_hash"])
        assert_hex_hash(member_stats["reconciliation_summary_hash"])
        assert_equal(member_stats["reconciliation_summary"]["report_type"], "member_asset_stats")
        assert_equal(member_stats["reconciliation_summary"]["summary_version"], 1)
        assert_equal(member_stats["reconciliation_summary"]["member_hash"], member_stats["member_hash"])
        assert_equal(member_stats["reconciliation_summary"]["filters"], member_stats["filters"])
        assert_hex_hash(member_stats["reconciliation_summary"]["filters_hash"])
        assert_equal(member_stats["reconciliation_summary"]["height"], member_stats["height"])
        assert_equal(member_stats["reconciliation_summary"]["bestblock"], member_stats["bestblock"])
        assert_equal(member_stats["chain_snapshot"]["height"], member_stats["height"])
        assert_equal(member_stats["chain_snapshot"]["bestblock"], member_stats["bestblock"])
        assert_equal(member_stats["reconciliation_summary"]["chain_snapshot"], member_stats["chain_snapshot"])
        assert_hex_hash(member_stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert_equal(member_stats["reconciliation_summary"]["reconciliation_hash"], member_stats["reconciliation_hash"])
        assert_greater_than(member_stats["searched_txouts"], 0)
        assert_greater_than(member_stats["asset_count"], 0)
        assert_greater_than(member_stats["utxo_count"], 0)
        assert_equal(member_stats["reconciliation_summary"]["searched_txouts"], member_stats["searched_txouts"])
        assert_equal(member_stats["reconciliation_summary"]["asset_count"], member_stats["asset_count"])
        assert_equal(member_stats["reconciliation_summary"]["utxo_count"], member_stats["utxo_count"])
        assert_greater_than(member_stats["min_confirmations_observed"], 0)
        assert_greater_than(member_stats["max_confirmations_observed"], 0)
        assert_equal(member_stats["reconciliation_summary"]["min_confirmations_observed"], member_stats["min_confirmations_observed"])
        assert_equal(member_stats["reconciliation_summary"]["max_confirmations_observed"], member_stats["max_confirmations_observed"])
        assert member_stats["max_confirmations_observed"] >= member_stats["min_confirmations_observed"]
        assert_greater_than(member_stats["total_amount"], 0)
        assert_equal(member_stats["issued_amount"], 0)
        assert_equal(member_stats["held_amount"], member_stats["total_amount"])
        assert_equal(member_stats["burned_amount"], 0)
        assert_equal(member_stats["holder_asset_count"], 1)
        assert_equal(member_stats["overflow"], False)
        assert_equal(member_stats["reconciliation_summary"]["total_amount"], member_stats["total_amount"])
        assert_equal(member_stats["reconciliation_summary"]["issued_amount"], member_stats["issued_amount"])
        assert_equal(member_stats["reconciliation_summary"]["held_amount"], member_stats["held_amount"])
        assert_equal(member_stats["reconciliation_summary"]["burned_amount"], member_stats["burned_amount"])
        assert_equal(member_stats["reconciliation_summary"]["holder_asset_count"], member_stats["holder_asset_count"])
        assert_equal(member_stats["reconciliation_summary"]["overflow"], member_stats["overflow"])
        repeated_member_stats = node.getbitplusmemberassetstats(HASH_C)
        assert_equal(repeated_member_stats["reconciliation_hash"], member_stats["reconciliation_hash"])
        assert_equal(repeated_member_stats["reconciliation_summary_hash"], member_stats["reconciliation_summary_hash"])
        assert_equal(repeated_member_stats["reconciliation_summary"]["filters_hash"], member_stats["reconciliation_summary"]["filters_hash"])
        assert_equal(repeated_member_stats["reconciliation_summary"]["chain_snapshot_hash"], member_stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert asset_id in member_stats["assets"]
        assert_greater_than(member_stats["assets"][asset_id]["utxo_count"], 0)
        assert_equal(member_stats["assets"][asset_id]["min_confirmations_observed"], member_stats["min_confirmations_observed"])
        assert_equal(member_stats["assets"][asset_id]["max_confirmations_observed"], member_stats["max_confirmations_observed"])
        assert_greater_than(member_stats["assets"][asset_id]["total_amount"], 0)
        assert_equal(member_stats["assets"][asset_id]["held_amount"], member_stats["assets"][asset_id]["total_amount"])
        assert_equal(member_stats["assets"][asset_id]["is_holder"], True)
        assert_greater_than(member_stats["assets"][asset_id]["by_type"]["transfer"]["count"], 0)
        assert_equal(member_stats["assets"][asset_id]["by_metadata_hash"][metadata["commitment_hash"]]["amount"], member_stats["assets"][asset_id]["total_amount"])
        filtered_member_stats = node.getbitplusmemberassetstats(HASH_C, {
            "asset_id": asset_id,
            "type": "transfer",
            "metadata_hash": metadata["commitment_hash"],
        })
        assert_equal(filtered_member_stats["filters"]["asset_id"], asset_id)
        assert_equal(filtered_member_stats["filters"]["type"], "transfer")
        assert_equal(filtered_member_stats["filters"]["metadata_hash"], metadata["commitment_hash"])
        assert_equal(filtered_member_stats["reconciliation_summary"]["filters"], filtered_member_stats["filters"])
        assert_hex_hash(filtered_member_stats["reconciliation_summary"]["filters_hash"])
        assert filtered_member_stats["reconciliation_summary"]["filters_hash"] != member_stats["reconciliation_summary"]["filters_hash"]
        assert_hex_hash(filtered_member_stats["reconciliation_hash"])
        assert_hex_hash(filtered_member_stats["reconciliation_summary_hash"])
        assert filtered_member_stats["reconciliation_hash"] != member_stats["reconciliation_hash"]
        assert filtered_member_stats["reconciliation_summary_hash"] != member_stats["reconciliation_summary_hash"]
        assert_equal(filtered_member_stats["asset_count"], 1)
        assert_equal(filtered_member_stats["utxo_count"], member_stats["assets"][asset_id]["utxo_count"])
        assert_equal(filtered_member_stats["held_amount"], member_stats["assets"][asset_id]["held_amount"])
        reordered_filtered_member_stats = node.getbitplusmemberassetstats(HASH_C, {
            "metadata_hash": metadata["commitment_hash"],
            "type": "transfer",
            "asset_id": asset_id,
        })
        assert_equal(reordered_filtered_member_stats["filters"], filtered_member_stats["filters"])
        assert_equal(reordered_filtered_member_stats["reconciliation_summary"]["filters_hash"], filtered_member_stats["reconciliation_summary"]["filters_hash"])
        assert_equal(reordered_filtered_member_stats["reconciliation_hash"], filtered_member_stats["reconciliation_hash"])
        assert_equal(reordered_filtered_member_stats["reconciliation_summary_hash"], filtered_member_stats["reconciliation_summary_hash"])
        confirmed_member_stats = node.getbitplusmemberassetstats(HASH_C, {"asset_id": asset_id, "min_confirmations": 1})
        assert_equal(confirmed_member_stats["filters"]["min_confirmations"], 1)
        assert_equal(confirmed_member_stats["reconciliation_summary"]["filters"], confirmed_member_stats["filters"])
        assert_hex_hash(confirmed_member_stats["reconciliation_summary"]["filters_hash"])
        assert confirmed_member_stats["reconciliation_summary"]["filters_hash"] != member_stats["reconciliation_summary"]["filters_hash"]
        assert_equal(confirmed_member_stats["utxo_count"], filtered_member_stats["utxo_count"])
        assert_equal(confirmed_member_stats["min_confirmations_observed"], filtered_member_stats["min_confirmations_observed"])
        assert_equal(confirmed_member_stats["max_confirmations_observed"], filtered_member_stats["max_confirmations_observed"])
        assert_hex_hash(confirmed_member_stats["reconciliation_hash"])
        assert_hex_hash(confirmed_member_stats["reconciliation_summary_hash"])
        assert confirmed_member_stats["reconciliation_hash"] != filtered_member_stats["reconciliation_hash"]
        assert confirmed_member_stats["reconciliation_summary_hash"] != filtered_member_stats["reconciliation_summary_hash"]
        mature_member_stats = node.getbitplusmemberassetstats(HASH_C, {"asset_id": asset_id, "min_confirmations": 1000000})
        assert_equal(mature_member_stats["filters"]["min_confirmations"], 1000000)
        assert_equal(mature_member_stats["utxo_count"], 0)
        assert "min_confirmations_observed" not in mature_member_stats
        assert "max_confirmations_observed" not in mature_member_stats
        assert "min_confirmations_observed" not in mature_member_stats["reconciliation_summary"]
        assert "max_confirmations_observed" not in mature_member_stats["reconciliation_summary"]
        missing_member_stats = node.getbitplusmemberassetstats(HASH_D, {"asset_id": asset_id})
        assert_hex_hash(missing_member_stats["reconciliation_hash"])
        assert_hex_hash(missing_member_stats["reconciliation_summary_hash"])
        assert_equal(missing_member_stats["utxo_count"], 0)
        assert "min_confirmations_observed" not in missing_member_stats
        assert "max_confirmations_observed" not in missing_member_stats
        assert "min_confirmations_observed" not in missing_member_stats["reconciliation_summary"]
        assert "max_confirmations_observed" not in missing_member_stats["reconciliation_summary"]
        assert_equal(missing_member_stats["holder_asset_count"], 0)

        self.log.info("Test Bitplus reconciliation reports are stable across restart")
        self.restart_node(0)
        node = self.nodes[0]
        restarted_scan = node.scanbitplusassetutxos(asset_id, 20)
        assert_equal(restarted_scan["reconciliation_hash"], scanned["reconciliation_hash"])
        assert_equal(restarted_scan["scan_summary_hash"], scanned["scan_summary_hash"])
        assert_equal(restarted_scan["scan_summary"]["chain_snapshot_hash"], scanned["scan_summary"]["chain_snapshot_hash"])
        restarted_second_page = node.scanbitplusassetutxos(asset_id, 1, {}, first_page["next_cursor"])
        assert_equal(restarted_second_page["reconciliation_hash"], second_page["reconciliation_hash"])
        assert_equal(restarted_second_page["scan_summary_hash"], second_page["scan_summary_hash"])
        restarted_stats = node.getbitplusassetstats(asset_id)
        assert_equal(restarted_stats["reconciliation_hash"], stats["reconciliation_hash"])
        assert_equal(restarted_stats["reconciliation_summary_hash"], stats["reconciliation_summary_hash"])
        restarted_member_stats = node.getbitplusmemberassetstats(HASH_C)
        assert_equal(restarted_member_stats["reconciliation_hash"], member_stats["reconciliation_hash"])
        assert_equal(restarted_member_stats["reconciliation_summary_hash"], member_stats["reconciliation_summary_hash"])

        self.log.info("Test Bitplus asset reconciliation follows active-chain reorgs")
        node.invalidateblock(asset_utxo_block)
        assert_raises_rpc_error(-8, "cursor does not match the active chain tip", node.scanbitplusassetutxos, asset_id, 1, {}, first_page["next_cursor"])
        reorged_scan = node.scanbitplusassetutxos(asset_id, 10)
        assert_hex_hash(reorged_scan["reconciliation_hash"])
        assert reorged_scan["reconciliation_hash"] != scanned["reconciliation_hash"]
        assert_hex_hash(reorged_scan["scan_summary"]["chain_snapshot_hash"])
        assert reorged_scan["scan_summary"]["chain_snapshot_hash"] != scanned["scan_summary"]["chain_snapshot_hash"]
        assert_equal(reorged_scan["matches"], 0)
        assert_equal(reorged_scan["complete"], True)
        reorged_stats = node.getbitplusassetstats(asset_id)
        assert_hex_hash(reorged_stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert reorged_stats["reconciliation_summary"]["chain_snapshot_hash"] != stats["reconciliation_summary"]["chain_snapshot_hash"]
        assert_equal(reorged_stats["utxo_count"], 0)
        assert_equal(reorged_stats["total_amount"], 0)
        reorged_member_stats = node.getbitplusmemberassetstats(HASH_C, {"asset_id": asset_id})
        assert_hex_hash(reorged_member_stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert reorged_member_stats["reconciliation_summary"]["chain_snapshot_hash"] != member_stats["reconciliation_summary"]["chain_snapshot_hash"]
        assert_equal(reorged_member_stats["asset_count"], 0)
        assert_equal(reorged_member_stats["utxo_count"], 0)
        assert_equal(reorged_member_stats["total_amount"], 0)

        node.reconsiderblock(asset_utxo_block)
        restored_scan = node.scanbitplusassetutxos(asset_id, 20)
        assert_hex_hash(restored_scan["reconciliation_hash"])
        assert_equal(restored_scan["reconciliation_hash"], scanned["reconciliation_hash"])
        assert_equal(restored_scan["scan_summary"]["chain_snapshot_hash"], scanned["scan_summary"]["chain_snapshot_hash"])
        restored_found = [utxo for utxo in restored_scan["utxos"] if utxo["txid"] == asset_utxo_tx["txid"] and utxo["vout"] == asset_utxo_tx["sent_vout"]]
        assert_equal(len(restored_found), 1)
        restored_stats = node.getbitplusassetstats(asset_id)
        assert_equal(restored_stats["reconciliation_summary"]["chain_snapshot_hash"], stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert_equal(restored_stats["utxo_count"], stats["utxo_count"])
        assert_equal(restored_stats["total_amount"], stats["total_amount"])
        restored_member_stats = node.getbitplusmemberassetstats(HASH_C, {"asset_id": asset_id})
        assert_equal(restored_member_stats["reconciliation_summary"]["chain_snapshot_hash"], filtered_member_stats["reconciliation_summary"]["chain_snapshot_hash"])
        assert_equal(restored_member_stats["utxo_count"], filtered_member_stats["utxo_count"])
        assert_equal(restored_member_stats["total_amount"], filtered_member_stats["total_amount"])

        self.log.info("Test contract leaf construction RPCs")
        assert_contract_leaf(node.createbitpluscovleaf(OUTPUT_SCRIPT, "1.00000000", 0))

        vault = node.createbitplusvault(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(vault["recovery_leaf"])
        assert_contract_leaf(vault["delayed_spend_leaf"])

        htlc = node.createbitplushtlc(AUTH_SCRIPT, HASH_A, OUTPUT_SCRIPT, "1.00000000", 0, 900000, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(htlc["claim_leaf"])
        assert_contract_leaf(htlc["refund_leaf"])

        collateral = node.createbitpluscollateral(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(collateral["release_leaf"])
        assert_contract_leaf(collateral["return_leaf"])

        refunds = node.createbitplusrefundpaths(AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(refunds["absolute_refund_leaf"])
        assert_contract_leaf(refunds["relative_refund_leaf"])

        assert_contract_leaf(node.createbitplusvaultrecoveryleaf(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusvaultdelayedleaf(AUTH_SCRIPT, 144, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplushtlcclaimleaf(AUTH_SCRIPT, HASH_A, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplushtlcrefundleaf(AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusdvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, OUTPUT_SCRIPT, "1.00000000", 1))
        assert_contract_leaf(node.createbitplusdvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, OUTPUT_SCRIPT, "1.00000000", 1, CUSTOM_ASSET_LOCK_A))
        assert_contract_leaf(node.createbitpluspvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, asset_id, 50, metadata["commitment_hash"], HASH_E, 1))
        assert_contract_leaf(node.createbitpluspvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, asset_id, 50, metadata["commitment_hash"], HASH_E, 1, CUSTOM_ASSET_LOCK_A, CUSTOM_ASSET_LOCK_B))
        assert_contract_leaf(node.createbitpluscollateralreleaseleaf(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitpluscollateralreturnleaf(AUTH_SCRIPT, 144, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusrefundabsoluteleaf(AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusrefundrelativeleaf(AUTH_SCRIPT, 144, OUTPUT_SCRIPT, "1.00000000", 0))

        self.log.info("Test RPC parameter rejection")
        assert_raises_rpc_error(-8, "members must not be empty", node.createbitplusassetwhitelistroot, [])
        assert_raises_rpc_error(-8, "proof_index out of range", node.createbitplusassetwhitelistroot, [HASH_A], 1)
        assert_raises_rpc_error(-8, "asset-metadata-null", node.createbitplusassetid, NULL_HASH, HASH_D, 0)
        assert_raises_rpc_error(-8, "asset-metadata-issuer-null", node.createbitplusassetmetadata, NULL_HASH, HASH_B, whitelist["commitment_hash"])
        assert_raises_rpc_error(-8, "asset-whitelist-members-null", node.createbitplusassetwhitelist, HASH_A, HASH_B, NULL_HASH)
        assert_raises_rpc_error(-8, "asset-whitelist-members-null", node.createbitplusassetissuance, HASH_D, 0, 500, HASH_A, HASH_B, HASH_A, HASH_B, NULL_HASH, HASH_E)
        assert_raises_rpc_error(-8, "asset-id-null", node.createbitplusasset, "transfer", NULL_HASH, 100, metadata["commitment_hash"], HASH_E)
        assert_raises_rpc_error(-8, "asset-whitelist-proof-root-mismatch", node.createbitplusassettransfer, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], HASH_A)
        assert_raises_rpc_error(-8, "asset-whitelist-proof-root-mismatch", node.createbitplusdvp, AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], HASH_A, OUTPUT_SCRIPT, "1.00000000", 1)
        assert_raises_rpc_error(-8, "second-asset-whitelist-proof-root-mismatch", node.createbitpluspvp, AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_C, 0, 2, root["merkle_path"], root["members_root"], asset_id, 50, metadata["commitment_hash"], HASH_C, 1, 2, root["merkle_path"], HASH_A)
        assert_raises_rpc_error(-8, "asset-id-null", node.createbitplusassetburn, NULL_HASH, 25, metadata["commitment_hash"], HASH_C)
        assert_raises_rpc_error(-8, "asset-locking-script-unspendable", node.createbitplusasset, "transfer", asset_id, 100, metadata["commitment_hash"], HASH_E, "6a")
        assert_raises_rpc_error(-8, "asset-whitelist-proof-member-null", node.createbitplusassetwhitelistproof, 0, NULL_HASH, 0, [])
        assert_raises_rpc_error(-8, "asset-id-null", node.createbitplusdvpleaf, AUTH_SCRIPT, NULL_HASH, 100, metadata["commitment_hash"], HASH_E, 0, OUTPUT_SCRIPT, "1.00000000", 1)
        assert_raises_rpc_error(-8, "amount must be greater than zero", node.createbitpluscovleaf, OUTPUT_SCRIPT, "0.00000000", 0)
        assert_raises_rpc_error(-8, "output_index out of range", node.createbitpluscovleaf, OUTPUT_SCRIPT, "1.00000000", -1)
        assert_raises_rpc_error(-8, "outputs must not be empty", node.createbitplusscripttransaction, [{"txid": HASH_D, "vout": 0}], [])
        assert_raises_rpc_error(-8, "outputs must not be empty", node.createbitpluspsbt, [{"txid": HASH_D, "vout": 0}], [])
        assert_raises_rpc_error(-8, "output index mismatch", node.createbitplusscripttransaction, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": OUTPUT_SCRIPT, "amount": "1.00000000", "index": 1}])
        assert_raises_rpc_error(-8, "output index mismatch", node.createbitpluspsbt, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": OUTPUT_SCRIPT, "amount": "1.00000000", "index": 1}])
        assert_raises_rpc_error(-8, "scriptPubKey must not be empty", node.createbitplusscripttransaction, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": "", "amount": "1.00000000", "index": 0}])
        assert_raises_rpc_error(-8, "scriptPubKey must not be empty", node.createbitpluspsbt, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": "", "amount": "1.00000000", "index": 0}])
        assert_raises_rpc_error(-3, "Amount out of range", node.decodebitplusscript, OUTPUT_SCRIPT, "-0.00000001")
        assert_raises_rpc_error(-22, "TX decode failed", node.analyzebitplustransaction, "00")
        assert_raises_rpc_error(-22, "TX decode failed", node.analyzebitpluspsbt, ";definitely not base64;")
        assert_raises_rpc_error(-22, "TX decode failed", node.preparebitpluspsbt, ";definitely not base64;")
        assert_raises_rpc_error(-8, "format must be one of", node.checkbitplussettlement, script_psbt["psbt"], "bogus")
        assert_raises_rpc_error(-8, "min_input_confirmations must be non-negative", node.checkbitplussettlement, lookup_tx.serialize().hex(), "raw", True, 0, -1)
        assert_raises_rpc_error(-8, "asset_id must not be null", node.scanbitplusassetutxos, NULL_HASH)
        assert_raises_rpc_error(-8, "max_results must be greater than zero", node.scanbitplusassetutxos, asset_id, 0)
        assert_raises_rpc_error(-8, "max_results must not exceed 10000", node.scanbitplusassetutxos, asset_id, 10001)
        assert_raises_rpc_error(-3, "Wrong type passed", node.scanbitplusassetutxos, asset_id, 10, [])
        assert_raises_rpc_error(-3, "Wrong type passed", node.scanbitplusassetutxos, asset_id, 10, {}, [])
        assert_raises_rpc_error(-8, "unknown filters field: memberhash", node.scanbitplusassetutxos, asset_id, 10, {"memberhash": HASH_C})
        assert_raises_rpc_error(-8, "asset type must be one of", node.scanbitplusassetutxos, asset_id, 10, {"type": "bad"})
        assert_raises_rpc_error(-8, "metadata_hash must not be null", node.scanbitplusassetutxos, asset_id, 10, {"metadata_hash": NULL_HASH})
        assert_raises_rpc_error(-8, "member_hash must not be null", node.scanbitplusassetutxos, asset_id, 10, {"member_hash": NULL_HASH})
        assert_raises_rpc_error(-8, "min_confirmations must be non-negative", node.scanbitplusassetutxos, asset_id, 10, {"min_confirmations": -1})
        assert_raises_rpc_error(-8, "asset_id must not be null", node.getbitplusassetstats, NULL_HASH)
        assert_raises_rpc_error(-3, "Wrong type passed", node.getbitplusassetstats, asset_id, [])
        assert_raises_rpc_error(-8, "unknown filters field: asset_id", node.getbitplusassetstats, asset_id, {"asset_id": asset_id})
        assert_raises_rpc_error(-8, "asset type must be one of", node.getbitplusassetstats, asset_id, {"type": "bad"})
        assert_raises_rpc_error(-8, "metadata_hash must not be null", node.getbitplusassetstats, asset_id, {"metadata_hash": NULL_HASH})
        assert_raises_rpc_error(-8, "member_hash must not be null", node.getbitplusassetstats, asset_id, {"member_hash": NULL_HASH})
        assert_raises_rpc_error(-8, "min_confirmations must be non-negative", node.getbitplusassetstats, asset_id, {"min_confirmations": -1})
        assert_raises_rpc_error(-8, "member_hash must not be null", node.getbitplusmemberassetstats, NULL_HASH)
        assert_raises_rpc_error(-3, "Wrong type passed", node.getbitplusmemberassetstats, HASH_C, [])
        assert_raises_rpc_error(-8, "unknown filters field: memberhash", node.getbitplusmemberassetstats, HASH_C, {"memberhash": HASH_C})
        assert_raises_rpc_error(-8, "asset_id must not be null", node.getbitplusmemberassetstats, HASH_C, {"asset_id": NULL_HASH})
        assert_raises_rpc_error(-8, "asset type must be one of", node.getbitplusmemberassetstats, HASH_C, {"type": "bad"})
        assert_raises_rpc_error(-8, "metadata_hash must not be null", node.getbitplusmemberassetstats, HASH_C, {"metadata_hash": NULL_HASH})
        assert_raises_rpc_error(-8, "min_confirmations must be non-negative", node.getbitplusmemberassetstats, HASH_C, {"min_confirmations": -1})
        assert_raises_rpc_error(-8, "input_index out of range", node.analyzebitplustransaction, analysis_tx, [{"input_index": 1, "scriptPubKey": transfer["transfer"]["scriptPubKey"], "amount": "0.00000000"}])
        assert_raises_rpc_error(-8, "duplicate input_index", node.analyzebitplustransaction, analysis_tx, [{"input_index": 0, "scriptPubKey": transfer["transfer"]["scriptPubKey"], "amount": "0.00000000"}, {"input_index": 0, "scriptPubKey": transfer["transfer"]["scriptPubKey"], "amount": "0.00000000"}])
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusvaultdelayedleaf, AUTH_SCRIPT, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "secret_hash must not be null", node.createbitplushtlcclaimleaf, AUTH_SCRIPT, NULL_HASH, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "absolute_expiry must be non-negative", node.createbitplushtlcrefundleaf, AUTH_SCRIPT, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusvault, AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitpluscollateral, AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusrefundpaths, AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)


if __name__ == "__main__":
    BitplusContractsRPCTest(__file__).main()
