#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Bitplus institutional contract construction RPCs."""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
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

        self.log.info("Test contract leaf construction RPCs")
        assert_contract_leaf(node.createbitpluscovleaf(OUTPUT_SCRIPT, "1.00000000", 0))

        vault = node.createbitplusvault(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(vault["recovery_leaf"])
        assert_contract_leaf(vault["delayed_spend_leaf"])

        collateral = node.createbitpluscollateral(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(collateral["release_leaf"])
        assert_contract_leaf(collateral["return_leaf"])

        refunds = node.createbitplusrefundpaths(AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0, 144, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_contract_leaf(refunds["absolute_refund_leaf"])
        assert_contract_leaf(refunds["relative_refund_leaf"])

        assert_contract_leaf(node.createbitplusvaultrecoveryleaf(AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusvaultdelayedleaf(AUTH_SCRIPT, 144, OUTPUT_SCRIPT, "1.00000000", 0))
        assert_contract_leaf(node.createbitplusdvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, OUTPUT_SCRIPT, "1.00000000", 1))
        assert_contract_leaf(node.createbitpluspvpleaf(AUTH_SCRIPT, asset_id, 100, metadata["commitment_hash"], HASH_E, 0, asset_id, 50, metadata["commitment_hash"], HASH_E, 1))
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
        assert_raises_rpc_error(-8, "output index mismatch", node.createbitplusscripttransaction, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": OUTPUT_SCRIPT, "amount": "1.00000000", "index": 1}])
        assert_raises_rpc_error(-8, "scriptPubKey must not be empty", node.createbitplusscripttransaction, [{"txid": HASH_D, "vout": 0}], [{"scriptPubKey": "", "amount": "1.00000000", "index": 0}])
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusvaultdelayedleaf, AUTH_SCRIPT, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusvault, AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitpluscollateral, AUTH_SCRIPT, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)
        assert_raises_rpc_error(-8, "relative_delay must be non-negative", node.createbitplusrefundpaths, AUTH_SCRIPT, 900000, OUTPUT_SCRIPT, "1.00000000", 0, -1, OUTPUT_SCRIPT, "1.00000000", 0)


if __name__ == "__main__":
    BitplusContractsRPCTest(__file__).main()
