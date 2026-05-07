#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test active Bitplus native-asset validation rules."""

from decimal import Decimal
import hashlib

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import CScript
from test_framework.test_framework import BitplusTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    softfork_active,
)
from test_framework.wallet import MiniWallet, MiniWalletMode


HASH_A = "11" * 32
HASH_B = "22" * 32
SECRET = b"bitplus settlement member"
MEMBER_HASH = hashlib.sha256(SECRET).digest()[::-1].hex()
ZERO_BTP = 0
TRANSFER_VOUT = 4


def txid_from_prevout(prevout):
    return f"{prevout.hash:064x}"


def asset_unlock_script():
    return bytes(CScript([SECRET]))


class BitplusAssetValidationTest(BitplusTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1", "-vbparams=institutional_contracts:0:999999999999:0"]]

    def assert_mempool_result(self, tx, *, allowed, reject_reason=None):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        if result["allowed"] != allowed:
            raise AssertionError(f"unexpected mempool result: {result}")
        assert_equal(result["allowed"], allowed)
        if reject_reason is not None:
            assert_equal(result["reject-reason"], reject_reason)

    def assert_generateblock_rejects(self, tx, reject_reason):
        assert_raises_rpc_error(
            -25,
            f"TestBlockValidity failed: {reject_reason}",
            self.generateblock,
            self.nodes[0],
            output="raw(51)",
            transactions=[tx.serialize().hex()],
        )

    def build_issuance_tx(self, wallet, *, include_metadata=True):
        node = self.nodes[0]
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        anchor_txid = txid_from_prevout(tx.vin[0].prevout)
        anchor_vout = tx.vin[0].prevout.n

        root = node.createbitplusassetwhitelistroot([MEMBER_HASH], 0)
        issuance = node.createbitplusassetissuance(
            anchor_txid,
            anchor_vout,
            500,
            HASH_A,
            HASH_B,
            HASH_A,
            HASH_B,
            root["members_root"],
            MEMBER_HASH,
        )
        transfer = node.createbitplusassettransfer(
            issuance["asset_id"],
            500,
            issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            TRANSFER_VOUT,
            0,
            root["merkle_path"],
            root["members_root"],
        )

        if include_metadata:
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["whitelist"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["issuance"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(transfer["transfer"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(transfer["proof"]["scriptPubKey"])))
        return tx, issuance, root

    def build_asset_spend_tx(
        self,
        wallet,
        issuance_tx,
        issuance,
        root,
        *,
        transfer_amount=300,
        burn_amount=200,
        include_proof=True,
        duplicate_proof=False,
        invalid_proof_member=False,
    ):
        node = self.nodes[0]
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        tx.vin.insert(0, CTxIn(COutPoint(int(issuance_tx.txid_hex, 16), TRANSFER_VOUT), scriptSig=asset_unlock_script()))

        transfer_index = len(tx.vout) + 2
        transfer = node.createbitplusassettransfer(
            issuance["asset_id"],
            transfer_amount,
            issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            transfer_index,
            0,
            root["merkle_path"],
            root["members_root"],
        )
        burn = None
        if burn_amount:
            burn = node.createbitplusassetburn(
                issuance["asset_id"],
                burn_amount,
                issuance["metadata"]["commitment_hash"],
                MEMBER_HASH,
            )

        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["whitelist"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(transfer["transfer"]["scriptPubKey"])))
        if include_proof:
            proof = transfer["proof"]
            if invalid_proof_member:
                proof = node.createbitplusassetwhitelistproof(transfer_index, HASH_A, 0, root["merkle_path"])
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(proof["scriptPubKey"])))
            if duplicate_proof:
                tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(proof["scriptPubKey"])))
        if burn is not None:
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(burn["scriptPubKey"])))
        return tx

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)

        if not softfork_active(node, "institutional_contracts"):
            self.log.info("Mine to institutional_contracts activation")
            self.generate(wallet, 432)
        assert softfork_active(node, "institutional_contracts")

        self.log.info("Reject issuance missing linked metadata")
        missing_metadata_tx, _, _ = self.build_issuance_tx(wallet, include_metadata=False)
        self.assert_mempool_result(missing_metadata_tx, allowed=False, reject_reason="asset-issuance-metadata-missing")

        self.log.info("Accept balanced issuance with metadata, whitelist, transfer, and proof")
        issuance_tx, issuance, root = self.build_issuance_tx(wallet)
        self.assert_mempool_result(issuance_tx, allowed=True)
        issuance_txid = node.sendrawtransaction(issuance_tx.serialize().hex(), maxfeerate=0)
        self.generateblock(node, output="raw(51)", transactions=[issuance_txid])

        self.log.info("Accept balanced asset spend with burn and whitelist proof")
        valid_spend = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root)
        self.assert_mempool_result(valid_spend, allowed=True)

        self.log.info("Reject transfer without whitelist proof")
        missing_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, include_proof=False)
        self.assert_mempool_result(missing_proof, allowed=False, reject_reason="asset-whitelist-proof-missing")
        self.assert_generateblock_rejects(missing_proof, "asset-whitelist-proof-missing")

        self.log.info("Reject duplicate whitelist proof")
        duplicate_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, duplicate_proof=True)
        self.assert_mempool_result(duplicate_proof, allowed=False, reject_reason="asset-whitelist-proof-duplicate")
        self.assert_generateblock_rejects(duplicate_proof, "asset-whitelist-proof-duplicate")

        self.log.info("Reject whitelist proof for the wrong member")
        invalid_member_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, invalid_proof_member=True)
        self.assert_mempool_result(invalid_member_proof, allowed=False, reject_reason="asset-whitelist-proof-member-mismatch")
        self.assert_generateblock_rejects(invalid_member_proof, "asset-whitelist-proof-member-mismatch")

        self.log.info("Reject unbalanced asset spend")
        unbalanced = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, transfer_amount=499, burn_amount=0)
        self.assert_mempool_result(unbalanced, allowed=False, reject_reason="bad-txns-asset-conservation")
        self.assert_generateblock_rejects(unbalanced, "bad-txns-asset-conservation")

        self.log.info("Mine balanced asset spend")
        valid_spend_txid = node.sendrawtransaction(valid_spend.serialize().hex(), maxfeerate=0)
        self.generateblock(node, output="raw(51)", transactions=[valid_spend_txid])


if __name__ == "__main__":
    BitplusAssetValidationTest(__file__).main()
