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
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_EQUAL,
    OP_RETURN,
    OP_SHA256,
    OP_TRUE,
)
from test_framework.test_framework import BitplusTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    softfork_active,
)
from test_framework.wallet import MiniWallet, MiniWalletMode


HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32
SECRET = b"bitplus settlement member"
MEMBER_HASH = hashlib.sha256(SECRET).digest()[::-1].hex()
ZERO_BTP = 0
TRANSFER_VOUT = 4


def txid_from_prevout(prevout):
    return f"{prevout.hash:064x}"


def asset_unlock_script():
    return bytes(CScript([SECRET]))


def assert_hex_hash(value):
    assert_equal(len(value), 64)
    int(value, 16)


def asset_payload(*, asset_type=2, asset_id=HASH_A, amount=1, metadata_hash=HASH_B, member_hash=MEMBER_HASH):
    return (
        b"BTPASSET"
        + bytes([1])
        + bytes([asset_type])
        + bytes.fromhex(asset_id)
        + amount.to_bytes(8, "little")
        + bytes.fromhex(metadata_hash)
        + bytes.fromhex(member_hash)
    )


def asset_locking_script(member_hash=MEMBER_HASH):
    return CScript([OP_SHA256, bytes.fromhex(member_hash), OP_EQUAL])


class BitplusAssetValidationTest(BitplusTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1", "-bitplusassetindex=1", "-vbparams=institutional_contracts:0:999999999999:0"]]

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

    def assert_rejects(self, tx, reject_reason):
        self.assert_mempool_result(tx, allowed=False, reject_reason=reject_reason)
        self.assert_generateblock_rejects(tx, reject_reason)

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

    def build_anchor_mismatch_tx(self, wallet):
        node = self.nodes[0]
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        root = node.createbitplusassetwhitelistroot([MEMBER_HASH], 0)
        issuance = node.createbitplusassetissuance(
            HASH_C,
            0,
            500,
            HASH_A,
            HASH_B,
            HASH_A,
            HASH_B,
            root["members_root"],
            MEMBER_HASH,
        )
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["whitelist"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["issuance"]["scriptPubKey"])))
        return tx

    def build_malformed_asset_tx(self, wallet):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        tx.vout.append(CTxOut(ZERO_BTP, CScript([b"BTPASSET", OP_DROP, OP_TRUE])))
        return tx

    def build_invalid_asset_tx(self, wallet, *, payload=None, locking_script=None):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        if payload is None:
            payload = asset_payload()
        if locking_script is None:
            locking_script = asset_locking_script()
        tx.vout.append(CTxOut(ZERO_BTP, CScript(bytes(CScript([payload, OP_DROP])) + bytes(locking_script))))
        return tx

    def build_malformed_metadata_tx(self, wallet):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, b"BTPMETA"])))
        return tx

    def build_malformed_whitelist_tx(self, wallet):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, b"BTPWLST"])))
        return tx

    def build_malformed_whitelist_proof_tx(self, wallet):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, b"BTPWPROOF"])))
        return tx

    def build_invalid_metadata_tx(self, wallet, *, issuer_id=HASH_A, document_hash=HASH_B, rules_hash=HASH_C):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        payload = (
            b"BTPMETA"
            + bytes([1])
            + bytes.fromhex(issuer_id)
            + bytes.fromhex(document_hash)
            + bytes.fromhex(rules_hash)
        )
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, payload])))
        return tx

    def build_duplicate_issuance_tx(self, wallet):
        tx, issuance, _ = self.build_issuance_tx(wallet)
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["issuance"]["scriptPubKey"])))
        return tx

    def build_missing_whitelist_tx(self, wallet):
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
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["issuance"]["scriptPubKey"])))
        return tx

    def build_orphan_proof_tx(self, wallet):
        node = self.nodes[0]
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        root = node.createbitplusassetwhitelistroot([MEMBER_HASH], 0)
        whitelist = node.createbitplusassetwhitelist(HASH_A, HASH_B, root["members_root"])
        metadata = node.createbitplusassetmetadata(HASH_A, HASH_B, whitelist["commitment_hash"])
        proof = node.createbitplusassetwhitelistproof(0, MEMBER_HASH, 0, root["merkle_path"])
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(metadata["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(whitelist["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(proof["scriptPubKey"])))
        return tx

    def build_invalid_whitelist_tx(self, wallet, *, list_id=HASH_A, admin_key_hash=HASH_B, members_root=None):
        node = self.nodes[0]
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        if members_root is None:
            members_root = HASH_C
        payload = (
            b"BTPWLST"
            + bytes([1])
            + bytes.fromhex(list_id)
            + bytes.fromhex(admin_key_hash)
            + bytes.fromhex(members_root)
            + (0).to_bytes(4, "little")
        )
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, payload])))
        return tx

    def build_invalid_whitelist_proof_tx(self, wallet, *, asset_output_index=0, member_hash=MEMBER_HASH, proof_index=0, merkle_path=None):
        tx = wallet.create_self_transfer(fee=Decimal("0.00010000"))["tx"]
        if merkle_path is None:
            merkle_path = []
        payload = (
            b"BTPWPROOF"
            + bytes([1])
            + asset_output_index.to_bytes(4, "little")
            + bytes.fromhex(member_hash)
            + proof_index.to_bytes(4, "little")
            + bytes([len(merkle_path)])
            + b"".join(bytes.fromhex(sibling) for sibling in merkle_path)
        )
        tx.vout.append(CTxOut(ZERO_BTP, CScript([OP_RETURN, payload])))
        return tx

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
        invalid_proof_root=False,
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
            if invalid_proof_root:
                proof = node.createbitplusassetwhitelistproof(transfer_index, MEMBER_HASH, 0, [HASH_C])
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(proof["scriptPubKey"])))
            if duplicate_proof:
                tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(proof["scriptPubKey"])))
        if burn is not None:
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(burn["scriptPubKey"])))
        return tx

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)
        self.wait_until(lambda: node.getindexinfo()["bitplusassetindex"]["synced"] is True)

        if not softfork_active(node, "institutional_contracts"):
            self.log.info("Mine to institutional_contracts activation")
            self.generate(wallet, 432)
        self.wait_until(lambda: node.getindexinfo()["bitplusassetindex"]["synced"] is True)
        assert softfork_active(node, "institutional_contracts")

        self.log.info("Reject issuance missing linked metadata")
        missing_metadata_tx, _, _ = self.build_issuance_tx(wallet, include_metadata=False)
        self.assert_rejects(missing_metadata_tx, "asset-issuance-metadata-missing")

        self.log.info("Reject asset carrier with nonzero BTP amount")
        nonzero_carrier, _, _ = self.build_issuance_tx(wallet)
        nonzero_carrier.vout[TRANSFER_VOUT].nValue = 1
        self.assert_rejects(nonzero_carrier, "asset-carrier-nonzero")

        self.log.info("Reject invalid asset commitment fields and locking scripts")
        invalid_asset_cases = [
            (self.build_invalid_asset_tx(wallet, payload=asset_payload(asset_id="00" * 32)), "asset-id-null"),
            (self.build_invalid_asset_tx(wallet, payload=asset_payload(metadata_hash="00" * 32)), "asset-metadata-null"),
            (self.build_invalid_asset_tx(wallet, payload=asset_payload(member_hash="00" * 32)), "asset-member-null"),
            (self.build_invalid_asset_tx(wallet, payload=asset_payload(amount=0)), "asset-amount-zero"),
            (self.build_invalid_asset_tx(wallet, locking_script=CScript([OP_RETURN, b"bad asset lock"])), "asset-locking-script-unspendable"),
            (self.build_invalid_asset_tx(wallet, locking_script=CScript([asset_payload(asset_id=HASH_C), OP_DROP, OP_TRUE])), "asset-locking-script-nested"),
        ]
        for invalid_asset_tx, reject_reason in invalid_asset_cases:
            analysis = node.analyzebitplustransaction(invalid_asset_tx.serialize().hex())
            assert_equal(analysis["valid"], False)
            if reject_reason not in analysis["issues"]:
                raise AssertionError(f"{reject_reason} not in {analysis['issues']}")
            self.assert_rejects(invalid_asset_tx, reject_reason)

        self.log.info("Reject malformed reserved Bitplus commitment prefixes")
        malformed_cases = [
            (self.build_malformed_asset_tx(wallet), "asset-commitment-malformed"),
            (self.build_malformed_metadata_tx(wallet), "asset-metadata-malformed"),
            (self.build_malformed_whitelist_tx(wallet), "asset-whitelist-malformed"),
            (self.build_malformed_whitelist_proof_tx(wallet), "asset-whitelist-proof-malformed"),
        ]
        for malformed_tx, reject_reason in malformed_cases:
            analysis = node.analyzebitplustransaction(malformed_tx.serialize().hex())
            assert_equal(analysis["valid"], False)
            assert reject_reason in analysis["issues"]
            self.assert_rejects(malformed_tx, reject_reason)

        self.log.info("Reject issuance with mismatched anchor")
        self.assert_rejects(self.build_anchor_mismatch_tx(wallet), "asset-issuance-anchor-mismatch")

        self.log.info("Reject duplicate issuance for one asset id")
        self.assert_rejects(self.build_duplicate_issuance_tx(wallet), "asset-issuance-duplicate")

        self.log.info("Reject metadata without linked whitelist")
        self.assert_rejects(self.build_missing_whitelist_tx(wallet), "asset-metadata-whitelist-missing")

        self.log.info("Reject invalid metadata commitment fields")
        invalid_metadata_cases = [
            (self.build_invalid_metadata_tx(wallet, issuer_id="00" * 32), "asset-metadata-issuer-null"),
            (self.build_invalid_metadata_tx(wallet, document_hash="00" * 32), "asset-metadata-document-null"),
            (self.build_invalid_metadata_tx(wallet, rules_hash="00" * 32), "asset-metadata-rules-null"),
        ]
        for invalid_metadata_tx, reject_reason in invalid_metadata_cases:
            analysis = node.analyzebitplustransaction(invalid_metadata_tx.serialize().hex())
            assert_equal(analysis["valid"], False)
            assert reject_reason in analysis["issues"]
            self.assert_rejects(invalid_metadata_tx, reject_reason)

        self.log.info("Reject orphan whitelist proof")
        self.assert_rejects(self.build_orphan_proof_tx(wallet), "asset-whitelist-proof-orphan")

        self.log.info("Reject invalid whitelist proof commitment fields")
        invalid_proof_cases = [
            (self.build_invalid_whitelist_proof_tx(wallet, member_hash="00" * 32), "asset-whitelist-proof-member-null"),
            (self.build_invalid_whitelist_proof_tx(wallet, proof_index=2, merkle_path=[HASH_C]), "asset-whitelist-proof-index-range"),
        ]
        for invalid_proof_tx, reject_reason in invalid_proof_cases:
            analysis = node.analyzebitplustransaction(invalid_proof_tx.serialize().hex())
            assert_equal(analysis["valid"], False)
            assert reject_reason in analysis["issues"]
            self.assert_rejects(invalid_proof_tx, reject_reason)

        self.log.info("Reject invalid whitelist commitment fields")
        invalid_whitelist_cases = [
            (self.build_invalid_whitelist_tx(wallet, list_id="00" * 32), "asset-whitelist-list-null"),
            (self.build_invalid_whitelist_tx(wallet, admin_key_hash="00" * 32), "asset-whitelist-admin-null"),
            (self.build_invalid_whitelist_tx(wallet, members_root="00" * 32), "asset-whitelist-members-null"),
        ]
        for invalid_whitelist_tx, reject_reason in invalid_whitelist_cases:
            analysis = node.analyzebitplustransaction(invalid_whitelist_tx.serialize().hex())
            assert_equal(analysis["valid"], False)
            assert reject_reason in analysis["issues"]
            self.assert_rejects(invalid_whitelist_tx, reject_reason)

        self.log.info("Accept balanced issuance with metadata, whitelist, transfer, and proof")
        issuance_tx, issuance, root = self.build_issuance_tx(wallet)
        self.assert_mempool_result(issuance_tx, allowed=True)
        issuance_txid = node.sendrawtransaction(issuance_tx.serialize().hex(), maxfeerate=0)
        issuance_block = self.generateblock(node, output="raw(51)", transactions=[issuance_txid])["hash"]

        self.log.info("Verify asset reconciliation across issuance-block invalidation")
        confirmed_scan = node.scanbitplusassetutxos(issuance["asset_id"], 10)
        assert_equal(len([utxo for utxo in confirmed_scan["utxos"] if utxo["txid"] == issuance_txid and utxo["vout"] == TRANSFER_VOUT]), 1)
        node.invalidateblock(issuance_block)
        assert issuance_txid in node.getrawmempool()
        assert_equal(node.scanbitplusassetutxos(issuance["asset_id"], 10)["matches"], 0)
        assert_equal(node.getbitplusassetstats(issuance["asset_id"])["utxo_count"], 0)
        assert_equal(node.getbitplusmemberassetstats(MEMBER_HASH, {"asset_id": issuance["asset_id"]})["utxo_count"], 0)
        node.reconsiderblock(issuance_block)
        assert issuance_txid not in node.getrawmempool()
        restored_scan = node.scanbitplusassetutxos(issuance["asset_id"], 10)
        assert_equal(len([utxo for utxo in restored_scan["utxos"] if utxo["txid"] == issuance_txid and utxo["vout"] == TRANSFER_VOUT]), 1)

        self.log.info("Accept balanced asset spend with burn and whitelist proof")
        valid_spend = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root)
        self.assert_mempool_result(valid_spend, allowed=True)

        self.log.info("Reject transfer without whitelist proof")
        missing_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, include_proof=False)
        self.assert_rejects(missing_proof, "asset-whitelist-proof-missing")

        self.log.info("Reject duplicate whitelist proof")
        duplicate_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, duplicate_proof=True)
        self.assert_rejects(duplicate_proof, "asset-whitelist-proof-duplicate")

        self.log.info("Reject whitelist proof for the wrong member")
        invalid_member_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, invalid_proof_member=True)
        self.assert_rejects(invalid_member_proof, "asset-whitelist-proof-member-mismatch")

        self.log.info("Reject whitelist proof with invalid Merkle root")
        invalid_root_proof = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, invalid_proof_root=True)
        self.assert_rejects(invalid_root_proof, "asset-whitelist-proof-invalid")

        self.log.info("Reject unbalanced asset spend")
        unbalanced = self.build_asset_spend_tx(wallet, issuance_tx, issuance, root, transfer_amount=499, burn_amount=0)
        self.assert_rejects(unbalanced, "bad-txns-asset-conservation")

        self.log.info("Mine balanced asset spend")
        valid_spend_txid = node.sendrawtransaction(valid_spend.serialize().hex(), maxfeerate=0)
        spend_block = self.generateblock(node, output="raw(51)", transactions=[valid_spend_txid])["hash"]

        self.log.info("Verify asset reconciliation across spend-block invalidation")
        spent_scan = node.scanbitplusassetutxos(issuance["asset_id"], 10)
        assert_equal(len([utxo for utxo in spent_scan["utxos"] if utxo["txid"] == issuance_txid and utxo["vout"] == TRANSFER_VOUT]), 0)
        assert_equal(len([utxo for utxo in spent_scan["utxos"] if utxo["txid"] == valid_spend_txid and utxo["commitment"]["type"] == "transfer"]), 1)
        spent_stats = node.getbitplusassetstats(issuance["asset_id"])
        assert_hex_hash(spent_stats["reconciliation_hash"])
        assert_equal(spent_stats["utxo_count"], 3)
        assert_equal(spent_stats["total_amount"], 1000)
        assert_equal(spent_stats["issued_amount"], 500)
        assert_equal(spent_stats["held_amount"], 300)
        assert_equal(spent_stats["burned_amount"], 200)
        assert_equal(spent_stats["outstanding_amount"], 300)
        assert_equal(spent_stats["supply_underflow"], False)
        assert_equal(spent_stats["holder_supply_balanced"], True)
        assert_equal(spent_stats["holder_supply_delta"], 0)
        assert_equal(spent_stats["holder_count"], 1)
        assert_equal(spent_stats["by_type"]["issuance"]["amount"], 500)
        assert_equal(spent_stats["by_type"]["transfer"]["amount"], 300)
        assert_equal(spent_stats["by_type"]["burn"]["amount"], 200)
        assert_equal(spent_stats["by_holder_member_hash"][MEMBER_HASH]["amount"], 300)

        node.invalidateblock(spend_block)
        assert valid_spend_txid in node.getrawmempool()
        rollback_scan = node.scanbitplusassetutxos(issuance["asset_id"], 10)
        assert_equal(len([utxo for utxo in rollback_scan["utxos"] if utxo["txid"] == issuance_txid and utxo["vout"] == TRANSFER_VOUT]), 1)
        assert_equal(len([utxo for utxo in rollback_scan["utxos"] if utxo["txid"] == valid_spend_txid]), 0)
        rollback_stats = node.getbitplusassetstats(issuance["asset_id"])
        assert_hex_hash(rollback_stats["reconciliation_hash"])
        assert rollback_stats["reconciliation_hash"] != spent_stats["reconciliation_hash"]
        assert_equal(rollback_stats["utxo_count"], 2)
        assert_equal(rollback_stats["total_amount"], 1000)
        assert_equal(rollback_stats["issued_amount"], 500)
        assert_equal(rollback_stats["held_amount"], 500)
        assert_equal(rollback_stats["burned_amount"], 0)
        assert_equal(rollback_stats["outstanding_amount"], 500)
        assert_equal(rollback_stats["supply_underflow"], False)
        assert_equal(rollback_stats["holder_supply_balanced"], True)
        assert_equal(rollback_stats["holder_supply_delta"], 0)
        assert_equal(rollback_stats["holder_count"], 1)
        assert_equal(rollback_stats["by_type"]["issuance"]["amount"], 500)
        assert_equal(rollback_stats["by_type"]["transfer"]["amount"], 500)
        assert_equal(rollback_stats["by_holder_member_hash"][MEMBER_HASH]["amount"], 500)

        issuance_only_stats = node.getbitplusassetstats(issuance["asset_id"], {"type": "issuance"})
        assert_equal(issuance_only_stats["utxo_count"], 1)
        assert_equal(issuance_only_stats["issued_amount"], 500)
        assert_equal(issuance_only_stats["held_amount"], 0)
        assert_equal(issuance_only_stats["outstanding_amount"], 500)
        assert_equal(issuance_only_stats["holder_supply_balanced"], False)
        assert_equal(issuance_only_stats["holder_supply_delta"], -500)
        assert_equal(issuance_only_stats["holder_count"], 0)
        assert_equal(issuance_only_stats["by_holder_member_hash"], {})

        node.reconsiderblock(spend_block)
        assert valid_spend_txid not in node.getrawmempool()
        restored_spend_scan = node.scanbitplusassetutxos(issuance["asset_id"], 10)
        assert_equal(len([utxo for utxo in restored_spend_scan["utxos"] if utxo["txid"] == issuance_txid and utxo["vout"] == TRANSFER_VOUT]), 0)
        assert_equal(len([utxo for utxo in restored_spend_scan["utxos"] if utxo["txid"] == valid_spend_txid and utxo["commitment"]["type"] == "transfer"]), 1)
        burn_only_stats = node.getbitplusassetstats(issuance["asset_id"], {"type": "burn"})
        assert_equal(burn_only_stats["utxo_count"], 1)
        assert_equal(burn_only_stats["burned_amount"], 200)
        assert_equal(burn_only_stats["held_amount"], 0)
        assert_equal(burn_only_stats["outstanding_amount"], 0)
        assert_equal(burn_only_stats["supply_underflow"], True)
        assert_equal(burn_only_stats["holder_supply_balanced"], False)
        assert_equal(burn_only_stats["holder_supply_delta"], 0)
        assert_equal(burn_only_stats["holder_count"], 0)
        assert_equal(burn_only_stats["by_holder_member_hash"], {})


if __name__ == "__main__":
    BitplusAssetValidationTest(__file__).main()
