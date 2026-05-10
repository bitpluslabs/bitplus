#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test active Bitplus covenant execution."""

from decimal import Decimal
import hashlib

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_TRUE,
    LEAF_VERSION_TAPSCRIPT,
    hash256,
    taproot_construct,
)
from test_framework.test_framework import BitplusTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    softfork_active,
)
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.key import compute_xonly_pubkey


FUNDING_AMOUNT = 1_000_000
TARGET_AMOUNT = 900_000
VAULT_RECOVERY_AMOUNT = 800_000
VAULT_DELAYED_AMOUNT = 700_000
VAULT_DELAY = 1
COLLATERAL_RELEASE_AMOUNT = 600_000
COLLATERAL_RETURN_AMOUNT = 500_000
COLLATERAL_DELAY = 1
HTLC_CLAIM_AMOUNT = 650_000
HTLC_REFUND_AMOUNT = 550_000
REFUND_ABSOLUTE_AMOUNT = 400_000
REFUND_RELATIVE_AMOUNT = 300_000
REFUND_RELATIVE_DELAY = 1
DVP_PAYMENT_AMOUNT = 800_000
PVP_CHANGE_AMOUNT = 990_000
HASH_A = "11" * 32
HASH_B = "22" * 32
SECRET = b"bitplus settlement member"
MEMBER_HASH = hashlib.sha256(SECRET).digest()[::-1].hex()
HTLC_SECRET = b"bitplus htlc preimage"
HTLC_BAD_SECRET = b"bitplus wrong htlc preimage"
HTLC_SECRET_HASH = hashlib.sha256(HTLC_SECRET).digest()[::-1].hex()
ZERO_BTP = 0
TRANSFER_VOUT = 4
CUSTOM_ASSET_LOCK_A = "52"
CUSTOM_ASSET_LOCK_B = "53"


def control_block(tap, leaf_name):
    leaf = tap.leaves[leaf_name]
    return bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def txid_from_prevout(prevout):
    return f"{prevout.hash:064x}"


def asset_unlock_script():
    return bytes(CScript([SECRET]))


class BitplusCovenantsTest(BitplusTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1", "-vbparams=institutional_contracts:0:999999999999:0"]]

    def build_covenant_spend(self, funding_txid, funding_vout, tap, *, amount=TARGET_AMOUNT):
        leaf = tap.leaves["cov"]
        return self.build_taproot_script_spend(
            funding_txid,
            funding_vout,
            tap,
            leaf_name="cov",
            amount=amount,
            sequence=0xfffffffe,
        )

    def build_taproot_script_spend(self, funding_txid, funding_vout, tap, *, leaf_name, amount, sequence, witness_items=None):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(funding_txid, 16), funding_vout), nSequence=sequence)]
        tx.vout = [
            CTxOut(amount, CScript([OP_TRUE])),
            CTxOut(0, CScript([OP_RETURN, b"bitplus fixed-template execution padding"])),
        ]
        self.attach_taproot_script_witness(tx, 0, tap, leaf_name, witness_items=witness_items)
        return tx

    def attach_taproot_script_witness(self, tx, input_index, tap, leaf_name, witness_items=None):
        leaf = tap.leaves[leaf_name]
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[input_index].scriptWitness.stack = [
            *(witness_items or []),
            bytes(leaf.script),
            control_block(tap, leaf_name),
        ]

    def assert_script_rejects(self, tx, mempool_reason, block_reason):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], mempool_reason)
        assert_raises_rpc_error(
            -25,
            f"TestBlockValidity failed: {block_reason}",
            self.generateblock,
            self.nodes[0],
            output="raw(51)",
            transactions=[tx.serialize().hex()],
        )

    def assert_consensus_rejects(self, tx, reason):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], reason)
        assert_raises_rpc_error(
            -25,
            f"TestBlockValidity failed: {reason}",
            self.generateblock,
            self.nodes[0],
            output="raw(51)",
            transactions=[tx.serialize().hex()],
        )

    def assert_covenant_rejects(self, tx):
        self.assert_script_rejects(
            tx,
            "mempool-script-verify-flag-failed (Output covenant requirement not satisfied)",
            "block-script-verify-flag-failed (Output covenant requirement not satisfied)",
        )

    def fund_taproot(self, wallet, tap):
        funding = wallet.send_to(from_node=self.nodes[0], scriptPubKey=tap.scriptPubKey, amount=FUNDING_AMOUNT, fee=1_000)
        self.generateblock(self.nodes[0], output="raw(51)", transactions=[funding["txid"]])
        return funding

    def issue_asset(self, wallet):
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

        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["whitelist"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(issuance["issuance"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(transfer["transfer"]["scriptPubKey"])))
        tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(transfer["proof"]["scriptPubKey"])))

        self.assert_accept_and_mine(tx)
        return tx, issuance, root

    def asset_input(self, issuance_tx):
        return CTxIn(COutPoint(int(issuance_tx.txid_hex, 16), TRANSFER_VOUT), scriptSig=asset_unlock_script())

    def build_dvp_spend(self, funding, tap, issuance_tx, issuance, root, *, payment_amount=DVP_PAYMENT_AMOUNT, include_proof=True, asset_locking_script=None):
        node = self.nodes[0]
        dvp_args = [
            "51",
            issuance["asset_id"],
            300,
            issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            root["merkle_path"],
            root["members_root"],
            CScript([OP_TRUE]).hex(),
            f"{DVP_PAYMENT_AMOUNT / 100_000_000:.8f}",
            1,
        ]
        if asset_locking_script is not None:
            dvp_args.append(asset_locking_script)
        dvp = node.createbitplusdvp(*dvp_args)
        burn = node.createbitplusassetburn(issuance["asset_id"], 200, issuance["metadata"]["commitment_hash"], MEMBER_HASH)

        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            self.asset_input(issuance_tx),
            CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]), nSequence=0xfffffffe),
        ]
        tx.vout = [
            CTxOut(ZERO_BTP, bytes.fromhex(dvp["transfer"]["scriptPubKey"])),
            CTxOut(payment_amount, CScript([OP_TRUE])),
            CTxOut(ZERO_BTP, bytes.fromhex(issuance["metadata"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(issuance["whitelist"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(burn["scriptPubKey"])),
        ]
        if include_proof:
            tx.vout.insert(4, CTxOut(ZERO_BTP, bytes.fromhex(dvp["proof"]["scriptPubKey"])))
        self.attach_taproot_script_witness(tx, 1, tap, "dvp")
        return tx

    def build_pvp_spend(self, funding, tap, first_issuance_tx, first_issuance, first_root, second_issuance_tx, second_issuance, second_root, *, wrong_second_index=False, include_second_proof=True, first_asset_locking_script=None, second_asset_locking_script=None):
        node = self.nodes[0]
        second_output_index = 2 if wrong_second_index else 1
        first_transfer_args = [
            first_issuance["asset_id"],
            500,
            first_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            first_root["merkle_path"],
            first_root["members_root"],
        ]
        if first_asset_locking_script is not None:
            first_transfer_args.append(first_asset_locking_script)
        first_transfer = node.createbitplusassettransfer(*first_transfer_args)

        second_transfer_args = [
            second_issuance["asset_id"],
            500,
            second_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            second_output_index,
            0,
            second_root["merkle_path"],
            second_root["members_root"],
        ]
        if second_asset_locking_script is not None:
            second_transfer_args.append(second_asset_locking_script)
        second_transfer = node.createbitplusassettransfer(*second_transfer_args)

        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            self.asset_input(first_issuance_tx),
            self.asset_input(second_issuance_tx),
            CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]), nSequence=0xfffffffe),
        ]
        tx.vout = [
            CTxOut(ZERO_BTP, bytes.fromhex(first_transfer["transfer"]["scriptPubKey"])),
        ]
        if wrong_second_index:
            tx.vout.extend([
                CTxOut(100_000, CScript([OP_TRUE])),
                CTxOut(ZERO_BTP, bytes.fromhex(second_transfer["transfer"]["scriptPubKey"])),
                CTxOut(PVP_CHANGE_AMOUNT - 100_000, CScript([OP_TRUE])),
            ])
        else:
            tx.vout.extend([
                CTxOut(ZERO_BTP, bytes.fromhex(second_transfer["transfer"]["scriptPubKey"])),
                CTxOut(PVP_CHANGE_AMOUNT, CScript([OP_TRUE])),
            ])
        tx.vout.extend([
            CTxOut(ZERO_BTP, bytes.fromhex(first_issuance["metadata"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(first_issuance["whitelist"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(first_transfer["proof"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(second_issuance["metadata"]["scriptPubKey"])),
            CTxOut(ZERO_BTP, bytes.fromhex(second_issuance["whitelist"]["scriptPubKey"])),
        ])
        if include_second_proof:
            tx.vout.append(CTxOut(ZERO_BTP, bytes.fromhex(second_transfer["proof"]["scriptPubKey"])))
        self.attach_taproot_script_witness(tx, 2, tap, "pvp")
        return tx

    def assert_accept_and_mine(self, tx):
        node = self.nodes[0]
        result = node.testmempoolaccept([tx.serialize().hex()])[0]
        if result["allowed"] is not True:
            raise AssertionError(f"unexpected accept result: {result}")
        assert_equal(result["allowed"], True)
        txid = node.sendrawtransaction(tx.serialize().hex(), maxfeerate=0)
        self.generateblock(node, output="raw(51)", transactions=[txid])

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)

        if not softfork_active(node, "institutional_contracts"):
            self.log.info("Mine to institutional_contracts activation")
            self.generate(wallet, 432)
        assert softfork_active(node, "institutional_contracts")

        self.log.info("Fund Taproot covenant script path")
        target_script = CScript([OP_TRUE])
        covenant_fragment = node.createbitpluscovleaf(target_script.hex(), "0.00900000", 0)["script"]
        covenant_leaf = CScript(bytes.fromhex(covenant_fragment) + bytes([OP_TRUE]))
        internal_key = compute_xonly_pubkey(hash256(b"bitplus covenant internal key"))[0]
        tap = taproot_construct(internal_key, [("cov", covenant_leaf, LEAF_VERSION_TAPSCRIPT)])
        funding = self.fund_taproot(wallet, tap)

        self.log.info("Reject covenant spend with mismatched output amount")
        bad_spend = self.build_covenant_spend(funding["txid"], funding["sent_vout"], tap, amount=TARGET_AMOUNT + 1)
        self.assert_covenant_rejects(bad_spend)

        self.log.info("Accept and mine exact covenant spend")
        good_spend = self.build_covenant_spend(funding["txid"], funding["sent_vout"], tap)
        self.assert_accept_and_mine(good_spend)

        self.log.info("Fund Taproot vault template")
        vault = node.createbitplusvault(
            "51",
            CScript([OP_TRUE]).hex(),
            "0.00800000",
            0,
            VAULT_DELAY,
            CScript([OP_TRUE]).hex(),
            "0.00700000",
            0,
        )
        vault_internal_key = compute_xonly_pubkey(hash256(b"bitplus vault internal key"))[0]
        vault_tap = taproot_construct(vault_internal_key, [
            ("recovery", CScript(bytes.fromhex(vault["recovery_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
            ("delayed", CScript(bytes.fromhex(vault["delayed_spend_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject vault recovery spend with wrong output amount")
        recovery_funding = self.fund_taproot(wallet, vault_tap)
        bad_recovery = self.build_taproot_script_spend(
            recovery_funding["txid"],
            recovery_funding["sent_vout"],
            vault_tap,
            leaf_name="recovery",
            amount=VAULT_RECOVERY_AMOUNT + 1,
            sequence=0xfffffffe,
        )
        self.assert_covenant_rejects(bad_recovery)

        self.log.info("Accept and mine vault recovery path")
        good_recovery = self.build_taproot_script_spend(
            recovery_funding["txid"],
            recovery_funding["sent_vout"],
            vault_tap,
            leaf_name="recovery",
            amount=VAULT_RECOVERY_AMOUNT,
            sequence=0xfffffffe,
        )
        self.assert_accept_and_mine(good_recovery)

        self.log.info("Reject vault delayed path before relative delay")
        delayed_funding = self.fund_taproot(wallet, vault_tap)
        immature_delayed = self.build_taproot_script_spend(
            delayed_funding["txid"],
            delayed_funding["sent_vout"],
            vault_tap,
            leaf_name="delayed",
            amount=VAULT_DELAYED_AMOUNT,
            sequence=0,
        )
        self.assert_script_rejects(
            immature_delayed,
            "mempool-script-verify-flag-failed (Locktime requirement not satisfied)",
            "block-script-verify-flag-failed (Locktime requirement not satisfied)",
        )

        self.log.info("Accept and mine vault delayed path after relative delay")
        mature_delayed = self.build_taproot_script_spend(
            delayed_funding["txid"],
            delayed_funding["sent_vout"],
            vault_tap,
            leaf_name="delayed",
            amount=VAULT_DELAYED_AMOUNT,
            sequence=VAULT_DELAY,
        )
        self.assert_accept_and_mine(mature_delayed)

        self.log.info("Fund Taproot HTLC template")
        htlc_expiry = node.getblockcount() + 1
        htlc = node.createbitplushtlc(
            "51",
            HTLC_SECRET_HASH,
            CScript([OP_TRUE]).hex(),
            "0.00650000",
            0,
            htlc_expiry,
            CScript([OP_TRUE]).hex(),
            "0.00550000",
            0,
        )
        htlc_internal_key = compute_xonly_pubkey(hash256(b"bitplus htlc internal key"))[0]
        htlc_tap = taproot_construct(htlc_internal_key, [
            ("claim", CScript(bytes.fromhex(htlc["claim_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
            ("refund", CScript(bytes.fromhex(htlc["refund_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject HTLC claim with wrong preimage")
        bad_claim_funding = self.fund_taproot(wallet, htlc_tap)
        bad_claim = self.build_taproot_script_spend(
            bad_claim_funding["txid"],
            bad_claim_funding["sent_vout"],
            htlc_tap,
            leaf_name="claim",
            amount=HTLC_CLAIM_AMOUNT,
            sequence=0xfffffffe,
            witness_items=[HTLC_BAD_SECRET],
        )
        self.assert_script_rejects(
            bad_claim,
            "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
            "block-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
        )

        self.log.info("Accept and mine HTLC claim with preimage")
        good_claim = self.build_taproot_script_spend(
            bad_claim_funding["txid"],
            bad_claim_funding["sent_vout"],
            htlc_tap,
            leaf_name="claim",
            amount=HTLC_CLAIM_AMOUNT,
            sequence=0xfffffffe,
            witness_items=[HTLC_SECRET],
        )
        self.assert_accept_and_mine(good_claim)

        self.log.info("Reject HTLC refund before CLTV expiry")
        refund_funding = self.fund_taproot(wallet, htlc_tap)
        premature_htlc_refund = self.build_taproot_script_spend(
            refund_funding["txid"],
            refund_funding["sent_vout"],
            htlc_tap,
            leaf_name="refund",
            amount=HTLC_REFUND_AMOUNT,
            sequence=0xfffffffe,
        )
        self.assert_script_rejects(
            premature_htlc_refund,
            "mempool-script-verify-flag-failed (Locktime requirement not satisfied)",
            "block-script-verify-flag-failed (Locktime requirement not satisfied)",
        )

        self.log.info("Accept and mine HTLC refund at CLTV expiry")
        mature_htlc_refund = self.build_taproot_script_spend(
            refund_funding["txid"],
            refund_funding["sent_vout"],
            htlc_tap,
            leaf_name="refund",
            amount=HTLC_REFUND_AMOUNT,
            sequence=0xfffffffe,
        )
        mature_htlc_refund.nLockTime = htlc_expiry
        self.assert_accept_and_mine(mature_htlc_refund)

        self.log.info("Fund Taproot collateral template")
        collateral = node.createbitpluscollateral(
            "51",
            CScript([OP_TRUE]).hex(),
            "0.00600000",
            0,
            COLLATERAL_DELAY,
            CScript([OP_TRUE]).hex(),
            "0.00500000",
            0,
        )
        collateral_internal_key = compute_xonly_pubkey(hash256(b"bitplus collateral internal key"))[0]
        collateral_tap = taproot_construct(collateral_internal_key, [
            ("release", CScript(bytes.fromhex(collateral["release_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
            ("return", CScript(bytes.fromhex(collateral["return_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject collateral release with wrong output amount")
        collateral_release_funding = self.fund_taproot(wallet, collateral_tap)
        bad_release = self.build_taproot_script_spend(
            collateral_release_funding["txid"],
            collateral_release_funding["sent_vout"],
            collateral_tap,
            leaf_name="release",
            amount=COLLATERAL_RELEASE_AMOUNT + 1,
            sequence=0xfffffffe,
        )
        self.assert_covenant_rejects(bad_release)

        self.log.info("Accept and mine collateral release path")
        good_release = self.build_taproot_script_spend(
            collateral_release_funding["txid"],
            collateral_release_funding["sent_vout"],
            collateral_tap,
            leaf_name="release",
            amount=COLLATERAL_RELEASE_AMOUNT,
            sequence=0xfffffffe,
        )
        self.assert_accept_and_mine(good_release)

        self.log.info("Reject collateral return before relative delay")
        collateral_return_funding = self.fund_taproot(wallet, collateral_tap)
        immature_return = self.build_taproot_script_spend(
            collateral_return_funding["txid"],
            collateral_return_funding["sent_vout"],
            collateral_tap,
            leaf_name="return",
            amount=COLLATERAL_RETURN_AMOUNT,
            sequence=0,
        )
        self.assert_script_rejects(
            immature_return,
            "mempool-script-verify-flag-failed (Locktime requirement not satisfied)",
            "block-script-verify-flag-failed (Locktime requirement not satisfied)",
        )

        self.log.info("Accept and mine collateral return after relative delay")
        mature_return = self.build_taproot_script_spend(
            collateral_return_funding["txid"],
            collateral_return_funding["sent_vout"],
            collateral_tap,
            leaf_name="return",
            amount=COLLATERAL_RETURN_AMOUNT,
            sequence=COLLATERAL_DELAY,
        )
        self.assert_accept_and_mine(mature_return)

        self.log.info("Fund Taproot refund template")
        refund_expiry = node.getblockcount() + 1
        refunds = node.createbitplusrefundpaths(
            "51",
            refund_expiry,
            CScript([OP_TRUE]).hex(),
            "0.00400000",
            0,
            REFUND_RELATIVE_DELAY,
            CScript([OP_TRUE]).hex(),
            "0.00300000",
            0,
        )
        refund_internal_key = compute_xonly_pubkey(hash256(b"bitplus refund internal key"))[0]
        refund_tap = taproot_construct(refund_internal_key, [
            ("absolute", CScript(bytes.fromhex(refunds["absolute_refund_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
            ("relative", CScript(bytes.fromhex(refunds["relative_refund_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject absolute refund before CLTV expiry")
        absolute_refund_funding = self.fund_taproot(wallet, refund_tap)
        premature_absolute = self.build_taproot_script_spend(
            absolute_refund_funding["txid"],
            absolute_refund_funding["sent_vout"],
            refund_tap,
            leaf_name="absolute",
            amount=REFUND_ABSOLUTE_AMOUNT,
            sequence=0xfffffffe,
        )
        self.assert_script_rejects(
            premature_absolute,
            "mempool-script-verify-flag-failed (Locktime requirement not satisfied)",
            "block-script-verify-flag-failed (Locktime requirement not satisfied)",
        )

        self.log.info("Accept and mine absolute refund at CLTV expiry")
        mature_absolute = self.build_taproot_script_spend(
            absolute_refund_funding["txid"],
            absolute_refund_funding["sent_vout"],
            refund_tap,
            leaf_name="absolute",
            amount=REFUND_ABSOLUTE_AMOUNT,
            sequence=0xfffffffe,
        )
        mature_absolute.nLockTime = refund_expiry
        self.assert_accept_and_mine(mature_absolute)

        self.log.info("Reject relative refund before delay")
        relative_refund_funding = self.fund_taproot(wallet, refund_tap)
        immature_relative = self.build_taproot_script_spend(
            relative_refund_funding["txid"],
            relative_refund_funding["sent_vout"],
            refund_tap,
            leaf_name="relative",
            amount=REFUND_RELATIVE_AMOUNT,
            sequence=0,
        )
        self.assert_script_rejects(
            immature_relative,
            "mempool-script-verify-flag-failed (Locktime requirement not satisfied)",
            "block-script-verify-flag-failed (Locktime requirement not satisfied)",
        )

        self.log.info("Accept and mine relative refund after delay")
        mature_relative = self.build_taproot_script_spend(
            relative_refund_funding["txid"],
            relative_refund_funding["sent_vout"],
            refund_tap,
            leaf_name="relative",
            amount=REFUND_RELATIVE_AMOUNT,
            sequence=REFUND_RELATIVE_DELAY,
        )
        self.assert_accept_and_mine(mature_relative)

        self.log.info("Issue asset for DvP settlement")
        dvp_issuance_tx, dvp_issuance, dvp_root = self.issue_asset(wallet)
        dvp = node.createbitplusdvp(
            "51",
            dvp_issuance["asset_id"],
            300,
            dvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            dvp_root["merkle_path"],
            dvp_root["members_root"],
            CScript([OP_TRUE]).hex(),
            f"{DVP_PAYMENT_AMOUNT / 100_000_000:.8f}",
            1,
        )
        dvp_internal_key = compute_xonly_pubkey(hash256(b"bitplus dvp internal key"))[0]
        dvp_tap = taproot_construct(dvp_internal_key, [
            ("dvp", CScript(bytes.fromhex(dvp["settlement_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject DvP settlement with wrong payment amount")
        dvp_funding = self.fund_taproot(wallet, dvp_tap)
        bad_dvp = self.build_dvp_spend(dvp_funding, dvp_tap, dvp_issuance_tx, dvp_issuance, dvp_root, payment_amount=DVP_PAYMENT_AMOUNT - 1)
        self.assert_covenant_rejects(bad_dvp)

        self.log.info("Reject DvP settlement missing whitelist proof")
        missing_dvp_proof = self.build_dvp_spend(dvp_funding, dvp_tap, dvp_issuance_tx, dvp_issuance, dvp_root, include_proof=False)
        self.assert_consensus_rejects(missing_dvp_proof, "asset-whitelist-proof-missing")

        self.log.info("Accept and mine atomic DvP settlement")
        good_dvp = self.build_dvp_spend(dvp_funding, dvp_tap, dvp_issuance_tx, dvp_issuance, dvp_root)
        self.assert_accept_and_mine(good_dvp)

        self.log.info("Accept and mine atomic DvP settlement with custom asset locking script")
        custom_dvp_issuance_tx, custom_dvp_issuance, custom_dvp_root = self.issue_asset(wallet)
        custom_dvp = node.createbitplusdvp(
            "51",
            custom_dvp_issuance["asset_id"],
            300,
            custom_dvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            custom_dvp_root["merkle_path"],
            custom_dvp_root["members_root"],
            CScript([OP_TRUE]).hex(),
            f"{DVP_PAYMENT_AMOUNT / 100_000_000:.8f}",
            1,
            CUSTOM_ASSET_LOCK_A,
        )
        custom_dvp_internal_key = compute_xonly_pubkey(hash256(b"bitplus custom dvp internal key"))[0]
        custom_dvp_tap = taproot_construct(custom_dvp_internal_key, [
            ("dvp", CScript(bytes.fromhex(custom_dvp["settlement_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])
        custom_dvp_funding = self.fund_taproot(wallet, custom_dvp_tap)
        custom_dvp_spend = self.build_dvp_spend(
            custom_dvp_funding,
            custom_dvp_tap,
            custom_dvp_issuance_tx,
            custom_dvp_issuance,
            custom_dvp_root,
            asset_locking_script=CUSTOM_ASSET_LOCK_A,
        )
        self.assert_accept_and_mine(custom_dvp_spend)

        self.log.info("Issue asset pair for PvP settlement")
        first_pvp_issuance_tx, first_pvp_issuance, first_pvp_root = self.issue_asset(wallet)
        second_pvp_issuance_tx, second_pvp_issuance, second_pvp_root = self.issue_asset(wallet)
        pvp = node.createbitpluspvp(
            "51",
            first_pvp_issuance["asset_id"],
            500,
            first_pvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            first_pvp_root["merkle_path"],
            first_pvp_root["members_root"],
            second_pvp_issuance["asset_id"],
            500,
            second_pvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            1,
            0,
            second_pvp_root["merkle_path"],
            second_pvp_root["members_root"],
        )
        pvp_internal_key = compute_xonly_pubkey(hash256(b"bitplus pvp internal key"))[0]
        pvp_tap = taproot_construct(pvp_internal_key, [
            ("pvp", CScript(bytes.fromhex(pvp["settlement_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])

        self.log.info("Reject PvP settlement with second asset at wrong output index")
        bad_pvp_funding = self.fund_taproot(wallet, pvp_tap)
        bad_pvp = self.build_pvp_spend(
            bad_pvp_funding,
            pvp_tap,
            first_pvp_issuance_tx,
            first_pvp_issuance,
            first_pvp_root,
            second_pvp_issuance_tx,
            second_pvp_issuance,
            second_pvp_root,
            wrong_second_index=True,
        )
        self.assert_covenant_rejects(bad_pvp)

        self.log.info("Reject PvP settlement missing second whitelist proof")
        missing_proof_pvp = self.build_pvp_spend(
            bad_pvp_funding,
            pvp_tap,
            first_pvp_issuance_tx,
            first_pvp_issuance,
            first_pvp_root,
            second_pvp_issuance_tx,
            second_pvp_issuance,
            second_pvp_root,
            include_second_proof=False,
        )
        self.assert_consensus_rejects(missing_proof_pvp, "asset-whitelist-proof-missing")

        self.log.info("Accept and mine atomic PvP settlement")
        good_pvp_funding = self.fund_taproot(wallet, pvp_tap)
        good_pvp = self.build_pvp_spend(
            good_pvp_funding,
            pvp_tap,
            first_pvp_issuance_tx,
            first_pvp_issuance,
            first_pvp_root,
            second_pvp_issuance_tx,
            second_pvp_issuance,
            second_pvp_root,
        )
        self.assert_accept_and_mine(good_pvp)

        self.log.info("Accept and mine atomic PvP settlement with custom asset locking scripts")
        first_custom_pvp_issuance_tx, first_custom_pvp_issuance, first_custom_pvp_root = self.issue_asset(wallet)
        second_custom_pvp_issuance_tx, second_custom_pvp_issuance, second_custom_pvp_root = self.issue_asset(wallet)
        custom_pvp = node.createbitpluspvp(
            "51",
            first_custom_pvp_issuance["asset_id"],
            500,
            first_custom_pvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            0,
            0,
            first_custom_pvp_root["merkle_path"],
            first_custom_pvp_root["members_root"],
            second_custom_pvp_issuance["asset_id"],
            500,
            second_custom_pvp_issuance["metadata"]["commitment_hash"],
            MEMBER_HASH,
            1,
            0,
            second_custom_pvp_root["merkle_path"],
            second_custom_pvp_root["members_root"],
            CUSTOM_ASSET_LOCK_A,
            CUSTOM_ASSET_LOCK_B,
        )
        custom_pvp_internal_key = compute_xonly_pubkey(hash256(b"bitplus custom pvp internal key"))[0]
        custom_pvp_tap = taproot_construct(custom_pvp_internal_key, [
            ("pvp", CScript(bytes.fromhex(custom_pvp["settlement_leaf"]["script"])), LEAF_VERSION_TAPSCRIPT),
        ])
        custom_pvp_funding = self.fund_taproot(wallet, custom_pvp_tap)
        custom_pvp_spend = self.build_pvp_spend(
            custom_pvp_funding,
            custom_pvp_tap,
            first_custom_pvp_issuance_tx,
            first_custom_pvp_issuance,
            first_custom_pvp_root,
            second_custom_pvp_issuance_tx,
            second_custom_pvp_issuance,
            second_custom_pvp_root,
            first_asset_locking_script=CUSTOM_ASSET_LOCK_A,
            second_asset_locking_script=CUSTOM_ASSET_LOCK_B,
        )
        self.assert_accept_and_mine(custom_pvp_spend)


if __name__ == "__main__":
    BitplusCovenantsTest(__file__).main()
