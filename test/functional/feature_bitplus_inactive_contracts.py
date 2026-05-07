#!/usr/bin/env python3
# Copyright (c) 2026 The Bitplus Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Bitplus institutional contracts stay dormant before activation."""

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
)
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.key import compute_xonly_pubkey


FUNDING_AMOUNT = 1_000_000
WRONG_AMOUNT = 700_000


def control_block(tap, leaf_name):
    leaf = tap.leaves[leaf_name]
    return bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


class BitplusInactiveContractsTest(BitplusTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)

        deployments = node.getdeploymentinfo()["deployments"]
        assert_equal(deployments.get("institutional_contracts", {"active": False})["active"], False)
        self.generate(wallet, 101)

        self.log.info("Fund dormant covenant leaf")
        target_script = CScript([OP_TRUE])
        covenant_fragment = node.createbitpluscovleaf(target_script.hex(), "0.00900000", 0)["script"]
        covenant_leaf = CScript(bytes.fromhex(covenant_fragment) + bytes([OP_TRUE]))
        internal_key = compute_xonly_pubkey(hash256(b"bitplus inactive covenant internal key"))[0]
        tap = taproot_construct(internal_key, [("cov", covenant_leaf, LEAF_VERSION_TAPSCRIPT)])
        funding = wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=FUNDING_AMOUNT, fee=1_000)
        self.generateblock(node, output="raw(51)", transactions=[funding["txid"]])

        self.log.info("Mine mismatched covenant spend while deployment is inactive")
        leaf = tap.leaves["cov"]
        spend = CTransaction()
        spend.version = 2
        spend.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]), nSequence=0xfffffffe)]
        spend.vout = [
            CTxOut(WRONG_AMOUNT, target_script),
            CTxOut(0, CScript([OP_RETURN, b"bitplus inactive contract padding"])),
        ]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [
            bytes(leaf.script),
            control_block(tap, "cov"),
        ]

        self.generateblock(node, output="raw(51)", transactions=[spend.serialize().hex()])


if __name__ == "__main__":
    BitplusInactiveContractsTest(__file__).main()
