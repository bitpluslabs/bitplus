// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/rawtransaction_psbt.h>

#include <coins.h>
#include <index/txindex.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>

#include <map>

using node::FindCoins;
using node::NodeContext;

PartiallySignedTransaction ProcessPSBT(
    const std::string& psbt_string,
    const std::any& context,
    const HidingSigningProvider& provider,
    std::optional<int> sighash_type,
    bool finalize)
{
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, psbt_string, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();
    const NodeContext& node = EnsureAnyNodeContext(context);

    std::map<COutPoint, Coin> coins;

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& psbt_input = psbtx.inputs.at(i);
        const CTxIn& tx_in = psbtx.tx->vin.at(i);

        if (psbt_input.non_witness_utxo) continue;

        CTransactionRef tx;
        if (g_txindex) {
            uint256 block_hash;
            g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx);
        }
        if (!tx) {
            tx = node.mempool->get(tx_in.prevout.hash);
        }
        if (tx) {
            psbt_input.non_witness_utxo = tx;
        } else {
            coins[tx_in.prevout];
        }
    }

    if (!coins.empty()) {
        FindCoins(node, coins);
        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs.at(i);
            if (!input.non_witness_utxo) {
                const CTxIn& tx_in = psbtx.tx->vin.at(i);
                const Coin& coin = coins.at(tx_in.prevout);
                if (!coin.out.IsNull() && IsSegWitOutput(provider, coin.out.scriptPubKey)) {
                    input.witness_utxo = coin.out;
                }
            }
        }
    }

    const PrecomputedTransactionData& txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        if (PSBTInputSigned(psbtx.inputs.at(i))) {
            continue;
        }
        if (SignPSBTInput(provider, psbtx, /*index=*/i, &txdata, {.sighash_type = sighash_type, .finalize = finalize}, /*out_sigdata=*/nullptr) == common::PSBTError::SIGHASH_MISMATCH) {
            throw JSONRPCPSBTError(common::PSBTError::SIGHASH_MISMATCH);
        }
    }

    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        UpdatePSBTOutput(provider, psbtx, i);
    }

    RemoveUnnecessaryTransactions(psbtx);

    return psbtx;
}
