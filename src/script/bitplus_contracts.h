// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_SCRIPT_BITPLUS_CONTRACTS_H
#define BITPLUS_SCRIPT_BITPLUS_CONTRACTS_H

#include <consensus/amount.h>
#include <script/bitplus_assets.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>

namespace bitplus::contracts {

/** Build <scriptPubKeyHash> <amount> <output_index> OP_CHECKOUTPUTVERIFY. */
CScript BuildCheckOutputVerifyScript(const CScript& script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build a vault recovery leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the
 * transaction to create the exact recovery output.
 */
CScript BuildVaultRecoveryLeaf(const CScript& authorization_script, const CScript& recovery_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build a delayed vault spend leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the input
 * sequence to satisfy the relative delay and the transaction to create the
 * exact destination output.
 */
CScript BuildVaultDelayedSpendLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& destination_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build an HTLC claim leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires a SHA256
 * preimage and sends the locked value to the exact claim output.
 */
CScript BuildHtlcClaimLeaf(const CScript& authorization_script, const uint256& secret_hash, const CScript& claim_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build an HTLC refund leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires nLockTime
 * to satisfy the absolute expiry and sends the locked value to the exact refund
 * output.
 */
CScript BuildHtlcRefundLeaf(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build a delivery-versus-payment settlement leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the
 * transaction to carry the exact asset-transfer commitment output and the exact
 * BTP payment output.
 */
CScript BuildDvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index);

/**
 * Build a delivery-versus-payment settlement leaf with a custom asset locking
 * script.
 *
 * The asset transfer output is committed as:
 * <asset_transfer> OP_DROP <asset_locking_script>
 */
CScript BuildDvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    const CScript& asset_locking_script,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index);

/**
 * Build a payment-versus-payment settlement leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the
 * transaction to carry two exact asset-transfer commitment outputs.
 */
CScript BuildPvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    uint32_t second_asset_output_index);

/**
 * Build a payment-versus-payment settlement leaf with custom asset locking
 * scripts.
 *
 * Each asset transfer output is committed as:
 * <asset_transfer> OP_DROP <asset_locking_script>
 */
CScript BuildPvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    const CScript& first_asset_locking_script,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    const CScript& second_asset_locking_script,
    uint32_t second_asset_output_index);

/**
 * Build a collateral release leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf releases the locked
 * collateral to the exact release output.
 */
CScript BuildCollateralReleaseLeaf(const CScript& authorization_script, const CScript& release_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build a delayed collateral return leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the input
 * sequence to satisfy the relative delay and returns the locked collateral to
 * the exact return output.
 */
CScript BuildCollateralReturnLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& return_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build an absolute-expiry refund leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires nLockTime
 * to satisfy the absolute expiry and refunds to the exact output.
 */
CScript BuildAbsoluteRefundLeaf(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index);

/**
 * Build a relative-expiry refund leaf.
 *
 * The authorization script must leave exactly one truthy stack item for
 * OP_VERIFY and no extra stack items. On success, the leaf requires the input
 * sequence to satisfy the relative delay and refunds to the exact output.
 */
CScript BuildRelativeRefundLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index);

} // namespace bitplus::contracts

#endif // BITPLUS_SCRIPT_BITPLUS_CONTRACTS_H
