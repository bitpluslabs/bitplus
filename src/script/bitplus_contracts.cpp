// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bitplus_contracts.h>

#include <hash.h>
#include <uint256.h>

#include <vector>

namespace bitplus::contracts {

CScript BuildCheckOutputVerifyScript(const CScript& script_pub_key, CAmount amount, uint32_t output_index)
{
    const uint256 script_pub_key_hash{(HashWriter{} << script_pub_key).GetSHA256()};
    const std::vector<unsigned char> script_pub_key_hash_vch{script_pub_key_hash.begin(), script_pub_key_hash.end()};
    return CScript{} << script_pub_key_hash_vch << static_cast<int64_t>(amount) << static_cast<int64_t>(output_index) << OP_CHECKOUTPUTVERIFY;
}

CScript BuildVaultRecoveryLeaf(const CScript& authorization_script, const CScript& recovery_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(recovery_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildVaultDelayedSpendLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& destination_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        relative_delay,
        OP_CHECKSEQUENCEVERIFY,
        OP_DROP,
        BuildCheckOutputVerifyScript(destination_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildHtlcClaimLeaf(const CScript& authorization_script, const uint256& secret_hash, const CScript& claim_script_pub_key, CAmount amount, uint32_t output_index)
{
    const std::vector<unsigned char> secret_hash_vch{secret_hash.begin(), secret_hash.end()};
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        OP_SHA256,
        secret_hash_vch,
        OP_EQUALVERIFY,
        BuildCheckOutputVerifyScript(claim_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildHtlcRefundLeaf(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        absolute_expiry,
        OP_CHECKLOCKTIMEVERIFY,
        OP_DROP,
        BuildCheckOutputVerifyScript(refund_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildDvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index)
{
    return BuildDvPSettlementLeaf(
        authorization_script,
        asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(asset_transfer),
        asset_output_index,
        payment_script_pub_key,
        payment_amount,
        payment_output_index);
}

CScript BuildDvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    const CScript& asset_locking_script,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index)
{
    const CScript asset_script_pub_key{bitplus::assets::BuildAssetCommitmentScript(asset_transfer, asset_locking_script)};
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(asset_script_pub_key, 0, asset_output_index),
        BuildCheckOutputVerifyScript(payment_script_pub_key, payment_amount, payment_output_index),
        OP_TRUE);
}

CScript BuildPvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    uint32_t second_asset_output_index)
{
    return BuildPvPSettlementLeaf(
        authorization_script,
        first_asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(first_asset_transfer),
        first_asset_output_index,
        second_asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(second_asset_transfer),
        second_asset_output_index);
}

CScript BuildPvPSettlementLeaf(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    const CScript& first_asset_locking_script,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    const CScript& second_asset_locking_script,
    uint32_t second_asset_output_index)
{
    const CScript first_asset_script_pub_key{bitplus::assets::BuildAssetCommitmentScript(first_asset_transfer, first_asset_locking_script)};
    const CScript second_asset_script_pub_key{bitplus::assets::BuildAssetCommitmentScript(second_asset_transfer, second_asset_locking_script)};
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(first_asset_script_pub_key, 0, first_asset_output_index),
        BuildCheckOutputVerifyScript(second_asset_script_pub_key, 0, second_asset_output_index),
        OP_TRUE);
}

CScript BuildCollateralReleaseLeaf(const CScript& authorization_script, const CScript& release_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(release_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildCollateralReturnLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& return_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        relative_delay,
        OP_CHECKSEQUENCEVERIFY,
        OP_DROP,
        BuildCheckOutputVerifyScript(return_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildAbsoluteRefundLeaf(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        absolute_expiry,
        OP_CHECKLOCKTIMEVERIFY,
        OP_DROP,
        BuildCheckOutputVerifyScript(refund_script_pub_key, amount, output_index),
        OP_TRUE);
}

CScript BuildRelativeRefundLeaf(const CScript& authorization_script, int64_t relative_delay, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        relative_delay,
        OP_CHECKSEQUENCEVERIFY,
        OP_DROP,
        BuildCheckOutputVerifyScript(refund_script_pub_key, amount, output_index),
        OP_TRUE);
}

} // namespace bitplus::contracts
