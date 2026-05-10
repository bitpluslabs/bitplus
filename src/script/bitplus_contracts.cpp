// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bitplus_contracts.h>

#include <consensus/amount.h>
#include <hash.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/translation.h>

#include <vector>

namespace bitplus::contracts {
namespace {

util::Result<void> ValidateAuthorizationScript(const CScript& authorization_script)
{
    if (authorization_script.empty()) return util::Error{Untranslated("authorization_script must not be empty")};
    return {};
}

util::Result<void> ValidateOutputScript(const CScript& script_pub_key, const char* name)
{
    if (script_pub_key.empty()) return util::Error{Untranslated(strprintf("%s must not be empty", name))};
    return {};
}

util::Result<void> ValidateCovenantAmount(CAmount amount, const char* name)
{
    if (amount < 0) return util::Error{Untranslated(strprintf("%s must be non-negative", name))};
    if (!MoneyRange(amount)) return util::Error{Untranslated(strprintf("%s out of range", name))};
    return {};
}

util::Result<void> ValidatePositiveAmount(CAmount amount, const char* name)
{
    if (amount <= 0) return util::Error{Untranslated(strprintf("%s must be greater than zero", name))};
    if (!MoneyRange(amount)) return util::Error{Untranslated(strprintf("%s out of range", name))};
    return {};
}

util::Result<void> ValidateNonNegativeLockValue(int64_t value, const char* name)
{
    if (value < 0) return util::Error{Untranslated(strprintf("%s must be non-negative", name))};
    return {};
}

util::Result<void> ValidateAssetLockingScript(const CScript& locking_script, const char* name)
{
    if (locking_script.empty()) return util::Error{Untranslated(strprintf("%s must not be empty", name))};
    if (locking_script.IsUnspendable()) return util::Error{Untranslated(strprintf("%s must be spendable", name))};
    if (bitplus::assets::DecodeAssetCommitmentLockingScript(locking_script).has_value()) {
        return util::Error{Untranslated(strprintf("%s must not be a nested asset carrier", name))};
    }
    return {};
}

util::Result<void> ValidateAssetCarrier(const bitplus::assets::AssetCommitment& commitment, const CScript& locking_script, const char* name)
{
    if (auto valid_lock{ValidateAssetLockingScript(locking_script, name)}; !valid_lock) return util::Error{util::ErrorString(valid_lock)};

    const CScript script_pub_key{bitplus::assets::BuildAssetCommitmentScript(commitment, locking_script)};
    const std::optional<bitplus::assets::AssetOutput> output{
        bitplus::assets::DecodeAssetOutput(CTxOut{0, script_pub_key}, 0)
    };
    if (!output.has_value()) return util::Error{Untranslated("invalid asset commitment script")};

    const bitplus::assets::AssetValidationResult result{bitplus::assets::ValidateAssetOutput(*output)};
    if (!result.valid) return util::Error{Untranslated(result.reason)};
    return {};
}

} // namespace

CScript BuildCheckOutputVerifyScript(const CScript& script_pub_key, CAmount amount, uint32_t output_index)
{
    const uint256 script_pub_key_hash{(HashWriter{} << script_pub_key).GetSHA256()};
    const std::vector<unsigned char> script_pub_key_hash_vch{script_pub_key_hash.begin(), script_pub_key_hash.end()};
    return CScript{} << script_pub_key_hash_vch << static_cast<int64_t>(amount) << static_cast<int64_t>(output_index) << OP_CHECKOUTPUTVERIFY;
}

util::Result<CScript> BuildCheckOutputVerifyScriptChecked(const CScript& script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateOutputScript(script_pub_key, "script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateCovenantAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildCheckOutputVerifyScript(script_pub_key, amount, output_index);
}

CScript BuildVaultRecoveryLeaf(const CScript& authorization_script, const CScript& recovery_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(recovery_script_pub_key, amount, output_index),
        OP_TRUE);
}

util::Result<CScript> BuildVaultRecoveryLeafChecked(const CScript& authorization_script, const CScript& recovery_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(recovery_script_pub_key, "recovery_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildVaultRecoveryLeaf(authorization_script, recovery_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildVaultDelayedSpendLeafChecked(const CScript& authorization_script, int64_t relative_delay, const CScript& destination_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateNonNegativeLockValue(relative_delay, "relative_delay")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(destination_script_pub_key, "destination_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildVaultDelayedSpendLeaf(authorization_script, relative_delay, destination_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildHtlcClaimLeafChecked(const CScript& authorization_script, const uint256& secret_hash, const CScript& claim_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (secret_hash.IsNull()) return util::Error{Untranslated("secret_hash must not be null")};
    if (auto valid{ValidateOutputScript(claim_script_pub_key, "claim_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildHtlcClaimLeaf(authorization_script, secret_hash, claim_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildHtlcRefundLeafChecked(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateNonNegativeLockValue(absolute_expiry, "absolute_expiry")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(refund_script_pub_key, "refund_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildHtlcRefundLeaf(authorization_script, absolute_expiry, refund_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildDvPSettlementLeafChecked(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index)
{
    return BuildDvPSettlementLeafChecked(
        authorization_script,
        asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(asset_transfer),
        asset_output_index,
        payment_script_pub_key,
        payment_amount,
        payment_output_index);
}

util::Result<CScript> BuildDvPSettlementLeafChecked(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& asset_transfer,
    const CScript& asset_locking_script,
    uint32_t asset_output_index,
    const CScript& payment_script_pub_key,
    CAmount payment_amount,
    uint32_t payment_output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateAssetCarrier(asset_transfer, asset_locking_script, "asset_locking_script")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(payment_script_pub_key, "payment_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(payment_amount, "payment_amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildDvPSettlementLeaf(authorization_script, asset_transfer, asset_locking_script, asset_output_index, payment_script_pub_key, payment_amount, payment_output_index);
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

util::Result<CScript> BuildPvPSettlementLeafChecked(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    uint32_t second_asset_output_index)
{
    return BuildPvPSettlementLeafChecked(
        authorization_script,
        first_asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(first_asset_transfer),
        first_asset_output_index,
        second_asset_transfer,
        bitplus::assets::BuildDefaultAssetLockingScript(second_asset_transfer),
        second_asset_output_index);
}

util::Result<CScript> BuildPvPSettlementLeafChecked(
    const CScript& authorization_script,
    const bitplus::assets::AssetCommitment& first_asset_transfer,
    const CScript& first_asset_locking_script,
    uint32_t first_asset_output_index,
    const bitplus::assets::AssetCommitment& second_asset_transfer,
    const CScript& second_asset_locking_script,
    uint32_t second_asset_output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateAssetCarrier(first_asset_transfer, first_asset_locking_script, "first_asset_locking_script")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateAssetCarrier(second_asset_transfer, second_asset_locking_script, "second_asset_locking_script")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildPvPSettlementLeaf(authorization_script, first_asset_transfer, first_asset_locking_script, first_asset_output_index, second_asset_transfer, second_asset_locking_script, second_asset_output_index);
}

CScript BuildCollateralReleaseLeaf(const CScript& authorization_script, const CScript& release_script_pub_key, CAmount amount, uint32_t output_index)
{
    return BuildScript(
        authorization_script,
        OP_VERIFY,
        BuildCheckOutputVerifyScript(release_script_pub_key, amount, output_index),
        OP_TRUE);
}

util::Result<CScript> BuildCollateralReleaseLeafChecked(const CScript& authorization_script, const CScript& release_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(release_script_pub_key, "release_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildCollateralReleaseLeaf(authorization_script, release_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildCollateralReturnLeafChecked(const CScript& authorization_script, int64_t relative_delay, const CScript& return_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateNonNegativeLockValue(relative_delay, "relative_delay")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(return_script_pub_key, "return_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildCollateralReturnLeaf(authorization_script, relative_delay, return_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildAbsoluteRefundLeafChecked(const CScript& authorization_script, int64_t absolute_expiry, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateNonNegativeLockValue(absolute_expiry, "absolute_expiry")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(refund_script_pub_key, "refund_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildAbsoluteRefundLeaf(authorization_script, absolute_expiry, refund_script_pub_key, amount, output_index);
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

util::Result<CScript> BuildRelativeRefundLeafChecked(const CScript& authorization_script, int64_t relative_delay, const CScript& refund_script_pub_key, CAmount amount, uint32_t output_index)
{
    if (auto valid{ValidateAuthorizationScript(authorization_script)}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateNonNegativeLockValue(relative_delay, "relative_delay")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidateOutputScript(refund_script_pub_key, "refund_script_pub_key")}; !valid) return util::Error{util::ErrorString(valid)};
    if (auto valid{ValidatePositiveAmount(amount, "amount")}; !valid) return util::Error{util::ErrorString(valid)};
    return BuildRelativeRefundLeaf(authorization_script, relative_delay, refund_script_pub_key, amount, output_index);
}

} // namespace bitplus::contracts
