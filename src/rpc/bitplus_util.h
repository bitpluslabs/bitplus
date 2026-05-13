// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_RPC_BITPLUS_UTIL_H
#define BITPLUS_RPC_BITPLUS_UTIL_H

#include <consensus/amount.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <script/script.h>
#include <uint256.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <univalue.h>

namespace bitplus::rpc {

inline UniValue AssetCommitmentToJSON(const assets::AssetCommitment& commitment, const CScript& script_pub_key)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("payload", HexStr(assets::EncodeAssetCommitment(commitment)));
    result.pushKV("scriptPubKey", HexStr(script_pub_key));
    result.pushKV("commitment_hash", assets::HashAssetCommitment(commitment).ToString());
    result.pushKV("asset_id", commitment.asset_id.ToString());
    return result;
}

inline assets::AssetCommitmentType ParseAssetCommitmentType(const std::string& type)
{
    if (type == "issuance") return assets::AssetCommitmentType::ISSUANCE;
    if (type == "transfer") return assets::AssetCommitmentType::TRANSFER;
    if (type == "burn") return assets::AssetCommitmentType::BURN;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "asset type must be one of: issuance, transfer, burn");
}

inline uint64_t ParseAssetAmount(const UniValue& value)
{
    const int64_t amount{value.getInt<int64_t>()};
    if (amount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "asset amount must be greater than zero");
    }
    return static_cast<uint64_t>(amount);
}

inline CScript ParseScriptHex(const UniValue& value, std::string_view name)
{
    const std::vector<unsigned char> bytes{ParseHexV(value, name)};
    return CScript{bytes.begin(), bytes.end()};
}

inline uint32_t ParseOutputIndex(const UniValue& value, std::string_view name)
{
    const int64_t index{value.getInt<int64_t>()};
    if (index < 0 || index > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " out of range");
    }
    return static_cast<uint32_t>(index);
}

inline int64_t ParseNonNegativeInt64(const UniValue& value, std::string_view name)
{
    const int64_t parsed{value.getInt<int64_t>()};
    if (parsed < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be non-negative");
    return parsed;
}

inline CAmount ParsePositiveBtpAmount(const UniValue& value, std::string_view name)
{
    const CAmount amount{AmountFromValue(value)};
    if (amount <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be greater than zero");
    return amount;
}

inline CAmount ParseNonNegativeBtpAmount(const UniValue& value, std::string_view name)
{
    const CAmount amount{AmountFromValue(value)};
    if (amount < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be non-negative");
    return amount;
}

inline uint256 ParseNonNullHash(const UniValue& value, std::string_view name)
{
    const uint256 hash{ParseHashV(value, name)};
    if (hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must not be null");
    return hash;
}

inline std::vector<uint256> ParseWhitelistMerklePath(const UniValue& value, std::string_view name)
{
    const UniValue& array{value.get_array()};
    const auto& siblings{array.getValues()};
    if (siblings.size() > assets::MAX_WHITELIST_PROOF_DEPTH) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " too deep");

    std::vector<uint256> path;
    path.reserve(siblings.size());
    for (const UniValue& sibling : siblings) {
        const uint256 hash{ParseHashV(sibling, name)};
        if (hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " sibling must not be null");
        path.push_back(hash);
    }
    return path;
}

inline std::string SignedMovementString(uint64_t received, uint64_t spent)
{
    if (received >= spent) return std::to_string(received - spent);
    return "-" + std::to_string(spent - received);
}

inline void ThrowIfInvalidAssetResult(const assets::AssetValidationResult& result)
{
    if (!result.valid) throw JSONRPCError(RPC_INVALID_PARAMETER, result.reason);
}

inline void ValidateConstructedAssetScript(const CScript& script_pub_key)
{
    const std::optional<assets::AssetOutput> output{
        assets::DecodeAssetOutput(CTxOut{0, script_pub_key}, 0)
    };
    if (!output.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset commitment script");
    ThrowIfInvalidAssetResult(assets::ValidateAssetOutput(*output));
}

struct AssetScriptWithLocking {
    CScript script_pub_key;
    CScript locking_script;
};

inline AssetScriptWithLocking BuildAssetScriptWithOptionalLockingScript(
    const assets::AssetCommitment& commitment,
    const UniValue& locking_script,
    std::string_view locking_script_name)
{
    CScript inner_locking_script;
    if (locking_script.isNull()) {
        inner_locking_script = assets::BuildDefaultAssetLockingScript(commitment);
    } else {
        const std::vector<unsigned char> locking_script_bytes{ParseHexV(locking_script, locking_script_name)};
        inner_locking_script = CScript{locking_script_bytes.begin(), locking_script_bytes.end()};
    }

    CScript script_pub_key{assets::BuildAssetCommitmentScript(commitment, inner_locking_script)};
    ValidateConstructedAssetScript(script_pub_key);
    return {.script_pub_key = std::move(script_pub_key), .locking_script = std::move(inner_locking_script)};
}

inline assets::AssetCommitment ParseTransferCommitment(
    const UniValue& asset_id,
    const UniValue& amount,
    const UniValue& metadata_hash,
    const UniValue& member_hash)
{
    assets::AssetCommitment commitment{
        .type = assets::AssetCommitmentType::TRANSFER,
        .asset_id = ParseHashV(asset_id, "asset_id"),
        .amount = ParseAssetAmount(amount),
        .metadata_hash = ParseHashV(metadata_hash, "metadata_hash"),
        .member_hash = ParseHashV(member_hash, "member_hash"),
    };
    ValidateConstructedAssetScript(assets::BuildAssetCommitmentScript(commitment));
    return commitment;
}

inline UniValue ContractLeafToJSON(const CScript& script)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("script", HexStr(script));
    result.pushKV("script_hash", (HashWriter{} << script).GetSHA256().ToString());
    return result;
}

inline CScript CheckedContractScript(util::Result<CScript> script)
{
    if (!script) throw JSONRPCError(RPC_INVALID_PARAMETER, util::ErrorString(script).original);
    return std::move(script.value());
}

inline void PushAssetValidation(UniValue& result, const assets::AssetValidationResult& validation)
{
    result.pushKV("valid", validation.valid);
    if (!validation.valid) result.pushKV("validation_error", validation.reason);
}

inline std::string AssetCommitmentTypeToString(assets::AssetCommitmentType type)
{
    switch (type) {
    case assets::AssetCommitmentType::ISSUANCE:
        return "issuance";
    case assets::AssetCommitmentType::TRANSFER:
        return "transfer";
    case assets::AssetCommitmentType::BURN:
        return "burn";
    }
    return "unknown";
}

inline UniValue DecodedAssetCommitmentToJSON(const assets::AssetOutput& output)
{
    UniValue asset{UniValue::VOBJ};
    asset.pushKV("format", "BTPASSET");
    asset.pushKV("type", AssetCommitmentTypeToString(output.commitment.type));
    asset.pushKV("asset_id", output.commitment.asset_id.ToString());
    asset.pushKV("amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(output.commitment.amount))});
    asset.pushKV("metadata_hash", output.commitment.metadata_hash.ToString());
    asset.pushKV("member_hash", output.commitment.member_hash.ToString());
    asset.pushKV("commitment_hash", assets::HashAssetCommitment(output.commitment).ToString());
    asset.pushKV("locking_script", HexStr(output.locking_script));
    return asset;
}

inline UniValue DecodedMetadataCommitmentToJSON(const assets::AssetMetadataOutput& output)
{
    UniValue metadata{UniValue::VOBJ};
    metadata.pushKV("format", "BTPMETA");
    metadata.pushKV("issuer_id", output.commitment.issuer_id.ToString());
    metadata.pushKV("document_hash", output.commitment.document_hash.ToString());
    metadata.pushKV("rules_hash", output.commitment.rules_hash.ToString());
    metadata.pushKV("commitment_hash", assets::HashAssetMetadataCommitment(output.commitment).ToString());
    return metadata;
}

inline UniValue DecodedWhitelistCommitmentToJSON(const assets::AssetWhitelistOutput& output)
{
    UniValue whitelist{UniValue::VOBJ};
    whitelist.pushKV("format", "BTPWLST");
    whitelist.pushKV("list_id", output.commitment.list_id.ToString());
    whitelist.pushKV("admin_key_hash", output.commitment.admin_key_hash.ToString());
    whitelist.pushKV("members_root", output.commitment.members_root.ToString());
    whitelist.pushKV("flags", static_cast<int64_t>(output.commitment.flags));
    whitelist.pushKV("commitment_hash", assets::HashAssetWhitelistCommitment(output.commitment).ToString());
    return whitelist;
}

inline UniValue DecodedWhitelistProofCommitmentToJSON(const assets::AssetWhitelistProofOutput& output)
{
    UniValue proof{UniValue::VOBJ};
    proof.pushKV("format", "BTPWPROOF");
    proof.pushKV("asset_output_index", static_cast<int64_t>(output.commitment.asset_output_index));
    proof.pushKV("member_hash", output.commitment.member_hash.ToString());
    proof.pushKV("proof_index", static_cast<int64_t>(output.commitment.proof_index));
    UniValue path{UniValue::VARR};
    for (const uint256& sibling : output.commitment.merkle_path) {
        path.push_back(sibling.ToString());
    }
    proof.pushKV("merkle_path", std::move(path));
    proof.pushKV("members_root", assets::ComputeWhitelistMembersRoot(output.commitment).ToString());
    proof.pushKV("commitment_hash", assets::HashAssetWhitelistProofCommitment(output.commitment).ToString());
    return proof;
}

} // namespace bitplus::rpc

#endif // BITPLUS_RPC_BITPLUS_UTIL_H
