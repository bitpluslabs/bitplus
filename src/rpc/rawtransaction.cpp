// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <script/bitplus_contracts.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <txmempool.h>
#include <uint256.h>
#include <undo.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>

#include <univalue.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;

static constexpr decltype(CTransaction::version) DEFAULT_RAWTX_VERSION{CTransaction::CURRENT_VERSION};

static UniValue AssetCommitmentToJSON(const bitplus::assets::AssetCommitment& commitment, const CScript& script_pub_key)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("payload", HexStr(bitplus::assets::EncodeAssetCommitment(commitment)));
    result.pushKV("scriptPubKey", HexStr(script_pub_key));
    result.pushKV("commitment_hash", bitplus::assets::HashAssetCommitment(commitment).ToString());
    result.pushKV("asset_id", commitment.asset_id.ToString());
    return result;
}

static bitplus::assets::AssetCommitmentType ParseAssetCommitmentType(const std::string& type)
{
    if (type == "issuance") return bitplus::assets::AssetCommitmentType::ISSUANCE;
    if (type == "transfer") return bitplus::assets::AssetCommitmentType::TRANSFER;
    if (type == "burn") return bitplus::assets::AssetCommitmentType::BURN;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "asset type must be one of: issuance, transfer, burn");
}

static uint64_t ParseAssetAmount(const UniValue& value)
{
    const int64_t amount{value.getInt<int64_t>()};
    if (amount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "asset amount must be greater than zero");
    }
    return static_cast<uint64_t>(amount);
}

static CScript ParseScriptHex(const UniValue& value, std::string_view name)
{
    const std::vector<unsigned char> bytes{ParseHexV(value, name)};
    return CScript{bytes.begin(), bytes.end()};
}

static uint32_t ParseOutputIndex(const UniValue& value, std::string_view name)
{
    const int64_t index{value.getInt<int64_t>()};
    if (index < 0 || index > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " out of range");
    }
    return static_cast<uint32_t>(index);
}

static int64_t ParseNonNegativeInt64(const UniValue& value, std::string_view name)
{
    const int64_t parsed{value.getInt<int64_t>()};
    if (parsed < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be non-negative");
    return parsed;
}

static CAmount ParsePositiveBtpAmount(const UniValue& value, std::string_view name)
{
    const CAmount amount{AmountFromValue(value)};
    if (amount <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be greater than zero");
    return amount;
}

static uint256 ParseNonNullHash(const UniValue& value, std::string_view name)
{
    const uint256 hash{ParseHashV(value, name)};
    if (hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must not be null");
    return hash;
}

static void ThrowIfInvalidAssetResult(const bitplus::assets::AssetValidationResult& result)
{
    if (!result.valid) throw JSONRPCError(RPC_INVALID_PARAMETER, result.reason);
}

static void ValidateConstructedAssetScript(const CScript& script_pub_key)
{
    const std::optional<bitplus::assets::AssetOutput> output{
        bitplus::assets::DecodeAssetOutput(CTxOut{0, script_pub_key}, 0)
    };
    if (!output.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset commitment script");
    ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetOutput(*output));
}

struct AssetScriptWithLocking {
    CScript script_pub_key;
    CScript locking_script;
};

static AssetScriptWithLocking BuildAssetScriptWithOptionalLockingScript(
    const bitplus::assets::AssetCommitment& commitment,
    const UniValue& locking_script,
    std::string_view locking_script_name)
{
    CScript inner_locking_script;
    if (locking_script.isNull()) {
        inner_locking_script = bitplus::assets::BuildDefaultAssetLockingScript(commitment);
    } else {
        const std::vector<unsigned char> locking_script_bytes{ParseHexV(locking_script, locking_script_name)};
        inner_locking_script = CScript{locking_script_bytes.begin(), locking_script_bytes.end()};
    }

    CScript script_pub_key{bitplus::assets::BuildAssetCommitmentScript(commitment, inner_locking_script)};
    ValidateConstructedAssetScript(script_pub_key);
    return {.script_pub_key = std::move(script_pub_key), .locking_script = std::move(inner_locking_script)};
}

static bitplus::assets::AssetCommitment ParseTransferCommitment(
    const UniValue& asset_id,
    const UniValue& amount,
    const UniValue& metadata_hash,
    const UniValue& member_hash)
{
    bitplus::assets::AssetCommitment commitment{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = ParseHashV(asset_id, "asset_id"),
        .amount = ParseAssetAmount(amount),
        .metadata_hash = ParseHashV(metadata_hash, "metadata_hash"),
        .member_hash = ParseHashV(member_hash, "member_hash"),
    };
    ValidateConstructedAssetScript(bitplus::assets::BuildAssetCommitmentScript(commitment));
    return commitment;
}

static UniValue ContractLeafToJSON(const CScript& script)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("script", HexStr(script));
    result.pushKV("script_hash", (HashWriter{} << script).GetSHA256().ToString());
    return result;
}

static void PushAssetValidation(UniValue& result, const bitplus::assets::AssetValidationResult& validation)
{
    result.pushKV("valid", validation.valid);
    if (!validation.valid) result.pushKV("validation_error", validation.reason);
}

static std::string AssetCommitmentTypeToString(bitplus::assets::AssetCommitmentType type)
{
    switch (type) {
    case bitplus::assets::AssetCommitmentType::ISSUANCE:
        return "issuance";
    case bitplus::assets::AssetCommitmentType::TRANSFER:
        return "transfer";
    case bitplus::assets::AssetCommitmentType::BURN:
        return "burn";
    }
    return "unknown";
}

static UniValue DecodedAssetCommitmentToJSON(const bitplus::assets::AssetOutput& output)
{
    UniValue asset{UniValue::VOBJ};
    asset.pushKV("format", "BTPASSET");
    asset.pushKV("version", static_cast<int>(bitplus::assets::ASSET_COMMITMENT_VERSION));
    asset.pushKV("type", AssetCommitmentTypeToString(output.commitment.type));
    asset.pushKV("asset_id", output.commitment.asset_id.ToString());
    asset.pushKV("amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(output.commitment.amount))});
    asset.pushKV("metadata_hash", output.commitment.metadata_hash.ToString());
    asset.pushKV("member_hash", output.commitment.member_hash.ToString());
    asset.pushKV("commitment_hash", bitplus::assets::HashAssetCommitment(output.commitment).ToString());
    asset.pushKV("locking_script", HexStr(output.locking_script));
    return asset;
}

static UniValue DecodedMetadataCommitmentToJSON(const bitplus::assets::AssetMetadataOutput& output)
{
    UniValue metadata{UniValue::VOBJ};
    metadata.pushKV("format", "BTPMETA");
    metadata.pushKV("version", static_cast<int>(bitplus::assets::ASSET_METADATA_VERSION));
    metadata.pushKV("issuer_id", output.commitment.issuer_id.ToString());
    metadata.pushKV("document_hash", output.commitment.document_hash.ToString());
    metadata.pushKV("rules_hash", output.commitment.rules_hash.ToString());
    metadata.pushKV("commitment_hash", bitplus::assets::HashAssetMetadataCommitment(output.commitment).ToString());
    return metadata;
}

static UniValue DecodedWhitelistCommitmentToJSON(const bitplus::assets::AssetWhitelistOutput& output)
{
    UniValue whitelist{UniValue::VOBJ};
    whitelist.pushKV("format", "BTPWLST");
    whitelist.pushKV("version", static_cast<int>(bitplus::assets::ASSET_WHITELIST_VERSION));
    whitelist.pushKV("list_id", output.commitment.list_id.ToString());
    whitelist.pushKV("admin_key_hash", output.commitment.admin_key_hash.ToString());
    whitelist.pushKV("members_root", output.commitment.members_root.ToString());
    whitelist.pushKV("flags", static_cast<int64_t>(output.commitment.flags));
    whitelist.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistCommitment(output.commitment).ToString());
    return whitelist;
}

static UniValue DecodedWhitelistProofCommitmentToJSON(const bitplus::assets::AssetWhitelistProofOutput& output)
{
    UniValue proof{UniValue::VOBJ};
    proof.pushKV("format", "BTPWPROOF");
    proof.pushKV("version", static_cast<int>(bitplus::assets::ASSET_WHITELIST_PROOF_VERSION));
    proof.pushKV("asset_output_index", static_cast<int64_t>(output.commitment.asset_output_index));
    proof.pushKV("member_hash", output.commitment.member_hash.ToString());
    proof.pushKV("proof_index", static_cast<int64_t>(output.commitment.proof_index));
    UniValue path{UniValue::VARR};
    for (const uint256& sibling : output.commitment.merkle_path) {
        path.push_back(sibling.ToString());
    }
    proof.pushKV("merkle_path", std::move(path));
    proof.pushKV("members_root", bitplus::assets::ComputeWhitelistMembersRoot(output.commitment).ToString());
    proof.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(output.commitment).ToString());
    return proof;
}

static RPCMethod decodebitplusscript()
{
    return RPCMethod{
        "decodebitplusscript",
        "Decode and validate a Bitplus institutional commitment scriptPubKey.\n",
        {
            {"script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ScriptPubKey hex to decode."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "BTP amount carried by this output. Asset carriers must be zero."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Default{0}, "Output index used for validation reporting."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The scriptPubKey hex."},
            {RPCResult::Type::STR, "asm", "Script assembly."},
            {RPCResult::Type::BOOL, "recognized", "Whether this is a Bitplus institutional commitment."},
            {RPCResult::Type::STR, "bitplus_type", /*optional=*/true, "asset, metadata, whitelist, or whitelist_proof."},
            {RPCResult::Type::BOOL, "valid", /*optional=*/true, "Whether the Bitplus commitment is structurally valid."},
            {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
            {RPCResult::Type::OBJ_DYN, "commitment", /*optional=*/true, "Decoded Bitplus commitment fields.", {
                {RPCResult::Type::ANY, "field", "A decoded commitment field."},
            }},
        }},
        RPCExamples{HelpExampleCli("decodebitplusscript", "\"script_pub_key\" 0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CScript script_pub_key{ParseScriptHex(request.params[0], "script_pub_key")};
            const CAmount amount{request.params[1].isNull() ? 0 : AmountFromValue(request.params[1])};
            if (amount < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be non-negative");
            const uint32_t output_index{request.params[2].isNull() ? 0 : ParseOutputIndex(request.params[2], "output_index")};

            UniValue result{UniValue::VOBJ};
            result.pushKV("hex", HexStr(script_pub_key));
            result.pushKV("asm", ScriptToAsmStr(script_pub_key));

            const CTxOut output{amount, script_pub_key};
            if (const std::optional<bitplus::assets::AssetOutput> asset{bitplus::assets::DecodeAssetOutput(output, output_index)}) {
                result.pushKV("recognized", true);
                result.pushKV("bitplus_type", "asset");
                result.pushKV("commitment", DecodedAssetCommitmentToJSON(*asset));
                PushAssetValidation(result, bitplus::assets::ValidateAssetOutput(*asset));
                return result;
            }
            if (const std::optional<bitplus::assets::AssetMetadataOutput> metadata{bitplus::assets::DecodeAssetMetadataOutput(output, output_index)}) {
                result.pushKV("recognized", true);
                result.pushKV("bitplus_type", "metadata");
                result.pushKV("commitment", DecodedMetadataCommitmentToJSON(*metadata));
                PushAssetValidation(result, bitplus::assets::ValidateAssetMetadataOutput(*metadata));
                return result;
            }
            if (const std::optional<bitplus::assets::AssetWhitelistOutput> whitelist{bitplus::assets::DecodeAssetWhitelistOutput(output, output_index)}) {
                result.pushKV("recognized", true);
                result.pushKV("bitplus_type", "whitelist");
                result.pushKV("commitment", DecodedWhitelistCommitmentToJSON(*whitelist));
                PushAssetValidation(result, bitplus::assets::ValidateAssetWhitelistOutput(*whitelist));
                return result;
            }
            if (const std::optional<bitplus::assets::AssetWhitelistProofOutput> proof{bitplus::assets::DecodeAssetWhitelistProofOutput(output, output_index)}) {
                result.pushKV("recognized", true);
                result.pushKV("bitplus_type", "whitelist_proof");
                result.pushKV("commitment", DecodedWhitelistProofCommitmentToJSON(*proof));
                PushAssetValidation(result, bitplus::assets::ValidateAssetWhitelistProofOutput(*proof));
                return result;
            }

            result.pushKV("recognized", false);
            return result;
        },
    };
}

static void PushIssue(UniValue& issues, std::string_view reason)
{
    issues.push_back(std::string{reason});
}

static void PushOptionalValidationError(UniValue& object, const bitplus::assets::AssetValidationResult& validation)
{
    object.pushKV("valid", validation.valid);
    if (!validation.valid) object.pushKV("validation_error", validation.reason);
}

static UniValue AssetConservationToJSON(const bitplus::assets::AssetConservationResult& conservation)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("asset_id", conservation.asset_id.ToString());
    result.pushKV("spent", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(conservation.spent))});
    result.pushKV("issued", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(conservation.issued))});
    result.pushKV("transferred", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(conservation.transferred))});
    result.pushKV("burned", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(conservation.burned))});
    result.pushKV("balanced", conservation.balanced);
    result.pushKV("overflow", conservation.overflow);
    return result;
}

struct BitplusParticipantMovement
{
    uint64_t spent{0};
    uint64_t received{0};
    uint64_t burned{0};
    bool overflow{false};
};

static void AddMovementAmount(uint64_t& target, uint64_t amount, bool& overflow)
{
    const uint64_t previous{target};
    target += amount;
    if (target < previous) overflow = true;
}

static std::string SignedMovementString(uint64_t received, uint64_t spent)
{
    if (received >= spent) return strprintf("%llu", static_cast<unsigned long long>(received - spent));
    return strprintf("-%llu", static_cast<unsigned long long>(spent - received));
}

static uint256 BitplusReviewHash(
    const CTransaction& tx,
    const std::vector<bitplus::assets::AssetOutput>& spent_asset_outputs)
{
    static constexpr std::string_view REVIEW_DOMAIN{"BitplusReviewV1"};
    HashWriter writer{};
    writer << std::vector<unsigned char>{REVIEW_DOMAIN.begin(), REVIEW_DOMAIN.end()};
    writer << tx.GetHash();
    writer << static_cast<uint64_t>(spent_asset_outputs.size());
    for (const bitplus::assets::AssetOutput& output : spent_asset_outputs) {
        writer << output.output_index;
        writer << bitplus::assets::EncodeAssetCommitment(output.commitment);
        writer << output.locking_script;
    }
    return writer.GetSHA256();
}

static UniValue ParticipantMovementsToJSON(
    const std::vector<bitplus::assets::AssetOutput>& spent_asset_outputs,
    const std::vector<bitplus::assets::AssetOutput>& asset_outputs)
{
    std::map<std::string, std::map<std::string, BitplusParticipantMovement>> movements;

    for (const bitplus::assets::AssetOutput& output : spent_asset_outputs) {
        BitplusParticipantMovement& movement{
            movements[output.commitment.asset_id.ToString()][output.commitment.member_hash.ToString()]
        };
        AddMovementAmount(movement.spent, output.commitment.amount, movement.overflow);
    }

    for (const bitplus::assets::AssetOutput& output : asset_outputs) {
        BitplusParticipantMovement& movement{
            movements[output.commitment.asset_id.ToString()][output.commitment.member_hash.ToString()]
        };
        if (output.commitment.type == bitplus::assets::AssetCommitmentType::BURN) {
            AddMovementAmount(movement.burned, output.commitment.amount, movement.overflow);
        } else {
            AddMovementAmount(movement.received, output.commitment.amount, movement.overflow);
        }
    }

    UniValue result{UniValue::VARR};
    for (const auto& [asset_id, members] : movements) {
        for (const auto& [member_hash, movement] : members) {
            UniValue entry{UniValue::VOBJ};
            entry.pushKV("asset_id", asset_id);
            entry.pushKV("member_hash", member_hash);
            entry.pushKV("spent", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(movement.spent))});
            entry.pushKV("received", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(movement.received))});
            entry.pushKV("burned", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(movement.burned))});
            entry.pushKV("net", UniValue{UniValue::VNUM, SignedMovementString(movement.received, movement.spent)});
            entry.pushKV("overflow", movement.overflow);
            result.push_back(std::move(entry));
        }
    }
    return result;
}

static UniValue AnalyzeBitplusTransactionToJSON(
    const CTransaction& tx,
    std::vector<bitplus::assets::AssetOutput> spent_asset_outputs,
    bool conservation_checked,
    const std::optional<std::vector<uint32_t>>& missing_input_utxos = std::nullopt,
    std::string_view utxos_available_field = "input_utxos_available",
    std::string_view missing_utxos_field = "missing_input_utxos",
    std::string_view missing_utxos_issue = "input-utxo-missing")
{
    const std::vector<bitplus::assets::AssetOutput> asset_outputs{bitplus::assets::ExtractAssetOutputs(tx)};
    const std::vector<bitplus::assets::AssetMetadataOutput> metadata_outputs{bitplus::assets::ExtractAssetMetadataOutputs(tx)};
    const std::vector<bitplus::assets::AssetWhitelistOutput> whitelist_outputs{bitplus::assets::ExtractAssetWhitelistOutputs(tx)};
    const std::vector<bitplus::assets::AssetWhitelistProofOutput> proof_outputs{bitplus::assets::ExtractAssetWhitelistProofOutputs(tx)};

    UniValue issues{UniValue::VARR};
    if (missing_input_utxos.has_value() && !missing_input_utxos->empty()) PushIssue(issues, missing_utxos_issue);
    if (const auto invalid{bitplus::assets::FindFirstMalformedAssetCommitmentOutput(tx)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetOutput(asset_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetOutput(spent_asset_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetMetadataOutput(metadata_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetWhitelistOutput(whitelist_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetWhitelistProofOutput(proof_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstUnlinkedAssetMetadata(asset_outputs, metadata_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstInvalidAssetIssuanceAnchor(asset_outputs, tx)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstUnlinkedAssetWhitelist(metadata_outputs, whitelist_outputs)}) PushIssue(issues, invalid->reason);
    if (const auto invalid{bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, proof_outputs)}) PushIssue(issues, invalid->reason);
    const std::vector<bitplus::assets::AssetConservationResult> conservation{
        conservation_checked ? bitplus::assets::CheckAssetConservation(spent_asset_outputs, asset_outputs) : std::vector<bitplus::assets::AssetConservationResult>{}
    };
    for (const bitplus::assets::AssetConservationResult& result : conservation) {
        if (!result.balanced) {
            PushIssue(issues, "bad-txns-asset-conservation");
            break;
        }
    }

    UniValue assets{UniValue::VARR};
    for (const bitplus::assets::AssetOutput& output : asset_outputs) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("output_index", static_cast<int64_t>(output.output_index));
        PushOptionalValidationError(entry, bitplus::assets::ValidateAssetOutput(output));
        entry.pushKV("commitment", DecodedAssetCommitmentToJSON(output));
        assets.push_back(std::move(entry));
    }

    UniValue spent_assets{UniValue::VARR};
    for (const bitplus::assets::AssetOutput& output : spent_asset_outputs) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("input_index", static_cast<int64_t>(output.output_index));
        PushOptionalValidationError(entry, bitplus::assets::ValidateAssetOutput(output));
        entry.pushKV("commitment", DecodedAssetCommitmentToJSON(output));
        spent_assets.push_back(std::move(entry));
    }

    UniValue conservation_univ{UniValue::VARR};
    for (const bitplus::assets::AssetConservationResult& result : conservation) {
        conservation_univ.push_back(AssetConservationToJSON(result));
    }

    UniValue metadata{UniValue::VARR};
    for (const bitplus::assets::AssetMetadataOutput& output : metadata_outputs) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("output_index", static_cast<int64_t>(output.output_index));
        PushOptionalValidationError(entry, bitplus::assets::ValidateAssetMetadataOutput(output));
        entry.pushKV("commitment", DecodedMetadataCommitmentToJSON(output));
        metadata.push_back(std::move(entry));
    }

    UniValue whitelists{UniValue::VARR};
    for (const bitplus::assets::AssetWhitelistOutput& output : whitelist_outputs) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("output_index", static_cast<int64_t>(output.output_index));
        PushOptionalValidationError(entry, bitplus::assets::ValidateAssetWhitelistOutput(output));
        entry.pushKV("commitment", DecodedWhitelistCommitmentToJSON(output));
        whitelists.push_back(std::move(entry));
    }

    UniValue proofs{UniValue::VARR};
    for (const bitplus::assets::AssetWhitelistProofOutput& output : proof_outputs) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("output_index", static_cast<int64_t>(output.output_index));
        PushOptionalValidationError(entry, bitplus::assets::ValidateAssetWhitelistProofOutput(output));
        entry.pushKV("commitment", DecodedWhitelistProofCommitmentToJSON(output));
        proofs.push_back(std::move(entry));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", tx.GetHash().ToString());
    result.pushKV("output_count", static_cast<int64_t>(tx.vout.size()));
    result.pushKV("recognized_outputs", static_cast<int64_t>(asset_outputs.size() + metadata_outputs.size() + whitelist_outputs.size() + proof_outputs.size()));
    result.pushKV("bitplus_review_hash", BitplusReviewHash(tx, spent_asset_outputs).ToString());
    result.pushKV("bitplus_review_complete", conservation_checked && (!missing_input_utxos.has_value() || missing_input_utxos->empty()));
    result.pushKV("conservation_checked", conservation_checked);
    if (missing_input_utxos.has_value()) {
        result.pushKV(std::string{utxos_available_field}, missing_input_utxos->empty());
        UniValue missing{UniValue::VARR};
        for (const uint32_t input_index : *missing_input_utxos) {
            missing.push_back(static_cast<int64_t>(input_index));
        }
        result.pushKV(std::string{missing_utxos_field}, std::move(missing));
    }
    result.pushKV("valid", issues.empty());
    result.pushKV("issues", std::move(issues));
    result.pushKV("spent_asset_outputs", std::move(spent_assets));
    result.pushKV("asset_conservation", std::move(conservation_univ));
    result.pushKV("participant_movements", ParticipantMovementsToJSON(spent_asset_outputs, asset_outputs));
    result.pushKV("asset_outputs", std::move(assets));
    result.pushKV("metadata_outputs", std::move(metadata));
    result.pushKV("whitelist_outputs", std::move(whitelists));
    result.pushKV("whitelist_proof_outputs", std::move(proofs));
    return result;
}

static std::optional<bitplus::assets::AssetOutput> DecodeSpentAssetOutput(const CTxOut& output, uint32_t input_index)
{
    return bitplus::assets::DecodeAssetOutput(output, input_index);
}

struct BitplusSpentAssetLookup
{
    std::vector<bitplus::assets::AssetOutput> spent_asset_outputs;
    std::vector<uint32_t> missing_input_utxos;
    bool any_input_utxo_available{false};
};

struct BitplusInputConfirmation
{
    uint32_t input_index{0};
    bool available{false};
    bool from_mempool{false};
    int64_t height{-1};
    int64_t confirmations{0};
};

static std::vector<BitplusInputConfirmation> LookupInputConfirmationsFromNode(
    const CTransaction& tx,
    const JSONRPCRequest& request)
{
    CCoinsViewCache view{&CoinsViewEmpty::Get()};
    int64_t tip_height{-1};
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache& view_chain = chainman.ActiveChainstate().CoinsTip();
        tip_height = chainman.ActiveChain().Height();
        CCoinsViewMemPool view_mempool{&view_chain, mempool};
        view.SetBackend(view_mempool);
        for (const CTxIn& txin : tx.vin) {
            view.AccessCoin(txin.prevout);
        }
        view.SetBackend(CoinsViewEmpty::Get());
    }

    std::vector<BitplusInputConfirmation> confirmations;
    confirmations.reserve(tx.vin.size());
    for (uint32_t i{0}; i < tx.vin.size(); ++i) {
        BitplusInputConfirmation input;
        input.input_index = i;
        const Coin& coin{view.AccessCoin(tx.vin[i].prevout)};
        if (!coin.IsSpent()) {
            input.available = true;
            input.from_mempool = coin.nHeight == MEMPOOL_HEIGHT;
            if (!input.from_mempool) {
                input.height = coin.nHeight;
                input.confirmations = tip_height >= input.height ? tip_height - input.height + 1 : 0;
            }
        }
        confirmations.push_back(input);
    }
    return confirmations;
}

static UniValue InputConfirmationsToJSON(const std::vector<BitplusInputConfirmation>& confirmations)
{
    UniValue result{UniValue::VARR};
    for (const BitplusInputConfirmation& confirmation : confirmations) {
        UniValue input{UniValue::VOBJ};
        input.pushKV("input_index", static_cast<int64_t>(confirmation.input_index));
        input.pushKV("available", confirmation.available);
        if (confirmation.available) {
            input.pushKV("source", confirmation.from_mempool ? "mempool" : "chain");
            input.pushKV("confirmations", confirmation.confirmations);
            if (!confirmation.from_mempool) input.pushKV("height", confirmation.height);
        }
        result.push_back(std::move(input));
    }
    return result;
}

static UniValue InputsBelowMinConfirmationsToJSON(
    const std::vector<BitplusInputConfirmation>& confirmations,
    int64_t min_confirmations)
{
    UniValue result{UniValue::VARR};
    for (const BitplusInputConfirmation& confirmation : confirmations) {
        if (!confirmation.available || confirmation.confirmations >= min_confirmations) continue;
        UniValue input{UniValue::VOBJ};
        input.pushKV("input_index", static_cast<int64_t>(confirmation.input_index));
        input.pushKV("confirmations", confirmation.confirmations);
        input.pushKV("required_confirmations", min_confirmations);
        input.pushKV("source", confirmation.from_mempool ? "mempool" : "chain");
        result.push_back(std::move(input));
    }
    return result;
}

static UniValue InputConfirmationSummaryToJSON(
    const std::vector<BitplusInputConfirmation>& confirmations,
    int64_t min_confirmations)
{
    UniValue summary{UniValue::VOBJ};
    int64_t available{0};
    int64_t missing{0};
    int64_t confirmed{0};
    int64_t mempool{0};
    int64_t below_min{0};
    std::optional<int64_t> min_observed;

    for (const BitplusInputConfirmation& confirmation : confirmations) {
        if (!confirmation.available) {
            ++missing;
            continue;
        }
        ++available;
        if (confirmation.from_mempool) {
            ++mempool;
        } else {
            ++confirmed;
        }
        min_observed = min_observed.has_value() ? std::min(*min_observed, confirmation.confirmations) : confirmation.confirmations;
        if (confirmation.confirmations < min_confirmations) ++below_min;
    }

    summary.pushKV("total_inputs", static_cast<int64_t>(confirmations.size()));
    summary.pushKV("available_inputs", available);
    summary.pushKV("missing_inputs", missing);
    summary.pushKV("confirmed_inputs", confirmed);
    summary.pushKV("mempool_inputs", mempool);
    summary.pushKV("required_confirmations", min_confirmations);
    summary.pushKV("below_min_confirmations", below_min);
    if (min_observed.has_value()) {
        summary.pushKV("min_observed_confirmations", *min_observed);
    }
    return summary;
}

static BitplusSpentAssetLookup LookupSpentAssetOutputsFromNode(
    const CTransaction& tx,
    const JSONRPCRequest& request,
    const std::set<uint32_t>& supplied_input_indexes = {})
{
    BitplusSpentAssetLookup lookup;
    CCoinsViewCache view{&CoinsViewEmpty::Get()};
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache& view_chain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool view_mempool{&view_chain, mempool};
        view.SetBackend(view_mempool);
        for (uint32_t i{0}; i < tx.vin.size(); ++i) {
            if (!supplied_input_indexes.contains(i)) view.AccessCoin(tx.vin[i].prevout);
        }
        view.SetBackend(CoinsViewEmpty::Get());
    }

    for (uint32_t i{0}; i < tx.vin.size(); ++i) {
        if (supplied_input_indexes.contains(i)) continue;
        const Coin& coin{view.AccessCoin(tx.vin[i].prevout)};
        if (coin.IsSpent()) {
            lookup.missing_input_utxos.push_back(i);
            continue;
        }
        lookup.any_input_utxo_available = true;
        const std::optional<bitplus::assets::AssetOutput> output{DecodeSpentAssetOutput(coin.out, i)};
        if (output.has_value()) lookup.spent_asset_outputs.push_back(*output);
    }
    return lookup;
}

static UniValue AnalyzeBitplusPSBTToJSON(const PartiallySignedTransaction& psbtx)
{
    std::vector<bitplus::assets::AssetOutput> spent_asset_outputs;
    std::vector<uint32_t> missing_utxos;
    for (uint32_t i{0}; i < psbtx.tx->vin.size(); ++i) {
        CTxOut txout;
        if (!psbtx.GetInputUTXO(txout, i)) {
            missing_utxos.push_back(i);
            continue;
        }
        const std::optional<bitplus::assets::AssetOutput> output{DecodeSpentAssetOutput(txout, i)};
        if (output.has_value()) spent_asset_outputs.push_back(*output);
    }

    return AnalyzeBitplusTransactionToJSON(
        CTransaction{*psbtx.tx},
        std::move(spent_asset_outputs),
        missing_utxos.size() < psbtx.tx->vin.size(),
        missing_utxos,
        "psbt_utxos_available",
        "missing_psbt_utxos",
        "psbt-input-utxo-missing");
}

static RPCMethod analyzebitplustransaction()
{
    return RPCMethod{
        "analyzebitplustransaction",
        "Analyze Bitplus institutional commitments in a raw transaction before signing or broadcast.\n"
        "This checks output structure and same-transaction metadata, whitelist, issuance-anchor, and proof linkage.\n"
        "If spent outputs are supplied, it also checks asset conservation against those prevouts.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction hex."},
            {"spent_outputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional previous outputs spent by this transaction for conservation preflight.", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index spending this previous output."},
                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Previous output scriptPubKey hex."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Previous output BTP amount."},
                }},
            }},
            {"lookup_spent_outputs", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, fill missing spent outputs from the node UTXO set and mempool."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            {RPCResult::Type::NUM, "output_count", "Number of outputs in the transaction."},
            {RPCResult::Type::NUM, "recognized_outputs", "Number of Bitplus institutional commitment outputs."},
            {RPCResult::Type::STR_HEX, "bitplus_review_hash", "Deterministic review hash committing to the transaction and spent asset context used by this analysis."},
            {RPCResult::Type::BOOL, "bitplus_review_complete", "Whether this analysis had enough spent-output context for a complete asset-conservation review."},
            {RPCResult::Type::BOOL, "conservation_checked", "Whether spent outputs were supplied and asset conservation was checked."},
            {RPCResult::Type::BOOL, "input_utxos_available", /*optional=*/true, "Whether all inputs had supplied, UTXO-set, or mempool previous outputs when lookup was requested."},
            {RPCResult::Type::ARR, "missing_input_utxos", /*optional=*/true, "Input indexes whose previous outputs could not be found when lookup was requested.", {
                {RPCResult::Type::NUM, "input_index", "Missing input index."},
            }},
            {RPCResult::Type::BOOL, "valid", "Whether all analyzable Bitplus output and same-transaction linkage checks passed."},
            {RPCResult::Type::ARR, "issues", "Detected validation or linkage issues.", {
                {RPCResult::Type::STR, "issue", "A validation issue."},
            }},
            {RPCResult::Type::ARR, "spent_asset_outputs", "Decoded spent BTPASSET prevouts supplied for preflight.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "input_index", "Transaction input index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this spent asset output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "asset_conservation", "Per-asset conservation results when spent outputs are supplied.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "asset_id", "Asset id."},
                    {RPCResult::Type::NUM, "spent", "Spent transfer amount."},
                    {RPCResult::Type::NUM, "issued", "Issued amount."},
                    {RPCResult::Type::NUM, "transferred", "Created transfer amount."},
                    {RPCResult::Type::NUM, "burned", "Burned amount."},
                    {RPCResult::Type::BOOL, "balanced", "Whether conservation balances for this asset."},
                    {RPCResult::Type::BOOL, "overflow", "Whether amount arithmetic overflowed."},
                }},
            }},
            {RPCResult::Type::ARR, "participant_movements", "Per-asset participant movement totals from spent and created asset outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "asset_id", "Asset id."},
                    {RPCResult::Type::STR_HEX, "member_hash", "Participant/member hash."},
                    {RPCResult::Type::NUM, "spent", "Asset units spent from this member's inputs."},
                    {RPCResult::Type::NUM, "received", "Live asset units created for this member."},
                    {RPCResult::Type::NUM, "burned", "Burn asset units attributed to this member."},
                    {RPCResult::Type::NUM, "net", "Live balance delta, received minus spent."},
                    {RPCResult::Type::BOOL, "overflow", "Whether amount arithmetic overflowed."},
                }},
            }},
            {RPCResult::Type::ARR, "asset_outputs", "Decoded BTPASSET carrier outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "metadata_outputs", "Decoded BTPMETA outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_outputs", "Decoded BTPWLST outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_proof_outputs", "Decoded BTPWPROOF outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("analyzebitplustransaction", "\"rawtxhex\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            const CTransaction tx{std::move(mtx)};
            std::vector<bitplus::assets::AssetOutput> spent_asset_outputs;
            const bool spent_outputs_supplied{!request.params[1].isNull() && !request.params[1].get_array().empty()};
            const bool lookup_spent_outputs{!request.params[2].isNull() && request.params[2].get_bool()};
            bool conservation_checked{spent_outputs_supplied};
            std::set<uint32_t> checked_input_indexes;

            if (spent_outputs_supplied) {
                for (const UniValue& prevout_univ : request.params[1].get_array().getValues()) {
                    const UniValue& prevout{prevout_univ.get_obj()};
                    const uint32_t input_index{ParseOutputIndex(prevout.find_value("input_index"), "input_index")};
                    if (input_index >= tx.vin.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "input_index out of range");
                    }
                    if (!checked_input_indexes.insert(input_index).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate input_index");
                    }
                    const CAmount amount{AmountFromValue(prevout.find_value("amount"))};
                    if (amount < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be non-negative");
                    const CScript script_pub_key{ParseScriptHex(prevout.find_value("scriptPubKey"), "scriptPubKey")};
                    const std::optional<bitplus::assets::AssetOutput> output{DecodeSpentAssetOutput(CTxOut{amount, script_pub_key}, input_index)};
                    if (output.has_value()) spent_asset_outputs.push_back(*output);
                }
            }

            std::optional<std::vector<uint32_t>> missing_input_utxos;
            if (lookup_spent_outputs) {
                BitplusSpentAssetLookup lookup{LookupSpentAssetOutputsFromNode(tx, request, checked_input_indexes)};
                missing_input_utxos = std::move(lookup.missing_input_utxos);
                conservation_checked = conservation_checked || lookup.any_input_utxo_available;
                spent_asset_outputs.insert(
                    spent_asset_outputs.end(),
                    std::make_move_iterator(lookup.spent_asset_outputs.begin()),
                    std::make_move_iterator(lookup.spent_asset_outputs.end()));
            }

            return AnalyzeBitplusTransactionToJSON(tx, std::move(spent_asset_outputs), conservation_checked, missing_input_utxos);
        },
    };
}

static RPCMethod analyzebitpluspsbt()
{
    return RPCMethod{
        "analyzebitpluspsbt",
        "Analyze Bitplus institutional commitments in a PSBT before signing or broadcast.\n"
        "This uses PSBT input UTXOs when present to preflight asset conservation.\n",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "The unsigned transaction id."},
            {RPCResult::Type::NUM, "output_count", "Number of outputs in the unsigned transaction."},
            {RPCResult::Type::NUM, "recognized_outputs", "Number of Bitplus institutional commitment outputs."},
            {RPCResult::Type::STR_HEX, "bitplus_review_hash", "Deterministic review hash committing to the unsigned transaction and PSBT spent asset context used by this analysis."},
            {RPCResult::Type::BOOL, "bitplus_review_complete", "Whether this PSBT carried enough input UTXO context for a complete asset-conservation review."},
            {RPCResult::Type::BOOL, "conservation_checked", "Whether at least one PSBT input UTXO was available for conservation preflight."},
            {RPCResult::Type::BOOL, "psbt_utxos_available", "Whether all PSBT inputs include a witness_utxo or non_witness_utxo."},
            {RPCResult::Type::ARR, "missing_psbt_utxos", "Input indexes without PSBT UTXO data.", {
                {RPCResult::Type::NUM, "input_index", "Missing input index."},
            }},
            {RPCResult::Type::BOOL, "valid", "Whether all analyzable Bitplus checks passed."},
            {RPCResult::Type::ARR, "issues", "Detected validation or linkage issues.", {
                {RPCResult::Type::STR, "issue", "A validation issue."},
            }},
            {RPCResult::Type::ARR, "spent_asset_outputs", "Decoded spent BTPASSET UTXOs found in the PSBT.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "input_index", "Transaction input index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this spent asset output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "asset_conservation", "Per-asset conservation results when PSBT input UTXOs are available.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "asset_id", "Asset id."},
                    {RPCResult::Type::NUM, "spent", "Spent transfer amount."},
                    {RPCResult::Type::NUM, "issued", "Issued amount."},
                    {RPCResult::Type::NUM, "transferred", "Created transfer amount."},
                    {RPCResult::Type::NUM, "burned", "Burned amount."},
                    {RPCResult::Type::BOOL, "balanced", "Whether conservation balances for this asset."},
                    {RPCResult::Type::BOOL, "overflow", "Whether amount arithmetic overflowed."},
                }},
            }},
            {RPCResult::Type::ARR, "participant_movements", "Per-asset participant movement totals from spent and created asset outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "asset_id", "Asset id."},
                    {RPCResult::Type::STR_HEX, "member_hash", "Participant/member hash."},
                    {RPCResult::Type::NUM, "spent", "Asset units spent from this member's inputs."},
                    {RPCResult::Type::NUM, "received", "Live asset units created for this member."},
                    {RPCResult::Type::NUM, "burned", "Burn asset units attributed to this member."},
                    {RPCResult::Type::NUM, "net", "Live balance delta, received minus spent."},
                    {RPCResult::Type::BOOL, "overflow", "Whether amount arithmetic overflowed."},
                }},
            }},
            {RPCResult::Type::ARR, "asset_outputs", "Decoded BTPASSET carrier outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "A decoded output field."},
                }},
            }},
            {RPCResult::Type::ARR, "metadata_outputs", "Decoded BTPMETA outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "A decoded output field."},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_outputs", "Decoded BTPWLST outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "A decoded output field."},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_proof_outputs", "Decoded BTPWPROOF outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "A decoded output field."},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("analyzebitpluspsbt", "\"psbt\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            PartiallySignedTransaction psbtx;
            std::string error;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }

            return AnalyzeBitplusPSBTToJSON(psbtx);
        },
    };
}

static CAmount ParseNonNegativeBtpAmount(const UniValue& value, std::string_view name)
{
    const CAmount amount{AmountFromValue(value)};
    if (amount < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{name} + " must be non-negative");
    return amount;
}

static void AddBitplusScriptOutputs(CMutableTransaction& raw_tx, const UniValue& outputs_in)
{
    const UniValue& outputs{outputs_in.get_array()};
    if (outputs.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs must not be empty");

    for (uint32_t i{0}; i < outputs.size(); ++i) {
        const UniValue& output{outputs[i].get_obj()};
        const UniValue& index_value{output.find_value("index")};
        if (!index_value.isNull()) {
            const uint32_t expected_index{ParseOutputIndex(index_value, "index")};
            if (expected_index != i) throw JSONRPCError(RPC_INVALID_PARAMETER, "output index mismatch");
        }

        const UniValue& script_value{output.find_value("scriptPubKey")};
        if (script_value.isStr() && script_value.get_str().empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey must not be empty");
        }
        const CScript script_pub_key{ParseScriptHex(script_value, "scriptPubKey")};
        if (script_pub_key.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey must not be empty");
        if (script_pub_key.size() > MAX_SCRIPT_SIZE) throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey too large");
        if (!script_pub_key.HasValidOps()) throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey has invalid opcodes");

        raw_tx.vout.emplace_back(
            ParseNonNegativeBtpAmount(output.find_value("amount"), "amount"),
            script_pub_key);
    }
}

static CMutableTransaction BuildBitplusScriptTransaction(const RPCMethod& self, const JSONRPCRequest& request)
{
    CMutableTransaction raw_tx;

    if (!request.params[2].isNull()) {
        const int64_t locktime{request.params[2].getInt<int64_t>()};
        if (locktime < 0 || locktime > LOCKTIME_MAX) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        }
        raw_tx.nLockTime = locktime;
    }

    const uint32_t version{self.Arg<uint32_t>("version")};
    if (version < TX_MIN_STANDARD_VERSION || version > TX_MAX_STANDARD_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, version out of range(%d~%d)", TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION));
    }
    raw_tx.version = version;

    const bool rbf{request.params[3].isNull() ? true : request.params[3].get_bool()};
    AddInputs(raw_tx, request.params[0], std::optional<bool>{rbf});
    AddBitplusScriptOutputs(raw_tx, request.params[1]);

    if (rbf && raw_tx.vin.size() > 0 && !SignalsOptInRBF(CTransaction(raw_tx))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }

    return raw_tx;
}

static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitplus-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitplus-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(*pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            }
            else
                entry.pushKV("confirmations", 0);
        }
    }
}

static std::vector<RPCArg> CreateTxDoc()
{
    return {
        {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
            {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                    },
                },
            },
        },
        {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                "At least one output of either type must be specified.\n"
                "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                "                             accepted as second parameter.",
            {
                {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                    {
                        {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the bitplus address, the value (float or string) is the amount in " + CURRENCY_UNIT},
                    },
                },
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data that becomes a part of an OP_RETURN output"},
                    },
                },
            },
         RPCArgOptions{.skip_type_check = true}},
        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
        {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable.\n"
                "Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible."},
        {"version", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_RAWTX_VERSION}, "Transaction version"},
    };
}

// Update PSBT with information from the mempool, the UTXO set, the txindex, and the provided descriptors.
// Optionally, sign the inputs that we can using information from the descriptors.
PartiallySignedTransaction ProcessPSBT(const std::string& psbt_string, const std::any& context, const HidingSigningProvider& provider, std::optional<int> sighash_type, bool finalize)
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, psbt_string, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();
    const NodeContext& node = EnsureAnyNodeContext(context);

    // If we can't find the corresponding full transaction for all of our inputs,
    // this will be used to find just the utxos for the segwit inputs for which
    // the full transaction isn't found
    std::map<COutPoint, Coin> coins;

    // Fetch previous transactions:
    // First, look in the txindex and the mempool
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& psbt_input = psbtx.inputs.at(i);
        const CTxIn& tx_in = psbtx.tx->vin.at(i);

        // The `non_witness_utxo` is the whole previous transaction
        if (psbt_input.non_witness_utxo) continue;

        CTransactionRef tx;

        // Look in the txindex
        if (g_txindex) {
            uint256 block_hash;
            g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx);
        }
        // If we still don't have it look in the mempool
        if (!tx) {
            tx = node.mempool->get(tx_in.prevout.hash);
        }
        if (tx) {
            psbt_input.non_witness_utxo = tx;
        } else {
            coins[tx_in.prevout]; // Create empty map entry keyed by prevout
        }
    }

    // If we still haven't found all of the inputs, look for the missing ones in the utxo set
    if (!coins.empty()) {
        FindCoins(node, coins);
        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs.at(i);

            // If there are still missing utxos, add them if they were found in the utxo set
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

        // Update script/keypath information using descriptor data.
        // Note that SignPSBTInput does a lot more than just constructing ECDSA signatures.
        // We only actually care about those if our signing provider doesn't hide private
        // information, as is the case with `descriptorprocesspsbt`
        // Only error for mismatching sighash types as it is critical that the sighash to sign with matches the PSBT's
        if (SignPSBTInput(provider, psbtx, /*index=*/i, &txdata, {.sighash_type = sighash_type, .finalize = finalize}, /*out_sigdata=*/nullptr) == common::PSBTError::SIGHASH_MISMATCH) {
            throw JSONRPCPSBTError(common::PSBTError::SIGHASH_MISMATCH);
        }
    }

    // Update script/keypath information using descriptor data.
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        UpdatePSBTOutput(provider, psbtx, i);
    }

    RemoveUnnecessaryTransactions(psbtx);

    return psbtx;
}

static RPCMethod getrawtransaction()
{
    return RPCMethod{
                "getrawtransaction",

                "By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled\n"
                "and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.\n"
                "If a blockhash argument is passed, it will return the transaction if\n"
                "the specified block is available and the transaction is in that block.\n\n"
                "Hint: Use gettransaction for wallet transactions.\n\n"

                "If verbosity is 0 or omitted, returns the serialized transaction as a hex-encoded string.\n"
                "If verbosity is 1, returns a JSON Object with information about the transaction.\n"
                "If verbosity is 2, returns a JSON Object with information about the transaction, including fee and prevout information.",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for hex-encoded data, 1 for a JSON object, and 2 for JSON object with fee and prevout",
                     RPCArgOptions{.skip_type_check = true}},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The block in which to look for the transaction"},
                },
                {
                    RPCResult{"if verbosity is not set or set to 0",
                         RPCResult::Type::STR, "data", "The serialized transaction as a hex-encoded string for 'txid'"
                     },
                     RPCResult{"if verbosity is set to 1",
                         RPCResult::Type::OBJ, "", "",
                         Cat<std::vector<RPCResult>>(
                         {
                             {RPCResult::Type::BOOL, "in_active_chain", /*optional=*/true, "Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)"},
                             {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "the block hash"},
                             {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The confirmations"},
                             {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME},
                             {RPCResult::Type::NUM, "time", /*optional=*/true, "Same as \"blocktime\""},
                             {RPCResult::Type::STR_HEX, "hex", "The serialized, hex-encoded data for 'txid'"},
                         },
                         TxDoc({.txid_field_doc="The transaction id (same as provided)"})),
                    },
                    RPCResult{"for verbosity = 2",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "utxo being spent",
                                {
                                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                                    {RPCResult::Type::OBJ, "prevout", /*optional=*/true, "The previous output, omitted if block undo data is not available",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                    }},
                                }},
                            }},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 0 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 2 \"myblockhash\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    auto txid{Txid::FromUint256(ParseHashV(request.params[0], "parameter 1"))};
    const CBlockIndex* blockindex = nullptr;

    if (txid.ToUint256() == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
        // Special exception for the genesis block coinbase transaction
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
    }

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/0, /*allow_bool=*/true)};

    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), txid, chainman.m_blockman, hash_block);
    if (!tx) {
        std::string errmsg;
        if (blockindex) {
            const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
            if (!block_has_data) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }

    if (verbosity <= 0) {
        return EncodeHexTx(*tx);
    }

    UniValue result(UniValue::VOBJ);
    if (blockindex) {
        LOCK(cs_main);
        result.pushKV("in_active_chain", chainman.ActiveChain().Contains(*blockindex));
    }
    // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
    if (request.params[2].isNull()) {
        LOCK(cs_main);
        blockindex = chainman.m_blockman.LookupBlockIndex(hash_block); // May be nullptr for mempool transactions
    }
    if (verbosity == 1) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CBlockUndo blockUndo;
    CBlock block;

    if (tx->IsCoinBase() || !blockindex || WITH_LOCK(::cs_main, return !(blockindex->nStatus & BLOCK_HAVE_MASK))) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }
    if (!chainman.m_blockman.ReadBlockUndo(blockUndo, *blockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
    }
    if (!chainman.m_blockman.ReadBlock(block, *blockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }
    TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    return result;
},
    };
}

static RPCMethod createrawtransaction()
{
    return RPCMethod{
        "createrawtransaction",
        "Create a transaction spending the given inputs and creating new outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"
                },
                RPCExamples{
                    HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf, self.Arg<uint32_t>("version"));

    return EncodeHexTx(CTransaction(rawTx));
},
    };
}

static RPCMethod decoderawtransaction()
{
    return RPCMethod{"decoderawtransaction",
                "Return a JSON object representing the serialized, hex-encoded transaction.",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    TxDoc(),
                },
                RPCExamples{
                    HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;

    bool try_witness = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool try_no_witness = request.params[1].isNull() ? true : !request.params[1].get_bool();

    if (!DecodeHexTx(mtx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VOBJ);
    TxToUniv(CTransaction(std::move(mtx)), /*block_hash=*/uint256(), /*entry=*/result, /*include_hex=*/false);

    return result;
},
    };
}

static RPCMethod decodescript()
{
    return RPCMethod{
        "decodescript",
        "Decode a hex-encoded script.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded script"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the script"},
                {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                {RPCResult::Type::STR, "type", "The output type (e.g. " + GetAllOutputTypes() + ")"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitplus address (only if a well-defined address exists)"},
                {RPCResult::Type::STR, "p2sh", /*optional=*/true,
                 "address of P2SH script wrapping this redeem script (not returned for types that should not be wrapped)"},
                {RPCResult::Type::OBJ, "segwit", /*optional=*/true,
                 "Result of a witness output script wrapping this redeem script (not returned for types that should not be wrapped)",
                 {
                     {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                     {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                     {RPCResult::Type::STR, "type", "The type of the output script (e.g. witness_v0_keyhash or witness_v0_scripthash)"},
                     {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitplus address (only if a well-defined address exists)"},
                     {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                     {RPCResult::Type::STR, "p2sh-segwit", "address of the P2SH script wrapping this witness redeem script"},
                 }},
            },
        },
        RPCExamples{
            HelpExampleCli("decodescript", "\"hexstring\"")
          + HelpExampleRpc("decodescript", "\"hexstring\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptToUniv(script, /*out=*/r, /*include_hex=*/false, /*include_address=*/true);

    std::vector<std::vector<unsigned char>> solutions_data;
    const TxoutType which_type{Solver(script, solutions_data)};

    const bool can_wrap{[&] {
        switch (which_type) {
        case TxoutType::MULTISIG:
        case TxoutType::NONSTANDARD:
        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            // Can be wrapped if the checks below pass
            break;
        case TxoutType::NULL_DATA:
        case TxoutType::SCRIPTHASH:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
        case TxoutType::ANCHOR:
            // Should not be wrapped
            return false;
        } // no default case, so the compiler can warn about missing cases
        if (!script.HasValidOps() || script.IsUnspendable()) {
            return false;
        }
        for (CScript::const_iterator it{script.begin()}; it != script.end();) {
            opcodetype op;
            CHECK_NONFATAL(script.GetOp(it, op));
            if (op == OP_CHECKSIGADD || IsOpSuccess(op)) {
                return false;
            }
        }
        return true;
    }()};

    if (can_wrap) {
        r.pushKV("p2sh", EncodeDestination(ScriptHash(script)));
        // P2SH and witness programs cannot be wrapped in P2WSH, if this script
        // is a witness program, don't return addresses for a segwit programs.
        const bool can_wrap_P2WSH{[&] {
            switch (which_type) {
            case TxoutType::MULTISIG:
            case TxoutType::PUBKEY:
            // Uncompressed pubkeys cannot be used with segwit checksigs.
            // If the script contains an uncompressed pubkey, skip encoding of a segwit program.
                for (const auto& solution : solutions_data) {
                    if ((solution.size() != 1) && !CPubKey(solution).IsCompressed()) {
                        return false;
                    }
                }
                return true;
            case TxoutType::NONSTANDARD:
            case TxoutType::PUBKEYHASH:
                // Can be P2WSH wrapped
                return true;
            case TxoutType::NULL_DATA:
            case TxoutType::SCRIPTHASH:
            case TxoutType::WITNESS_UNKNOWN:
            case TxoutType::WITNESS_V0_KEYHASH:
            case TxoutType::WITNESS_V0_SCRIPTHASH:
            case TxoutType::WITNESS_V1_TAPROOT:
            case TxoutType::ANCHOR:
                // Should not be wrapped
                return false;
            } // no default case, so the compiler can warn about missing cases
            NONFATAL_UNREACHABLE();
        }()};
        if (can_wrap_P2WSH) {
            UniValue sr(UniValue::VOBJ);
            CScript segwitScr;
            FlatSigningProvider provider;
            if (which_type == TxoutType::PUBKEY) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(Hash160(solutions_data[0])));
            } else if (which_type == TxoutType::PUBKEYHASH) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(uint160{solutions_data[0]}));
            } else {
                // Scripts that are not fit for P2WPKH are encoded as P2WSH.
                provider.scripts[CScriptID(script)] = script;
                segwitScr = GetScriptForDestination(WitnessV0ScriptHash(script));
            }
            ScriptToUniv(segwitScr, /*out=*/sr, /*include_hex=*/true, /*include_address=*/true, /*provider=*/&provider);
            sr.pushKV("p2sh-segwit", EncodeDestination(ScriptHash(segwitScr)));
            r.pushKV("segwit", std::move(sr));
        }
    }

    return r;
},
    };
}

static RPCMethod combinerawtransaction()
{
    return RPCMethod{
        "combinerawtransaction",
        "Combine multiple partially signed transactions into one transaction.\n"
                "The combined transaction may be another partially signed transaction or a \n"
                "fully signed transaction.",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The hex strings of partially signed transactions",
                        {
                            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded raw transaction"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The hex-encoded raw transaction with signature(s)"
                },
                RPCExamples{
                    HelpExampleCli("combinerawtransaction", R"('["myhex1", "myhex2", "myhex3"]')")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{

    UniValue txs = request.params[0].get_array();
    std::vector<CMutableTransaction> txVariants(txs.size());

    for (unsigned int idx = 0; idx < txs.size(); idx++) {
        if (!DecodeHexTx(txVariants[idx], txs[idx].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx));
        }
    }

    if (txVariants.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transactions");
    }

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsViewCache view{&CoinsViewEmpty::Get()};
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(CoinsViewEmpty::Get()); // switch back to avoid locking mempool for too long
    }

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Input not found or already spent");
        }
        SignatureData sigdata;

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            if (txv.vin.size() > i) {
                sigdata.MergeSignatureData(DataFromTransaction(txv, i, coin.out));
            }
        }
        ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(mergedTx, i, coin.out.nValue, {.sighash_type = SIGHASH_ALL}), coin.out.scriptPubKey, sigdata);

        UpdateInput(txin, sigdata);
    }

    return EncodeHexTx(CTransaction(mergedTx));
},
    };
}

static RPCMethod signrawtransactionwithkey()
{
    return RPCMethod{
        "signrawtransactionwithkey",
        "Sign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second argument is an array of base58-encoded private\n"
                "keys that will be the only keys used to sign the transaction.\n"
                "The third optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base58-encoded private keys for signing",
                        {
                            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "private key in base58-encoding"},
                        },
                        },
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "output script"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                                },
                                },
                        },
                        },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of:\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithkey", "\"myhex\" \"[\\\"key1\\\",\\\"key2\\\"]\"")
            + HelpExampleRpc("signrawtransactionwithkey", "\"myhex\", \"[\\\"key1\\\",\\\"key2\\\"]\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    FlatSigningProvider keystore;
    const UniValue& keys = request.params[1].get_array();
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        UniValue k = keys[idx];
        CKey key = DecodeSecret(k.get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        CPubKey pubkey = key.GetPubKey();
        CKeyID key_id = pubkey.GetID();
        keystore.pubkeys.emplace(key_id, pubkey);
        keystore.keys.emplace(key_id, key);
    }

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    FindCoins(node, coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[2], &keystore, coins);

    UniValue result(UniValue::VOBJ);
    SignTransaction(mtx, &keystore, coins, request.params[3], result);
    return result;
},
    };
}

const RPCResult& DecodePSBTInputs()
{
    static const RPCResult decodepsbt_inputs{
        RPCResult::Type::ARR, "inputs", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "non_witness_utxo", /*optional=*/true, "Decoded network transaction for non-witness UTXOs",
                    TxDoc({.elision_description="The layout is the same as the output of decoderawtransaction."})
                },
                {RPCResult::Type::OBJ, "witness_utxo", /*optional=*/true, "Transaction output for witness UTXOs",
                {
                    {RPCResult::Type::NUM, "amount", "The value in " + CURRENCY_UNIT},
                    {RPCResult::Type::OBJ, "scriptPubKey", "",
                    {
                        {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                        {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                        {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                        {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                        {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitplus address (only if a well-defined address exists)"},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "partial_signatures", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key and signature that corresponds to it."},
                }},
                {RPCResult::Type::STR, "sighash", /*optional=*/true, "The sighash type to be used"},
                {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                }},
                {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                }},
                {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pubkey", "The public key with the derivation path as the value."},
                        {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                        {RPCResult::Type::STR, "path", "The path"},
                    }},
                }},
                {RPCResult::Type::OBJ, "final_scriptSig", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the final signature script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw final signature script bytes, hex-encoded"},
                }},
                {RPCResult::Type::ARR, "final_scriptwitness", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR_HEX, "", "hex-encoded witness data (if any)"},
                }},
                {RPCResult::Type::OBJ_DYN, "ripemd160_preimages", /*optional=*/ true, "",
                {
                    {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
                }},
                {RPCResult::Type::OBJ_DYN, "sha256_preimages", /*optional=*/ true, "",
                {
                    {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
                }},
                {RPCResult::Type::OBJ_DYN, "hash160_preimages", /*optional=*/ true, "",
                {
                    {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
                }},
                {RPCResult::Type::OBJ_DYN, "hash256_preimages", /*optional=*/ true, "",
                {
                    {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
                }},
                {RPCResult::Type::STR_HEX, "taproot_key_path_sig", /*optional=*/ true, "hex-encoded signature for the Taproot key path spend"},
                {RPCResult::Type::ARR, "taproot_script_path_sigs", /*optional=*/ true, "",
                {
                    {RPCResult::Type::OBJ, "signature", /*optional=*/ true, "The signature for the pubkey and leaf hash combination",
                    {
                        {RPCResult::Type::STR, "pubkey", "The x-only pubkey for this signature"},
                        {RPCResult::Type::STR, "leaf_hash", "The leaf hash for this signature"},
                        {RPCResult::Type::STR, "sig", "The signature itself"},
                    }},
                }},
                {RPCResult::Type::ARR, "taproot_scripts", /*optional=*/ true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "script", "A leaf script"},
                        {RPCResult::Type::NUM, "leaf_ver", "The version number for the leaf script"},
                        {RPCResult::Type::ARR, "control_blocks", "The control blocks for this script",
                        {
                            {RPCResult::Type::STR_HEX, "control_block", "A hex-encoded control block for this script"},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                        {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                        {RPCResult::Type::STR, "path", "The path"},
                        {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                        }},
                    }},
                }},
                {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
                {RPCResult::Type::STR_HEX, "taproot_merkle_root", /*optional=*/ true, "The hex-encoded Taproot merkle root"},
                {RPCResult::Type::ARR, "musig2_participant_pubkeys", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which the participants create."},
                        {RPCResult::Type::ARR, "participant_pubkeys", "",
                        {
                            {RPCResult::Type::STR_HEX, "pubkey", "The compressed public keys that are aggregated for aggregate_pubkey."},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "musig2_pubnonces", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "participant_pubkey", "The compressed public key of the participant that created this pubnonce."},
                        {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which this pubnonce is for."},
                        {RPCResult::Type::STR_HEX, "leaf_hash", /*optional=*/true, "The hash of the leaf script that contains the aggregate pubkey being signed for. Omitted when signing for the internal key."},
                        {RPCResult::Type::STR_HEX, "pubnonce", "The public nonce itself."},
                    }},
                }},
                {RPCResult::Type::ARR, "musig2_partial_sigs", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "participant_pubkey", "The compressed public key of the participant that created this partial signature."},
                        {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which this partial signature is for."},
                        {RPCResult::Type::STR_HEX, "leaf_hash", /*optional=*/true, "The hash of the leaf script that contains the aggregate pubkey being signed for. Omitted when signing for the internal key."},
                        {RPCResult::Type::STR_HEX, "partial_sig", "The partial signature itself."},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/ true, "The unknown input fields",
                {
                    {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                }},
                {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The input proprietary map",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                        {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                        {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                        {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                    }},
                }},
            }},
        }
    };
    return decodepsbt_inputs;
}

const RPCResult& DecodePSBTOutputs()
{
    static const RPCResult decodepsbt_outputs{
        RPCResult::Type::ARR, "outputs", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                }},
                {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                }},
                {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pubkey", "The public key this path corresponds to"},
                        {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                        {RPCResult::Type::STR, "path", "The path"},
                    }},
                }},
                {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
                {RPCResult::Type::ARR, "taproot_tree", /*optional=*/ true, "The tuples that make up the Taproot tree, in depth first search order",
                {
                    {RPCResult::Type::OBJ, "tuple", /*optional=*/ true, "A single leaf script in the taproot tree",
                    {
                        {RPCResult::Type::NUM, "depth", "The depth of this element in the tree"},
                        {RPCResult::Type::NUM, "leaf_ver", "The version of this leaf"},
                        {RPCResult::Type::STR, "script", "The hex-encoded script itself"},
                    }},
                }},
                {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                        {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                        {RPCResult::Type::STR, "path", "The path"},
                        {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "musig2_participant_pubkeys", /*optional=*/true, "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which the participants create."},
                        {RPCResult::Type::ARR, "participant_pubkeys", "",
                        {
                            {RPCResult::Type::STR_HEX, "pubkey", "The compressed public keys that are aggregated for aggregate_pubkey."},
                        }},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/true, "The unknown output fields",
                {
                    {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                }},
                {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The output proprietary map",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                        {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                        {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                        {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                    }},
                }},
            }},
        }
    };
    return decodepsbt_outputs;
}

static RPCMethod decodepsbt()
{
    return RPCMethod{
        "decodepsbt",
        "Return a JSON object representing the serialized, base64-encoded partially signed Bitplus transaction.",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "tx", "The decoded network-serialized unsigned transaction.",
                            TxDoc({.elision_description="The layout is the same as the output of decoderawtransaction."})
                        },
                        {RPCResult::Type::ARR, "global_xpubs", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "xpub", "The extended public key this path corresponds to"},
                                {RPCResult::Type::STR_HEX, "master_fingerprint", "The fingerprint of the master key"},
                                {RPCResult::Type::STR, "path", "The path"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "psbt_version", "The PSBT version number. Not to be confused with the unsigned transaction version"},
                        {RPCResult::Type::ARR, "proprietary", "The global proprietary map",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                                {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                                {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                                {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                            }},
                        }},
                        {RPCResult::Type::OBJ_DYN, "unknown", "The unknown global fields",
                        {
                             {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                        }},
                        DecodePSBTInputs(),
                        DecodePSBTOutputs(),
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid if all UTXOs slots in the PSBT have been filled."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("decodepsbt", "\"psbt\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    UniValue result(UniValue::VOBJ);

    // Add the decoded tx
    UniValue tx_univ(UniValue::VOBJ);
    TxToUniv(CTransaction(*psbtx.tx), /*block_hash=*/uint256(), /*entry=*/tx_univ, /*include_hex=*/false);
    result.pushKV("tx", std::move(tx_univ));

    // Add the global xpubs
    UniValue global_xpubs(UniValue::VARR);
    for (std::pair<KeyOriginInfo, std::set<CExtPubKey>> xpub_pair : psbtx.m_xpubs) {
        for (auto& xpub : xpub_pair.second) {
            std::vector<unsigned char> ser_xpub;
            ser_xpub.assign(BIP32_EXTKEY_WITH_VERSION_SIZE, 0);
            xpub.EncodeWithVersion(ser_xpub.data());

            UniValue keypath(UniValue::VOBJ);
            keypath.pushKV("xpub", EncodeBase58Check(ser_xpub));
            keypath.pushKV("master_fingerprint", HexStr(std::span<unsigned char>(xpub_pair.first.fingerprint, xpub_pair.first.fingerprint + 4)));
            keypath.pushKV("path", WriteHDKeypath(xpub_pair.first.path));
            global_xpubs.push_back(std::move(keypath));
        }
    }
    result.pushKV("global_xpubs", std::move(global_xpubs));

    // PSBT version
    result.pushKV("psbt_version", psbtx.GetVersion());

    // Proprietary
    UniValue proprietary(UniValue::VARR);
    for (const auto& entry : psbtx.m_proprietary) {
        UniValue this_prop(UniValue::VOBJ);
        this_prop.pushKV("identifier", HexStr(entry.identifier));
        this_prop.pushKV("subtype", entry.subtype);
        this_prop.pushKV("key", HexStr(entry.key));
        this_prop.pushKV("value", HexStr(entry.value));
        proprietary.push_back(std::move(this_prop));
    }
    result.pushKV("proprietary", std::move(proprietary));

    // Unknown data
    UniValue unknowns(UniValue::VOBJ);
    for (auto entry : psbtx.unknown) {
        unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
    }
    result.pushKV("unknown", std::move(unknowns));

    // inputs
    CAmount total_in = 0;
    bool have_all_utxos = true;
    UniValue inputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const PSBTInput& input = psbtx.inputs[i];
        UniValue in(UniValue::VOBJ);
        // UTXOs
        bool have_a_utxo = false;
        CTxOut txout;
        if (!input.witness_utxo.IsNull()) {
            txout = input.witness_utxo;

            UniValue o(UniValue::VOBJ);
            ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);

            UniValue out(UniValue::VOBJ);
            out.pushKV("amount", ValueFromAmount(txout.nValue));
            out.pushKV("scriptPubKey", std::move(o));

            in.pushKV("witness_utxo", std::move(out));

            have_a_utxo = true;
        }
        if (input.non_witness_utxo) {
            txout = input.non_witness_utxo->vout[psbtx.tx->vin[i].prevout.n];

            UniValue non_wit(UniValue::VOBJ);
            TxToUniv(*input.non_witness_utxo, /*block_hash=*/uint256(), /*entry=*/non_wit, /*include_hex=*/false);
            in.pushKV("non_witness_utxo", std::move(non_wit));

            have_a_utxo = true;
        }
        if (have_a_utxo) {
            if (MoneyRange(txout.nValue) && MoneyRange(total_in + txout.nValue)) {
                total_in += txout.nValue;
            } else {
                // Hack to just not show fee later
                have_all_utxos = false;
            }
        } else {
            have_all_utxos = false;
        }

        // Partial sigs
        if (!input.partial_sigs.empty()) {
            UniValue partial_sigs(UniValue::VOBJ);
            for (const auto& sig : input.partial_sigs) {
                partial_sigs.pushKV(HexStr(sig.second.first), HexStr(sig.second.second));
            }
            in.pushKV("partial_signatures", std::move(partial_sigs));
        }

        // Sighash
        if (input.sighash_type != std::nullopt) {
            in.pushKV("sighash", SighashToStr((unsigned char)*input.sighash_type));
        }

        // Redeem script and witness script
        if (!input.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.redeem_script, /*out=*/r);
            in.pushKV("redeem_script", std::move(r));
        }
        if (!input.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.witness_script, /*out=*/r);
            in.pushKV("witness_script", std::move(r));
        }

        // keypaths
        if (!input.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : input.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));

                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(std::move(keypath));
            }
            in.pushKV("bip32_derivs", std::move(keypaths));
        }

        // Final scriptSig and scriptwitness
        if (!input.final_script_sig.empty()) {
            UniValue scriptsig(UniValue::VOBJ);
            scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true));
            scriptsig.pushKV("hex", HexStr(input.final_script_sig));
            in.pushKV("final_scriptSig", std::move(scriptsig));
        }
        if (!input.final_script_witness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : input.final_script_witness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("final_scriptwitness", std::move(txinwitness));
        }

        // Ripemd160 hash preimages
        if (!input.ripemd160_preimages.empty()) {
            UniValue ripemd160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.ripemd160_preimages) {
                ripemd160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("ripemd160_preimages", std::move(ripemd160_preimages));
        }

        // Sha256 hash preimages
        if (!input.sha256_preimages.empty()) {
            UniValue sha256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.sha256_preimages) {
                sha256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("sha256_preimages", std::move(sha256_preimages));
        }

        // Hash160 hash preimages
        if (!input.hash160_preimages.empty()) {
            UniValue hash160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash160_preimages) {
                hash160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash160_preimages", std::move(hash160_preimages));
        }

        // Hash256 hash preimages
        if (!input.hash256_preimages.empty()) {
            UniValue hash256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash256_preimages) {
                hash256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash256_preimages", std::move(hash256_preimages));
        }

        // Taproot key path signature
        if (!input.m_tap_key_sig.empty()) {
            in.pushKV("taproot_key_path_sig", HexStr(input.m_tap_key_sig));
        }

        // Taproot script path signatures
        if (!input.m_tap_script_sigs.empty()) {
            UniValue script_sigs(UniValue::VARR);
            for (const auto& [pubkey_leaf, sig] : input.m_tap_script_sigs) {
                const auto& [xonly, leaf_hash] = pubkey_leaf;
                UniValue sigobj(UniValue::VOBJ);
                sigobj.pushKV("pubkey", HexStr(xonly));
                sigobj.pushKV("leaf_hash", HexStr(leaf_hash));
                sigobj.pushKV("sig", HexStr(sig));
                script_sigs.push_back(std::move(sigobj));
            }
            in.pushKV("taproot_script_path_sigs", std::move(script_sigs));
        }

        // Taproot leaf scripts
        if (!input.m_tap_scripts.empty()) {
            UniValue tap_scripts(UniValue::VARR);
            for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
                const auto& [script, leaf_ver] = leaf;
                UniValue script_info(UniValue::VOBJ);
                script_info.pushKV("script", HexStr(script));
                script_info.pushKV("leaf_ver", leaf_ver);
                UniValue control_blocks_univ(UniValue::VARR);
                for (const auto& control_block : control_blocks) {
                    control_blocks_univ.push_back(HexStr(control_block));
                }
                script_info.pushKV("control_blocks", std::move(control_blocks_univ));
                tap_scripts.push_back(std::move(script_info));
            }
            in.pushKV("taproot_scripts", std::move(tap_scripts));
        }

        // Taproot bip32 keypaths
        if (!input.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", std::move(leaf_hashes_arr));
                keypaths.push_back(std::move(path_obj));
            }
            in.pushKV("taproot_bip32_derivs", std::move(keypaths));
        }

        // Taproot internal key
        if (!input.m_tap_internal_key.IsNull()) {
            in.pushKV("taproot_internal_key", HexStr(input.m_tap_internal_key));
        }

        // Write taproot merkle root
        if (!input.m_tap_merkle_root.IsNull()) {
            in.pushKV("taproot_merkle_root", HexStr(input.m_tap_merkle_root));
        }

        // Write MuSig2 fields
        if (!input.m_musig2_participants.empty()) {
            UniValue musig_pubkeys(UniValue::VARR);
            for (const auto& [agg, parts] : input.m_musig2_participants) {
                UniValue musig_part(UniValue::VOBJ);
                musig_part.pushKV("aggregate_pubkey", HexStr(agg));
                UniValue part_pubkeys(UniValue::VARR);
                for (const auto& pub : parts) {
                    part_pubkeys.push_back(HexStr(pub));
                }
                musig_part.pushKV("participant_pubkeys", part_pubkeys);
                musig_pubkeys.push_back(musig_part);
            }
            in.pushKV("musig2_participant_pubkeys", musig_pubkeys);
        }
        if (!input.m_musig2_pubnonces.empty()) {
            UniValue musig_pubnonces(UniValue::VARR);
            for (const auto& [agg_lh, part_pubnonce] : input.m_musig2_pubnonces) {
                const auto& [agg, lh] = agg_lh;
                for (const auto& [part, pubnonce] : part_pubnonce) {
                    UniValue info(UniValue::VOBJ);
                    info.pushKV("participant_pubkey", HexStr(part));
                    info.pushKV("aggregate_pubkey", HexStr(agg));
                    if (!lh.IsNull()) info.pushKV("leaf_hash", HexStr(lh));
                    info.pushKV("pubnonce", HexStr(pubnonce));
                    musig_pubnonces.push_back(info);
                }
            }
            in.pushKV("musig2_pubnonces", musig_pubnonces);
        }
        if (!input.m_musig2_partial_sigs.empty()) {
            UniValue musig_partial_sigs(UniValue::VARR);
            for (const auto& [agg_lh, part_psig] : input.m_musig2_partial_sigs) {
                const auto& [agg, lh] = agg_lh;
                for (const auto& [part, psig] : part_psig) {
                    UniValue info(UniValue::VOBJ);
                    info.pushKV("participant_pubkey", HexStr(part));
                    info.pushKV("aggregate_pubkey", HexStr(agg));
                    if (!lh.IsNull()) info.pushKV("leaf_hash", HexStr(lh));
                    info.pushKV("partial_sig", HexStr(psig));
                    musig_partial_sigs.push_back(info);
                }
            }
            in.pushKV("musig2_partial_sigs", musig_partial_sigs);
        }

        // Proprietary
        if (!input.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : input.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(std::move(this_prop));
            }
            in.pushKV("proprietary", std::move(proprietary));
        }

        // Unknown data
        if (input.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : input.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            in.pushKV("unknown", std::move(unknowns));
        }

        inputs.push_back(std::move(in));
    }
    result.pushKV("inputs", std::move(inputs));

    // outputs
    CAmount output_value = 0;
    UniValue outputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        const PSBTOutput& output = psbtx.outputs[i];
        UniValue out(UniValue::VOBJ);
        // Redeem script and witness script
        if (!output.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.redeem_script, /*out=*/r);
            out.pushKV("redeem_script", std::move(r));
        }
        if (!output.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.witness_script, /*out=*/r);
            out.pushKV("witness_script", std::move(r));
        }

        // keypaths
        if (!output.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : output.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));
                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(std::move(keypath));
            }
            out.pushKV("bip32_derivs", std::move(keypaths));
        }

        // Taproot internal key
        if (!output.m_tap_internal_key.IsNull()) {
            out.pushKV("taproot_internal_key", HexStr(output.m_tap_internal_key));
        }

        // Taproot tree
        if (!output.m_tap_tree.empty()) {
            UniValue tree(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : output.m_tap_tree) {
                UniValue elem(UniValue::VOBJ);
                elem.pushKV("depth", depth);
                elem.pushKV("leaf_ver", leaf_ver);
                elem.pushKV("script", HexStr(script));
                tree.push_back(std::move(elem));
            }
            out.pushKV("taproot_tree", std::move(tree));
        }

        // Taproot bip32 keypaths
        if (!output.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : output.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", std::move(leaf_hashes_arr));
                keypaths.push_back(std::move(path_obj));
            }
            out.pushKV("taproot_bip32_derivs", std::move(keypaths));
        }

        // Write MuSig2 fields
        if (!output.m_musig2_participants.empty()) {
            UniValue musig_pubkeys(UniValue::VARR);
            for (const auto& [agg, parts] : output.m_musig2_participants) {
                UniValue musig_part(UniValue::VOBJ);
                musig_part.pushKV("aggregate_pubkey", HexStr(agg));
                UniValue part_pubkeys(UniValue::VARR);
                for (const auto& pub : parts) {
                    part_pubkeys.push_back(HexStr(pub));
                }
                musig_part.pushKV("participant_pubkeys", part_pubkeys);
                musig_pubkeys.push_back(musig_part);
            }
            out.pushKV("musig2_participant_pubkeys", musig_pubkeys);
        }

        // Proprietary
        if (!output.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : output.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(std::move(this_prop));
            }
            out.pushKV("proprietary", std::move(proprietary));
        }

        // Unknown data
        if (output.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : output.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            out.pushKV("unknown", std::move(unknowns));
        }

        outputs.push_back(std::move(out));

        // Fee calculation
        if (MoneyRange(psbtx.tx->vout[i].nValue) && MoneyRange(output_value + psbtx.tx->vout[i].nValue)) {
            output_value += psbtx.tx->vout[i].nValue;
        } else {
            // Hack to just not show fee later
            have_all_utxos = false;
        }
    }
    result.pushKV("outputs", std::move(outputs));
    if (have_all_utxos) {
        result.pushKV("fee", ValueFromAmount(total_in - output_value));
    }

    return result;
},
    };
}

static RPCMethod combinepsbt()
{
    return RPCMethod{
        "combinepsbt",
        "Combine multiple partially signed Bitplus transactions into one transaction.\n"
                "Implements the Combiner role.\n",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                        {
                            {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A base64 string of a PSBT"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
                },
                RPCExamples{
                    HelpExampleCli("combinepsbt", R"('["mybase64_1", "mybase64_2", "mybase64_3"]')")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();
    if (txs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txs' cannot be empty");
    }
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
    }

    PartiallySignedTransaction merged_psbt;
    if (!CombinePSBTs(merged_psbt, psbtxs)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBTs not compatible (different transactions)");
    }

    DataStream ssTx{};
    ssTx << merged_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCMethod finalizepsbt()
{
    return RPCMethod{"finalizepsbt",
                "Finalize the inputs of a PSBT. If the transaction is fully signed, it will produce a\n"
                "network serialized transaction which can be broadcast with sendrawtransaction. Otherwise a PSBT will be\n"
                "created which has the final_scriptSig and final_scriptwitness fields filled for inputs that are complete.\n"
                "Implements the Finalizer and Extractor roles.\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                    {"extract", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true and the transaction is complete,\n"
            "                             extract and return the complete transaction in normal network serialization instead of the PSBT."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", /*optional=*/true, "The base64-encoded partially signed transaction if not extracted"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if extracted"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("finalizepsbt", "\"psbt\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    bool extract = request.params[1].isNull() || (!request.params[1].isNull() && request.params[1].get_bool());

    CMutableTransaction mtx;
    bool complete = FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);
    DataStream ssTx{};
    std::string result_str;

    if (complete && extract) {
        ssTx << TX_WITH_WITNESS(mtx);
        result_str = HexStr(ssTx);
        result.pushKV("hex", result_str);
    } else {
        ssTx << psbtx;
        result_str = EncodeBase64(ssTx.str());
        result.pushKV("psbt", result_str);
    }
    result.pushKV("complete", complete);

    return result;
},
    };
}

static RPCMethod createpsbt()
{
    return RPCMethod{
        "createpsbt",
        "Creates a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator role.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                    HelpExampleCli("createpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{

    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf, self.Arg<uint32_t>("version"));

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = rawTx;
    for (unsigned int i = 0; i < rawTx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < rawTx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCMethod converttopsbt()
{
    return RPCMethod{
        "converttopsbt",
        "Converts a network serialized transaction to a PSBT. This should be used only with createrawtransaction and fundrawtransaction\n"
                "createpsbt and walletcreatefundedpsbt should be used for new applications.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of a raw transaction"},
                    {"permitsigdata", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, any signatures in the input will be discarded and conversion\n"
                            "                              will continue. If false, RPC will fail if any signatures are present."},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                            "\nCreate a transaction\n"
                            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"") +
                            "\nConvert the transaction to a PSBT\n"
                            + HelpExampleCli("converttopsbt", "\"rawtransaction\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // parse hex string from parameter
    CMutableTransaction tx;
    bool permitsigdata = request.params[1].isNull() ? false : request.params[1].get_bool();
    bool witness_specified = !request.params[2].isNull();
    bool iswitness = witness_specified ? request.params[2].get_bool() : false;
    const bool try_witness = witness_specified ? iswitness : true;
    const bool try_no_witness = witness_specified ? !iswitness : true;
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Remove all scriptSigs and scriptWitnesses from inputs
    for (CTxIn& input : tx.vin) {
        if ((!input.scriptSig.empty() || !input.scriptWitness.IsNull()) && !permitsigdata) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Inputs must not have scriptSigs and scriptWitnesses");
        }
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCMethod utxoupdatepsbt()
{
    return RPCMethod{
        "utxoupdatepsbt",
        "Updates all segwit inputs and outputs in a PSBT with data from output descriptors, the UTXO set, txindex, or the mempool.\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of either strings or objects", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                         {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                         {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                    }},
                }},
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction with inputs updated"
            },
            RPCExamples {
                HelpExampleCli("utxoupdatepsbt", "\"psbt\"")
            },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Parse descriptors, if any.
    FlatSigningProvider provider;
    if (!request.params[1].isNull()) {
        auto descs = request.params[1].get_array();
        for (size_t i = 0; i < descs.size(); ++i) {
            EvalDescriptorStringOrObject(descs[i], provider);
        }
    }

    // We don't actually need private keys further on; hide them as a precaution.
    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/true, /*hide_origin=*/false),
        /*sighash_type=*/std::nullopt,
        /*finalize=*/false);

    DataStream ssTx{};
    ssTx << psbtx;
    return EncodeBase64(ssTx);
},
    };
}

static RPCMethod joinpsbts()
{
    return RPCMethod{
        "joinpsbts",
        "Joins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs\n"
            "No input in any of the PSBTs can be in more than one of the PSBTs.\n",
            {
                {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                    {
                        {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
                    }}
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
            },
            RPCExamples {
                HelpExampleCli("joinpsbts", "\"psbt\"")
            },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();

    if (txs.size() <= 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least two PSBTs are required to join PSBTs.");
    }

    uint32_t best_version = 1;
    uint32_t best_locktime = 0xffffffff;
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
        // Choose the highest version number
        if (psbtx.tx->version > best_version) {
            best_version = psbtx.tx->version;
        }
        // Choose the lowest lock time
        if (psbtx.tx->nLockTime < best_locktime) {
            best_locktime = psbtx.tx->nLockTime;
        }
    }

    // Create a blank psbt where everything will be added
    PartiallySignedTransaction merged_psbt;
    merged_psbt.tx = CMutableTransaction();
    merged_psbt.tx->version = best_version;
    merged_psbt.tx->nLockTime = best_locktime;

    // Merge
    for (auto& psbt : psbtxs) {
        for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
            if (!merged_psbt.AddInput(psbt.tx->vin[i], psbt.inputs[i])) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input %s:%d exists in multiple PSBTs", psbt.tx->vin[i].prevout.hash.ToString(), psbt.tx->vin[i].prevout.n));
            }
        }
        for (unsigned int i = 0; i < psbt.tx->vout.size(); ++i) {
            merged_psbt.AddOutput(psbt.tx->vout[i], psbt.outputs[i]);
        }
        for (auto& xpub_pair : psbt.m_xpubs) {
            if (!merged_psbt.m_xpubs.contains(xpub_pair.first)) {
                merged_psbt.m_xpubs[xpub_pair.first] = xpub_pair.second;
            } else {
                merged_psbt.m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
            }
        }
        merged_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
    }

    // Generate list of shuffled indices for shuffling inputs and outputs of the merged PSBT
    std::vector<int> input_indices(merged_psbt.inputs.size());
    std::iota(input_indices.begin(), input_indices.end(), 0);
    std::vector<int> output_indices(merged_psbt.outputs.size());
    std::iota(output_indices.begin(), output_indices.end(), 0);

    // Shuffle input and output indices lists
    std::shuffle(input_indices.begin(), input_indices.end(), FastRandomContext());
    std::shuffle(output_indices.begin(), output_indices.end(), FastRandomContext());

    PartiallySignedTransaction shuffled_psbt;
    shuffled_psbt.tx = CMutableTransaction();
    shuffled_psbt.tx->version = merged_psbt.tx->version;
    shuffled_psbt.tx->nLockTime = merged_psbt.tx->nLockTime;
    for (int i : input_indices) {
        shuffled_psbt.AddInput(merged_psbt.tx->vin[i], merged_psbt.inputs[i]);
    }
    for (int i : output_indices) {
        shuffled_psbt.AddOutput(merged_psbt.tx->vout[i], merged_psbt.outputs[i]);
    }
    shuffled_psbt.unknown.insert(merged_psbt.unknown.begin(), merged_psbt.unknown.end());

    DataStream ssTx{};
    ssTx << shuffled_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCMethod analyzepsbt()
{
    return RPCMethod{
        "analyzepsbt",
        "Analyzes and provides information about the current status of a PSBT and its inputs\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
            },
            RPCResult {
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ARR, "inputs", /*optional=*/true, "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "has_utxo", "Whether a UTXO is provided"},
                            {RPCResult::Type::BOOL, "is_final", "Whether the input is finalized"},
                            {RPCResult::Type::OBJ, "missing", /*optional=*/true, "Things that are missing that are required to complete this input",
                            {
                                {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose BIP 32 derivation path is missing"},
                                }},
                                {RPCResult::Type::ARR, "signatures", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose signature is missing"},
                                }},
                                {RPCResult::Type::STR_HEX, "redeemscript", /*optional=*/true, "Hash160 of the redeem script that is missing"},
                                {RPCResult::Type::STR_HEX, "witnessscript", /*optional=*/true, "SHA256 of the witness script that is missing"},
                            }},
                            {RPCResult::Type::STR, "next", /*optional=*/true, "Role of the next person that this input needs to go to"},
                        }},
                    }},
                    {RPCResult::Type::NUM, "estimated_vsize", /*optional=*/true, "Estimated vsize of the final signed transaction"},
                    {RPCResult::Type::STR_AMOUNT, "estimated_feerate", /*optional=*/true, "Estimated feerate of the final signed transaction in " + CURRENCY_UNIT + "/kvB. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR, "next", "Role of the next person that this psbt needs to go to"},
                    {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"},
                }
            },
            RPCExamples {
                HelpExampleCli("analyzepsbt", "\"psbt\"")
            },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    PSBTAnalysis psbta = AnalyzePSBT(psbtx);

    UniValue result(UniValue::VOBJ);
    UniValue inputs_result(UniValue::VARR);
    for (const auto& input : psbta.inputs) {
        UniValue input_univ(UniValue::VOBJ);
        UniValue missing(UniValue::VOBJ);

        input_univ.pushKV("has_utxo", input.has_utxo);
        input_univ.pushKV("is_final", input.is_final);
        input_univ.pushKV("next", PSBTRoleName(input.next));

        if (!input.missing_pubkeys.empty()) {
            UniValue missing_pubkeys_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_pubkeys) {
                missing_pubkeys_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("pubkeys", std::move(missing_pubkeys_univ));
        }
        if (!input.missing_redeem_script.IsNull()) {
            missing.pushKV("redeemscript", HexStr(input.missing_redeem_script));
        }
        if (!input.missing_witness_script.IsNull()) {
            missing.pushKV("witnessscript", HexStr(input.missing_witness_script));
        }
        if (!input.missing_sigs.empty()) {
            UniValue missing_sigs_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_sigs) {
                missing_sigs_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("signatures", std::move(missing_sigs_univ));
        }
        if (!missing.getKeys().empty()) {
            input_univ.pushKV("missing", std::move(missing));
        }
        inputs_result.push_back(std::move(input_univ));
    }
    if (!inputs_result.empty()) result.pushKV("inputs", std::move(inputs_result));

    if (psbta.estimated_vsize != std::nullopt) {
        result.pushKV("estimated_vsize", *psbta.estimated_vsize);
    }
    if (psbta.estimated_feerate != std::nullopt) {
        result.pushKV("estimated_feerate", ValueFromAmount(psbta.estimated_feerate->GetFeePerK()));
    }
    if (psbta.fee != std::nullopt) {
        result.pushKV("fee", ValueFromAmount(*psbta.fee));
    }
    result.pushKV("next", PSBTRoleName(psbta.next));
    if (!psbta.error.empty()) {
        result.pushKV("error", psbta.error);
    }

    return result;
},
    };
}

RPCMethod descriptorprocesspsbt()
{
    return RPCMethod{
        "descriptorprocesspsbt",
        "Update all segwit inputs in a PSBT with information from output descriptors, the UTXO set or the mempool. \n"
                "Then, sign the inputs we are able to with information from the output descriptors. ",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of either strings or objects", {
                        {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                             {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                             {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                        }},
                    }},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                    {"finalize", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also finalize inputs if possible"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The base64-encoded partially signed transaction"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if complete"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[\\\"descriptor1\\\", \\\"descriptor2\\\"]\"") +
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[{\\\"desc\\\":\\\"mydescriptor\\\", \\\"range\\\":21}]\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    // Add descriptor information to a signing provider
    FlatSigningProvider provider;

    auto descs = request.params[1].get_array();
    for (size_t i = 0; i < descs.size(); ++i) {
        EvalDescriptorStringOrObject(descs[i], provider, /*expand_priv=*/true);
    }

    std::optional<int> sighash_type = ParseSighashString(request.params[2]);
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool finalize = request.params[4].isNull() ? true : request.params[4].get_bool();

    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/false, !bip32derivs),
        sighash_type,
        finalize);

    // Check whether or not all of the inputs are now signed
    bool complete = true;
    for (const auto& input : psbtx.inputs) {
        complete &= PSBTInputSigned(input);
    }

    DataStream ssTx{};
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);

    result.pushKV("psbt", EncodeBase64(ssTx));
    result.pushKV("complete", complete);
    if (complete) {
        CMutableTransaction mtx;
        PartiallySignedTransaction psbtx_copy = psbtx;
        CHECK_NONFATAL(FinalizeAndExtractPSBT(psbtx_copy, mtx));
        DataStream ssTx_final;
        ssTx_final << TX_WITH_WITNESS(mtx);
        result.pushKV("hex", HexStr(ssTx_final));
    }
    return result;
},
    };
}

static RPCMethod createbitplusassetid()
{
    return RPCMethod{
        "createbitplusassetid",
        "Compute the deterministic Bitplus asset id for an issuance anchor.\n",
        {
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The BTPMETA commitment hash."},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The first input txid anchoring the issuance."},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The first input output index anchoring the issuance."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "asset_id", "The deterministic asset id."},
        RPCExamples{HelpExampleCli("createbitplusassetid", "\"metadata_hash\" \"txid\" 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const uint256 metadata_hash{ParseHashV(request.params[0], "metadata_hash")};
            if (metadata_hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-metadata-null");
            const int vout{request.params[2].getInt<int>()};
            if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            return bitplus::assets::ComputeAssetId(
                metadata_hash,
                COutPoint{Txid::FromUint256(ParseHashV(request.params[1], "txid")), static_cast<uint32_t>(vout)}
            ).ToString();
        },
    };
}

static RPCMethod createbitplusscripttransaction()
{
    return RPCMethod{
        "createbitplusscripttransaction",
        "Create a raw transaction with exact Bitplus scriptPubKey outputs.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on replaceable and locktime"}, "The sequence number"},
                }},
            }},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ordered exact script outputs.", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact output scriptPubKey hex."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Output BTP amount."},
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional expected output index; rejects if it does not match the array position."},
                }},
            }},
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
            {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable."},
            {"version", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_RAWTX_VERSION}, "Transaction version"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The serialized transaction."},
            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
        }},
        RPCExamples{HelpExampleCli("createbitplusscripttransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"scriptPubKey\\\":\\\"51\\\",\\\"amount\\\":\\\"1.0\\\",\\\"index\\\":0}]\"")},
        [&](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CMutableTransaction raw_tx{BuildBitplusScriptTransaction(self, request)};
            const CTransaction tx{raw_tx};
            UniValue result{UniValue::VOBJ};
            result.pushKV("hex", EncodeHexTx(tx));
            result.pushKV("txid", tx.GetHash().ToString());
            return result;
        },
    };
}

static RPCMethod createbitpluspsbt()
{
    return RPCMethod{
        "createbitpluspsbt",
        "Create an unsigned PSBT with exact Bitplus scriptPubKey outputs.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on replaceable and locktime"}, "The sequence number"},
                }},
            }},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ordered exact script outputs.", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact output scriptPubKey hex."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Output BTP amount."},
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional expected output index; rejects if it does not match the array position."},
                }},
            }},
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
            {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable."},
            {"version", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_RAWTX_VERSION}, "Transaction version"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "psbt", "The base64-encoded PSBT."},
            {RPCResult::Type::STR_HEX, "txid", "The unsigned transaction id."},
        }},
        RPCExamples{HelpExampleCli("createbitpluspsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"scriptPubKey\\\":\\\"51\\\",\\\"amount\\\":\\\"1.0\\\",\\\"index\\\":0}]\"")},
        [&](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CMutableTransaction raw_tx{BuildBitplusScriptTransaction(self, request)};
            PartiallySignedTransaction psbtx;
            psbtx.tx = raw_tx;
            for (size_t i{0}; i < raw_tx.vin.size(); ++i) {
                psbtx.inputs.emplace_back();
            }
            for (size_t i{0}; i < raw_tx.vout.size(); ++i) {
                psbtx.outputs.emplace_back();
            }

            DataStream ss_tx{};
            ss_tx << psbtx;

            const CTransaction tx{raw_tx};
            UniValue result{UniValue::VOBJ};
            result.pushKV("psbt", EncodeBase64(ss_tx));
            result.pushKV("txid", tx.GetHash().ToString());
            return result;
        },
    };
}

static void AppendSettlementIssues(UniValue& issues, const UniValue& analysis)
{
    const UniValue& analysis_issues{analysis.find_value("issues")};
    if (!analysis_issues.isNull()) {
        for (const UniValue& issue : analysis_issues.get_array().getValues()) {
            issues.push_back(issue.get_str());
        }
    }
}

static int64_t ArraySizeOrZero(const UniValue& value)
{
    return value.isNull() ? 0 : static_cast<int64_t>(value.get_array().size());
}

static UniValue BitplusAnalysisSummaryToJSON(const UniValue& analysis)
{
    const UniValue& asset_outputs{analysis.find_value("asset_outputs")};
    const UniValue& metadata_outputs{analysis.find_value("metadata_outputs")};
    const UniValue& whitelist_outputs{analysis.find_value("whitelist_outputs")};
    const UniValue& proof_outputs{analysis.find_value("whitelist_proof_outputs")};
    const UniValue& spent_asset_outputs{analysis.find_value("spent_asset_outputs")};
    const UniValue& conservation{analysis.find_value("asset_conservation")};
    const UniValue& movements{analysis.find_value("participant_movements")};
    const UniValue& issues{analysis.find_value("issues")};

    int64_t unbalanced_conservation{0};
    if (!conservation.isNull()) {
        for (const UniValue& entry : conservation.get_array().getValues()) {
            const UniValue& balanced{entry.find_value("balanced")};
            if (!balanced.isNull() && !balanced.get_bool()) ++unbalanced_conservation;
        }
    }

    UniValue counts{UniValue::VOBJ};
    counts.pushKV("asset_outputs", ArraySizeOrZero(asset_outputs));
    counts.pushKV("metadata_outputs", ArraySizeOrZero(metadata_outputs));
    counts.pushKV("whitelist_outputs", ArraySizeOrZero(whitelist_outputs));
    counts.pushKV("whitelist_proof_outputs", ArraySizeOrZero(proof_outputs));

    UniValue summary{UniValue::VOBJ};
    summary.pushKV("recognized_outputs", analysis.find_value("recognized_outputs").getInt<int64_t>());
    summary.pushKV("output_commitment_counts", std::move(counts));
    summary.pushKV("spent_asset_outputs", ArraySizeOrZero(spent_asset_outputs));
    summary.pushKV("asset_conservation_entries", ArraySizeOrZero(conservation));
    summary.pushKV("unbalanced_asset_conservation_entries", unbalanced_conservation);
    summary.pushKV("participant_movement_entries", ArraySizeOrZero(movements));
    summary.pushKV("issue_count", ArraySizeOrZero(issues));
    summary.pushKV("valid", analysis.find_value("valid").get_bool());
    summary.pushKV("review_complete", analysis.find_value("bitplus_review_complete").get_bool());
    summary.pushKV("conservation_checked", analysis.find_value("conservation_checked").get_bool());
    return summary;
}

static bool IssueStartsWith(std::string_view issue, std::string_view prefix)
{
    return issue.size() >= prefix.size() && issue.substr(0, prefix.size()) == prefix;
}

static UniValue ReadinessIssueSummaryToJSON(
    const UniValue& issues,
    const UniValue& warnings,
    const UniValue& bitplus_analysis)
{
    int64_t finalization_issues{0};
    int64_t activation_issues{0};
    int64_t prevout_context_issues{0};
    int64_t confirmation_issues{0};
    int64_t mempool_issues{0};
    int64_t fee_policy_issues{0};

    for (const UniValue& issue_value : issues.get_array().getValues()) {
        const std::string issue{issue_value.get_str()};
        if (issue == "psbt-not-finalized") ++finalization_issues;
        if (issue == "institutional-contracts-not-active") ++activation_issues;
        if (issue == "input-utxo-missing" || issue == "psbt-input-utxo-missing") ++prevout_context_issues;
        if (issue == "input-confirmations-unavailable" || issue == "input-confirmations-too-low") ++confirmation_issues;
        if (IssueStartsWith(issue, "mempool-") || IssueStartsWith(issue, "mempool-reject:")) ++mempool_issues;
        if (issue == "mempool-max-fee-exceeded") ++fee_policy_issues;
    }

    const int64_t issue_count{ArraySizeOrZero(issues)};
    const int64_t warning_count{ArraySizeOrZero(warnings)};
    const int64_t analyzer_issue_count{ArraySizeOrZero(bitplus_analysis.find_value("issues"))};
    UniValue summary{UniValue::VOBJ};
    summary.pushKV("blocking_issue_count", issue_count);
    summary.pushKV("warning_count", warning_count);
    summary.pushKV("analyzer_issue_count", analyzer_issue_count);
    summary.pushKV("readiness_issue_count", std::max<int64_t>(0, issue_count - analyzer_issue_count));
    summary.pushKV("has_blocking_issues", issue_count > 0);
    summary.pushKV("has_warnings", warning_count > 0);
    summary.pushKV("finalization_issues", finalization_issues);
    summary.pushKV("activation_issues", activation_issues);
    summary.pushKV("prevout_context_issues", prevout_context_issues);
    summary.pushKV("confirmation_issues", confirmation_issues);
    summary.pushKV("mempool_issues", mempool_issues);
    summary.pushKV("fee_policy_issues", fee_policy_issues);
    return summary;
}

static void WriteHashString(HashWriter& writer, std::string_view value);

static void WriteIssueList(HashWriter& writer, const UniValue& values)
{
    const auto& array{values.get_array().getValues()};
    writer << static_cast<uint64_t>(array.size());
    for (const UniValue& value : array) {
        WriteHashString(writer, value.get_str());
    }
}

static void WriteReportObject(HashWriter& writer, const UniValue& value)
{
    WriteHashString(writer, value.write(/*prettyIndent=*/0));
}

static uint256 CompactReportHash(std::string_view domain, const UniValue& value)
{
    HashWriter writer{};
    WriteHashString(writer, domain);
    WriteReportObject(writer, value);
    return writer.GetSHA256();
}

static uint256 ReadinessReportHash(
    const uint256& settlement_readiness_hash,
    const UniValue& chain_snapshot,
    const UniValue& readiness_policy,
    const UniValue& input_confirmation_summary,
    const UniValue& bitplus_analysis_summary,
    const UniValue& readiness_issue_summary,
    bool ready_to_broadcast,
    const UniValue& issues,
    const UniValue& warnings)
{
    HashWriter writer{};
    WriteHashString(writer, "BitplusReadinessReportV1");
    writer << settlement_readiness_hash;
    WriteReportObject(writer, chain_snapshot);
    WriteReportObject(writer, readiness_policy);
    WriteReportObject(writer, input_confirmation_summary);
    WriteReportObject(writer, bitplus_analysis_summary);
    WriteReportObject(writer, readiness_issue_summary);
    writer << ready_to_broadcast;
    WriteIssueList(writer, issues);
    WriteIssueList(writer, warnings);
    return writer.GetSHA256();
}

static uint256 SettlementReadinessHash(
    std::string_view format,
    const uint256& txid,
    const std::optional<uint256>& wtxid,
    bool final_transaction_available,
    int64_t chain_height,
    const uint256& chain_tip_hash,
    bool institutional_active,
    CAmount max_fee_rate_per_k,
    int64_t min_input_confirmations,
    const std::optional<std::vector<BitplusInputConfirmation>>& input_confirmations,
    bool input_confirmations_available,
    bool bitplus_valid,
    int64_t recognized_outputs,
    bool conservation_checked,
    bool prevout_context_available,
    const UniValue& missing_prevouts,
    std::string_view bitplus_review_hash,
    bool bitplus_review_complete,
    bool check_mempool,
    const std::optional<bool>& mempool_allowed,
    bool ready_to_broadcast,
    const UniValue& issues,
    const UniValue& warnings)
{
    HashWriter writer{};
    WriteHashString(writer, "BitplusSettlementReadinessV1");
    WriteHashString(writer, format);
    writer << txid;
    writer << wtxid.has_value();
    if (wtxid.has_value()) writer << *wtxid;
    writer << final_transaction_available;
    writer << chain_height;
    writer << chain_tip_hash;
    writer << institutional_active;
    writer << max_fee_rate_per_k;
    writer << min_input_confirmations;
    writer << input_confirmations.has_value();
    if (input_confirmations.has_value()) {
        writer << input_confirmations_available;
        writer << static_cast<uint64_t>(input_confirmations->size());
        for (const BitplusInputConfirmation& confirmation : *input_confirmations) {
            writer << confirmation.input_index;
            writer << confirmation.available;
            writer << confirmation.from_mempool;
            writer << confirmation.height;
            writer << confirmation.confirmations;
        }
    }
    writer << bitplus_valid;
    writer << recognized_outputs;
    writer << conservation_checked;
    writer << prevout_context_available;
    writer << static_cast<uint64_t>(missing_prevouts.isNull() ? 0 : missing_prevouts.get_array().size());
    if (!missing_prevouts.isNull()) {
        for (const UniValue& missing : missing_prevouts.get_array().getValues()) {
            writer << missing.getInt<int64_t>();
        }
    }
    WriteHashString(writer, bitplus_review_hash);
    writer << bitplus_review_complete;
    writer << check_mempool;
    writer << mempool_allowed.has_value();
    if (mempool_allowed.has_value()) writer << *mempool_allowed;
    writer << ready_to_broadcast;
    WriteIssueList(writer, issues);
    WriteIssueList(writer, warnings);
    return writer.GetSHA256();
}

static int64_t CountMissingPSBTUtxos(const UniValue& analysis)
{
    const UniValue& missing{analysis.find_value("missing_psbt_utxos")};
    return missing.isNull() ? 0 : static_cast<int64_t>(missing.get_array().size());
}

static RPCMethod preparebitpluspsbt()
{
    return RPCMethod{
        "preparebitpluspsbt",
        "Update a Bitplus PSBT with available UTXO data and return institutional analysis.\n",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string."},
            {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional output descriptors for script metadata enrichment.", {
                {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                    {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                }},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "psbt", "The updated base64-encoded PSBT."},
            {RPCResult::Type::STR_HEX, "txid", "The unsigned transaction id."},
            {RPCResult::Type::NUM, "missing_utxos_before", "Number of PSBT inputs without UTXO data before update."},
            {RPCResult::Type::NUM, "missing_utxos_after", "Number of PSBT inputs without UTXO data after update."},
            {RPCResult::Type::BOOL, "utxos_fully_available", "Whether every input has PSBT UTXO data after update."},
            {RPCResult::Type::OBJ_DYN, "bitplus_analysis", "Detailed Bitplus PSBT analyzer output after update.", {
                {RPCResult::Type::ANY, "field", "Analyzer field."},
            }},
        }},
        RPCExamples{HelpExampleCli("preparebitpluspsbt", "\"psbt\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            PartiallySignedTransaction original_psbt;
            std::string error;
            if (!DecodeBase64PSBT(original_psbt, request.params[0].get_str(), error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
            }
            const UniValue before_analysis{AnalyzeBitplusPSBTToJSON(original_psbt)};

            FlatSigningProvider provider;
            if (!request.params[1].isNull()) {
                const UniValue& descs{request.params[1].get_array()};
                for (size_t i{0}; i < descs.size(); ++i) {
                    EvalDescriptorStringOrObject(descs[i], provider);
                }
            }

            const PartiallySignedTransaction updated_psbt{ProcessPSBT(
                request.params[0].get_str(),
                request.context,
                HidingSigningProvider(&provider, /*hide_secret=*/true, /*hide_origin=*/false),
                /*sighash_type=*/std::nullopt,
                /*finalize=*/false)};
            const UniValue after_analysis{AnalyzeBitplusPSBTToJSON(updated_psbt)};

            DataStream ss_tx{};
            ss_tx << updated_psbt;

            UniValue result{UniValue::VOBJ};
            result.pushKV("psbt", EncodeBase64(ss_tx));
            result.pushKV("txid", CTransaction{*updated_psbt.tx}.GetHash().ToString());
            result.pushKV("missing_utxos_before", CountMissingPSBTUtxos(before_analysis));
            result.pushKV("missing_utxos_after", CountMissingPSBTUtxos(after_analysis));
            result.pushKV("utxos_fully_available", after_analysis.find_value("psbt_utxos_available").get_bool());
            result.pushKV("bitplus_analysis", after_analysis);
            return result;
        },
    };
}

static RPCMethod checkbitplussettlement()
{
    return RPCMethod{
        "checkbitplussettlement",
        "Run an operator readiness check for a Bitplus settlement raw transaction or PSBT.\n",
        {
            {"transaction", RPCArg::Type::STR, RPCArg::Optional::NO, "Raw transaction hex or base64 PSBT."},
            {"format", RPCArg::Type::STR, RPCArg::Default{"auto"}, "Input format: auto, raw, or psbt."},
            {"check_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true and a final transaction is available, run mempool test-accept."},
            {"maxfeerate", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())}, "Reject readiness if the mempool-accepted transaction fee rate exceeds this BTP/kvB value. Set 0 to disable."},
            {"min_input_confirmations", RPCArg::Type::NUM, RPCArg::Default{6}, "Minimum confirmations required for every final transaction input. Use 0 to allow unconfirmed inputs."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "format", "Detected or requested input format."},
            {RPCResult::Type::STR_HEX, "txid", "Transaction id."},
            {RPCResult::Type::STR_HEX, "wtxid", /*optional=*/true, "Witness transaction id when a final transaction is available."},
            {RPCResult::Type::BOOL, "final_transaction_available", "Whether a broadcastable transaction was available or extractable from the PSBT."},
            {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this readiness check.", {
                {RPCResult::Type::NUM, "height", "Active chain height."},
                {RPCResult::Type::STR_HEX, "bestblock", "Active chain tip hash."},
            }},
            {RPCResult::Type::BOOL, "institutional_contracts_active", "Whether the institutional contracts deployment is active for the next block."},
            {RPCResult::Type::NUM, "weight", /*optional=*/true, "Final transaction weight."},
            {RPCResult::Type::NUM, "vsize", /*optional=*/true, "Final transaction virtual size."},
            {RPCResult::Type::OBJ, "readiness_policy", "Versioned operator policy knobs used by this readiness check.", {
                {RPCResult::Type::STR, "version", "Readiness policy/hash domain version."},
                {RPCResult::Type::STR, "format", "Detected or requested input format used for policy evaluation."},
                {RPCResult::Type::BOOL, "check_mempool", "Whether mempool test-accept was required for final transactions."},
                {RPCResult::Type::STR_AMOUNT, "maxfeerate", "Maximum fee rate in BTP/kvB. Zero disables the max-fee check."},
                {RPCResult::Type::NUM, "min_input_confirmations", "Minimum input confirmation depth required."},
                {RPCResult::Type::BOOL, "require_institutional_contracts_active", "Whether recognized Bitplus outputs require active institutional deployment."},
                {RPCResult::Type::BOOL, "require_complete_bitplus_review", "Whether incomplete Bitplus prevout context is blocking."},
            }},
            {RPCResult::Type::STR_AMOUNT, "maxfeerate", "Maximum fee rate used by this readiness check in BTP/kvB. Zero disables the max-fee check."},
            {RPCResult::Type::NUM, "min_input_confirmations", "Minimum input confirmation depth required by this readiness check."},
            {RPCResult::Type::BOOL, "input_confirmations_available", /*optional=*/true, "Whether every final transaction input was found for confirmation-depth review."},
            {RPCResult::Type::OBJ, "input_confirmation_summary", /*optional=*/true, "Aggregate input confirmation counts for final transactions.", {
                {RPCResult::Type::NUM, "total_inputs", "Total transaction inputs."},
                {RPCResult::Type::NUM, "available_inputs", "Inputs whose prevouts were found."},
                {RPCResult::Type::NUM, "missing_inputs", "Inputs whose prevouts were missing."},
                {RPCResult::Type::NUM, "confirmed_inputs", "Inputs confirmed in the active chain."},
                {RPCResult::Type::NUM, "mempool_inputs", "Inputs sourced from the mempool."},
                {RPCResult::Type::NUM, "required_confirmations", "Required confirmation count."},
                {RPCResult::Type::NUM, "below_min_confirmations", "Available inputs below the required confirmation count."},
                {RPCResult::Type::NUM, "min_observed_confirmations", /*optional=*/true, "Lowest observed confirmation count among available inputs."},
            }},
            {RPCResult::Type::ARR, "input_confirmations", /*optional=*/true, "Per-input confirmation evidence for final transactions.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "input_index", "Transaction input index."},
                    {RPCResult::Type::BOOL, "available", "Whether the input prevout was found."},
                    {RPCResult::Type::STR, "source", /*optional=*/true, "chain or mempool."},
                    {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "Input confirmation count, or 0 for mempool inputs."},
                    {RPCResult::Type::NUM, "height", /*optional=*/true, "Block height for confirmed inputs."},
                }},
            }},
            {RPCResult::Type::ARR, "inputs_below_min_confirmations", /*optional=*/true, "Inputs available but below the configured confirmation requirement.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "input_index", "Transaction input index."},
                    {RPCResult::Type::NUM, "confirmations", "Observed confirmation count."},
                    {RPCResult::Type::NUM, "required_confirmations", "Required confirmation count."},
                    {RPCResult::Type::STR, "source", "chain or mempool."},
                }},
            }},
            {RPCResult::Type::BOOL, "bitplus_valid", "Whether Bitplus structural/linkage/conservation checks passed."},
            {RPCResult::Type::NUM, "recognized_outputs", "Number of Bitplus institutional commitment outputs from the analyzer."},
            {RPCResult::Type::OBJ, "bitplus_analysis_summary", "Compact summary of the detailed Bitplus analyzer output.", {
                {RPCResult::Type::NUM, "recognized_outputs", "Total recognized Bitplus commitment outputs."},
                {RPCResult::Type::OBJ, "output_commitment_counts", "Recognized output counts by commitment family.", {
                    {RPCResult::Type::NUM, "asset_outputs", "BTPASSET carrier outputs."},
                    {RPCResult::Type::NUM, "metadata_outputs", "BTPMETA outputs."},
                    {RPCResult::Type::NUM, "whitelist_outputs", "BTPWLST outputs."},
                    {RPCResult::Type::NUM, "whitelist_proof_outputs", "BTPWPROOF outputs."},
                }},
                {RPCResult::Type::NUM, "spent_asset_outputs", "Decoded spent BTPASSET inputs included in review."},
                {RPCResult::Type::NUM, "asset_conservation_entries", "Per-asset conservation rows."},
                {RPCResult::Type::NUM, "unbalanced_asset_conservation_entries", "Conservation rows that do not balance."},
                {RPCResult::Type::NUM, "participant_movement_entries", "Participant movement rows."},
                {RPCResult::Type::NUM, "issue_count", "Analyzer issue count."},
                {RPCResult::Type::BOOL, "valid", "Whether the analyzer found the package valid."},
                {RPCResult::Type::BOOL, "review_complete", "Whether the analyzer had complete prevout context."},
                {RPCResult::Type::BOOL, "conservation_checked", "Whether asset conservation was checked."},
            }},
            {RPCResult::Type::BOOL, "conservation_checked", "Whether the analyzer checked asset conservation with spent-output context."},
            {RPCResult::Type::BOOL, "prevout_context_available", "Whether all input previous outputs were available to the analyzer."},
            {RPCResult::Type::ARR, "missing_prevout_indexes", "Input indexes whose previous outputs were missing from the analyzer context.", {
                {RPCResult::Type::NUM, "input_index", "Missing input index."},
            }},
            {RPCResult::Type::STR_HEX, "bitplus_review_hash", "Deterministic review hash from the Bitplus analyzer."},
            {RPCResult::Type::BOOL, "bitplus_review_complete", "Whether the analyzer had enough spent-output context for complete asset-conservation review."},
            {RPCResult::Type::ARR, "asset_conservation", "Per-asset conservation summary copied from the Bitplus analyzer.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "Conservation field."},
                }},
            }},
            {RPCResult::Type::ARR, "participant_movements", "Per-asset participant movement summary copied from the Bitplus analyzer.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ANY, "field", "Movement field."},
                }},
            }},
            {RPCResult::Type::STR_HEX, "settlement_readiness_hash", "Deterministic hash committing to the full readiness gate decision, including confirmation and mempool policy inputs."},
            {RPCResult::Type::STR_HEX, "readiness_report_hash", "Deterministic hash committing to the compact operator readiness report fields."},
            {RPCResult::Type::BOOL, "mempool_allowed", /*optional=*/true, "Whether mempool test-accept allowed the final transaction."},
            {RPCResult::Type::OBJ, "mempool", /*optional=*/true, "Mempool test-accept result.", {
                {RPCResult::Type::BOOL, "allowed", "Whether mempool test-accept allowed the final transaction."},
                {RPCResult::Type::NUM, "vsize", /*optional=*/true, "Virtual size used by mempool acceptance."},
                {RPCResult::Type::STR, "reject-reason", /*optional=*/true, "Mempool rejection reason."},
                {RPCResult::Type::STR, "reject-details", /*optional=*/true, "Mempool rejection details."},
                {RPCResult::Type::OBJ, "fees", /*optional=*/true, "Fee details.", {
                    {RPCResult::Type::STR_AMOUNT, "base", "Base fee."},
                    {RPCResult::Type::STR_AMOUNT, "effective-feerate", "Effective fee rate in BTP/kvB."},
                }},
            }},
            {RPCResult::Type::BOOL, "ready_to_broadcast", "Whether the final transaction is ready for broadcast under these checks."},
            {RPCResult::Type::OBJ, "readiness_issue_summary", "Compact issue and warning counts grouped by operator-facing category.", {
                {RPCResult::Type::NUM, "blocking_issue_count", "Total blocking issue count."},
                {RPCResult::Type::NUM, "warning_count", "Total warning count."},
                {RPCResult::Type::NUM, "analyzer_issue_count", "Issues produced by the Bitplus analyzer."},
                {RPCResult::Type::NUM, "readiness_issue_count", "Issues added by the readiness gate after analyzer review."},
                {RPCResult::Type::BOOL, "has_blocking_issues", "Whether any blocking issues are present."},
                {RPCResult::Type::BOOL, "has_warnings", "Whether any warnings are present."},
                {RPCResult::Type::NUM, "finalization_issues", "Issues related to missing final transaction data."},
                {RPCResult::Type::NUM, "activation_issues", "Issues related to inactive institutional deployment."},
                {RPCResult::Type::NUM, "prevout_context_issues", "Issues related to missing input prevout context."},
                {RPCResult::Type::NUM, "confirmation_issues", "Issues related to missing or insufficient confirmations."},
                {RPCResult::Type::NUM, "mempool_issues", "Issues related to mempool test-accept."},
                {RPCResult::Type::NUM, "fee_policy_issues", "Issues related to max fee-rate policy."},
            }},
            {RPCResult::Type::ARR, "issues", "Blocking readiness issues.", {
                {RPCResult::Type::STR, "issue", "Issue string."},
            }},
            {RPCResult::Type::ARR, "warnings", "Non-blocking warnings.", {
                {RPCResult::Type::STR, "warning", "Warning string."},
            }},
            {RPCResult::Type::OBJ_DYN, "bitplus_analysis", "Detailed Bitplus analyzer output.", {
                {RPCResult::Type::ANY, "field", "Analyzer field."},
            }},
        }},
        RPCExamples{HelpExampleCli("checkbitplussettlement", "\"rawtx_or_psbt\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const std::string input{request.params[0].get_str()};
            const std::string format_arg{request.params[1].isNull() ? "auto" : ToLower(request.params[1].get_str())};
            if (format_arg != "auto" && format_arg != "raw" && format_arg != "psbt") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "format must be one of: auto, raw, psbt");
            }

            CMutableTransaction raw_mtx;
            PartiallySignedTransaction psbtx;
            std::string detected_format;
            UniValue bitplus_analysis{UniValue::VOBJ};
            std::optional<CTransaction> final_tx;
            bool final_transaction_available{false};

            if (format_arg == "raw" || (format_arg == "auto" && IsHex(input) && DecodeHexTx(raw_mtx, input))) {
                if (format_arg == "raw" && !DecodeHexTx(raw_mtx, input)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
                }
                detected_format = "raw";
                final_tx.emplace(std::move(raw_mtx));
                final_transaction_available = true;
                BitplusSpentAssetLookup lookup{LookupSpentAssetOutputsFromNode(*final_tx, request)};
                bitplus_analysis = AnalyzeBitplusTransactionToJSON(
                    *final_tx,
                    std::move(lookup.spent_asset_outputs),
                    lookup.any_input_utxo_available,
                    lookup.missing_input_utxos);
            } else {
                if (format_arg == "raw") {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
                }
                std::string error;
                if (!DecodeBase64PSBT(psbtx, input, error)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
                }
                detected_format = "psbt";
                bitplus_analysis = AnalyzeBitplusPSBTToJSON(psbtx);
                PartiallySignedTransaction psbtx_copy{psbtx};
                CMutableTransaction extracted;
                if (FinalizeAndExtractPSBT(psbtx_copy, extracted)) {
                    final_tx.emplace(std::move(extracted));
                    final_transaction_available = true;
                }
            }

            UniValue issues{UniValue::VARR};
            UniValue warnings{UniValue::VARR};
            AppendSettlementIssues(issues, bitplus_analysis);

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            bool institutional_active{false};
            int64_t chain_height{-1};
            uint256 chain_tip_hash;
            {
                LOCK(cs_main);
                const CBlockIndex* tip{chainman.ActiveChain().Tip()};
                if (tip != nullptr) {
                    chain_height = tip->nHeight;
                    chain_tip_hash = tip->GetBlockHash();
                }
                institutional_active = DeploymentActiveAfter(tip, chainman, Consensus::DEPLOYMENT_INSTITUTIONAL_CONTRACTS);
            }

            const int64_t recognized_outputs{bitplus_analysis.find_value("recognized_outputs").getInt<int64_t>()};
            if (recognized_outputs > 0 && !institutional_active) {
                issues.push_back("institutional-contracts-not-active");
            }

            const bool bitplus_valid{bitplus_analysis.find_value("valid").get_bool()};
            if (!bitplus_valid && bitplus_analysis.find_value("issues").get_array().empty()) {
                issues.push_back("bitplus-analysis-invalid");
            }

            if (!final_transaction_available) {
                issues.push_back("psbt-not-finalized");
            }

            const bool check_mempool{request.params[2].isNull() ? true : request.params[2].get_bool()};
            const CFeeRate max_raw_tx_fee_rate{ParseFeeRate(self.Arg<UniValue>("maxfeerate"))};
            const int64_t min_input_confirmations{request.params[4].isNull() ? 6 : request.params[4].getInt<int64_t>()};
            if (min_input_confirmations < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "min_input_confirmations must be non-negative");
            }
            std::optional<std::vector<BitplusInputConfirmation>> input_confirmations;
            bool input_confirmations_available{false};
            bool inputs_below_min_confirmations{false};
            if (final_transaction_available) {
                input_confirmations = LookupInputConfirmationsFromNode(*final_tx, request);
                input_confirmations_available = true;
                for (const BitplusInputConfirmation& confirmation : *input_confirmations) {
                    if (!confirmation.available) {
                        input_confirmations_available = false;
                    } else if (confirmation.confirmations < min_input_confirmations) {
                        inputs_below_min_confirmations = true;
                    }
                }
                if (!input_confirmations_available) issues.push_back("input-confirmations-unavailable");
                if (inputs_below_min_confirmations) issues.push_back("input-confirmations-too-low");
            }
            std::optional<bool> mempool_allowed;
            UniValue mempool_result{UniValue::VOBJ};

            if (final_transaction_available && check_mempool) {
                const CTransactionRef tx_ref{MakeTransactionRef(*final_tx)};
                const MempoolAcceptResult accept_result{WITH_LOCK(cs_main, return chainman.ProcessTransaction(tx_ref, /*test_accept=*/true);)};
                if (accept_result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                    const CAmount fee{accept_result.m_base_fees.value()};
                    const int64_t vsize{accept_result.m_vsize.value()};
                    const CAmount max_raw_tx_fee{max_raw_tx_fee_rate.GetFee(vsize)};
                    if (max_raw_tx_fee && fee > max_raw_tx_fee) {
                        mempool_allowed = false;
                        mempool_result.pushKV("allowed", false);
                        mempool_result.pushKV("reject-reason", "max-fee-exceeded");
                        issues.push_back("mempool-max-fee-exceeded");
                    } else {
                        mempool_allowed = true;
                        mempool_result.pushKV("allowed", true);
                        mempool_result.pushKV("vsize", vsize);
                        UniValue fees{UniValue::VOBJ};
                        fees.pushKV("base", ValueFromAmount(fee));
                        fees.pushKV("effective-feerate", ValueFromAmount(accept_result.m_effective_feerate.value().GetFeePerK()));
                        mempool_result.pushKV("fees", std::move(fees));
                    }
                } else {
                    mempool_allowed = false;
                    mempool_result.pushKV("allowed", false);
                    const TxValidationState state{accept_result.m_state};
                    if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS) {
                        mempool_result.pushKV("reject-reason", "missing-inputs");
                        issues.push_back("mempool-missing-inputs");
                    } else {
                        mempool_result.pushKV("reject-reason", state.GetRejectReason());
                        mempool_result.pushKV("reject-details", state.ToString());
                        issues.push_back(std::string{"mempool-reject:"} + state.GetRejectReason());
                    }
                }
            } else if (final_transaction_available && !check_mempool) {
                warnings.push_back("mempool-check-skipped");
            }

            const UniValue& context_available{
                detected_format == "psbt" ? bitplus_analysis.find_value("psbt_utxos_available") : bitplus_analysis.find_value("input_utxos_available")
            };
            const UniValue& missing_prevouts{
                detected_format == "psbt" ? bitplus_analysis.find_value("missing_psbt_utxos") : bitplus_analysis.find_value("missing_input_utxos")
            };
            const bool prevout_context_available{!context_available.isNull() && context_available.get_bool()};
            const bool ready_to_broadcast{
                issues.empty() &&
                bitplus_valid &&
                final_transaction_available &&
                (!check_mempool || (mempool_allowed.has_value() && *mempool_allowed))
            };
            const uint256 txid{
                final_transaction_available ? final_tx->GetHash().ToUint256() : CTransaction{*psbtx.tx}.GetHash().ToUint256()
            };
            const std::optional<uint256> wtxid{
                final_transaction_available ? std::optional<uint256>{final_tx->GetWitnessHash().ToUint256()} : std::nullopt
            };
            const uint256 settlement_readiness_hash{SettlementReadinessHash(
                detected_format,
                txid,
                wtxid,
                final_transaction_available,
                chain_height,
                chain_tip_hash,
                institutional_active,
                max_raw_tx_fee_rate.GetFeePerK(),
                min_input_confirmations,
                input_confirmations,
                input_confirmations_available,
                bitplus_valid,
                recognized_outputs,
                bitplus_analysis.find_value("conservation_checked").get_bool(),
                prevout_context_available,
                missing_prevouts,
                bitplus_analysis.find_value("bitplus_review_hash").get_str(),
                bitplus_analysis.find_value("bitplus_review_complete").get_bool(),
                check_mempool,
                mempool_allowed,
                ready_to_broadcast,
                issues,
                warnings)};

            UniValue result{UniValue::VOBJ};
            result.pushKV("format", detected_format);
            result.pushKV("txid", txid.ToString());
            if (final_transaction_available) {
                result.pushKV("wtxid", wtxid->ToString());
            }
            result.pushKV("final_transaction_available", final_transaction_available);
            UniValue chain_snapshot{UniValue::VOBJ};
            chain_snapshot.pushKV("height", chain_height);
            chain_snapshot.pushKV("bestblock", chain_tip_hash.ToString());
            result.pushKV("chain_snapshot", chain_snapshot);
            result.pushKV("institutional_contracts_active", institutional_active);
            if (final_transaction_available) {
                result.pushKV("weight", GetTransactionWeight(*final_tx));
                result.pushKV("vsize", GetVirtualTransactionSize(*final_tx));
            }
            UniValue readiness_policy{UniValue::VOBJ};
            readiness_policy.pushKV("version", "BitplusSettlementReadinessV1");
            readiness_policy.pushKV("format", detected_format);
            readiness_policy.pushKV("check_mempool", check_mempool);
            readiness_policy.pushKV("maxfeerate", ValueFromAmount(max_raw_tx_fee_rate.GetFeePerK()));
            readiness_policy.pushKV("min_input_confirmations", min_input_confirmations);
            readiness_policy.pushKV("require_institutional_contracts_active", true);
            readiness_policy.pushKV("require_complete_bitplus_review", true);
            result.pushKV("readiness_policy", readiness_policy);
            result.pushKV("maxfeerate", ValueFromAmount(max_raw_tx_fee_rate.GetFeePerK()));
            result.pushKV("min_input_confirmations", min_input_confirmations);
            UniValue input_confirmation_summary{UniValue::VOBJ};
            if (input_confirmations.has_value()) {
                input_confirmation_summary = InputConfirmationSummaryToJSON(*input_confirmations, min_input_confirmations);
                result.pushKV("input_confirmations_available", input_confirmations_available);
                result.pushKV("input_confirmation_summary", input_confirmation_summary);
                result.pushKV("input_confirmations", InputConfirmationsToJSON(*input_confirmations));
                result.pushKV("inputs_below_min_confirmations", InputsBelowMinConfirmationsToJSON(*input_confirmations, min_input_confirmations));
            }
            UniValue bitplus_analysis_summary{BitplusAnalysisSummaryToJSON(bitplus_analysis)};
            UniValue readiness_issue_summary{ReadinessIssueSummaryToJSON(issues, warnings, bitplus_analysis)};
            const uint256 readiness_report_hash{ReadinessReportHash(
                settlement_readiness_hash,
                chain_snapshot,
                readiness_policy,
                input_confirmation_summary,
                bitplus_analysis_summary,
                readiness_issue_summary,
                ready_to_broadcast,
                issues,
                warnings)};
            result.pushKV("bitplus_valid", bitplus_valid);
            result.pushKV("recognized_outputs", recognized_outputs);
            result.pushKV("bitplus_analysis_summary", bitplus_analysis_summary);
            result.pushKV("conservation_checked", bitplus_analysis.find_value("conservation_checked").get_bool());
            result.pushKV("prevout_context_available", prevout_context_available);
            result.pushKV("missing_prevout_indexes", missing_prevouts.isNull() ? UniValue{UniValue::VARR} : missing_prevouts);
            result.pushKV("bitplus_review_hash", bitplus_analysis.find_value("bitplus_review_hash").get_str());
            result.pushKV("bitplus_review_complete", bitplus_analysis.find_value("bitplus_review_complete").get_bool());
            result.pushKV("asset_conservation", bitplus_analysis.find_value("asset_conservation"));
            result.pushKV("participant_movements", bitplus_analysis.find_value("participant_movements"));
            result.pushKV("settlement_readiness_hash", settlement_readiness_hash.ToString());
            result.pushKV("readiness_report_hash", readiness_report_hash.ToString());
            if (mempool_allowed.has_value()) result.pushKV("mempool_allowed", *mempool_allowed);
            if (!mempool_result.empty()) result.pushKV("mempool", std::move(mempool_result));
            result.pushKV("ready_to_broadcast", ready_to_broadcast);
            result.pushKV("readiness_issue_summary", readiness_issue_summary);
            result.pushKV("issues", std::move(issues));
            result.pushKV("warnings", std::move(warnings));
            result.pushKV("bitplus_analysis", std::move(bitplus_analysis));
            return result;
        },
    };
}

struct BitplusAssetScanFilters
{
    std::optional<bitplus::assets::AssetCommitmentType> type;
    std::optional<uint256> metadata_hash;
    std::optional<uint256> member_hash;
    std::optional<int64_t> min_confirmations;
    UniValue ToJSON() const
    {
        UniValue filters{UniValue::VOBJ};
        if (type.has_value()) filters.pushKV("type", AssetCommitmentTypeToString(*type));
        if (metadata_hash.has_value()) filters.pushKV("metadata_hash", metadata_hash->ToString());
        if (member_hash.has_value()) filters.pushKV("member_hash", member_hash->ToString());
        if (min_confirmations.has_value()) filters.pushKV("min_confirmations", *min_confirmations);
        return filters;
    }
    bool Match(const bitplus::assets::AssetCommitment& commitment, int64_t confirmations) const
    {
        return (!type.has_value() || commitment.type == *type) &&
            (!metadata_hash.has_value() || commitment.metadata_hash == *metadata_hash) &&
            (!member_hash.has_value() || commitment.member_hash == *member_hash) &&
            (!min_confirmations.has_value() || confirmations >= *min_confirmations);
    }
};

struct BitplusAssetScanCursor
{
    int64_t cursor_version;
    uint256 bestblock;
    int64_t height;
    uint256 asset_id;
    uint256 filters_hash;
    COutPoint after;
};

static void RejectUnknownObjectFields(const UniValue& value, const std::set<std::string>& allowed, std::string_view object_name)
{
    for (const std::string& key : value.getKeys()) {
        if (!allowed.contains(key)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("unknown %s field: %s", object_name, key));
        }
    }
}

static BitplusAssetScanFilters ParseBitplusAssetScanFilters(const UniValue& value, bool allow_asset_id_filter = false)
{
    BitplusAssetScanFilters filters;
    if (value.isNull()) return filters;
    if (!value.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "filters must be an object");

    const UniValue& filters_in{value.get_obj()};
    std::set<std::string> allowed_fields{"type", "metadata_hash", "member_hash", "min_confirmations"};
    if (allow_asset_id_filter) allowed_fields.insert("asset_id");
    RejectUnknownObjectFields(filters_in, allowed_fields, "filters");
    const UniValue& type_value{filters_in.find_value("type")};
    if (!type_value.isNull()) {
        filters.type = ParseAssetCommitmentType(type_value.get_str());
    }
    const UniValue& metadata_value{filters_in.find_value("metadata_hash")};
    if (!metadata_value.isNull()) {
        filters.metadata_hash = ParseHashV(metadata_value, "metadata_hash");
        if (filters.metadata_hash->IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "metadata_hash must not be null");
    }
    const UniValue& member_value{filters_in.find_value("member_hash")};
    if (!member_value.isNull()) {
        filters.member_hash = ParseHashV(member_value, "member_hash");
        if (filters.member_hash->IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "member_hash must not be null");
    }
    const UniValue& min_confirmations_value{filters_in.find_value("min_confirmations")};
    if (!min_confirmations_value.isNull()) {
        filters.min_confirmations = min_confirmations_value.getInt<int64_t>();
        if (*filters.min_confirmations < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "min_confirmations must be non-negative");
    }
    return filters;
}

static BitplusAssetScanCursor ParseBitplusAssetScanCursor(const UniValue& value)
{
    if (!value.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor must be an object");
    const UniValue& cursor{value.get_obj()};
    RejectUnknownObjectFields(cursor, {"cursor_version", "bestblock", "height", "asset_id", "filters_hash", "txid", "vout"}, "cursor");
    const UniValue& cursor_version_value{cursor.find_value("cursor_version")};
    if (cursor_version_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor cursor_version is required");
    const UniValue& bestblock_value{cursor.find_value("bestblock")};
    if (bestblock_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor bestblock is required");
    const UniValue& height_value{cursor.find_value("height")};
    if (height_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor height is required");
    const UniValue& asset_id_value{cursor.find_value("asset_id")};
    if (asset_id_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor asset_id is required");
    const UniValue& filters_hash_value{cursor.find_value("filters_hash")};
    if (filters_hash_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor filters_hash is required");
    const UniValue& txid_value{cursor.find_value("txid")};
    if (txid_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor txid is required");
    const UniValue& vout_value{cursor.find_value("vout")};
    if (vout_value.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor vout is required");

    BitplusAssetScanCursor result{
        .cursor_version = cursor_version_value.getInt<int64_t>(),
        .bestblock = ParseHashV(bestblock_value, "cursor.bestblock"),
        .height = height_value.getInt<int64_t>(),
        .asset_id = ParseHashV(asset_id_value, "cursor.asset_id"),
        .filters_hash = ParseHashV(filters_hash_value, "cursor.filters_hash"),
        .after = COutPoint{
            Txid::FromUint256(ParseHashV(txid_value, "cursor.txid")),
            0,
        },
    };
    if (result.cursor_version != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor_version must be 1");
    if (result.bestblock.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor bestblock must not be null");
    if (result.asset_id.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor asset_id must not be null");
    if (result.filters_hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor filters_hash must not be null");
    if (result.after.hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor txid must not be null");
    if (result.height < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor height must be non-negative");

    const int64_t vout{vout_value.getInt<int64_t>()};
    if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor vout out of range");
    }
    result.after.n = static_cast<uint32_t>(vout);
    return result;
}

static UniValue BitplusAssetScanCursorToJSON(const CBlockIndex& tip, const uint256& asset_id, const uint256& filters_hash, const COutPoint& outpoint)
{
    UniValue cursor{UniValue::VOBJ};
    cursor.pushKV("cursor_version", 1);
    cursor.pushKV("bestblock", tip.GetBlockHash().GetHex());
    cursor.pushKV("height", static_cast<int64_t>(tip.nHeight));
    cursor.pushKV("asset_id", asset_id.ToString());
    cursor.pushKV("filters_hash", filters_hash.ToString());
    cursor.pushKV("txid", outpoint.hash.GetHex());
    cursor.pushKV("vout", static_cast<int64_t>(outpoint.n));
    return cursor;
}

static void ThrowIfActiveChainTipChangedDuringBitplusScan(ChainstateManager& chainman, const CBlockIndex& expected_tip)
{
    LOCK(cs_main);
    const CBlockIndex* current_tip{chainman.ActiveChainstate().m_chain.Tip()};
    if (current_tip == nullptr ||
        current_tip->nHeight != expected_tip.nHeight ||
        current_tip->GetBlockHash() != expected_tip.GetBlockHash()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "active chain tip changed during scan; retry");
    }
}

static UniValue BitplusChainSnapshotToJSON(const CBlockIndex& tip)
{
    UniValue chain_snapshot{UniValue::VOBJ};
    chain_snapshot.pushKV("height", static_cast<int64_t>(tip.nHeight));
    chain_snapshot.pushKV("bestblock", tip.GetBlockHash().GetHex());
    return chain_snapshot;
}

static void WriteHashString(HashWriter& writer, std::string_view value);
static void WriteAssetScanFiltersForHash(HashWriter& writer, const BitplusAssetScanFilters& filters);
static void WriteOptionalAssetScanCursorForHash(HashWriter& writer, const std::optional<BitplusAssetScanCursor>& cursor);

static RPCMethod scanbitplusassetutxos()
{
    return RPCMethod{
        "scanbitplusassetutxos",
        "Scan the confirmed UTXO set for Bitplus asset outputs by asset id.\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id to scan for."},
            {"max_results", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum number of matching UTXOs to return."},
            {"filters", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional asset commitment filters.", {
                {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Only return this asset type: issuance, transfer, or burn."},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only return outputs with this metadata commitment hash."},
                {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only return outputs with this member hash."},
                {"min_confirmations", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Only return UTXOs with at least this many confirmations."},
            }},
            {"cursor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Continuation cursor returned by a previous incomplete scan page.", {
                {"cursor_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Cursor schema version. Current version is 1."},
                {"bestblock", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Best block hash from the previous scan page."},
                {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Chain height from the previous scan page."},
                {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id from the previous scan page."},
                {"filters_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Applied filters hash from the previous scan page."},
                {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id of the last UTXO returned by the previous page."},
                {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index of the last UTXO returned by the previous page."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "report_type", "Report type: asset_utxo_scan."},
            {RPCResult::Type::NUM, "report_version", "Report schema version."},
            {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::STR_HEX, "member_hash", /*optional=*/true, "Filtered member hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::OBJ, "cursor", /*optional=*/true, "Applied continuation cursor.", {
                {RPCResult::Type::NUM, "cursor_version", "Cursor schema version."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash from the cursor."},
                {RPCResult::Type::NUM, "height", "Chain height from the cursor."},
                {RPCResult::Type::STR_HEX, "asset_id", "Asset id from the cursor."},
                {RPCResult::Type::STR_HEX, "filters_hash", "Applied filters hash from the cursor."},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id from the cursor."},
                {RPCResult::Type::NUM, "vout", "Output index from the cursor."},
            }},
            {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
            {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
            {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
            {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this scan.", {
                {RPCResult::Type::NUM, "height", "Chain height."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
            }},
            {RPCResult::Type::STR_HEX, "reconciliation_hash", "Deterministic hash committing to the scan snapshot, filters, completeness, and returned UTXOs."},
            {RPCResult::Type::STR_HEX, "scan_summary_hash", "Deterministic hash committing to scan_summary."},
            {RPCResult::Type::OBJ, "scan_summary", "Compact operator summary of the bounded scan page.", {
                {RPCResult::Type::STR, "report_type", "Report type."},
                {RPCResult::Type::NUM, "summary_version", "Compact summary schema version."},
                {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ANY, "field", "A filter field."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::OBJ_DYN, "cursor", /*optional=*/true, "Applied continuation cursor.", {
                    {RPCResult::Type::ANY, "field", "A cursor field."},
                }},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this scan.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the scan chain snapshot."},
                {RPCResult::Type::NUM, "max_results", "Maximum number of matching UTXOs requested."},
                {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
                {RPCResult::Type::BOOL, "cursor_applied", "Whether this page started from a continuation cursor."},
                {RPCResult::Type::BOOL, "complete", "Whether the scan completed before max_results was reached."},
                {RPCResult::Type::BOOL, "has_next_cursor", "Whether a next_cursor was returned."},
                {RPCResult::Type::NUM, "matches", "Number of returned matching UTXOs."},
                {RPCResult::Type::STR_HEX, "reconciliation_hash", "Hash for this bounded scan page."},
            }},
            {RPCResult::Type::BOOL, "complete", "Whether the scan completed before max_results was reached."},
            {RPCResult::Type::OBJ, "next_cursor", /*optional=*/true, "Cursor to pass into the next call when complete is false.", {
                {RPCResult::Type::NUM, "cursor_version", "Cursor schema version."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash for this scan page."},
                {RPCResult::Type::NUM, "height", "Chain height for this scan page."},
                {RPCResult::Type::STR_HEX, "asset_id", "Asset id for this scan page."},
                {RPCResult::Type::STR_HEX, "filters_hash", "Applied filters hash for this scan page."},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id of the last returned UTXO."},
                {RPCResult::Type::NUM, "vout", "Output index of the last returned UTXO."},
            }},
            {RPCResult::Type::NUM, "matches", "Number of returned matching UTXOs."},
            {RPCResult::Type::ARR, "utxos", "Matching Bitplus asset UTXOs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction id."},
                    {RPCResult::Type::NUM, "vout", "Output index."},
                    {RPCResult::Type::STR_AMOUNT, "amount", "BTP amount on the output."},
                    {RPCResult::Type::STR_HEX, "scriptPubKey", "Output scriptPubKey."},
                    {RPCResult::Type::BOOL, "coinbase", "Whether this UTXO is from a coinbase transaction."},
                    {RPCResult::Type::NUM, "height", "Block height containing this UTXO."},
                    {RPCResult::Type::STR_HEX, "blockhash", "Block hash containing this UTXO."},
                    {RPCResult::Type::NUM, "confirmations", "Confirmations for this UTXO."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded Bitplus asset commitment.", {
                        {RPCResult::Type::ANY, "field", "A decoded commitment field."},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("scanbitplusassetutxos", "\"asset_id\" 100")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const uint256 asset_id{ParseHashV(request.params[0], "asset_id")};
            if (asset_id.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must not be null");

            const int64_t max_results_signed{request.params[1].isNull() ? 100 : request.params[1].getInt<int64_t>()};
            if (max_results_signed <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_results must be greater than zero");
            if (max_results_signed > 10000) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_results must not exceed 10000");
            const size_t max_results{static_cast<size_t>(max_results_signed)};

            const BitplusAssetScanFilters filters{ParseBitplusAssetScanFilters(request.params[2])};
            const UniValue filters_json{filters.ToJSON()};
            const uint256 filters_hash{CompactReportHash("BitplusAssetScanFiltersV1", filters_json)};
            const std::optional<BitplusAssetScanCursor> scan_cursor{
                request.params[3].isNull() ? std::optional<BitplusAssetScanCursor>{} :
                    std::optional<BitplusAssetScanCursor>{ParseBitplusAssetScanCursor(request.params[3])}
            };

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            std::unique_ptr<CCoinsViewCursor> cursor;
            const CBlockIndex* tip{nullptr};
            {
                LOCK(cs_main);
                Chainstate& active_chainstate{chainman.ActiveChainstate()};
                active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            }
            if (scan_cursor.has_value()) {
                if (scan_cursor->bestblock != tip->GetBlockHash() || scan_cursor->height != tip->nHeight) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor does not match the active chain tip");
                }
                if (scan_cursor->asset_id != asset_id) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor asset_id does not match requested asset_id");
                }
                if (scan_cursor->filters_hash != filters_hash) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor filters_hash does not match requested filters");
                }
            }

            int64_t searched{0};
            bool complete{true};
            bool cursor_found{!scan_cursor.has_value()};
            std::optional<COutPoint> last_returned;
            UniValue utxos{UniValue::VARR};
            HashWriter reconciliation_writer{};
            WriteHashString(reconciliation_writer, "BitplusAssetUtxoScanV1");
            reconciliation_writer << tip->GetBlockHash();
            reconciliation_writer << static_cast<int64_t>(tip->nHeight);
            reconciliation_writer << asset_id;
            reconciliation_writer << static_cast<uint64_t>(max_results);
            WriteAssetScanFiltersForHash(reconciliation_writer, filters);
            WriteOptionalAssetScanCursorForHash(reconciliation_writer, scan_cursor);
            while (cursor->Valid()) {
                COutPoint outpoint;
                Coin coin;
                if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "UTXO cursor read failed");
                }
                ++searched;
                if (searched % 8192 == 0) node.rpc_interruption_point();

                if (!cursor_found) {
                    cursor_found = outpoint == scan_cursor->after;
                    cursor->Next();
                    continue;
                }

                const std::optional<bitplus::assets::AssetOutput> asset_output{
                    bitplus::assets::DecodeAssetOutput(coin.out, outpoint.n)
                };
                const int64_t confirmations{static_cast<int64_t>(tip->nHeight - coin.nHeight + 1)};
                if (asset_output.has_value() &&
                    asset_output->commitment.asset_id == asset_id &&
                    filters.Match(asset_output->commitment, confirmations)) {
                    const CBlockIndex& coin_block{*CHECK_NONFATAL(tip->GetAncestor(coin.nHeight))};
                    UniValue utxo{UniValue::VOBJ};
                    utxo.pushKV("txid", outpoint.hash.GetHex());
                    utxo.pushKV("vout", static_cast<int64_t>(outpoint.n));
                    utxo.pushKV("amount", ValueFromAmount(coin.out.nValue));
                    utxo.pushKV("scriptPubKey", HexStr(coin.out.scriptPubKey));
                    utxo.pushKV("coinbase", coin.IsCoinBase());
                    utxo.pushKV("height", static_cast<int64_t>(coin.nHeight));
                    utxo.pushKV("blockhash", coin_block.GetBlockHash().GetHex());
                    utxo.pushKV("confirmations", confirmations);
                    utxo.pushKV("commitment", DecodedAssetCommitmentToJSON(*asset_output));
                    utxos.push_back(std::move(utxo));
                    reconciliation_writer << outpoint;
                    reconciliation_writer << coin.out.nValue;
                    reconciliation_writer << coin.out.scriptPubKey;
                    reconciliation_writer << coin.IsCoinBase();
                    reconciliation_writer << static_cast<int64_t>(coin.nHeight);
                    reconciliation_writer << coin_block.GetBlockHash();
                    reconciliation_writer << bitplus::assets::EncodeAssetCommitment(asset_output->commitment);
                    reconciliation_writer << asset_output->locking_script;
                    last_returned = outpoint;
                    if (utxos.size() >= max_results) {
                        complete = false;
                        break;
                    }
                }
                cursor->Next();
            }
            if (!cursor_found) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor outpoint was not found in the active UTXO set");
            ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);

            UniValue result{UniValue::VOBJ};
            result.pushKV("report_type", "asset_utxo_scan");
            result.pushKV("report_version", 1);
            result.pushKV("asset_id", asset_id.ToString());
            result.pushKV("filters", filters_json);
            if (scan_cursor.has_value()) result.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
            result.pushKV("searched_txouts", searched);
            result.pushKV("height", static_cast<int64_t>(tip->nHeight));
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("chain_snapshot", BitplusChainSnapshotToJSON(*tip));
            reconciliation_writer << searched;
            reconciliation_writer << complete;
            reconciliation_writer << static_cast<int64_t>(utxos.size());
            const std::string reconciliation_hash{reconciliation_writer.GetSHA256().ToString()};
            result.pushKV("reconciliation_hash", reconciliation_hash);
            UniValue scan_summary{UniValue::VOBJ};
            scan_summary.pushKV("report_type", "asset_utxo_scan");
            scan_summary.pushKV("summary_version", 1);
            scan_summary.pushKV("asset_id", asset_id.ToString());
            scan_summary.pushKV("filters", filters_json);
            scan_summary.pushKV("filters_hash", filters_hash.ToString());
            if (scan_cursor.has_value()) scan_summary.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
            scan_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            scan_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            scan_summary.pushKV("chain_snapshot", chain_snapshot);
            scan_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshotV1", chain_snapshot).ToString());
            scan_summary.pushKV("max_results", static_cast<int64_t>(max_results));
            scan_summary.pushKV("searched_txouts", searched);
            scan_summary.pushKV("cursor_applied", scan_cursor.has_value());
            scan_summary.pushKV("complete", complete);
            scan_summary.pushKV("has_next_cursor", !complete && last_returned.has_value());
            scan_summary.pushKV("matches", static_cast<int64_t>(utxos.size()));
            scan_summary.pushKV("reconciliation_hash", reconciliation_hash);
            result.pushKV("scan_summary_hash", CompactReportHash("BitplusAssetUtxoScanSummaryV1", scan_summary).ToString());
            result.pushKV("scan_summary", std::move(scan_summary));
            result.pushKV("complete", complete);
            if (!complete && last_returned.has_value()) result.pushKV("next_cursor", BitplusAssetScanCursorToJSON(*tip, asset_id, filters_hash, *last_returned));
            result.pushKV("matches", static_cast<int64_t>(utxos.size()));
            result.pushKV("utxos", std::move(utxos));
            return result;
        },
    };
}

static UniValue AssetTypeCountersToJSON(const std::map<std::string, std::pair<int64_t, uint64_t>>& counters)
{
    UniValue result{UniValue::VOBJ};
    for (const auto& [type, stats] : counters) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("count", stats.first);
        entry.pushKV("amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(stats.second))});
        result.pushKV(type, std::move(entry));
    }
    return result;
}

static void WriteHashString(HashWriter& writer, std::string_view value)
{
    writer << std::vector<unsigned char>{value.begin(), value.end()};
}

static void WriteOptionalHash(HashWriter& writer, const std::optional<uint256>& value)
{
    writer << value.has_value();
    if (value.has_value()) writer << *value;
}

static void WriteAssetScanFiltersForHash(HashWriter& writer, const BitplusAssetScanFilters& filters)
{
    writer << filters.type.has_value();
    if (filters.type.has_value()) writer << static_cast<uint8_t>(*filters.type);
    WriteOptionalHash(writer, filters.metadata_hash);
    WriteOptionalHash(writer, filters.member_hash);
    writer << filters.min_confirmations.has_value();
    if (filters.min_confirmations.has_value()) writer << *filters.min_confirmations;
}

static void WriteOptionalAssetScanCursorForHash(HashWriter& writer, const std::optional<BitplusAssetScanCursor>& cursor)
{
    writer << cursor.has_value();
    if (!cursor.has_value()) return;
    writer << cursor->cursor_version;
    writer << cursor->bestblock;
    writer << cursor->height;
    writer << cursor->asset_id;
    writer << cursor->filters_hash;
    writer << cursor->after;
}

static void WriteCountersForHash(HashWriter& writer, const std::map<std::string, std::pair<int64_t, uint64_t>>& counters)
{
    writer << static_cast<uint64_t>(counters.size());
    for (const auto& [key, stats] : counters) {
        WriteHashString(writer, key);
        writer << stats.first;
        writer << stats.second;
    }
}

static RPCMethod getbitplusassetstats()
{
    return RPCMethod{
        "getbitplusassetstats",
        "Scan the confirmed UTXO set and summarize live Bitplus asset outputs by asset id.\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id to summarize."},
            {"filters", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional asset commitment filters.", {
                {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Only include this asset type: issuance, transfer, or burn."},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only include outputs with this metadata commitment hash."},
                {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only include outputs with this member hash."},
                {"min_confirmations", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Only include UTXOs with at least this many confirmations."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "report_type", "Report type: asset_stats."},
            {RPCResult::Type::NUM, "report_version", "Report schema version."},
            {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::STR_HEX, "member_hash", /*optional=*/true, "Filtered member hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
            {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
            {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
            {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                {RPCResult::Type::NUM, "height", "Chain height."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
            }},
            {RPCResult::Type::STR_HEX, "reconciliation_hash", "Deterministic hash committing to the scan snapshot, filters, totals, and breakdowns."},
            {RPCResult::Type::STR_HEX, "reconciliation_summary_hash", "Deterministic hash committing to reconciliation_summary."},
            {RPCResult::Type::OBJ, "reconciliation_summary", "Compact operator summary of the reconciliation report.", {
                {RPCResult::Type::STR, "report_type", "Report type."},
                {RPCResult::Type::NUM, "summary_version", "Compact summary schema version."},
                {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ANY, "field", "A filter field."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the stats chain snapshot."},
                {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
                {RPCResult::Type::NUM, "utxo_count", "Number of matching live asset UTXOs."},
                {RPCResult::Type::NUM, "min_confirmations_observed", /*optional=*/true, "Lowest confirmation count among matching UTXOs."},
                {RPCResult::Type::NUM, "max_confirmations_observed", /*optional=*/true, "Highest confirmation count among matching UTXOs."},
                {RPCResult::Type::NUM, "total_amount", "Total matching asset units."},
                {RPCResult::Type::NUM, "issued_amount", "Total matching live issuance-carrier units."},
                {RPCResult::Type::NUM, "held_amount", "Total matching live transfer units held by members."},
                {RPCResult::Type::NUM, "burned_amount", "Total matching live burn-carrier units."},
                {RPCResult::Type::NUM, "outstanding_amount", "Issued minus burned amount for the matching lifecycle view, or zero on underflow."},
                {RPCResult::Type::BOOL, "supply_underflow", "Whether burned amount exceeds issued amount in the matching lifecycle view."},
                {RPCResult::Type::BOOL, "holder_supply_balanced", "Whether held transfer amount equals issued minus burned without overflow or underflow."},
                {RPCResult::Type::NUM, "holder_count", "Number of member hashes with matching live transfer UTXOs."},
                {RPCResult::Type::BOOL, "overflow", "Whether amount aggregation overflowed."},
                {RPCResult::Type::STR_HEX, "reconciliation_hash", "Hash for this full reconciliation report."},
            }},
            {RPCResult::Type::NUM, "utxo_count", "Number of matching live asset UTXOs."},
            {RPCResult::Type::NUM, "min_confirmations_observed", /*optional=*/true, "Lowest confirmation count among matching UTXOs."},
            {RPCResult::Type::NUM, "max_confirmations_observed", /*optional=*/true, "Highest confirmation count among matching UTXOs."},
            {RPCResult::Type::NUM, "total_amount", "Total matching asset units."},
            {RPCResult::Type::NUM, "issued_amount", "Total matching live issuance-carrier units."},
            {RPCResult::Type::NUM, "held_amount", "Total matching live transfer units held by members."},
            {RPCResult::Type::NUM, "burned_amount", "Total matching live burn-carrier units."},
            {RPCResult::Type::NUM, "outstanding_amount", "Issued minus burned amount for the matching lifecycle view, or zero on underflow."},
            {RPCResult::Type::BOOL, "supply_underflow", "Whether burned amount exceeds issued amount in the matching lifecycle view."},
            {RPCResult::Type::BOOL, "holder_supply_balanced", "Whether held transfer amount equals issued minus burned without overflow or underflow."},
            {RPCResult::Type::NUM, "holder_supply_delta", "Signed held-minus-outstanding amount; negative means holders are short, positive means holders exceed lifecycle supply."},
            {RPCResult::Type::NUM, "holder_count", "Number of member hashes with matching live transfer UTXOs."},
            {RPCResult::Type::BOOL, "overflow", "Whether amount aggregation overflowed."},
            {RPCResult::Type::OBJ_DYN, "by_type", "Count and amount by asset commitment type.", {
                {RPCResult::Type::OBJ, "type", "Per-type stats.", {
                    {RPCResult::Type::NUM, "count", "UTXO count."},
                    {RPCResult::Type::NUM, "amount", "Asset amount."},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "by_metadata_hash", "Count and amount by metadata hash.", {
                {RPCResult::Type::OBJ, "metadata_hash", "Per-metadata stats.", {
                    {RPCResult::Type::NUM, "count", "UTXO count."},
                    {RPCResult::Type::NUM, "amount", "Asset amount."},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "by_member_hash", "Count and amount by member hash.", {
                {RPCResult::Type::OBJ, "member_hash", "Per-member stats.", {
                    {RPCResult::Type::NUM, "count", "UTXO count."},
                    {RPCResult::Type::NUM, "amount", "Asset amount."},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "by_holder_member_hash", "Transfer-only count and amount by holder member hash.", {
                {RPCResult::Type::OBJ, "member_hash", "Per-holder stats.", {
                    {RPCResult::Type::NUM, "count", "Transfer UTXO count."},
                    {RPCResult::Type::NUM, "amount", "Held transfer amount."},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("getbitplusassetstats", "\"asset_id\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const uint256 asset_id{ParseHashV(request.params[0], "asset_id")};
            if (asset_id.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must not be null");
            const BitplusAssetScanFilters filters{ParseBitplusAssetScanFilters(request.params[1])};

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            std::unique_ptr<CCoinsViewCursor> cursor;
            const CBlockIndex* tip{nullptr};
            {
                LOCK(cs_main);
                Chainstate& active_chainstate{chainman.ActiveChainstate()};
                active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            }

            int64_t searched{0};
            int64_t utxo_count{0};
            uint64_t total_amount{0};
            uint64_t issued_amount{0};
            uint64_t held_amount{0};
            uint64_t burned_amount{0};
            bool overflow{false};
            std::map<std::string, std::pair<int64_t, uint64_t>> by_type;
            std::map<std::string, std::pair<int64_t, uint64_t>> by_metadata;
            std::map<std::string, std::pair<int64_t, uint64_t>> by_member;
            std::map<std::string, std::pair<int64_t, uint64_t>> by_holder_member;
            std::optional<int64_t> min_confirmations_observed;
            std::optional<int64_t> max_confirmations_observed;

            auto add_amount = [&](uint64_t& target, uint64_t amount) {
                const uint64_t previous{target};
                target += amount;
                if (target < previous) overflow = true;
            };
            auto add_counter = [&](std::map<std::string, std::pair<int64_t, uint64_t>>& counters, const std::string& key, uint64_t amount) {
                auto& entry{counters[key]};
                ++entry.first;
                add_amount(entry.second, amount);
            };

            while (cursor->Valid()) {
                COutPoint outpoint;
                Coin coin;
                if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "UTXO cursor read failed");
                }
                ++searched;
                if (searched % 8192 == 0) node.rpc_interruption_point();

                const std::optional<bitplus::assets::AssetOutput> asset_output{
                    bitplus::assets::DecodeAssetOutput(coin.out, outpoint.n)
                };
                const int64_t confirmations{static_cast<int64_t>(tip->nHeight - coin.nHeight + 1)};
                if (asset_output.has_value() &&
                    asset_output->commitment.asset_id == asset_id &&
                    filters.Match(asset_output->commitment, confirmations)) {
                    ++utxo_count;
                    min_confirmations_observed = min_confirmations_observed.has_value() ? std::min(*min_confirmations_observed, confirmations) : confirmations;
                    max_confirmations_observed = max_confirmations_observed.has_value() ? std::max(*max_confirmations_observed, confirmations) : confirmations;
                    add_amount(total_amount, asset_output->commitment.amount);
                    switch (asset_output->commitment.type) {
                    case bitplus::assets::AssetCommitmentType::ISSUANCE:
                        add_amount(issued_amount, asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::TRANSFER:
                        add_amount(held_amount, asset_output->commitment.amount);
                        add_counter(by_holder_member, asset_output->commitment.member_hash.ToString(), asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::BURN:
                        add_amount(burned_amount, asset_output->commitment.amount);
                        break;
                    }
                    add_counter(by_type, AssetCommitmentTypeToString(asset_output->commitment.type), asset_output->commitment.amount);
                    add_counter(by_metadata, asset_output->commitment.metadata_hash.ToString(), asset_output->commitment.amount);
                    add_counter(by_member, asset_output->commitment.member_hash.ToString(), asset_output->commitment.amount);
                }
                cursor->Next();
            }
            ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);

            UniValue result{UniValue::VOBJ};
            result.pushKV("report_type", "asset_stats");
            result.pushKV("report_version", 1);
            result.pushKV("asset_id", asset_id.ToString());
            result.pushKV("filters", filters.ToJSON());
            result.pushKV("searched_txouts", searched);
            result.pushKV("height", static_cast<int64_t>(tip->nHeight));
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("chain_snapshot", BitplusChainSnapshotToJSON(*tip));
            result.pushKV("utxo_count", utxo_count);
            if (min_confirmations_observed.has_value()) result.pushKV("min_confirmations_observed", *min_confirmations_observed);
            if (max_confirmations_observed.has_value()) result.pushKV("max_confirmations_observed", *max_confirmations_observed);
            result.pushKV("total_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(total_amount))});
            result.pushKV("issued_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(issued_amount))});
            result.pushKV("held_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(held_amount))});
            result.pushKV("burned_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(burned_amount))});
            const bool supply_underflow{burned_amount > issued_amount};
            const uint64_t outstanding_amount{supply_underflow ? 0 : issued_amount - burned_amount};
            HashWriter reconciliation_writer{};
            WriteHashString(reconciliation_writer, "BitplusAssetStatsV1");
            reconciliation_writer << tip->GetBlockHash();
            reconciliation_writer << static_cast<int64_t>(tip->nHeight);
            reconciliation_writer << asset_id;
            WriteAssetScanFiltersForHash(reconciliation_writer, filters);
            reconciliation_writer << min_confirmations_observed.has_value();
            if (min_confirmations_observed.has_value()) reconciliation_writer << *min_confirmations_observed;
            reconciliation_writer << max_confirmations_observed.has_value();
            if (max_confirmations_observed.has_value()) reconciliation_writer << *max_confirmations_observed;
            reconciliation_writer << searched;
            reconciliation_writer << utxo_count;
            reconciliation_writer << total_amount;
            reconciliation_writer << issued_amount;
            reconciliation_writer << held_amount;
            reconciliation_writer << burned_amount;
            reconciliation_writer << outstanding_amount;
            reconciliation_writer << supply_underflow;
            reconciliation_writer << (!overflow && !supply_underflow && held_amount == outstanding_amount);
            reconciliation_writer << static_cast<int64_t>(by_holder_member.size());
            reconciliation_writer << overflow;
            WriteCountersForHash(reconciliation_writer, by_type);
            WriteCountersForHash(reconciliation_writer, by_metadata);
            WriteCountersForHash(reconciliation_writer, by_member);
            WriteCountersForHash(reconciliation_writer, by_holder_member);

            result.pushKV("outstanding_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(outstanding_amount))});
            result.pushKV("supply_underflow", supply_underflow);
            result.pushKV("holder_supply_balanced", !overflow && !supply_underflow && held_amount == outstanding_amount);
            result.pushKV("holder_supply_delta", UniValue{UniValue::VNUM, SignedMovementString(held_amount, outstanding_amount)});
            result.pushKV("holder_count", static_cast<int64_t>(by_holder_member.size()));
            result.pushKV("overflow", overflow);
            const std::string reconciliation_hash{reconciliation_writer.GetSHA256().ToString()};
            result.pushKV("reconciliation_hash", reconciliation_hash);
            UniValue reconciliation_summary{UniValue::VOBJ};
            reconciliation_summary.pushKV("report_type", "asset_stats");
            reconciliation_summary.pushKV("summary_version", 1);
            reconciliation_summary.pushKV("asset_id", asset_id.ToString());
            const UniValue filters_json{filters.ToJSON()};
            reconciliation_summary.pushKV("filters", filters_json);
            reconciliation_summary.pushKV("filters_hash", CompactReportHash("BitplusAssetScanFiltersV1", filters_json).ToString());
            reconciliation_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            reconciliation_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            reconciliation_summary.pushKV("chain_snapshot", chain_snapshot);
            reconciliation_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshotV1", chain_snapshot).ToString());
            reconciliation_summary.pushKV("searched_txouts", searched);
            reconciliation_summary.pushKV("utxo_count", utxo_count);
            if (min_confirmations_observed.has_value()) reconciliation_summary.pushKV("min_confirmations_observed", *min_confirmations_observed);
            if (max_confirmations_observed.has_value()) reconciliation_summary.pushKV("max_confirmations_observed", *max_confirmations_observed);
            reconciliation_summary.pushKV("total_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(total_amount))});
            reconciliation_summary.pushKV("issued_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(issued_amount))});
            reconciliation_summary.pushKV("held_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(held_amount))});
            reconciliation_summary.pushKV("burned_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(burned_amount))});
            reconciliation_summary.pushKV("outstanding_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(outstanding_amount))});
            reconciliation_summary.pushKV("supply_underflow", supply_underflow);
            reconciliation_summary.pushKV("holder_supply_balanced", !overflow && !supply_underflow && held_amount == outstanding_amount);
            reconciliation_summary.pushKV("holder_count", static_cast<int64_t>(by_holder_member.size()));
            reconciliation_summary.pushKV("overflow", overflow);
            reconciliation_summary.pushKV("reconciliation_hash", reconciliation_hash);
            result.pushKV("reconciliation_summary_hash", CompactReportHash("BitplusAssetStatsSummaryV1", reconciliation_summary).ToString());
            result.pushKV("reconciliation_summary", std::move(reconciliation_summary));
            result.pushKV("by_type", AssetTypeCountersToJSON(by_type));
            result.pushKV("by_metadata_hash", AssetTypeCountersToJSON(by_metadata));
            result.pushKV("by_member_hash", AssetTypeCountersToJSON(by_member));
            result.pushKV("by_holder_member_hash", AssetTypeCountersToJSON(by_holder_member));
            return result;
        },
    };
}

struct BitplusMemberAssetStats
{
    int64_t utxo_count{0};
    uint64_t total_amount{0};
    uint64_t issued_amount{0};
    uint64_t held_amount{0};
    uint64_t burned_amount{0};
    std::optional<int64_t> min_confirmations_observed;
    std::optional<int64_t> max_confirmations_observed;
    std::map<std::string, std::pair<int64_t, uint64_t>> by_type;
    std::map<std::string, std::pair<int64_t, uint64_t>> by_metadata;
};

static RPCMethod getbitplusmemberassetstats()
{
    return RPCMethod{
        "getbitplusmemberassetstats",
        "Scan the confirmed UTXO set and summarize live Bitplus asset outputs by member hash, grouped by asset id.\n",
        {
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Member hash to summarize."},
            {"filters", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional asset commitment filters.", {
                {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only include outputs for this asset id."},
                {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Only include this asset type: issuance, transfer, or burn."},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only include outputs with this metadata commitment hash."},
                {"min_confirmations", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Only include UTXOs with at least this many confirmations."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "report_type", "Report type: member_asset_stats."},
            {RPCResult::Type::NUM, "report_version", "Report schema version."},
            {RPCResult::Type::STR_HEX, "member_hash", "The requested member hash."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Filtered asset id."},
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
            {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
            {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
            {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                {RPCResult::Type::NUM, "height", "Chain height."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
            }},
            {RPCResult::Type::STR_HEX, "reconciliation_hash", "Deterministic hash committing to the scan snapshot, filters, totals, and per-asset breakdowns."},
            {RPCResult::Type::STR_HEX, "reconciliation_summary_hash", "Deterministic hash committing to reconciliation_summary."},
            {RPCResult::Type::OBJ, "reconciliation_summary", "Compact operator summary of the reconciliation report.", {
                {RPCResult::Type::STR, "report_type", "Report type."},
                {RPCResult::Type::NUM, "summary_version", "Compact summary schema version."},
                {RPCResult::Type::STR_HEX, "member_hash", "The requested member hash."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ANY, "field", "A filter field."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the stats chain snapshot."},
                {RPCResult::Type::NUM, "searched_txouts", "Number of UTXOs scanned."},
                {RPCResult::Type::NUM, "asset_count", "Number of matching asset ids."},
                {RPCResult::Type::NUM, "utxo_count", "Number of matching live asset UTXOs."},
                {RPCResult::Type::NUM, "min_confirmations_observed", /*optional=*/true, "Lowest confirmation count among matching UTXOs."},
                {RPCResult::Type::NUM, "max_confirmations_observed", /*optional=*/true, "Highest confirmation count among matching UTXOs."},
                {RPCResult::Type::NUM, "total_amount", "Total matching asset units."},
                {RPCResult::Type::NUM, "issued_amount", "Total matching live issuance-carrier units."},
                {RPCResult::Type::NUM, "held_amount", "Total matching live transfer units held by this member."},
                {RPCResult::Type::NUM, "burned_amount", "Total matching live burn-carrier units."},
                {RPCResult::Type::NUM, "holder_asset_count", "Number of matching asset ids where this member has live transfer holdings."},
                {RPCResult::Type::BOOL, "overflow", "Whether amount aggregation overflowed."},
                {RPCResult::Type::STR_HEX, "reconciliation_hash", "Hash for this full reconciliation report."},
            }},
            {RPCResult::Type::NUM, "asset_count", "Number of matching asset ids."},
            {RPCResult::Type::NUM, "utxo_count", "Number of matching live asset UTXOs."},
            {RPCResult::Type::NUM, "min_confirmations_observed", /*optional=*/true, "Lowest confirmation count among matching UTXOs."},
            {RPCResult::Type::NUM, "max_confirmations_observed", /*optional=*/true, "Highest confirmation count among matching UTXOs."},
            {RPCResult::Type::NUM, "total_amount", "Total matching asset units."},
            {RPCResult::Type::NUM, "issued_amount", "Total matching live issuance-carrier units."},
            {RPCResult::Type::NUM, "held_amount", "Total matching live transfer units held by this member."},
            {RPCResult::Type::NUM, "burned_amount", "Total matching live burn-carrier units."},
            {RPCResult::Type::NUM, "holder_asset_count", "Number of matching asset ids where this member has live transfer holdings."},
            {RPCResult::Type::BOOL, "overflow", "Whether amount aggregation overflowed."},
            {RPCResult::Type::OBJ_DYN, "assets", "Per-asset reconciliation stats.", {
                {RPCResult::Type::OBJ, "asset_id", "Per-asset stats.", {
                    {RPCResult::Type::NUM, "utxo_count", "UTXO count."},
                    {RPCResult::Type::NUM, "min_confirmations_observed", /*optional=*/true, "Lowest confirmation count among matching UTXOs for this asset."},
                    {RPCResult::Type::NUM, "max_confirmations_observed", /*optional=*/true, "Highest confirmation count among matching UTXOs for this asset."},
                    {RPCResult::Type::NUM, "total_amount", "Asset amount."},
                    {RPCResult::Type::NUM, "issued_amount", "Live issuance-carrier amount."},
                    {RPCResult::Type::NUM, "held_amount", "Live transfer amount held by this member."},
                    {RPCResult::Type::NUM, "burned_amount", "Live burn-carrier amount."},
                    {RPCResult::Type::BOOL, "is_holder", "Whether this member has live transfer holdings for this asset."},
                    {RPCResult::Type::OBJ_DYN, "by_type", "Count and amount by asset commitment type.", {
                        {RPCResult::Type::OBJ, "type", "Per-type stats.", {
                            {RPCResult::Type::NUM, "count", "UTXO count."},
                            {RPCResult::Type::NUM, "amount", "Asset amount."},
                        }},
                    }},
                    {RPCResult::Type::OBJ_DYN, "by_metadata_hash", "Count and amount by metadata hash.", {
                        {RPCResult::Type::OBJ, "metadata_hash", "Per-metadata stats.", {
                            {RPCResult::Type::NUM, "count", "UTXO count."},
                            {RPCResult::Type::NUM, "amount", "Asset amount."},
                        }},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("getbitplusmemberassetstats", "\"member_hash\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const uint256 member_hash{ParseHashV(request.params[0], "member_hash")};
            if (member_hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "member_hash must not be null");

            const BitplusAssetScanFilters filters{ParseBitplusAssetScanFilters(request.params[1], /*allow_asset_id_filter=*/true)};
            std::optional<uint256> asset_id_filter;
            if (!request.params[1].isNull()) {
                const UniValue& filters_in{request.params[1].get_obj()};
                const UniValue& asset_id_value{filters_in.find_value("asset_id")};
                if (!asset_id_value.isNull()) {
                    asset_id_filter = ParseHashV(asset_id_value, "asset_id");
                    if (asset_id_filter->IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must not be null");
                }
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            std::unique_ptr<CCoinsViewCursor> cursor;
            const CBlockIndex* tip{nullptr};
            {
                LOCK(cs_main);
                Chainstate& active_chainstate{chainman.ActiveChainstate()};
                active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            }

            int64_t searched{0};
            int64_t utxo_count{0};
            uint64_t total_amount{0};
            uint64_t issued_amount{0};
            uint64_t held_amount{0};
            uint64_t burned_amount{0};
            bool overflow{false};
            std::optional<int64_t> min_confirmations_observed;
            std::optional<int64_t> max_confirmations_observed;
            std::map<std::string, BitplusMemberAssetStats> assets;

            auto add_amount = [&](uint64_t& target, uint64_t amount) {
                const uint64_t previous{target};
                target += amount;
                if (target < previous) overflow = true;
            };
            auto add_counter = [&](std::map<std::string, std::pair<int64_t, uint64_t>>& counters, const std::string& key, uint64_t amount) {
                auto& entry{counters[key]};
                ++entry.first;
                add_amount(entry.second, amount);
            };

            while (cursor->Valid()) {
                COutPoint outpoint;
                Coin coin;
                if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "UTXO cursor read failed");
                }
                ++searched;
                if (searched % 8192 == 0) node.rpc_interruption_point();

                const std::optional<bitplus::assets::AssetOutput> asset_output{
                    bitplus::assets::DecodeAssetOutput(coin.out, outpoint.n)
                };
                const int64_t confirmations{static_cast<int64_t>(tip->nHeight - coin.nHeight + 1)};
                if (asset_output.has_value() &&
                    asset_output->commitment.member_hash == member_hash &&
                    (!asset_id_filter.has_value() || asset_output->commitment.asset_id == *asset_id_filter) &&
                    filters.Match(asset_output->commitment, confirmations)) {
                    ++utxo_count;
                    min_confirmations_observed = min_confirmations_observed.has_value() ? std::min(*min_confirmations_observed, confirmations) : confirmations;
                    max_confirmations_observed = max_confirmations_observed.has_value() ? std::max(*max_confirmations_observed, confirmations) : confirmations;
                    add_amount(total_amount, asset_output->commitment.amount);
                    switch (asset_output->commitment.type) {
                    case bitplus::assets::AssetCommitmentType::ISSUANCE:
                        add_amount(issued_amount, asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::TRANSFER:
                        add_amount(held_amount, asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::BURN:
                        add_amount(burned_amount, asset_output->commitment.amount);
                        break;
                    }

                    const std::string asset_id{asset_output->commitment.asset_id.ToString()};
                    BitplusMemberAssetStats& asset_stats{assets[asset_id]};
                    ++asset_stats.utxo_count;
                    asset_stats.min_confirmations_observed = asset_stats.min_confirmations_observed.has_value() ? std::min(*asset_stats.min_confirmations_observed, confirmations) : confirmations;
                    asset_stats.max_confirmations_observed = asset_stats.max_confirmations_observed.has_value() ? std::max(*asset_stats.max_confirmations_observed, confirmations) : confirmations;
                    add_amount(asset_stats.total_amount, asset_output->commitment.amount);
                    switch (asset_output->commitment.type) {
                    case bitplus::assets::AssetCommitmentType::ISSUANCE:
                        add_amount(asset_stats.issued_amount, asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::TRANSFER:
                        add_amount(asset_stats.held_amount, asset_output->commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::BURN:
                        add_amount(asset_stats.burned_amount, asset_output->commitment.amount);
                        break;
                    }
                    add_counter(asset_stats.by_type, AssetCommitmentTypeToString(asset_output->commitment.type), asset_output->commitment.amount);
                    add_counter(asset_stats.by_metadata, asset_output->commitment.metadata_hash.ToString(), asset_output->commitment.amount);
                }
                cursor->Next();
            }
            ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);

            UniValue filters_json{filters.ToJSON()};
            if (asset_id_filter.has_value()) filters_json.pushKV("asset_id", asset_id_filter->ToString());

            UniValue assets_json{UniValue::VOBJ};
            int64_t holder_asset_count{0};
            HashWriter reconciliation_writer{};
            WriteHashString(reconciliation_writer, "BitplusMemberAssetStatsV1");
            reconciliation_writer << tip->GetBlockHash();
            reconciliation_writer << static_cast<int64_t>(tip->nHeight);
            reconciliation_writer << member_hash;
            WriteAssetScanFiltersForHash(reconciliation_writer, filters);
            WriteOptionalHash(reconciliation_writer, asset_id_filter);
            reconciliation_writer << min_confirmations_observed.has_value();
            if (min_confirmations_observed.has_value()) reconciliation_writer << *min_confirmations_observed;
            reconciliation_writer << max_confirmations_observed.has_value();
            if (max_confirmations_observed.has_value()) reconciliation_writer << *max_confirmations_observed;
            reconciliation_writer << searched;
            reconciliation_writer << utxo_count;
            reconciliation_writer << total_amount;
            reconciliation_writer << issued_amount;
            reconciliation_writer << held_amount;
            reconciliation_writer << burned_amount;
            reconciliation_writer << overflow;
            reconciliation_writer << static_cast<uint64_t>(assets.size());
            for (const auto& [asset_id, stats] : assets) {
                UniValue asset_json{UniValue::VOBJ};
                asset_json.pushKV("utxo_count", stats.utxo_count);
                if (stats.min_confirmations_observed.has_value()) asset_json.pushKV("min_confirmations_observed", *stats.min_confirmations_observed);
                if (stats.max_confirmations_observed.has_value()) asset_json.pushKV("max_confirmations_observed", *stats.max_confirmations_observed);
                asset_json.pushKV("total_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(stats.total_amount))});
                asset_json.pushKV("issued_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(stats.issued_amount))});
                asset_json.pushKV("held_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(stats.held_amount))});
                asset_json.pushKV("burned_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(stats.burned_amount))});
                const bool is_holder{stats.held_amount > 0};
                if (is_holder) ++holder_asset_count;
                asset_json.pushKV("is_holder", is_holder);
                asset_json.pushKV("by_type", AssetTypeCountersToJSON(stats.by_type));
                asset_json.pushKV("by_metadata_hash", AssetTypeCountersToJSON(stats.by_metadata));
                assets_json.pushKV(asset_id, std::move(asset_json));

                WriteHashString(reconciliation_writer, asset_id);
                reconciliation_writer << stats.utxo_count;
                reconciliation_writer << stats.min_confirmations_observed.has_value();
                if (stats.min_confirmations_observed.has_value()) reconciliation_writer << *stats.min_confirmations_observed;
                reconciliation_writer << stats.max_confirmations_observed.has_value();
                if (stats.max_confirmations_observed.has_value()) reconciliation_writer << *stats.max_confirmations_observed;
                reconciliation_writer << stats.total_amount;
                reconciliation_writer << stats.issued_amount;
                reconciliation_writer << stats.held_amount;
                reconciliation_writer << stats.burned_amount;
                reconciliation_writer << is_holder;
                WriteCountersForHash(reconciliation_writer, stats.by_type);
                WriteCountersForHash(reconciliation_writer, stats.by_metadata);
            }
            reconciliation_writer << holder_asset_count;

            UniValue result{UniValue::VOBJ};
            result.pushKV("report_type", "member_asset_stats");
            result.pushKV("report_version", 1);
            result.pushKV("member_hash", member_hash.ToString());
            result.pushKV("filters", filters_json);
            result.pushKV("searched_txouts", searched);
            result.pushKV("height", static_cast<int64_t>(tip->nHeight));
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("chain_snapshot", BitplusChainSnapshotToJSON(*tip));
            const std::string reconciliation_hash{reconciliation_writer.GetSHA256().ToString()};
            result.pushKV("reconciliation_hash", reconciliation_hash);
            result.pushKV("asset_count", static_cast<int64_t>(assets.size()));
            result.pushKV("utxo_count", utxo_count);
            if (min_confirmations_observed.has_value()) result.pushKV("min_confirmations_observed", *min_confirmations_observed);
            if (max_confirmations_observed.has_value()) result.pushKV("max_confirmations_observed", *max_confirmations_observed);
            result.pushKV("total_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(total_amount))});
            result.pushKV("issued_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(issued_amount))});
            result.pushKV("held_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(held_amount))});
            result.pushKV("burned_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(burned_amount))});
            result.pushKV("holder_asset_count", holder_asset_count);
            result.pushKV("overflow", overflow);
            UniValue reconciliation_summary{UniValue::VOBJ};
            reconciliation_summary.pushKV("report_type", "member_asset_stats");
            reconciliation_summary.pushKV("summary_version", 1);
            reconciliation_summary.pushKV("member_hash", member_hash.ToString());
            reconciliation_summary.pushKV("filters", filters_json);
            reconciliation_summary.pushKV("filters_hash", CompactReportHash("BitplusMemberAssetStatsFiltersV1", filters_json).ToString());
            reconciliation_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            reconciliation_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            reconciliation_summary.pushKV("chain_snapshot", chain_snapshot);
            reconciliation_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshotV1", chain_snapshot).ToString());
            reconciliation_summary.pushKV("searched_txouts", searched);
            reconciliation_summary.pushKV("asset_count", static_cast<int64_t>(assets.size()));
            reconciliation_summary.pushKV("utxo_count", utxo_count);
            if (min_confirmations_observed.has_value()) reconciliation_summary.pushKV("min_confirmations_observed", *min_confirmations_observed);
            if (max_confirmations_observed.has_value()) reconciliation_summary.pushKV("max_confirmations_observed", *max_confirmations_observed);
            reconciliation_summary.pushKV("total_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(total_amount))});
            reconciliation_summary.pushKV("issued_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(issued_amount))});
            reconciliation_summary.pushKV("held_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(held_amount))});
            reconciliation_summary.pushKV("burned_amount", UniValue{UniValue::VNUM, strprintf("%llu", static_cast<unsigned long long>(burned_amount))});
            reconciliation_summary.pushKV("holder_asset_count", holder_asset_count);
            reconciliation_summary.pushKV("overflow", overflow);
            reconciliation_summary.pushKV("reconciliation_hash", reconciliation_hash);
            result.pushKV("reconciliation_summary_hash", CompactReportHash("BitplusMemberAssetStatsSummaryV1", reconciliation_summary).ToString());
            result.pushKV("reconciliation_summary", std::move(reconciliation_summary));
            result.pushKV("assets", std::move(assets_json));
            return result;
        },
    };
}

static RPCMethod createbitplusassetmetadata()
{
    return RPCMethod{
        "createbitplusassetmetadata",
        "Build a Bitplus asset metadata commitment script.\n",
        {
            {"issuer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Issuer identifier hash."},
            {"document_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Off-chain document hash."},
            {"rules_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Whitelist rules commitment hash."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "payload", "The raw BTPMETA payload."},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
            {RPCResult::Type::STR_HEX, "commitment_hash", "The metadata commitment hash."},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetmetadata", "\"issuer_id\" \"document_hash\" \"rules_hash\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetMetadataCommitment commitment{
                .issuer_id = ParseHashV(request.params[0], "issuer_id"),
                .document_hash = ParseHashV(request.params[1], "document_hash"),
                .rules_hash = ParseHashV(request.params[2], "rules_hash"),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetMetadataOutput(
                bitplus::assets::AssetMetadataOutput{.output_index = 0, .commitment = commitment}));
            UniValue result{UniValue::VOBJ};
            result.pushKV("payload", HexStr(bitplus::assets::EncodeAssetMetadataCommitment(commitment)));
            result.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetMetadataCommitmentScript(commitment)));
            result.pushKV("commitment_hash", bitplus::assets::HashAssetMetadataCommitment(commitment).ToString());
            return result;
        },
    };
}

static RPCMethod createbitplusassetwhitelist()
{
    return RPCMethod{
        "createbitplusassetwhitelist",
        "Build a Bitplus asset whitelist rules commitment script.\n",
        {
            {"list_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Whitelist identifier hash."},
            {"admin_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Admin key or policy hash."},
            {"members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root of approved members."},
            {"flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Whitelist rule flags."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "payload", "The raw BTPWLST payload."},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
            {RPCResult::Type::STR_HEX, "commitment_hash", "The whitelist commitment hash."},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetwhitelist", "\"list_id\" \"admin_key_hash\" \"members_root\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const int64_t flags{request.params[3].isNull() ? 0 : request.params[3].getInt<int64_t>()};
            if (flags < 0 || flags > std::numeric_limits<uint32_t>::max()) throw JSONRPCError(RPC_INVALID_PARAMETER, "flags out of range");
            const bitplus::assets::AssetWhitelistCommitment commitment{
                .list_id = ParseHashV(request.params[0], "list_id"),
                .admin_key_hash = ParseHashV(request.params[1], "admin_key_hash"),
                .members_root = ParseHashV(request.params[2], "members_root"),
                .flags = static_cast<uint32_t>(flags),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistOutput(
                bitplus::assets::AssetWhitelistOutput{.output_index = 0, .commitment = commitment}));
            UniValue result{UniValue::VOBJ};
            result.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistCommitment(commitment)));
            result.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistCommitmentScript(commitment)));
            result.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistCommitment(commitment).ToString());
            return result;
        },
    };
}

static RPCMethod createbitplusassetwhitelistroot()
{
    return RPCMethod{
        "createbitplusassetwhitelistroot",
        "Compute a Bitplus whitelist members root and, optionally, a proof path for one member.\n",
        {
            {"members", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of approved settlement member hashes, in whitelist order.", {
                {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A settlement member hash."},
            }},
            {"proof_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional member index for which to return a Merkle proof path."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "members_root", "Merkle root for the supplied member set."},
            {RPCResult::Type::NUM, "member_count", "Number of supplied members."},
            {RPCResult::Type::NUM, "proof_index", /*optional=*/true, "Proof leaf index, if requested."},
            {RPCResult::Type::STR_HEX, "member_hash", /*optional=*/true, "Member hash at proof_index, if requested."},
            {RPCResult::Type::ARR, "merkle_path", /*optional=*/true, "Merkle sibling path for proof_index, if requested.", {
                {RPCResult::Type::STR_HEX, "sibling", "A Merkle sibling hash."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetwhitelistroot", "'[\"member_hash\"]' 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const UniValue& members_param{request.params[0].get_array()};
            const auto& member_values{members_param.getValues()};
            if (member_values.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "members must not be empty");
            if (member_values.size() > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "too many members");
            }

            std::vector<uint256> members;
            members.reserve(member_values.size());
            for (const UniValue& member : member_values) {
                uint256 member_hash{ParseHashV(member, "members")};
                if (member_hash.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "member hash must not be null");
                members.push_back(member_hash);
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("members_root", bitplus::assets::ComputeWhitelistMembersRoot(members).ToString());
            result.pushKV("member_count", static_cast<int64_t>(members.size()));

            if (!request.params[1].isNull()) {
                const int64_t proof_index{request.params[1].getInt<int64_t>()};
                if (proof_index < 0 || static_cast<uint64_t>(proof_index) >= members.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_index out of range");
                }
                const std::vector<uint256> path{bitplus::assets::ComputeWhitelistMerklePath(members, static_cast<uint32_t>(proof_index))};
                UniValue merkle_path{UniValue::VARR};
                for (const uint256& sibling : path) {
                    merkle_path.push_back(sibling.ToString());
                }
                result.pushKV("proof_index", proof_index);
                result.pushKV("member_hash", members[proof_index].ToString());
                result.pushKV("merkle_path", std::move(merkle_path));
            }

            return result;
        },
    };
}

static RPCMethod createbitplusassetissuance()
{
    return RPCMethod{
        "createbitplusassetissuance",
        "Build a consistent Bitplus native asset issuance bundle.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The first input txid anchoring the issuance."},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The first input output index anchoring the issuance."},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Issued asset amount, as a positive integer."},
            {"issuer_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Issuer identifier hash."},
            {"document_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Off-chain document hash."},
            {"list_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Whitelist identifier hash."},
            {"admin_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Admin key or policy hash."},
            {"members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root of approved members."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement member hash for the issuance carrier."},
            {"flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Whitelist rule flags."},
            {"locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner issuance carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "asset_id", "The deterministic asset id."},
            {RPCResult::Type::OBJ, "whitelist", "Whitelist commitment output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPWLST payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The whitelist commitment hash."},
            }},
            {RPCResult::Type::OBJ, "metadata", "Metadata commitment output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPMETA payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The metadata commitment hash."},
            }},
            {RPCResult::Type::OBJ, "issuance", "Spendable issuance asset carrier output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The issuance asset commitment hash."},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetissuance", "\"txid\" 0 100 \"issuer_id\" \"document_hash\" \"list_id\" \"admin_key_hash\" \"members_root\" \"member_hash\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const int vout{request.params[1].getInt<int>()};
            if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");

            const int64_t flags{request.params[9].isNull() ? 0 : request.params[9].getInt<int64_t>()};
            if (flags < 0 || flags > std::numeric_limits<uint32_t>::max()) throw JSONRPCError(RPC_INVALID_PARAMETER, "flags out of range");

            const bitplus::assets::AssetWhitelistCommitment whitelist{
                .list_id = ParseHashV(request.params[5], "list_id"),
                .admin_key_hash = ParseHashV(request.params[6], "admin_key_hash"),
                .members_root = ParseHashV(request.params[7], "members_root"),
                .flags = static_cast<uint32_t>(flags),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistOutput(
                bitplus::assets::AssetWhitelistOutput{.output_index = 0, .commitment = whitelist}));

            const bitplus::assets::AssetMetadataCommitment metadata{
                .issuer_id = ParseHashV(request.params[3], "issuer_id"),
                .document_hash = ParseHashV(request.params[4], "document_hash"),
                .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetMetadataOutput(
                bitplus::assets::AssetMetadataOutput{.output_index = 0, .commitment = metadata}));

            const uint256 metadata_hash{bitplus::assets::HashAssetMetadataCommitment(metadata)};
            const uint256 asset_id{bitplus::assets::ComputeAssetId(
                metadata_hash,
                COutPoint{Txid::FromUint256(ParseHashV(request.params[0], "txid")), static_cast<uint32_t>(vout)})};

            const bitplus::assets::AssetCommitment issuance{
                .type = bitplus::assets::AssetCommitmentType::ISSUANCE,
                .asset_id = asset_id,
                .amount = ParseAssetAmount(request.params[2]),
                .metadata_hash = metadata_hash,
                .member_hash = ParseHashV(request.params[8], "member_hash"),
            };

            CScript issuance_script_pub_key;
            if (request.params[10].isNull()) {
                issuance_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(issuance);
            } else {
                const std::vector<unsigned char> locking_script_bytes{ParseHexV(request.params[10], "locking_script")};
                issuance_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(
                    issuance,
                    CScript{locking_script_bytes.begin(), locking_script_bytes.end()});
            }
            ValidateConstructedAssetScript(issuance_script_pub_key);

            UniValue whitelist_obj{UniValue::VOBJ};
            whitelist_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistCommitment(whitelist)));
            whitelist_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistCommitmentScript(whitelist)));
            whitelist_obj.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistCommitment(whitelist).ToString());

            UniValue metadata_obj{UniValue::VOBJ};
            metadata_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetMetadataCommitment(metadata)));
            metadata_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetMetadataCommitmentScript(metadata)));
            metadata_obj.pushKV("commitment_hash", metadata_hash.ToString());

            UniValue result{UniValue::VOBJ};
            result.pushKV("asset_id", asset_id.ToString());
            result.pushKV("whitelist", std::move(whitelist_obj));
            result.pushKV("metadata", std::move(metadata_obj));
            result.pushKV("issuance", AssetCommitmentToJSON(issuance, issuance_script_pub_key));
            return result;
        },
    };
}

static RPCMethod createbitplusasset()
{
    return RPCMethod{
        "createbitplusasset",
        "Build a spendable Bitplus native asset carrier script.\n",
        {
            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset commitment type: issuance, transfer, or burn."},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id."},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset amount, as a positive integer."},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "BTPMETA commitment hash."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement member hash."},
            {"locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
            {RPCResult::Type::STR_HEX, "commitment_hash", "The asset commitment hash."},
            {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
        }},
        RPCExamples{HelpExampleCli("createbitplusasset", "\"transfer\" \"asset_id\" 100 \"metadata_hash\" \"member_hash\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment commitment{
                .type = ParseAssetCommitmentType(request.params[0].get_str()),
                .asset_id = ParseHashV(request.params[1], "asset_id"),
                .amount = ParseAssetAmount(request.params[2]),
                .metadata_hash = ParseHashV(request.params[3], "metadata_hash"),
                .member_hash = ParseHashV(request.params[4], "member_hash"),
            };
            CScript script_pub_key;
            if (request.params[5].isNull()) {
                script_pub_key = bitplus::assets::BuildAssetCommitmentScript(commitment);
            } else {
                const std::vector<unsigned char> locking_script_bytes{ParseHexV(request.params[5], "locking_script")};
                script_pub_key = bitplus::assets::BuildAssetCommitmentScript(
                    commitment,
                    CScript{locking_script_bytes.begin(), locking_script_bytes.end()});
            }
            ValidateConstructedAssetScript(script_pub_key);
            return AssetCommitmentToJSON(commitment, script_pub_key);
        },
    };
}

static RPCMethod createbitplusassettransfer()
{
    return RPCMethod{
        "createbitplusassettransfer",
        "Build a Bitplus native asset transfer bundle with its whitelist proof.\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id."},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Transfer asset amount, as a positive integer."},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "BTPMETA commitment hash."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement member hash."},
            {"asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The asset transfer output index authorized by the proof."},
            {"proof_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Merkle proof leaf index."},
            {"merkle_path", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of Merkle sibling hashes.", {
                {"sibling", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A Merkle sibling hash."},
            }},
            {"members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Expected whitelist members root."},
            {"locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner transfer carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "members_root", "The verified whitelist members root."},
            {RPCResult::Type::OBJ, "transfer", "Spendable transfer asset carrier output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The transfer asset commitment hash."},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
            }},
            {RPCResult::Type::OBJ, "proof", "Whitelist membership proof output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPWPROOF payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "members_root", "The root computed from this proof."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The proof commitment hash."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusassettransfer", "\"asset_id\" 100 \"metadata_hash\" \"member_hash\" 0 0 \"[]\" \"members_root\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment transfer{
                .type = bitplus::assets::AssetCommitmentType::TRANSFER,
                .asset_id = ParseHashV(request.params[0], "asset_id"),
                .amount = ParseAssetAmount(request.params[1]),
                .metadata_hash = ParseHashV(request.params[2], "metadata_hash"),
                .member_hash = ParseHashV(request.params[3], "member_hash"),
            };

            CScript transfer_script_pub_key;
            if (request.params[8].isNull()) {
                transfer_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(transfer);
            } else {
                const std::vector<unsigned char> locking_script_bytes{ParseHexV(request.params[8], "locking_script")};
                transfer_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(
                    transfer,
                    CScript{locking_script_bytes.begin(), locking_script_bytes.end()});
            }
            ValidateConstructedAssetScript(transfer_script_pub_key);

            const uint32_t asset_output_index{ParseOutputIndex(request.params[4], "asset_output_index")};
            const uint32_t proof_index{ParseOutputIndex(request.params[5], "proof_index")};
            std::vector<uint256> path;
            for (const UniValue& sibling : request.params[6].get_array().getValues()) {
                path.push_back(ParseHashV(sibling, "merkle_path"));
            }

            const bitplus::assets::AssetWhitelistProofCommitment proof{
                .asset_output_index = asset_output_index,
                .member_hash = transfer.member_hash,
                .proof_index = proof_index,
                .merkle_path = std::move(path),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistProofOutput(
                bitplus::assets::AssetWhitelistProofOutput{.output_index = 0, .commitment = proof}));

            const uint256 expected_members_root{ParseHashV(request.params[7], "members_root")};
            if (expected_members_root.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-members-null");
            const uint256 computed_members_root{bitplus::assets::ComputeWhitelistMembersRoot(proof)};
            if (computed_members_root != expected_members_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-proof-root-mismatch");
            }

            UniValue proof_obj{UniValue::VOBJ};
            proof_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistProofCommitment(proof)));
            proof_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistProofCommitmentScript(proof)));
            proof_obj.pushKV("members_root", computed_members_root.ToString());
            proof_obj.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(proof).ToString());

            UniValue result{UniValue::VOBJ};
            result.pushKV("members_root", computed_members_root.ToString());
            result.pushKV("transfer", AssetCommitmentToJSON(transfer, transfer_script_pub_key));
            result.pushKV("proof", std::move(proof_obj));
            return result;
        },
    };
}

static RPCMethod createbitplusassetburn()
{
    return RPCMethod{
        "createbitplusassetburn",
        "Build a Bitplus native asset burn carrier script.\n",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id."},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Burned asset amount, as a positive integer."},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "BTPMETA commitment hash."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement member hash authorizing/recording the burn."},
            {"locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner burn carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
            {RPCResult::Type::STR_HEX, "commitment_hash", "The burn asset commitment hash."},
            {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetburn", "\"asset_id\" 100 \"metadata_hash\" \"member_hash\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment burn{
                .type = bitplus::assets::AssetCommitmentType::BURN,
                .asset_id = ParseHashV(request.params[0], "asset_id"),
                .amount = ParseAssetAmount(request.params[1]),
                .metadata_hash = ParseHashV(request.params[2], "metadata_hash"),
                .member_hash = ParseHashV(request.params[3], "member_hash"),
            };

            CScript burn_script_pub_key;
            if (request.params[4].isNull()) {
                burn_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(burn);
            } else {
                const std::vector<unsigned char> locking_script_bytes{ParseHexV(request.params[4], "locking_script")};
                burn_script_pub_key = bitplus::assets::BuildAssetCommitmentScript(
                    burn,
                    CScript{locking_script_bytes.begin(), locking_script_bytes.end()});
            }
            ValidateConstructedAssetScript(burn_script_pub_key);
            return AssetCommitmentToJSON(burn, burn_script_pub_key);
        },
    };
}

static RPCMethod createbitplusassetwhitelistproof()
{
    return RPCMethod{
        "createbitplusassetwhitelistproof",
        "Build a Bitplus whitelist membership proof commitment script.\n",
        {
            {"asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The asset transfer output index this proof authorizes."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement member hash."},
            {"proof_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Merkle proof leaf index."},
            {"merkle_path", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of Merkle sibling hashes.", {
                {"sibling", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A Merkle sibling hash."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "payload", "The raw BTPWPROOF payload."},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
            {RPCResult::Type::STR_HEX, "members_root", "The root computed from this proof."},
            {RPCResult::Type::STR_HEX, "commitment_hash", "The proof commitment hash."},
        }},
        RPCExamples{HelpExampleCli("createbitplusassetwhitelistproof", "0 \"member_hash\" 0 \"[]\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const int output_index{request.params[0].getInt<int>()};
            const int proof_index{request.params[2].getInt<int>()};
            if (output_index < 0 || proof_index < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "indexes must be non-negative");
            std::vector<uint256> path;
            for (const UniValue& sibling : request.params[3].get_array().getValues()) {
                path.push_back(ParseHashV(sibling, "merkle_path"));
            }
            const bitplus::assets::AssetWhitelistProofCommitment commitment{
                .asset_output_index = static_cast<uint32_t>(output_index),
                .member_hash = ParseHashV(request.params[1], "member_hash"),
                .proof_index = static_cast<uint32_t>(proof_index),
                .merkle_path = std::move(path),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistProofOutput(
                bitplus::assets::AssetWhitelistProofOutput{.output_index = 0, .commitment = commitment}));
            UniValue result{UniValue::VOBJ};
            result.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistProofCommitment(commitment)));
            result.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistProofCommitmentScript(commitment)));
            result.pushKV("members_root", bitplus::assets::ComputeWhitelistMembersRoot(commitment).ToString());
            result.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(commitment).ToString());
            return result;
        },
    };
}

static RPCMethod createbitplusdvp()
{
    return RPCMethod{
        "createbitplusdvp",
        "Build a Bitplus delivery-versus-payment bundle with transfer, proof, and settlement leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer asset id."},
            {"asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Transfer asset amount."},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer metadata commitment hash."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer member hash."},
            {"asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact asset transfer output index."},
            {"proof_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Merkle proof leaf index."},
            {"merkle_path", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of Merkle sibling hashes.", {
                {"sibling", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A Merkle sibling hash."},
            }},
            {"members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Expected whitelist members root."},
            {"payment_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact BTP payment output scriptPubKey hex."},
            {"payment_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact BTP payment amount."},
            {"payment_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact BTP payment output index."},
            {"asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner transfer carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "members_root", "The verified whitelist members root."},
            {RPCResult::Type::OBJ, "transfer", "Spendable transfer asset carrier output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The transfer asset commitment hash."},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
            }},
            {RPCResult::Type::OBJ, "proof", "Whitelist membership proof output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPWPROOF payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "members_root", "The root computed from this proof."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The proof commitment hash."},
            }},
            {RPCResult::Type::OBJ, "settlement_leaf", "DvP settlement Tapscript leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The DvP settlement leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusdvp", "\"auth_script\" \"asset_id\" 100 \"metadata_hash\" \"member_hash\" 0 0 \"[]\" \"members_root\" \"payment_script_pub_key\" 1.0 1")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment transfer{
                .type = bitplus::assets::AssetCommitmentType::TRANSFER,
                .asset_id = ParseHashV(request.params[1], "asset_id"),
                .amount = ParseAssetAmount(request.params[2]),
                .metadata_hash = ParseHashV(request.params[3], "metadata_hash"),
                .member_hash = ParseHashV(request.params[4], "member_hash"),
            };
            const AssetScriptWithLocking transfer_script{
                BuildAssetScriptWithOptionalLockingScript(transfer, request.params[12], "asset_locking_script")
            };

            const uint32_t asset_output_index{ParseOutputIndex(request.params[5], "asset_output_index")};
            const uint32_t proof_index{ParseOutputIndex(request.params[6], "proof_index")};
            std::vector<uint256> path;
            for (const UniValue& sibling : request.params[7].get_array().getValues()) {
                path.push_back(ParseHashV(sibling, "merkle_path"));
            }

            const bitplus::assets::AssetWhitelistProofCommitment proof{
                .asset_output_index = asset_output_index,
                .member_hash = transfer.member_hash,
                .proof_index = proof_index,
                .merkle_path = std::move(path),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistProofOutput(
                bitplus::assets::AssetWhitelistProofOutput{.output_index = 0, .commitment = proof}));

            const uint256 expected_members_root{ParseHashV(request.params[8], "members_root")};
            if (expected_members_root.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-members-null");
            const uint256 computed_members_root{bitplus::assets::ComputeWhitelistMembersRoot(proof)};
            if (computed_members_root != expected_members_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-proof-root-mismatch");
            }

            UniValue proof_obj{UniValue::VOBJ};
            proof_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistProofCommitment(proof)));
            proof_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistProofCommitmentScript(proof)));
            proof_obj.pushKV("members_root", computed_members_root.ToString());
            proof_obj.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(proof).ToString());

            UniValue result{UniValue::VOBJ};
            result.pushKV("members_root", computed_members_root.ToString());
            result.pushKV("transfer", AssetCommitmentToJSON(transfer, transfer_script.script_pub_key));
            result.pushKV("proof", std::move(proof_obj));
            result.pushKV("settlement_leaf", ContractLeafToJSON(bitplus::contracts::BuildDvPSettlementLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                transfer,
                transfer_script.locking_script,
                asset_output_index,
                ParseScriptHex(request.params[9], "payment_script_pub_key"),
                ParsePositiveBtpAmount(request.params[10], "payment_amount"),
                ParseOutputIndex(request.params[11], "payment_output_index"))));
            return result;
        },
    };
}

static RPCMethod createbitpluspvp()
{
    return RPCMethod{
        "createbitpluspvp",
        "Build a Bitplus payment-versus-payment bundle with two transfers, proofs, and settlement leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"first_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer asset id."},
            {"first_asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "First transfer asset amount."},
            {"first_metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer metadata commitment hash."},
            {"first_member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer member hash."},
            {"first_asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact first asset transfer output index."},
            {"first_proof_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "First Merkle proof leaf index."},
            {"first_merkle_path", RPCArg::Type::ARR, RPCArg::Optional::NO, "First Merkle sibling path.", {
                {"sibling", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A Merkle sibling hash."},
            }},
            {"first_members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Expected first whitelist members root."},
            {"second_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer asset id."},
            {"second_asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Second transfer asset amount."},
            {"second_metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer metadata commitment hash."},
            {"second_member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer member hash."},
            {"second_asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact second asset transfer output index."},
            {"second_proof_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Second Merkle proof leaf index."},
            {"second_merkle_path", RPCArg::Type::ARR, RPCArg::Optional::NO, "Second Merkle sibling path.", {
                {"sibling", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A Merkle sibling hash."},
            }},
            {"second_members_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Expected second whitelist members root."},
            {"first_asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner first transfer carrier locking script."},
            {"second_asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner second transfer carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "first_transfer", "First spendable transfer asset carrier output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The transfer asset commitment hash."},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
            }},
            {RPCResult::Type::OBJ, "first_proof", "First whitelist membership proof output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPWPROOF payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "members_root", "The root computed from this proof."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The proof commitment hash."},
            }},
            {RPCResult::Type::OBJ, "second_transfer", "Second spendable transfer asset carrier output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPASSET payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The spendable asset carrier scriptPubKey."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The transfer asset commitment hash."},
                {RPCResult::Type::STR_HEX, "asset_id", "The asset id."},
            }},
            {RPCResult::Type::OBJ, "second_proof", "Second whitelist membership proof output.", {
                {RPCResult::Type::STR_HEX, "payload", "The raw BTPWPROOF payload."},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The OP_RETURN scriptPubKey."},
                {RPCResult::Type::STR_HEX, "members_root", "The root computed from this proof."},
                {RPCResult::Type::STR_HEX, "commitment_hash", "The proof commitment hash."},
            }},
            {RPCResult::Type::OBJ, "settlement_leaf", "PvP settlement Tapscript leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The PvP settlement leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitpluspvp", "\"auth_script\" \"asset_id_a\" 100 \"metadata_hash_a\" \"member_hash_a\" 0 0 \"[]\" \"members_root_a\" \"asset_id_b\" 200 \"metadata_hash_b\" \"member_hash_b\" 1 0 \"[]\" \"members_root_b\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment first_transfer{
                .type = bitplus::assets::AssetCommitmentType::TRANSFER,
                .asset_id = ParseHashV(request.params[1], "first_asset_id"),
                .amount = ParseAssetAmount(request.params[2]),
                .metadata_hash = ParseHashV(request.params[3], "first_metadata_hash"),
                .member_hash = ParseHashV(request.params[4], "first_member_hash"),
            };
            const AssetScriptWithLocking first_transfer_script{
                BuildAssetScriptWithOptionalLockingScript(first_transfer, request.params[17], "first_asset_locking_script")
            };

            std::vector<uint256> first_path;
            for (const UniValue& sibling : request.params[7].get_array().getValues()) {
                first_path.push_back(ParseHashV(sibling, "first_merkle_path"));
            }
            const bitplus::assets::AssetWhitelistProofCommitment first_proof{
                .asset_output_index = ParseOutputIndex(request.params[5], "first_asset_output_index"),
                .member_hash = first_transfer.member_hash,
                .proof_index = ParseOutputIndex(request.params[6], "first_proof_index"),
                .merkle_path = std::move(first_path),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistProofOutput(
                bitplus::assets::AssetWhitelistProofOutput{.output_index = 0, .commitment = first_proof}));
            const uint256 first_expected_root{ParseHashV(request.params[8], "first_members_root")};
            if (first_expected_root.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-members-null");
            const uint256 first_computed_root{bitplus::assets::ComputeWhitelistMembersRoot(first_proof)};
            if (first_computed_root != first_expected_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "first-asset-whitelist-proof-root-mismatch");
            }

            const bitplus::assets::AssetCommitment second_transfer{
                .type = bitplus::assets::AssetCommitmentType::TRANSFER,
                .asset_id = ParseHashV(request.params[9], "second_asset_id"),
                .amount = ParseAssetAmount(request.params[10]),
                .metadata_hash = ParseHashV(request.params[11], "second_metadata_hash"),
                .member_hash = ParseHashV(request.params[12], "second_member_hash"),
            };
            const AssetScriptWithLocking second_transfer_script{
                BuildAssetScriptWithOptionalLockingScript(second_transfer, request.params[18], "second_asset_locking_script")
            };

            std::vector<uint256> second_path;
            for (const UniValue& sibling : request.params[15].get_array().getValues()) {
                second_path.push_back(ParseHashV(sibling, "second_merkle_path"));
            }
            const bitplus::assets::AssetWhitelistProofCommitment second_proof{
                .asset_output_index = ParseOutputIndex(request.params[13], "second_asset_output_index"),
                .member_hash = second_transfer.member_hash,
                .proof_index = ParseOutputIndex(request.params[14], "second_proof_index"),
                .merkle_path = std::move(second_path),
            };
            ThrowIfInvalidAssetResult(bitplus::assets::ValidateAssetWhitelistProofOutput(
                bitplus::assets::AssetWhitelistProofOutput{.output_index = 0, .commitment = second_proof}));
            const uint256 second_expected_root{ParseHashV(request.params[16], "second_members_root")};
            if (second_expected_root.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset-whitelist-members-null");
            const uint256 second_computed_root{bitplus::assets::ComputeWhitelistMembersRoot(second_proof)};
            if (second_computed_root != second_expected_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "second-asset-whitelist-proof-root-mismatch");
            }

            UniValue first_proof_obj{UniValue::VOBJ};
            first_proof_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistProofCommitment(first_proof)));
            first_proof_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistProofCommitmentScript(first_proof)));
            first_proof_obj.pushKV("members_root", first_computed_root.ToString());
            first_proof_obj.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(first_proof).ToString());

            UniValue second_proof_obj{UniValue::VOBJ};
            second_proof_obj.pushKV("payload", HexStr(bitplus::assets::EncodeAssetWhitelistProofCommitment(second_proof)));
            second_proof_obj.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetWhitelistProofCommitmentScript(second_proof)));
            second_proof_obj.pushKV("members_root", second_computed_root.ToString());
            second_proof_obj.pushKV("commitment_hash", bitplus::assets::HashAssetWhitelistProofCommitment(second_proof).ToString());

            UniValue result{UniValue::VOBJ};
            result.pushKV("first_transfer", AssetCommitmentToJSON(first_transfer, first_transfer_script.script_pub_key));
            result.pushKV("first_proof", std::move(first_proof_obj));
            result.pushKV("second_transfer", AssetCommitmentToJSON(second_transfer, second_transfer_script.script_pub_key));
            result.pushKV("second_proof", std::move(second_proof_obj));
            result.pushKV("settlement_leaf", ContractLeafToJSON(bitplus::contracts::BuildPvPSettlementLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                first_transfer,
                first_transfer_script.locking_script,
                first_proof.asset_output_index,
                second_transfer,
                second_transfer_script.locking_script,
                second_proof.asset_output_index)));
            return result;
        },
    };
}

static RPCMethod createbitplusvault()
{
    return RPCMethod{
        "createbitplusvault",
        "Build Bitplus vault recovery and delayed-spend Tapscript leaves.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"recovery_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact recovery output scriptPubKey hex."},
            {"recovery_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact recovery BTP amount."},
            {"recovery_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact recovery output index."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay for the delayed spend path."},
            {"destination_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact delayed destination output scriptPubKey hex."},
            {"destination_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact delayed destination BTP amount."},
            {"destination_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact delayed destination output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "recovery_leaf", "Immediate vault recovery leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The vault recovery leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
            {RPCResult::Type::OBJ, "delayed_spend_leaf", "Delayed vault spend leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The delayed vault spend leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusvault", "\"auth_script\" \"recovery_script_pub_key\" 1.0 0 144 \"destination_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CScript authorization_script{ParseScriptHex(request.params[0], "authorization_script")};
            UniValue result{UniValue::VOBJ};
            result.pushKV("recovery_leaf", ContractLeafToJSON(bitplus::contracts::BuildVaultRecoveryLeaf(
                authorization_script,
                ParseScriptHex(request.params[1], "recovery_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "recovery_amount"),
                ParseOutputIndex(request.params[3], "recovery_output_index"))));
            result.pushKV("delayed_spend_leaf", ContractLeafToJSON(bitplus::contracts::BuildVaultDelayedSpendLeaf(
                authorization_script,
                ParseNonNegativeInt64(request.params[4], "relative_delay"),
                ParseScriptHex(request.params[5], "destination_script_pub_key"),
                ParsePositiveBtpAmount(request.params[6], "destination_amount"),
                ParseOutputIndex(request.params[7], "destination_output_index"))));
            return result;
        },
    };
}

static RPCMethod createbitplushtlc()
{
    return RPCMethod{
        "createbitplushtlc",
        "Build Bitplus HTLC claim and refund Tapscript leaves.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"secret_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA256 hash required by the claim path."},
            {"claim_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact claim output scriptPubKey hex."},
            {"claim_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact claim BTP amount."},
            {"claim_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact claim output index."},
            {"absolute_expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute CLTV expiry for the refund path."},
            {"refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact refund output scriptPubKey hex."},
            {"refund_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact refund BTP amount."},
            {"refund_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact refund output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "claim_leaf", "HTLC claim leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The HTLC claim leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
            {RPCResult::Type::OBJ, "refund_leaf", "HTLC refund leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The HTLC refund leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplushtlc", "\"auth_script\" \"secret_hash\" \"claim_script_pub_key\" 1.0 0 900000 \"refund_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CScript authorization_script{ParseScriptHex(request.params[0], "authorization_script")};
            UniValue result{UniValue::VOBJ};
            result.pushKV("claim_leaf", ContractLeafToJSON(bitplus::contracts::BuildHtlcClaimLeaf(
                authorization_script,
                ParseNonNullHash(request.params[1], "secret_hash"),
                ParseScriptHex(request.params[2], "claim_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "claim_amount"),
                ParseOutputIndex(request.params[4], "claim_output_index"))));
            result.pushKV("refund_leaf", ContractLeafToJSON(bitplus::contracts::BuildHtlcRefundLeaf(
                authorization_script,
                ParseNonNegativeInt64(request.params[5], "absolute_expiry"),
                ParseScriptHex(request.params[6], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "refund_amount"),
                ParseOutputIndex(request.params[8], "refund_output_index"))));
            return result;
        },
    };
}

static RPCMethod createbitpluscollateral()
{
    return RPCMethod{
        "createbitpluscollateral",
        "Build Bitplus collateral release and delayed-return Tapscript leaves.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"release_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact release output scriptPubKey hex."},
            {"release_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact release BTP amount."},
            {"release_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact release output index."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay for the return path."},
            {"return_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact return output scriptPubKey hex."},
            {"return_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact return BTP amount."},
            {"return_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact return output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "release_leaf", "Collateral release leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The collateral release leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
            {RPCResult::Type::OBJ, "return_leaf", "Delayed collateral return leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The collateral return leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitpluscollateral", "\"auth_script\" \"release_script_pub_key\" 1.0 0 144 \"return_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CScript authorization_script{ParseScriptHex(request.params[0], "authorization_script")};
            UniValue result{UniValue::VOBJ};
            result.pushKV("release_leaf", ContractLeafToJSON(bitplus::contracts::BuildCollateralReleaseLeaf(
                authorization_script,
                ParseScriptHex(request.params[1], "release_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "release_amount"),
                ParseOutputIndex(request.params[3], "release_output_index"))));
            result.pushKV("return_leaf", ContractLeafToJSON(bitplus::contracts::BuildCollateralReturnLeaf(
                authorization_script,
                ParseNonNegativeInt64(request.params[4], "relative_delay"),
                ParseScriptHex(request.params[5], "return_script_pub_key"),
                ParsePositiveBtpAmount(request.params[6], "return_amount"),
                ParseOutputIndex(request.params[7], "return_output_index"))));
            return result;
        },
    };
}

static RPCMethod createbitplusrefundpaths()
{
    return RPCMethod{
        "createbitplusrefundpaths",
        "Build Bitplus absolute and relative refund Tapscript leaves.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"absolute_expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute CLTV expiry."},
            {"absolute_refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact absolute refund output scriptPubKey hex."},
            {"absolute_refund_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact absolute refund BTP amount."},
            {"absolute_refund_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact absolute refund output index."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay."},
            {"relative_refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact relative refund output scriptPubKey hex."},
            {"relative_refund_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact relative refund BTP amount."},
            {"relative_refund_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact relative refund output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "absolute_refund_leaf", "Absolute-expiry refund leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The absolute refund leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
            {RPCResult::Type::OBJ, "relative_refund_leaf", "Relative-expiry refund leaf.", {
                {RPCResult::Type::STR_HEX, "script", "The relative refund leaf script."},
                {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
            }},
        }},
        RPCExamples{HelpExampleCli("createbitplusrefundpaths", "\"auth_script\" 900000 \"absolute_refund_script_pub_key\" 1.0 0 144 \"relative_refund_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const CScript authorization_script{ParseScriptHex(request.params[0], "authorization_script")};
            UniValue result{UniValue::VOBJ};
            result.pushKV("absolute_refund_leaf", ContractLeafToJSON(bitplus::contracts::BuildAbsoluteRefundLeaf(
                authorization_script,
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "absolute_refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "absolute_refund_amount"),
                ParseOutputIndex(request.params[4], "absolute_refund_output_index"))));
            result.pushKV("relative_refund_leaf", ContractLeafToJSON(bitplus::contracts::BuildRelativeRefundLeaf(
                authorization_script,
                ParseNonNegativeInt64(request.params[5], "relative_delay"),
                ParseScriptHex(request.params[6], "relative_refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "relative_refund_amount"),
                ParseOutputIndex(request.params[8], "relative_refund_output_index"))));
            return result;
        },
    };
}

static RPCMethod createbitpluscovleaf()
{
    return RPCMethod{
        "createbitpluscovleaf",
        "Build a Bitplus OP_CHECKOUTPUTVERIFY covenant leaf fragment.\n",
        {
            {"script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact transaction output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The covenant script fragment."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the script fragment."},
        }},
        RPCExamples{HelpExampleCli("createbitpluscovleaf", "\"script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildCheckOutputVerifyScript(
                ParseScriptHex(request.params[0], "script_pub_key"),
                ParsePositiveBtpAmount(request.params[1], "amount"),
                ParseOutputIndex(request.params[2], "output_index")));
        },
    };
}

static RPCMethod createbitplusvaultrecoveryleaf()
{
    return RPCMethod{
        "createbitplusvaultrecoveryleaf",
        "Build a Bitplus vault recovery Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"recovery_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact recovery output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact recovery BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact recovery output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The vault recovery leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplusvaultrecoveryleaf", "\"auth_script\" \"recovery_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildVaultRecoveryLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseScriptHex(request.params[1], "recovery_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "amount"),
                ParseOutputIndex(request.params[3], "output_index")));
        },
    };
}

static RPCMethod createbitplusvaultdelayedleaf()
{
    return RPCMethod{
        "createbitplusvaultdelayedleaf",
        "Build a Bitplus delayed vault spend Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay."},
            {"destination_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact destination output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact destination BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact destination output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The delayed vault spend leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplusvaultdelayedleaf", "\"auth_script\" 144 \"destination_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildVaultDelayedSpendLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "destination_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

static RPCMethod createbitplushtlcclaimleaf()
{
    return RPCMethod{
        "createbitplushtlcclaimleaf",
        "Build a Bitplus HTLC claim Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"secret_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA256 hash required by the claim path."},
            {"claim_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact claim output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact claim BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact claim output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The HTLC claim leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplushtlcclaimleaf", "\"auth_script\" \"secret_hash\" \"claim_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildHtlcClaimLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNullHash(request.params[1], "secret_hash"),
                ParseScriptHex(request.params[2], "claim_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

static RPCMethod createbitplushtlcrefundleaf()
{
    return RPCMethod{
        "createbitplushtlcrefundleaf",
        "Build a Bitplus HTLC refund Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"absolute_expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute CLTV expiry."},
            {"refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact refund output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact refund BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact refund output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The HTLC refund leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplushtlcrefundleaf", "\"auth_script\" 900000 \"refund_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildHtlcRefundLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

static RPCMethod createbitplusdvpleaf()
{
    return RPCMethod{
        "createbitplusdvpleaf",
        "Build a Bitplus delivery-versus-payment Tapscript settlement leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer asset id."},
            {"asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Transfer asset amount."},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer metadata commitment hash."},
            {"member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transfer member hash."},
            {"asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact asset transfer output index."},
            {"payment_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact BTP payment output scriptPubKey hex."},
            {"payment_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact BTP payment amount."},
            {"payment_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact BTP payment output index."},
            {"asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner transfer carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The DvP settlement leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplusdvpleaf", "\"auth_script\" \"asset_id\" 100 \"metadata_hash\" \"member_hash\" 0 \"payment_script_pub_key\" 1.0 1")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment transfer{
                ParseTransferCommitment(request.params[1], request.params[2], request.params[3], request.params[4])
            };
            const AssetScriptWithLocking transfer_script{
                BuildAssetScriptWithOptionalLockingScript(transfer, request.params[9], "asset_locking_script")
            };
            return ContractLeafToJSON(bitplus::contracts::BuildDvPSettlementLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                transfer,
                transfer_script.locking_script,
                ParseOutputIndex(request.params[5], "asset_output_index"),
                ParseScriptHex(request.params[6], "payment_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "payment_amount"),
                ParseOutputIndex(request.params[8], "payment_output_index")));
        },
    };
}

static RPCMethod createbitpluspvpleaf()
{
    return RPCMethod{
        "createbitpluspvpleaf",
        "Build a Bitplus payment-versus-payment Tapscript settlement leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"first_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer asset id."},
            {"first_asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "First transfer asset amount."},
            {"first_metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer metadata commitment hash."},
            {"first_member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "First transfer member hash."},
            {"first_asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact first asset transfer output index."},
            {"second_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer asset id."},
            {"second_asset_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Second transfer asset amount."},
            {"second_metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer metadata commitment hash."},
            {"second_member_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Second transfer member hash."},
            {"second_asset_output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact second asset transfer output index."},
            {"first_asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner first transfer carrier locking script."},
            {"second_asset_locking_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional inner second transfer carrier locking script."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The PvP settlement leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitpluspvpleaf", "\"auth_script\" \"asset_id_a\" 100 \"metadata_hash_a\" \"member_hash_a\" 0 \"asset_id_b\" 200 \"metadata_hash_b\" \"member_hash_b\" 1")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const bitplus::assets::AssetCommitment first_transfer{
                ParseTransferCommitment(request.params[1], request.params[2], request.params[3], request.params[4])
            };
            const bitplus::assets::AssetCommitment second_transfer{
                ParseTransferCommitment(request.params[6], request.params[7], request.params[8], request.params[9])
            };
            const AssetScriptWithLocking first_transfer_script{
                BuildAssetScriptWithOptionalLockingScript(first_transfer, request.params[11], "first_asset_locking_script")
            };
            const AssetScriptWithLocking second_transfer_script{
                BuildAssetScriptWithOptionalLockingScript(second_transfer, request.params[12], "second_asset_locking_script")
            };
            return ContractLeafToJSON(bitplus::contracts::BuildPvPSettlementLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                first_transfer,
                first_transfer_script.locking_script,
                ParseOutputIndex(request.params[5], "first_asset_output_index"),
                second_transfer,
                second_transfer_script.locking_script,
                ParseOutputIndex(request.params[10], "second_asset_output_index")));
        },
    };
}

static RPCMethod createbitpluscollateralreleaseleaf()
{
    return RPCMethod{
        "createbitpluscollateralreleaseleaf",
        "Build a Bitplus collateral release Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"release_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact release output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact release BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact release output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The collateral release leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitpluscollateralreleaseleaf", "\"auth_script\" \"release_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildCollateralReleaseLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseScriptHex(request.params[1], "release_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "amount"),
                ParseOutputIndex(request.params[3], "output_index")));
        },
    };
}

static RPCMethod createbitpluscollateralreturnleaf()
{
    return RPCMethod{
        "createbitpluscollateralreturnleaf",
        "Build a Bitplus delayed collateral return Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay."},
            {"return_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact return output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact return BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact return output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The collateral return leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitpluscollateralreturnleaf", "\"auth_script\" 144 \"return_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildCollateralReturnLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "return_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

static RPCMethod createbitplusrefundabsoluteleaf()
{
    return RPCMethod{
        "createbitplusrefundabsoluteleaf",
        "Build a Bitplus absolute-expiry refund Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"absolute_expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute CLTV expiry."},
            {"refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact refund output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact refund BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact refund output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The absolute refund leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplusrefundabsoluteleaf", "\"auth_script\" 900000 \"refund_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildAbsoluteRefundLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

static RPCMethod createbitplusrefundrelativeleaf()
{
    return RPCMethod{
        "createbitplusrefundrelativeleaf",
        "Build a Bitplus relative-expiry refund Tapscript leaf.\n",
        {
            {"authorization_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script that must leave a truthy stack item."},
            {"relative_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative CSV delay."},
            {"refund_script_pub_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact refund output scriptPubKey hex."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact refund BTP amount."},
            {"output_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exact refund output index."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "script", "The relative refund leaf script."},
            {RPCResult::Type::STR_HEX, "script_hash", "SHA256 hash of the leaf script."},
        }},
        RPCExamples{HelpExampleCli("createbitplusrefundrelativeleaf", "\"auth_script\" 144 \"refund_script_pub_key\" 1.0 0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            return ContractLeafToJSON(bitplus::contracts::BuildRelativeRefundLeaf(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index")));
        },
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &getrawtransaction},
        {"rawtransactions", &createrawtransaction},
        {"rawtransactions", &decoderawtransaction},
        {"rawtransactions", &decodescript},
        {"rawtransactions", &combinerawtransaction},
        {"rawtransactions", &signrawtransactionwithkey},
        {"rawtransactions", &decodepsbt},
        {"rawtransactions", &combinepsbt},
        {"rawtransactions", &finalizepsbt},
        {"rawtransactions", &createpsbt},
        {"rawtransactions", &converttopsbt},
        {"rawtransactions", &utxoupdatepsbt},
        {"rawtransactions", &descriptorprocesspsbt},
        {"rawtransactions", &joinpsbts},
        {"rawtransactions", &analyzepsbt},
        {"rawtransactions", &decodebitplusscript},
        {"rawtransactions", &analyzebitplustransaction},
        {"rawtransactions", &analyzebitpluspsbt},
        {"rawtransactions", &createbitplusscripttransaction},
        {"rawtransactions", &createbitpluspsbt},
        {"rawtransactions", &preparebitpluspsbt},
        {"rawtransactions", &checkbitplussettlement},
        {"rawtransactions", &scanbitplusassetutxos},
        {"rawtransactions", &getbitplusassetstats},
        {"rawtransactions", &getbitplusmemberassetstats},
        {"rawtransactions", &createbitplusassetid},
        {"rawtransactions", &createbitplusassetmetadata},
        {"rawtransactions", &createbitplusassetwhitelist},
        {"rawtransactions", &createbitplusassetwhitelistroot},
        {"rawtransactions", &createbitplusassetissuance},
        {"rawtransactions", &createbitplusasset},
        {"rawtransactions", &createbitplusassettransfer},
        {"rawtransactions", &createbitplusassetburn},
        {"rawtransactions", &createbitplusassetwhitelistproof},
        {"rawtransactions", &createbitplusdvp},
        {"rawtransactions", &createbitpluspvp},
        {"rawtransactions", &createbitplusvault},
        {"rawtransactions", &createbitplushtlc},
        {"rawtransactions", &createbitpluscollateral},
        {"rawtransactions", &createbitplusrefundpaths},
        {"rawtransactions", &createbitpluscovleaf},
        {"rawtransactions", &createbitplusvaultrecoveryleaf},
        {"rawtransactions", &createbitplusvaultdelayedleaf},
        {"rawtransactions", &createbitplushtlcclaimleaf},
        {"rawtransactions", &createbitplushtlcrefundleaf},
        {"rawtransactions", &createbitplusdvpleaf},
        {"rawtransactions", &createbitpluspvpleaf},
        {"rawtransactions", &createbitpluscollateralreleaseleaf},
        {"rawtransactions", &createbitpluscollateralreturnleaf},
        {"rawtransactions", &createbitplusrefundabsoluteleaf},
        {"rawtransactions", &createbitplusrefundrelativeleaf},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
