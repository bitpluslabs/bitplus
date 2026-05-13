// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/bitplus_util.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/bitplusassetindex.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_psbt.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <script/bitplus_contracts.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <txmempool.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <univalue.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;
using namespace bitplus::rpc;

static constexpr decltype(CTransaction::version) DEFAULT_RAWTX_VERSION{CTransaction::CURRENT_VERSION};

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
                {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
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

static uint256 BitplusReviewHash(
    const CTransaction& tx,
    const std::vector<bitplus::assets::AssetOutput>& spent_asset_outputs)
{
    static constexpr std::string_view REVIEW_DOMAIN{"BitplusReview"};
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
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
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
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "metadata_outputs", "Decoded BTPMETA outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_outputs", "Decoded BTPWLST outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_proof_outputs", "Decoded BTPWPROOF outputs.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "output_index", "Transaction output index."},
                    {RPCResult::Type::BOOL, "valid", "Whether this output is structurally valid."},
                    {RPCResult::Type::STR, "validation_error", /*optional=*/true, "Validation error when valid is false."},
                    {RPCResult::Type::OBJ_DYN, "commitment", "Decoded commitment fields.", {
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
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
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
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
                    {RPCResult::Type::ELISION, "", "Decoded output fields vary by type."},
                }},
            }},
            {RPCResult::Type::ARR, "metadata_outputs", "Decoded BTPMETA outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ELISION, "", "Decoded output fields vary by type."},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_outputs", "Decoded BTPWLST outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ELISION, "", "Decoded output fields vary by type."},
                }},
            }},
            {RPCResult::Type::ARR, "whitelist_proof_outputs", "Decoded BTPWPROOF outputs.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ELISION, "", "Decoded output fields vary by type."},
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

static void WriteHashString(HashWriter& writer, std::string_view value)
{
    writer << std::vector<unsigned char>{value.begin(), value.end()};
}

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
    WriteHashString(writer, "BitplusReadinessReport");
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
    WriteHashString(writer, "BitplusSettlementReadiness");
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
                {RPCResult::Type::ELISION, "", "Analyzer fields vary by transaction."},
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
            {RPCResult::Type::OBJ, "readiness_policy", "Operator policy knobs used by this readiness check.", {
                {RPCResult::Type::STR, "policy", "Readiness policy/hash domain."},
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
                    {RPCResult::Type::ELISION, "", "Conservation fields vary by asset."},
                }},
            }},
            {RPCResult::Type::ARR, "participant_movements", "Per-asset participant movement summary copied from the Bitplus analyzer.", {
                {RPCResult::Type::OBJ_DYN, "", "", {
                    {RPCResult::Type::ELISION, "", "Movement fields vary by asset."},
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
                {RPCResult::Type::ELISION, "", "Analyzer fields vary by transaction."},
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
            readiness_policy.pushKV("policy", "BitplusSettlementReadiness");
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

void RegisterBitplusSettlementRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &decodebitplusscript},
        {"rawtransactions", &analyzebitplustransaction},
        {"rawtransactions", &analyzebitpluspsbt},
        {"rawtransactions", &createbitplusscripttransaction},
        {"rawtransactions", &createbitpluspsbt},
        {"rawtransactions", &preparebitpluspsbt},
        {"rawtransactions", &checkbitplussettlement},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
