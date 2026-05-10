// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bitplus_assets.h>

#include <coins.h>
#include <crypto/common.h>
#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>

namespace bitplus::assets {
namespace {

static constexpr std::array<unsigned char, 8> ASSET_COMMITMENT_MAGIC{
    'B', 'T', 'P', 'A', 'S', 'S', 'E', 'T'
};
static constexpr std::array<unsigned char, 7> ASSET_METADATA_MAGIC{
    'B', 'T', 'P', 'M', 'E', 'T', 'A'
};
static constexpr std::array<unsigned char, 7> ASSET_WHITELIST_MAGIC{
    'B', 'T', 'P', 'W', 'L', 'S', 'T'
};
static constexpr std::array<unsigned char, 9> ASSET_WHITELIST_PROOF_MAGIC{
    'B', 'T', 'P', 'W', 'P', 'R', 'O', 'O', 'F'
};
static constexpr size_t ASSET_COMMITMENT_SIZE{
    ASSET_COMMITMENT_MAGIC.size() + 1 + 1 + uint256::size() + sizeof(uint64_t) + uint256::size() + uint256::size()
};
static constexpr size_t ASSET_METADATA_SIZE{
    ASSET_METADATA_MAGIC.size() + 1 + uint256::size() + uint256::size() + uint256::size()
};
static constexpr size_t ASSET_WHITELIST_SIZE{
    ASSET_WHITELIST_MAGIC.size() + 1 + uint256::size() + uint256::size() + uint256::size() + sizeof(uint32_t)
};
static constexpr size_t ASSET_WHITELIST_PROOF_FIXED_SIZE{
    ASSET_WHITELIST_PROOF_MAGIC.size() + 1 + sizeof(uint32_t) + uint256::size() + sizeof(uint32_t) + 1
};
static constexpr size_t MAX_WHITELIST_PROOF_DEPTH{32};

bool IsKnownType(uint8_t type)
{
    return type == static_cast<uint8_t>(AssetCommitmentType::ISSUANCE) ||
           type == static_cast<uint8_t>(AssetCommitmentType::TRANSFER) ||
           type == static_cast<uint8_t>(AssetCommitmentType::BURN);
}

template <size_t N>
bool StartsWithMagic(std::span<const unsigned char> payload, const std::array<unsigned char, N>& magic)
{
    return payload.size() >= magic.size() && std::equal(magic.begin(), magic.end(), payload.begin());
}

void AddToSummary(uint64_t& total, uint64_t amount, bool& overflow)
{
    if (std::numeric_limits<uint64_t>::max() - total < amount) {
        overflow = true;
        return;
    }
    total += amount;
}

struct MutableAssetConservation {
    uint64_t spent{0};
    uint64_t issued{0};
    uint64_t transferred{0};
    uint64_t burned{0};
    bool overflow{false};
};

uint256 HashPair(const uint256& left, const uint256& right)
{
    return (HashWriter{} << left << right).GetSHA256();
}

bool WhitelistProofIndexInRange(const AssetWhitelistProofCommitment& proof)
{
    if (proof.merkle_path.size() >= sizeof(uint32_t) * 8) return true;
    return (proof.proof_index >> proof.merkle_path.size()) == 0;
}

} // namespace

std::vector<unsigned char> EncodeAssetCommitment(const AssetCommitment& commitment)
{
    std::vector<unsigned char> payload;
    payload.reserve(ASSET_COMMITMENT_SIZE);
    payload.insert(payload.end(), ASSET_COMMITMENT_MAGIC.begin(), ASSET_COMMITMENT_MAGIC.end());
    payload.push_back(ASSET_COMMITMENT_VERSION);
    payload.push_back(static_cast<uint8_t>(commitment.type));
    payload.insert(payload.end(), commitment.asset_id.begin(), commitment.asset_id.end());

    std::array<unsigned char, sizeof(uint64_t)> amount;
    WriteLE64(amount.data(), commitment.amount);
    payload.insert(payload.end(), amount.begin(), amount.end());

    payload.insert(payload.end(), commitment.metadata_hash.begin(), commitment.metadata_hash.end());
    payload.insert(payload.end(), commitment.member_hash.begin(), commitment.member_hash.end());
    return payload;
}

std::optional<AssetCommitment> DecodeAssetCommitment(std::span<const unsigned char> payload)
{
    if (payload.size() != ASSET_COMMITMENT_SIZE) return std::nullopt;
    if (!std::equal(ASSET_COMMITMENT_MAGIC.begin(), ASSET_COMMITMENT_MAGIC.end(), payload.begin())) return std::nullopt;

    size_t offset{ASSET_COMMITMENT_MAGIC.size()};
    if (payload[offset++] != ASSET_COMMITMENT_VERSION) return std::nullopt;

    const uint8_t raw_type{payload[offset++]};
    if (!IsKnownType(raw_type)) return std::nullopt;

    AssetCommitment commitment;
    commitment.type = static_cast<AssetCommitmentType>(raw_type);
    commitment.asset_id = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.amount = ReadLE64(payload.subspan(offset, sizeof(uint64_t)).data());
    offset += sizeof(uint64_t);
    commitment.metadata_hash = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.member_hash = uint256{payload.subspan(offset, uint256::size())};
    return commitment;
}

uint256 HashAssetCommitment(const AssetCommitment& commitment)
{
    return (HashWriter{} << EncodeAssetCommitment(commitment)).GetSHA256();
}

uint256 ComputeAssetId(const uint256& metadata_hash, const COutPoint& issuance_anchor)
{
    return (HashWriter{} << metadata_hash << issuance_anchor).GetSHA256();
}

CScript BuildDefaultAssetLockingScript(const AssetCommitment& commitment)
{
    const std::vector<unsigned char> member_hash{commitment.member_hash.begin(), commitment.member_hash.end()};
    return CScript{} << OP_SHA256 << member_hash << OP_EQUAL;
}

CScript BuildAssetCommitmentScript(const AssetCommitment& commitment)
{
    return BuildAssetCommitmentScript(commitment, BuildDefaultAssetLockingScript(commitment));
}

CScript BuildAssetCommitmentScript(const AssetCommitment& commitment, const CScript& locking_script)
{
    CScript script{CScript{} << EncodeAssetCommitment(commitment) << OP_DROP};
    script.insert(script.end(), locking_script.begin(), locking_script.end());
    return script;
}

std::optional<AssetCommitment> DecodeAssetCommitmentScript(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    if (opcode > OP_PUSHDATA4) return std::nullopt;
    const std::optional<AssetCommitment> commitment{DecodeAssetCommitment(data)};
    if (!commitment.has_value()) return std::nullopt;
    if (!script.GetOp(pc, opcode) || opcode != OP_DROP) return std::nullopt;
    if (pc == script.end()) return std::nullopt;

    return commitment;
}

std::optional<CScript> DecodeAssetCommitmentLockingScript(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    if (opcode > OP_PUSHDATA4) return std::nullopt;
    if (!DecodeAssetCommitment(data).has_value()) return std::nullopt;
    if (!script.GetOp(pc, opcode) || opcode != OP_DROP) return std::nullopt;
    if (pc == script.end()) return std::nullopt;

    return CScript{pc, script.end()};
}

std::optional<AssetOutput> DecodeAssetOutput(const CTxOut& txout, uint32_t output_index)
{
    const std::optional<AssetCommitment> commitment{DecodeAssetCommitmentScript(txout.scriptPubKey)};
    if (!commitment.has_value()) return std::nullopt;
    const std::optional<CScript> locking_script{DecodeAssetCommitmentLockingScript(txout.scriptPubKey)};
    if (!locking_script.has_value()) return std::nullopt;

    return AssetOutput{
        .output_index = output_index,
        .carrier_amount = txout.nValue,
        .commitment = *commitment,
        .locking_script = *locking_script,
    };
}

std::vector<AssetOutput> ExtractAssetOutputs(const CTransaction& tx)
{
    std::vector<AssetOutput> outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        std::optional<AssetOutput> output{DecodeAssetOutput(tx.vout[i], i)};
        if (output.has_value()) outputs.push_back(*output);
    }
    return outputs;
}

std::optional<AssetValidationResult> FindFirstMalformedAssetCommitmentOutput(const CTransaction& tx)
{
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        const CScript& script{tx.vout[i].scriptPubKey};
        CScript::const_iterator pc{script.begin()};
        opcodetype opcode;
        std::vector<unsigned char> data;

        if (!script.GetOp(pc, opcode, data)) continue;
        if (opcode == OP_RETURN) {
            if (!script.GetOp(pc, opcode, data) || opcode > OP_PUSHDATA4) continue;
            if (StartsWithMagic(data, ASSET_METADATA_MAGIC) && !DecodeAssetMetadataOutput(tx.vout[i], i).has_value()) {
                return AssetValidationResult{.output_index = i, .valid = false, .reason = "asset-metadata-malformed"};
            }
            if (StartsWithMagic(data, ASSET_WHITELIST_MAGIC) && !DecodeAssetWhitelistOutput(tx.vout[i], i).has_value()) {
                return AssetValidationResult{.output_index = i, .valid = false, .reason = "asset-whitelist-malformed"};
            }
            if (StartsWithMagic(data, ASSET_WHITELIST_PROOF_MAGIC) && !DecodeAssetWhitelistProofOutput(tx.vout[i], i).has_value()) {
                return AssetValidationResult{.output_index = i, .valid = false, .reason = "asset-whitelist-proof-malformed"};
            }
            continue;
        }

        if (opcode <= OP_PUSHDATA4 && StartsWithMagic(data, ASSET_COMMITMENT_MAGIC) && !DecodeAssetOutput(tx.vout[i], i).has_value()) {
            return AssetValidationResult{.output_index = i, .valid = false, .reason = "asset-commitment-malformed"};
        }
    }
    return std::nullopt;
}

std::optional<std::vector<AssetOutput>> ExtractSpentAssetOutputs(const CTransaction& tx, const CCoinsViewCache& coins)
{
    std::vector<AssetOutput> outputs;
    if (tx.IsCoinBase()) return outputs;

    for (const CTxIn& txin : tx.vin) {
        const std::optional<Coin> coin{coins.GetCoin(txin.prevout)};
        if (!coin.has_value()) return std::nullopt;

        std::optional<AssetOutput> output{DecodeAssetOutput(coin->out, txin.prevout.n)};
        if (output.has_value()) outputs.push_back(*output);
    }
    return outputs;
}

AssetBalanceSummary SummarizeAssetOutputs(std::span<const AssetOutput> outputs, const uint256& asset_id)
{
    AssetBalanceSummary summary;
    for (const AssetOutput& output : outputs) {
        if (output.commitment.asset_id != asset_id) continue;

        switch (output.commitment.type) {
        case AssetCommitmentType::ISSUANCE:
            AddToSummary(summary.issued, output.commitment.amount, summary.overflow);
            break;
        case AssetCommitmentType::TRANSFER:
            AddToSummary(summary.transferred, output.commitment.amount, summary.overflow);
            break;
        case AssetCommitmentType::BURN:
            AddToSummary(summary.burned, output.commitment.amount, summary.overflow);
            break;
        }
    }
    return summary;
}

AssetValidationResult ValidateAssetOutput(const AssetOutput& output)
{
    if (output.carrier_amount != 0) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-carrier-nonzero"};
    }
    if (output.commitment.asset_id.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-id-null"};
    }
    if (output.commitment.metadata_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-metadata-null"};
    }
    if (output.commitment.member_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-member-null"};
    }
    if (output.commitment.amount == 0) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-amount-zero"};
    }
    if (output.locking_script.empty()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-locking-script-empty"};
    }
    if (output.locking_script.IsUnspendable()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-locking-script-unspendable"};
    }
    if (DecodeAssetCommitmentLockingScript(output.locking_script).has_value()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-locking-script-nested"};
    }
    return {.output_index = output.output_index, .valid = true, .reason = ""};
}

std::optional<AssetValidationResult> FindFirstInvalidAssetOutput(std::span<const AssetOutput> outputs)
{
    for (const AssetOutput& output : outputs) {
        AssetValidationResult result{ValidateAssetOutput(output)};
        if (!result.valid) return result;
    }
    return std::nullopt;
}

std::optional<AssetValidationResult> FindFirstInvalidAssetIssuanceAnchor(std::span<const AssetOutput> outputs, const CTransaction& tx)
{
    if (tx.IsCoinBase()) {
        for (const AssetOutput& output : outputs) {
            if (output.commitment.type == AssetCommitmentType::ISSUANCE) {
                return AssetValidationResult{
                    .output_index = output.output_index,
                    .valid = false,
                    .reason = "asset-issuance-coinbase",
                };
            }
        }
        return std::nullopt;
    }

    if (tx.vin.empty()) {
        for (const AssetOutput& output : outputs) {
            if (output.commitment.type == AssetCommitmentType::ISSUANCE) {
                return AssetValidationResult{
                    .output_index = output.output_index,
                    .valid = false,
                    .reason = "asset-issuance-anchor-missing",
                };
            }
        }
        return std::nullopt;
    }

    const COutPoint& issuance_anchor{tx.vin.front().prevout};
    for (const AssetOutput& output : outputs) {
        if (output.commitment.type != AssetCommitmentType::ISSUANCE) continue;
        if (output.commitment.asset_id != ComputeAssetId(output.commitment.metadata_hash, issuance_anchor)) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-issuance-anchor-mismatch",
            };
        }
    }
    return std::nullopt;
}

std::vector<AssetConservationResult> CheckAssetConservation(std::span<const AssetOutput> spent_outputs, std::span<const AssetOutput> created_outputs)
{
    std::map<uint256, MutableAssetConservation> summaries;
    std::set<uint256> asset_ids;

    for (const AssetOutput& output : spent_outputs) {
        const uint256& asset_id{output.commitment.asset_id};
        asset_ids.insert(asset_id);
        if (output.commitment.type == AssetCommitmentType::TRANSFER) {
            AddToSummary(summaries[asset_id].spent, output.commitment.amount, summaries[asset_id].overflow);
        }
    }

    for (const AssetOutput& output : created_outputs) {
        const uint256& asset_id{output.commitment.asset_id};
        asset_ids.insert(asset_id);
        MutableAssetConservation& summary{summaries[asset_id]};

        switch (output.commitment.type) {
        case AssetCommitmentType::ISSUANCE:
            AddToSummary(summary.issued, output.commitment.amount, summary.overflow);
            break;
        case AssetCommitmentType::TRANSFER:
            AddToSummary(summary.transferred, output.commitment.amount, summary.overflow);
            break;
        case AssetCommitmentType::BURN:
            AddToSummary(summary.burned, output.commitment.amount, summary.overflow);
            break;
        }
    }

    std::vector<AssetConservationResult> results;
    results.reserve(asset_ids.size());
    for (const uint256& asset_id : asset_ids) {
        const MutableAssetConservation& summary{summaries[asset_id]};
        const bool left_overflow{std::numeric_limits<uint64_t>::max() - summary.spent < summary.issued};
        const bool right_overflow{std::numeric_limits<uint64_t>::max() - summary.transferred < summary.burned};
        const bool overflow{summary.overflow || left_overflow || right_overflow};
        const uint64_t left{overflow ? 0 : summary.spent + summary.issued};
        const uint64_t right{overflow ? 1 : summary.transferred + summary.burned};

        results.push_back(AssetConservationResult{
            .asset_id = asset_id,
            .spent = summary.spent,
            .issued = summary.issued,
            .transferred = summary.transferred,
            .burned = summary.burned,
            .balanced = !overflow && left == right,
            .overflow = overflow,
        });
    }
    return results;
}

std::optional<std::vector<AssetConservationResult>> CheckTransactionAssetConservation(const CTransaction& tx, const CCoinsViewCache& coins)
{
    const std::optional<std::vector<AssetOutput>> spent_outputs{ExtractSpentAssetOutputs(tx, coins)};
    if (!spent_outputs.has_value()) return std::nullopt;

    const std::vector<AssetOutput> created_outputs{ExtractAssetOutputs(tx)};
    return CheckAssetConservation(*spent_outputs, created_outputs);
}

std::vector<unsigned char> EncodeAssetMetadataCommitment(const AssetMetadataCommitment& commitment)
{
    std::vector<unsigned char> payload;
    payload.reserve(ASSET_METADATA_SIZE);
    payload.insert(payload.end(), ASSET_METADATA_MAGIC.begin(), ASSET_METADATA_MAGIC.end());
    payload.push_back(ASSET_METADATA_VERSION);
    payload.insert(payload.end(), commitment.issuer_id.begin(), commitment.issuer_id.end());
    payload.insert(payload.end(), commitment.document_hash.begin(), commitment.document_hash.end());
    payload.insert(payload.end(), commitment.rules_hash.begin(), commitment.rules_hash.end());
    return payload;
}

std::optional<AssetMetadataCommitment> DecodeAssetMetadataCommitment(std::span<const unsigned char> payload)
{
    if (payload.size() != ASSET_METADATA_SIZE) return std::nullopt;
    if (!std::equal(ASSET_METADATA_MAGIC.begin(), ASSET_METADATA_MAGIC.end(), payload.begin())) return std::nullopt;

    size_t offset{ASSET_METADATA_MAGIC.size()};
    if (payload[offset++] != ASSET_METADATA_VERSION) return std::nullopt;

    AssetMetadataCommitment commitment;
    commitment.issuer_id = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.document_hash = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.rules_hash = uint256{payload.subspan(offset, uint256::size())};
    return commitment;
}

uint256 HashAssetMetadataCommitment(const AssetMetadataCommitment& commitment)
{
    return (HashWriter{} << EncodeAssetMetadataCommitment(commitment)).GetSHA256();
}

CScript BuildAssetMetadataCommitmentScript(const AssetMetadataCommitment& commitment)
{
    return CScript{} << OP_RETURN << EncodeAssetMetadataCommitment(commitment);
}

std::optional<AssetMetadataCommitment> DecodeAssetMetadataCommitmentScript(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return std::nullopt;
    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    if (pc != script.end()) return std::nullopt;
    if (opcode > OP_PUSHDATA4) return std::nullopt;

    return DecodeAssetMetadataCommitment(data);
}

std::optional<AssetMetadataOutput> DecodeAssetMetadataOutput(const CTxOut& txout, uint32_t output_index)
{
    const std::optional<AssetMetadataCommitment> commitment{DecodeAssetMetadataCommitmentScript(txout.scriptPubKey)};
    if (!commitment.has_value()) return std::nullopt;

    return AssetMetadataOutput{.output_index = output_index, .commitment = *commitment};
}

std::vector<AssetMetadataOutput> ExtractAssetMetadataOutputs(const CTransaction& tx)
{
    std::vector<AssetMetadataOutput> outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        std::optional<AssetMetadataOutput> output{DecodeAssetMetadataOutput(tx.vout[i], i)};
        if (output.has_value()) outputs.push_back(*output);
    }
    return outputs;
}

AssetValidationResult ValidateAssetMetadataOutput(const AssetMetadataOutput& output)
{
    if (output.commitment.issuer_id.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-metadata-issuer-null"};
    }
    if (output.commitment.document_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-metadata-document-null"};
    }
    if (output.commitment.rules_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-metadata-rules-null"};
    }
    return {.output_index = output.output_index, .valid = true, .reason = ""};
}

std::optional<AssetValidationResult> FindFirstInvalidAssetMetadataOutput(std::span<const AssetMetadataOutput> outputs)
{
    for (const AssetMetadataOutput& output : outputs) {
        AssetValidationResult result{ValidateAssetMetadataOutput(output)};
        if (!result.valid) return result;
    }
    return std::nullopt;
}

std::optional<AssetValidationResult> FindFirstUnlinkedAssetMetadata(std::span<const AssetOutput> asset_outputs, std::span<const AssetMetadataOutput> metadata_outputs)
{
    std::set<uint256> metadata_hashes;
    for (const AssetMetadataOutput& output : metadata_outputs) {
        metadata_hashes.insert(HashAssetMetadataCommitment(output.commitment));
    }

    std::set<uint256> seen_issuance_ids;
    for (const AssetOutput& output : asset_outputs) {
        if (output.commitment.type != AssetCommitmentType::ISSUANCE) continue;
        if (const auto [_, inserted] = seen_issuance_ids.insert(output.commitment.asset_id); !inserted) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-issuance-duplicate",
            };
        }
        if (!metadata_hashes.contains(output.commitment.metadata_hash)) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-issuance-metadata-missing",
            };
        }
    }
    return std::nullopt;
}

std::vector<unsigned char> EncodeAssetWhitelistCommitment(const AssetWhitelistCommitment& commitment)
{
    std::vector<unsigned char> payload;
    payload.reserve(ASSET_WHITELIST_SIZE);
    payload.insert(payload.end(), ASSET_WHITELIST_MAGIC.begin(), ASSET_WHITELIST_MAGIC.end());
    payload.push_back(ASSET_WHITELIST_VERSION);
    payload.insert(payload.end(), commitment.list_id.begin(), commitment.list_id.end());
    payload.insert(payload.end(), commitment.admin_key_hash.begin(), commitment.admin_key_hash.end());
    payload.insert(payload.end(), commitment.members_root.begin(), commitment.members_root.end());

    std::array<unsigned char, sizeof(uint32_t)> flags;
    WriteLE32(flags.data(), commitment.flags);
    payload.insert(payload.end(), flags.begin(), flags.end());
    return payload;
}

std::optional<AssetWhitelistCommitment> DecodeAssetWhitelistCommitment(std::span<const unsigned char> payload)
{
    if (payload.size() != ASSET_WHITELIST_SIZE) return std::nullopt;
    if (!std::equal(ASSET_WHITELIST_MAGIC.begin(), ASSET_WHITELIST_MAGIC.end(), payload.begin())) return std::nullopt;

    size_t offset{ASSET_WHITELIST_MAGIC.size()};
    if (payload[offset++] != ASSET_WHITELIST_VERSION) return std::nullopt;

    AssetWhitelistCommitment commitment;
    commitment.list_id = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.admin_key_hash = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.members_root = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.flags = ReadLE32(payload.subspan(offset, sizeof(uint32_t)).data());
    return commitment;
}

uint256 HashAssetWhitelistCommitment(const AssetWhitelistCommitment& commitment)
{
    return (HashWriter{} << EncodeAssetWhitelistCommitment(commitment)).GetSHA256();
}

CScript BuildAssetWhitelistCommitmentScript(const AssetWhitelistCommitment& commitment)
{
    return CScript{} << OP_RETURN << EncodeAssetWhitelistCommitment(commitment);
}

std::optional<AssetWhitelistCommitment> DecodeAssetWhitelistCommitmentScript(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return std::nullopt;
    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    if (pc != script.end()) return std::nullopt;
    if (opcode > OP_PUSHDATA4) return std::nullopt;

    return DecodeAssetWhitelistCommitment(data);
}

std::optional<AssetWhitelistOutput> DecodeAssetWhitelistOutput(const CTxOut& txout, uint32_t output_index)
{
    const std::optional<AssetWhitelistCommitment> commitment{DecodeAssetWhitelistCommitmentScript(txout.scriptPubKey)};
    if (!commitment.has_value()) return std::nullopt;

    return AssetWhitelistOutput{.output_index = output_index, .commitment = *commitment};
}

std::vector<AssetWhitelistOutput> ExtractAssetWhitelistOutputs(const CTransaction& tx)
{
    std::vector<AssetWhitelistOutput> outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        std::optional<AssetWhitelistOutput> output{DecodeAssetWhitelistOutput(tx.vout[i], i)};
        if (output.has_value()) outputs.push_back(*output);
    }
    return outputs;
}

AssetValidationResult ValidateAssetWhitelistOutput(const AssetWhitelistOutput& output)
{
    if (output.commitment.list_id.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-list-null"};
    }
    if (output.commitment.admin_key_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-admin-null"};
    }
    if (output.commitment.members_root.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-members-null"};
    }
    return {.output_index = output.output_index, .valid = true, .reason = ""};
}

std::optional<AssetValidationResult> FindFirstInvalidAssetWhitelistOutput(std::span<const AssetWhitelistOutput> outputs)
{
    for (const AssetWhitelistOutput& output : outputs) {
        AssetValidationResult result{ValidateAssetWhitelistOutput(output)};
        if (!result.valid) return result;
    }
    return std::nullopt;
}

std::optional<AssetValidationResult> FindFirstUnlinkedAssetWhitelist(std::span<const AssetMetadataOutput> metadata_outputs, std::span<const AssetWhitelistOutput> whitelist_outputs)
{
    std::set<uint256> whitelist_hashes;
    for (const AssetWhitelistOutput& output : whitelist_outputs) {
        whitelist_hashes.insert(HashAssetWhitelistCommitment(output.commitment));
    }

    for (const AssetMetadataOutput& output : metadata_outputs) {
        if (!whitelist_hashes.contains(output.commitment.rules_hash)) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-metadata-whitelist-missing",
            };
        }
    }
    return std::nullopt;
}

uint256 ComputeWhitelistMemberLeaf(const uint256& member_hash)
{
    static constexpr std::array<unsigned char, 14> tag{
        'B', 'T', 'P', 'W', 'L', 'S', 'T', 'M', 'E', 'M', 'B', 'E', 'R', 0
    };
    return (HashWriter{} << tag << member_hash).GetSHA256();
}

uint256 ComputeWhitelistMembersRoot(std::span<const uint256> member_hashes)
{
    if (member_hashes.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(member_hashes.size());
    for (const uint256& member_hash : member_hashes) {
        level.push_back(ComputeWhitelistMemberLeaf(member_hash));
    }

    while (level.size() > 1) {
        std::vector<uint256> next_level;
        next_level.reserve((level.size() + 1) / 2);
        for (size_t i{0}; i < level.size(); i += 2) {
            const uint256& left{level[i]};
            const uint256& right{i + 1 < level.size() ? level[i + 1] : level[i]};
            next_level.push_back(HashPair(left, right));
        }
        level = std::move(next_level);
    }
    return level.front();
}

uint256 ComputeWhitelistMembersRoot(const AssetWhitelistProofCommitment& proof)
{
    uint256 root{ComputeWhitelistMemberLeaf(proof.member_hash)};
    uint32_t index{proof.proof_index};
    for (const uint256& sibling : proof.merkle_path) {
        if ((index & 1U) == 0) {
            root = HashPair(root, sibling);
        } else {
            root = HashPair(sibling, root);
        }
        index >>= 1U;
    }
    return root;
}

std::vector<uint256> ComputeWhitelistMerklePath(std::span<const uint256> member_hashes, uint32_t position)
{
    if (member_hashes.empty() || position >= member_hashes.size()) return {};

    std::vector<uint256> level;
    level.reserve(member_hashes.size());
    for (const uint256& member_hash : member_hashes) {
        level.push_back(ComputeWhitelistMemberLeaf(member_hash));
    }

    std::vector<uint256> path;
    path.reserve(MAX_WHITELIST_PROOF_DEPTH);
    size_t index{position};
    while (level.size() > 1) {
        const size_t sibling_index{index ^ 1U};
        path.push_back(sibling_index < level.size() ? level[sibling_index] : level[index]);

        std::vector<uint256> next_level;
        next_level.reserve((level.size() + 1) / 2);
        for (size_t i{0}; i < level.size(); i += 2) {
            const uint256& left{level[i]};
            const uint256& right{i + 1 < level.size() ? level[i + 1] : level[i]};
            next_level.push_back(HashPair(left, right));
        }
        level = std::move(next_level);
        index >>= 1U;
    }
    return path;
}

bool VerifyWhitelistProof(const AssetWhitelistProofCommitment& proof, const AssetWhitelistCommitment& whitelist)
{
    if (proof.member_hash.IsNull()) return false;
    if (proof.merkle_path.size() > MAX_WHITELIST_PROOF_DEPTH) return false;
    if (!WhitelistProofIndexInRange(proof)) return false;
    return ComputeWhitelistMembersRoot(proof) == whitelist.members_root;
}

std::vector<unsigned char> EncodeAssetWhitelistProofCommitment(const AssetWhitelistProofCommitment& commitment)
{
    std::vector<unsigned char> payload;
    payload.reserve(ASSET_WHITELIST_PROOF_FIXED_SIZE + commitment.merkle_path.size() * uint256::size());
    payload.insert(payload.end(), ASSET_WHITELIST_PROOF_MAGIC.begin(), ASSET_WHITELIST_PROOF_MAGIC.end());
    payload.push_back(ASSET_WHITELIST_PROOF_VERSION);

    std::array<unsigned char, sizeof(uint32_t)> output_index;
    WriteLE32(output_index.data(), commitment.asset_output_index);
    payload.insert(payload.end(), output_index.begin(), output_index.end());

    payload.insert(payload.end(), commitment.member_hash.begin(), commitment.member_hash.end());

    std::array<unsigned char, sizeof(uint32_t)> proof_index;
    WriteLE32(proof_index.data(), commitment.proof_index);
    payload.insert(payload.end(), proof_index.begin(), proof_index.end());

    payload.push_back(static_cast<unsigned char>(commitment.merkle_path.size()));
    for (const uint256& sibling : commitment.merkle_path) {
        payload.insert(payload.end(), sibling.begin(), sibling.end());
    }
    return payload;
}

std::optional<AssetWhitelistProofCommitment> DecodeAssetWhitelistProofCommitment(std::span<const unsigned char> payload)
{
    if (payload.size() < ASSET_WHITELIST_PROOF_FIXED_SIZE) return std::nullopt;
    if (!std::equal(ASSET_WHITELIST_PROOF_MAGIC.begin(), ASSET_WHITELIST_PROOF_MAGIC.end(), payload.begin())) return std::nullopt;

    size_t offset{ASSET_WHITELIST_PROOF_MAGIC.size()};
    if (payload[offset++] != ASSET_WHITELIST_PROOF_VERSION) return std::nullopt;

    AssetWhitelistProofCommitment commitment;
    commitment.asset_output_index = ReadLE32(payload.subspan(offset, sizeof(uint32_t)).data());
    offset += sizeof(uint32_t);
    commitment.member_hash = uint256{payload.subspan(offset, uint256::size())};
    offset += uint256::size();
    commitment.proof_index = ReadLE32(payload.subspan(offset, sizeof(uint32_t)).data());
    offset += sizeof(uint32_t);

    const size_t path_size{payload[offset++]};
    if (path_size > MAX_WHITELIST_PROOF_DEPTH) return std::nullopt;
    if (payload.size() != ASSET_WHITELIST_PROOF_FIXED_SIZE + path_size * uint256::size()) return std::nullopt;

    commitment.merkle_path.reserve(path_size);
    for (size_t i{0}; i < path_size; ++i) {
        commitment.merkle_path.emplace_back(payload.subspan(offset, uint256::size()));
        offset += uint256::size();
    }
    return commitment;
}

uint256 HashAssetWhitelistProofCommitment(const AssetWhitelistProofCommitment& commitment)
{
    return (HashWriter{} << EncodeAssetWhitelistProofCommitment(commitment)).GetSHA256();
}

CScript BuildAssetWhitelistProofCommitmentScript(const AssetWhitelistProofCommitment& commitment)
{
    return CScript{} << OP_RETURN << EncodeAssetWhitelistProofCommitment(commitment);
}

std::optional<AssetWhitelistProofCommitment> DecodeAssetWhitelistProofCommitmentScript(const CScript& script)
{
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return std::nullopt;
    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    if (pc != script.end()) return std::nullopt;
    if (opcode > OP_PUSHDATA4) return std::nullopt;

    return DecodeAssetWhitelistProofCommitment(data);
}

std::optional<AssetWhitelistProofOutput> DecodeAssetWhitelistProofOutput(const CTxOut& txout, uint32_t output_index)
{
    const std::optional<AssetWhitelistProofCommitment> commitment{DecodeAssetWhitelistProofCommitmentScript(txout.scriptPubKey)};
    if (!commitment.has_value()) return std::nullopt;

    return AssetWhitelistProofOutput{.output_index = output_index, .commitment = *commitment};
}

std::vector<AssetWhitelistProofOutput> ExtractAssetWhitelistProofOutputs(const CTransaction& tx)
{
    std::vector<AssetWhitelistProofOutput> outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        std::optional<AssetWhitelistProofOutput> output{DecodeAssetWhitelistProofOutput(tx.vout[i], i)};
        if (output.has_value()) outputs.push_back(*output);
    }
    return outputs;
}

AssetValidationResult ValidateAssetWhitelistProofOutput(const AssetWhitelistProofOutput& output)
{
    if (output.commitment.member_hash.IsNull()) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-proof-member-null"};
    }
    if (output.commitment.merkle_path.size() > MAX_WHITELIST_PROOF_DEPTH) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-proof-too-deep"};
    }
    if (!WhitelistProofIndexInRange(output.commitment)) {
        return {.output_index = output.output_index, .valid = false, .reason = "asset-whitelist-proof-index-range"};
    }
    return {.output_index = output.output_index, .valid = true, .reason = ""};
}

std::optional<AssetValidationResult> FindFirstInvalidAssetWhitelistProofOutput(std::span<const AssetWhitelistProofOutput> outputs)
{
    for (const AssetWhitelistProofOutput& output : outputs) {
        AssetValidationResult result{ValidateAssetWhitelistProofOutput(output)};
        if (!result.valid) return result;
    }
    return std::nullopt;
}

std::optional<AssetValidationResult> FindFirstUnprovenWhitelistedTransfer(
    std::span<const AssetOutput> asset_outputs,
    std::span<const AssetMetadataOutput> metadata_outputs,
    std::span<const AssetWhitelistOutput> whitelist_outputs,
    std::span<const AssetWhitelistProofOutput> proof_outputs)
{
    std::map<uint256, AssetMetadataOutput> metadata_by_hash;
    for (const AssetMetadataOutput& output : metadata_outputs) {
        metadata_by_hash.emplace(HashAssetMetadataCommitment(output.commitment), output);
    }

    std::map<uint256, AssetWhitelistOutput> whitelist_by_hash;
    for (const AssetWhitelistOutput& output : whitelist_outputs) {
        whitelist_by_hash.emplace(HashAssetWhitelistCommitment(output.commitment), output);
    }

    std::map<uint32_t, AssetWhitelistProofOutput> proof_by_asset_output;
    for (const AssetWhitelistProofOutput& output : proof_outputs) {
        if (!proof_by_asset_output.emplace(output.commitment.asset_output_index, output).second) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-whitelist-proof-duplicate",
            };
        }
    }

    std::set<uint32_t> transfer_output_indices;
    for (const AssetOutput& output : asset_outputs) {
        if (output.commitment.type != AssetCommitmentType::TRANSFER) continue;
        transfer_output_indices.insert(output.output_index);

        const auto metadata_it{metadata_by_hash.find(output.commitment.metadata_hash)};
        if (metadata_it == metadata_by_hash.end()) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-transfer-metadata-missing",
            };
        }

        const auto whitelist_it{whitelist_by_hash.find(metadata_it->second.commitment.rules_hash)};
        if (whitelist_it == whitelist_by_hash.end()) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-transfer-whitelist-missing",
            };
        }

        const auto proof_it{proof_by_asset_output.find(output.output_index)};
        if (proof_it == proof_by_asset_output.end()) {
            return AssetValidationResult{
                .output_index = output.output_index,
                .valid = false,
                .reason = "asset-whitelist-proof-missing",
            };
        }

        if (proof_it->second.commitment.member_hash != output.commitment.member_hash) {
            return AssetValidationResult{
                .output_index = proof_it->second.output_index,
                .valid = false,
                .reason = "asset-whitelist-proof-member-mismatch",
            };
        }

        if (!VerifyWhitelistProof(proof_it->second.commitment, whitelist_it->second.commitment)) {
            return AssetValidationResult{
                .output_index = proof_it->second.output_index,
                .valid = false,
                .reason = "asset-whitelist-proof-invalid",
            };
        }
    }

    for (const AssetWhitelistProofOutput& proof : proof_outputs) {
        if (!transfer_output_indices.contains(proof.commitment.asset_output_index)) {
            return AssetValidationResult{
                .output_index = proof.output_index,
                .valid = false,
                .reason = "asset-whitelist-proof-orphan",
            };
        }
    }

    return std::nullopt;
}

} // namespace bitplus::assets
