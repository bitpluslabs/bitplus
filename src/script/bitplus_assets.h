// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_SCRIPT_BITPLUS_ASSETS_H
#define BITPLUS_SCRIPT_BITPLUS_ASSETS_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class CCoinsViewCache;

namespace bitplus::assets {

inline constexpr size_t MAX_WHITELIST_PROOF_DEPTH{32};

enum class AssetCommitmentType : uint8_t {
    ISSUANCE = 1,
    TRANSFER = 2,
    BURN = 3,
};

struct AssetCommitment {
    AssetCommitmentType type{AssetCommitmentType::TRANSFER};
    uint256 asset_id{};
    uint64_t amount{0};
    uint256 metadata_hash{};
    uint256 member_hash{};

    friend bool operator==(const AssetCommitment&, const AssetCommitment&) = default;
};

struct AssetMetadataCommitment {
    uint256 issuer_id{};
    uint256 document_hash{};
    uint256 rules_hash{};

    friend bool operator==(const AssetMetadataCommitment&, const AssetMetadataCommitment&) = default;
};

struct AssetWhitelistCommitment {
    uint256 list_id{};
    uint256 admin_key_hash{};
    uint256 members_root{};
    uint32_t flags{0};

    friend bool operator==(const AssetWhitelistCommitment&, const AssetWhitelistCommitment&) = default;
};

struct AssetOutput {
    uint32_t output_index{0};
    CAmount carrier_amount{0};
    AssetCommitment commitment{};
    CScript locking_script{};

    friend bool operator==(const AssetOutput&, const AssetOutput&) = default;
};

struct AssetBalanceSummary {
    uint64_t issued{0};
    uint64_t transferred{0};
    uint64_t burned{0};
    bool overflow{false};

    friend bool operator==(const AssetBalanceSummary&, const AssetBalanceSummary&) = default;
};

struct AssetConservationResult {
    uint256 asset_id{};
    uint64_t spent{0};
    uint64_t issued{0};
    uint64_t transferred{0};
    uint64_t burned{0};
    bool balanced{false};
    bool overflow{false};

    friend bool operator==(const AssetConservationResult&, const AssetConservationResult&) = default;
};

struct AssetValidationResult {
    uint32_t output_index{0};
    bool valid{false};
    const char* reason{""};

    friend bool operator==(const AssetValidationResult&, const AssetValidationResult&) = default;
};

struct AssetMetadataOutput {
    uint32_t output_index{0};
    AssetMetadataCommitment commitment{};
};

struct AssetWhitelistOutput {
    uint32_t output_index{0};
    AssetWhitelistCommitment commitment{};
};

struct AssetWhitelistProofCommitment {
    uint32_t asset_output_index{0};
    uint256 member_hash{};
    uint32_t proof_index{0};
    std::vector<uint256> merkle_path{};

    friend bool operator==(const AssetWhitelistProofCommitment&, const AssetWhitelistProofCommitment&) = default;
};

struct AssetWhitelistProofOutput {
    uint32_t output_index{0};
    AssetWhitelistProofCommitment commitment{};
};

std::vector<unsigned char> EncodeAssetCommitment(const AssetCommitment& commitment);
std::optional<AssetCommitment> DecodeAssetCommitment(std::span<const unsigned char> payload);
uint256 HashAssetCommitment(const AssetCommitment& commitment);
uint256 ComputeAssetId(const uint256& metadata_hash, const COutPoint& issuance_anchor);

CScript BuildDefaultAssetLockingScript(const AssetCommitment& commitment);
CScript BuildAssetCommitmentScript(const AssetCommitment& commitment);
CScript BuildAssetCommitmentScript(const AssetCommitment& commitment, const CScript& locking_script);
std::optional<AssetCommitment> DecodeAssetCommitmentScript(const CScript& script);
std::optional<CScript> DecodeAssetCommitmentLockingScript(const CScript& script);
std::optional<AssetOutput> DecodeAssetOutput(const CTxOut& txout, uint32_t output_index);
std::vector<AssetOutput> ExtractAssetOutputs(const CTransaction& tx);
std::optional<AssetValidationResult> FindFirstMalformedAssetCommitmentOutput(const CTransaction& tx);
std::optional<std::vector<AssetOutput>> ExtractSpentAssetOutputs(const CTransaction& tx, const CCoinsViewCache& coins);
AssetBalanceSummary SummarizeAssetOutputs(std::span<const AssetOutput> outputs, const uint256& asset_id);
AssetValidationResult ValidateAssetOutput(const AssetOutput& output);
std::optional<AssetValidationResult> FindFirstInvalidAssetOutput(std::span<const AssetOutput> outputs);
std::optional<AssetValidationResult> FindFirstInvalidAssetIssuanceAnchor(std::span<const AssetOutput> outputs, const CTransaction& tx);
std::vector<AssetConservationResult> CheckAssetConservation(std::span<const AssetOutput> spent_outputs, std::span<const AssetOutput> created_outputs);
std::optional<std::vector<AssetConservationResult>> CheckTransactionAssetConservation(const CTransaction& tx, const CCoinsViewCache& coins);

std::vector<unsigned char> EncodeAssetMetadataCommitment(const AssetMetadataCommitment& commitment);
std::optional<AssetMetadataCommitment> DecodeAssetMetadataCommitment(std::span<const unsigned char> payload);
uint256 HashAssetMetadataCommitment(const AssetMetadataCommitment& commitment);

CScript BuildAssetMetadataCommitmentScript(const AssetMetadataCommitment& commitment);
std::optional<AssetMetadataCommitment> DecodeAssetMetadataCommitmentScript(const CScript& script);
std::optional<AssetMetadataOutput> DecodeAssetMetadataOutput(const CTxOut& txout, uint32_t output_index);
std::vector<AssetMetadataOutput> ExtractAssetMetadataOutputs(const CTransaction& tx);
AssetValidationResult ValidateAssetMetadataOutput(const AssetMetadataOutput& output);
std::optional<AssetValidationResult> FindFirstInvalidAssetMetadataOutput(std::span<const AssetMetadataOutput> outputs);
std::optional<AssetValidationResult> FindFirstUnlinkedAssetMetadata(std::span<const AssetOutput> asset_outputs, std::span<const AssetMetadataOutput> metadata_outputs);

std::vector<unsigned char> EncodeAssetWhitelistCommitment(const AssetWhitelistCommitment& commitment);
std::optional<AssetWhitelistCommitment> DecodeAssetWhitelistCommitment(std::span<const unsigned char> payload);
uint256 HashAssetWhitelistCommitment(const AssetWhitelistCommitment& commitment);

CScript BuildAssetWhitelistCommitmentScript(const AssetWhitelistCommitment& commitment);
std::optional<AssetWhitelistCommitment> DecodeAssetWhitelistCommitmentScript(const CScript& script);
std::optional<AssetWhitelistOutput> DecodeAssetWhitelistOutput(const CTxOut& txout, uint32_t output_index);
std::vector<AssetWhitelistOutput> ExtractAssetWhitelistOutputs(const CTransaction& tx);
AssetValidationResult ValidateAssetWhitelistOutput(const AssetWhitelistOutput& output);
std::optional<AssetValidationResult> FindFirstInvalidAssetWhitelistOutput(std::span<const AssetWhitelistOutput> outputs);
std::optional<AssetValidationResult> FindFirstUnlinkedAssetWhitelist(std::span<const AssetMetadataOutput> metadata_outputs, std::span<const AssetWhitelistOutput> whitelist_outputs);

uint256 ComputeWhitelistMemberLeaf(const uint256& member_hash);
uint256 ComputeWhitelistMembersRoot(std::span<const uint256> member_hashes);
uint256 ComputeWhitelistMembersRoot(const AssetWhitelistProofCommitment& proof);
std::vector<uint256> ComputeWhitelistMerklePath(std::span<const uint256> member_hashes, uint32_t position);
bool VerifyWhitelistProof(const AssetWhitelistProofCommitment& proof, const AssetWhitelistCommitment& whitelist);
std::vector<unsigned char> EncodeAssetWhitelistProofCommitment(const AssetWhitelistProofCommitment& commitment);
std::optional<AssetWhitelistProofCommitment> DecodeAssetWhitelistProofCommitment(std::span<const unsigned char> payload);
uint256 HashAssetWhitelistProofCommitment(const AssetWhitelistProofCommitment& commitment);

CScript BuildAssetWhitelistProofCommitmentScript(const AssetWhitelistProofCommitment& commitment);
std::optional<AssetWhitelistProofCommitment> DecodeAssetWhitelistProofCommitmentScript(const CScript& script);
std::optional<AssetWhitelistProofOutput> DecodeAssetWhitelistProofOutput(const CTxOut& txout, uint32_t output_index);
std::vector<AssetWhitelistProofOutput> ExtractAssetWhitelistProofOutputs(const CTransaction& tx);
AssetValidationResult ValidateAssetWhitelistProofOutput(const AssetWhitelistProofOutput& output);
std::optional<AssetValidationResult> FindFirstInvalidAssetWhitelistProofOutput(std::span<const AssetWhitelistProofOutput> outputs);
std::optional<AssetValidationResult> FindFirstUnprovenWhitelistedTransfer(
    std::span<const AssetOutput> asset_outputs,
    std::span<const AssetMetadataOutput> metadata_outputs,
    std::span<const AssetWhitelistOutput> whitelist_outputs,
    std::span<const AssetWhitelistProofOutput> proof_outputs);

} // namespace bitplus::assets

#endif // BITPLUS_SCRIPT_BITPLUS_ASSETS_H
