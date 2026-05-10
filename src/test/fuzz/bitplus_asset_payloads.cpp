// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bitplus_assets.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

bitplus::assets::AssetCommitmentType ConsumeAssetType(FuzzedDataProvider& provider)
{
    switch (provider.ConsumeIntegralInRange<int>(0, 2)) {
    case 0:
        return bitplus::assets::AssetCommitmentType::ISSUANCE;
    case 1:
        return bitplus::assets::AssetCommitmentType::TRANSFER;
    default:
        return bitplus::assets::AssetCommitmentType::BURN;
    }
}

template <typename T, typename EncodeFn, typename DecodeFn, typename HashFn>
void AssertRoundTripStable(const T& value, EncodeFn encode, DecodeFn decode, HashFn hash)
{
    const std::vector<unsigned char> encoded{encode(value)};
    const std::optional<T> decoded{decode(encoded)};
    assert(decoded.has_value());
    assert(*decoded == value);
    assert(encode(*decoded) == encoded);
    assert(hash(*decoded) == hash(value));
}

} // namespace

FUZZ_TARGET(bitplus_asset_payloads)
{
    (void)bitplus::assets::DecodeAssetCommitment(buffer);
    (void)bitplus::assets::DecodeAssetMetadataCommitment(buffer);
    (void)bitplus::assets::DecodeAssetWhitelistCommitment(buffer);
    (void)bitplus::assets::DecodeAssetWhitelistProofCommitment(buffer);

    FuzzedDataProvider provider(buffer.data(), buffer.size());

    const std::vector<unsigned char> raw_payload{ConsumeRandomLengthByteVector(provider, 256)};
    (void)bitplus::assets::DecodeAssetCommitment(raw_payload);
    (void)bitplus::assets::DecodeAssetMetadataCommitment(raw_payload);
    (void)bitplus::assets::DecodeAssetWhitelistCommitment(raw_payload);
    (void)bitplus::assets::DecodeAssetWhitelistProofCommitment(raw_payload);

    const CScript raw_script{raw_payload.begin(), raw_payload.end()};
    (void)bitplus::assets::DecodeAssetCommitmentScript(raw_script);
    (void)bitplus::assets::DecodeAssetCommitmentLockingScript(raw_script);
    (void)bitplus::assets::DecodeAssetMetadataCommitmentScript(raw_script);
    (void)bitplus::assets::DecodeAssetWhitelistCommitmentScript(raw_script);
    (void)bitplus::assets::DecodeAssetWhitelistProofCommitmentScript(raw_script);

    const bitplus::assets::AssetCommitment asset{
        .type = ConsumeAssetType(provider),
        .asset_id = ConsumeUInt256(provider),
        .amount = provider.ConsumeIntegral<uint64_t>(),
        .metadata_hash = ConsumeUInt256(provider),
        .member_hash = ConsumeUInt256(provider),
    };
    AssertRoundTripStable(
        asset,
        bitplus::assets::EncodeAssetCommitment,
        bitplus::assets::DecodeAssetCommitment,
        bitplus::assets::HashAssetCommitment);

    const bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = ConsumeUInt256(provider),
        .document_hash = ConsumeUInt256(provider),
        .rules_hash = ConsumeUInt256(provider),
    };
    AssertRoundTripStable(
        metadata,
        bitplus::assets::EncodeAssetMetadataCommitment,
        bitplus::assets::DecodeAssetMetadataCommitment,
        bitplus::assets::HashAssetMetadataCommitment);

    const bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = ConsumeUInt256(provider),
        .admin_key_hash = ConsumeUInt256(provider),
        .members_root = ConsumeUInt256(provider),
        .flags = provider.ConsumeIntegral<uint32_t>(),
    };
    AssertRoundTripStable(
        whitelist,
        bitplus::assets::EncodeAssetWhitelistCommitment,
        bitplus::assets::DecodeAssetWhitelistCommitment,
        bitplus::assets::HashAssetWhitelistCommitment);

    std::vector<uint256> merkle_path;
    const size_t path_len{provider.ConsumeIntegralInRange<size_t>(0, 32)};
    merkle_path.reserve(path_len);
    for (size_t i{0}; i < path_len; ++i) {
        merkle_path.push_back(ConsumeUInt256(provider));
    }
    const bitplus::assets::AssetWhitelistProofCommitment proof{
        .asset_output_index = provider.ConsumeIntegral<uint32_t>(),
        .member_hash = ConsumeUInt256(provider),
        .proof_index = provider.ConsumeIntegral<uint32_t>(),
        .merkle_path = std::move(merkle_path),
    };
    AssertRoundTripStable(
        proof,
        bitplus::assets::EncodeAssetWhitelistProofCommitment,
        bitplus::assets::DecodeAssetWhitelistProofCommitment,
        bitplus::assets::HashAssetWhitelistProofCommitment);
}
