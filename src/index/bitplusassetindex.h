// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_INDEX_BITPLUSASSETINDEX_H
#define BITPLUS_INDEX_BITPLUSASSETINDEX_H

#include <consensus/amount.h>
#include <index/base.h>
#include <primitives/transaction.h>
#include <script/bitplus_assets.h>
#include <script/script.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace interfaces {
class Chain;
}

static constexpr bool DEFAULT_BITPLUSASSETINDEX{false};

struct BitplusAssetIndexEntry {
    CAmount carrier_amount{0};
    bitplus::assets::AssetCommitment commitment{};
    CScript locking_script{};
    int height{0};
    uint256 block_hash{};
    bool coinbase{false};

    friend bool operator==(const BitplusAssetIndexEntry&, const BitplusAssetIndexEntry&) = default;

    SERIALIZE_METHODS(BitplusAssetIndexEntry, obj)
    {
        uint8_t type{static_cast<uint8_t>(obj.commitment.type)};
        READWRITE(obj.carrier_amount);
        READWRITE(type, obj.commitment.asset_id, obj.commitment.amount, obj.commitment.metadata_hash, obj.commitment.member_hash);
        SER_READ(obj, obj.commitment.type = static_cast<bitplus::assets::AssetCommitmentType>(type));
        READWRITE(obj.locking_script);
        READWRITE(obj.height);
        READWRITE(obj.block_hash);
        READWRITE(obj.coinbase);
    }
};

using BitplusAssetIndexCallback = std::function<bool(const COutPoint& outpoint, const BitplusAssetIndexEntry& entry)>;

class BitplusAssetIndex final : public BaseIndex
{
private:
    std::unique_ptr<BaseIndex::DB> m_db;

    bool AllowPrune() const override { return false; }

protected:
    interfaces::Chain::NotifyOptions CustomOptions() override;

    bool CustomAppend(const interfaces::BlockInfo& block) override;

    bool CustomRemove(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

public:
    explicit BitplusAssetIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool ForEachAssetUtxo(
        const uint256& asset_id,
        const std::optional<COutPoint>& after,
        int64_t& searched,
        bool& cursor_found,
        const BitplusAssetIndexCallback& callback) const;

    bool ForEachMemberUtxo(
        const uint256& member_hash,
        int64_t& searched,
        const BitplusAssetIndexCallback& callback) const;
};

extern std::unique_ptr<BitplusAssetIndex> g_bitplus_asset_index;

#endif // BITPLUS_INDEX_BITPLUSASSETINDEX_H
