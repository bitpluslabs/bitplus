// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/bitplusassetindex.h>

#include <common/args.h>
#include <dbwrapper.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <script/bitplus_assets.h>
#include <undo.h>
#include <util/fs.h>

#include <map>

constexpr uint8_t DB_ASSET_BY_OUTPOINT{'o'};
constexpr uint8_t DB_ASSET_BY_ASSET{'a'};
constexpr uint8_t DB_ASSET_BY_MEMBER{'m'};

std::unique_ptr<BitplusAssetIndex> g_bitplus_asset_index;

struct AssetOutpointKey {
    COutPoint outpoint;

    explicit AssetOutpointKey(const COutPoint& outpoint_in = COutPoint{}) : outpoint(outpoint_in) {}

    SERIALIZE_METHODS(AssetOutpointKey, obj)
    {
        uint8_t prefix{DB_ASSET_BY_OUTPOINT};
        READWRITE(prefix);
        if (prefix != DB_ASSET_BY_OUTPOINT) {
            throw std::ios_base::failure("Invalid format for Bitplus asset outpoint index key");
        }
        READWRITE(obj.outpoint);
    }
};

struct AssetIdKey {
    uint256 asset_id;
    COutPoint outpoint;

    AssetIdKey(const uint256& asset_id_in = uint256{}, const COutPoint& outpoint_in = COutPoint{})
        : asset_id(asset_id_in), outpoint(outpoint_in) {}

    SERIALIZE_METHODS(AssetIdKey, obj)
    {
        uint8_t prefix{DB_ASSET_BY_ASSET};
        READWRITE(prefix);
        if (prefix != DB_ASSET_BY_ASSET) {
            throw std::ios_base::failure("Invalid format for Bitplus asset id index key");
        }
        READWRITE(obj.asset_id);
        READWRITE(obj.outpoint);
    }
};

struct MemberKey {
    uint256 member_hash;
    COutPoint outpoint;

    MemberKey(const uint256& member_hash_in = uint256{}, const COutPoint& outpoint_in = COutPoint{})
        : member_hash(member_hash_in), outpoint(outpoint_in) {}

    SERIALIZE_METHODS(MemberKey, obj)
    {
        uint8_t prefix{DB_ASSET_BY_MEMBER};
        READWRITE(prefix);
        if (prefix != DB_ASSET_BY_MEMBER) {
            throw std::ios_base::failure("Invalid format for Bitplus asset member index key");
        }
        READWRITE(obj.member_hash);
        READWRITE(obj.outpoint);
    }
};

static std::optional<BitplusAssetIndexEntry> DecodeIndexableAssetEntry(
    const CTxOut& txout,
    uint32_t output_index,
    int height,
    const uint256& block_hash,
    bool coinbase)
{
    const std::optional<bitplus::assets::AssetOutput> output{bitplus::assets::DecodeAssetOutput(txout, output_index)};
    if (!output.has_value()) return std::nullopt;

    const bitplus::assets::AssetValidationResult validation{bitplus::assets::ValidateAssetOutput(*output)};
    if (!validation.valid) return std::nullopt;

    return BitplusAssetIndexEntry{
        .carrier_amount = output->carrier_amount,
        .commitment = output->commitment,
        .locking_script = output->locking_script,
        .height = height,
        .block_hash = block_hash,
        .coinbase = coinbase,
    };
}

static void WriteAssetEntry(CDBBatch& batch, const COutPoint& outpoint, const BitplusAssetIndexEntry& entry)
{
    batch.Write(AssetOutpointKey{outpoint}, entry);
    batch.Write(AssetIdKey{entry.commitment.asset_id, outpoint}, "");
    batch.Write(MemberKey{entry.commitment.member_hash, outpoint}, "");
}

static void EraseAssetEntry(CDBBatch& batch, const COutPoint& outpoint, const BitplusAssetIndexEntry& entry)
{
    batch.Erase(AssetOutpointKey{outpoint});
    batch.Erase(AssetIdKey{entry.commitment.asset_id, outpoint});
    batch.Erase(MemberKey{entry.commitment.member_hash, outpoint});
}

BitplusAssetIndex::BitplusAssetIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "bitplusassetindex"),
      m_db{std::make_unique<BaseIndex::DB>(gArgs.GetDataDirNet() / "indexes" / "bitplusassetindex" / "db", n_cache_size, f_memory, f_wipe)}
{
}

interfaces::Chain::NotifyOptions BitplusAssetIndex::CustomOptions()
{
    interfaces::Chain::NotifyOptions options;
    options.connect_undo_data = true;
    options.disconnect_data = true;
    options.disconnect_undo_data = true;
    return options;
}

bool BitplusAssetIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    if (block.height < 0) return false;
    assert(block.data);
    assert(block.height == 0 || block.undo_data);

    CDBBatch batch(*m_db);
    std::map<COutPoint, BitplusAssetIndexEntry> created_in_block;

    for (size_t tx_index{0}; tx_index < block.data->vtx.size(); ++tx_index) {
        const CTransaction& tx{*block.data->vtx.at(tx_index)};
        const bool coinbase{tx.IsCoinBase()};

        if (!coinbase) {
            for (const CTxIn& input : tx.vin) {
                const auto created_it{created_in_block.find(input.prevout)};
                if (created_it != created_in_block.end()) {
                    EraseAssetEntry(batch, input.prevout, created_it->second);
                    created_in_block.erase(created_it);
                    continue;
                }

                BitplusAssetIndexEntry spent_entry;
                if (m_db->Read(AssetOutpointKey{input.prevout}, spent_entry)) {
                    EraseAssetEntry(batch, input.prevout, spent_entry);
                }
            }
        }

        for (uint32_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
            const COutPoint outpoint{tx.GetHash(), output_index};
            const std::optional<BitplusAssetIndexEntry> entry{
                DecodeIndexableAssetEntry(tx.vout[output_index], output_index, block.height, block.hash, coinbase)
            };
            if (!entry.has_value()) continue;

            WriteAssetEntry(batch, outpoint, *entry);
            created_in_block.emplace(outpoint, *entry);
        }
    }

    m_db->WriteBatch(batch);
    return true;
}

bool BitplusAssetIndex::CustomRemove(const interfaces::BlockInfo& block)
{
    if (block.height < 0) return false;
    assert(block.data);
    assert(block.height == 0 || block.undo_data);

    CDBBatch batch(*m_db);

    for (size_t tx_index{block.data->vtx.size()}; tx_index > 0; --tx_index) {
        const CTransaction& tx{*block.data->vtx.at(tx_index - 1)};
        const bool coinbase{tx.IsCoinBase()};

        for (uint32_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
            const COutPoint outpoint{tx.GetHash(), output_index};
            const std::optional<BitplusAssetIndexEntry> entry{
                DecodeIndexableAssetEntry(tx.vout[output_index], output_index, block.height, block.hash, coinbase)
            };
            if (entry.has_value()) {
                EraseAssetEntry(batch, outpoint, *entry);
            }
        }

        if (!coinbase) {
            const CTxUndo& tx_undo{block.undo_data->vtxundo.at(tx_index - 2)};
            for (size_t input_index{0}; input_index < tx_undo.vprevout.size(); ++input_index) {
                const Coin& coin{tx_undo.vprevout[input_index]};
                const COutPoint outpoint{tx.vin[input_index].prevout};
                const std::optional<BitplusAssetIndexEntry> entry{
                    DecodeIndexableAssetEntry(coin.out, outpoint.n, coin.nHeight, *block.prev_hash, coin.IsCoinBase())
                };
                if (entry.has_value()) {
                    WriteAssetEntry(batch, outpoint, *entry);
                }
            }
        }
    }

    m_db->WriteBatch(batch);
    return true;
}

bool BitplusAssetIndex::ForEachAssetUtxo(
    const uint256& asset_id,
    const std::optional<COutPoint>& after,
    int64_t& searched,
    bool& cursor_found,
    const BitplusAssetIndexCallback& callback) const
{
    searched = 0;
    cursor_found = !after.has_value();

    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    AssetIdKey key;
    for (it->Seek(std::pair{DB_ASSET_BY_ASSET, asset_id}); it->Valid() && it->GetKey(key) && key.asset_id == asset_id; it->Next()) {
        ++searched;
        if (!cursor_found) {
            cursor_found = key.outpoint == *after;
            continue;
        }

        BitplusAssetIndexEntry entry;
        if (!m_db->Read(AssetOutpointKey{key.outpoint}, entry)) {
            LogError("Bitplus asset index missing outpoint entry for %s:%u", key.outpoint.hash.GetHex(), key.outpoint.n);
            continue;
        }
        if (!callback(key.outpoint, entry)) return true;
    }
    return true;
}

bool BitplusAssetIndex::ForEachMemberUtxo(
    const uint256& member_hash,
    int64_t& searched,
    const BitplusAssetIndexCallback& callback) const
{
    searched = 0;

    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    MemberKey key;
    for (it->Seek(std::pair{DB_ASSET_BY_MEMBER, member_hash}); it->Valid() && it->GetKey(key) && key.member_hash == member_hash; it->Next()) {
        ++searched;
        BitplusAssetIndexEntry entry;
        if (!m_db->Read(AssetOutpointKey{key.outpoint}, entry)) {
            LogError("Bitplus asset index missing outpoint entry for %s:%u", key.outpoint.hash.GetHex(), key.outpoint.n);
            continue;
        }
        if (!callback(key.outpoint, entry)) return true;
    }
    return true;
}

BaseIndex::DB& BitplusAssetIndex::GetDB() const { return *m_db; }
