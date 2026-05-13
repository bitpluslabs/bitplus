// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/bitplus_util.h>

#include <chain.h>
#include <coins.h>
#include <core_io.h>
#include <index/bitplusassetindex.h>
#include <node/context.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <uint256.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <validation.h>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <univalue.h>

using node::NodeContext;
using namespace bitplus::rpc;

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
    RejectUnknownObjectFields(cursor, {"bestblock", "height", "asset_id", "filters_hash", "txid", "vout"}, "cursor");
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
        .bestblock = ParseHashV(bestblock_value, "cursor.bestblock"),
        .height = height_value.getInt<int64_t>(),
        .asset_id = ParseHashV(asset_id_value, "cursor.asset_id"),
        .filters_hash = ParseHashV(filters_hash_value, "cursor.filters_hash"),
        .after = COutPoint{
            Txid::FromUint256(ParseHashV(txid_value, "cursor.txid")),
            0,
        },
    };
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

static bool TryGetSyncedBitplusAssetIndexTip(ChainstateManager& chainman, const CBlockIndex*& tip)
{
    if (!g_bitplus_asset_index || !g_bitplus_asset_index->BlockUntilSyncedToCurrentChain()) return false;

    {
        LOCK(cs_main);
        tip = CHECK_NONFATAL(chainman.ActiveChainstate().m_chain.Tip());
    }

    const IndexSummary index_summary{g_bitplus_asset_index->GetSummary()};
    return index_summary.synced &&
        index_summary.best_block_height == tip->nHeight &&
        index_summary.best_block_hash == tip->GetBlockHash();
}

static void WriteHashString(HashWriter& writer, std::string_view value);
static void WriteAssetScanFiltersForHash(HashWriter& writer, const BitplusAssetScanFilters& filters);
static void WriteOptionalAssetScanCursorForHash(HashWriter& writer, const std::optional<BitplusAssetScanCursor>& cursor);

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
            {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::STR_HEX, "member_hash", /*optional=*/true, "Filtered member hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::OBJ, "cursor", /*optional=*/true, "Applied continuation cursor.", {
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash from the cursor."},
                {RPCResult::Type::NUM, "height", "Chain height from the cursor."},
                {RPCResult::Type::STR_HEX, "asset_id", "Asset id from the cursor."},
                {RPCResult::Type::STR_HEX, "filters_hash", "Applied filters hash from the cursor."},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id from the cursor."},
                {RPCResult::Type::NUM, "vout", "Output index from the cursor."},
            }},
            {RPCResult::Type::STR, "query_backend", "Backend used for the query: asset_index or utxo_scan."},
            {RPCResult::Type::STR, "index_fallback_reason", /*optional=*/true, "Reason the optional asset index was bypassed after initially being selected."},
            {RPCResult::Type::NUM, "searched_txouts", "Backend-specific number of rows or UTXOs examined."},
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
                {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ELISION, "", "Filter fields vary by query."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::OBJ_DYN, "cursor", /*optional=*/true, "Applied continuation cursor.", {
                    {RPCResult::Type::ELISION, "", "Cursor fields vary by query."},
                }},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this scan.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the scan chain snapshot."},
                {RPCResult::Type::NUM, "max_results", "Maximum number of matching UTXOs requested."},
                {RPCResult::Type::BOOL, "cursor_applied", "Whether this page started from a continuation cursor."},
                {RPCResult::Type::BOOL, "complete", "Whether the scan completed before max_results was reached."},
                {RPCResult::Type::BOOL, "has_next_cursor", "Whether a next_cursor was returned."},
                {RPCResult::Type::NUM, "matches", "Number of returned matching UTXOs."},
                {RPCResult::Type::STR_HEX, "reconciliation_hash", "Hash for this bounded scan page."},
            }},
            {RPCResult::Type::BOOL, "complete", "Whether the scan completed before max_results was reached."},
            {RPCResult::Type::OBJ, "next_cursor", /*optional=*/true, "Cursor to pass into the next call when complete is false.", {
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
                        {RPCResult::Type::ELISION, "", "Decoded commitment fields vary by type."},
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
            const uint256 filters_hash{CompactReportHash("BitplusAssetScanFilters", filters_json)};
            const std::optional<BitplusAssetScanCursor> scan_cursor{
                request.params[3].isNull() ? std::optional<BitplusAssetScanCursor>{} :
                    std::optional<BitplusAssetScanCursor>{ParseBitplusAssetScanCursor(request.params[3])}
            };

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const CBlockIndex* indexed_tip{nullptr};
            const bool use_asset_index{TryGetSyncedBitplusAssetIndexTip(chainman, indexed_tip)};
            const char* index_fallback_reason{nullptr};
            if (use_asset_index) {
                const char* query_backend{"asset_index"};
                const CBlockIndex* tip{indexed_tip};
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
                bool cursor_found{false};
                std::optional<COutPoint> last_returned;
                UniValue utxos{UniValue::VARR};
                HashWriter reconciliation_writer{};
                WriteHashString(reconciliation_writer, "BitplusAssetUtxoScan");
                reconciliation_writer << tip->GetBlockHash();
                reconciliation_writer << static_cast<int64_t>(tip->nHeight);
                reconciliation_writer << asset_id;
                reconciliation_writer << static_cast<uint64_t>(max_results);
                WriteAssetScanFiltersForHash(reconciliation_writer, filters);
                WriteOptionalAssetScanCursorForHash(reconciliation_writer, scan_cursor);

                const bool ok{g_bitplus_asset_index->ForEachAssetUtxo(
                    asset_id,
                    scan_cursor.has_value() ? std::optional<COutPoint>{scan_cursor->after} : std::optional<COutPoint>{},
                    searched,
                    cursor_found,
                    [&](const COutPoint& outpoint, const BitplusAssetIndexEntry& entry) {
                        const int64_t confirmations{static_cast<int64_t>(tip->nHeight - entry.height + 1)};
                        if (!filters.Match(entry.commitment, confirmations)) return true;

                        const CBlockIndex& coin_block{*CHECK_NONFATAL(tip->GetAncestor(entry.height))};
                        bitplus::assets::AssetOutput asset_output{
                            .output_index = outpoint.n,
                            .carrier_amount = entry.carrier_amount,
                            .commitment = entry.commitment,
                            .locking_script = entry.locking_script,
                        };
                        UniValue utxo{UniValue::VOBJ};
                        utxo.pushKV("txid", outpoint.hash.GetHex());
                        utxo.pushKV("vout", static_cast<int64_t>(outpoint.n));
                        utxo.pushKV("amount", ValueFromAmount(entry.carrier_amount));
                        utxo.pushKV("scriptPubKey", HexStr(bitplus::assets::BuildAssetCommitmentScript(entry.commitment, entry.locking_script)));
                        utxo.pushKV("coinbase", entry.coinbase);
                        utxo.pushKV("height", static_cast<int64_t>(entry.height));
                        utxo.pushKV("blockhash", coin_block.GetBlockHash().GetHex());
                        utxo.pushKV("confirmations", confirmations);
                        utxo.pushKV("commitment", DecodedAssetCommitmentToJSON(asset_output));
                        utxos.push_back(std::move(utxo));
                        reconciliation_writer << outpoint;
                        reconciliation_writer << entry.carrier_amount;
                        reconciliation_writer << bitplus::assets::BuildAssetCommitmentScript(entry.commitment, entry.locking_script);
                        reconciliation_writer << entry.coinbase;
                        reconciliation_writer << static_cast<int64_t>(entry.height);
                        reconciliation_writer << coin_block.GetBlockHash();
                        reconciliation_writer << bitplus::assets::EncodeAssetCommitment(entry.commitment);
                        reconciliation_writer << entry.locking_script;
                        last_returned = outpoint;
                        if (utxos.size() >= max_results) {
                            complete = false;
                            return false;
                        }
                        return true;
                    })};
                if (!ok) {
                    LogError("Bitplus asset index read failed; falling back to active UTXO scan");
                    index_fallback_reason = "index_read_failed";
                } else {
                    if (!cursor_found) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor outpoint was not found in the active UTXO set");
                    ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);

                    UniValue result{UniValue::VOBJ};
                    result.pushKV("report_type", "asset_utxo_scan");
                    result.pushKV("asset_id", asset_id.ToString());
                    result.pushKV("filters", filters_json);
                    if (scan_cursor.has_value()) result.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
                    result.pushKV("query_backend", query_backend);
                    result.pushKV("searched_txouts", searched);
                    result.pushKV("height", static_cast<int64_t>(tip->nHeight));
                    result.pushKV("bestblock", tip->GetBlockHash().GetHex());
                    result.pushKV("chain_snapshot", BitplusChainSnapshotToJSON(*tip));
                    reconciliation_writer << complete;
                    reconciliation_writer << static_cast<int64_t>(utxos.size());
                    const std::string reconciliation_hash{reconciliation_writer.GetSHA256().ToString()};
                    result.pushKV("reconciliation_hash", reconciliation_hash);
                    UniValue scan_summary{UniValue::VOBJ};
                    scan_summary.pushKV("report_type", "asset_utxo_scan");
                    scan_summary.pushKV("asset_id", asset_id.ToString());
                    scan_summary.pushKV("filters", filters_json);
                    scan_summary.pushKV("filters_hash", filters_hash.ToString());
                    if (scan_cursor.has_value()) scan_summary.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
                    scan_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
                    scan_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
                    const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
                    scan_summary.pushKV("chain_snapshot", chain_snapshot);
                    scan_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshot", chain_snapshot).ToString());
                    scan_summary.pushKV("max_results", static_cast<int64_t>(max_results));
                    scan_summary.pushKV("cursor_applied", scan_cursor.has_value());
                    scan_summary.pushKV("complete", complete);
                    scan_summary.pushKV("has_next_cursor", !complete && last_returned.has_value());
                    scan_summary.pushKV("matches", static_cast<int64_t>(utxos.size()));
                    scan_summary.pushKV("reconciliation_hash", reconciliation_hash);
                    result.pushKV("scan_summary_hash", CompactReportHash("BitplusAssetUtxoScanSummary", scan_summary).ToString());
                    result.pushKV("scan_summary", std::move(scan_summary));
                    result.pushKV("complete", complete);
                    if (!complete && last_returned.has_value()) result.pushKV("next_cursor", BitplusAssetScanCursorToJSON(*tip, asset_id, filters_hash, *last_returned));
                    result.pushKV("matches", static_cast<int64_t>(utxos.size()));
                    result.pushKV("utxos", std::move(utxos));
                    return result;
                }
            }

            const char* query_backend{"utxo_scan"};
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
            WriteHashString(reconciliation_writer, "BitplusAssetUtxoScan");
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
            result.pushKV("asset_id", asset_id.ToString());
            result.pushKV("filters", filters_json);
            if (scan_cursor.has_value()) result.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
            result.pushKV("query_backend", query_backend);
            if (index_fallback_reason) result.pushKV("index_fallback_reason", index_fallback_reason);
            result.pushKV("searched_txouts", searched);
            result.pushKV("height", static_cast<int64_t>(tip->nHeight));
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("chain_snapshot", BitplusChainSnapshotToJSON(*tip));
            reconciliation_writer << complete;
            reconciliation_writer << static_cast<int64_t>(utxos.size());
            const std::string reconciliation_hash{reconciliation_writer.GetSHA256().ToString()};
            result.pushKV("reconciliation_hash", reconciliation_hash);
            UniValue scan_summary{UniValue::VOBJ};
            scan_summary.pushKV("report_type", "asset_utxo_scan");
            scan_summary.pushKV("asset_id", asset_id.ToString());
            scan_summary.pushKV("filters", filters_json);
            scan_summary.pushKV("filters_hash", filters_hash.ToString());
            if (scan_cursor.has_value()) scan_summary.pushKV("cursor", BitplusAssetScanCursorToJSON(*tip, scan_cursor->asset_id, scan_cursor->filters_hash, scan_cursor->after));
            scan_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            scan_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            scan_summary.pushKV("chain_snapshot", chain_snapshot);
            scan_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshot", chain_snapshot).ToString());
            scan_summary.pushKV("max_results", static_cast<int64_t>(max_results));
            scan_summary.pushKV("cursor_applied", scan_cursor.has_value());
            scan_summary.pushKV("complete", complete);
            scan_summary.pushKV("has_next_cursor", !complete && last_returned.has_value());
            scan_summary.pushKV("matches", static_cast<int64_t>(utxos.size()));
            scan_summary.pushKV("reconciliation_hash", reconciliation_hash);
            result.pushKV("scan_summary_hash", CompactReportHash("BitplusAssetUtxoScanSummary", scan_summary).ToString());
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
        "Summarize confirmed live Bitplus asset outputs by asset id, using the Bitplus asset index when enabled and synced.\n",
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
            {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::STR_HEX, "member_hash", /*optional=*/true, "Filtered member hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::STR, "query_backend", "Backend used for the query: asset_index or utxo_scan."},
            {RPCResult::Type::STR, "index_fallback_reason", /*optional=*/true, "Reason the optional asset index was bypassed after initially being selected."},
            {RPCResult::Type::NUM, "searched_txouts", "Backend-specific number of rows or UTXOs examined."},
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
                {RPCResult::Type::STR_HEX, "asset_id", "The requested asset id."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ELISION, "", "Filter fields vary by query."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the stats chain snapshot."},
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

            const CBlockIndex* tip{nullptr};
            bool use_asset_index{TryGetSyncedBitplusAssetIndexTip(chainman, tip)};
            const char* query_backend{use_asset_index ? "asset_index" : "utxo_scan"};
            const char* index_fallback_reason{nullptr};

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

            auto add_asset_output = [&](const bitplus::assets::AssetOutput& asset_output, int64_t confirmations) {
                if (asset_output.commitment.asset_id != asset_id || !filters.Match(asset_output.commitment, confirmations)) return;

                ++utxo_count;
                min_confirmations_observed = min_confirmations_observed.has_value() ? std::min(*min_confirmations_observed, confirmations) : confirmations;
                max_confirmations_observed = max_confirmations_observed.has_value() ? std::max(*max_confirmations_observed, confirmations) : confirmations;
                add_amount(total_amount, asset_output.commitment.amount);
                switch (asset_output.commitment.type) {
                case bitplus::assets::AssetCommitmentType::ISSUANCE:
                    add_amount(issued_amount, asset_output.commitment.amount);
                    break;
                case bitplus::assets::AssetCommitmentType::TRANSFER:
                    add_amount(held_amount, asset_output.commitment.amount);
                    add_counter(by_holder_member, asset_output.commitment.member_hash.ToString(), asset_output.commitment.amount);
                    break;
                case bitplus::assets::AssetCommitmentType::BURN:
                    add_amount(burned_amount, asset_output.commitment.amount);
                    break;
                }
                add_counter(by_type, AssetCommitmentTypeToString(asset_output.commitment.type), asset_output.commitment.amount);
                add_counter(by_metadata, asset_output.commitment.metadata_hash.ToString(), asset_output.commitment.amount);
                add_counter(by_member, asset_output.commitment.member_hash.ToString(), asset_output.commitment.amount);
            };

            if (use_asset_index) {
                bool cursor_found{false};
                const bool ok{g_bitplus_asset_index->ForEachAssetUtxo(
                    asset_id,
                    std::nullopt,
                    searched,
                    cursor_found,
                    [&](const COutPoint& outpoint, const BitplusAssetIndexEntry& entry) {
                        if (searched % 8192 == 0) node.rpc_interruption_point();
                        bitplus::assets::AssetOutput asset_output{
                            .output_index = outpoint.n,
                            .carrier_amount = entry.carrier_amount,
                            .commitment = entry.commitment,
                            .locking_script = entry.locking_script,
                        };
                        add_asset_output(asset_output, static_cast<int64_t>(tip->nHeight - entry.height + 1));
                        return true;
                    })};
                if (!ok) {
                    LogError("Bitplus asset index read failed; falling back to active UTXO scan");
                    use_asset_index = false;
                    query_backend = "utxo_scan";
                    index_fallback_reason = "index_read_failed";
                } else {
                    ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);
                }
            }
            if (!use_asset_index) {
                searched = 0;
                utxo_count = 0;
                total_amount = 0;
                issued_amount = 0;
                held_amount = 0;
                burned_amount = 0;
                overflow = false;
                by_type.clear();
                by_metadata.clear();
                by_member.clear();
                by_holder_member.clear();
                min_confirmations_observed.reset();
                max_confirmations_observed.reset();

                std::unique_ptr<CCoinsViewCursor> cursor;
                {
                    LOCK(cs_main);
                    Chainstate& active_chainstate{chainman.ActiveChainstate()};
                    active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                    cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                    tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
                }

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
                    if (asset_output.has_value()) {
                        add_asset_output(*asset_output, static_cast<int64_t>(tip->nHeight - coin.nHeight + 1));
                    }
                    cursor->Next();
                }
                ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("report_type", "asset_stats");
            result.pushKV("asset_id", asset_id.ToString());
            result.pushKV("filters", filters.ToJSON());
            result.pushKV("query_backend", query_backend);
            if (index_fallback_reason) result.pushKV("index_fallback_reason", index_fallback_reason);
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
            WriteHashString(reconciliation_writer, "BitplusAssetStats");
            reconciliation_writer << tip->GetBlockHash();
            reconciliation_writer << static_cast<int64_t>(tip->nHeight);
            reconciliation_writer << asset_id;
            WriteAssetScanFiltersForHash(reconciliation_writer, filters);
            reconciliation_writer << min_confirmations_observed.has_value();
            if (min_confirmations_observed.has_value()) reconciliation_writer << *min_confirmations_observed;
            reconciliation_writer << max_confirmations_observed.has_value();
            if (max_confirmations_observed.has_value()) reconciliation_writer << *max_confirmations_observed;
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
            reconciliation_summary.pushKV("asset_id", asset_id.ToString());
            const UniValue filters_json{filters.ToJSON()};
            reconciliation_summary.pushKV("filters", filters_json);
            reconciliation_summary.pushKV("filters_hash", CompactReportHash("BitplusAssetScanFilters", filters_json).ToString());
            reconciliation_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            reconciliation_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            reconciliation_summary.pushKV("chain_snapshot", chain_snapshot);
            reconciliation_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshot", chain_snapshot).ToString());
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
            result.pushKV("reconciliation_summary_hash", CompactReportHash("BitplusAssetStatsSummary", reconciliation_summary).ToString());
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
        "Summarize confirmed live Bitplus asset outputs by member hash, grouped by asset id, using the Bitplus asset index when enabled and synced.\n",
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
            {RPCResult::Type::STR_HEX, "member_hash", "The requested member hash."},
            {RPCResult::Type::OBJ, "filters", "Applied filters.", {
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "Filtered asset id."},
                {RPCResult::Type::STR, "type", /*optional=*/true, "Filtered asset type."},
                {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Filtered metadata commitment hash."},
                {RPCResult::Type::NUM, "min_confirmations", /*optional=*/true, "Filtered minimum confirmations."},
            }},
            {RPCResult::Type::STR, "query_backend", "Backend used for the query: asset_index or utxo_scan."},
            {RPCResult::Type::STR, "index_fallback_reason", /*optional=*/true, "Reason the optional asset index was bypassed after initially being selected."},
            {RPCResult::Type::NUM, "searched_txouts", "Backend-specific number of rows or UTXOs examined."},
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
                {RPCResult::Type::STR_HEX, "member_hash", "The requested member hash."},
                {RPCResult::Type::OBJ_DYN, "filters", "Applied filters.", {
                    {RPCResult::Type::ELISION, "", "Filter fields vary by query."},
                }},
                {RPCResult::Type::STR_HEX, "filters_hash", "Deterministic hash committing to the applied filters."},
                {RPCResult::Type::NUM, "height", "Chain height at the scan snapshot."},
                {RPCResult::Type::STR_HEX, "bestblock", "Best block hash at the scan snapshot."},
                {RPCResult::Type::OBJ, "chain_snapshot", "Active chain snapshot used by this stats report.", {
                    {RPCResult::Type::NUM, "height", "Chain height."},
                    {RPCResult::Type::STR_HEX, "bestblock", "Best block hash."},
                }},
                {RPCResult::Type::STR_HEX, "chain_snapshot_hash", "Deterministic hash committing to the stats chain snapshot."},
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

            const CBlockIndex* tip{nullptr};
            bool use_asset_index{TryGetSyncedBitplusAssetIndexTip(chainman, tip)};
            const char* query_backend{use_asset_index ? "asset_index" : "utxo_scan"};
            const char* index_fallback_reason{nullptr};

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

            auto add_asset_output = [&](const bitplus::assets::AssetOutput& asset_output, int64_t confirmations) {
                if (asset_output.commitment.member_hash == member_hash &&
                    (!asset_id_filter.has_value() || asset_output.commitment.asset_id == *asset_id_filter) &&
                    filters.Match(asset_output.commitment, confirmations)) {
                    ++utxo_count;
                    min_confirmations_observed = min_confirmations_observed.has_value() ? std::min(*min_confirmations_observed, confirmations) : confirmations;
                    max_confirmations_observed = max_confirmations_observed.has_value() ? std::max(*max_confirmations_observed, confirmations) : confirmations;
                    add_amount(total_amount, asset_output.commitment.amount);
                    switch (asset_output.commitment.type) {
                    case bitplus::assets::AssetCommitmentType::ISSUANCE:
                        add_amount(issued_amount, asset_output.commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::TRANSFER:
                        add_amount(held_amount, asset_output.commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::BURN:
                        add_amount(burned_amount, asset_output.commitment.amount);
                        break;
                    }

                    const std::string asset_id{asset_output.commitment.asset_id.ToString()};
                    BitplusMemberAssetStats& asset_stats{assets[asset_id]};
                    ++asset_stats.utxo_count;
                    asset_stats.min_confirmations_observed = asset_stats.min_confirmations_observed.has_value() ? std::min(*asset_stats.min_confirmations_observed, confirmations) : confirmations;
                    asset_stats.max_confirmations_observed = asset_stats.max_confirmations_observed.has_value() ? std::max(*asset_stats.max_confirmations_observed, confirmations) : confirmations;
                    add_amount(asset_stats.total_amount, asset_output.commitment.amount);
                    switch (asset_output.commitment.type) {
                    case bitplus::assets::AssetCommitmentType::ISSUANCE:
                        add_amount(asset_stats.issued_amount, asset_output.commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::TRANSFER:
                        add_amount(asset_stats.held_amount, asset_output.commitment.amount);
                        break;
                    case bitplus::assets::AssetCommitmentType::BURN:
                        add_amount(asset_stats.burned_amount, asset_output.commitment.amount);
                        break;
                    }
                    add_counter(asset_stats.by_type, AssetCommitmentTypeToString(asset_output.commitment.type), asset_output.commitment.amount);
                    add_counter(asset_stats.by_metadata, asset_output.commitment.metadata_hash.ToString(), asset_output.commitment.amount);
                }
            };

            if (use_asset_index) {
                const bool ok{g_bitplus_asset_index->ForEachMemberUtxo(
                    member_hash,
                    searched,
                    [&](const COutPoint& outpoint, const BitplusAssetIndexEntry& entry) {
                        if (searched % 8192 == 0) node.rpc_interruption_point();
                        bitplus::assets::AssetOutput asset_output{
                            .output_index = outpoint.n,
                            .carrier_amount = entry.carrier_amount,
                            .commitment = entry.commitment,
                            .locking_script = entry.locking_script,
                        };
                        add_asset_output(asset_output, static_cast<int64_t>(tip->nHeight - entry.height + 1));
                        return true;
                    })};
                if (!ok) {
                    LogError("Bitplus asset index read failed; falling back to active UTXO scan");
                    use_asset_index = false;
                    query_backend = "utxo_scan";
                    index_fallback_reason = "index_read_failed";
                } else {
                    ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);
                }
            }
            if (!use_asset_index) {
                searched = 0;
                utxo_count = 0;
                total_amount = 0;
                issued_amount = 0;
                held_amount = 0;
                burned_amount = 0;
                overflow = false;
                assets.clear();
                min_confirmations_observed.reset();
                max_confirmations_observed.reset();

                std::unique_ptr<CCoinsViewCursor> cursor;
                {
                    LOCK(cs_main);
                    Chainstate& active_chainstate{chainman.ActiveChainstate()};
                    active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                    cursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                    tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
                }

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
                    if (asset_output.has_value()) {
                        add_asset_output(*asset_output, static_cast<int64_t>(tip->nHeight - coin.nHeight + 1));
                    }
                    cursor->Next();
                }
                ThrowIfActiveChainTipChangedDuringBitplusScan(chainman, *tip);
            }

            UniValue filters_json{filters.ToJSON()};
            if (asset_id_filter.has_value()) filters_json.pushKV("asset_id", asset_id_filter->ToString());

            UniValue assets_json{UniValue::VOBJ};
            int64_t holder_asset_count{0};
            HashWriter reconciliation_writer{};
            WriteHashString(reconciliation_writer, "BitplusMemberAssetStats");
            reconciliation_writer << tip->GetBlockHash();
            reconciliation_writer << static_cast<int64_t>(tip->nHeight);
            reconciliation_writer << member_hash;
            WriteAssetScanFiltersForHash(reconciliation_writer, filters);
            WriteOptionalHash(reconciliation_writer, asset_id_filter);
            reconciliation_writer << min_confirmations_observed.has_value();
            if (min_confirmations_observed.has_value()) reconciliation_writer << *min_confirmations_observed;
            reconciliation_writer << max_confirmations_observed.has_value();
            if (max_confirmations_observed.has_value()) reconciliation_writer << *max_confirmations_observed;
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
            result.pushKV("member_hash", member_hash.ToString());
            result.pushKV("filters", filters_json);
            result.pushKV("query_backend", query_backend);
            if (index_fallback_reason) result.pushKV("index_fallback_reason", index_fallback_reason);
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
            reconciliation_summary.pushKV("member_hash", member_hash.ToString());
            reconciliation_summary.pushKV("filters", filters_json);
            reconciliation_summary.pushKV("filters_hash", CompactReportHash("BitplusMemberAssetStatsFilters", filters_json).ToString());
            reconciliation_summary.pushKV("height", static_cast<int64_t>(tip->nHeight));
            reconciliation_summary.pushKV("bestblock", tip->GetBlockHash().GetHex());
            const UniValue chain_snapshot{BitplusChainSnapshotToJSON(*tip)};
            reconciliation_summary.pushKV("chain_snapshot", chain_snapshot);
            reconciliation_summary.pushKV("chain_snapshot_hash", CompactReportHash("BitplusChainSnapshot", chain_snapshot).ToString());
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
            result.pushKV("reconciliation_summary_hash", CompactReportHash("BitplusMemberAssetStatsSummary", reconciliation_summary).ToString());
            result.pushKV("reconciliation_summary", std::move(reconciliation_summary));
            result.pushKV("assets", std::move(assets_json));
            return result;
        },
    };
}

void RegisterBitplusReportRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &scanbitplusassetutxos},
        {"rawtransactions", &getbitplusassetstats},
        {"rawtransactions", &getbitplusmemberassetstats},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
