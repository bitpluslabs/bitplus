// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/bitplus_util.h>

#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdint>
#include <vector>

#include <univalue.h>

using namespace bitplus::rpc;
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
            const uint256 txid{ParseNonNullHash(request.params[1], "txid")};
            const uint32_t vout{ParseOutputIndex(request.params[2], "vout")};
            return bitplus::assets::ComputeAssetId(
                metadata_hash,
                COutPoint{Txid::FromUint256(txid), vout}
            ).ToString();
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
            const uint32_t vout{ParseOutputIndex(request.params[1], "vout")};

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
            const uint256 txid{ParseNonNullHash(request.params[0], "txid")};
            const uint256 asset_id{bitplus::assets::ComputeAssetId(
                metadata_hash,
                COutPoint{Txid::FromUint256(txid), vout})};

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
            std::vector<uint256> path{ParseWhitelistMerklePath(request.params[6], "merkle_path")};

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
            const uint32_t output_index{ParseOutputIndex(request.params[0], "asset_output_index")};
            const uint32_t proof_index{ParseOutputIndex(request.params[2], "proof_index")};
            std::vector<uint256> path{ParseWhitelistMerklePath(request.params[3], "merkle_path")};
            const bitplus::assets::AssetWhitelistProofCommitment commitment{
                .asset_output_index = output_index,
                .member_hash = ParseHashV(request.params[1], "member_hash"),
                .proof_index = proof_index,
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

void RegisterBitplusAssetRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &createbitplusassetid},
        {"rawtransactions", &createbitplusassetmetadata},
        {"rawtransactions", &createbitplusassetwhitelist},
        {"rawtransactions", &createbitplusassetwhitelistroot},
        {"rawtransactions", &createbitplusassetissuance},
        {"rawtransactions", &createbitplusasset},
        {"rawtransactions", &createbitplusassettransfer},
        {"rawtransactions", &createbitplusassetburn},
        {"rawtransactions", &createbitplusassetwhitelistproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
