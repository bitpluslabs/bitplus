// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/bitplus_util.h>

#include <rpc/server.h>
#include <rpc/util.h>
#include <script/bitplus_assets.h>
#include <script/bitplus_contracts.h>
#include <script/script.h>
#include <uint256.h>

#include <univalue.h>

using namespace bitplus::rpc;
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
            std::vector<uint256> path{ParseWhitelistMerklePath(request.params[7], "merkle_path")};

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
            result.pushKV("settlement_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildDvPSettlementLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                transfer,
                transfer_script.locking_script,
                asset_output_index,
                ParseScriptHex(request.params[9], "payment_script_pub_key"),
                ParsePositiveBtpAmount(request.params[10], "payment_amount"),
                ParseOutputIndex(request.params[11], "payment_output_index")))));
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

            std::vector<uint256> first_path{ParseWhitelistMerklePath(request.params[7], "first_merkle_path")};
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

            std::vector<uint256> second_path{ParseWhitelistMerklePath(request.params[15], "second_merkle_path")};
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
            result.pushKV("settlement_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildPvPSettlementLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                first_transfer,
                first_transfer_script.locking_script,
                first_proof.asset_output_index,
                second_transfer,
                second_transfer_script.locking_script,
                second_proof.asset_output_index))));
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
            result.pushKV("recovery_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildVaultRecoveryLeafChecked(
                authorization_script,
                ParseScriptHex(request.params[1], "recovery_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "recovery_amount"),
                ParseOutputIndex(request.params[3], "recovery_output_index")))));
            result.pushKV("delayed_spend_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildVaultDelayedSpendLeafChecked(
                authorization_script,
                ParseNonNegativeInt64(request.params[4], "relative_delay"),
                ParseScriptHex(request.params[5], "destination_script_pub_key"),
                ParsePositiveBtpAmount(request.params[6], "destination_amount"),
                ParseOutputIndex(request.params[7], "destination_output_index")))));
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
            result.pushKV("claim_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildHtlcClaimLeafChecked(
                authorization_script,
                ParseNonNullHash(request.params[1], "secret_hash"),
                ParseScriptHex(request.params[2], "claim_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "claim_amount"),
                ParseOutputIndex(request.params[4], "claim_output_index")))));
            result.pushKV("refund_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildHtlcRefundLeafChecked(
                authorization_script,
                ParseNonNegativeInt64(request.params[5], "absolute_expiry"),
                ParseScriptHex(request.params[6], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "refund_amount"),
                ParseOutputIndex(request.params[8], "refund_output_index")))));
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
            result.pushKV("release_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildCollateralReleaseLeafChecked(
                authorization_script,
                ParseScriptHex(request.params[1], "release_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "release_amount"),
                ParseOutputIndex(request.params[3], "release_output_index")))));
            result.pushKV("return_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildCollateralReturnLeafChecked(
                authorization_script,
                ParseNonNegativeInt64(request.params[4], "relative_delay"),
                ParseScriptHex(request.params[5], "return_script_pub_key"),
                ParsePositiveBtpAmount(request.params[6], "return_amount"),
                ParseOutputIndex(request.params[7], "return_output_index")))));
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
            result.pushKV("absolute_refund_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildAbsoluteRefundLeafChecked(
                authorization_script,
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "absolute_refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "absolute_refund_amount"),
                ParseOutputIndex(request.params[4], "absolute_refund_output_index")))));
            result.pushKV("relative_refund_leaf", ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildRelativeRefundLeafChecked(
                authorization_script,
                ParseNonNegativeInt64(request.params[5], "relative_delay"),
                ParseScriptHex(request.params[6], "relative_refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "relative_refund_amount"),
                ParseOutputIndex(request.params[8], "relative_refund_output_index")))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildCheckOutputVerifyScriptChecked(
                ParseScriptHex(request.params[0], "script_pub_key"),
                ParseNonNegativeBtpAmount(request.params[1], "amount"),
                ParseOutputIndex(request.params[2], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildVaultRecoveryLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseScriptHex(request.params[1], "recovery_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "amount"),
                ParseOutputIndex(request.params[3], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildVaultDelayedSpendLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "destination_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildHtlcClaimLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNullHash(request.params[1], "secret_hash"),
                ParseScriptHex(request.params[2], "claim_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildHtlcRefundLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildDvPSettlementLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                transfer,
                transfer_script.locking_script,
                ParseOutputIndex(request.params[5], "asset_output_index"),
                ParseScriptHex(request.params[6], "payment_script_pub_key"),
                ParsePositiveBtpAmount(request.params[7], "payment_amount"),
                ParseOutputIndex(request.params[8], "payment_output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildPvPSettlementLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                first_transfer,
                first_transfer_script.locking_script,
                ParseOutputIndex(request.params[5], "first_asset_output_index"),
                second_transfer,
                second_transfer_script.locking_script,
                ParseOutputIndex(request.params[10], "second_asset_output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildCollateralReleaseLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseScriptHex(request.params[1], "release_script_pub_key"),
                ParsePositiveBtpAmount(request.params[2], "amount"),
                ParseOutputIndex(request.params[3], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildCollateralReturnLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "return_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildAbsoluteRefundLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "absolute_expiry"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
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
            return ContractLeafToJSON(CheckedContractScript(bitplus::contracts::BuildRelativeRefundLeafChecked(
                ParseScriptHex(request.params[0], "authorization_script"),
                ParseNonNegativeInt64(request.params[1], "relative_delay"),
                ParseScriptHex(request.params[2], "refund_script_pub_key"),
                ParsePositiveBtpAmount(request.params[3], "amount"),
                ParseOutputIndex(request.params[4], "output_index"))));
        },
    };
}


void RegisterBitplusContractRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
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