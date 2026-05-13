// Copyright (c) 2026 The Bitplus Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_RPC_RAWTRANSACTION_PSBT_H
#define BITPLUS_RPC_RAWTRANSACTION_PSBT_H

#include <psbt.h>
#include <script/signingprovider.h>

#include <any>
#include <optional>
#include <string>

PartiallySignedTransaction ProcessPSBT(
    const std::string& psbt_string,
    const std::any& context,
    const HidingSigningProvider& provider,
    std::optional<int> sighash_type,
    bool finalize);

#endif // BITPLUS_RPC_RAWTRANSACTION_PSBT_H
