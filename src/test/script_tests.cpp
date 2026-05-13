// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/script_tests.json.h>
#include <test/data/bip341_wallet_vectors.json.h>

#include <common/system.h>
#include <coins.h>
#include <core_io.h>
#include <hash.h>
#include <key.h>
#include <script/bitplus_assets.h>
#include <script/bitplus_contracts.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cstdint>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <secp256k1.h>
#include <univalue.h>

#include <array>
#include <limits>

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;

static const script_verify_flags gFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

script_verify_flags ParseScriptFlags(std::string strFlags);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"},
    {SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY, "TAPSCRIPT_EMPTY_PUBKEY"},
    {SCRIPT_ERR_CHECKOUTPUTVERIFY, "CHECKOUTPUTVERIFY"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
    {SCRIPT_ERR_SCRIPTNUM, "SCRIPTNUM"}
};

static std::string FormatScriptFlags(script_verify_flags flags)
{
    return util::Join(GetScriptFlagNames(flags), ",");
}

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return se.name;
    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors)
        if (se.name == name)
            return se.err;
    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

struct ScriptTest : BasicTestingSetup {
void DoTest(const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& scriptWitness, script_verify_flags flags, const std::string& message, int scriptError, CAmount nValue = 0)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    if (flags & SCRIPT_VERIFY_CLEANSTACK) {
        flags |= SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_WITNESS;
    }
    ScriptError err;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, nValue)};
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, scriptWitness, txCredit);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, FormatScriptError(err) + " where " + FormatScriptError((ScriptError_t)scriptError) + " expected: " + message);

    // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
    for (int i = 0; i < 256; ++i) {
        script_verify_flags extra_flags = script_verify_flags::from_int(m_rng.randbits(MAX_SCRIPT_VERIFY_FLAGS_BITS));
        script_verify_flags combined_flags{expect ? (flags & ~extra_flags) : (flags | extra_flags)};
        // Weed out some invalid flag combinations.
        if (combined_flags & SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) continue;
        if (combined_flags & SCRIPT_VERIFY_WITNESS && ~combined_flags & SCRIPT_VERIFY_P2SH) continue;
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, combined_flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message + strprintf(" (with flags %x)", combined_flags.as_int()));
    }
}
}; // struct ScriptTest

void static NegateSignatureS(std::vector<unsigned char>& vchSig) {
    // Parse the signature.
    std::vector<unsigned char> r, s;
    r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
    s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);

    while (s.size() < 33) {
        s.insert(s.begin(), 0x00);
    }
    assert(s[0] == 0);
    // Perform mod-n negation of s by (ab)using libsecp256k1
    // (note that this function is meant to be used for negating secret keys,
    //  but it works for any non-zero scalar modulo the group order, i.e. also for s)
    int ret = secp256k1_ec_seckey_negate(secp256k1_context_static, s.data() + 1);
    assert(ret);

    if (s[1] < 0x80) {
        s.erase(s.begin());
    }

    // Reconstruct the signature.
    vchSig.clear();
    vchSig.push_back(0x30);
    vchSig.push_back(4 + r.size() + s.size());
    vchSig.push_back(0x02);
    vchSig.push_back(r.size());
    vchSig.insert(vchSig.end(), r.begin(), r.end());
    vchSig.push_back(0x02);
    vchSig.push_back(s.size());
    vchSig.insert(vchSig.end(), s.begin(), s.end());
}

namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(pubkey0H.data()) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};

enum class WitnessMode {
    NONE,
    PKH,
    SH
};

class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    //! The Witness embedded script
    CScript witscript;
    CScriptWitness scriptWitness;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush{false};
    std::vector<unsigned char> push;
    std::string comment;
    script_verify_flags flags;
    int scriptError{SCRIPT_ERR_OK};
    CAmount nValue;

    void DoPush()
    {
        if (havePush) {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char>& data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript& script_, const std::string& comment_, script_verify_flags flags_, bool P2SH = false, WitnessMode wm = WitnessMode::NONE, int witnessversion = 0, CAmount nValue_ = 0) : script(script_), comment(comment_), flags(flags_), nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (wm == WitnessMode::PKH) {
            uint160 hash;
            CHash160().Write(std::span{script}.subspan(1)).Finalize(hash);
            script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        } else if (wm == WitnessMode::SH) {
            witscript = scriptPubKey;
            uint256 hash;
            CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        }
        if (P2SH) {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), CScriptWitness(), *creditTx);
    }

    TestBuilder& ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder& Opcode(const opcodetype& _op)
    {
        DoPush();
        spendTx.vin[0].scriptSig << _op;
        return *this;
    }

    TestBuilder& Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder& Push(const std::string& hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder& Push(const CScript& _script)
    {
        DoPush(std::vector<unsigned char>(_script.begin(), _script.end()));
        return *this;
    }

    TestBuilder& PushSig(const CKey& key, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::BASE, CAmount amount = 0)
    {
        uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount, sigversion);
        std::vector<unsigned char> vchSig, r, s;
        uint32_t iter = 0;
        do {
            key.Sign(hash, vchSig, false, iter++);
            if ((lenS == 33) != (vchSig[5 + vchSig[3]] == 33)) {
                NegateSignatureS(vchSig);
            }
            r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
            s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);
        } while (lenR != r.size() || lenS != s.size());
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder& PushWitSig(const CKey& key, CAmount amount = -1, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::WITNESS_V0)
    {
        if (amount == -1)
            amount = nValue;
        return PushSig(key, nHashType, lenR, lenS, sigversion, amount).AsWit();
    }

    TestBuilder& Push(const CPubKey& pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder& PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder& PushWitRedeem()
    {
        DoPush(std::vector<unsigned char>(witscript.begin(), witscript.end()));
        return AsWit();
    }

    TestBuilder& EditPush(unsigned int pos, const std::string& hexin, const std::string& hexout)
    {
        assert(havePush);
        std::vector<unsigned char> datain = ParseHex(hexin);
        std::vector<unsigned char> dataout = ParseHex(hexout);
        assert(pos + datain.size() <= push.size());
        BOOST_CHECK_MESSAGE(std::vector<unsigned char>(push.begin() + pos, push.begin() + pos + datain.size()) == datain, comment);
        push.erase(push.begin() + pos, push.begin() + pos + datain.size());
        push.insert(push.begin() + pos, dataout.begin(), dataout.end());
        return *this;
    }

    TestBuilder& DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder& Test(ScriptTest& test)
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        test.DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, scriptWitness, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    TestBuilder& AsWit()
    {
        assert(havePush);
        scriptWitness.stack.push_back(push);
        havePush = false;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (!scriptWitness.stack.empty()) {
            UniValue wit(UniValue::VARR);
            for (unsigned i = 0; i < scriptWitness.stack.size(); i++) {
                wit.push_back(HexStr(scriptWitness.stack[i]));
            }
            wit.push_back(ValueFromAmount(nValue));
            array.push_back(std::move(wit));
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() const
    {
        return comment;
    }
};

std::string JSONPrettyPrint(const UniValue& univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between commas and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos) {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, ScriptTest)

BOOST_AUTO_TEST_CASE(script_build)
{
    const KeyData keys;

    std::vector<TestBuilder> tests;

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK", 0
                               ).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK, bad sig", 0
                               ).PushSig(keys.key0).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH", 0
                               ).PushSig(keys.key1).Push(keys.pubkey1C));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey2C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH, bad pubkey", 0
                               ).PushSig(keys.key2).Push(keys.pubkey2C).DamagePush(5).ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay marked with normal hashtype", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY).EditPush(70, "81", "01").ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK), bad redeemscript", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem().DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey0.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).Push(keys.pubkey0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig but no VERIFY_P2SH", 0, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem().ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3, 2 sigs", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3)", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key2).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3), 1 sig", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).Num(0).PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, without DERSIG", 0
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, without DERSIG", 0
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, without DERSIG", 0
                               ).Num(1).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, without DERSIG", 0
                               ).Num(1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, without DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S but no LOW_S", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S", SCRIPT_VERIFY_LOW_S
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33).ScriptError(SCRIPT_ERR_SIG_HIGH_S));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey and no STRICTENC", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0H) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the first 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig and nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP but no SIGPUSHONLY", 0
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP).ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no P2SH or SIGPUSHONLY", 0, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with non-push scriptSig but with P2SH validation", SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key2).Opcode(OP_NOP8));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no SIGPUSHONLY", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but not P2SH", SCRIPT_VERIFY_SIGPUSHONLY, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0).ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem().ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with future witness version", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::PKH, 1
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0);
        uint256 hash;
        CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
        std::vector<unsigned char> hashBytes = ToByteVector(hash);
        hashBytes.pop_back();
        tests.push_back(TestBuilder(CScript() << OP_0 << hashBytes,
                                    "P2WPKH with wrong witness program length", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false
                                   ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2WSH with empty witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "P2WSH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                                   ).PushWitSig(keys.key0).Push(witscript).DamagePush(0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with non-empty scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Num(11).ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "P2SH(P2WPKH) with superfluous push in scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().Num(11).PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_MALLEATED_P2SH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key0).Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));

    // Compressed keys should pass SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2WSH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2WPKH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2SH(P2WPKH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit().PushRedeem());

    // Testing uncompressed key in witness with SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    // P2WSH 1-of-2 multisig with compressed keys
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());

    // P2WSH 1-of-2 multisig with first key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    // P2WSH 1-of-2 multisig with second key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    std::set<std::string> tests_set;

    {
        UniValue json_tests = read_json(json_tests::script_tests);

        for (unsigned int idx = 0; idx < json_tests.size(); idx++) {
            const UniValue& tv = json_tests[idx];
            tests_set.insert(JSONPrettyPrint(tv.get_array()));
        }
    }

#ifdef UPDATE_JSON_TESTS
    std::string strGen;
#endif
    for (TestBuilder& test : tests) {
        test.Test(*this);
        std::string str = JSONPrettyPrint(test.GetJSON());
#ifdef UPDATE_JSON_TESTS
        strGen += str + ",\n";
#else
        if (!tests_set.contains(str)) {
            BOOST_CHECK_MESSAGE(false, "Missing auto script_valid test: " + test.GetComment());
        }
#endif
    }

#ifdef UPDATE_JSON_TESTS
    FILE* file = fsbridge::fopen("script_tests.json.gen", "w");
    fputs(strGen.c_str(), file);
    fclose(file);
#endif
}

BOOST_AUTO_TEST_CASE(script_json_test)
{
    // Read tests from test/data/script_tests.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(json_tests::script_tests);

    const KeyData keys;
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        TaprootBuilder taprootBuilder;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                auto element = test[pos][i].get_str();
                // We use #SCRIPT# to flag a non-hex script that we can read using ParseScript
                // Taproot script must be third from the last element in witness stack
                static const std::string SCRIPT_FLAG{"#SCRIPT#"};
                if (element.starts_with(SCRIPT_FLAG)) {
                    CScript script = ParseScript(element.substr(SCRIPT_FLAG.size()));
                    witness.stack.push_back(ToByteVector(script));
                } else if (element == "#CONTROLBLOCK#") {
                    // Taproot script control block - second from the last element in witness stack
                    // If #CONTROLBLOCK# we auto-generate the control block
                    taprootBuilder.Add(/*depth=*/0, witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
                    taprootBuilder.Finalize(XOnlyPubKey(keys.key0.GetPubKey()));
                    auto controlblocks = taprootBuilder.GetSpendData().scripts[{witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT}];
                    witness.stack.push_back(*(controlblocks.begin()));
                } else {
                    const auto witness_value{TryParseHex<unsigned char>(element)};
                    if (!witness_value.has_value()) {
                        BOOST_ERROR("Bad witness in test: " << strTest << " witness is not hex: " << element);
                    }
                    witness.stack.push_back(witness_value.value());
                }
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {
            if (test.size() != 1) {
                BOOST_ERROR("Bad test: " << strTest);
            }
            continue;
        }
        std::string scriptSigString = test[pos++].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        std::string scriptPubKeyString = test[pos++].get_str();
        CScript scriptPubKey;
        // If requested, auto-generate the taproot output
        if (scriptPubKeyString == "0x51 0x20 #TAPROOTOUTPUT#") {
            BOOST_CHECK_MESSAGE(taprootBuilder.IsComplete(), "Failed to autogenerate Tapscript output key");
            scriptPubKey = CScript() << OP_1 << ToByteVector(taprootBuilder.GetOutput());
        } else {
            scriptPubKey = ParseScript(scriptPubKeyString);
        }
        script_verify_flags scriptflags = ParseScriptFlags(test[pos++].get_str());
        int scriptError = ParseScriptError(test[pos++].get_str());

        DoTest(scriptPubKey, scriptSig, witness, scriptflags, strTest, scriptError, nValue);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(direct, direct + sizeof(direct)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(pushdata1, pushdata1 + sizeof(pushdata1)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata1Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(pushdata2, pushdata2 + sizeof(pushdata2)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata2Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(pushdata4, pushdata4 + sizeof(pushdata4)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata4Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    const std::vector<unsigned char> pushdata1_trunc{OP_PUSHDATA1, 1};
    const std::vector<unsigned char> pushdata2_trunc{OP_PUSHDATA2, 1, 0};
    const std::vector<unsigned char> pushdata4_trunc{OP_PUSHDATA4, 1, 0, 0, 0};

    std::vector<std::vector<unsigned char>> stack_ignore;
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata1_trunc.begin(), pushdata1_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata2_trunc.begin(), pushdata2_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata4_trunc.begin(), pushdata4_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(script_cltv_truncated)
{
    const auto script_cltv_trunc = CScript() << OP_CHECKLOCKTIMEVERIFY;

    std::vector<std::vector<unsigned char>> stack_ignore;
    ScriptError err;
    BOOST_CHECK(!EvalScript(stack_ignore, script_cltv_trunc, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(script_checkoutputverify)
{
    const CAmount amount{50'000};
    const CScript target_script{CScript{} << OP_TRUE};
    const uint256 target_hash{(HashWriter{} << target_script).GetSHA256()};
    const std::vector<unsigned char> target_hash_vch{target_hash.begin(), target_hash.end()};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(amount, target_script);

    const CScript covenant_script{CScript{} << target_hash_vch << CScriptNum{amount} << 0 << OP_CHECKOUTPUTVERIFY << OP_TRUE};
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};

    BOOST_CHECK(EvalScript(stack, covenant_script, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1);
    BOOST_CHECK(stack.back() == std::vector<unsigned char>{1});

    tx.vout[0].nValue = amount + 1;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, covenant_script, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHECKOUTPUTVERIFY);
}

BOOST_AUTO_TEST_CASE(script_vault_templates)
{
    const CAmount amount{75'000};
    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript recovery_script{CScript{} << OP_1};
    const CScript destination_script{CScript{} << OP_2};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 10;
    tx.vout.emplace_back(amount, recovery_script);

    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    const CScript recovery_leaf{bitplus::contracts::BuildVaultRecoveryLeaf(auth_script, recovery_script, amount, 0)};
    BOOST_CHECK(EvalScript(stack, recovery_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vout[0].scriptPubKey = destination_script;
    stack.clear();
    const CScript delayed_leaf{bitplus::contracts::BuildVaultDelayedSpendLeaf(auth_script, 10, destination_script, amount, 0)};
    BOOST_CHECK(EvalScript(stack, delayed_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vin[0].nSequence = 9;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, delayed_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(script_contract_checked_builders)
{
    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript output_script{CScript{} << OP_1};

    auto empty_auth{bitplus::contracts::BuildVaultRecoveryLeafChecked(CScript{}, output_script, 1, 0)};
    BOOST_CHECK(!empty_auth);
    BOOST_CHECK_EQUAL(util::ErrorString(empty_auth).original, "authorization_script must not be empty");

    auto negative_amount{bitplus::contracts::BuildCheckOutputVerifyScriptChecked(output_script, -1, 0)};
    BOOST_CHECK(!negative_amount);
    BOOST_CHECK_EQUAL(util::ErrorString(negative_amount).original, "amount must be non-negative");

    auto zero_btp_amount{bitplus::contracts::BuildCollateralReleaseLeafChecked(auth_script, output_script, 0, 0)};
    BOOST_CHECK(!zero_btp_amount);
    BOOST_CHECK_EQUAL(util::ErrorString(zero_btp_amount).original, "amount must be greater than zero");

    auto negative_delay{bitplus::contracts::BuildVaultDelayedSpendLeafChecked(auth_script, -1, output_script, 1, 0)};
    BOOST_CHECK(!negative_delay);
    BOOST_CHECK_EQUAL(util::ErrorString(negative_delay).original, "relative_delay must be non-negative");

    auto oversized_delay{bitplus::contracts::BuildVaultDelayedSpendLeafChecked(auth_script, static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1, output_script, 1, 0)};
    BOOST_CHECK(!oversized_delay);
    BOOST_CHECK_EQUAL(util::ErrorString(oversized_delay).original, "relative_delay out of range");

    auto null_secret{bitplus::contracts::BuildHtlcClaimLeafChecked(auth_script, uint256{}, output_script, 1, 0)};
    BOOST_CHECK(!null_secret);
    BOOST_CHECK_EQUAL(util::ErrorString(null_secret).original, "secret_hash must not be null");

    bitplus::assets::AssetCommitment transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = uint256{1},
        .amount = 1,
        .metadata_hash = uint256{2},
        .member_hash = uint256{3},
    };
    auto unspendable_asset_lock{bitplus::contracts::BuildDvPSettlementLeafChecked(
        auth_script,
        transfer,
        CScript{} << OP_RETURN,
        0,
        output_script,
        1,
        1)};
    BOOST_CHECK(!unspendable_asset_lock);
    BOOST_CHECK_EQUAL(util::ErrorString(unspendable_asset_lock).original, "asset_locking_script must be spendable");

    bitplus::assets::AssetCommitment issuance{transfer};
    issuance.type = bitplus::assets::AssetCommitmentType::ISSUANCE;
    auto non_transfer_asset_leg{bitplus::contracts::BuildDvPSettlementLeafChecked(
        auth_script,
        issuance,
        0,
        output_script,
        1,
        1)};
    BOOST_CHECK(!non_transfer_asset_leg);
    BOOST_CHECK_EQUAL(util::ErrorString(non_transfer_asset_leg).original, "asset_locking_script commitment must be a transfer");

    auto valid_dvp{bitplus::contracts::BuildDvPSettlementLeafChecked(auth_script, transfer, 0, output_script, 1, 1)};
    BOOST_CHECK(valid_dvp);
}

BOOST_AUTO_TEST_CASE(script_asset_commitments)
{
    bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{6},
        .admin_key_hash = uint256{7},
        .members_root = uint256{8},
        .flags = 1,
    };

    bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{3},
        .document_hash = uint256{4},
        .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
    };

    bitplus::assets::AssetCommitment commitment{
        .type = bitplus::assets::AssetCommitmentType::ISSUANCE,
        .asset_id = uint256{1},
        .amount = 1'000'000,
        .metadata_hash = bitplus::assets::HashAssetMetadataCommitment(metadata),
        .member_hash = uint256{11},
    };

    const std::vector<unsigned char> encoded{bitplus::assets::EncodeAssetCommitment(commitment)};
    const std::optional<bitplus::assets::AssetCommitment> decoded{bitplus::assets::DecodeAssetCommitment(encoded)};
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == commitment);

    const CScript script{bitplus::assets::BuildAssetCommitmentScript(commitment)};
    const std::optional<bitplus::assets::AssetCommitment> decoded_script{bitplus::assets::DecodeAssetCommitmentScript(script)};
    BOOST_REQUIRE(decoded_script.has_value());
    BOOST_CHECK(*decoded_script == commitment);

    std::vector<unsigned char> mutated{encoded};
    mutated[0] = 0;
    BOOST_CHECK(!bitplus::assets::DecodeAssetCommitment(mutated).has_value());
    BOOST_CHECK(bitplus::assets::HashAssetCommitment(commitment) != uint256{});
}

BOOST_AUTO_TEST_CASE(script_asset_output_extraction)
{
    const uint256 asset_id{1};
    const uint256 other_asset_id{2};
    const uint256 metadata_hash{3};
    const bitplus::assets::AssetCommitment issuance{
        .type = bitplus::assets::AssetCommitmentType::ISSUANCE,
        .asset_id = asset_id,
        .amount = 100,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };
    const bitplus::assets::AssetCommitment transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = asset_id,
        .amount = 60,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };
    const bitplus::assets::AssetCommitment burn{
        .type = bitplus::assets::AssetCommitmentType::BURN,
        .asset_id = asset_id,
        .amount = 10,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };
    const bitplus::assets::AssetCommitment other_transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = other_asset_id,
        .amount = 1,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };

    CMutableTransaction tx;
    tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(issuance));
    tx.vout.emplace_back(0, CScript{} << OP_TRUE);
    tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(transfer));
    tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(burn));
    tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(other_transfer));

    const CTransaction ctx{tx};
    const std::vector<bitplus::assets::AssetOutput> outputs{bitplus::assets::ExtractAssetOutputs(ctx)};
    BOOST_REQUIRE_EQUAL(outputs.size(), 4);
    BOOST_CHECK_EQUAL(outputs[0].output_index, 0U);
    BOOST_CHECK_EQUAL(outputs[1].output_index, 2U);
    BOOST_CHECK_EQUAL(outputs[2].output_index, 3U);
    BOOST_CHECK_EQUAL(outputs[3].output_index, 4U);

    const bitplus::assets::AssetBalanceSummary summary{bitplus::assets::SummarizeAssetOutputs(outputs, asset_id)};
    BOOST_CHECK_EQUAL(summary.issued, 100U);
    BOOST_CHECK_EQUAL(summary.transferred, 60U);
    BOOST_CHECK_EQUAL(summary.burned, 10U);
    BOOST_CHECK(!summary.overflow);

    const bitplus::assets::AssetBalanceSummary other_summary{bitplus::assets::SummarizeAssetOutputs(outputs, other_asset_id)};
    BOOST_CHECK_EQUAL(other_summary.issued, 0U);
    BOOST_CHECK_EQUAL(other_summary.transferred, 1U);
    BOOST_CHECK_EQUAL(other_summary.burned, 0U);
    BOOST_CHECK(!other_summary.overflow);
}

BOOST_AUTO_TEST_CASE(script_asset_output_validation)
{
    bitplus::assets::AssetOutput output{
        .output_index = 0,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = uint256{1},
            .amount = 100,
            .metadata_hash = uint256{2},
            .member_hash = uint256{11},
        },
        .locking_script = CScript{} << OP_TRUE,
    };

    BOOST_CHECK(bitplus::assets::ValidateAssetOutput(output).valid);

    output.carrier_amount = 1;
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-carrier-nonzero");
    output.carrier_amount = 0;

    output.commitment.asset_id = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-id-null");
    output.commitment.asset_id = uint256{1};

    output.commitment.metadata_hash = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-metadata-null");
    output.commitment.metadata_hash = uint256{2};

    output.commitment.member_hash = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-member-null");
    output.commitment.member_hash = uint256{11};

    output.commitment.amount = 0;
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-amount-zero");
    output.commitment.amount = 100;

    output.locking_script = bitplus::assets::BuildAssetCommitmentScript(output.commitment);
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetOutput(output).reason, "asset-locking-script-nested");
}

BOOST_AUTO_TEST_CASE(script_asset_metadata_output_validation)
{
    bitplus::assets::AssetMetadataOutput output{
        .output_index = 0,
        .commitment = bitplus::assets::AssetMetadataCommitment{
            .issuer_id = uint256{1},
            .document_hash = uint256{2},
            .rules_hash = uint256{3},
        },
    };

    BOOST_CHECK(bitplus::assets::ValidateAssetMetadataOutput(output).valid);

    output.commitment.issuer_id = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetMetadataOutput(output).reason, "asset-metadata-issuer-null");
    output.commitment.issuer_id = uint256{1};

    output.commitment.document_hash = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetMetadataOutput(output).reason, "asset-metadata-document-null");
    output.commitment.document_hash = uint256{2};

    output.commitment.rules_hash = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetMetadataOutput(output).reason, "asset-metadata-rules-null");
}

BOOST_AUTO_TEST_CASE(script_asset_whitelist_output_validation)
{
    bitplus::assets::AssetWhitelistOutput output{
        .output_index = 0,
        .commitment = bitplus::assets::AssetWhitelistCommitment{
            .list_id = uint256{1},
            .admin_key_hash = uint256{2},
            .members_root = uint256{3},
            .flags = 1,
        },
    };

    BOOST_CHECK(bitplus::assets::ValidateAssetWhitelistOutput(output).valid);

    output.commitment.list_id = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetWhitelistOutput(output).reason, "asset-whitelist-list-null");
    output.commitment.list_id = uint256{1};

    output.commitment.admin_key_hash = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetWhitelistOutput(output).reason, "asset-whitelist-admin-null");
    output.commitment.admin_key_hash = uint256{2};

    output.commitment.members_root = uint256{};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetWhitelistOutput(output).reason, "asset-whitelist-members-null");
}

BOOST_AUTO_TEST_CASE(script_asset_whitelist_proof_commitments)
{
    const uint256 member_hash{1};
    const uint256 sibling_hash{2};
    const uint256 leaf{bitplus::assets::ComputeWhitelistMemberLeaf(member_hash)};
    const uint256 members_root{(HashWriter{} << leaf << sibling_hash).GetSHA256()};
    const bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{3},
        .admin_key_hash = uint256{4},
        .members_root = members_root,
        .flags = 1,
    };
    bitplus::assets::AssetWhitelistProofCommitment proof{
        .asset_output_index = 5,
        .member_hash = member_hash,
        .proof_index = 0,
        .merkle_path = {sibling_hash},
    };

    BOOST_CHECK(bitplus::assets::VerifyWhitelistProof(proof, whitelist));
    BOOST_CHECK_EQUAL(bitplus::assets::ComputeWhitelistMembersRoot(proof), members_root);

    const std::vector<uint256> members{uint256{10}, uint256{11}, uint256{12}};
    const uint256 computed_root{bitplus::assets::ComputeWhitelistMembersRoot(members)};
    const std::vector<uint256> computed_path{bitplus::assets::ComputeWhitelistMerklePath(members, 2)};
    const bitplus::assets::AssetWhitelistProofCommitment computed_proof{
        .asset_output_index = 7,
        .member_hash = members[2],
        .proof_index = 2,
        .merkle_path = computed_path,
    };
    const bitplus::assets::AssetWhitelistCommitment computed_whitelist{
        .list_id = uint256{8},
        .admin_key_hash = uint256{9},
        .members_root = computed_root,
        .flags = 0,
    };
    BOOST_CHECK(bitplus::assets::VerifyWhitelistProof(computed_proof, computed_whitelist));
    BOOST_CHECK_EQUAL(bitplus::assets::ComputeWhitelistMembersRoot(computed_proof), computed_root);
    BOOST_CHECK(bitplus::assets::ComputeWhitelistMembersRoot(std::span<const uint256>{}).IsNull());

    const std::vector<unsigned char> encoded{bitplus::assets::EncodeAssetWhitelistProofCommitment(proof)};
    const std::optional<bitplus::assets::AssetWhitelistProofCommitment> decoded{
        bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded)
    };
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == proof);

    const CScript script{bitplus::assets::BuildAssetWhitelistProofCommitmentScript(proof)};
    const std::optional<bitplus::assets::AssetWhitelistProofCommitment> decoded_script{
        bitplus::assets::DecodeAssetWhitelistProofCommitmentScript(script)
    };
    BOOST_REQUIRE(decoded_script.has_value());
    BOOST_CHECK(*decoded_script == proof);

    proof.member_hash = uint256{};
    bitplus::assets::AssetWhitelistProofOutput output{.output_index = 6, .commitment = proof};
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetWhitelistProofOutput(output).reason, "asset-whitelist-proof-member-null");

    proof.member_hash = member_hash;
    proof.proof_index = 2;
    output.commitment = proof;
    BOOST_CHECK_EQUAL(bitplus::assets::ValidateAssetWhitelistProofOutput(output).reason, "asset-whitelist-proof-index-range");
}

BOOST_AUTO_TEST_CASE(script_asset_serialization_hash_stability)
{
    const bitplus::assets::AssetCommitment asset{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = uint256{1},
        .amount = 0x0102030405060708ULL,
        .metadata_hash = uint256{2},
        .member_hash = uint256{3},
    };
    const std::vector<unsigned char> encoded_asset{bitplus::assets::EncodeAssetCommitment(asset)};
    BOOST_REQUIRE_EQUAL(encoded_asset.size(), 8U + 1U + 32U + 8U + 32U + 32U);
    const std::string encoded_asset_magic{encoded_asset.begin(), encoded_asset.begin() + 8};
    BOOST_CHECK_EQUAL(encoded_asset_magic, "BTPASSET");
    BOOST_CHECK_EQUAL(encoded_asset[8], static_cast<uint8_t>(bitplus::assets::AssetCommitmentType::TRANSFER));
    BOOST_CHECK_EQUAL(HexStr(std::span<const unsigned char>{encoded_asset}.subspan(41, 8)), "0807060504030201");
    BOOST_REQUIRE(bitplus::assets::DecodeAssetCommitment(encoded_asset).has_value());
    BOOST_CHECK(*bitplus::assets::DecodeAssetCommitment(encoded_asset) == asset);
    BOOST_CHECK(bitplus::assets::EncodeAssetCommitment(*bitplus::assets::DecodeAssetCommitment(encoded_asset)) == encoded_asset);
    BOOST_CHECK_EQUAL(bitplus::assets::HashAssetCommitment(asset), bitplus::assets::HashAssetCommitment(*bitplus::assets::DecodeAssetCommitment(encoded_asset)));

    std::vector<unsigned char> mutated_asset{encoded_asset};
    mutated_asset[8] = 0xff;
    BOOST_CHECK(!bitplus::assets::DecodeAssetCommitment(mutated_asset).has_value());
    mutated_asset = encoded_asset;
    mutated_asset.push_back(0);
    BOOST_CHECK(!bitplus::assets::DecodeAssetCommitment(mutated_asset).has_value());

    const bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{4},
        .document_hash = uint256{5},
        .rules_hash = uint256{6},
    };
    const std::vector<unsigned char> encoded_metadata{bitplus::assets::EncodeAssetMetadataCommitment(metadata)};
    BOOST_REQUIRE_EQUAL(encoded_metadata.size(), 7U + 32U + 32U + 32U);
    const std::string encoded_metadata_magic{encoded_metadata.begin(), encoded_metadata.begin() + 7};
    BOOST_CHECK_EQUAL(encoded_metadata_magic, "BTPMETA");
    BOOST_REQUIRE(bitplus::assets::DecodeAssetMetadataCommitment(encoded_metadata).has_value());
    BOOST_CHECK(bitplus::assets::EncodeAssetMetadataCommitment(*bitplus::assets::DecodeAssetMetadataCommitment(encoded_metadata)) == encoded_metadata);
    BOOST_CHECK_EQUAL(bitplus::assets::HashAssetMetadataCommitment(metadata), bitplus::assets::HashAssetMetadataCommitment(*bitplus::assets::DecodeAssetMetadataCommitment(encoded_metadata)));

    const bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{7},
        .admin_key_hash = uint256{8},
        .members_root = uint256{9},
        .flags = 0x01020304,
    };
    const std::vector<unsigned char> encoded_whitelist{bitplus::assets::EncodeAssetWhitelistCommitment(whitelist)};
    BOOST_REQUIRE_EQUAL(encoded_whitelist.size(), 7U + 32U + 32U + 32U + 4U);
    const std::string encoded_whitelist_magic{encoded_whitelist.begin(), encoded_whitelist.begin() + 7};
    BOOST_CHECK_EQUAL(encoded_whitelist_magic, "BTPWLST");
    BOOST_CHECK_EQUAL(HexStr(std::span<const unsigned char>{encoded_whitelist}.last(4)), "04030201");
    BOOST_REQUIRE(bitplus::assets::DecodeAssetWhitelistCommitment(encoded_whitelist).has_value());
    BOOST_CHECK(bitplus::assets::EncodeAssetWhitelistCommitment(*bitplus::assets::DecodeAssetWhitelistCommitment(encoded_whitelist)) == encoded_whitelist);
    BOOST_CHECK_EQUAL(bitplus::assets::HashAssetWhitelistCommitment(whitelist), bitplus::assets::HashAssetWhitelistCommitment(*bitplus::assets::DecodeAssetWhitelistCommitment(encoded_whitelist)));

    const bitplus::assets::AssetWhitelistProofCommitment proof{
        .asset_output_index = 0x01020304,
        .member_hash = uint256{10},
        .proof_index = 0x05060708,
        .merkle_path = {uint256{11}, uint256{12}},
    };
    const std::vector<unsigned char> encoded_proof{bitplus::assets::EncodeAssetWhitelistProofCommitment(proof)};
    BOOST_REQUIRE_EQUAL(encoded_proof.size(), 9U + 4U + 32U + 4U + 1U + 2U * 32U);
    const std::string encoded_proof_magic{encoded_proof.begin(), encoded_proof.begin() + 9};
    BOOST_CHECK_EQUAL(encoded_proof_magic, "BTPWPROOF");
    BOOST_CHECK_EQUAL(HexStr(std::span<const unsigned char>{encoded_proof}.subspan(9, 4)), "04030201");
    BOOST_CHECK_EQUAL(HexStr(std::span<const unsigned char>{encoded_proof}.subspan(45, 4)), "08070605");
    BOOST_CHECK_EQUAL(encoded_proof[49], 2U);
    BOOST_REQUIRE(bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded_proof).has_value());
    BOOST_CHECK(bitplus::assets::EncodeAssetWhitelistProofCommitment(*bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded_proof)) == encoded_proof);
    BOOST_CHECK_EQUAL(bitplus::assets::HashAssetWhitelistProofCommitment(proof), bitplus::assets::HashAssetWhitelistProofCommitment(*bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded_proof)));

    bitplus::assets::AssetWhitelistProofCommitment max_depth_proof{proof};
    max_depth_proof.merkle_path.assign(32, uint256{13});
    const std::vector<unsigned char> encoded_max_depth_proof{bitplus::assets::EncodeAssetWhitelistProofCommitment(max_depth_proof)};
    BOOST_REQUIRE(bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded_max_depth_proof).has_value());
    BOOST_CHECK(*bitplus::assets::DecodeAssetWhitelistProofCommitment(encoded_max_depth_proof) == max_depth_proof);

    bitplus::assets::AssetWhitelistProofCommitment too_deep_proof{proof};
    too_deep_proof.merkle_path.assign(33, uint256{14});
    BOOST_CHECK(!bitplus::assets::DecodeAssetWhitelistProofCommitment(bitplus::assets::EncodeAssetWhitelistProofCommitment(too_deep_proof)).has_value());

    std::vector<unsigned char> truncated_proof{encoded_proof};
    truncated_proof.pop_back();
    BOOST_CHECK(!bitplus::assets::DecodeAssetWhitelistProofCommitment(truncated_proof).has_value());
}

BOOST_AUTO_TEST_CASE(script_asset_reference_validation)
{
    const bitplus::assets::AssetWhitelistOutput whitelist_output{
        .output_index = 0,
        .commitment = bitplus::assets::AssetWhitelistCommitment{
            .list_id = uint256{1},
            .admin_key_hash = uint256{2},
            .members_root = uint256{3},
            .flags = 1,
        },
    };
    const bitplus::assets::AssetMetadataOutput metadata_output{
        .output_index = 1,
        .commitment = bitplus::assets::AssetMetadataCommitment{
            .issuer_id = uint256{4},
            .document_hash = uint256{5},
            .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist_output.commitment),
        },
    };
    const uint256 metadata_hash{bitplus::assets::HashAssetMetadataCommitment(metadata_output.commitment)};
    CMutableTransaction issuance_tx;
    issuance_tx.vin.emplace_back(Txid::FromUint256(uint256{9}), 0);
    const COutPoint& issuance_anchor{issuance_tx.vin.front().prevout};
    const bitplus::assets::AssetOutput issuance_output{
        .output_index = 2,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::ISSUANCE,
            .asset_id = bitplus::assets::ComputeAssetId(metadata_hash, issuance_anchor),
            .amount = 100,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };
    const bitplus::assets::AssetOutput transfer_output{
        .output_index = 3,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = uint256{6},
            .amount = 100,
            .metadata_hash = uint256{7},
            .member_hash = uint256{11},
        },
    };

    const std::array asset_outputs{issuance_output, transfer_output};
    const std::array metadata_outputs{metadata_output};
    const std::array whitelist_outputs{whitelist_output};
    BOOST_CHECK(!bitplus::assets::FindFirstUnlinkedAssetMetadata(asset_outputs, metadata_outputs).has_value());
    BOOST_CHECK(!bitplus::assets::FindFirstInvalidAssetIssuanceAnchor(asset_outputs, CTransaction{issuance_tx}).has_value());
    BOOST_CHECK(!bitplus::assets::FindFirstUnlinkedAssetWhitelist(metadata_outputs, whitelist_outputs).has_value());

    const std::optional<bitplus::assets::AssetValidationResult> missing_metadata{
        bitplus::assets::FindFirstUnlinkedAssetMetadata(asset_outputs, std::span<const bitplus::assets::AssetMetadataOutput>{})
    };
    BOOST_REQUIRE(missing_metadata.has_value());
    BOOST_CHECK_EQUAL(missing_metadata->reason, "asset-issuance-metadata-missing");

    CMutableTransaction wrong_issuance_tx;
    wrong_issuance_tx.vin.emplace_back(Txid::FromUint256(uint256{10}), 0);
    const std::optional<bitplus::assets::AssetValidationResult> mismatched_anchor{
        bitplus::assets::FindFirstInvalidAssetIssuanceAnchor(asset_outputs, CTransaction{wrong_issuance_tx})
    };
    BOOST_REQUIRE(mismatched_anchor.has_value());
    BOOST_CHECK_EQUAL(mismatched_anchor->reason, "asset-issuance-anchor-mismatch");

    CMutableTransaction coinbase_issuance_tx;
    coinbase_issuance_tx.vin.resize(1);
    coinbase_issuance_tx.vin[0].prevout.SetNull();
    const std::optional<bitplus::assets::AssetValidationResult> coinbase_issuance{
        bitplus::assets::FindFirstInvalidAssetIssuanceAnchor(asset_outputs, CTransaction{coinbase_issuance_tx})
    };
    BOOST_REQUIRE(coinbase_issuance.has_value());
    BOOST_CHECK_EQUAL(coinbase_issuance->reason, "asset-issuance-coinbase");

    bitplus::assets::AssetOutput duplicate_issuance{issuance_output};
    duplicate_issuance.output_index = 4;
    const std::array duplicate_asset_outputs{issuance_output, duplicate_issuance};
    const std::optional<bitplus::assets::AssetValidationResult> duplicate_issuance_result{
        bitplus::assets::FindFirstUnlinkedAssetMetadata(duplicate_asset_outputs, metadata_outputs)
    };
    BOOST_REQUIRE(duplicate_issuance_result.has_value());
    BOOST_CHECK_EQUAL(duplicate_issuance_result->reason, "asset-issuance-duplicate");

    const std::optional<bitplus::assets::AssetValidationResult> missing_whitelist{
        bitplus::assets::FindFirstUnlinkedAssetWhitelist(metadata_outputs, std::span<const bitplus::assets::AssetWhitelistOutput>{})
    };
    BOOST_REQUIRE(missing_whitelist.has_value());
    BOOST_CHECK_EQUAL(missing_whitelist->reason, "asset-metadata-whitelist-missing");
}

BOOST_AUTO_TEST_CASE(script_asset_whitelisted_transfer_validation)
{
    const uint256 member_hash{1};
    const uint256 sibling_hash{2};
    const uint256 members_root{
        (HashWriter{} << bitplus::assets::ComputeWhitelistMemberLeaf(member_hash) << sibling_hash).GetSHA256()
    };
    const bitplus::assets::AssetWhitelistOutput whitelist_output{
        .output_index = 0,
        .commitment = bitplus::assets::AssetWhitelistCommitment{
            .list_id = uint256{3},
            .admin_key_hash = uint256{4},
            .members_root = members_root,
            .flags = 1,
        },
    };
    const bitplus::assets::AssetMetadataOutput metadata_output{
        .output_index = 1,
        .commitment = bitplus::assets::AssetMetadataCommitment{
            .issuer_id = uint256{5},
            .document_hash = uint256{6},
            .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist_output.commitment),
        },
    };
    const uint256 metadata_hash{bitplus::assets::HashAssetMetadataCommitment(metadata_output.commitment)};
    const bitplus::assets::AssetOutput transfer_output{
        .output_index = 2,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = uint256{7},
            .amount = 100,
            .metadata_hash = metadata_hash,
            .member_hash = member_hash,
        },
    };
    const bitplus::assets::AssetWhitelistProofOutput proof_output{
        .output_index = 3,
        .commitment = bitplus::assets::AssetWhitelistProofCommitment{
            .asset_output_index = transfer_output.output_index,
            .member_hash = member_hash,
            .proof_index = 0,
            .merkle_path = {sibling_hash},
        },
    };

    const std::array asset_outputs{transfer_output};
    const std::array metadata_outputs{metadata_output};
    const std::array whitelist_outputs{whitelist_output};
    const std::array proof_outputs{proof_output};
    BOOST_CHECK(!bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, proof_outputs).has_value());

    const std::optional<bitplus::assets::AssetValidationResult> missing_metadata{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, std::span<const bitplus::assets::AssetMetadataOutput>{}, whitelist_outputs, proof_outputs)
    };
    BOOST_REQUIRE(missing_metadata.has_value());
    BOOST_CHECK_EQUAL(missing_metadata->reason, "asset-transfer-metadata-missing");

    const std::optional<bitplus::assets::AssetValidationResult> missing_whitelist{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, std::span<const bitplus::assets::AssetWhitelistOutput>{}, proof_outputs)
    };
    BOOST_REQUIRE(missing_whitelist.has_value());
    BOOST_CHECK_EQUAL(missing_whitelist->reason, "asset-transfer-whitelist-missing");

    const std::optional<bitplus::assets::AssetValidationResult> missing_proof{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, std::span<const bitplus::assets::AssetWhitelistProofOutput>{})
    };
    BOOST_REQUIRE(missing_proof.has_value());
    BOOST_CHECK_EQUAL(missing_proof->reason, "asset-whitelist-proof-missing");

    bitplus::assets::AssetWhitelistProofOutput mismatched_member_proof{proof_output};
    mismatched_member_proof.commitment.member_hash = uint256{11};
    const std::array mismatched_member_proofs{mismatched_member_proof};
    const std::optional<bitplus::assets::AssetValidationResult> mismatched_member{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, mismatched_member_proofs)
    };
    BOOST_REQUIRE(mismatched_member.has_value());
    BOOST_CHECK_EQUAL(mismatched_member->reason, "asset-whitelist-proof-member-mismatch");

    bitplus::assets::AssetWhitelistProofOutput wrong_proof{proof_output};
    wrong_proof.commitment.merkle_path = {uint256{8}};
    const std::array wrong_proofs{wrong_proof};
    const std::optional<bitplus::assets::AssetValidationResult> invalid_proof{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, wrong_proofs)
    };
    BOOST_REQUIRE(invalid_proof.has_value());
    BOOST_CHECK_EQUAL(invalid_proof->reason, "asset-whitelist-proof-invalid");

    bitplus::assets::AssetWhitelistProofOutput duplicate_proof{proof_output};
    duplicate_proof.output_index = 4;
    const std::array duplicate_proofs{proof_output, duplicate_proof};
    const std::optional<bitplus::assets::AssetValidationResult> duplicate_proof_result{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, duplicate_proofs)
    };
    BOOST_REQUIRE(duplicate_proof_result.has_value());
    BOOST_CHECK_EQUAL(duplicate_proof_result->reason, "asset-whitelist-proof-duplicate");

    bitplus::assets::AssetWhitelistProofOutput orphan_proof{proof_output};
    orphan_proof.commitment.asset_output_index = 9;
    const std::array orphan_proofs{proof_output, orphan_proof};
    const std::optional<bitplus::assets::AssetValidationResult> orphan_proof_result{
        bitplus::assets::FindFirstUnprovenWhitelistedTransfer(asset_outputs, metadata_outputs, whitelist_outputs, orphan_proofs)
    };
    BOOST_REQUIRE(orphan_proof_result.has_value());
    BOOST_CHECK_EQUAL(orphan_proof_result->reason, "asset-whitelist-proof-orphan");
}

BOOST_AUTO_TEST_CASE(script_asset_conservation)
{
    const uint256 asset_id{1};
    const uint256 issued_asset_id{2};
    const uint256 metadata_hash{3};

    const bitplus::assets::AssetOutput spent{
        .output_index = 0,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = asset_id,
            .amount = 100,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };
    const bitplus::assets::AssetOutput transferred{
        .output_index = 0,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = asset_id,
            .amount = 70,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };
    const bitplus::assets::AssetOutput burned{
        .output_index = 1,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::BURN,
            .asset_id = asset_id,
            .amount = 30,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };
    const bitplus::assets::AssetOutput issued{
        .output_index = 2,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::ISSUANCE,
            .asset_id = issued_asset_id,
            .amount = 50,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };
    const bitplus::assets::AssetOutput issued_transfer{
        .output_index = 3,
        .carrier_amount = 0,
        .commitment = bitplus::assets::AssetCommitment{
            .type = bitplus::assets::AssetCommitmentType::TRANSFER,
            .asset_id = issued_asset_id,
            .amount = 50,
            .metadata_hash = metadata_hash,
            .member_hash = uint256{11},
        },
    };

    const std::array balanced_created{transferred, burned, issued, issued_transfer};
    const std::vector<bitplus::assets::AssetConservationResult> balanced{
        bitplus::assets::CheckAssetConservation(std::span<const bitplus::assets::AssetOutput>{&spent, 1}, balanced_created)
    };
    BOOST_REQUIRE_EQUAL(balanced.size(), 2);
    BOOST_CHECK(balanced[0].balanced);
    BOOST_CHECK(!balanced[0].overflow);
    BOOST_CHECK(balanced[1].balanced);
    BOOST_CHECK(!balanced[1].overflow);

    bitplus::assets::AssetOutput inflated{transferred};
    inflated.commitment.amount = 71;
    const std::array inflated_created{inflated, burned};
    const std::vector<bitplus::assets::AssetConservationResult> unbalanced{
        bitplus::assets::CheckAssetConservation(std::span<const bitplus::assets::AssetOutput>{&spent, 1}, inflated_created)
    };
    BOOST_REQUIRE_EQUAL(unbalanced.size(), 1);
    BOOST_CHECK(!unbalanced[0].balanced);
    BOOST_CHECK(!unbalanced[0].overflow);
}

BOOST_AUTO_TEST_CASE(script_transaction_asset_conservation)
{
    const uint256 asset_id{1};
    const uint256 metadata_hash{3};
    const bitplus::assets::AssetCommitment spent_asset{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = asset_id,
        .amount = 100,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };
    const bitplus::assets::AssetCommitment created_asset{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = asset_id,
        .amount = 100,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };

    CCoinsViewCache coins{&CoinsViewEmpty::Get()};
    const COutPoint prevout{Txid::FromUint256(uint256{9}), 0};
    coins.AddCoin(prevout, Coin{CTxOut{0, bitplus::assets::BuildAssetCommitmentScript(spent_asset)}, 1, false}, false);

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(created_asset));

    const CTransaction ctx{tx};
    const std::optional<std::vector<bitplus::assets::AssetOutput>> spent_outputs{bitplus::assets::ExtractSpentAssetOutputs(ctx, coins)};
    BOOST_REQUIRE(spent_outputs.has_value());
    BOOST_REQUIRE_EQUAL(spent_outputs->size(), 1);
    BOOST_CHECK(spent_outputs->front().commitment == spent_asset);

    const std::optional<std::vector<bitplus::assets::AssetConservationResult>> results{bitplus::assets::CheckTransactionAssetConservation(ctx, coins)};
    BOOST_REQUIRE(results.has_value());
    BOOST_REQUIRE_EQUAL(results->size(), 1);
    BOOST_CHECK(results->front().balanced);
    BOOST_CHECK(!results->front().overflow);

    CMutableTransaction missing_tx;
    missing_tx.vin.emplace_back(Txid::FromUint256(uint256{10}), 0);
    missing_tx.vout.emplace_back(0, bitplus::assets::BuildAssetCommitmentScript(created_asset));
    BOOST_CHECK(!bitplus::assets::CheckTransactionAssetConservation(CTransaction{missing_tx}, coins).has_value());
}

BOOST_AUTO_TEST_CASE(script_asset_metadata_commitments)
{
    bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{6},
        .admin_key_hash = uint256{7},
        .members_root = uint256{8},
        .flags = 1,
    };

    bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{3},
        .document_hash = uint256{4},
        .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
    };

    const std::vector<unsigned char> encoded{bitplus::assets::EncodeAssetMetadataCommitment(metadata)};
    const std::optional<bitplus::assets::AssetMetadataCommitment> decoded{bitplus::assets::DecodeAssetMetadataCommitment(encoded)};
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == metadata);

    const CScript script{bitplus::assets::BuildAssetMetadataCommitmentScript(metadata)};
    const std::optional<bitplus::assets::AssetMetadataCommitment> decoded_script{bitplus::assets::DecodeAssetMetadataCommitmentScript(script)};
    BOOST_REQUIRE(decoded_script.has_value());
    BOOST_CHECK(*decoded_script == metadata);

    std::vector<unsigned char> mutated{encoded};
    mutated[0] = 0;
    BOOST_CHECK(!bitplus::assets::DecodeAssetMetadataCommitment(mutated).has_value());
    BOOST_CHECK(bitplus::assets::HashAssetMetadataCommitment(metadata) != uint256{});
}

BOOST_AUTO_TEST_CASE(script_asset_whitelist_commitments)
{
    bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{6},
        .admin_key_hash = uint256{7},
        .members_root = uint256{8},
        .flags = 1,
    };

    const std::vector<unsigned char> encoded{bitplus::assets::EncodeAssetWhitelistCommitment(whitelist)};
    const std::optional<bitplus::assets::AssetWhitelistCommitment> decoded{bitplus::assets::DecodeAssetWhitelistCommitment(encoded)};
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == whitelist);

    const CScript script{bitplus::assets::BuildAssetWhitelistCommitmentScript(whitelist)};
    const std::optional<bitplus::assets::AssetWhitelistCommitment> decoded_script{bitplus::assets::DecodeAssetWhitelistCommitmentScript(script)};
    BOOST_REQUIRE(decoded_script.has_value());
    BOOST_CHECK(*decoded_script == whitelist);

    bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{3},
        .document_hash = uint256{4},
        .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
    };
    BOOST_CHECK(metadata.rules_hash != uint256{});

    std::vector<unsigned char> mutated{encoded};
    mutated[0] = 0;
    BOOST_CHECK(!bitplus::assets::DecodeAssetWhitelistCommitment(mutated).has_value());
    BOOST_CHECK(bitplus::assets::HashAssetWhitelistCommitment(whitelist) != uint256{});
}

BOOST_AUTO_TEST_CASE(script_dvp_settlement_template)
{
    bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{6},
        .admin_key_hash = uint256{7},
        .members_root = uint256{8},
        .flags = 1,
    };
    bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{3},
        .document_hash = uint256{4},
        .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
    };
    bitplus::assets::AssetCommitment asset_transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = uint256{1},
        .amount = 1'000,
        .metadata_hash = bitplus::assets::HashAssetMetadataCommitment(metadata),
        .member_hash = uint256{11},
    };

    const CAmount payment_amount{125'000};
    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript payment_script{CScript{} << OP_1};
    const CScript asset_script{bitplus::assets::BuildAssetCommitmentScript(asset_transfer)};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(0, asset_script);
    tx.vout.emplace_back(payment_amount, payment_script);

    const CScript dvp_leaf{bitplus::contracts::BuildDvPSettlementLeaf(auth_script, asset_transfer, 0, payment_script, payment_amount, 1)};
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK(EvalScript(stack, dvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vout[1].nValue = payment_amount - 1;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, dvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHECKOUTPUTVERIFY);

    const CScript custom_asset_lock{CScript{} << OP_2};
    const CScript custom_asset_script{bitplus::assets::BuildAssetCommitmentScript(asset_transfer, custom_asset_lock)};
    tx.vout[0].nValue = 0;
    tx.vout[0].scriptPubKey = custom_asset_script;
    tx.vout[1].nValue = payment_amount;
    stack.clear();
    const CScript custom_dvp_leaf{bitplus::contracts::BuildDvPSettlementLeaf(auth_script, asset_transfer, custom_asset_lock, 0, payment_script, payment_amount, 1)};
    BOOST_CHECK(EvalScript(stack, custom_dvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vout[0].scriptPubKey = asset_script;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, custom_dvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHECKOUTPUTVERIFY);
}

BOOST_AUTO_TEST_CASE(script_pvp_settlement_template)
{
    bitplus::assets::AssetWhitelistCommitment whitelist{
        .list_id = uint256{6},
        .admin_key_hash = uint256{7},
        .members_root = uint256{8},
        .flags = 1,
    };
    bitplus::assets::AssetMetadataCommitment metadata{
        .issuer_id = uint256{3},
        .document_hash = uint256{4},
        .rules_hash = bitplus::assets::HashAssetWhitelistCommitment(whitelist),
    };
    const uint256 metadata_hash{bitplus::assets::HashAssetMetadataCommitment(metadata)};
    bitplus::assets::AssetCommitment first_asset_transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = uint256{1},
        .amount = 1'000,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };
    bitplus::assets::AssetCommitment second_asset_transfer{
        .type = bitplus::assets::AssetCommitmentType::TRANSFER,
        .asset_id = uint256{2},
        .amount = 2'000,
        .metadata_hash = metadata_hash,
        .member_hash = uint256{11},
    };

    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript first_asset_script{bitplus::assets::BuildAssetCommitmentScript(first_asset_transfer)};
    const CScript second_asset_script{bitplus::assets::BuildAssetCommitmentScript(second_asset_transfer)};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(0, first_asset_script);
    tx.vout.emplace_back(0, second_asset_script);

    const CScript pvp_leaf{bitplus::contracts::BuildPvPSettlementLeaf(auth_script, first_asset_transfer, 0, second_asset_transfer, 1)};
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK(EvalScript(stack, pvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    second_asset_transfer.amount += 1;
    tx.vout[1].scriptPubKey = bitplus::assets::BuildAssetCommitmentScript(second_asset_transfer);
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, pvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHECKOUTPUTVERIFY);

    const CScript first_custom_lock{CScript{} << OP_2};
    const CScript second_custom_lock{CScript{} << OP_3};
    tx.vout[0].scriptPubKey = bitplus::assets::BuildAssetCommitmentScript(first_asset_transfer, first_custom_lock);
    tx.vout[1].scriptPubKey = bitplus::assets::BuildAssetCommitmentScript(second_asset_transfer, second_custom_lock);
    stack.clear();
    const CScript custom_pvp_leaf{bitplus::contracts::BuildPvPSettlementLeaf(
        auth_script,
        first_asset_transfer,
        first_custom_lock,
        0,
        second_asset_transfer,
        second_custom_lock,
        1)};
    BOOST_CHECK(EvalScript(stack, custom_pvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vout[1].scriptPubKey = bitplus::assets::BuildAssetCommitmentScript(second_asset_transfer);
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, custom_pvp_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHECKOUTPUTVERIFY);
}

BOOST_AUTO_TEST_CASE(script_collateral_templates)
{
    const CAmount collateral_amount{250'000};
    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript release_script{CScript{} << OP_1};
    const CScript return_script{CScript{} << OP_2};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 20;
    tx.vout.emplace_back(collateral_amount, release_script);

    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    const CScript release_leaf{bitplus::contracts::BuildCollateralReleaseLeaf(auth_script, release_script, collateral_amount, 0)};
    BOOST_CHECK(EvalScript(stack, release_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vout[0].scriptPubKey = return_script;
    stack.clear();
    const CScript return_leaf{bitplus::contracts::BuildCollateralReturnLeaf(auth_script, 20, return_script, collateral_amount, 0)};
    BOOST_CHECK(EvalScript(stack, return_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vin[0].nSequence = 19;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, return_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(script_expiry_refund_templates)
{
    const CAmount refund_amount{175'000};
    const CScript auth_script{CScript{} << OP_TRUE};
    const CScript refund_script{CScript{} << OP_1};

    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 500;
    tx.vin.resize(1);
    tx.vin[0].nSequence = 30;
    tx.vout.emplace_back(refund_amount, refund_script);

    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    const CScript absolute_refund_leaf{bitplus::contracts::BuildAbsoluteRefundLeaf(auth_script, 500, refund_script, refund_amount, 0)};
    BOOST_CHECK(EvalScript(stack, absolute_refund_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.nLockTime = 499;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, absolute_refund_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    tx.nLockTime = 0;
    tx.vin[0].nSequence = 30;
    stack.clear();
    const CScript relative_refund_leaf{bitplus::contracts::BuildRelativeRefundLeaf(auth_script, 30, refund_script, refund_amount, 0)};
    BOOST_CHECK(EvalScript(stack, relative_refund_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    tx.vin[0].nSequence = 29;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, relative_refund_leaf, SCRIPT_VERIFY_INSTITUTIONAL_CONTRACTS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, MutableTransactionSignatureChecker{&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL}, SigVersion::TAPSCRIPT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

static CScript
sign_multisig(const CScript& scriptPubKey, const std::vector<CKey>& keys, const CTransaction& transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the block chain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    for (const CKey &key : keys)
    {
        std::vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
static CScript
sign_multisig(const CScript& scriptPubKey, const CKey& key, const CTransaction& transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CTransaction txFrom12{BuildCreditingTransaction(scriptPubKey12)};
    CMutableTransaction txTo12 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom12);

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, CTransaction(txTo12));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();
    CKey key4 = GenerateRandomKey(/*compressed=*/false);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << ToByteVector(key3.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    const CTransaction txFrom23{BuildCreditingTransaction(scriptPubKey23)};
    CMutableTransaction txTo23 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom23);

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't reuse sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));
}

/** Return the TxoutType of a script without exposing Solver details. */
static TxoutType GetTxoutType(const CScript& output_script)
{
    std::vector<std::vector<uint8_t>> unused;
    return Solver(output_script, unused);
}

#define CHECK_SCRIPT_STATIC_SIZE(script, expected_size)                   \
    do {                                                                  \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));              \
        BOOST_CHECK_EQUAL((script).capacity(), CScriptBase::STATIC_SIZE); \
        BOOST_CHECK_EQUAL((script).allocated_memory(), 0);                \
    } while (0)

#define CHECK_SCRIPT_DYNAMIC_SIZE(script, expected_size, expected_extra)                 \
    do {                                                                 \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));             \
        BOOST_CHECK_EQUAL((script).capacity(), (expected_extra));         \
        BOOST_CHECK_EQUAL((script).allocated_memory(), (expected_extra)); \
    } while (0)

BOOST_AUTO_TEST_CASE(script_size_and_capacity_test)
{
    BOOST_CHECK_EQUAL(sizeof(CompressedScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CScriptBase), 40);
    BOOST_CHECK_NE(sizeof(CScriptBase), sizeof(prevector<CScriptBase::STATIC_SIZE + 1, uint8_t>)); // CScriptBase size should be set to avoid wasting space in padding
    BOOST_CHECK_EQUAL(sizeof(CScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CTxOut), 48);

    CKey dummy_key;
    dummy_key.MakeNewKey(/*fCompressed=*/true);
    const CPubKey dummy_pubkey{dummy_key.GetPubKey()};

    // Small OP_RETURN has direct allocation
    {
        const auto script{CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xaa)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::NULL_DATA);
        CHECK_SCRIPT_STATIC_SIZE(script, 12);
    }

    // P2WPKH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0KeyHash{PKHash{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V0_KEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 22);
    }

    // P2SH has direct allocation
    {
        const auto script{GetScriptForDestination(ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 23);
    }

    // P2PKH has direct allocation
    {
        const auto script{GetScriptForDestination(PKHash{dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 25);
    }

    // P2WSH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToWitnessScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // P2TR has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V1_TAPROOT);
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // Compressed P2PK has direct allocation
    {
        const auto script{GetScriptForRawPubKey(dummy_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_STATIC_SIZE(script, 35);
    }

    // Uncompressed P2PK needs extra allocation
    {
        CKey uncompressed_key;
        uncompressed_key.MakeNewKey(/*fCompressed=*/false);
        const CPubKey uncompressed_pubkey{uncompressed_key.GetPubKey()};

        const auto script{GetScriptForRawPubKey(uncompressed_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 67, 67);
    }

    // Bare multisig needs extra allocation
    {
        const auto script{GetScriptForMultisig(1, std::vector{2, dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::MULTISIG);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 71, 103);
    }
}

/* Wrapper around ProduceSignature to combine two scriptsigs */
SignatureData CombineSignatures(const CTxOut& txout, const CMutableTransaction& tx, const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    SignatureData data;
    data.MergeSignatureData(scriptSig1);
    data.MergeSignatureData(scriptSig2);
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(tx, 0, txout.nValue, {.sighash_type = SIGHASH_DEFAULT}), txout.scriptPubKey, data);
    return data;
}

BOOST_AUTO_TEST_CASE(script_combineSigs)
{
    // Test the ProduceSignature's ability to combine signatures function
    FillableSigningProvider keystore;
    std::vector<CKey> keys;
    std::vector<CPubKey> pubkeys;
    for (int i = 0; i < 3; i++)
    {
        CKey key = GenerateRandomKey(/*compressed=*/i%2 == 1);
        keys.push_back(key);
        pubkeys.push_back(key.GetPubKey());
        BOOST_CHECK(keystore.AddKey(key));
    }

    CMutableTransaction txFrom = BuildCreditingTransaction(GetScriptForDestination(PKHash(keys[0].GetPubKey())));
    CMutableTransaction txTo = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(txFrom));
    CScript& scriptPubKey = txFrom.vout[0].scriptPubKey;
    SignatureData scriptSig;

    SignatureData empty;
    SignatureData combined = CombineSignatures(txFrom.vout[0], txTo, empty, empty);
    BOOST_CHECK(combined.scriptSig.empty());

    // Single signature case:
    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy)); // changes scriptSig
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    SignatureData scriptSigCopy = scriptSig;
    // Signing again will give a different, valid signature:
    SignatureData dummy_b;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_b));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // P2SH, single-signature case:
    CScript pkSingle; pkSingle << ToByteVector(keys[0].GetPubKey()) << OP_CHECKSIG;
    BOOST_CHECK(keystore.AddCScript(pkSingle));
    scriptPubKey = GetScriptForDestination(ScriptHash(pkSingle));
    SignatureData dummy_c;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_c));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    scriptSigCopy = scriptSig;
    SignatureData dummy_d;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_d));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // Hardest case:  Multisig 2-of-3
    scriptPubKey = GetScriptForMultisig(2, pubkeys);
    BOOST_CHECK(keystore.AddCScript(scriptPubKey));
    SignatureData dummy_e;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_e));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);

    // A couple of partially-signed versions:
    std::vector<unsigned char> sig1;
    uint256 hash1 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keys[0].Sign(hash1, sig1));
    sig1.push_back(SIGHASH_ALL);
    std::vector<unsigned char> sig2;
    uint256 hash2 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_NONE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[1].Sign(hash2, sig2));
    sig2.push_back(SIGHASH_NONE);
    std::vector<unsigned char> sig3;
    uint256 hash3 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_SINGLE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[2].Sign(hash3, sig3));
    sig3.push_back(SIGHASH_SINGLE);

    // Not fussy about order (or even existence) of placeholders or signatures:
    CScript partial1a = CScript() << OP_0 << sig1 << OP_0;
    CScript partial1b = CScript() << OP_0 << OP_0 << sig1;
    CScript partial2a = CScript() << OP_0 << sig2;
    CScript partial2b = CScript() << sig2 << OP_0;
    CScript partial3a = CScript() << sig3;
    CScript partial3b = CScript() << OP_0 << OP_0 << sig3;
    CScript partial3c = CScript() << OP_0 << sig3 << OP_0;
    CScript complete12 = CScript() << OP_0 << sig1 << sig2;
    CScript complete13 = CScript() << OP_0 << sig1 << sig3;
    CScript complete23 = CScript() << OP_0 << sig2 << sig3;
    SignatureData partial1_sigs;
    partial1_sigs.signatures.emplace(keys[0].GetPubKey().GetID(), SigPair(keys[0].GetPubKey(), sig1));
    SignatureData partial2_sigs;
    partial2_sigs.signatures.emplace(keys[1].GetPubKey().GetID(), SigPair(keys[1].GetPubKey(), sig2));
    SignatureData partial3_sigs;
    partial3_sigs.signatures.emplace(keys[2].GetPubKey().GetID(), SigPair(keys[2].GetPubKey(), sig3));

    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == partial1a);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete13);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == partial3c);
}

/**
 * Reproduction of an exception incorrectly raised when parsing a public key inside a TapMiniscript.
 */
BOOST_AUTO_TEST_CASE(sign_invalid_miniscript)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;

    // Create a Taproot output which contains a leaf in which a non-32 bytes push is used where a public key is expected
    // by the Miniscript parser. This offending Script was found by the RPC fuzzer.
    const auto invalid_pubkey{"173d36c8c9c9c9ffffffffffff0200000000021e1e37373721361818181818181e1e1e1e19000000000000000000b19292929292926b006c9b9b9292"_hex_u8};
    TaprootBuilder builder;
    builder.Add(0, {invalid_pubkey}, 0xc0);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    prev.vout.emplace_back(0, GetScriptForDestination(builder.GetOutput()));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});
    sig_data.tr_spenddata = builder.GetSpendData();

    // SignSignature can fail but it shouldn't raise an exception (nor crash).
    BOOST_CHECK(!SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

/* P2A input should be considered signed. */
BOOST_AUTO_TEST_CASE(sign_paytoanchor)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;
    prev.vout.emplace_back(0, GetScriptForDestination(PayToAnchor{}));

    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});

    BOOST_CHECK(SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

BOOST_AUTO_TEST_CASE(script_standard_push)
{
    ScriptError err;
    for (int i=0; i<67000; i++) {
        CScript script;
        script << i;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Number " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Number " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    for (unsigned int i=0; i<=MAX_SCRIPT_ELEMENT_SIZE; i++) {
        std::vector<unsigned char> data(i, '\111');
        CScript script;
        script << data;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Length " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Length " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(script_IsPushOnly_on_invalid_scripts)
{
    // IsPushOnly returns false when given a script containing only pushes that
    // are invalid due to truncation. IsPushOnly() is consensus critical
    // because P2SH evaluation uses it, although this specific behavior should
    // not be consensus critical as the P2SH evaluation would fail first due to
    // the invalid push. Still, it doesn't hurt to test it explicitly.
    static const unsigned char direct[] = { 1 };
    BOOST_CHECK(!CScript(direct, direct+sizeof(direct)).IsPushOnly());
}

BOOST_AUTO_TEST_CASE(script_CheckMinimalPush_boundary)
{
    // Test the boundary at exactly 65535 bytes: must use OP_PUSHDATA2, not OP_PUSHDATA4.
    std::vector<unsigned char> data(65535, '\x42');
    BOOST_CHECK(CheckMinimalPush(data, OP_PUSHDATA2));
    BOOST_CHECK(!CheckMinimalPush(data, OP_PUSHDATA4));
}

BOOST_AUTO_TEST_CASE(script_GetScriptAsm)
{
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY));

    std::string derSig("304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090");
    std::string pubKey("03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2");
    std::vector<unsigned char> vchPubKey = ToByteVector(ParseHex(pubKey));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey, true));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey));
}

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

BOOST_AUTO_TEST_CASE(script_byte_array_u8_vector_equivalence)
{
    const CScript scriptPubKey1 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex_v_u8 << OP_CHECKSIG;
    const CScript scriptPubKey2 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BOOST_CHECK(scriptPubKey1 == scriptPubKey2);
}

BOOST_AUTO_TEST_CASE(script_FindAndDelete)
{
    // Exercise the FindAndDelete functionality
    CScript s;
    CScript d;
    CScript expect;

    s = CScript() << OP_1 << OP_2;
    d = CScript(); // delete nothing should be a no-op
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_1 << OP_2 << OP_3;
    d = CScript() << OP_2;
    expect = CScript() << OP_1 << OP_3;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3;
    d = CScript() << OP_3;
    expect = CScript() << OP_1 << OP_4;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 4);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff03"_hex); // PUSH 0x02ff03 onto stack
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex); // PUSH 0x02ff03 PUSH 0x02ff03
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("02"_hex);
    expect = s; // FindAndDelete matches entire opcodes
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("ff"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    // This is an odd edge case: strip of the push-three-bytes
    // prefix, leaving 02ff03 which is push-two-bytes:
    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("03"_hex);
    expect = CScript() << "ff03"_hex << "ff03"_hex;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Byte sequence that spans multiple opcodes:
    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0); // doesn't match 'inside' opcodes
    BOOST_CHECK(s == expect);

    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("02feed51"_hex);
    expect = ToScript("69"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("02feed51"_hex);
    expect = ToScript("516969"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Another weird edge case:
    // End with invalid push (not enough data)...
    s = ToScript("0003feed"_hex);
    d = ToScript("03feed"_hex); // ... can remove the invalid push
    expect = ToScript("00"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0003feed"_hex);
    d = ToScript("00"_hex);
    expect = ToScript("03feed"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);
}

BOOST_AUTO_TEST_CASE(script_HasValidOps)
{
    // Exercise the HasValidOps functionality
    CScript script;
    script = ToScript("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex); // Normal script
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("76a914ff34567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex);
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("ff88ac"_hex); // Script with OP_INVALIDOPCODE explicit
    BOOST_CHECK(!script.HasValidOps());
    script = ToScript("88acc0"_hex); // Script with undefined opcode
    BOOST_CHECK(!script.HasValidOps());
}

BOOST_AUTO_TEST_CASE(bip341_keypath_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    const auto& vectors = tests["keyPathSpending"];

    for (const auto& vec : vectors.getValues()) {
        auto txhex = ParseHex(vec["given"]["rawUnsignedTx"].get_str());
        CMutableTransaction tx;
        SpanReader{txhex} >> TX_WITH_WITNESS(tx);
        std::vector<CTxOut> utxos;
        for (const auto& utxo_spent : vec["given"]["utxosSpent"].getValues()) {
            auto script_bytes = ParseHex(utxo_spent["scriptPubKey"].get_str());
            CScript script{script_bytes.begin(), script_bytes.end()};
            CAmount amount{utxo_spent["amountSats"].getInt<int>()};
            utxos.emplace_back(amount, script);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{utxos}, true);

        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), vec["intermediary"]["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), vec["intermediary"]["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), vec["intermediary"]["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), vec["intermediary"]["hashScriptPubkeys"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), vec["intermediary"]["hashSequences"].get_str());

        for (const auto& input : vec["inputSpending"].getValues()) {
            int txinpos = input["given"]["txinIndex"].getInt<int>();
            int hashtype = input["given"]["hashType"].getInt<int>();

            // Load key.
            auto privkey = ParseHex(input["given"]["internalPrivkey"].get_str());
            CKey key;
            key.Set(privkey.begin(), privkey.end(), true);

            // Load Merkle root.
            uint256 merkle_root;
            if (!input["given"]["merkleRoot"].isNull()) {
                merkle_root = uint256{ParseHex(input["given"]["merkleRoot"].get_str())};
            }

            // Compute and verify (internal) public key.
            XOnlyPubKey pubkey{key.GetPubKey()};
            BOOST_CHECK_EQUAL(HexStr(pubkey), input["intermediary"]["internalPubkey"].get_str());

            // Sign and verify signature.
            FlatSigningProvider provider;
            provider.keys[key.GetPubKey().GetID()] = key;
            MutableTransactionSignatureCreator creator(tx, txinpos, utxos[txinpos].nValue, &txdata, {.sighash_type = hashtype});
            std::vector<unsigned char> signature;
            BOOST_CHECK(creator.CreateSchnorrSig(provider, signature, pubkey, nullptr, &merkle_root, SigVersion::TAPROOT));
            BOOST_CHECK_EQUAL(HexStr(signature), input["expected"]["witness"][0].get_str());

            // We can't observe the tweak used inside the signing logic, so verify by recomputing it.
            BOOST_CHECK_EQUAL(HexStr(pubkey.ComputeTapTweakHash(merkle_root.IsNull() ? nullptr : &merkle_root)), input["intermediary"]["tweak"].get_str());

            // We can't observe the sighash used inside the signing logic, so verify by recomputing it.
            ScriptExecutionData sed;
            sed.m_annex_init = true;
            sed.m_annex_present = false;
            uint256 sighash;
            BOOST_CHECK(SignatureHashSchnorr(sighash, sed, tx, txinpos, hashtype, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), input["intermediary"]["sigHash"].get_str());

            // To verify the sigmsg, hash the expected sigmsg, and compare it with the (expected) sighash.
            BOOST_CHECK_EQUAL(HexStr((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{ParseHex(input["intermediary"]["sigMsg"].get_str())}).GetSHA256()), input["intermediary"]["sigHash"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(compute_tapbranch)
{
    constexpr uint256 hash1{"8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"};
    constexpr uint256 hash2{"f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"};
    constexpr uint256 result{"a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9"};
    BOOST_CHECK_EQUAL(ComputeTapbranchHash(hash1, hash2), result);
}

BOOST_AUTO_TEST_CASE(compute_tapleaf)
{
    constexpr uint8_t script[6] = {'f','o','o','b','a','r'};
    constexpr uint256 tlc0{"edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"};
    constexpr uint256 tlc2{"8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"};

    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc0, std::span(script)), tlc0);
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc2, std::span(script)), tlc2);
}

BOOST_AUTO_TEST_CASE(formatscriptflags)
{
    // quick check that FormatScriptFlags reports any unknown/unexpected bits
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH), "P2SH");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_TAPROOT), "P2SH,TAPROOT");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH | script_verify_flags::from_int(1u<<31)), "P2SH,0x80000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_TAPROOT | script_verify_flags::from_int(1u<<27)), "TAPROOT,0x08000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_TAPROOT | script_verify_flags::from_int((1u<<28) | (1ull<<58))), "TAPROOT,0x400000010000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(script_verify_flags::from_int(1u<<26)), "0x04000000");
}

BOOST_AUTO_TEST_SUITE_END()
