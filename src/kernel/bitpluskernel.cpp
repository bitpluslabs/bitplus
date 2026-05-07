// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITPLUSKERNEL_BUILD

#include <kernel/bitpluskernel.h>

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <kernel/caches.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace Consensus {
struct Params;
} // namespace Consensus

using kernel::ChainstateRole;
using util::ImmediateTaskRunner;

// Define G_TRANSLATION_FUN symbol in libbitpluskernel library so users of the
// library aren't required to export this symbol
extern const TranslateFn G_TRANSLATION_FUN{nullptr};

static const kernel::Context btpk_context_static{};

namespace {

bool is_valid_flag_combination(script_verify_flags flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

class WriterStream
{
private:
    btpk_WriteBytes m_writer;
    void* m_user_data;

public:
    WriterStream(btpk_WriteBytes writer, void* user_data)
        : m_writer{writer}, m_user_data{user_data} {}

    //
    // Stream subset
    //
    void write(std::span<const std::byte> src)
    {
        if (m_writer(src.data(), src.size(), m_user_data) != 0) {
            throw std::runtime_error("Failed to write serialization data");
        }
    }

    template <typename T>
    WriterStream& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

template <typename C, typename CPP>
struct Handle {
    static C* ref(CPP* cpp_type)
    {
        return reinterpret_cast<C*>(cpp_type);
    }

    static const C* ref(const CPP* cpp_type)
    {
        return reinterpret_cast<const C*>(cpp_type);
    }

    template <typename... Args>
    static C* create(Args&&... args)
    {
        auto cpp_obj{std::make_unique<CPP>(std::forward<Args>(args)...)};
        return ref(cpp_obj.release());
    }

    static C* copy(const C* ptr)
    {
        auto cpp_obj{std::make_unique<CPP>(get(ptr))};
        return ref(cpp_obj.release());
    }

    static const CPP& get(const C* ptr)
    {
        return *reinterpret_cast<const CPP*>(ptr);
    }

    static CPP& get(C* ptr)
    {
        return *reinterpret_cast<CPP*>(ptr);
    }

    static void operator delete(void* ptr)
    {
        delete reinterpret_cast<CPP*>(ptr);
    }
};

} // namespace

struct btpk_BlockTreeEntry: Handle<btpk_BlockTreeEntry, CBlockIndex> {};
struct btpk_Block : Handle<btpk_Block, std::shared_ptr<const CBlock>> {};
struct btpk_BlockValidationState : Handle<btpk_BlockValidationState, BlockValidationState> {};

namespace {

BCLog::Level get_bclog_level(btpk_LogLevel level)
{
    switch (level) {
    case btpk_LogLevel_INFO: {
        return BCLog::Level::Info;
    }
    case btpk_LogLevel_DEBUG: {
        return BCLog::Level::Debug;
    }
    case btpk_LogLevel_TRACE: {
        return BCLog::Level::Trace;
    }
    }
    assert(false);
}

BCLog::LogFlags get_bclog_flag(btpk_LogCategory category)
{
    switch (category) {
    case btpk_LogCategory_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case btpk_LogCategory_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case btpk_LogCategory_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case btpk_LogCategory_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case btpk_LogCategory_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case btpk_LogCategory_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case btpk_LogCategory_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case btpk_LogCategory_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case btpk_LogCategory_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case btpk_LogCategory_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case btpk_LogCategory_ALL: {
        return BCLog::LogFlags::ALL;
    }
    }
    assert(false);
}

btpk_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return btpk_SynchronizationState_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return btpk_SynchronizationState_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return btpk_SynchronizationState_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btpk_Warning cast_btpk_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return btpk_Warning_UNKNOWN_NEW_RULES_ACTIVATED;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return btpk_Warning_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

struct LoggingConnection {
    std::unique_ptr<std::list<std::function<void(const std::string&)>>::iterator> m_connection;
    void* m_user_data;
    std::function<void(void* user_data)> m_deleter;

    LoggingConnection(btpk_LogCallback callback, void* user_data, btpk_DestroyCallback user_data_destroy_callback)
    {
        LOCK(cs_main);

        auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str(), str.length()); })};

        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(connection);
            if (user_data && user_data_destroy_callback) {
                user_data_destroy_callback(user_data);
            }
            throw std::runtime_error("Failed to start logging");
        }

        m_connection = std::make_unique<std::list<std::function<void(const std::string&)>>::iterator>(connection);
        m_user_data = user_data;
        m_deleter = user_data_destroy_callback;

        LogDebug(BCLog::KERNEL, "Logger connected.");
    }

    ~LoggingConnection()
    {
        LOCK(cs_main);
        LogDebug(BCLog::KERNEL, "Logger disconnecting.");

        // Switch back to buffering by calling DisconnectTestLogger if the
        // connection that we are about to remove is the last one.
        if (LogInstance().NumConnections() == 1) {
            LogInstance().DisconnectTestLogger();
        } else {
            LogInstance().DeleteCallback(*m_connection);
        }

        m_connection.reset();
        if (m_user_data && m_deleter) {
            m_deleter(m_user_data);
        }
    }
};

class KernelNotifications final : public kernel::Notifications
{
private:
    btpk_NotificationInterfaceCallbacks m_cbs;

public:
    KernelNotifications(btpk_NotificationInterfaceCallbacks cbs)
        : m_cbs{cbs}
    {
    }

    ~KernelNotifications()
    {
        if (m_cbs.user_data && m_cbs.user_data_destroy) {
            m_cbs.user_data_destroy(m_cbs.user_data);
        }
        m_cbs.user_data_destroy = nullptr;
        m_cbs.user_data = nullptr;
    }

    kernel::InterruptResult blockTip(SynchronizationState state, const CBlockIndex& index, double verification_progress) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip(m_cbs.user_data, cast_state(state), btpk_BlockTreeEntry::ref(&index), verification_progress);
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip(m_cbs.user_data, cast_state(state), height, timestamp, presync ? 1 : 0);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs.progress) m_cbs.progress(m_cbs.user_data, title.original.c_str(), title.original.length(), progress_percent, resume_possible ? 1 : 0);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set(m_cbs.user_data, cast_btpk_warning(id), message.original.c_str(), message.original.length());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset(m_cbs.user_data, cast_btpk_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error(m_cbs.user_data, message.original.c_str(), message.original.length());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error(m_cbs.user_data, message.original.c_str(), message.original.length());
    }
};

class KernelValidationInterface final : public CValidationInterface
{
public:
    btpk_ValidationInterfaceCallbacks m_cbs;

    explicit KernelValidationInterface(const btpk_ValidationInterfaceCallbacks vi_cbs) : m_cbs{vi_cbs} {}

    ~KernelValidationInterface()
    {
        if (m_cbs.user_data && m_cbs.user_data_destroy) {
            m_cbs.user_data_destroy(m_cbs.user_data);
        }
        m_cbs.user_data = nullptr;
        m_cbs.user_data_destroy = nullptr;
    }

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& stateIn) override
    {
        if (m_cbs.block_checked) {
            m_cbs.block_checked(m_cbs.user_data,
                                btpk_Block::copy(btpk_Block::ref(&block)),
                                btpk_BlockValidationState::ref(&stateIn));
        }
    }

    void NewPoWValidBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block) override
    {
        if (m_cbs.pow_valid_block) {
            m_cbs.pow_valid_block(m_cbs.user_data,
                                  btpk_Block::copy(btpk_Block::ref(&block)),
                                  btpk_BlockTreeEntry::ref(pindex));
        }
    }

    void BlockConnected(const ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        if (m_cbs.block_connected) {
            m_cbs.block_connected(m_cbs.user_data,
                                  btpk_Block::copy(btpk_Block::ref(&block)),
                                  btpk_BlockTreeEntry::ref(pindex));
        }
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        if (m_cbs.block_disconnected) {
            m_cbs.block_disconnected(m_cbs.user_data,
                                     btpk_Block::copy(btpk_Block::ref(&block)),
                                     btpk_BlockTreeEntry::ref(pindex));
        }
    }
};

struct ContextOptions {
    mutable Mutex m_mutex;
    std::unique_ptr<const CChainParams> m_chainparams GUARDED_BY(m_mutex);
    std::shared_ptr<KernelNotifications> m_notifications GUARDED_BY(m_mutex);
    std::shared_ptr<KernelValidationInterface> m_validation_interface GUARDED_BY(m_mutex);
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::shared_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<const CChainParams> m_chainparams;

    std::shared_ptr<KernelValidationInterface> m_validation_interface;

    Context(const ContextOptions* options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()}
    {
        if (options) {
            LOCK(options->m_mutex);
            if (options->m_chainparams) {
                m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
            }
            if (options->m_notifications) {
                m_notifications = options->m_notifications;
            }
            if (options->m_validation_interface) {
                m_signals = std::make_unique<ValidationSignals>(std::make_unique<ImmediateTaskRunner>());
                m_validation_interface = options->m_validation_interface;
                m_signals->RegisterSharedValidationInterface(m_validation_interface);
            }
        }

        if (!m_chainparams) {
            m_chainparams = CChainParams::Main();
        }
        if (!m_notifications) {
            m_notifications = std::make_shared<KernelNotifications>(btpk_NotificationInterfaceCallbacks{
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr});
        }

        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }

    ~Context()
    {
        if (m_signals) {
            m_signals->UnregisterSharedValidationInterface(m_validation_interface);
        }
    }
};

//! Helper struct to wrap the ChainstateManager-related Options
struct ChainstateManagerOptions {
    mutable Mutex m_mutex;
    ChainstateManager::Options m_chainman_options GUARDED_BY(m_mutex);
    node::BlockManager::Options m_blockman_options GUARDED_BY(m_mutex);
    std::shared_ptr<const Context> m_context;
    node::ChainstateLoadOptions m_chainstate_load_options GUARDED_BY(m_mutex);

    ChainstateManagerOptions(const std::shared_ptr<const Context>& context, const fs::path& data_dir, const fs::path& blocks_dir)
        : m_chainman_options{ChainstateManager::Options{
              .chainparams = *context->m_chainparams,
              .datadir = data_dir,
              .notifications = *context->m_notifications,
              .signals = context->m_signals.get()}},
          m_blockman_options{node::BlockManager::Options{
              .chainparams = *context->m_chainparams,
              .blocks_dir = blocks_dir,
              .notifications = *context->m_notifications,
              .block_tree_db_params = DBParams{
                  .path = data_dir / "blocks" / "index",
                  .cache_bytes = kernel::CacheSizes{DEFAULT_KERNEL_CACHE}.block_tree_db,
              }}},
          m_context{context}, m_chainstate_load_options{node::ChainstateLoadOptions{}}
    {
    }
};

struct ChainMan {
    std::unique_ptr<ChainstateManager> m_chainman;
    std::shared_ptr<const Context> m_context;

    ChainMan(std::unique_ptr<ChainstateManager> chainman, std::shared_ptr<const Context> context)
        : m_chainman(std::move(chainman)), m_context(std::move(context)) {}
};

} // namespace

struct btpk_Transaction : Handle<btpk_Transaction, std::shared_ptr<const CTransaction>> {};
struct btpk_TransactionOutput : Handle<btpk_TransactionOutput, CTxOut> {};
struct btpk_ScriptPubkey : Handle<btpk_ScriptPubkey, CScript> {};
struct btpk_LoggingConnection : Handle<btpk_LoggingConnection, LoggingConnection> {};
struct btpk_ContextOptions : Handle<btpk_ContextOptions, ContextOptions> {};
struct btpk_Context : Handle<btpk_Context, std::shared_ptr<const Context>> {};
struct btpk_ChainParameters : Handle<btpk_ChainParameters, CChainParams> {};
struct btpk_ChainstateManagerOptions : Handle<btpk_ChainstateManagerOptions, ChainstateManagerOptions> {};
struct btpk_ChainstateManager : Handle<btpk_ChainstateManager, ChainMan> {};
struct btpk_Chain : Handle<btpk_Chain, CChain> {};
struct btpk_BlockSpentOutputs : Handle<btpk_BlockSpentOutputs, std::shared_ptr<CBlockUndo>> {};
struct btpk_TransactionSpentOutputs : Handle<btpk_TransactionSpentOutputs, CTxUndo> {};
struct btpk_Coin : Handle<btpk_Coin, Coin> {};
struct btpk_BlockHash : Handle<btpk_BlockHash, uint256> {};
struct btpk_TransactionInput : Handle<btpk_TransactionInput, CTxIn> {};
struct btpk_TransactionOutPoint: Handle<btpk_TransactionOutPoint, COutPoint> {};
struct btpk_Txid: Handle<btpk_Txid, Txid> {};
struct btpk_PrecomputedTransactionData : Handle<btpk_PrecomputedTransactionData, PrecomputedTransactionData> {};
struct btpk_BlockHeader: Handle<btpk_BlockHeader, CBlockHeader> {};
struct btpk_ConsensusParams: Handle<btpk_ConsensusParams, Consensus::Params> {};

btpk_Transaction* btpk_transaction_create(const void* raw_transaction, size_t raw_transaction_len)
{
    if (raw_transaction == nullptr && raw_transaction_len != 0) {
        return nullptr;
    }
    try {
        SpanReader stream{std::span{reinterpret_cast<const std::byte*>(raw_transaction), raw_transaction_len}};
        return btpk_Transaction::create(std::make_shared<const CTransaction>(deserialize, TX_WITH_WITNESS, stream));
    } catch (...) {
        return nullptr;
    }
}

size_t btpk_transaction_count_outputs(const btpk_Transaction* transaction)
{
    return btpk_Transaction::get(transaction)->vout.size();
}

const btpk_TransactionOutput* btpk_transaction_get_output_at(const btpk_Transaction* transaction, size_t output_index)
{
    const CTransaction& tx = *btpk_Transaction::get(transaction);
    assert(output_index < tx.vout.size());
    return btpk_TransactionOutput::ref(&tx.vout[output_index]);
}

size_t btpk_transaction_count_inputs(const btpk_Transaction* transaction)
{
    return btpk_Transaction::get(transaction)->vin.size();
}

const btpk_TransactionInput* btpk_transaction_get_input_at(const btpk_Transaction* transaction, size_t input_index)
{
    assert(input_index < btpk_Transaction::get(transaction)->vin.size());
    return btpk_TransactionInput::ref(&btpk_Transaction::get(transaction)->vin[input_index]);
}

uint32_t btpk_transaction_get_locktime(const btpk_Transaction* transaction)
{
    return btpk_Transaction::get(transaction)->nLockTime;
}

const btpk_Txid* btpk_transaction_get_txid(const btpk_Transaction* transaction)
{
    return btpk_Txid::ref(&btpk_Transaction::get(transaction)->GetHash());
}

btpk_Transaction* btpk_transaction_copy(const btpk_Transaction* transaction)
{
    return btpk_Transaction::copy(transaction);
}

int btpk_transaction_to_bytes(const btpk_Transaction* transaction, btpk_WriteBytes writer, void* user_data)
{
    try {
        WriterStream ws{writer, user_data};
        ws << TX_WITH_WITNESS(btpk_Transaction::get(transaction));
        return 0;
    } catch (...) {
        return -1;
    }
}

void btpk_transaction_destroy(btpk_Transaction* transaction)
{
    delete transaction;
}

btpk_ScriptPubkey* btpk_script_pubkey_create(const void* script_pubkey, size_t script_pubkey_len)
{
    if (script_pubkey == nullptr && script_pubkey_len != 0) {
        return nullptr;
    }
    auto data = std::span{reinterpret_cast<const uint8_t*>(script_pubkey), script_pubkey_len};
    return btpk_ScriptPubkey::create(data.begin(), data.end());
}

int btpk_script_pubkey_to_bytes(const btpk_ScriptPubkey* script_pubkey_, btpk_WriteBytes writer, void* user_data)
{
    const auto& script_pubkey{btpk_ScriptPubkey::get(script_pubkey_)};
    return writer(script_pubkey.data(), script_pubkey.size(), user_data);
}

btpk_ScriptPubkey* btpk_script_pubkey_copy(const btpk_ScriptPubkey* script_pubkey)
{
    return btpk_ScriptPubkey::copy(script_pubkey);
}

void btpk_script_pubkey_destroy(btpk_ScriptPubkey* script_pubkey)
{
    delete script_pubkey;
}

btpk_TransactionOutput* btpk_transaction_output_create(const btpk_ScriptPubkey* script_pubkey, int64_t amount)
{
    return btpk_TransactionOutput::create(amount, btpk_ScriptPubkey::get(script_pubkey));
}

btpk_TransactionOutput* btpk_transaction_output_copy(const btpk_TransactionOutput* output)
{
    return btpk_TransactionOutput::copy(output);
}

const btpk_ScriptPubkey* btpk_transaction_output_get_script_pubkey(const btpk_TransactionOutput* output)
{
    return btpk_ScriptPubkey::ref(&btpk_TransactionOutput::get(output).scriptPubKey);
}

int64_t btpk_transaction_output_get_amount(const btpk_TransactionOutput* output)
{
    return btpk_TransactionOutput::get(output).nValue;
}

void btpk_transaction_output_destroy(btpk_TransactionOutput* output)
{
    delete output;
}

btpk_PrecomputedTransactionData* btpk_precomputed_transaction_data_create(
    const btpk_Transaction* tx_to,
    const btpk_TransactionOutput** spent_outputs_, size_t spent_outputs_len)
{
    try {
        const CTransaction& tx{*btpk_Transaction::get(tx_to)};
        auto txdata{btpk_PrecomputedTransactionData::create()};
        if (spent_outputs_ != nullptr && spent_outputs_len > 0) {
            assert(spent_outputs_len == tx.vin.size());
            std::vector<CTxOut> spent_outputs;
            spent_outputs.reserve(spent_outputs_len);
            for (size_t i = 0; i < spent_outputs_len; i++) {
                const CTxOut& tx_out{btpk_TransactionOutput::get(spent_outputs_[i])};
                spent_outputs.push_back(tx_out);
            }
            btpk_PrecomputedTransactionData::get(txdata).Init(tx, std::move(spent_outputs));
        } else {
            btpk_PrecomputedTransactionData::get(txdata).Init(tx, {});
        }

        return txdata;
    } catch (...) {
        return nullptr;
    }
}

btpk_PrecomputedTransactionData* btpk_precomputed_transaction_data_copy(const btpk_PrecomputedTransactionData* precomputed_txdata)
{
    return btpk_PrecomputedTransactionData::copy(precomputed_txdata);
}

void btpk_precomputed_transaction_data_destroy(btpk_PrecomputedTransactionData* precomputed_txdata)
{
    delete precomputed_txdata;
}

int btpk_script_pubkey_verify(const btpk_ScriptPubkey* script_pubkey,
                              const int64_t amount,
                              const btpk_Transaction* tx_to,
                              const btpk_PrecomputedTransactionData* precomputed_txdata,
                              const unsigned int input_index,
                              const btpk_ScriptVerificationFlags flags,
                              btpk_ScriptVerifyStatus* status)
{
    // Assert that all specified flags are part of the interface before continuing
    assert((flags & ~btpk_ScriptVerificationFlags_ALL) == 0);

    if (!is_valid_flag_combination(script_verify_flags::from_int(flags))) {
        if (status) *status = btpk_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION;
        return 0;
    }

    const CTransaction& tx{*btpk_Transaction::get(tx_to)};
    assert(input_index < tx.vin.size());

    const PrecomputedTransactionData& txdata{precomputed_txdata ? btpk_PrecomputedTransactionData::get(precomputed_txdata) : PrecomputedTransactionData(tx)};

    if (flags & btpk_ScriptVerificationFlags_TAPROOT && txdata.m_spent_outputs.empty()) {
        if (status) *status = btpk_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED;
        return 0;
    }

    if (status) *status = btpk_ScriptVerifyStatus_OK;

    bool result = VerifyScript(tx.vin[input_index].scriptSig,
                               btpk_ScriptPubkey::get(script_pubkey),
                               &tx.vin[input_index].scriptWitness,
                               script_verify_flags::from_int(flags),
                               TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                               nullptr);
    return result ? 1 : 0;
}

btpk_TransactionInput* btpk_transaction_input_copy(const btpk_TransactionInput* input)
{
    return btpk_TransactionInput::copy(input);
}

const btpk_TransactionOutPoint* btpk_transaction_input_get_out_point(const btpk_TransactionInput* input)
{
    return btpk_TransactionOutPoint::ref(&btpk_TransactionInput::get(input).prevout);
}

uint32_t btpk_transaction_input_get_sequence(const btpk_TransactionInput* input)
{
    return btpk_TransactionInput::get(input).nSequence;
}

void btpk_transaction_input_destroy(btpk_TransactionInput* input)
{
    delete input;
}

btpk_TransactionOutPoint* btpk_transaction_out_point_copy(const btpk_TransactionOutPoint* out_point)
{
    return btpk_TransactionOutPoint::copy(out_point);
}

uint32_t btpk_transaction_out_point_get_index(const btpk_TransactionOutPoint* out_point)
{
    return btpk_TransactionOutPoint::get(out_point).n;
}

const btpk_Txid* btpk_transaction_out_point_get_txid(const btpk_TransactionOutPoint* out_point)
{
    return btpk_Txid::ref(&btpk_TransactionOutPoint::get(out_point).hash);
}

void btpk_transaction_out_point_destroy(btpk_TransactionOutPoint* out_point)
{
    delete out_point;
}

btpk_Txid* btpk_txid_copy(const btpk_Txid* txid)
{
    return btpk_Txid::copy(txid);
}

void btpk_txid_to_bytes(const btpk_Txid* txid, unsigned char output[32])
{
    std::memcpy(output, btpk_Txid::get(txid).begin(), 32);
}

int btpk_txid_equals(const btpk_Txid* txid1, const btpk_Txid* txid2)
{
    return btpk_Txid::get(txid1) == btpk_Txid::get(txid2);
}

void btpk_txid_destroy(btpk_Txid* txid)
{
    delete txid;
}

void btpk_logging_set_options(const btpk_LoggingOptions options)
{
    LOCK(cs_main);
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;
}

void btpk_logging_set_level_category(btpk_LogCategory category, btpk_LogLevel level)
{
    LOCK(cs_main);
    if (category == btpk_LogCategory_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void btpk_logging_enable_category(btpk_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void btpk_logging_disable_category(btpk_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void btpk_logging_disable()
{
    LogInstance().DisableLogging();
}

btpk_LoggingConnection* btpk_logging_connection_create(btpk_LogCallback callback, void* user_data, btpk_DestroyCallback user_data_destroy_callback)
{
    try {
        return btpk_LoggingConnection::create(callback, user_data, user_data_destroy_callback);
    } catch (const std::exception&) {
        return nullptr;
    }
}

void btpk_logging_connection_destroy(btpk_LoggingConnection* connection)
{
    delete connection;
}

btpk_ChainParameters* btpk_chain_parameters_create(const btpk_ChainType chain_type)
{
    switch (chain_type) {
    case btpk_ChainType_MAINNET: {
        return btpk_ChainParameters::ref(const_cast<CChainParams*>(CChainParams::Main().release()));
    }
    case btpk_ChainType_TESTNET: {
        return btpk_ChainParameters::ref(const_cast<CChainParams*>(CChainParams::TestNet().release()));
    }
    case btpk_ChainType_TESTNET_4: {
        return btpk_ChainParameters::ref(const_cast<CChainParams*>(CChainParams::TestNet4().release()));
    }
    case btpk_ChainType_SIGNET: {
        return btpk_ChainParameters::ref(const_cast<CChainParams*>(CChainParams::SigNet({}).release()));
    }
    case btpk_ChainType_REGTEST: {
        return btpk_ChainParameters::ref(const_cast<CChainParams*>(CChainParams::RegTest({}).release()));
    }
    }
    assert(false);
}

btpk_ChainParameters* btpk_chain_parameters_copy(const btpk_ChainParameters* chain_parameters)
{
    return btpk_ChainParameters::copy(chain_parameters);
}

const btpk_ConsensusParams* btpk_chain_parameters_get_consensus_params(const btpk_ChainParameters* chain_parameters)
{
    return btpk_ConsensusParams::ref(&btpk_ChainParameters::get(chain_parameters).GetConsensus());
}

void btpk_chain_parameters_destroy(btpk_ChainParameters* chain_parameters)
{
    delete chain_parameters;
}

btpk_ContextOptions* btpk_context_options_create()
{
    return btpk_ContextOptions::create();
}

void btpk_context_options_set_chainparams(btpk_ContextOptions* options, const btpk_ChainParameters* chain_parameters)
{
    // Copy the chainparams, so the caller can free it again
    LOCK(btpk_ContextOptions::get(options).m_mutex);
    btpk_ContextOptions::get(options).m_chainparams = std::make_unique<const CChainParams>(btpk_ChainParameters::get(chain_parameters));
}

void btpk_context_options_set_notifications(btpk_ContextOptions* options, btpk_NotificationInterfaceCallbacks notifications)
{
    // The KernelNotifications are copy-initialized, so the caller can free them again.
    LOCK(btpk_ContextOptions::get(options).m_mutex);
    btpk_ContextOptions::get(options).m_notifications = std::make_shared<KernelNotifications>(notifications);
}

void btpk_context_options_set_validation_interface(btpk_ContextOptions* options, btpk_ValidationInterfaceCallbacks vi_cbs)
{
    LOCK(btpk_ContextOptions::get(options).m_mutex);
    btpk_ContextOptions::get(options).m_validation_interface = std::make_shared<KernelValidationInterface>(vi_cbs);
}

void btpk_context_options_destroy(btpk_ContextOptions* options)
{
    delete options;
}

btpk_Context* btpk_context_create(const btpk_ContextOptions* options)
{
    bool sane{true};
    const ContextOptions* opts = options ? &btpk_ContextOptions::get(options) : nullptr;
    auto context{std::make_shared<const Context>(opts, sane)};
    if (!sane) {
        LogError("Kernel context sanity check failed.");
        return nullptr;
    }
    return btpk_Context::create(context);
}

btpk_Context* btpk_context_copy(const btpk_Context* context)
{
    return btpk_Context::copy(context);
}

int btpk_context_interrupt(btpk_Context* context)
{
    return (*btpk_Context::get(context)->m_interrupt)() ? 0 : -1;
}

void btpk_context_destroy(btpk_Context* context)
{
    delete context;
}

const btpk_BlockTreeEntry* btpk_block_tree_entry_get_previous(const btpk_BlockTreeEntry* entry)
{
    if (!btpk_BlockTreeEntry::get(entry).pprev) {
        LogInfo("Genesis block has no previous.");
        return nullptr;
    }

    return btpk_BlockTreeEntry::ref(btpk_BlockTreeEntry::get(entry).pprev);
}

const btpk_BlockTreeEntry* btpk_block_tree_entry_get_ancestor(const btpk_BlockTreeEntry* block_tree_entry, int32_t height)
{
    const auto* ancestor{btpk_BlockTreeEntry::get(block_tree_entry).GetAncestor(height)};
    assert(ancestor);
    return btpk_BlockTreeEntry::ref(ancestor);
}

btpk_BlockValidationState* btpk_block_validation_state_create()
{
    return btpk_BlockValidationState::create();
}

btpk_BlockValidationState* btpk_block_validation_state_copy(const btpk_BlockValidationState* state)
{
    return btpk_BlockValidationState::copy(state);
}

void btpk_block_validation_state_destroy(btpk_BlockValidationState* state)
{
    delete state;
}

btpk_ValidationMode btpk_block_validation_state_get_validation_mode(const btpk_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = btpk_BlockValidationState::get(block_validation_state_);
    if (block_validation_state.IsValid()) return btpk_ValidationMode_VALID;
    if (block_validation_state.IsInvalid()) return btpk_ValidationMode_INVALID;
    return btpk_ValidationMode_INTERNAL_ERROR;
}

btpk_BlockValidationResult btpk_block_validation_state_get_block_validation_result(const btpk_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = btpk_BlockValidationState::get(block_validation_state_);
    switch (block_validation_state.GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return btpk_BlockValidationResult_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return btpk_BlockValidationResult_CONSENSUS;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return btpk_BlockValidationResult_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return btpk_BlockValidationResult_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return btpk_BlockValidationResult_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return btpk_BlockValidationResult_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return btpk_BlockValidationResult_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return btpk_BlockValidationResult_TIME_FUTURE;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return btpk_BlockValidationResult_HEADER_LOW_WORK;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btpk_ChainstateManagerOptions* btpk_chainstate_manager_options_create(const btpk_Context* context, const char* data_dir, size_t data_dir_len, const char* blocks_dir, size_t blocks_dir_len)
{
    if (data_dir == nullptr || data_dir_len == 0 || blocks_dir == nullptr || blocks_dir_len == 0) {
        LogError("Failed to create chainstate manager options: dir must be non-null and non-empty");
        return nullptr;
    }
    try {
        fs::path abs_data_dir{fs::absolute(fs::PathFromString({data_dir, data_dir_len}))};
        fs::create_directories(abs_data_dir);
        fs::path abs_blocks_dir{fs::absolute(fs::PathFromString({blocks_dir, blocks_dir_len}))};
        fs::create_directories(abs_blocks_dir);
        return btpk_ChainstateManagerOptions::create(btpk_Context::get(context), abs_data_dir, abs_blocks_dir);
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager options: %s", e.what());
        return nullptr;
    }
}

void btpk_chainstate_manager_options_set_worker_threads_num(btpk_ChainstateManagerOptions* opts, int worker_threads)
{
    LOCK(btpk_ChainstateManagerOptions::get(opts).m_mutex);
    btpk_ChainstateManagerOptions::get(opts).m_chainman_options.worker_threads_num = worker_threads;
}

void btpk_chainstate_manager_options_destroy(btpk_ChainstateManagerOptions* options)
{
    delete options;
}

int btpk_chainstate_manager_options_set_wipe_dbs(btpk_ChainstateManagerOptions* chainman_opts, int wipe_block_tree_db, int wipe_chainstate_db)
{
    if (wipe_block_tree_db == 1 && wipe_chainstate_db != 1) {
        LogError("Wiping the block tree db without also wiping the chainstate db is currently unsupported.");
        return -1;
    }
    auto& opts{btpk_ChainstateManagerOptions::get(chainman_opts)};
    LOCK(opts.m_mutex);
    opts.m_blockman_options.block_tree_db_params.wipe_data = wipe_block_tree_db == 1;
    opts.m_chainstate_load_options.wipe_chainstate_db = wipe_chainstate_db == 1;
    return 0;
}

void btpk_chainstate_manager_options_update_block_tree_db_in_memory(
    btpk_ChainstateManagerOptions* chainman_opts,
    int block_tree_db_in_memory)
{
    auto& opts{btpk_ChainstateManagerOptions::get(chainman_opts)};
    LOCK(opts.m_mutex);
    opts.m_blockman_options.block_tree_db_params.memory_only = block_tree_db_in_memory == 1;
}

void btpk_chainstate_manager_options_update_chainstate_db_in_memory(
    btpk_ChainstateManagerOptions* chainman_opts,
    int chainstate_db_in_memory)
{
    auto& opts{btpk_ChainstateManagerOptions::get(chainman_opts)};
    LOCK(opts.m_mutex);
    opts.m_chainstate_load_options.coins_db_in_memory = chainstate_db_in_memory == 1;
}

btpk_ChainstateManager* btpk_chainstate_manager_create(
    const btpk_ChainstateManagerOptions* chainman_opts)
{
    auto& opts{btpk_ChainstateManagerOptions::get(chainman_opts)};
    std::unique_ptr<ChainstateManager> chainman;
    try {
        LOCK(opts.m_mutex);
        chainman = std::make_unique<ChainstateManager>(*opts.m_context->m_interrupt, opts.m_chainman_options, opts.m_blockman_options);
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager: %s", e.what());
        return nullptr;
    }

    try {
        const auto chainstate_load_opts{WITH_LOCK(opts.m_mutex, return opts.m_chainstate_load_options)};

        kernel::CacheSizes cache_sizes{DEFAULT_KERNEL_CACHE};
        auto [status, chainstate_err]{node::LoadChainstate(*chainman, cache_sizes, chainstate_load_opts)};
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to load chain state from your data directory: %s", chainstate_err.original);
            return nullptr;
        }
        std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(*chainman, chainstate_load_opts);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to verify loaded chain state from your datadir: %s", chainstate_err.original);
            return nullptr;
        }
        if (auto result = chainman->ActivateBestChains(); !result) {
            LogError("%s", util::ErrorString(result).original);
            return nullptr;
        }
    } catch (const std::exception& e) {
        LogError("Failed to load chainstate: %s", e.what());
        return nullptr;
    }

    return btpk_ChainstateManager::create(std::move(chainman), opts.m_context);
}

const btpk_BlockTreeEntry* btpk_chainstate_manager_get_block_tree_entry_by_hash(const btpk_ChainstateManager* chainman, const btpk_BlockHash* block_hash)
{
    auto block_index = WITH_LOCK(btpk_ChainstateManager::get(chainman).m_chainman->GetMutex(),
                                 return btpk_ChainstateManager::get(chainman).m_chainman->m_blockman.LookupBlockIndex(btpk_BlockHash::get(block_hash)));
    if (!block_index) {
        LogDebug(BCLog::KERNEL, "A block with the given hash is not indexed.");
        return nullptr;
    }
    return btpk_BlockTreeEntry::ref(block_index);
}

const btpk_BlockTreeEntry* btpk_chainstate_manager_get_best_entry(const btpk_ChainstateManager* chainstate_manager)
{
    auto& chainman = *btpk_ChainstateManager::get(chainstate_manager).m_chainman;
    return btpk_BlockTreeEntry::ref(WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header));
}

void btpk_chainstate_manager_destroy(btpk_ChainstateManager* chainman)
{
    {
        LOCK(btpk_ChainstateManager::get(chainman).m_chainman->GetMutex());
        for (const auto& chainstate : btpk_ChainstateManager::get(chainman).m_chainman->m_chainstates) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }

    delete chainman;
}

int btpk_chainstate_manager_import_blocks(btpk_ChainstateManager* chainman, const char** block_file_paths_data, size_t* block_file_paths_lens, size_t block_file_paths_data_len)
{
    try {
        std::vector<fs::path> import_files;
        import_files.reserve(block_file_paths_data_len);
        for (uint32_t i = 0; i < block_file_paths_data_len; i++) {
            if (block_file_paths_data[i] != nullptr) {
                import_files.emplace_back(std::string{block_file_paths_data[i], block_file_paths_lens[i]}.c_str());
            }
        }
        auto& chainman_ref{*btpk_ChainstateManager::get(chainman).m_chainman};
        node::ImportBlocks(chainman_ref, import_files);
        WITH_LOCK(::cs_main, chainman_ref.UpdateIBDStatus());
    } catch (const std::exception& e) {
        LogError("Failed to import blocks: %s", e.what());
        return -1;
    }
    return 0;
}

btpk_Block* btpk_block_create(const void* raw_block, size_t raw_block_length)
{
    if (raw_block == nullptr && raw_block_length != 0) {
        return nullptr;
    }
    auto block{std::make_shared<CBlock>()};

    SpanReader stream{std::span{reinterpret_cast<const std::byte*>(raw_block), raw_block_length}};

    try {
        stream >> TX_WITH_WITNESS(*block);
    } catch (...) {
        LogDebug(BCLog::KERNEL, "Block decode failed.");
        return nullptr;
    }

    return btpk_Block::create(block);
}

btpk_Block* btpk_block_copy(const btpk_Block* block)
{
    return btpk_Block::copy(block);
}

int btpk_block_check(const btpk_Block* block, const btpk_ConsensusParams* consensus_params, btpk_BlockCheckFlags flags, btpk_BlockValidationState* validation_state)
{
    auto& state = btpk_BlockValidationState::get(validation_state);
    state = BlockValidationState{};

    const bool check_pow    = (flags & btpk_BlockCheckFlags_POW) != 0;
    const bool check_merkle = (flags & btpk_BlockCheckFlags_MERKLE) != 0;

    const bool result = CheckBlock(*btpk_Block::get(block), state, btpk_ConsensusParams::get(consensus_params), /*fCheckPOW=*/check_pow, /*fCheckMerkleRoot=*/check_merkle);

    return result ? 1 : 0;
}

size_t btpk_block_count_transactions(const btpk_Block* block)
{
    return btpk_Block::get(block)->vtx.size();
}

const btpk_Transaction* btpk_block_get_transaction_at(const btpk_Block* block, size_t index)
{
    assert(index < btpk_Block::get(block)->vtx.size());
    return btpk_Transaction::ref(&btpk_Block::get(block)->vtx[index]);
}

btpk_BlockHeader* btpk_block_get_header(const btpk_Block* block)
{
    const auto& block_ptr = btpk_Block::get(block);
    return btpk_BlockHeader::create(static_cast<const CBlockHeader&>(*block_ptr));
}

int btpk_block_to_bytes(const btpk_Block* block, btpk_WriteBytes writer, void* user_data)
{
    try {
        WriterStream ws{writer, user_data};
        ws << TX_WITH_WITNESS(*btpk_Block::get(block));
        return 0;
    } catch (...) {
        return -1;
    }
}

btpk_BlockHash* btpk_block_get_hash(const btpk_Block* block)
{
    return btpk_BlockHash::create(btpk_Block::get(block)->GetHash());
}

void btpk_block_destroy(btpk_Block* block)
{
    delete block;
}

btpk_Block* btpk_block_read(const btpk_ChainstateManager* chainman, const btpk_BlockTreeEntry* entry)
{
    auto block{std::make_shared<CBlock>()};
    if (!btpk_ChainstateManager::get(chainman).m_chainman->m_blockman.ReadBlock(*block, btpk_BlockTreeEntry::get(entry))) {
        LogError("Failed to read block.");
        return nullptr;
    }
    return btpk_Block::create(block);
}

btpk_BlockHeader* btpk_block_tree_entry_get_block_header(const btpk_BlockTreeEntry* entry)
{
    return btpk_BlockHeader::create(btpk_BlockTreeEntry::get(entry).GetBlockHeader());
}

int32_t btpk_block_tree_entry_get_height(const btpk_BlockTreeEntry* entry)
{
    return btpk_BlockTreeEntry::get(entry).nHeight;
}

const btpk_BlockHash* btpk_block_tree_entry_get_block_hash(const btpk_BlockTreeEntry* entry)
{
    return btpk_BlockHash::ref(btpk_BlockTreeEntry::get(entry).phashBlock);
}

int btpk_block_tree_entry_equals(const btpk_BlockTreeEntry* entry1, const btpk_BlockTreeEntry* entry2)
{
    return &btpk_BlockTreeEntry::get(entry1) == &btpk_BlockTreeEntry::get(entry2);
}

btpk_BlockHash* btpk_block_hash_create(const unsigned char block_hash[32])
{
    return btpk_BlockHash::create(std::span<const unsigned char>{block_hash, 32});
}

btpk_BlockHash* btpk_block_hash_copy(const btpk_BlockHash* block_hash)
{
    return btpk_BlockHash::copy(block_hash);
}

void btpk_block_hash_to_bytes(const btpk_BlockHash* block_hash, unsigned char output[32])
{
    std::memcpy(output, btpk_BlockHash::get(block_hash).begin(), 32);
}

int btpk_block_hash_equals(const btpk_BlockHash* hash1, const btpk_BlockHash* hash2)
{
    return btpk_BlockHash::get(hash1) == btpk_BlockHash::get(hash2);
}

void btpk_block_hash_destroy(btpk_BlockHash* hash)
{
    delete hash;
}

btpk_BlockSpentOutputs* btpk_block_spent_outputs_read(const btpk_ChainstateManager* chainman, const btpk_BlockTreeEntry* entry)
{
    auto block_undo{std::make_shared<CBlockUndo>()};
    if (btpk_BlockTreeEntry::get(entry).nHeight < 1) {
        LogDebug(BCLog::KERNEL, "The genesis block does not have any spent outputs.");
        return btpk_BlockSpentOutputs::create(block_undo);
    }
    if (!btpk_ChainstateManager::get(chainman).m_chainman->m_blockman.ReadBlockUndo(*block_undo, btpk_BlockTreeEntry::get(entry))) {
        LogError("Failed to read block spent outputs data.");
        return nullptr;
    }
    return btpk_BlockSpentOutputs::create(block_undo);
}

btpk_BlockSpentOutputs* btpk_block_spent_outputs_copy(const btpk_BlockSpentOutputs* block_spent_outputs)
{
    return btpk_BlockSpentOutputs::copy(block_spent_outputs);
}

size_t btpk_block_spent_outputs_count(const btpk_BlockSpentOutputs* block_spent_outputs)
{
    return btpk_BlockSpentOutputs::get(block_spent_outputs)->vtxundo.size();
}

const btpk_TransactionSpentOutputs* btpk_block_spent_outputs_get_transaction_spent_outputs_at(const btpk_BlockSpentOutputs* block_spent_outputs, size_t transaction_index)
{
    assert(transaction_index < btpk_BlockSpentOutputs::get(block_spent_outputs)->vtxundo.size());
    const auto* tx_undo{&btpk_BlockSpentOutputs::get(block_spent_outputs)->vtxundo.at(transaction_index)};
    return btpk_TransactionSpentOutputs::ref(tx_undo);
}

void btpk_block_spent_outputs_destroy(btpk_BlockSpentOutputs* block_spent_outputs)
{
    delete block_spent_outputs;
}

btpk_TransactionSpentOutputs* btpk_transaction_spent_outputs_copy(const btpk_TransactionSpentOutputs* transaction_spent_outputs)
{
    return btpk_TransactionSpentOutputs::copy(transaction_spent_outputs);
}

size_t btpk_transaction_spent_outputs_count(const btpk_TransactionSpentOutputs* transaction_spent_outputs)
{
    return btpk_TransactionSpentOutputs::get(transaction_spent_outputs).vprevout.size();
}

void btpk_transaction_spent_outputs_destroy(btpk_TransactionSpentOutputs* transaction_spent_outputs)
{
    delete transaction_spent_outputs;
}

const btpk_Coin* btpk_transaction_spent_outputs_get_coin_at(const btpk_TransactionSpentOutputs* transaction_spent_outputs, size_t coin_index)
{
    assert(coin_index < btpk_TransactionSpentOutputs::get(transaction_spent_outputs).vprevout.size());
    const Coin* coin{&btpk_TransactionSpentOutputs::get(transaction_spent_outputs).vprevout.at(coin_index)};
    return btpk_Coin::ref(coin);
}

btpk_Coin* btpk_coin_copy(const btpk_Coin* coin)
{
    return btpk_Coin::copy(coin);
}

uint32_t btpk_coin_confirmation_height(const btpk_Coin* coin)
{
    return btpk_Coin::get(coin).nHeight;
}

int btpk_coin_is_coinbase(const btpk_Coin* coin)
{
    return btpk_Coin::get(coin).IsCoinBase() ? 1 : 0;
}

const btpk_TransactionOutput* btpk_coin_get_output(const btpk_Coin* coin)
{
    return btpk_TransactionOutput::ref(&btpk_Coin::get(coin).out);
}

void btpk_coin_destroy(btpk_Coin* coin)
{
    delete coin;
}

int btpk_chainstate_manager_process_block(
    btpk_ChainstateManager* chainman,
    const btpk_Block* block,
    int* _new_block)
{
    bool new_block;
    auto result = btpk_ChainstateManager::get(chainman).m_chainman->ProcessNewBlock(btpk_Block::get(block), /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    if (_new_block) {
        *_new_block = new_block ? 1 : 0;
    }
    return result ? 0 : -1;
}

int btpk_chainstate_manager_process_block_header(
    btpk_ChainstateManager* chainstate_manager,
    const btpk_BlockHeader* header,
    btpk_BlockValidationState* state)
{
    try {
        auto& chainman = btpk_ChainstateManager::get(chainstate_manager).m_chainman;
        auto result = chainman->ProcessNewBlockHeaders({&btpk_BlockHeader::get(header), 1}, /*min_pow_checked=*/true, btpk_BlockValidationState::get(state), /*ppindex=*/nullptr);

        return result ? 0 : -1;
    } catch (const std::exception& e) {
        LogError("Failed to process block header: %s", e.what());
        return -1;
    }
}

const btpk_Chain* btpk_chainstate_manager_get_active_chain(const btpk_ChainstateManager* chainman)
{
    return btpk_Chain::ref(&WITH_LOCK(btpk_ChainstateManager::get(chainman).m_chainman->GetMutex(), return btpk_ChainstateManager::get(chainman).m_chainman->ActiveChain()));
}

int32_t btpk_chain_get_height(const btpk_Chain* chain)
{
    LOCK(::cs_main);
    return btpk_Chain::get(chain).Height();
}

const btpk_BlockTreeEntry* btpk_chain_get_by_height(const btpk_Chain* chain, int32_t height)
{
    LOCK(::cs_main);
    return btpk_BlockTreeEntry::ref(btpk_Chain::get(chain)[height]);
}

int btpk_chain_contains(const btpk_Chain* chain, const btpk_BlockTreeEntry* entry)
{
    LOCK(::cs_main);
    return btpk_Chain::get(chain).Contains(btpk_BlockTreeEntry::get(entry)) ? 1 : 0;
}

btpk_BlockHeader* btpk_block_header_create(const void* raw_block_header, size_t raw_block_header_len)
{
    if (raw_block_header == nullptr && raw_block_header_len != 0) {
        return nullptr;
    }
    auto header{std::make_unique<CBlockHeader>()};
    SpanReader stream{std::span{reinterpret_cast<const std::byte*>(raw_block_header), raw_block_header_len}};

    try {
        stream >> *header;
    } catch (...) {
        LogError("Block header decode failed.");
        return nullptr;
    }

    return btpk_BlockHeader::ref(header.release());
}

btpk_BlockHeader* btpk_block_header_copy(const btpk_BlockHeader* header)
{
    return btpk_BlockHeader::copy(header);
}

btpk_BlockHash* btpk_block_header_get_hash(const btpk_BlockHeader* header)
{
    return btpk_BlockHash::create(btpk_BlockHeader::get(header).GetHash());
}

const btpk_BlockHash* btpk_block_header_get_prev_hash(const btpk_BlockHeader* header)
{
    return btpk_BlockHash::ref(&btpk_BlockHeader::get(header).hashPrevBlock);
}

uint32_t btpk_block_header_get_timestamp(const btpk_BlockHeader* header)
{
    return btpk_BlockHeader::get(header).nTime;
}

uint32_t btpk_block_header_get_bits(const btpk_BlockHeader* header)
{
    return btpk_BlockHeader::get(header).nBits;
}

int32_t btpk_block_header_get_version(const btpk_BlockHeader* header)
{
    return btpk_BlockHeader::get(header).nVersion;
}

uint32_t btpk_block_header_get_nonce(const btpk_BlockHeader* header)
{
    return btpk_BlockHeader::get(header).nNonce;
}

int btpk_block_header_to_bytes(const btpk_BlockHeader* header, unsigned char output[80])
{
    try {
        SpanWriter{std::as_writable_bytes(std::span{output, 80})} << btpk_BlockHeader::get(header);
        return 0;
    } catch (...) {
        return -1;
    }
}

void btpk_block_header_destroy(btpk_BlockHeader* header)
{
    delete header;
}
