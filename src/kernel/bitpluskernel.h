// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_KERNEL_BITPLUSKERNEL_H
#define BITPLUS_KERNEL_BITPLUSKERNEL_H

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus

#ifndef BITPLUSKERNEL_API
    #ifdef BITPLUSKERNEL_BUILD
        #if defined(_WIN32)
            #define BITPLUSKERNEL_API __declspec(dllexport)
        #else
            #define BITPLUSKERNEL_API __attribute__((visibility("default")))
        #endif
    #else
        #if defined(_WIN32) && !defined(BITPLUSKERNEL_STATIC)
            #define BITPLUSKERNEL_API __declspec(dllimport)
        #else
            #define BITPLUSKERNEL_API
        #endif
    #endif
#endif

/* Warning attributes */
#if defined(__GNUC__)
    #define BITPLUSKERNEL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
    #define BITPLUSKERNEL_WARN_UNUSED_RESULT
#endif

/**
 * BITPLUSKERNEL_ARG_NONNULL is a compiler attribute used to indicate that
 * certain pointer arguments to a function are not expected to be null.
 *
 * Callers must not pass a null pointer for arguments marked with this attribute,
 * as doing so may result in undefined behavior. This attribute should only be
 * used for arguments where a null pointer is unambiguously a programmer error,
 * such as for opaque handles, and not for pointers to raw input data that might
 * validly be null (e.g., from an empty std::span or std::string).
 */
#if !defined(BITPLUSKERNEL_BUILD) && defined(__GNUC__)
    #define BITPLUSKERNEL_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITPLUSKERNEL_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @page remarks Remarks
 *
 * @section purpose Purpose
 *
 * This header currently exposes an API for interacting with parts of Bitplus
 * Core's consensus code. Users can validate blocks, iterate the block index,
 * read block and undo data from disk, and validate scripts. The header is
 * unversioned and not stable yet. Users should expect breaking changes. It is
 * also not yet included in releases of Bitplus Core.
 *
 * @section context Context
 *
 * The library provides a built-in static constant kernel context. This static
 * context offers only limited functionality. It detects and self-checks the
 * correct sha256 implementation, initializes the random number generator and
 * self-checks the secp256k1 static context. It is used internally for
 * otherwise "context-free" operations. This means that the user is not
 * required to initialize their own context before using the library.
 *
 * The user should create their own context for passing it to state-rich validation
 * functions and holding callbacks for kernel events.
 *
 * @section error Error handling
 *
 * Functions communicate an error through their return types, usually returning
 * a nullptr or a status code as documented by the returning function.
 * Additionally, verification functions, e.g. for scripts, may communicate more
 * detailed error information through status code out parameters.
 *
 * Fine-grained validation information is communicated through the validation
 * interface.
 *
 * The kernel notifications issue callbacks for errors. These are usually
 * indicative of a system error. If such an error is issued, it is recommended
 * to halt and tear down the existing kernel objects. Remediating the error may
 * require system intervention by the user.
 *
 * @section pointer Pointer and argument conventions
 *
 * The user is responsible for de-allocating the memory owned by pointers
 * returned by functions. Typically pointers returned by *_create(...) functions
 * can be de-allocated by corresponding *_destroy(...) functions.
 *
 * A function that takes pointer arguments makes no assumptions on their
 * lifetime. Once the function returns the user can safely de-allocate the
 * passed in arguments.
 *
 * Const pointers represent views, and do not transfer ownership. Lifetime
 * guarantees of these objects are described in the respective documentation.
 * Ownership of these resources may be taken by copying. They are typically
 * used for iteration with minimal overhead and require some care by the
 * programmer that their lifetime is not extended beyond that of the original
 * object.
 *
 * Array lengths follow the pointer argument they describe.
 *
 * @section types Type conventions
 *
 * Fixed-width integer types (e.g. int32_t, uint32_t) are used for data values
 * such as heights. Plain int and unsigned int are used for boolean-like values
 * and flags.
 */

/**
 * Opaque data structure for holding a transaction.
 */
typedef struct btpk_Transaction btpk_Transaction;

/**
 * Opaque data structure for holding a script pubkey.
 */
typedef struct btpk_ScriptPubkey btpk_ScriptPubkey;

/**
 * Opaque data structure for holding a transaction output.
 */
typedef struct btpk_TransactionOutput btpk_TransactionOutput;

/**
 * Opaque data structure for holding a logging connection.
 *
 * The logging connection can be used to manually stop logging.
 *
 * Messages that were logged before a connection is created are buffered in a
 * 1MB buffer. Logging can alternatively be permanently disabled by calling
 * @ref btpk_logging_disable. Functions changing the logging settings are
 * global and change the settings for all existing btpk_LoggingConnection
 * instances.
 */
typedef struct btpk_LoggingConnection btpk_LoggingConnection;

/**
 * Opaque data structure for holding the chain parameters.
 *
 * These are eventually placed into a kernel context through the kernel context
 * options. The parameters describe the properties of a chain, and may be
 * instantiated for either mainnet, testnet, signet, or regtest.
 */
typedef struct btpk_ChainParameters btpk_ChainParameters;

/**
 * Opaque data structure for holding options for creating a new kernel context.
 *
 * Once a kernel context has been created from these options, they may be
 * destroyed. The options hold the notification and validation interface
 * callbacks as well as the selected chain type until they are passed to the
 * context. If no options are configured, the context will be instantiated with
 * no callbacks and for mainnet. Their content and scope can be expanded over
 * time.
 */
typedef struct btpk_ContextOptions btpk_ContextOptions;

/**
 * Opaque data structure for holding a kernel context.
 *
 * The kernel context is used to initialize internal state and hold the chain
 * parameters and callbacks for handling error and validation events. Once
 * other validation objects are instantiated from it, the context is kept in
 * memory for the duration of their lifetimes.
 *
 * The processing of validation events is done through an internal task runner
 * owned by the context. It passes events through the registered validation
 * interface callbacks.
 *
 * A constructed context can be safely used from multiple threads.
 */
typedef struct btpk_Context btpk_Context;

/**
 * Opaque data structure for holding a block tree entry.
 *
 * This is a pointer to an element in the block index currently in memory of
 * the chainstate manager. It is valid for the lifetime of the chainstate
 * manager it was retrieved from. The entry is part of a tree-like structure
 * that is maintained internally. Every entry, besides the genesis, points to a
 * single parent. Multiple entries may share a parent, thus forming a tree.
 * Each entry corresponds to a single block and may be used to retrieve its
 * data and validation status.
 */
typedef struct btpk_BlockTreeEntry btpk_BlockTreeEntry;

/**
 * Opaque data structure for holding options for creating a new chainstate
 * manager.
 *
 * The chainstate manager options are used to set some parameters for the
 * chainstate manager.
 */
typedef struct btpk_ChainstateManagerOptions btpk_ChainstateManagerOptions;

/**
 * Opaque data structure for holding a chainstate manager.
 *
 * The chainstate manager is the central object for doing validation tasks as
 * well as retrieving data from the chain. Internally it is a complex data
 * structure with diverse functionality.
 *
 * Its functionality will be more and more exposed in the future.
 */
typedef struct btpk_ChainstateManager btpk_ChainstateManager;

/**
 * Opaque data structure for holding a block.
 */
typedef struct btpk_Block btpk_Block;

/**
 * Opaque data structure for holding the state of a block during validation.
 *
 * Contains information indicating whether validation was successful, and if not
 * which step during block validation failed.
 */
typedef struct btpk_BlockValidationState btpk_BlockValidationState;

/**
 * Opaque data structure for holding the Consensus Params.
 */
typedef struct btpk_ConsensusParams btpk_ConsensusParams;

/**
 * Opaque data structure for holding the currently known best-chain associated
 * with a chainstate.
 */
typedef struct btpk_Chain btpk_Chain;

/**
 * Opaque data structure for holding a block's spent outputs.
 *
 * Contains all the previous outputs consumed by all transactions in a specific
 * block. Internally it holds a nested vector. The top level vector has an
 * entry for each transaction in a block (in order of the actual transactions
 * of the block and without the coinbase transaction). This is exposed through
 * @ref btpk_TransactionSpentOutputs. Each btpk_TransactionSpentOutputs is in
 * turn a vector of all the previous outputs of a transaction (in order of
 * their corresponding inputs).
 */
typedef struct btpk_BlockSpentOutputs btpk_BlockSpentOutputs;

/**
 * Opaque data structure for holding a transaction's spent outputs.
 *
 * Holds the coins consumed by a certain transaction. Retrieved through the
 * @ref btpk_BlockSpentOutputs. The coins are in the same order as the
 * transaction's inputs consuming them.
 */
typedef struct btpk_TransactionSpentOutputs btpk_TransactionSpentOutputs;

/**
 * Opaque data structure for holding a coin.
 *
 * Holds information on the @ref btpk_TransactionOutput held within,
 * including the height it was spent at and whether it is a coinbase output.
 */
typedef struct btpk_Coin btpk_Coin;

/**
 * Opaque data structure for holding a block hash.
 *
 * This is a type-safe identifier for a block.
 */
typedef struct btpk_BlockHash btpk_BlockHash;

/**
 * Opaque data structure for holding a transaction input.
 *
 * Holds information on the @ref btpk_TransactionOutPoint held within.
 */
typedef struct btpk_TransactionInput btpk_TransactionInput;

/**
 * Opaque data structure for holding a transaction out point.
 *
 * Holds the txid and output index it is pointing to.
 */
typedef struct btpk_TransactionOutPoint btpk_TransactionOutPoint;

/**
 * Opaque data structure for holding precomputed transaction data.
 *
 * Reusable when verifying multiple inputs of the same transaction.
 * This avoids recomputing transaction hashes for each input.
 *
 * Required when verifying a taproot input.
 */
typedef struct btpk_PrecomputedTransactionData btpk_PrecomputedTransactionData;

/**
 * Opaque data structure for holding a btpk_Txid.
 *
 * This is a type-safe identifier for a transaction.
 */
typedef struct btpk_Txid btpk_Txid;

/**
 * Opaque data structure for holding a btpk_BlockHeader.
 */
typedef struct btpk_BlockHeader btpk_BlockHeader;

/** Current sync state passed to tip changed callbacks. */
typedef uint8_t btpk_SynchronizationState;
#define btpk_SynchronizationState_INIT_REINDEX ((btpk_SynchronizationState)(0))
#define btpk_SynchronizationState_INIT_DOWNLOAD ((btpk_SynchronizationState)(1))
#define btpk_SynchronizationState_POST_INIT ((btpk_SynchronizationState)(2))

/** Possible warning types issued by validation. */
typedef uint8_t btpk_Warning;
#define btpk_Warning_UNKNOWN_NEW_RULES_ACTIVATED ((btpk_Warning)(0))
#define btpk_Warning_LARGE_WORK_INVALID_CHAIN ((btpk_Warning)(1))

/** Callback function types */

/**
 * Function signature for the global logging callback. All bitplus kernel
 * internal logs will pass through this callback.
 */
typedef void (*btpk_LogCallback)(void* user_data, const char* message, size_t message_len);

/**
 * Function signature for freeing user data.
 */
typedef void (*btpk_DestroyCallback)(void* user_data);

/**
 * Function signatures for the kernel notifications.
 */
typedef void (*btpk_NotifyBlockTip)(void* user_data, btpk_SynchronizationState state, const btpk_BlockTreeEntry* entry, double verification_progress);
typedef void (*btpk_NotifyHeaderTip)(void* user_data, btpk_SynchronizationState state, int64_t height, int64_t timestamp, int presync);
typedef void (*btpk_NotifyProgress)(void* user_data, const char* title, size_t title_len, int progress_percent, int resume_possible);
typedef void (*btpk_NotifyWarningSet)(void* user_data, btpk_Warning warning, const char* message, size_t message_len);
typedef void (*btpk_NotifyWarningUnset)(void* user_data, btpk_Warning warning);
typedef void (*btpk_NotifyFlushError)(void* user_data, const char* message, size_t message_len);
typedef void (*btpk_NotifyFatalError)(void* user_data, const char* message, size_t message_len);

/**
 * Function signatures for the validation interface.
 */
typedef void (*btpk_ValidationInterfaceBlockChecked)(void* user_data, btpk_Block* block, const btpk_BlockValidationState* state);
typedef void (*btpk_ValidationInterfacePoWValidBlock)(void* user_data, btpk_Block* block, const btpk_BlockTreeEntry* entry);
typedef void (*btpk_ValidationInterfaceBlockConnected)(void* user_data, btpk_Block* block, const btpk_BlockTreeEntry* entry);
typedef void (*btpk_ValidationInterfaceBlockDisconnected)(void* user_data, btpk_Block* block, const btpk_BlockTreeEntry* entry);

/**
 * Function signature for serializing data.
 *
 * Returns 0 to indicate success.
 */
typedef int (*btpk_WriteBytes)(const void* bytes, size_t size, void* userdata);

/**
 * Whether a validated data structure is valid, invalid, or an error was
 * encountered during processing.
 */
typedef uint8_t btpk_ValidationMode;
#define btpk_ValidationMode_VALID ((btpk_ValidationMode)(0))
#define btpk_ValidationMode_INVALID ((btpk_ValidationMode)(1))
#define btpk_ValidationMode_INTERNAL_ERROR ((btpk_ValidationMode)(2))

/**
 * A granular "reason" why a block was invalid.
 */
typedef uint32_t btpk_BlockValidationResult;
#define btpk_BlockValidationResult_UNSET ((btpk_BlockValidationResult)(0))           //!< initial value. Block has not yet been rejected
#define btpk_BlockValidationResult_CONSENSUS ((btpk_BlockValidationResult)(1))       //!< invalid by consensus rules (excluding any below reasons)
#define btpk_BlockValidationResult_CACHED_INVALID ((btpk_BlockValidationResult)(2))  //!< this block was cached as being invalid and we didn't store the reason why
#define btpk_BlockValidationResult_INVALID_HEADER ((btpk_BlockValidationResult)(3))  //!< invalid proof of work or time too old
#define btpk_BlockValidationResult_MUTATED ((btpk_BlockValidationResult)(4))         //!< the block's data didn't match the data committed to by the PoW
#define btpk_BlockValidationResult_MISSING_PREV ((btpk_BlockValidationResult)(5))    //!< We don't have the previous block the checked one is built on
#define btpk_BlockValidationResult_INVALID_PREV ((btpk_BlockValidationResult)(6))    //!< A block this one builds on is invalid
#define btpk_BlockValidationResult_TIME_FUTURE ((btpk_BlockValidationResult)(7))     //!< block timestamp was > 2 hours in the future (or our clock is bad)
#define btpk_BlockValidationResult_HEADER_LOW_WORK ((btpk_BlockValidationResult)(8)) //!< the block header may be on a too-little-work chain

/**
 * Holds the validation interface callbacks. The user data pointer may be used
 * to point to user-defined structures to make processing the validation
 * callbacks easier. Note that these callbacks block any further validation
 * execution when they are called.
 */
typedef struct {
    void* user_data;                                              //!< Holds a user-defined opaque structure that is passed to the validation
                                                                  //!< interface callbacks. If user_data_destroy is also defined ownership of the
                                                                  //!< user_data is passed to the created context options and subsequently context.
    btpk_DestroyCallback user_data_destroy;                       //!< Frees the provided user data structure.
    btpk_ValidationInterfaceBlockChecked block_checked;           //!< Called when a new block has been fully validated. Contains the
                                                                  //!< result of its validation.
    btpk_ValidationInterfacePoWValidBlock pow_valid_block;        //!< Called when a new block extends the header chain and has a valid transaction
                                                                  //!< and segwit merkle root.
    btpk_ValidationInterfaceBlockConnected block_connected;       //!< Called when a block is valid and has now been connected to the best chain.
    btpk_ValidationInterfaceBlockDisconnected block_disconnected; //!< Called during a re-org when a block has been removed from the best chain.
} btpk_ValidationInterfaceCallbacks;

/**
 * A struct for holding the kernel notification callbacks. The user data
 * pointer may be used to point to user-defined structures to make processing
 * the notifications easier.
 *
 * If user_data_destroy is provided, the kernel will automatically call this
 * callback to clean up user_data when the notification interface object is destroyed.
 * If user_data_destroy is NULL, it is the user's responsibility to ensure that
 * the user_data outlives the kernel objects. Notifications can
 * occur even as kernel objects are deleted, so care has to be taken to ensure
 * safe unwinding.
 */
typedef struct {
    void* user_data;                        //!< Holds a user-defined opaque structure that is passed to the notification callbacks.
                                            //!< If user_data_destroy is also defined ownership of the user_data is passed to the
                                            //!< created context options and subsequently context.
    btpk_DestroyCallback user_data_destroy; //!< Frees the provided user data structure.
    btpk_NotifyBlockTip block_tip;          //!< The chain's tip was updated to the provided block entry.
    btpk_NotifyHeaderTip header_tip;        //!< A new best block header was added.
    btpk_NotifyProgress progress;           //!< Reports on current block synchronization progress.
    btpk_NotifyWarningSet warning_set;      //!< A warning issued by the kernel library during validation.
    btpk_NotifyWarningUnset warning_unset;  //!< A previous condition leading to the issuance of a warning is no longer given.
    btpk_NotifyFlushError flush_error;      //!< An error encountered when flushing data to disk.
    btpk_NotifyFatalError fatal_error;      //!< An unrecoverable system error encountered by the library.
} btpk_NotificationInterfaceCallbacks;

/**
 * A collection of logging categories that may be encountered by kernel code.
 */
typedef uint8_t btpk_LogCategory;
#define btpk_LogCategory_ALL ((btpk_LogCategory)(0))
#define btpk_LogCategory_BENCH ((btpk_LogCategory)(1))
#define btpk_LogCategory_BLOCKSTORAGE ((btpk_LogCategory)(2))
#define btpk_LogCategory_COINDB ((btpk_LogCategory)(3))
#define btpk_LogCategory_LEVELDB ((btpk_LogCategory)(4))
#define btpk_LogCategory_MEMPOOL ((btpk_LogCategory)(5))
#define btpk_LogCategory_PRUNE ((btpk_LogCategory)(6))
#define btpk_LogCategory_RAND ((btpk_LogCategory)(7))
#define btpk_LogCategory_REINDEX ((btpk_LogCategory)(8))
#define btpk_LogCategory_VALIDATION ((btpk_LogCategory)(9))
#define btpk_LogCategory_KERNEL ((btpk_LogCategory)(10))

/**
 * The level at which logs should be produced.
 */
typedef uint8_t btpk_LogLevel;
#define btpk_LogLevel_TRACE ((btpk_LogLevel)(0))
#define btpk_LogLevel_DEBUG ((btpk_LogLevel)(1))
#define btpk_LogLevel_INFO ((btpk_LogLevel)(2))

/**
 * Options controlling the format of log messages.
 *
 * Set fields as non-zero to indicate true.
 */
typedef struct {
    int log_timestamps;               //!< Prepend a timestamp to log messages.
    int log_time_micros;              //!< Log timestamps in microsecond precision.
    int log_threadnames;              //!< Prepend the name of the thread to log messages.
    int log_sourcelocations;          //!< Prepend the source location to log messages.
    int always_print_category_levels; //!< Prepend the log category and level to log messages.
} btpk_LoggingOptions;

/**
 * A collection of status codes that may be issued by the script verify function.
 */
typedef uint8_t btpk_ScriptVerifyStatus;
#define btpk_ScriptVerifyStatus_OK ((btpk_ScriptVerifyStatus)(0))
#define btpk_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION ((btpk_ScriptVerifyStatus)(1)) //!< The flags were combined in an invalid way.
#define btpk_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED ((btpk_ScriptVerifyStatus)(2))    //!< The taproot flag was set, so valid spent_outputs have to be provided.

/**
 * Script verification flags that may be composed with each other.
 */
typedef uint32_t btpk_ScriptVerificationFlags;
#define btpk_ScriptVerificationFlags_NONE ((btpk_ScriptVerificationFlags)(0))
#define btpk_ScriptVerificationFlags_P2SH ((btpk_ScriptVerificationFlags)(1U << 0))                 //!< evaluate P2SH (BIP16) subscripts
#define btpk_ScriptVerificationFlags_DERSIG ((btpk_ScriptVerificationFlags)(1U << 2))               //!< enforce strict DER (BIP66) compliance
#define btpk_ScriptVerificationFlags_NULLDUMMY ((btpk_ScriptVerificationFlags)(1U << 4))            //!< enforce NULLDUMMY (BIP147)
#define btpk_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY ((btpk_ScriptVerificationFlags)(1U << 9))  //!< enable CHECKLOCKTIMEVERIFY (BIP65)
#define btpk_ScriptVerificationFlags_CHECKSEQUENCEVERIFY ((btpk_ScriptVerificationFlags)(1U << 10)) //!< enable CHECKSEQUENCEVERIFY (BIP112)
#define btpk_ScriptVerificationFlags_WITNESS ((btpk_ScriptVerificationFlags)(1U << 11))             //!< enable WITNESS (BIP141)
#define btpk_ScriptVerificationFlags_TAPROOT ((btpk_ScriptVerificationFlags)(1U << 17))             //!< enable TAPROOT (BIPs 341 & 342)
#define btpk_ScriptVerificationFlags_ALL ((btpk_ScriptVerificationFlags)(btpk_ScriptVerificationFlags_P2SH |                \
                                                                         btpk_ScriptVerificationFlags_DERSIG |              \
                                                                         btpk_ScriptVerificationFlags_NULLDUMMY |           \
                                                                         btpk_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY | \
                                                                         btpk_ScriptVerificationFlags_CHECKSEQUENCEVERIFY | \
                                                                         btpk_ScriptVerificationFlags_WITNESS |             \
                                                                         btpk_ScriptVerificationFlags_TAPROOT))

typedef uint8_t btpk_ChainType;
#define btpk_ChainType_MAINNET ((btpk_ChainType)(0))
#define btpk_ChainType_TESTNET ((btpk_ChainType)(1))
#define btpk_ChainType_TESTNET_4 ((btpk_ChainType)(2))
#define btpk_ChainType_SIGNET ((btpk_ChainType)(3))
#define btpk_ChainType_REGTEST ((btpk_ChainType)(4))

/** @name Transaction
 * Functions for working with transactions.
 */
///@{

/**
 * @brief Create a new transaction from the serialized data.
 *
 * @param[in] raw_transaction     Serialized transaction.
 * @param[in] raw_transaction_len Length of the serialized transaction.
 * @return                        The transaction, or null on error.
 */
BITPLUSKERNEL_API btpk_Transaction* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_create(
    const void* raw_transaction, size_t raw_transaction_len);

/**
 * @brief Copy a transaction. Transactions are reference counted, so this just
 * increments the reference count.
 *
 * @param[in] transaction Non-null.
 * @return                The copied transaction.
 */
BITPLUSKERNEL_API btpk_Transaction* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_copy(
    const btpk_Transaction* transaction) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Serializes the transaction through the passed in callback to bytes.
 * This is consensus serialization that is also used for the P2P network.
 *
 * @param[in] transaction Non-null.
 * @param[in] writer      Non-null, callback to a write bytes function.
 * @param[in] user_data   Holds a user-defined opaque structure that will be
 *                        passed back through the writer callback.
 * @return                0 on success.
 */
BITPLUSKERNEL_API int btpk_transaction_to_bytes(
    const btpk_Transaction* transaction,
    btpk_WriteBytes writer,
    void* user_data) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Get the number of outputs of a transaction.
 *
 * @param[in] transaction Non-null.
 * @return                The number of outputs.
 */
BITPLUSKERNEL_API size_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_count_outputs(
    const btpk_Transaction* transaction) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the transaction outputs at the provided index. The returned
 * transaction output is not owned and depends on the lifetime of the
 * transaction.
 *
 * @param[in] transaction  Non-null.
 * @param[in] output_index The index of the transaction output to be retrieved.
 * @return                 The transaction output
 */
BITPLUSKERNEL_API const btpk_TransactionOutput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_get_output_at(
    const btpk_Transaction* transaction, size_t output_index) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the transaction input at the provided index. The returned
 * transaction input is not owned and depends on the lifetime of the
 * transaction.
 *
 * @param[in] transaction Non-null.
 * @param[in] input_index The index of the transaction input to be retrieved.
 * @return                 The transaction input
 */
BITPLUSKERNEL_API const btpk_TransactionInput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_get_input_at(
    const btpk_Transaction* transaction, size_t input_index) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the number of inputs of a transaction.
 *
 * @param[in] transaction Non-null.
 * @return                The number of inputs.
 */
BITPLUSKERNEL_API size_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_count_inputs(
    const btpk_Transaction* transaction) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get a transaction's nLockTime value.
 *
 * @param[in] transaction Non-null.
 * @return                The nLockTime value.
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_get_locktime(
    const btpk_Transaction* transaction) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the txid of a transaction. The returned txid is not owned and
 * depends on the lifetime of the transaction.
 *
 * @param[in] transaction Non-null.
 * @return                The txid.
 */
BITPLUSKERNEL_API const btpk_Txid* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_get_txid(
    const btpk_Transaction* transaction) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction.
 */
BITPLUSKERNEL_API void btpk_transaction_destroy(btpk_Transaction* transaction);

///@}

/** @name PrecomputedTransactionData
 * Functions for working with precomputed transaction data.
 */
///@{

/**
 * @brief Create precomputed transaction data for script verification.
 *
 * @param[in] tx_to             Non-null.
 * @param[in] spent_outputs     Nullable for non-taproot verification. Points to an array of
 *                              outputs spent by the transaction.
 * @param[in] spent_outputs_len Length of the spent_outputs array.
 * @return                      The precomputed data, or null on error.
 */
BITPLUSKERNEL_API btpk_PrecomputedTransactionData* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_precomputed_transaction_data_create(
    const btpk_Transaction* tx_to,
    const btpk_TransactionOutput** spent_outputs, size_t spent_outputs_len) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Copy precomputed transaction data.
 *
 * @param[in] precomputed_txdata Non-null.
 * @return                       The copied precomputed transaction data.
 */
BITPLUSKERNEL_API btpk_PrecomputedTransactionData* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_precomputed_transaction_data_copy(
    const btpk_PrecomputedTransactionData* precomputed_txdata) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the precomputed transaction data.
 */
BITPLUSKERNEL_API void btpk_precomputed_transaction_data_destroy(btpk_PrecomputedTransactionData* precomputed_txdata);

///@}

/** @name ScriptPubkey
 * Functions for working with script pubkeys.
 */
///@{

/**
 * @brief Create a script pubkey from serialized data.
 * @param[in] script_pubkey     Serialized script pubkey.
 * @param[in] script_pubkey_len Length of the script pubkey data.
 * @return                      The script pubkey.
 */
BITPLUSKERNEL_API btpk_ScriptPubkey* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_script_pubkey_create(
    const void* script_pubkey, size_t script_pubkey_len);

/**
 * @brief Copy a script pubkey.
 *
 * @param[in] script_pubkey Non-null.
 * @return                  The copied script pubkey.
 */
BITPLUSKERNEL_API btpk_ScriptPubkey* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_script_pubkey_copy(
    const btpk_ScriptPubkey* script_pubkey) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Verify if the input at input_index of tx_to spends the script pubkey
 * under the constraints specified by flags. If the
 * `btpk_ScriptVerificationFlags_WITNESS` flag is set in the flags bitfield, the
 * amount parameter is used. If the taproot flag is set, the precomputed data
 * must contain the spent outputs.
 *
 * @param[in] script_pubkey      Non-null, script pubkey to be spent.
 * @param[in] amount             Amount of the script pubkey's associated output. May be zero if
 *                               the witness flag is not set.
 * @param[in] tx_to              Non-null, transaction spending the script_pubkey.
 * @param[in] precomputed_txdata Nullable if the taproot flag is not set. Otherwise, precomputed data
 *                               for tx_to with the spent outputs must be provided.
 * @param[in] input_index        Index of the input in tx_to spending the script_pubkey.
 * @param[in] flags              Bitfield of btpk_ScriptVerificationFlags controlling validation constraints.
 * @param[out] status            Nullable, will be set to an error code if the operation fails, or OK otherwise.
 * @return                       1 if the script is valid, 0 otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_script_pubkey_verify(
    const btpk_ScriptPubkey* script_pubkey,
    int64_t amount,
    const btpk_Transaction* tx_to,
    const btpk_PrecomputedTransactionData* precomputed_txdata,
    unsigned int input_index,
    btpk_ScriptVerificationFlags flags,
    btpk_ScriptVerifyStatus* status) BITPLUSKERNEL_ARG_NONNULL(1, 3);

/**
 * @brief Serializes the script pubkey through the passed in callback to bytes.
 *
 * @param[in] script_pubkey Non-null.
 * @param[in] writer        Non-null, callback to a write bytes function.
 * @param[in] user_data     Holds a user-defined opaque structure that will be
 *                          passed back through the writer callback.
 * @return                  0 on success.
 */
BITPLUSKERNEL_API int btpk_script_pubkey_to_bytes(
    const btpk_ScriptPubkey* script_pubkey,
    btpk_WriteBytes writer,
    void* user_data) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the script pubkey.
 */
BITPLUSKERNEL_API void btpk_script_pubkey_destroy(btpk_ScriptPubkey* script_pubkey);

///@}

/** @name TransactionOutput
 * Functions for working with transaction outputs.
 */
///@{

/**
 * @brief Create a transaction output from a script pubkey and an amount.
 *
 * @param[in] script_pubkey Non-null.
 * @param[in] amount        The amount associated with the script pubkey for this output.
 * @return                  The transaction output.
 */
BITPLUSKERNEL_API btpk_TransactionOutput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_output_create(
    const btpk_ScriptPubkey* script_pubkey,
    int64_t amount) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the script pubkey of the output. The returned
 * script pubkey is not owned and depends on the lifetime of the
 * transaction output.
 *
 * @param[in] transaction_output Non-null.
 * @return                       The script pubkey.
 */
BITPLUSKERNEL_API const btpk_ScriptPubkey* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_output_get_script_pubkey(
    const btpk_TransactionOutput* transaction_output) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the amount in the output.
 *
 * @param[in] transaction_output Non-null.
 * @return                       The amount.
 */
BITPLUSKERNEL_API int64_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_output_get_amount(
    const btpk_TransactionOutput* transaction_output) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 *  @brief Copy a transaction output.
 *
 *  @param[in] transaction_output Non-null.
 *  @return                       The copied transaction output.
 */
BITPLUSKERNEL_API btpk_TransactionOutput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_output_copy(
    const btpk_TransactionOutput* transaction_output) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction output.
 */
BITPLUSKERNEL_API void btpk_transaction_output_destroy(btpk_TransactionOutput* transaction_output);

///@}

/** @name Logging
 * Logging-related functions.
 */
///@{

/**
 * @brief This disables the global internal logger. No log messages will be
 * buffered internally anymore once this is called and the buffer is cleared.
 * This function should only be called once and is not thread or re-entry safe.
 * Log messages will be buffered until this function is called, or a logging
 * connection is created. This must not be called while a logging connection
 * already exists.
 */
BITPLUSKERNEL_API void btpk_logging_disable();

/**
 * @brief Set some options for the global internal logger. This changes global
 * settings and will override settings for all existing @ref
 * btpk_LoggingConnection instances.
 *
 * @param[in] options Sets formatting options of the log messages.
 */
BITPLUSKERNEL_API void btpk_logging_set_options(btpk_LoggingOptions options);

/**
 * @brief Set the log level of the global internal logger. This does not
 * enable the selected categories. Use @ref btpk_logging_enable_category to
 * start logging from a specific, or all categories. This changes a global
 * setting and will override settings for all existing
 * @ref btpk_LoggingConnection instances.
 *
 * @param[in] category If btpk_LogCategory_ALL is chosen, sets both the global fallback log level
 *                     used by all categories that don't have a specific level set, and also
 *                     sets the log level for messages logged with the btpk_LogCategory_ALL category itself.
 *                     For any other category, sets a category-specific log level that overrides
 *                     the global fallback for that category only.

 * @param[in] level    Log level at which the log category is set.
 */
BITPLUSKERNEL_API void btpk_logging_set_level_category(btpk_LogCategory category, btpk_LogLevel level);

/**
 * @brief Enable a specific log category for the global internal logger. This
 * changes a global setting and will override settings for all existing @ref
 * btpk_LoggingConnection instances.
 *
 * @param[in] category If btpk_LogCategory_ALL is chosen, all categories will be enabled.
 */
BITPLUSKERNEL_API void btpk_logging_enable_category(btpk_LogCategory category);

/**
 * @brief Disable a specific log category for the global internal logger. This
 * changes a global setting and will override settings for all existing @ref
 * btpk_LoggingConnection instances.
 *
 * @param[in] category If btpk_LogCategory_ALL is chosen, all categories will be disabled.
 */
BITPLUSKERNEL_API void btpk_logging_disable_category(btpk_LogCategory category);

/**
 * @brief Start logging messages through the provided callback. Log messages
 * produced before this function is first called are buffered and on calling this
 * function are logged immediately.
 *
 * @param[in] log_callback               Non-null, function through which messages will be logged.
 * @param[in] user_data                  Nullable, holds a user-defined opaque structure. Is passed back
 *                                       to the user through the callback. If the user_data_destroy_callback
 *                                       is also defined it is assumed that ownership of the user_data is passed
 *                                       to the created logging connection.
 * @param[in] user_data_destroy_callback Nullable, function for freeing the user data.
 * @return                               A new kernel logging connection, or null on error.
 */
BITPLUSKERNEL_API btpk_LoggingConnection* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_logging_connection_create(
    btpk_LogCallback log_callback,
    void* user_data,
    btpk_DestroyCallback user_data_destroy_callback) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Stop logging and destroy the logging connection.
 */
BITPLUSKERNEL_API void btpk_logging_connection_destroy(btpk_LoggingConnection* logging_connection);

///@}

/** @name ChainParameters
 * Functions for working with chain parameters.
 */
///@{

/**
 * @brief Creates a chain parameters struct with default parameters based on the
 * passed in chain type.
 *
 * @param[in] chain_type Controls the chain parameters type created.
 * @return               An allocated chain parameters opaque struct.
 */
BITPLUSKERNEL_API btpk_ChainParameters* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_parameters_create(
    btpk_ChainType chain_type);

/**
 * Copy the chain parameters.
 */
BITPLUSKERNEL_API btpk_ChainParameters* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_parameters_copy(
    const btpk_ChainParameters* chain_parameters) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get btpk_ConsensusParams from btpk_ChainParameters. The returned
 * btpk_ConsensusParams pointer is valid only for the lifetime of the
 * btpk_ChainParameters object and must not be destroyed by the caller.
 *
 * @param[in] chain_parameters  Non-null.
 * @return                      The btpk_ConsensusParams.
 */
BITPLUSKERNEL_API const btpk_ConsensusParams* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_parameters_get_consensus_params(
    const btpk_ChainParameters* chain_parameters) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the chain parameters.
 */
BITPLUSKERNEL_API void btpk_chain_parameters_destroy(btpk_ChainParameters* chain_parameters);

///@}

/** @name ContextOptions
 * Functions for working with context options.
 */
///@{

/**
 * Creates an empty context options.
 */
BITPLUSKERNEL_API btpk_ContextOptions* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_context_options_create();

/**
 * @brief Sets the chain params for the context options. The context created
 * with the options will be configured for these chain parameters.
 *
 * @param[in] context_options  Non-null, previously created by @ref btpk_context_options_create.
 * @param[in] chain_parameters Is set to the context options.
 */
BITPLUSKERNEL_API void btpk_context_options_set_chainparams(
    btpk_ContextOptions* context_options,
    const btpk_ChainParameters* chain_parameters) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Set the kernel notifications for the context options. The context
 * created with the options will be configured with these notifications.
 *
 * @param[in] context_options Non-null, previously created by @ref btpk_context_options_create.
 * @param[in] notifications   Is set to the context options.
 */
BITPLUSKERNEL_API void btpk_context_options_set_notifications(
    btpk_ContextOptions* context_options,
    btpk_NotificationInterfaceCallbacks notifications) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Set the validation interface callbacks for the context options. The
 * context created with the options will be configured for these validation
 * interface callbacks. The callbacks will then be triggered from validation
 * events issued by the chainstate manager created from the same context.
 *
 * @param[in] context_options                Non-null, previously created with btpk_context_options_create.
 * @param[in] validation_interface_callbacks The callbacks used for passing validation information to the
 *                                           user.
 */
BITPLUSKERNEL_API void btpk_context_options_set_validation_interface(
    btpk_ContextOptions* context_options,
    btpk_ValidationInterfaceCallbacks validation_interface_callbacks) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the context options.
 */
BITPLUSKERNEL_API void btpk_context_options_destroy(btpk_ContextOptions* context_options);

///@}

/** @name Context
 * Functions for working with contexts.
 */
///@{

/**
 * @brief Create a new kernel context. If the options have not been previously
 * set, their corresponding fields will be initialized to default values; the
 * context will assume mainnet chain parameters and won't attempt to call the
 * kernel notification callbacks.
 *
 * @param[in] context_options Nullable, created by @ref btpk_context_options_create.
 * @return                    The allocated context, or null on error.
 */
BITPLUSKERNEL_API btpk_Context* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_context_create(
    const btpk_ContextOptions* context_options);

/**
 * Copy the context.
 */
BITPLUSKERNEL_API btpk_Context* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_context_copy(
    const btpk_Context* context) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Interrupt can be used to halt long-running validation functions like
 * when reindexing, importing or processing blocks.
 *
 * @param[in] context  Non-null.
 * @return             0 if the interrupt was successful, non-zero otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_context_interrupt(
    btpk_Context* context) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the context.
 */
BITPLUSKERNEL_API void btpk_context_destroy(btpk_Context* context);

///@}

/** @name BlockTreeEntry
 * Functions for working with block tree entries.
 */
///@{

/**
 * @brief Returns the previous block tree entry in the tree, or null if the current
 * block tree entry is the genesis block.
 *
 * @param[in] block_tree_entry Non-null.
 * @return                     The previous block tree entry, or null on error or if the current block tree entry is the genesis block.
 */
BITPLUSKERNEL_API const btpk_BlockTreeEntry* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_get_previous(
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Return the btpk_BlockHeader associated with this entry.
 *
 * @param[in] block_tree_entry Non-null.
 * @return                     btpk_BlockHeader.
 */
BITPLUSKERNEL_API btpk_BlockHeader* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_get_block_header(
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Return the height of a certain block tree entry.
 *
 * @param[in] block_tree_entry Non-null.
 * @return                     The block height.
 */
BITPLUSKERNEL_API int32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_get_height(
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Return the block hash associated with a block tree entry.
 *
 * @param[in] block_tree_entry Non-null.
 * @return                     The block hash.
 */
BITPLUSKERNEL_API const btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_get_block_hash(
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Check if two block tree entries are equal. Two block tree entries are equal when they
 * point to the same block.
 *
 * @param[in] entry1 Non-null.
 * @param[in] entry2 Non-null.
 * @return           1 if the block tree entries are equal, 0 otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_equals(
    const btpk_BlockTreeEntry* entry1, const btpk_BlockTreeEntry* entry2) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Return the ancestor of a btpk_BlockTreeEntry at the given height.
 *
 * @param[in] block_tree_entry Non-null.
 * @param[in] height           The height of the requested ancestor.
 * @return                     The ancestor at the given height.
 */
BITPLUSKERNEL_API const btpk_BlockTreeEntry* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_tree_entry_get_ancestor(
    const btpk_BlockTreeEntry* block_tree_entry,
    int32_t height) BITPLUSKERNEL_ARG_NONNULL(1);

///@}

/** @name ChainstateManagerOptions
 * Functions for working with chainstate manager options.
 */
///@{

/**
 * @brief Create options for the chainstate manager.
 *
 * @param[in] context          Non-null, the created options and through it the chainstate manager will
 *                             associate with this kernel context for the duration of their lifetimes.
 * @param[in] data_directory   Non-null, non-empty path string of the directory containing the
 *                             chainstate data. If the directory does not exist yet, it will be
 *                             created.
 * @param[in] blocks_directory Non-null, non-empty path string of the directory containing the block
 *                             data. If the directory does not exist yet, it will be created.
 * @return                     The allocated chainstate manager options, or null on error.
 */
BITPLUSKERNEL_API btpk_ChainstateManagerOptions* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_options_create(
    const btpk_Context* context,
    const char* data_directory,
    size_t data_directory_len,
    const char* blocks_directory,
    size_t blocks_directory_len) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Set the number of available worker threads used during validation.
 *
 * @param[in] chainstate_manager_options Non-null, options to be set.
 * @param[in] worker_threads             The number of worker threads that should be spawned in the thread pool
 *                                       used for validation. When set to 0 no parallel verification is done.
 *                                       The value range is clamped internally between 0 and 15.
 */
BITPLUSKERNEL_API void btpk_chainstate_manager_options_set_worker_threads_num(
    btpk_ChainstateManagerOptions* chainstate_manager_options,
    int worker_threads) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Sets wipe db in the options. In combination with calling
 * @ref btpk_chainstate_manager_import_blocks this triggers either a full reindex,
 * or a reindex of just the chainstate database.
 *
 * @param[in] chainstate_manager_options Non-null, created by @ref btpk_chainstate_manager_options_create.
 * @param[in] wipe_block_tree_db         Set wipe block tree db. Should only be 1 if wipe_chainstate_db is 1 too.
 * @param[in] wipe_chainstate_db         Set wipe chainstate db.
 * @return                               0 if the set was successful, non-zero if the set failed.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_options_set_wipe_dbs(
    btpk_ChainstateManagerOptions* chainstate_manager_options,
    int wipe_block_tree_db,
    int wipe_chainstate_db) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Sets block tree db in memory in the options.
 *
 * @param[in] chainstate_manager_options   Non-null, created by @ref btpk_chainstate_manager_options_create.
 * @param[in] block_tree_db_in_memory      Set block tree db in memory.
 */
BITPLUSKERNEL_API void btpk_chainstate_manager_options_update_block_tree_db_in_memory(
    btpk_ChainstateManagerOptions* chainstate_manager_options,
    int block_tree_db_in_memory) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Sets chainstate db in memory in the options.
 *
 * @param[in] chainstate_manager_options Non-null, created by @ref btpk_chainstate_manager_options_create.
 * @param[in] chainstate_db_in_memory    Set chainstate db in memory.
 */
BITPLUSKERNEL_API void btpk_chainstate_manager_options_update_chainstate_db_in_memory(
    btpk_ChainstateManagerOptions* chainstate_manager_options,
    int chainstate_db_in_memory) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the chainstate manager options.
 */
BITPLUSKERNEL_API void btpk_chainstate_manager_options_destroy(btpk_ChainstateManagerOptions* chainstate_manager_options);

///@}

/** @name ChainstateManager
 * Functions for chainstate management.
 */
///@{

/**
 * @brief Create a chainstate manager. This is the main object for many
 * validation tasks as well as for retrieving data from the chain and
 * interacting with its chainstate and indexes.
 *
 * @param[in] chainstate_manager_options Non-null, created by @ref btpk_chainstate_manager_options_create.
 * @return                               The allocated chainstate manager, or null on error.
 */
BITPLUSKERNEL_API btpk_ChainstateManager* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_create(
    const btpk_ChainstateManagerOptions* chainstate_manager_options) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the btpk_BlockTreeEntry whose associated btpk_BlockHeader has the most
 * known cumulative proof of work.
 *
 * @param[in] chainstate_manager Non-null.
 * @return                       The btpk_BlockTreeEntry.
 */
BITPLUSKERNEL_API const btpk_BlockTreeEntry* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_get_best_entry(
    const btpk_ChainstateManager* chainstate_manager) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Processes and validates the provided btpk_BlockHeader.
 *
 * @param[in] chainstate_manager        Non-null.
 * @param[in] header                    Non-null btpk_BlockHeader to be validated.
 * @param[out] block_validation_state   The result of the btpk_BlockHeader validation.
 * @return                              0 if btpk_BlockHeader processing completed successfully, non-zero on error.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_process_block_header(
    btpk_ChainstateManager* chainstate_manager,
    const btpk_BlockHeader* header,
    btpk_BlockValidationState* block_validation_state) BITPLUSKERNEL_ARG_NONNULL(1, 2, 3);

/**
 * @brief Triggers the start of a reindex if the wipe options were previously
 * set for the chainstate manager. Can also import an array of existing block
 * files selected by the user.
 *
 * @param[in] chainstate_manager        Non-null.
 * @param[in] block_file_paths_data     Nullable, array of block files described by their full filesystem paths.
 * @param[in] block_file_paths_lens     Nullable, array containing the lengths of each of the paths.
 * @param[in] block_file_paths_data_len Length of the block_file_paths_data and block_file_paths_len arrays.
 * @return                              0 if the import blocks call was completed successfully, non-zero otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_import_blocks(
    btpk_ChainstateManager* chainstate_manager,
    const char** block_file_paths_data, size_t* block_file_paths_lens,
    size_t block_file_paths_data_len) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Process and validate the passed in block with the chainstate
 * manager. Processing first does checks on the block, and if these passed,
 * saves it to disk. It then validates the block against the utxo set. If it is
 * valid, the chain is extended with it. The return value is not indicative of
 * the block's validity. Detailed information on the validity of the block can
 * be retrieved by registering the `block_checked` callback in the validation
 * interface.
 *
 * @param[in] chainstate_manager Non-null.
 * @param[in] block              Non-null, block to be validated.
 *
 * @param[out] new_block         Nullable, will be set to 1 if this block was not processed before. Note that this means it
 *                               might also not be 1 if processing was attempted before, but the block was found invalid
 *                               before its data was persisted.
 * @return                       0 if processing the block was successful. Will also return 0 for valid, but duplicate blocks.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_process_block(
    btpk_ChainstateManager* chainstate_manager,
    const btpk_Block* block,
    int* new_block) BITPLUSKERNEL_ARG_NONNULL(1, 2, 3);

/**
 * @brief Returns the best known currently active chain. Its lifetime is
 * dependent on the chainstate manager. It can be thought of as a view on a
 * vector of block tree entries that form the best chain. The returned chain
 * reference always points to the currently active best chain. However, state
 * transitions within the chainstate manager (e.g., processing blocks) will
 * update the chain's contents. Data retrieved from this chain is only
 * consistent up to the point when new data is processed in the chainstate
 * manager. It is the user's responsibility to guard against these
 * inconsistencies.
 *
 * @param[in] chainstate_manager Non-null.
 * @return                       The chain.
 */
BITPLUSKERNEL_API const btpk_Chain* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_get_active_chain(
    const btpk_ChainstateManager* chainstate_manager) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Retrieve a block tree entry by its block hash.
 *
 * @param[in] chainstate_manager Non-null.
 * @param[in] block_hash         Non-null.
 * @return                       The block tree entry of the block with the passed in hash, or null if
 *                               the block hash is not found.
 */
BITPLUSKERNEL_API const btpk_BlockTreeEntry* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chainstate_manager_get_block_tree_entry_by_hash(
    const btpk_ChainstateManager* chainstate_manager,
    const btpk_BlockHash* block_hash) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the chainstate manager.
 */
BITPLUSKERNEL_API void btpk_chainstate_manager_destroy(btpk_ChainstateManager* chainstate_manager);

///@}

/** @name Block
 * Functions for working with blocks.
 */
///@{

/**
 * @brief Reads the block the passed in block tree entry points to from disk and
 * returns it.
 *
 * @param[in] chainstate_manager Non-null.
 * @param[in] block_tree_entry   Non-null.
 * @return                       The read out block, or null on error.
 */
BITPLUSKERNEL_API btpk_Block* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_read(
    const btpk_ChainstateManager* chainstate_manager,
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Parse a serialized raw block into a new block object.
 *
 * @param[in] raw_block     Serialized block.
 * @param[in] raw_block_len Length of the serialized block.
 * @return                  The allocated block, or null on error.
 */
BITPLUSKERNEL_API btpk_Block* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_create(
    const void* raw_block, size_t raw_block_len);

/**
 * @brief Copy a block. Blocks are reference counted, so this just increments
 * the reference count.
 *
 * @param[in] block Non-null.
 * @return          The copied block.
 */
BITPLUSKERNEL_API btpk_Block* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_copy(
    const btpk_Block* block) BITPLUSKERNEL_ARG_NONNULL(1);

/** Bitflags to control context-free block checks (optional). */
typedef uint32_t btpk_BlockCheckFlags;
#define btpk_BlockCheckFlags_BASE   ((btpk_BlockCheckFlags)0)                                                        //!< run the base context-free block checks only
#define btpk_BlockCheckFlags_POW    ((btpk_BlockCheckFlags)(1U << 0))                                                //!< run CheckProofOfWork via CheckBlockHeader
#define btpk_BlockCheckFlags_MERKLE ((btpk_BlockCheckFlags)(1U << 1))                                                //!< verify merkle root (and mutation detection)
#define btpk_BlockCheckFlags_ALL    ((btpk_BlockCheckFlags)(btpk_BlockCheckFlags_POW | btpk_BlockCheckFlags_MERKLE)) //!< enable all optional context-free block checks

/**
 * @brief Perform context-free validation checks on a btpk_Block.
 *
 * Runs the base context-free block checks (size limits, coinbase structure,
 * transaction checks, and sigop limits) using the supplied
 * btpk_ConsensusParams. The proof-of-work and merkle-root checks are optional
 * and can be toggled via @p flags. Note that this does not include any
 * transaction script, timestamps, order, or other checks that may require more
 * context.
 *
 * @param[in]     block             Non-null, btpk_Block to validate.
 * @param[in]     consensus_params  Non-null, btpk_ConsensusParams for validation.
 * @param[in]     flags             Bitmask of btpk_BlockCheckFlags controlling the
 *                                  optional POW and merkle-root checks. Use
 *                                  btpk_BlockCheckFlags_BASE to run only the base
 *                                  checks.
 * @param[in,out] validation_state  Non-null, previously created with
 *                                  btpk_block_validation_state_create and updated
 *                                  in-place with the validation result.
 * @return                          1 if the btpk_Block passed the checks, 0 otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_check(
    const btpk_Block* block,
    const btpk_ConsensusParams* consensus_params,
    btpk_BlockCheckFlags flags,
    btpk_BlockValidationState* validation_state) BITPLUSKERNEL_ARG_NONNULL(1, 2, 4);

/**
 * @brief Count the number of transactions contained in a block.
 *
 * @param[in] block Non-null.
 * @return          The number of transactions in the block.
 */
BITPLUSKERNEL_API size_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_count_transactions(
    const btpk_Block* block) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the transaction at the provided index. The returned transaction
 * is not owned and depends on the lifetime of the block.
 *
 * @param[in] block             Non-null.
 * @param[in] transaction_index The index of the transaction to be retrieved.
 * @return                      The transaction.
 */
BITPLUSKERNEL_API const btpk_Transaction* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_get_transaction_at(
    const btpk_Block* block, size_t transaction_index) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the btpk_BlockHeader from the block.
 *
 * Creates a new btpk_BlockHeader object from the block's header data.
 *
 * @param[in] block Non-null btpk_Block
 * @return          btpk_BlockHeader.
 */
BITPLUSKERNEL_API btpk_BlockHeader* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_get_header(
    const btpk_Block* block) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Calculate and return the hash of a block.
 *
 * @param[in] block Non-null.
 * @return    The block hash.
 */
BITPLUSKERNEL_API btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_get_hash(
    const btpk_Block* block) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Serializes the block through the passed in callback to bytes.
 * This is consensus serialization that is also used for the P2P network.
 *
 * @param[in] block     Non-null.
 * @param[in] writer    Non-null, callback to a write bytes function.
 * @param[in] user_data Holds a user-defined opaque structure that will be
 *                      passed back through the writer callback.
 * @return              0 on success.
 */
BITPLUSKERNEL_API int btpk_block_to_bytes(
    const btpk_Block* block,
    btpk_WriteBytes writer,
    void* user_data) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the block.
 */
BITPLUSKERNEL_API void btpk_block_destroy(btpk_Block* block);

///@}

/** @name BlockValidationState
 * Functions for working with block validation states.
 */
///@{

/**
 * Create a new btpk_BlockValidationState.
 */
BITPLUSKERNEL_API btpk_BlockValidationState* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_validation_state_create();

/**
 * Returns the validation mode from an opaque btpk_BlockValidationState pointer.
 */
BITPLUSKERNEL_API btpk_ValidationMode btpk_block_validation_state_get_validation_mode(
    const btpk_BlockValidationState* block_validation_state) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Returns the validation result from an opaque btpk_BlockValidationState pointer.
 */
BITPLUSKERNEL_API btpk_BlockValidationResult btpk_block_validation_state_get_block_validation_result(
    const btpk_BlockValidationState* block_validation_state) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Copies the btpk_BlockValidationState.
 *
 * @param[in] block_validation_state Non-null.
 * @return                           The copied btpk_BlockValidationState.
 */
BITPLUSKERNEL_API btpk_BlockValidationState* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_validation_state_copy(
    const btpk_BlockValidationState* block_validation_state) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the btpk_BlockValidationState.
 */
BITPLUSKERNEL_API void btpk_block_validation_state_destroy(
    btpk_BlockValidationState* block_validation_state);

///@}

/** @name Chain
 * Functions for working with the chain
 */
///@{

/**
 * @brief Return the height of the tip of the chain.
 *
 * @param[in] chain Non-null.
 * @return          The current height.
 */
BITPLUSKERNEL_API int32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_get_height(
    const btpk_Chain* chain) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Retrieve a block tree entry by its height in the currently active chain.
 * Once retrieved there is no guarantee that it remains in the active chain.
 *
 * @param[in] chain        Non-null.
 * @param[in] block_height Height in the chain of the to be retrieved block tree entry.
 * @return                 The block tree entry at a certain height in the currently active chain, or null
 *                         if the height is out of bounds.
 */
BITPLUSKERNEL_API const btpk_BlockTreeEntry* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_get_by_height(
    const btpk_Chain* chain,
    int32_t block_height) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Return true if the passed in chain contains the block tree entry.
 *
 * @param[in] chain            Non-null.
 * @param[in] block_tree_entry Non-null.
 * @return                     1 if the block_tree_entry is in the chain, 0 otherwise.
 *
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_chain_contains(
    const btpk_Chain* chain,
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1, 2);

///@}

/** @name BlockSpentOutputs
 * Functions for working with block spent outputs.
 */
///@{

/**
 * @brief Reads the block spent coins data the passed in block tree entry points to from
 * disk and returns it.
 *
 * @param[in] chainstate_manager Non-null.
 * @param[in] block_tree_entry   Non-null.
 * @return                       The read out block spent outputs, or null on error.
 */
BITPLUSKERNEL_API btpk_BlockSpentOutputs* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_spent_outputs_read(
    const btpk_ChainstateManager* chainstate_manager,
    const btpk_BlockTreeEntry* block_tree_entry) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Copy a block's spent outputs.
 *
 * @param[in] block_spent_outputs Non-null.
 * @return                        The copied block spent outputs.
 */
BITPLUSKERNEL_API btpk_BlockSpentOutputs* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_spent_outputs_copy(
    const btpk_BlockSpentOutputs* block_spent_outputs) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns the number of transaction spent outputs whose data is contained in
 * block spent outputs.
 *
 * @param[in] block_spent_outputs Non-null.
 * @return                        The number of transaction spent outputs data in the block spent outputs.
 */
BITPLUSKERNEL_API size_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_spent_outputs_count(
    const btpk_BlockSpentOutputs* block_spent_outputs) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns a transaction spent outputs contained in the block spent
 * outputs at a certain index. The returned pointer is unowned and only valid
 * for the lifetime of block_spent_outputs.
 *
 * @param[in] block_spent_outputs             Non-null.
 * @param[in] transaction_spent_outputs_index The index of the transaction spent outputs within the block spent outputs.
 * @return                                    A transaction spent outputs pointer.
 */
BITPLUSKERNEL_API const btpk_TransactionSpentOutputs* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_spent_outputs_get_transaction_spent_outputs_at(
    const btpk_BlockSpentOutputs* block_spent_outputs,
    size_t transaction_spent_outputs_index) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the block spent outputs.
 */
BITPLUSKERNEL_API void btpk_block_spent_outputs_destroy(btpk_BlockSpentOutputs* block_spent_outputs);

///@}

/** @name TransactionSpentOutputs
 * Functions for working with the spent coins of a transaction
 */
///@{

/**
 * @brief Copy a transaction's spent outputs.
 *
 * @param[in] transaction_spent_outputs Non-null.
 * @return                              The copied transaction spent outputs.
 */
BITPLUSKERNEL_API btpk_TransactionSpentOutputs* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_spent_outputs_copy(
    const btpk_TransactionSpentOutputs* transaction_spent_outputs) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns the number of previous transaction outputs contained in the
 * transaction spent outputs data.
 *
 * @param[in] transaction_spent_outputs Non-null
 * @return                              The number of spent transaction outputs for the transaction.
 */
BITPLUSKERNEL_API size_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_spent_outputs_count(
    const btpk_TransactionSpentOutputs* transaction_spent_outputs) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns a coin contained in the transaction spent outputs at a
 * certain index. The returned pointer is unowned and only valid for the
 * lifetime of transaction_spent_outputs.
 *
 * @param[in] transaction_spent_outputs Non-null.
 * @param[in] coin_index                The index of the to be retrieved coin within the
 *                                      transaction spent outputs.
 * @return                              A coin pointer.
 */
BITPLUSKERNEL_API const btpk_Coin* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_spent_outputs_get_coin_at(
    const btpk_TransactionSpentOutputs* transaction_spent_outputs,
    size_t coin_index) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction spent outputs.
 */
BITPLUSKERNEL_API void btpk_transaction_spent_outputs_destroy(btpk_TransactionSpentOutputs* transaction_spent_outputs);

///@}

/** @name Transaction Input
 * Functions for working with transaction inputs.
 */
///@{

/**
 * @brief Copy a transaction input.
 *
 * @param[in] transaction_input Non-null.
 * @return                      The copied transaction input.
 */
BITPLUSKERNEL_API btpk_TransactionInput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_input_copy(
    const btpk_TransactionInput* transaction_input) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the transaction out point. The returned transaction out point is
 * not owned and depends on the lifetime of the transaction.
 *
 * @param[in] transaction_input Non-null.
 * @return                      The transaction out point.
 */
BITPLUSKERNEL_API const btpk_TransactionOutPoint* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_input_get_out_point(
    const btpk_TransactionInput* transaction_input) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get a transaction input's nSequence value.
 *
 * @param[in] transaction_input Non-null.
 * @return                      The nSequence value.
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_input_get_sequence(
    const btpk_TransactionInput* transaction_input) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction input.
 */
BITPLUSKERNEL_API void btpk_transaction_input_destroy(btpk_TransactionInput* transaction_input);

///@}

/** @name Transaction Out Point
 * Functions for working with transaction out points.
 */
///@{

/**
 * @brief Copy a transaction out point.
 *
 * @param[in] transaction_out_point Non-null.
 * @return                          The copied transaction out point.
 */
BITPLUSKERNEL_API btpk_TransactionOutPoint* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_out_point_copy(
    const btpk_TransactionOutPoint* transaction_out_point) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the output position from the transaction out point.
 *
 * @param[in] transaction_out_point Non-null.
 * @return                          The output index.
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_out_point_get_index(
    const btpk_TransactionOutPoint* transaction_out_point) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the txid from the transaction out point. The returned txid is
 * not owned and depends on the lifetime of the transaction out point.
 *
 * @param[in] transaction_out_point Non-null.
 * @return                          The txid.
 */
BITPLUSKERNEL_API const btpk_Txid* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_transaction_out_point_get_txid(
    const btpk_TransactionOutPoint* transaction_out_point) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction out point.
 */
BITPLUSKERNEL_API void btpk_transaction_out_point_destroy(btpk_TransactionOutPoint* transaction_out_point);

///@}

/** @name Txid
 * Functions for working with txids.
 */
///@{

/**
 * @brief Copy a txid.
 *
 * @param[in] txid Non-null.
 * @return         The copied txid.
 */
BITPLUSKERNEL_API btpk_Txid* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_txid_copy(
    const btpk_Txid* txid) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Check if two txids are equal.
 *
 * @param[in] txid1 Non-null.
 * @param[in] txid2 Non-null.
 * @return          0 if the txid is not equal.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_txid_equals(
    const btpk_Txid* txid1, const btpk_Txid* txid2) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Serializes the txid to bytes.
 *
 * @param[in] txid    Non-null.
 * @param[out] output The serialized txid.
 */
BITPLUSKERNEL_API void btpk_txid_to_bytes(
    const btpk_Txid* txid, unsigned char output[32]) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the txid.
 */
BITPLUSKERNEL_API void btpk_txid_destroy(btpk_Txid* txid);

///@}

/** @name Coin
 * Functions for working with coins.
 */
///@{

/**
 * @brief Copy a coin.
 *
 * @param[in] coin Non-null.
 * @return         The copied coin.
 */
BITPLUSKERNEL_API btpk_Coin* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_coin_copy(
    const btpk_Coin* coin) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns the block height where the transaction that
 * created this coin was included in.
 *
 * @param[in] coin Non-null.
 * @return         The block height of the coin.
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_coin_confirmation_height(
    const btpk_Coin* coin) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Returns whether the containing transaction was a coinbase.
 *
 * @param[in] coin Non-null.
 * @return         1 if the coin is a coinbase coin, 0 otherwise.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_coin_is_coinbase(
    const btpk_Coin* coin) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Return the transaction output of a coin. The returned pointer is
 * unowned and only valid for the lifetime of the coin.
 *
 * @param[in] coin Non-null.
 * @return         A transaction output pointer.
 */
BITPLUSKERNEL_API const btpk_TransactionOutput* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_coin_get_output(
    const btpk_Coin* coin) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * Destroy the coin.
 */
BITPLUSKERNEL_API void btpk_coin_destroy(btpk_Coin* coin);

///@}

/** @name BlockHash
 * Functions for working with block hashes.
 */
///@{

/**
 * @brief Create a block hash from its raw data.
 */
BITPLUSKERNEL_API btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_hash_create(
    const unsigned char block_hash[32]) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Check if two block hashes are equal.
 *
 * @param[in] hash1 Non-null.
 * @param[in] hash2 Non-null.
 * @return          0 if the block hashes are not equal.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_hash_equals(
    const btpk_BlockHash* hash1, const btpk_BlockHash* hash2) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Copy a block hash.
 *
 * @param[in] block_hash Non-null.
 * @return               The copied block hash.
 */
BITPLUSKERNEL_API btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_hash_copy(
    const btpk_BlockHash* block_hash) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Serializes the block hash to bytes.
 *
 * @param[in] block_hash     Non-null.
 * @param[in] output         The serialized block hash.
 */
BITPLUSKERNEL_API void btpk_block_hash_to_bytes(
    const btpk_BlockHash* block_hash, unsigned char output[32]) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the block hash.
 */
BITPLUSKERNEL_API void btpk_block_hash_destroy(btpk_BlockHash* block_hash);

///@}

/**
 * @name Block Header
 * Functions for working with block headers.
 */
///@{

/**
 * @brief Create a btpk_BlockHeader from serialized data.
 *
 * @param[in] raw_block_header      Non-null, serialized header data (80 bytes)
 * @param[in] raw_block_header_len  Length of serialized header (must be 80)
 * @return                          btpk_BlockHeader, or null on error.
 */
BITPLUSKERNEL_API btpk_BlockHeader* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_create(
    const void* raw_block_header, size_t raw_block_header_len);

/**
 * @brief Copy a btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader.
 * @return              Copied btpk_BlockHeader.
 */
BITPLUSKERNEL_API btpk_BlockHeader* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_copy(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the btpk_BlockHash.
 *
 * @param[in] header    Non-null header
 * @return              btpk_BlockHash.
 */
BITPLUSKERNEL_API btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_hash(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the previous btpk_BlockHash from btpk_BlockHeader. The returned hash
 * is unowned and only valid for the lifetime of the btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader
 * @return              Previous btpk_BlockHash
 */
BITPLUSKERNEL_API const btpk_BlockHash* BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_prev_hash(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the timestamp from btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader
 * @return              Block timestamp (Unix epoch seconds)
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_timestamp(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the nBits difficulty target from btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader
 * @return              Difficulty target (compact format)
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_bits(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the version from btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader
 * @return              Block version
 */
BITPLUSKERNEL_API int32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_version(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the nonce from btpk_BlockHeader.
 *
 * @param[in] header    Non-null btpk_BlockHeader
 * @return              Nonce
 */
BITPLUSKERNEL_API uint32_t BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_get_nonce(
    const btpk_BlockHeader* header) BITPLUSKERNEL_ARG_NONNULL(1);

/**
 * @brief Serializes the btpk_BlockHeader to bytes.
 * This is consensus serialization that is also used for the P2P network.
 *
 * @param[in] header    Non-null.
 * @param[out] output   The serialized block header (80 bytes).
 * @return              0 on success.
 */
BITPLUSKERNEL_API int BITPLUSKERNEL_WARN_UNUSED_RESULT btpk_block_header_to_bytes(
    const btpk_BlockHeader* header, unsigned char output[80]) BITPLUSKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the btpk_BlockHeader.
 */
BITPLUSKERNEL_API void btpk_block_header_destroy(btpk_BlockHeader* header);

///@}

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITPLUS_KERNEL_BITPLUSKERNEL_H
