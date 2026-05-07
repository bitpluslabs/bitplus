# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *libbitplus_cli*         | RPC client functionality used by *bitplus-cli* executable |
| *libbitplus_common*      | Home for common functionality shared by different executables and libraries. Similar to *libbitplus_util*, but higher-level (see [Dependencies](#dependencies)). |
| *libbitplus_consensus*   | Consensus functionality used by *libbitplus_node* and *libbitplus_wallet*. |
| *libbitplus_crypto*      | Hardware-optimized functions for data encryption, hashing, message authentication, and key derivation. |
| *libbitplus_kernel*      | Consensus engine and support library used for validation by *libbitplus_node*. |
| *libbitplusqt*           | GUI functionality used by *bitplus-qt* and *bitplus-gui* executables. |
| *libbitplus_ipc*         | IPC functionality used by *bitplus-node* and *bitplus-gui* executables to communicate when [`-DENABLE_IPC=ON`](multiprocess.md) is used. |
| *libbitplus_node*        | P2P and RPC server functionality used by *bitplusd* and *bitplus-qt* executables. |
| *libbitplus_util*        | Home for common functionality shared by different executables and libraries. Similar to *libbitplus_common*, but lower-level (see [Dependencies](#dependencies)). |
| *libbitplus_wallet*      | Wallet functionality used by *bitplusd* and *bitplus-wallet* executables. |
| *libbitplus_wallet_tool* | Lower-level wallet functionality used by *bitplus-wallet* executable. |
| *libbitplus_zmq*         | [ZeroMQ](../zmq.md) functionality used by *bitplusd* and *bitplus-qt* executables. |

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies. An exception is *libbitplus_kernel*, which, at some future point, will have a documented external interface.

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`add_library(bitplus_* ...)`](../../src/CMakeLists.txt) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *libbitplus_node* code lives in `src/node/` in the `node::` namespace
  - *libbitplus_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *libbitplus_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *libbitplus_util* code lives in `src/util/` in the `util::` namespace
  - *libbitplus_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "basis" }}}%%

graph TD;

bitplus-cli[bitplus-cli]-->libbitplus_cli;

bitplusd[bitplusd]-->libbitplus_node;
bitplusd[bitplusd]-->libbitplus_wallet;

bitplus-qt[bitplus-qt]-->libbitplus_node;
bitplus-qt[bitplus-qt]-->libbitplusqt;
bitplus-qt[bitplus-qt]-->libbitplus_wallet;

bitplus-wallet[bitplus-wallet]-->libbitplus_wallet;
bitplus-wallet[bitplus-wallet]-->libbitplus_wallet_tool;

libbitplus_cli-->libbitplus_util;
libbitplus_cli-->libbitplus_common;

libbitplus_consensus-->libbitplus_crypto;

libbitplus_common-->libbitplus_consensus;
libbitplus_common-->libbitplus_crypto;
libbitplus_common-->libbitplus_util;

libbitplus_kernel-->libbitplus_consensus;
libbitplus_kernel-->libbitplus_crypto;
libbitplus_kernel-->libbitplus_util;

libbitplus_node-->libbitplus_consensus;
libbitplus_node-->libbitplus_crypto;
libbitplus_node-->libbitplus_kernel;
libbitplus_node-->libbitplus_common;
libbitplus_node-->libbitplus_util;

libbitplusqt-->libbitplus_common;
libbitplusqt-->libbitplus_util;

libbitplus_util-->libbitplus_crypto;

libbitplus_wallet-->libbitplus_common;
libbitplus_wallet-->libbitplus_crypto;
libbitplus_wallet-->libbitplus_util;

libbitplus_wallet_tool-->libbitplus_wallet;
libbitplus_wallet_tool-->libbitplus_util;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class bitplus-qt,bitplusd,bitplus-cli,bitplus-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Crypto* lib depends on nothing. *Util* lib is depended on by everything. *Kernel* lib depends only on consensus, crypto, and util.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *libbitplus_wallet* and *libbitplus_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *libbitplus_crypto* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *libbitplus_consensus* should only depend on *libbitplus_crypto*, and all other libraries besides *libbitplus_crypto* should be allowed to depend on it.

- *libbitplus_util* should be a standalone dependency that any library can depend on, and it should not depend on other libraries except *libbitplus_crypto*. It provides basic utilities that fill in gaps in the C++ standard library and provide lightweight abstractions over platform-specific features. Since the util library is distributed with the kernel and is usable by kernel applications, it shouldn't contain functions that external code shouldn't call, like higher level code targeted at the node or wallet. (*libbitplus_common* is a better place for higher level code, or code that is meant to be used by internal applications only.)

- *libbitplus_common* is a home for miscellaneous shared code used by different Bitplus Core applications. It should not depend on anything other than *libbitplus_util*, *libbitplus_consensus*, and *libbitplus_crypto*.

- *libbitplus_kernel* should only depend on *libbitplus_util*, *libbitplus_consensus*, and *libbitplus_crypto*.

- The only thing that should depend on *libbitplus_kernel* internally should be *libbitplus_node*. GUI and wallet libraries *libbitplusqt* and *libbitplus_wallet* in particular should not depend on *libbitplus_kernel* and the unneeded functionality it would pull in, like block validation. To the extent that GUI and wallet code need scripting and signing functionality, they should be able to get it from *libbitplus_consensus*, *libbitplus_common*, *libbitplus_crypto*, and *libbitplus_util*, instead of *libbitplus_kernel*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *libbitplusqt*, *libbitplus_node*, *libbitplus_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](../../src/interfaces/) abstract interfaces.

## Work in progress

- Validation code is moving from *libbitplus_node* to *libbitplus_kernel* as part of [The libbitpluskernel Project #27587](https://github.com/bitplus/bitplus/issues/27587)
