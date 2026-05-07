Bitplus Core
=============

Setup
---------------------
Bitplus Core is the original Bitplus client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Bitplus transactions, which requires several hundred gigabytes or more of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to several days or more.

To download Bitplus Core, visit [bitpluscore.org](https://bitpluscore.org/en/download/).

Running
---------------------
The following are some helpful notes on how to run Bitplus Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/bitplus-qt` (GUI) or
- `bin/bitplusd` (headless)
- `bin/bitplus` (wrapper command)

The `bitplus` command supports subcommands like `bitplus gui`, `bitplus node`, and `bitplus rpc` exposing different functionality. Subcommands can be listed with `bitplus help`.

### Windows

Unpack the files into a directory, and then run bitplus-qt.exe.

### macOS

Drag Bitplus Core to your applications folder, and then run Bitplus Core.

### Need Help?

* See the documentation at the [Bitplus Wiki](https://en.bitplus.it/wiki/Main_Page)
for help and more information.
* Ask for help on [Bitplus StackExchange](https://bitplus.stackexchange.com).
* Ask for help on #bitplus on Libera Chat. If you don't have an IRC client, you can use [web.libera.chat](https://web.libera.chat/#bitplus).
* Ask for help on the [BitplusTalk](https://bitplustalk.org/) forums, in the [Technical Support board](https://bitplustalk.org/index.php?board=4.0).

Building
---------------------
The following are developer notes on how to build Bitplus Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

Development
---------------------
The Bitplus repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.bitpluscore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Discuss on the [BitplusTalk](https://bitplustalk.org/) forums, in the [Development & Technical Discussion board](https://bitplustalk.org/index.php?board=6.0).
* Discuss project-specific development on #bitplus-core-dev on Libera Chat. If you don't have an IRC client, you can use [web.libera.chat](https://web.libera.chat/#bitplus-core-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitplus.conf Configuration File](bitplus-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
