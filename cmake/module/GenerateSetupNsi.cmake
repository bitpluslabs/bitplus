# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  set(CLIENT_TARNAME "bitplus")
  set(BITPLUS_WRAPPER_NAME "bitplus")
  set(BITPLUS_GUI_NAME "bitplus-qt")
  set(BITPLUS_DAEMON_NAME "bitplusd")
  set(BITPLUS_CLI_NAME "bitplus-cli")
  set(BITPLUS_TX_NAME "bitplus-tx")
  set(BITPLUS_WALLET_TOOL_NAME "bitplus-wallet")
  set(BITPLUS_TEST_NAME "test_bitplus")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in ${PROJECT_BINARY_DIR}/bitplus-win64-setup.nsi USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
