# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(test_bitcoin-qt
  apptests.cpp
  clientmodeltests.cpp
  modaloverlaytests.cpp
  optiontests.cpp
  rpcnestedtests.cpp
  test_main.cpp
  uritests.cpp
  util.cpp
  ../../init/bitcoin-qt.cpp
)
set_target_properties(test_bitcoin-qt PROPERTIES OUTPUT_NAME test_qbit-qt)

target_link_libraries(test_bitcoin-qt
  core_interface
  bitcoinqt
  test_util
  bitcoin_node
  Boost::headers
  Qt6::Test
)

import_plugins(test_bitcoin-qt)

if(ENABLE_WALLET)
  target_sources(test_bitcoin-qt
    PRIVATE
      addressbooktests.cpp
      wallettests.cpp
      ../../wallet/test/wallet_test_fixture.cpp
  )
  target_link_libraries(test_bitcoin-qt bitcoin_wallet)
endif()

add_test(NAME test_qbit-qt
  COMMAND test_bitcoin-qt
)
set(qt_test_environment
  "QTEST_FUNCTION_TIMEOUT=600000"
)
if(WIN32 AND VCPKG_TARGET_TRIPLET)
  # Use a headless Qt platform for Windows vcpkg builds. Blacksmith Windows
  # runners do not provide all WinRT registrations needed by the windows plugin.
  list(APPEND qt_test_environment "QT_QPA_PLATFORM=offscreen")
endif()
set_tests_properties(test_qbit-qt PROPERTIES
  ENVIRONMENT "${qt_test_environment}"
)

install_binary_component(test_bitcoin-qt INTERNAL)
