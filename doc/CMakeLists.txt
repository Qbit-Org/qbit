# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

find_package(Doxygen COMPONENTS dot)
include(GNUInstallDirs)

if(DOXYGEN_FOUND)
  set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
  configure_file(Doxyfile.in ${doxyfile} USE_SOURCE_PERMISSIONS)

  # In CMake 3.27, The FindDoxygen module's doxygen_add_docs()
  # command gained a CONFIG_FILE option to specify a custom doxygen
  # configuration file.
  # TODO: Consider using it.
  add_custom_target(docs
    COMMAND Doxygen::doxygen ${doxyfile}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Generating developer documentation"
    VERBATIM USES_TERMINAL
  )
else()
  add_custom_target(docs
    COMMAND ${CMAKE_COMMAND} -E echo "Error: Doxygen not found"
  )
endif()

set(RPCDOCS_DATA_DIR "${PROJECT_BINARY_DIR}/doc/rpc")
set(RPCDOCS_SITE_DIR "${PROJECT_BINARY_DIR}/doc/rpc-site")
set(RPCDOCS_MANIFEST "${RPCDOCS_DATA_DIR}/rpc-docs.json")
set(RPCDOCS_BUILD_META "${RPCDOCS_DATA_DIR}/rpc-docs-build-meta.json")
set(RPCDOCS_SITE_MODEL "${RPCDOCS_DATA_DIR}/site-model.json")
set(RPCDOCS_SITE_INDEX "${RPCDOCS_SITE_DIR}/index.html")
set(RPCDOCS_SEARCH_INDEX "${RPCDOCS_SITE_DIR}/search/search_index.json")

set(RPCDOCS_FIXTURE_MANIFEST "${PROJECT_SOURCE_DIR}/doc/rpc/fixtures/rpc-docs-v1.sample.json")
set(RPCDOCS_FIXTURE_SITE_MODEL "${PROJECT_SOURCE_DIR}/doc/rpc/fixtures/site-model-v1.sample.json")
set(RPCDOCS_FIXTURE_OVERLAY "${PROJECT_SOURCE_DIR}/doc/rpc/fixtures/v30.2-delta-v1.sample.yml")
set(RPCDOCS_BASELINE "${PROJECT_SOURCE_DIR}/doc/rpc/baselines/v30.2/rpc-docs.json")
set(RPCDOCS_BASELINE_BUILD_META "${PROJECT_SOURCE_DIR}/doc/rpc/baselines/v30.2/rpc-docs-build-meta.json")
set(RPCDOCS_OVERLAY "${PROJECT_SOURCE_DIR}/doc/rpc/annotations/v30.2-delta.yml")
set(RPCDOCS_SITE_BUILDER "${PROJECT_SOURCE_DIR}/doc/rpc/site_builder.py")
set(RPCDOCS_MKDOCS_BASE "${PROJECT_SOURCE_DIR}/doc/rpc/mkdocs.base.yml")
set(RPCDOCS_NORMALIZE_SITE_PATHS "${PROJECT_SOURCE_DIR}/cmake/script/normalize_rpc_docs_site_paths.py")
set(RPCDOCS_GENERATOR_TARGET bitcoin-rpcdocgen)
file(GLOB RPCDOCS_SITE_ASSETS CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/doc/rpc/assets/*")

if(NOT EXISTS "${RPCDOCS_BASELINE}")
  set(RPCDOCS_BASELINE "${RPCDOCS_FIXTURE_MANIFEST}")
endif()

set(RPCDOCS_BASELINE_DEPS ${RPCDOCS_BASELINE})
if(EXISTS "${RPCDOCS_BASELINE_BUILD_META}")
  list(APPEND RPCDOCS_BASELINE_DEPS ${RPCDOCS_BASELINE_BUILD_META})
endif()

if(NOT EXISTS "${RPCDOCS_OVERLAY}")
  set(RPCDOCS_OVERLAY "${RPCDOCS_FIXTURE_OVERLAY}")
endif()

if(TARGET ${RPCDOCS_GENERATOR_TARGET})
  add_custom_command(
    OUTPUT ${RPCDOCS_MANIFEST} ${RPCDOCS_BUILD_META}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RPCDOCS_DATA_DIR}
    COMMAND $<TARGET_FILE:${RPCDOCS_GENERATOR_TARGET}> --output ${RPCDOCS_DATA_DIR}
    DEPENDS ${RPCDOCS_GENERATOR_TARGET}
    COMMENT "Generating RPC docs manifest"
    VERBATIM
  )
else()
  add_custom_command(
    OUTPUT ${RPCDOCS_MANIFEST} ${RPCDOCS_BUILD_META}
    COMMAND ${CMAKE_COMMAND}
            -DCLIENT_NAME=${CLIENT_NAME}
            -DCLIENT_VERSION_STRING=${CLIENT_VERSION_STRING}
            -DRPCDOCS_DATA_DIR=${RPCDOCS_DATA_DIR}
            -DRPCDOCS_MANIFEST_FIXTURE=${RPCDOCS_FIXTURE_MANIFEST}
            -DRPCDOCS_MANIFEST_OUT=${RPCDOCS_MANIFEST}
            -DRPCDOCS_BUILD_META_OUT=${RPCDOCS_BUILD_META}
            -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateRpcDocsFixtureData.cmake
    DEPENDS
      ${PROJECT_SOURCE_DIR}/cmake/script/GenerateRpcDocsFixtureData.cmake
      ${RPCDOCS_FIXTURE_MANIFEST}
    COMMENT "Generating RPC docs manifest from frozen fixtures"
    VERBATIM
  )
endif()

add_custom_target(rpcdocs-json DEPENDS ${RPCDOCS_MANIFEST} ${RPCDOCS_BUILD_META})

if(EXISTS "${PROJECT_SOURCE_DIR}/doc/rpc/build_site.py" AND TARGET Python3::Interpreter)
  add_custom_command(
    OUTPUT ${RPCDOCS_SITE_INDEX} ${RPCDOCS_SEARCH_INDEX} ${RPCDOCS_SITE_MODEL}
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${RPCDOCS_SITE_DIR}
    COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/doc/rpc/build_site.py
            --manifest ${RPCDOCS_MANIFEST}
            --baseline ${RPCDOCS_BASELINE}
            --overlay ${RPCDOCS_OVERLAY}
            --out ${RPCDOCS_SITE_DIR}
    COMMAND ${Python3_EXECUTABLE}
            ${RPCDOCS_NORMALIZE_SITE_PATHS}
            ${RPCDOCS_SITE_DIR}
    DEPENDS
      ${RPCDOCS_MANIFEST}
      ${RPCDOCS_BUILD_META}
      ${PROJECT_SOURCE_DIR}/doc/rpc/build_site.py
      ${RPCDOCS_SITE_BUILDER}
      ${RPCDOCS_MKDOCS_BASE}
      ${RPCDOCS_SITE_ASSETS}
      ${RPCDOCS_NORMALIZE_SITE_PATHS}
      ${RPCDOCS_BASELINE_DEPS}
      ${RPCDOCS_OVERLAY}
    COMMENT "Building RPC docs site"
    VERBATIM
  )
else()
  add_custom_command(
    OUTPUT ${RPCDOCS_SITE_MODEL}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RPCDOCS_DATA_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${RPCDOCS_FIXTURE_SITE_MODEL}
            ${RPCDOCS_SITE_MODEL}
    DEPENDS ${RPCDOCS_FIXTURE_SITE_MODEL}
    COMMENT "Generating RPC docs site model from frozen fixtures"
    VERBATIM
  )

  add_custom_command(
    OUTPUT ${RPCDOCS_SITE_INDEX} ${RPCDOCS_SEARCH_INDEX}
    COMMAND ${CMAKE_COMMAND}
            -DRPCDOCS_SITE_DIR=${RPCDOCS_SITE_DIR}
            -DRPCDOCS_SITE_MODEL_PATH=${RPCDOCS_SITE_MODEL}
            -DRPCDOCS_SITE_INDEX=${RPCDOCS_SITE_INDEX}
            -DRPCDOCS_SEARCH_INDEX=${RPCDOCS_SEARCH_INDEX}
            -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateRpcDocsFixtureSite.cmake
    DEPENDS
      ${RPCDOCS_MANIFEST}
      ${RPCDOCS_BUILD_META}
      ${RPCDOCS_SITE_MODEL}
      ${PROJECT_SOURCE_DIR}/cmake/script/GenerateRpcDocsFixtureSite.cmake
    COMMENT "Building RPC docs site from frozen fixtures"
    VERBATIM
  )
endif()

add_custom_target(rpcdocs-site
  DEPENDS ${RPCDOCS_SITE_INDEX} ${RPCDOCS_SEARCH_INDEX} ${RPCDOCS_SITE_MODEL}
)
add_dependencies(rpcdocs-site rpcdocs-json)
add_custom_target(rpcdocs DEPENDS rpcdocs-site)

set(rpcdocs_install_script "${CMAKE_CURRENT_BINARY_DIR}/BuildRpcDocsForInstall.cmake")
configure_file(
  "${PROJECT_SOURCE_DIR}/cmake/script/BuildRpcDocsForInstall.cmake.in"
  "${rpcdocs_install_script}"
  @ONLY
)

install(SCRIPT "${rpcdocs_install_script}" COMPONENT rpcdocs EXCLUDE_FROM_ALL)

install(DIRECTORY ${RPCDOCS_SITE_DIR}/
  DESTINATION ${CMAKE_INSTALL_DOCDIR}/rpc
  COMPONENT rpcdocs
  EXCLUDE_FROM_ALL
)

install(FILES
  ${RPCDOCS_MANIFEST}
  ${RPCDOCS_BUILD_META}
  DESTINATION ${CMAKE_INSTALL_DOCDIR}/rpc/data
  COMPONENT rpcdocs
  EXCLUDE_FROM_ALL
)

install(FILES ${RPCDOCS_SITE_MODEL}
  DESTINATION ${CMAKE_INSTALL_DOCDIR}/rpc/data
  COMPONENT rpcdocs
  OPTIONAL
  EXCLUDE_FROM_ALL
)
