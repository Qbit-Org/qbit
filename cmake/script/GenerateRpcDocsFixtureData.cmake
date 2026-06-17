cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
  RPCDOCS_DATA_DIR
  RPCDOCS_MANIFEST_FIXTURE
  RPCDOCS_MANIFEST_OUT
  RPCDOCS_BUILD_META_OUT
)
  if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "Missing required variable: ${required_var}")
  endif()
endforeach()

if(NOT DEFINED CLIENT_NAME OR "${CLIENT_NAME}" STREQUAL "")
  set(CLIENT_NAME "qbit")
endif()

if(NOT DEFINED CLIENT_VERSION_STRING OR "${CLIENT_VERSION_STRING}" STREQUAL "")
  set(CLIENT_VERSION_STRING "unknown")
endif()

file(MAKE_DIRECTORY "${RPCDOCS_DATA_DIR}")
file(COPY_FILE "${RPCDOCS_MANIFEST_FIXTURE}" "${RPCDOCS_MANIFEST_OUT}" ONLY_IF_DIFFERENT)

file(WRITE "${RPCDOCS_BUILD_META_OUT}"
  "{\n"
  "  \"schema_version\": \"1\",\n"
  "  \"project\": \"${CLIENT_NAME}\",\n"
  "  \"project_version\": \"${CLIENT_VERSION_STRING}\",\n"
  "  \"generator\": \"rpcdocs-ci fixture fallback\",\n"
  "  \"mode\": \"fixture\"\n"
  "}\n"
)
