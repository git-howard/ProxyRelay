string(TIMESTAMP BUILD_DATE "%Y%m%d")
string(TIMESTAMP BUILD_TIME "%H%M")
set(BUILD_VER_STR "1.0.${BUILD_DATE}.${BUILD_TIME}")

set(IN_FILE "${CMAKE_CURRENT_LIST_DIR}/BuildVersion.h.in")
set(OUT_FILE "${CMAKE_CURRENT_LIST_DIR}/../include/BuildVersion.h")

configure_file(
    "${IN_FILE}"
    "${OUT_FILE}"
    @ONLY
)

message(STATUS "Build version updated to: ${BUILD_VER_STR}")
