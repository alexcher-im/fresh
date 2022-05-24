set(FRESH_EXCLUDE_MAIN true)
if (NOT DEFINED FRESH_SOURCE_DIR) # if compiling as standalone project
    set(FRESH_SOURCE_DIR ".")
    set(FRESH_EXCLUDE_MAIN false)
endif()

file(GLOB_RECURSE FRESH_SRCS
        ${FRESH_SOURCE_DIR}/*.cpp
        ${FRESH_SOURCE_DIR}/*.c
        ${FRESH_SOURCE_DIR}/*.h
        ${FRESH_SOURCE_DIR}/.hpp)

if (FRESH_EXCLUDE_MAIN)
    list(REMOVE_ITEM FRESH_SRCS "${FRESH_SOURCE_DIR}/hello_world_main.c")
endif()

idf_component_register(
        SRCS ${FRESH_SRCS}
        INCLUDE_DIRS ${FRESH_SOURCE_DIR} ${FRESH_SOURCE_DIR}/interfaces
        REQUIRES nvs_flash mbedtls libsodium
)

set_target_properties(${COMPONENT_LIB} PROPERTIES CXX_STANDARD 20)
