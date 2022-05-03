set(CMAKE_CXX_STANDARD 20)

if (NOT DEFINED FRESH_SOURCE_DIR)
    set(FRESH_SOURCE_DIR ".")
endif()

file(GLOB_RECURSE FRESH_SRCS
        ${FRESH_SOURCE_DIR}/*.cpp
        ${FRESH_SOURCE_DIR}/*.c
        ${FRESH_SOURCE_DIR}/*.h
        ${FRESH_SOURCE_DIR}/.hpp)

idf_component_register(
        SRCS ${FRESH_SRCS}
        INCLUDE_DIRS ${FRESH_SOURCE_DIR} ${FRESH_SOURCE_DIR}/interfaces
        REQUIRES nvs_flash mbedtls libsodium
)
