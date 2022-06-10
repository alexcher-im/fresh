# setting dirs
if (NOT DEFINED FRESH_SOURCE_DIR) # if compiling as standalone project
    set(FRESH_SOURCE_DIR ".")
endif()

set(FRESH_SRCS "${FRESH_SOURCE_DIR}/mesh_controller.cpp"
               "${FRESH_SOURCE_DIR}/mesh_stream_builder.cpp"
               ${FRESH_ADDITIONAL_SRCS})

# registering component (ESP-IDF)
if (DEFINED ESP_PLATFORM)

    # interfaces for ESP-IDF
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/wifi_esp_now_interface.cpp")
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/p2p_unsecured_short_interface.cpp")

    # adding platform-specific cpp files
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/platform/serial/stdio_serial.cpp")
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/platform/serial/esp32_uart_serial_stdout.cpp")

    # add component
    idf_component_register(
            SRCS ${FRESH_SRCS}
            INCLUDE_DIRS ${FRESH_SOURCE_DIR} ${FRESH_SOURCE_DIR}/interfaces
            REQUIRES nvs_flash mbedtls libsodium
    )

    set(FRESH_PROJECT_NAME ${COMPONENT_LIB})

# registering default CMake project (PC)
else()
    set(FRESH_PROJECT_NAME fresh_static)
    project(${FRESH_PROJECT_NAME})

    # interfaces for PC
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/p2p_unsecured_short_interface.cpp")

    # add platform-specific cpp files
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/platform/serial/stdio_serial.cpp")
    if (WIN32)
        list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/platform/serial/win32_serial.cpp")
    endif()

    # add targets
    add_library(${FRESH_PROJECT_NAME} STATIC ${FRESH_SRCS})
    target_include_directories(${FRESH_PROJECT_NAME} PUBLIC "${FRESH_SOURCE_DIR}" "${FRESH_SOURCE_DIR}/interfaces")
    add_executable(fresh_runner "${FRESH_SOURCE_DIR}/../runner/pc.cpp")
    target_link_libraries(fresh_runner PRIVATE ${FRESH_PROJECT_NAME})

    # link libsodium
    find_package(PkgConfig REQUIRED)
    pkg_search_module(sodium REQUIRED libsodium)
    target_include_directories(${FRESH_PROJECT_NAME} PRIVATE ${sodium_INCLUDE_DIRS})
    target_link_libraries(${FRESH_PROJECT_NAME} PRIVATE ${sodium_STATIC_LIBRARIES})
endif()

# set project properties
set_target_properties(${FRESH_PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
