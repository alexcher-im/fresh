# setting dirs
#set(FRESH_EXCLUDE_MAIN true)
if (NOT DEFINED FRESH_SOURCE_DIR) # if compiling as standalone project
    set(FRESH_SOURCE_DIR ".")
    #set(FRESH_EXCLUDE_MAIN false)
endif()
#set(FRESH_EXCLUDE_MAIN true)

# searching for files
#file(GLOB_RECURSE FRESH_SRCS
#        ${FRESH_SOURCE_DIR}/*.cpp
#        ${FRESH_SOURCE_DIR}/*.c
#        ${FRESH_SOURCE_DIR}/*.h
#        ${FRESH_SOURCE_DIR}/.hpp)

set(FRESH_SRCS "${FRESH_SOURCE_DIR}/mesh_controller.cpp" "${FRESH_SOURCE_DIR}/mesh_stream_builder.cpp")

#if (FRESH_EXCLUDE_MAIN)
#    list(REMOVE_ITEM FRESH_SRCS "${FRESH_SOURCE_DIR}/hello_world_main.c")
#endif()
list(APPEND FRESH_SRCS ${FRESH_ADDITIONAL_SRCS})

# registering component (ESP-IDF)
if (DEFINED ESP_PLATFORM)
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/wifi_esp_now_interface.cpp")
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/pc_std_uart_interface.cpp")
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
    list(APPEND FRESH_SRCS "${FRESH_SOURCE_DIR}/interfaces/pc_std_uart_interface.cpp")

    # add targets
    add_library(${FRESH_PROJECT_NAME} STATIC ${FRESH_SRCS})
    target_include_directories(${FRESH_PROJECT_NAME} PUBLIC "${FRESH_SOURCE_DIR}")
    add_executable(fresh_runner "${FRESH_SOURCE_DIR}/../runner/pc.cpp")
    target_link_libraries(fresh_runner PRIVATE ${FRESH_PROJECT_NAME})

    # link libsodium
    find_package(PkgConfig REQUIRED)
    pkg_search_module(sodium REQUIRED libsodium)
    #set(sodium_USE_STATIC_LIBS ON)
    #find_package(sodium REQUIRED)
    target_include_directories(${FRESH_PROJECT_NAME} PRIVATE ${sodium_INCLUDE_DIRS})
    target_link_libraries(${FRESH_PROJECT_NAME} PRIVATE ${sodium_STATIC_LIBRARIES})
endif()

# set project properties
set_target_properties(${FRESH_PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
