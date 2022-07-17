cmake_minimum_required(VERSION 3.5)

# ESP-IDF component
if ((NOT DEFINED ${FRESH_BUILD_SKIP_ESPIDF_COMPONENT}) AND ESP_PLATFORM)
    message(STATUS "[Fresh]: Setting up as ESP-IDF component")
    set(FRESH_SOURCE_DIR ${COMPONENT_DIR}/main) # not sure what will happen if ${COMPONENT_DIR} is empty
    include(${COMPONENT_DIR}/main/CMakeLists.txt)

# standalone ESP-IDF project
elseif((NOT DEFINED ${FRESH_BUILD_SKIP_ESPIDF_STANDALONE}) AND (DEFINED ENV{IDF_PATH}))
    message(STATUS "[Fresh]: Setting up as standalone ESP-IDF project")
    set(FRESH_ADDITIONAL_SRCS "../runner/esp_idf.cpp")
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    project(Fresh)

# standalone PC project
else()
    message(STATUS "[Fresh]: Setting up as standalone PC project")
    add_subdirectory(main)

endif()
