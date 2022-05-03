cmake_minimum_required(VERSION 3.5)

# check if standalone project
if (ESP_PLATFORM)
    set(FRESH_SOURCE_DIR ${COMPONENT_DIR}/main) # not sure what will happen if ${COMPONENT_DIR} is empty
    include(${COMPONENT_DIR}/main/CMakeLists.txt)
else()
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    project(Fresh)
endif()
