#file(GLOB MESH_PATH "*/*.cpp" "*/*.c")
##file(GLOB, MESH_INTERFACES_PATH, "interfaces/*.cpp", "interfaces/*.c")
#
#idf_component_register(SRCS ${MESH_PATH}
#        "")

set(CMAKE_CXX_STANDARD 20)

idf_component_register(SRCS "hello_world_main.c"
        "mesh_controller.cpp" "interfaces/wifi_esp_now_interface.cpp"
        "mesh_stream_builder.cpp"
        "")
