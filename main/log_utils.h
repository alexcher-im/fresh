#pragma once

#include "types.h"


enum class LogLevel
{
    UNKNOWN = 0,
    DISABLED,
    CRITICAL,
    ERROR,
    WARNING,
    INFO,
    DEBUG,
    LL_DEBUG,
    ALL
};


namespace LogFeatures
{
    enum Enum {
        TRACE_PACKET = 1 << 0,
        TRACE_MESH_SESSION = 1 << 1,
        TRACE_MESH_EST_SESSION = 1 << 2,
        TRACE_PACKET_IO = 1 << 3,  // trace all sends and receives
    };
}

constexpr LogLevel log_feature_level[] {
    LogLevel::LL_DEBUG,
    LogLevel::DEBUG,
    LogLevel::DEBUG,
    LogLevel::DEBUG,
};


constexpr LogLevel log_level = LogLevel::ALL;
constexpr int log_components = 0;


// starting from LSB
constexpr int get_first_one_bit(uint number) {
    if (!number)
        return -1;
    for (int i = 0; i < sizeof(number) * CHAR_BIT; ++i) {
        if (number & (1 << i))
            return i;
    }
    // not going to happen because the first check, only here to silence some stupid compilers/linters
    return -1;
}

constexpr bool is_log_feature_present(LogFeatures::Enum components) {
    return log_components & components ||
           log_level >= log_feature_level[get_first_one_bit(components)];
}


#define write_log(address, feature, string, ...) do {            \
if constexpr (is_log_feature_present(feature)) {                 \
printf("[%u]: " string "\n", (uint) address __VA_OPT__(,) __VA_ARGS__); \
fflush(stdout);                                                  \
} } while(0)
