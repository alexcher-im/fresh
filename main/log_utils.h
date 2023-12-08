#pragma once

#include "types.h"
#include "mesh_protocol.h"

#ifndef ESP_PLATFORM
#include <format>
#endif


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
constexpr bool ENABLE_PACKET_LOGGER = true;


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


#ifndef ESP_PLATFORM
namespace std {
    template <>
    struct formatter<MeshProto::far_addr_t> {
        constexpr auto parse(std::format_parse_context& ctx) {
            return ctx.begin();
        }

        auto format(const MeshProto::far_addr_t& obj, std::format_context& ctx) const {
            return std::format_to(ctx.out(), "{:08x}", (uint) obj);
        }
    };
}
#endif


class PacketLog {
public:
    constexpr static int BUF_SIZE = 320;

    std::array<char, BUF_SIZE> buffer;
    int written = 0;

    void write_raw_bytes(ubyte* bytes, int size) {
        for (int i = 0; i < size; ++i) {
            write_raw("{:02x}", bytes[i]);
            if (i != size - 1)
                write_raw(":");
        }
    }

    const char* finish() {
        buffer[std::min(written, BUF_SIZE - 1)] = 0;
        return buffer.data();
    }

    // damn ESP-IDF v5.1.2 (latest at the moment of writing this), using GCC 12.2, which does not support std::format
#ifndef ESP_PLATFORM
    template <typename... TArgs>
    void write(std::format_string<TArgs...> fmt, TArgs&&... args) {
        write_raw(", ");
        write_raw(std::move(fmt), std::forward<TArgs>(args)...);
    }

    template <typename... TArgs>
    void write_raw(std::format_string<TArgs...> fmt, TArgs&&... args) {
        if constexpr (!ENABLE_PACKET_LOGGER)
            return;
        if (written == BUF_SIZE - 1)
            return;

        auto begin = buffer.begin() + written;
        auto end = buffer.end();
        auto out = std::format_to_n(begin, end - begin, std::move(fmt), std::forward<TArgs>(args)...);
        written += out.size;
    }
#else
    template <typename... TArgs>
    void write(TArgs&&... args) { }
    template <typename... TArgs>
    void write_raw(TArgs&&... args) { }
#endif
};


#define write_log(address, feature, string, ...) do {            \
if constexpr (is_log_feature_present(feature)) {                 \
printf("[%u]: " string "\n", (uint) address __VA_OPT__(,) __VA_ARGS__); \
fflush(stdout);                                                  \
} } while(0)
