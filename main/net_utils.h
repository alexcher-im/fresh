#pragma once

// todo remove this header later (it is currently used by projects that depend on fresh)


// GCC in ESP-IDF v4.x didn't require this header for std::endian
#if __cplusplus > 201709L
#include <bit>
#endif

inline void net_memcpy(void* dst, const void* src, size_t size) {
    memcpy(dst, src, size);
}

inline int net_memcmp(const void* a, const void* b, size_t size) {
    return memcmp(a, b, size);
}


template <typename T>
constexpr T swap_integral_bytes(T val) {
    using U = std::make_unsigned_t<T>;

    U out;

    if constexpr (std::is_same_v<U, ubyte>)
        out = val;
    else if constexpr (std::is_same_v<U, ushort>)
        out = (val >> 8) | (val << 8);
    else if constexpr (std::is_same_v<U, uint>)
        out = ((val>>24)&0xff) |
              ((val<<8)&0xff0000) |
              ((val>>8)&0xff00) |
              ((val<<24)&0xff000000);
    else if constexpr (std::is_same_v<U, u64>)
        out = swap_integral_bytes((uint) (out >> 32)) &
        ((u64)swap_integral_bytes((uint) (out & 0xFFFFFFFF)) << 32);

    return (T) out;
}


template <typename T>
constexpr T num_to_le_num(T val) {
    if constexpr (std::endian::native == std::endian::little)
        return val;
    else
        return swap_integral_bytes(val);
}


// call this to read data from network packet
template <typename T>
inline T net_load(const T& ptr) {
    T out;
    net_memcpy(&out, &ptr, sizeof(T));

    if constexpr (std::is_integral_v<T>)
        out = num_to_le_num(out);

    return out;
}

// call this to put data into the network packet
template <typename T>
inline void net_store(T& ptr, T value) {
    if constexpr (std::is_integral_v<T>)
        value = num_to_le_num(value);

    net_memcpy(&ptr, &value, sizeof(T));
}

template <typename T, typename Integral> requires (std::is_integral_v<Integral>)
inline void net_store(T& ptr, Integral value) {
    net_store(ptr, (T) value);
}


template <typename T>
inline T net_pre_decrement(T& ptr) {
    T val = net_load(ptr) - 1;
    net_store(ptr, val);
    return val;
}

template <typename T>
inline T net_pre_increment(T& ptr) {
    T val = net_load(ptr) + 1;
    net_store(ptr, val);
    return val;
}


// call this to load from/store to network packet if data can be a C-array (so can't be returned from net_load() function)
template <typename T, int arr_size>
inline void net_loadstore_nonscalar(T (&dst_arr)[arr_size], const T (&src_arr)[arr_size]) {
    net_memcpy(*&dst_arr, *&src_arr, sizeof(T) * arr_size);
}
