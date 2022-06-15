#pragma once


inline void net_memcpy(void* dst, const void* src, size_t size) {
    memcpy(dst, src, size);
}

inline int net_memcmp(const void* a, const void* b, size_t size) {
    return memcmp(a, b, size);
}


template <typename T>
constexpr T swap_integral_bytes(T val) {
    using U = typename std::make_unsigned<T>::type;

    U out;

    if constexpr (std::is_same<U, ubyte>::value)
        out = val;
    else if constexpr (std::is_same<U, ushort>::value)
        out = (val >> 8) | (val << 8);
    else if constexpr (std::is_same<U, uint>::value)
        out = ((val>>24)&0xff) |
              ((val<<8)&0xff0000) |
              ((val>>8)&0xff00) |
              ((val<<24)&0xff000000);
    else if constexpr (std::is_same<U, u64>::value)
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


template <typename T>
inline T net_load(const T& ptr) {
    T out;
    net_memcpy(&out, &ptr, sizeof(T));

    if constexpr (std::is_integral<T>::value)
        out = num_to_le_num(out);

    return out;
}

template <typename T>
inline void net_store(T& ptr, T value) {
    if constexpr (std::is_integral<T>::value)
        value = num_to_le_num(value);

    net_memcpy(&ptr, &value, sizeof(T));
}

template <typename T, typename Integral, typename = typename std::enable_if<std::is_integral<Integral>::value>::type>
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


template <typename T>
inline void net_loadstore_nonscalar(T& ptr, T value) {
    net_store(ptr, value);
}

template <typename T, int arr_size>
inline void net_loadstore_nonscalar(T (&dst_arr)[arr_size], const T (&src_arr)[arr_size]) {
    net_memcpy(*&dst_arr, *&src_arr, sizeof(T) * arr_size);
}
