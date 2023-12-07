#pragma once

#include "types.h"

#include <bit>
#include <cstring>

// waiting for C++23 "deducing this" feature to get implemented...
// no CRTP, sorry

// todo add BlobScalarType<T type, bool aligned> class with serialize(T) function to override in specializations/derived classes


template <typename T, std::endian endian, bool aligned = false>
class BlobInteger
{
public:
    T native_value;

    constexpr BlobInteger() = default;
    constexpr BlobInteger(T val) {
        *this = val;
    }
    constexpr BlobInteger(const BlobInteger& src) = default;

    constexpr operator T() const { // implicit
        if constexpr (aligned) {
            return serialize(native_value);
        }
        else {
            T out;
            memcpy(&out, &native_value, sizeof(T));
            return serialize(out);
        }
    }

    constexpr BlobInteger& operator=(T other) {
        auto serialized = serialize(other);

        if constexpr (aligned)
            native_value = serialized;
        else
            memcpy(&native_value, &serialized, sizeof(T));

        return *this;
    }

    constexpr static T serialize(T src) {
        if constexpr (std::endian::native == endian)
            return src;
        else
            return std::byteswap(src);
    }

    // ++i
    constexpr T operator++() {
        auto val = (T) native_value;
        *this = val + 1;
        return val + 1;
    }

    // --i
    constexpr T operator--() {
        auto val = (T) native_value;
        *this = val + 1;
        return val + 1;
    }

    // i++
    constexpr T operator++(int) {
        auto val = (T) native_value;
        *this = val + 1;
        return val;
    }

    // i--
    constexpr T operator--(int) {
        auto val = (T) native_value;
        *this = val + 1;
        return val;
    }
};


template <typename T, bool aligned = false>
class BlobFloat
{
public:
    T native_value;

    constexpr BlobFloat() = default;
    constexpr BlobFloat(T val) {
        *this = val;
    }
    constexpr BlobFloat(const BlobFloat& src) = delete;

    constexpr operator T() const { // implicit
        if constexpr (aligned) {
            return native_value;
        }
        else {
            T out;
            memcpy(&out, &native_value, sizeof(T));
            return out;
        }
    }

    constexpr BlobFloat& operator=(T other) {
        if constexpr (aligned)
            native_value = other;
        else
            memcpy(&native_value, &other, sizeof(T));

        return *this;
    }
};


// todo finish this
template <typename T>
class BlobEnum {
public:
    T _internal;
};


using u8le = BlobInteger<ubyte, std::endian::little>;
using u16le = BlobInteger<ushort, std::endian::little>;
using u32le = BlobInteger<uint, std::endian::little>;
using u64le = BlobInteger<u64, std::endian::little>;

using i8le = BlobInteger<sbyte, std::endian::little>;
using i16le = BlobInteger<sshort, std::endian::little>;
using i32le = BlobInteger<sint, std::endian::little>;
using i64le = BlobInteger<slong, std::endian::little>;

using u8le_aligned = BlobInteger<ubyte, std::endian::little, true>;
using u16le_aligned = BlobInteger<ushort, std::endian::little, true>;
using u32le_aligned = BlobInteger<uint, std::endian::little, true>;
using u64le_aligned = BlobInteger<u64, std::endian::little, true>;

using i8le_aligned = BlobInteger<sbyte, std::endian::little, true>;
using i16le_aligned = BlobInteger<sshort, std::endian::little, true>;
using i32le_aligned = BlobInteger<sint, std::endian::little, true>;
using i64le_aligned = BlobInteger<slong, std::endian::little, true>;

using f32ieee = BlobFloat<float>;
using f64ieee = BlobFloat<double>;
using f32ieee_aligned = BlobFloat<float, true>;
using f64ieee_aligned = BlobFloat<float, true>;


template <typename T, std::endian endian, bool aligned = false>
struct BlobType_Class;

template <typename T, std::endian endian, bool aligned = false>
using BlobType = typename BlobType_Class<T, endian, aligned>::type;


template <typename T, std::endian endian, bool aligned> requires(std::is_integral_v<T>)
struct BlobType_Class<T, endian, aligned> {
    using type = BlobInteger<T, endian, aligned>;
};

template <typename T, std::endian endian, bool aligned> requires(std::is_floating_point_v<T>)
struct BlobType_Class<T, endian, aligned> {
    using type = BlobFloat<T, aligned>;
};

template <typename T, std::endian endian, bool aligned> requires(std::is_array_v<T>)
struct BlobType_Class<T, endian, aligned> {
    using type = T; // todo make array of BlobType<InternalT> types
};
