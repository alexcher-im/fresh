#pragma once
#include <cstdint>

//typedef uint64_t ulong;
typedef uint64_t u64;
typedef uint8_t  ubyte;
typedef int64_t  slong;
typedef int32_t  sint;
typedef int16_t  sshort;
typedef int8_t   sbyte;

#ifdef ESP_PLATFORM // fuck ESP-IDF v5.0+ typedefs in stdio.h
//                     ...and fuck my english linter for considering the word "fuck" offensive
typedef unsigned int uint;
typedef unsigned short ushort;
#else
typedef uint32_t uint;
typedef uint16_t ushort;
#endif
