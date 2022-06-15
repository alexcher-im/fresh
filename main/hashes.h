#pragma once

#include "types.h"


// write: 4 bytes
inline void crc32(ubyte* buf, uint size, ubyte* hash_write) {
    uint crc = 0xFFFFFFFF;

    for (int i = 0; i < size; ++i) {
        uint byte = buf[i];            // Get next byte.
        crc = crc ^ byte;
        for (int j = 7; j >= 0; --j) {    // Do eight times.
            uint mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }

    *((uint*)hash_write) = ~crc;
}
