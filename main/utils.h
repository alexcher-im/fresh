#pragma once

#include "types.h"


template <typename T, uint size>
class CircularQueue
{
public:
    T data[size]{};
    uint ptr{};

    bool contains(T value) {
        for (int i = 0; i < size; ++i)
            if (data[i] == value)
                return true;
        return false;
    }

    // try adding `value`. return true if value already existed in collection, false otherwise
    bool contains_add(T value) {
        if (contains(value))
            return true;
        data[ptr] = value;
        ptr = (ptr + 1) % size;
        return false;
    }
};
