#pragma once

#include "base.h"


class Win32Serial : public BaseSerial
{
public:
    ubyte* handle{}; // to not include windows.h in this header

    Win32Serial(const char* name, uint baudrate);

    size_t read_nonblock(void* dst, size_t size) override;

    void write(const void* data, size_t size) override;
};
