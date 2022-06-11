#pragma once

#include <cstdio>
#include "base.h"


class StdioSerial : public BaseSerial
{
public:
    FILE* handle;

    explicit StdioSerial(FILE* handle_);

    size_t read_nonblock(void* dst, size_t size) override;

    void write(const void* data, size_t size) override;
};
