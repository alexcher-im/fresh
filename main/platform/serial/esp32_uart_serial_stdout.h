#pragma once


#include "base.h"


class Esp32UartSerialOut : public BaseSerial
{
public:
    portMUX_TYPE lock;

    Esp32UartSerialOut();

    size_t read_nonblock(void* dst, size_t size) override { return *(volatile int*)nullptr; }

    void write(const void* data, size_t size) override;

    void start_writing() override;

    void end_writing() override;
};
