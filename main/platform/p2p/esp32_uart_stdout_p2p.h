#pragma once


#include "base.h"
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>


class Esp32UartSerialOut : public BaseSerial
{
public:
#ifdef CONFIG_IDF_TARGET_ESP32
    portMUX_TYPE lock;
#endif

    Esp32UartSerialOut();

    size_t read_nonblock(void* dst, size_t size) override { return *(volatile int*)nullptr; }

    void write(const void* data, size_t size) override;

    void start_writing() override;

    void end_writing() override;
};
