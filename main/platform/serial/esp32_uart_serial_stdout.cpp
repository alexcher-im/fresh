#include <esp32/rom/uart.h>
#include <freertos/FreeRTOS.h>
#include "esp32_uart_serial_stdout.h"
#include "types.h"


void Esp32UartSerialOut::write(const void* data, size_t size) {
    for (size_t i = 0; i < size; ++i)
        uart_tx_one_char(((const ubyte*) data)[i]);
}

Esp32UartSerialOut::Esp32UartSerialOut() {
    vPortCPUInitializeMutex(&lock);
}

void Esp32UartSerialOut::start_writing() {
    portENTER_CRITICAL(&lock);
}

void Esp32UartSerialOut::end_writing() {
    portEXIT_CRITICAL(&lock);
}
