#include <rom/uart.h>
#include "esp32_uart_stdout_p2p.h"
#include "types.h"


#ifdef CONFIG_IDF_TARGET_ESP32
#define LOCK_NAME &lock
#else
#define LOCK_NAME
#endif


void Esp32UartSerialOut::write(const void* data, size_t size) {
    for (size_t i = 0; i < size; ++i)
        uart_tx_one_char(((const ubyte*) data)[i]);
}

Esp32UartSerialOut::Esp32UartSerialOut() {
    #ifdef CONFIG_IDF_TARGET_ESP32
    vPortCPUInitializeMutex(LOCK_NAME);
    #endif
}

void Esp32UartSerialOut::start_writing() {
    portENTER_CRITICAL(LOCK_NAME);
}

void Esp32UartSerialOut::end_writing() {
    portEXIT_CRITICAL(LOCK_NAME);
}
