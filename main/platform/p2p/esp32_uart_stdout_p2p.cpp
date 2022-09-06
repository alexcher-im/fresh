#include "esp32_uart_stdout_p2p.h"
#include "types.h"


#ifdef CONFIG_IDF_TARGET_ESP32
#define LOCK_NAME &lock
#include <esp32/rom/uart.h>
#include <spinlock.h>
#else
#define LOCK_NAME
#include <rom/uart.h>
#endif

// on esp8266, portENTER_CRITICAL() have no arguments, but portENTER_CRITICAL(LOCK_NAME)
// will be treated as some existing but empty arg by the compiler
#define _invoke(macro, ...) macro(__VA_ARGS__)


void Esp32UartSerialOut::write(const void* data, size_t size) {
    for (int i = 0; i < size; ++i)
        uart_tx_one_char(((const ubyte*) data)[i]);
}

Esp32UartSerialOut::Esp32UartSerialOut() {
    #ifdef CONFIG_IDF_TARGET_ESP32
    spinlock_initialize(LOCK_NAME);
    #endif
}

void Esp32UartSerialOut::start_writing() {
    _invoke(portENTER_CRITICAL, LOCK_NAME);
}

void Esp32UartSerialOut::end_writing() {
    _invoke(portEXIT_CRITICAL, LOCK_NAME);
}

Esp32UartSerialOut::~Esp32UartSerialOut() {
    #ifdef CONFIG_IDF_TARGET_ESP32
    spinlock_release(LOCK_NAME);
    #endif
}
