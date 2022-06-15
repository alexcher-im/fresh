#pragma once

// checking for ESP-IDF
#if defined(ESP_PLATFORM)
#include <esp_system.h>

// using ESP32 api
#if defined(CONFIG_IDF_TARGET_ESP32)
#include "esp32_api.h"
// using ESP8266 api
#elif defined(CONFIG_IDF_TARGET_ESP8266)
#include "esp8266_api.h"

#endif

// not an ESP-IDF context
#else
// using common (PC) api
#include "common_api.h"

#endif

