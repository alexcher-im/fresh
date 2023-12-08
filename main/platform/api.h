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

#include <array>


// common classes
namespace Os
{
    class Sha256Hasher {
    public:
        Os::Sha256Handle handle;

        void update(const void* buf, uint size) {
            Os::update_sha256(&handle, buf, size);
        }

        std::array<ubyte, SHA256_DIGEST_SIZE> finish() {
            std::array<ubyte, SHA256_DIGEST_SIZE> ret;
            Os::finish_sha256(&handle, ret.data());
            return ret;
        }

        template <typename T>
        T finish() {
            static_assert(sizeof(T) <= SHA256_DIGEST_SIZE);
            std::array<ubyte, SHA256_DIGEST_SIZE> ret;
            Os::finish_sha256(&handle, ret.data());
            return *(T*) ret.data();
        }

        template <typename T>
        static T hash(const void* data, uint size) {
            auto ctx = Sha256Hasher();
            ctx.update(data, size);
            return ctx.finish<T>();
        }
    };
}
