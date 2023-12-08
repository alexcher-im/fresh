#pragma once

#include "../types.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/md.h>
#include <sha256_alt.h>
#include <mbedtls/sha256.h>
#include <rom/ets_sys.h>
#include <esp_random.h>
#include <esp_timer.h>


namespace Os
{
    using TaskHandle = TaskHandle_t;
    using Sha256Handle = mbedtls_sha256_context;
    constexpr size_t SHA256_DIGEST_SIZE = 32;

    inline u64 get_microseconds() {
        return esp_timer_get_time();
    }

    inline int create_task(void(*task_func)(void*), const char* name, uint stack_size, void* userdata,
                           uint priority, TaskHandle* out_task, u64 affinity) {
        auto esp_affinity = tskNO_AFFINITY;
        if (affinity & 0b11) esp_affinity = tskNO_AFFINITY;
        else if (affinity & 0b01) esp_affinity = 0;
        else if (affinity & 0x10) esp_affinity = 1;

        return xTaskCreatePinnedToCore(task_func, name, stack_size, userdata, priority, out_task, esp_affinity);
    }

    inline void end_self_task() {
        vTaskDelete(nullptr);
    }

    inline void end_task(TaskHandle& task) {
        vTaskDelete(task);
    }

    inline void detach_task(TaskHandle& task) {
        //
    }

    inline void sleep_ticks(uint ticks) {
        vTaskDelay(ticks);
    }

    inline void sleep_milliseconds(uint milliseconds) {
        sleep_ticks(milliseconds / portTICK_PERIOD_MS);
    }

    inline void yield_non_starving() {
        sleep_ticks(1);
    }

    inline void spinlock_microseconds(uint microseconds) {
        ets_delay_us(microseconds);
    }

    inline uint random_u32() {
        return esp_random();
    }

    inline void fill_random(void* buf, size_t len) {
        esp_fill_random(buf, len);
    }

    // crypto
    inline Sha256Handle create_sha256() {
        mbedtls_sha256_context ctx;
        ctx.mode = ESP_MBEDTLS_SHA256_UNUSED;
        mbedtls_sha256_starts(&ctx, 0);
        return ctx;
    }

    inline void update_sha256(Sha256Handle* ctx, const void* buf, uint size) {
        mbedtls_sha256_update(ctx, (const ubyte*) buf, size);
    }

    inline void finish_sha256(Sha256Handle* ctx, void* hash_write) {
        mbedtls_sha256_finish(ctx, (ubyte*) hash_write);
    }
}
