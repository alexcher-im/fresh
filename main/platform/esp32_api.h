#pragma once

#include "../types.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/md.h>


namespace Os
{
    typedef xTaskHandle TaskHandle;
    typedef mbedtls_md_context_t Sha256Handle;

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
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
        mbedtls_md_starts(&ctx);
        return ctx;
    }

    inline void update_sha256(Sha256Handle* ctx, const void* buf, uint size) {
        mbedtls_md_update(ctx, (const ubyte*) buf, size);
    }

    inline void finish_sha256(Sha256Handle* ctx, void* hash_write) {
        mbedtls_md_finish(ctx, (ubyte*) hash_write);
        mbedtls_md_free(ctx);
    }

    inline void sha256(const ubyte* buf, size_t size, ubyte out[32]) {
        auto ctx = create_sha256();
        update_sha256(&ctx, buf, size);
        finish_sha256(&ctx, out);
    }
}
