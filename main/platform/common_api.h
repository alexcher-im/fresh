#pragma once

#include <chrono>
#include <thread>
#include <random>
#include <sodium/crypto_hash_sha256.h>
#include "../types.h"


#if __x86_64__
#include <immintrin.h>
//#define YIELD_CPU __asm__ __volatile__("pause")
#define YIELD_CPU _mm_pause()
#else
#define YIELD_CPU std::this_thread::yield()
#endif


namespace Os
{
    using TaskHandle = std::thread;
    using Sha256Handle = crypto_hash_sha256_state;
    constexpr size_t SHA256_DIGEST_SIZE = 32;

    inline std::random_device g_random_device;

    inline u64 get_microseconds() {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    }

    inline int create_task(void(*task_func)(void*), const char* name, uint stack_size, void* userdata,
                           uint priority, TaskHandle* out_task, u64 affinity) {
        std::thread thr(task_func, userdata);
        *out_task = std::move(thr);

        return 0;
    }

    inline void end_self_task() {
        // nothing
    }

    inline void end_task(TaskHandle& task) {
        task.join();
    }

    inline void detach_task(TaskHandle& task) {
        task.detach();
    }

    inline void sleep_ticks(uint ticks) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ticks));
    }

    inline void sleep_milliseconds(uint milliseconds) {
        sleep_ticks(milliseconds);
    }

    inline void yield_non_starving() {
        sleep_ticks(0);
    }

    inline void spinlock_microseconds(uint microseconds) {
        auto end = get_microseconds() + microseconds;
        while (get_microseconds() < end)
            YIELD_CPU;
    }

    inline uint random_u32() {
        return g_random_device();
    }

    inline void fill_random(void* buf, size_t len) {
        for (ssize_t i = 0; i < len / 4; ++i) {
            ((uint*) buf)[i] = random_u32();
        }
        if (len % 4) {
            auto val = random_u32();
            for (int i = 0; i < len % 4; ++i) {
                ((ubyte*) buf)[len / 4 * 4 + i] = val & (0xFF << i);
            }
        }
    }

    // crypto
    inline Sha256Handle create_sha256() {
        crypto_hash_sha256_state ctx;
        crypto_hash_sha256_init(&ctx);
        return ctx;
    }

    inline void update_sha256(Sha256Handle* ctx, const void* buf, uint size) {
        crypto_hash_sha256_update(ctx, (const unsigned char*) buf, size);
    }

    inline void finish_sha256(Sha256Handle* ctx, void* hash_write) {
        crypto_hash_sha256_final(ctx, (unsigned char*) hash_write);
    }
}