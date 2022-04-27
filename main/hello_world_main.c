#include <stdio.h>
#include <nvs_flash.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "hashes.h"


void benchmark_crypto(uint rand_size, uint iter_count) {
    // fill random
    rand_size = (rand_size + 3) / 4 * 4;
    ubyte* data = malloc(rand_size);
    for (uint i = 0; i < rand_size / sizeof(uint); ++i) {
        ((uint*)data)[i] = esp_random();
    }

    // measuring
    ubyte hash_digest[64];
    u64 start = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        crc32(data, rand_size, hash_digest);
    }
    u64 after_crc = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        sha1(data, rand_size, hash_digest);
    }
    u64 after_sha1 = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        sha256(data, rand_size, hash_digest);
    }
    u64 after_sha256 = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        md5(data, rand_size, hash_digest);
    }
    u64 after_md5 = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        optimized2_md5(data, rand_size, hash_digest);
    }
    u64 after_md5_opt = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        optimized_sha256(data, rand_size, hash_digest);
    }
    u64 after_sha256_opt = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        sudium_sha256(data, rand_size, hash_digest);
    }
    u64 after_sha256_sodium = esp_timer_get_time();

    ubyte key[32];
    for (uint i = 0; i < iter_count; ++i) {
        aes_hash(data, rand_size, hash_digest, key);
    }
    u64 after_aes = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        chacha20_hash_sodium(data, rand_size, hash_digest, key);
    }
    u64 after_chacha = esp_timer_get_time();

    for (uint i = 0; i < iter_count; ++i) {
        chacha20_hash_manual(data, rand_size, hash_digest);
    }
    u64 after_chacha_manual = esp_timer_get_time();

    printf("hashing %d bytes of random data:\n"
           "  CRC32:      %llu us\n"
           "  SHA-1:      %llu us\n"
           "  SHA-256:    %llu us\n"
           "  MD5:        %llu us\n"
           "  MD5-OPT:    %llu us\n"
           "  SHA256-OPT: %llu us\n"
           "  SHA256-SOD: %llu us\n"
           "  AES-128-MB: %llu us\n"
           "  CHACHA20:   %llu us\n"
           "  CHACHA20_M: %llu us\n\n", rand_size,
           after_crc-start, after_sha1-after_crc, after_sha256-after_sha1, after_md5-after_sha256,
           after_md5_opt - after_md5, after_sha256_opt - after_md5_opt, after_sha256_sodium - after_sha256_opt,
           after_aes - after_sha256_sodium, after_chacha - after_aes, after_chacha_manual - after_chacha);
    fflush(stdout);

    free(data);
}


void start_mesh();


void app_main(void)
{
    start_mesh();
    return;

    benchmark_crypto(16, 10000);
    benchmark_crypto(32, 10000);
    benchmark_crypto(64, 10000);
    benchmark_crypto(256, 10000);
    benchmark_crypto(1024, 10000);
    benchmark_crypto(4096, 10000);
    benchmark_crypto(16536, 10000);
    benchmark_crypto(65536, 10000);

    /* Print chip information */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU cores, WiFi%s%s, ",
           "ESP32",
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);

    printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    for (int i = 10; i >= 0; i--) {
        printf("Restarting in %d seconds...\n", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    printf("Restarting now.\n");
    fflush(stdout);
    esp_restart();
}
