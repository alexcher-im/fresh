#pragma once

#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <esp32/rom/sha.h>
#include <esp32/sha.h>
#include <string.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_generichash.h>
#include "types.h"
#include <esp_system.h>
#include <mbedtls/cipher.h>
#include <sodium/crypto_stream_chacha20.h>


// write: 4 bytes
static void crc32(ubyte* buf, uint size, ubyte* hash_write) {
    uint crc = 0xFFFFFFFF;

    for (int i = 0; i < size; ++i) {
        uint byte = buf[i];            // Get next byte.
        crc = crc ^ byte;
        for (int j = 7; j >= 0; --j) {    // Do eight times.
            uint mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }

    *((uint*)hash_write) = ~crc;
}

// write: 32 bytes
static void sha256(const ubyte* buf, uint size, ubyte* hash_write) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, buf, size);
    mbedtls_md_finish(&ctx, hash_write);
    mbedtls_md_free(&ctx);
}

// write: 20 bytes
static void sha1(const ubyte* buf, uint size, ubyte* hash_write) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, buf, size);
    mbedtls_md_finish(&ctx, hash_write);
    mbedtls_md_free(&ctx);
}

// write: 16 bytes
static void md5(const ubyte* buf, uint size, ubyte* hash_write) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, buf, size);
    mbedtls_md_finish(&ctx, hash_write);
    mbedtls_md_free(&ctx);
}

static ubyte aes_cache[17000];

// write: 16 bytes
static void aes_hash(const ubyte* buf, uint size, ubyte* hash_write, ubyte key[16]) {
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    mbedtls_cipher_setkey(&cipher_ctx, key, cipher_info->key_bitlen, MBEDTLS_ENCRYPT);
    mbedtls_cipher_reset(&cipher_ctx);
    size_t kek;
    for (int i = 0; i < size; i += 16)
        mbedtls_cipher_update(&cipher_ctx, buf + i, 16, aes_cache, &kek);
    mbedtls_cipher_free(&cipher_ctx);

    memcpy(hash_write, aes_cache, 16);
}

#include "chacha20.h"

static uint chacha20_init_vector[16];

// warning: NOT a cryptographic hash:
//  padding sucks, attacker can lengthen a message within one block
//  hash state outputted as-is, so attacker can use it to produce more valid blocks

// solutions:
//  if no padding required, add a new empty block and hash it
//  add a final iteration of chacha20_process_block() on a modified (NOT XOR-ED!) hashdigest

// also a nice thing will be to zero-out the stack memory before exiting this function, but not required right now

// write: 64 bytes
static void chacha20_hash_manual(const ubyte* buf, uint size, ubyte* hash_write) {
    uint prev_block[16];
    uint* chacha_block = (uint*) hash_write;
    const uint block_size = sizeof(prev_block);

    memcpy(prev_block, chacha20_init_vector, sizeof(chacha20_init_vector));

    for (uint block_i = 0; block_i < size / block_size; ++block_i) {
        memcpy(chacha_block, buf, block_size);

        for (int i = 0; i < block_size / sizeof(prev_block[0]); ++i)
            chacha_block[i] ^= prev_block[i];
        chacha20_process_block(chacha_block);

        buf += block_size;
        memcpy(prev_block, chacha_block, block_size);
    }

    uint size_modulo = size % block_size;
    if (size_modulo) {
        memcpy(chacha_block, buf, size_modulo);
        memset(((ubyte*) chacha_block) + size_modulo, size_modulo, block_size - size_modulo);

        for (int i = 0; i < block_size / sizeof(prev_block[0]); ++i)
            chacha_block[i] ^= prev_block[i];
        chacha20_process_block(chacha_block);
    }
}

// write: 16 bytes
static void chacha20_hash_sodium(const ubyte* buf, uint size, ubyte* hash_write, ubyte key[32]) {
    ubyte nonce[8];
    crypto_stream_chacha20_xor(aes_cache, buf, size, nonce, key);

    memcpy(hash_write, aes_cache + size - 16, 16);
}

typedef mbedtls_md_context_t sha256_handle;

static inline sha256_handle create_sha256() {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
    mbedtls_md_starts(&ctx);
    return ctx;
}

static inline void update_sha256(mbedtls_md_context_t* ctx, const void* buf, uint size) {
    mbedtls_md_update(ctx, (const ubyte*) buf, size);
}

static inline void finish_sha256(mbedtls_md_context_t* ctx, void* hash_write) {
    mbedtls_md_finish(ctx, (ubyte*) hash_write);
    mbedtls_md_free(ctx);
}

static void optimized_md5(const ubyte* buf, uint size, ubyte* hash_write) {
    // setup
    const mbedtls_md_info_t* settings = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    void* ctx = settings->ctx_alloc_func();
    // starts
    settings->starts_func(ctx);
    // update
    settings->update_func(ctx, buf, size);
    // finish
    settings->finish_func(ctx, hash_write);
    // free
    settings->ctx_free_func(ctx);
}

typedef struct mbedtls_md5_context
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
} mbedtls_md5_context;

static mbedtls_md5_context static_md5_context;

static void optimized2_md5(const ubyte* buf, uint size, ubyte* hash_write) {
    // setup
    const mbedtls_md_info_t* settings = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    /// alloc ctx
    void* ctx = &static_md5_context;
    memset(ctx, 0, sizeof(mbedtls_md5_context));
    // starts
    settings->starts_func(ctx);
    // update
    settings->update_func(ctx, buf, size);
    // finish
    settings->finish_func(ctx, hash_write);
    // free
    //settings->ctx_free_func(ctx);
}

typedef enum {
    ESP_MBEDTLS_SHA256_UNUSED, /* first block hasn't been processed yet */
    ESP_MBEDTLS_SHA256_HARDWARE, /* using hardware SHA engine */
    ESP_MBEDTLS_SHA256_SOFTWARE, /* using software SHA */
} esp_mbedtls_sha256_mode;

typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[8];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
    int is224;                  /*!< 0 => SHA-256, else SHA-224 */
    esp_mbedtls_sha256_mode mode;
} mbedtls_sha256_context;

static mbedtls_sha256_context static_sha256_context;

void esp_sha_unlock_engine(esp_sha_type sha_type);

static void optimized_sha256(const ubyte* buf, uint size, ubyte* hash_write) {
    // setup
    const mbedtls_md_info_t* settings = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    /// alloc ctx
    void* ctx = &static_sha256_context;
    memset(&static_sha256_context, 0, sizeof(static_sha256_context));
    //void* ctx = settings->ctx_alloc_func();
    //static_sha256_context.mode = ESP_MBEDTLS_SHA256_HARDWARE;
    // starts
    settings->starts_func(ctx);
    // update
    settings->update_func(ctx, buf, size);
    // finish
    settings->finish_func(ctx, hash_write);
    // free
    if (static_sha256_context.mode == ESP_MBEDTLS_SHA256_HARDWARE) {
        esp_sha_unlock_engine(SHA2_256);
    }
    //settings->ctx_free_func(ctx);
}

static void sudium_sha256(const ubyte* buf, uint size, ubyte* hash_write) {
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, buf, size);
    crypto_hash_sha256_final(&state, hash_write);
}

static void sudium_md5(const ubyte* buf, uint size, ubyte* hash_write) {
    //crypto_generichash_state state;
    //crypto_generichash_init(&state, )
}

static inline void fill_random(void* buf, uint size) {
    esp_fill_random(buf, size);
    return;
    for (uint i = 0; i < size / 4; ++i)
        ((uint*)buf)[i] = esp_random();
    // overwriting only requested bytes
    if (size % 4)
        ((uint*)buf)[size / 4] = (esp_random() >> ((4 - (size % 4)) * 8)) |                         // new
                                 (((uint*)buf)[size / 4] & (0xFFFFFFFF >> ((4 - (size % 4)) * 8))); // old
}
