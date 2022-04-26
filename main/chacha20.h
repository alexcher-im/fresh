// modified version of https://github.com/Ginurx/chacha20-c

#pragma once

#include "types.h"

struct chacha20_cipher_context
{
    uint keystream32[16];
    size_t position;

    ubyte key[32];
    ubyte nonce[12];
    uint64_t counter;

    uint state[16];
};


inline uint32_t chacha20_cipher_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t chacha20_cipher_pack4(const uint8_t *a) {
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0 * 8;
    res |= (uint32_t)a[1] << 1 * 8;
    res |= (uint32_t)a[2] << 2 * 8;
    res |= (uint32_t)a[3] << 3 * 8;
    return res;
}

inline void chacha20_cipher_unpack4(uint32_t src, uint8_t *dst) {
    dst[0] = (src >> 0 * 8) & 0xff;
    dst[1] = (src >> 1 * 8) & 0xff;
    dst[2] = (src >> 2 * 8) & 0xff;
    dst[3] = (src >> 3 * 8) & 0xff;
}

inline void chacha20_cipher_init_block(struct chacha20_cipher_context *ctx, uint8_t key[], uint8_t nonce[]) {
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
    ctx->state[0] = chacha20_cipher_pack4(magic_constant + 0 * 4);
    ctx->state[1] = chacha20_cipher_pack4(magic_constant + 1 * 4);
    ctx->state[2] = chacha20_cipher_pack4(magic_constant + 2 * 4);
    ctx->state[3] = chacha20_cipher_pack4(magic_constant + 3 * 4);
    ctx->state[4] = chacha20_cipher_pack4(key + 0 * 4);
    ctx->state[5] = chacha20_cipher_pack4(key + 1 * 4);
    ctx->state[6] = chacha20_cipher_pack4(key + 2 * 4);
    ctx->state[7] = chacha20_cipher_pack4(key + 3 * 4);
    ctx->state[8] = chacha20_cipher_pack4(key + 4 * 4);
    ctx->state[9] = chacha20_cipher_pack4(key + 5 * 4);
    ctx->state[10] = chacha20_cipher_pack4(key + 6 * 4);
    ctx->state[11] = chacha20_cipher_pack4(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = chacha20_cipher_pack4(nonce + 0 * 4);
    ctx->state[14] = chacha20_cipher_pack4(nonce + 1 * 4);
    ctx->state[15] = chacha20_cipher_pack4(nonce + 2 * 4);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

inline void chacha20_cipher_block_set_counter(struct chacha20_cipher_context *ctx, uint64_t counter)
{
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = chacha20_cipher_pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

inline void chacha20_cipher_block_next(struct chacha20_cipher_context *ctx) {
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += (x)[b]; (x)[d] = chacha20_cipher_rotl32((x)[d] ^ (x)[a], 16); \
    (x)[c] += (x)[d]; (x)[b] = chacha20_cipher_rotl32((x)[b] ^ (x)[c], 12); \
    (x)[a] += (x)[b]; (x)[d] = chacha20_cipher_rotl32((x)[d] ^ (x)[a], 8); \
    (x)[c] += (x)[d]; (x)[b] = chacha20_cipher_rotl32((x)[b] ^ (x)[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
    }

#undef CHACHA20_QUARTERROUND

    for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

    uint32_t *counter = ctx->state + 12;
    // increment counter
    counter[0]++;
    if (0 == counter[0])
    {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        assert(0 != counter[1]);
    }
}

inline void chacha20_cipher_init_context(struct chacha20_cipher_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
    memset(ctx, 0, sizeof(struct chacha20_cipher_context));

    chacha20_cipher_init_block(ctx, key, nonce);
    chacha20_cipher_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

inline void chacha20_cipher_xor(struct chacha20_cipher_context *ctx, uint8_t *bytes, size_t n_bytes)
{
    uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
    for (size_t i = 0; i < n_bytes; i++)
    {
        if (ctx->position >= 64)
        {
            chacha20_cipher_block_next(ctx);
            ctx->position = 0;
        }
        bytes[i] ^= keystream8[ctx->position];
        ctx->position++;
    }
}

inline void chacha20_process_block(uint block[16]) {
#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += (x)[b]; (x)[d] = chacha20_cipher_rotl32((x)[d] ^ (x)[a], 16); \
    (x)[c] += (x)[d]; (x)[b] = chacha20_cipher_rotl32((x)[b] ^ (x)[c], 12); \
    (x)[a] += (x)[b]; (x)[d] = chacha20_cipher_rotl32((x)[d] ^ (x)[a], 8); \
    (x)[c] += (x)[d]; (x)[b] = chacha20_cipher_rotl32((x)[b] ^ (x)[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(block, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(block, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(block, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(block, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(block, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(block, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(block, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(block, 3, 4, 9, 14)
    }

#undef CHACHA20_QUARTERROUND
}
