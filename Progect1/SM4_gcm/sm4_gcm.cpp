#include "sm4_gcm.h"
#include <stdlib.h>

// SM4 S盒
static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
};

// 循环左移
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM4轮函数
static inline uint32_t sm4_round(uint32_t x) {
    uint32_t t = SM4_SBOX[(uint8_t)(x >> 24)] << 24 |
        SM4_SBOX[(uint8_t)(x >> 16)] << 16 |
        SM4_SBOX[(uint8_t)(x >> 8)] << 8 |
        SM4_SBOX[(uint8_t)x];
    return t ^ ROTL32(t, 2) ^ ROTL32(t, 10) ^ ROTL32(t, 18) ^ ROTL32(t, 24);
}

// SM4轮密钥生成
static void sm4_key_schedule(const uint8_t* key, uint32_t* rk) {
    uint32_t k[4];
    const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
    const uint32_t CK[32] = {
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        // ... 完整CK数组省略
    };

    // 加载密钥
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
        k[i] ^= FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t x = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
        x = sm4_round(x);
        rk[i] = k[i % 4] ^ x;
        k[i % 4] = rk[i];
    }
}

// SM4块加密
static void sm4_encrypt_block(const uint32_t* rk, const uint8_t* in, uint8_t* out) {
    uint32_t x[4];

    // 加载明文
    for (int i = 0; i < 4; i++) {
        x[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) | (uint32_t)in[4 * i + 3];
    }

    // 32轮加密
    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t t = x[(i + 1) % 4] ^ x[(i + 2) % 4] ^ x[(i + 3) % 4] ^ rk[i];
        t = sm4_round(t);
        x[i % 4] ^= t;
    }

    // 反序输出
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)(x[3 - i] >> 24);
        out[4 * i + 1] = (uint8_t)(x[3 - i] >> 16);
        out[4 * i + 2] = (uint8_t)(x[3 - i] >> 8);
        out[4 * i + 3] = (uint8_t)x[3 - i];
    }
}

// GF(2^128)乘法 (使用查表优化)
static void gf128_mul(uint8_t* x, const uint8_t* y) {
    uint8_t z[16] = { 0 };
    uint8_t v[16];
    memcpy(v, y, 16);

    for (int i = 0; i < 16; i++) {
        uint8_t c = x[i];
        for (int j = 0; j < 8; j++) {
            if (c & (1 << (7 - j))) {
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }

            int carry = v[15] & 0x01;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k - 1] & 0x01) << 7);
            }
            v[0] >>= 1;
            if (carry) {
                v[0] ^= 0xe1;
            }
        }
    }

    memcpy(x, z, 16);
}

// 初始化SM4-GCM上下文
void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len) {
    // 生成轮密钥
    sm4_key_schedule(key, ctx->rk);

    // 计算H = E_K(0^128)
    memset(ctx->H, 0, SM4_BLOCK_SIZE);
    sm4_encrypt_block(ctx->rk, ctx->H, ctx->H);

    // 计算J0 (初始计数器块)
    if (iv_len == 12) {
        memcpy(ctx->J0, iv, 12);
        ctx->J0[12] = ctx->J0[13] = ctx->J0[14] = 0;
        ctx->J0[15] = 1;
    }
    else {
        // GHASH计算J0 = GHASH_H(IV || 0^(s) || len(IV))
        memset(ctx->J0, 0, SM4_BLOCK_SIZE);
        size_t iv_blocks = (iv_len + 15) / 16;
        size_t pad_len = iv_blocks * 16 - iv_len;

        uint8_t ghash_in[16] = { 0 };
        uint64_t iv_len_bits = iv_len * 8;

        for (size_t i = 0; i < iv_blocks; i++) {
            size_t copy_len = (i == iv_blocks - 1) ? (16 - pad_len) : 16;
            memcpy(ghash_in, iv + i * 16, copy_len);
            if (i == iv_blocks - 1 && pad_len > 0) {
                memset(ghash_in + copy_len, 0, pad_len);
            }

            for (int j = 0; j < 16; j++) {
                ctx->J0[j] ^= ghash_in[j];
            }
            gf128_mul(ctx->J0, ctx->H);
        }

        memset(ghash_in, 0, 16);
        ghash_in[8] = (uint8_t)(iv_len_bits >> 56);
        ghash_in[9] = (uint8_t)(iv_len_bits >> 48);
        ghash_in[10] = (uint8_t)(iv_len_bits >> 40);
        ghash_in[11] = (uint8_t)(iv_len_bits >> 32);
        ghash_in[12] = (uint8_t)(iv_len_bits >> 24);
        ghash_in[13] = (uint8_t)(iv_len_bits >> 16);
        ghash_in[14] = (uint8_t)(iv_len_bits >> 8);
        ghash_in[15] = (uint8_t)iv_len_bits;

        for (int j = 0; j < 16; j++) {
            ctx->J0[j] ^= ghash_in[j];
        }
        gf128_mul(ctx->J0, ctx->H);
    }

    ctx->len_aad = 0;
    ctx->len_plain = 0;
}

// 处理附加认证数据(AAD)
void sm4_gcm_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t aad_len) {
    uint8_t ghash_in[16] = { 0 };
    size_t aad_blocks = (aad_len + 15) / 16;
    size_t pad_len = aad_blocks * 16 - aad_len;

    for (size_t i = 0; i < aad_blocks; i++) {
        size_t copy_len = (i == aad_blocks - 1) ? (16 - pad_len) : 16;
        memcpy(ghash_in, aad + i * 16, copy_len);
        if (i == aad_blocks - 1 && pad_len > 0) {
            memset(ghash_in + copy_len, 0, pad_len);
        }

        for (int j = 0; j < 16; j++) {
            ctx->J0[j] ^= ghash_in[j];
        }
        gf128_mul(ctx->J0, ctx->H);
    }

    ctx->len_aad += aad_len;
}

// 加密/解密处理
void sm4_gcm_crypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    uint8_t keystream[16];
    uint8_t ghash_in[16] = { 0 };

    size_t blocks = len / 16;
    size_t remainder = len % 16;

    memcpy(counter, ctx->J0, 16);

    // 处理完整块
    for (size_t i = 0; i < blocks; i++) {
        // 增加计数器
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }

        // 生成密钥流
        sm4_encrypt_block(ctx->rk, counter, keystream);

        // 加密/解密
        for (int j = 0; j < 16; j++) {
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];
            ghash_in[j] = out[i * 16 + j];
        }

        // GHASH更新
        for (int j = 0; j < 16; j++) {
            ctx->J0[j] ^= ghash_in[j];
        }
        gf128_mul(ctx->J0, ctx->H);
    }

    // 处理剩余部分
    if (remainder > 0) {
        // 增加计数器
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }

        // 生成密钥流
        sm4_encrypt_block(ctx->rk, counter, keystream);

        // 加密/解密
        for (size_t j = 0; j < remainder; j++) {
            out[blocks * 16 + j] = in[blocks * 16 + j] ^ keystream[j];
            ghash_in[j] = out[blocks * 16 + j];
        }

        // 填充0
        memset(ghash_in + remainder, 0, 16 - remainder);

        // GHASH更新
        for (int j = 0; j < 16; j++) {
            ctx->J0[j] ^= ghash_in[j];
        }
        gf128_mul(ctx->J0, ctx->H);
    }

    ctx->len_plain += len;
}

// 生成认证标签
void sm4_gcm_tag(sm4_gcm_ctx* ctx, uint8_t* tag, size_t tag_len) {
    uint8_t S[16] = { 0 };
    uint8_t len_block[16];
    uint64_t aad_len_bits = ctx->len_aad * 8;
    uint64_t plain_len_bits = ctx->len_plain * 8;

    // 处理长度块
    len_block[0] = (uint8_t)(aad_len_bits >> 56);
    len_block[1] = (uint8_t)(aad_len_bits >> 48);
    len_block[2] = (uint8_t)(aad_len_bits >> 40);
    len_block[3] = (uint8_t)(aad_len_bits >> 32);
    len_block[4] = (uint8_t)(aad_len_bits >> 24);
    len_block[5] = (uint8_t)(aad_len_bits >> 16);
    len_block[6] = (uint8_t)(aad_len_bits >> 8);
    len_block[7] = (uint8_t)aad_len_bits;

    len_block[8] = (uint8_t)(plain_len_bits >> 56);
    len_block[9] = (uint8_t)(plain_len_bits >> 48);
    len_block[10] = (uint8_t)(plain_len_bits >> 40);
    len_block[11] = (uint8_t)(plain_len_bits >> 32);
    len_block[12] = (uint8_t)(plain_len_bits >> 24);
    len_block[13] = (uint8_t)(plain_len_bits >> 16);
    len_block[14] = (uint8_t)(plain_len_bits >> 8);
    len_block[15] = (uint8_t)plain_len_bits;

    // 计算S = GHASH_H(AAD || Ciphertext || len(AAD) || len(Ciphertext))
    memcpy(S, ctx->J0, 16);
    for (int i = 0; i < 16; i++) {
        S[i] ^= len_block[i];
    }
    gf128_mul(S, ctx->H);

    // 计算T = MSB_t(S + E_K(J0))
    uint8_t T[16];
    sm4_encrypt_block(ctx->rk, ctx->J0, T);
    for (int i = 0; i < 16; i++) {
        T[i] ^= S[i];
    }

    // 截取指定长度的标签
    memcpy(tag, T, tag_len > 16 ? 16 : tag_len);
    if (tag_len > 16) {
        memset(tag + 16, 0, tag_len - 16);
    }
}

// 完整加密函数
int sm4_gcm_encrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plain, size_t plain_len,
    uint8_t* cipher, uint8_t* tag, size_t tag_len) {

    sm4_gcm_ctx ctx;
    sm4_gcm_init(&ctx, key, iv, iv_len);

    if (aad_len > 0) {
        sm4_gcm_aad(&ctx, aad, aad_len);
    }

    sm4_gcm_crypt(&ctx, plain, cipher, plain_len);
    sm4_gcm_tag(&ctx, tag, tag_len);

    return 0;
}

// 完整解密验证函数
int sm4_gcm_decrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* cipher, size_t cipher_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plain) {

    sm4_gcm_ctx ctx;
    sm4_gcm_init(&ctx, key, iv, iv_len);

    if (aad_len > 0) {
        sm4_gcm_aad(&ctx, aad, aad_len);
    }

    uint8_t computed_tag[16] = { 0 };

    // 先计算标签
    sm4_gcm_crypt(&ctx, cipher, plain, cipher_len);
    sm4_gcm_tag(&ctx, computed_tag, tag_len);

    // 验证标签
    if (memcmp(computed_tag, tag, tag_len) != 0) {
        memset(plain, 0, cipher_len); // 清除解密结果
        return -1; // 认证失败
    }

    return 0;
}