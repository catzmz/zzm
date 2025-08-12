#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>  // AVX2
#include <wmmintrin.h>  // AES-NI

// --- S盒 ---
static const uint8_t Sbox[256] = {
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

// 轮密钥FK和CK常量
static const uint32_t FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// 循环左移函数
static uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 线性变换L函数
static uint32_t L(uint32_t b) {
    return b ^ rol(b, 2) ^ rol(b, 10) ^ rol(b, 18) ^ rol(b, 24);
}

// 4个T-table数组
static uint32_t T0[256];
static uint32_t T1[256];
static uint32_t T2[256];
static uint32_t T3[256];

// 初始化T-table
void init_t_tables() {
    for (int i = 0; i < 256; i++) {
        uint32_t s = Sbox[i];
        uint32_t b = (s << 24) | (s << 16) | (s << 8) | s;  // 4字节相同
        T0[i] = L(b);
        T1[i] = L((b << 8) | (b >> 24));
        T2[i] = L((b << 16) | (b >> 16));
        T3[i] = L((b << 24) | (b >> 8));
    }
}

// 用T-table代替T函数
static uint32_t sm4_t_table(uint32_t a) {
    return T0[(a >> 24) & 0xFF] ^
        T1[(a >> 16) & 0xFF] ^
        T2[(a >> 8) & 0xFF] ^
        T3[a & 0xFF];
}

// 轮密钥扩展
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        K[i + 4] = K[i] ^ sm4_t_table(tmp);
        rk[i] = K[i + 4];
    }
}

// 单块加密（T-table版本）
void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) | in[4 * i + 3];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        X[i + 4] = X[i] ^ sm4_t_table(tmp);
    }
    // 反序输出
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (X[35 - i] >> 24) & 0xFF;
        out[4 * i + 1] = (X[35 - i] >> 16) & 0xFF;
        out[4 * i + 2] = (X[35 - i] >> 8) & 0xFF;
        out[4 * i + 3] = X[35 - i] & 0xFF;
    }
}

// ====== AES-NI 加速的 S盒变换 =====
// 这里用AES-NI的 _mm_aesenclast_si128 指令模拟S盒操作（需要打包4个字节到128bit）
static inline __m128i aesni_sbox(__m128i x) {
    // 使用空轮密钥，全零向量
    __m128i zero = _mm_setzero_si128();
    return _mm_aesenclast_si128(x, zero);
}

// AES-NI版本的单块加密，简化示范，只对T函数S盒部分做加速
void sm4_encrypt_block_aesni(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) | in[4 * i + 3];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];

        // 把tmp转成128bit，4个byte一样，打包成__m128i
        uint8_t bytes[16];
        for (int j = 0; j < 16; j++) {
            bytes[j] = (tmp >> ((3 - (j % 4)) * 8)) & 0xFF; // 4个字节循环
        }
        __m128i val = _mm_loadu_si128((__m128i*)bytes);

        __m128i sboxed = aesni_sbox(val);

        // 取出4个sbox后的字节重新组装回uint32_t
        uint8_t sbox_out[16];
        _mm_storeu_si128((__m128i*)sbox_out, sboxed);

        uint32_t sbox_val = ((uint32_t)sbox_out[0] << 24) | ((uint32_t)sbox_out[1] << 16) |
            ((uint32_t)sbox_out[2] << 8) | sbox_out[3];

        // L线性变换
        uint32_t res = sbox_val ^ rol(sbox_val, 2) ^ rol(sbox_val, 10) ^ rol(sbox_val, 18) ^ rol(sbox_val, 24);

        X[i + 4] = X[i] ^ res;
    }

    for (int i = 0; i < 4; i++) {
        out[4 * i] = (X[35 - i] >> 24) & 0xFF;
        out[4 * i + 1] = (X[35 - i] >> 16) & 0xFF;
        out[4 * i + 2] = (X[35 - i] >> 8) & 0xFF;
        out[4 * i + 3] = X[35 - i] & 0xFF;
    }
}

// ====== AVX2 并行加密4块 (示范实现) =====
void sm4_encrypt_4blocks_avx2(const uint8_t in[4][16], uint8_t out[4][16], const uint32_t rk[32]) {
    // 这里只演示一次轮函数操作的并行，完整实现需循环32轮
    // 这里仅示范X[0],X[1],X[2],X[3]四块数据同时加载和操作

    __m256i X0, X1, X2, X3; // 4块状态寄存器并行

    // 加载4个block的初始4个字（共16字节*4）
    // 按列加载方式简化，实际需字节序转换

    uint32_t X[4][36];

    // 初始化X
    for (int blk = 0; blk < 4; blk++) {
        for (int i = 0; i < 4; i++) {
            X[blk][i] = ((uint32_t)in[blk][4 * i] << 24) |
                ((uint32_t)in[blk][4 * i + 1] << 16) |
                ((uint32_t)in[blk][4 * i + 2] << 8) |
                in[blk][4 * i + 3];
        }
    }

    // 这里只示范第1轮加密计算
    for (int blk = 0; blk < 4; blk++) {
        uint32_t tmp = X[blk][1] ^ X[blk][2] ^ X[blk][3] ^ rk[0];
        X[blk][4] = X[blk][0] ^ sm4_t_table(tmp);
    }

    // 输出转换
    for (int blk = 0; blk < 4; blk++) {
        for (int i = 0; i < 4; i++) {
            uint32_t val = X[blk][35 - i];
            out[blk][4 * i] = (val >> 24) & 0xFF;
            out[blk][4 * i + 1] = (val >> 16) & 0xFF;
            out[blk][4 * i + 2] = (val >> 8) & 0xFF;
            out[blk][4 * i + 3] = val & 0xFF;
        }
    }
}

int main() {
    // 初始化T-table
    init_t_tables();

    uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    uint8_t plaintext[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    uint8_t ciphertext[16];

    printf("=== T-table 版本加密结果 ===\n");
    sm4_encrypt_block(plaintext, ciphertext, rk);
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("=== AES-NI 加速版本加密结果 ===\n");
    sm4_encrypt_block_aesni(plaintext, ciphertext, rk);
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    // 准备4个明文块
    uint8_t in4[4][16];
    uint8_t out4[4][16];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 16; j++) {
            in4[i][j] = plaintext[j];
        }
    }
    printf("=== AVX2 并行4块加密(1轮演示) ===\n");
    sm4_encrypt_4blocks_avx2(in4, out4, rk);
    for (int blk = 0; blk < 4; blk++) {
        printf("Block %d: ", blk);
        for (int i = 0; i < 16; i++) printf("%02x ", out4[blk][i]);
        printf("\n");
    }

    return 0;
}