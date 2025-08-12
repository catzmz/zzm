#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <stdint.h>
#include <string.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_NUM_ROUNDS 32

typedef struct {
    uint32_t rk[SM4_NUM_ROUNDS];  // 轮密钥
    uint8_t iv[SM4_BLOCK_SIZE];    // 初始向量
    uint8_t H[SM4_BLOCK_SIZE];     // 哈希子密钥
    uint8_t J0[SM4_BLOCK_SIZE];    // 预计数器块
    uint64_t len_aad;              // AAD长度(字节)
    uint64_t len_plain;            // 明文长度(字节)
} sm4_gcm_ctx;

// 初始化SM4-GCM上下文
void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len);

// 处理附加认证数据(AAD)
void sm4_gcm_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t aad_len);

// 加密/解密处理
void sm4_gcm_crypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len);

// 生成认证标签
void sm4_gcm_tag(sm4_gcm_ctx* ctx, uint8_t* tag, size_t tag_len);

// 完整加密函数
int sm4_gcm_encrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plain, size_t plain_len,
    uint8_t* cipher, uint8_t* tag, size_t tag_len);

// 完整解密验证函数
int sm4_gcm_decrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* cipher, size_t cipher_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plain);

#endif // SM4_GCM_H