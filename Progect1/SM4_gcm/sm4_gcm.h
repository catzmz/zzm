#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <stdint.h>
#include <string.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_NUM_ROUNDS 32

typedef struct {
    uint32_t rk[SM4_NUM_ROUNDS];  // ����Կ
    uint8_t iv[SM4_BLOCK_SIZE];    // ��ʼ����
    uint8_t H[SM4_BLOCK_SIZE];     // ��ϣ����Կ
    uint8_t J0[SM4_BLOCK_SIZE];    // Ԥ��������
    uint64_t len_aad;              // AAD����(�ֽ�)
    uint64_t len_plain;            // ���ĳ���(�ֽ�)
} sm4_gcm_ctx;

// ��ʼ��SM4-GCM������
void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len);

// ��������֤����(AAD)
void sm4_gcm_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t aad_len);

// ����/���ܴ���
void sm4_gcm_crypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len);

// ������֤��ǩ
void sm4_gcm_tag(sm4_gcm_ctx* ctx, uint8_t* tag, size_t tag_len);

// �������ܺ���
int sm4_gcm_encrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plain, size_t plain_len,
    uint8_t* cipher, uint8_t* tag, size_t tag_len);

// ����������֤����
int sm4_gcm_decrypt(
    const uint8_t* key, const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* cipher, size_t cipher_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plain);

#endif // SM4_GCM_H