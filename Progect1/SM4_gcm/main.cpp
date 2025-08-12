#include "sm4_gcm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 打印十六进制数据
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {
            printf("\n");
        }
    }
    printf("\n");
}

// 测试用例1: 基本加密解密
void test_basic_encrypt_decrypt() {
    printf("=== Test 1: Basic Encrypt/Decrypt ===\n");

    // 测试数据
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef };
    const char* plaintext = "Hello, this is a SM4-GCM test message!";
    size_t plain_len = strlen(plaintext);

    // 分配缓冲区
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // 打印输入数据
    print_hex("Key", key, sizeof(key));
    print_hex("IV", iv, sizeof(iv));
    print_hex("AAD", aad, sizeof(aad));
    printf("Plaintext: %s\n", plaintext);

    // 加密
    sm4_gcm_encrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        (uint8_t*)plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // 打印加密结果
    print_hex("Ciphertext", ciphertext, plain_len);
    print_hex("Tag", tag, sizeof(tag));

    // 解密
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // 打印解密结果
    if (ret == 0) {
        printf("Decryption successful!\n");
        printf("Decrypted: %s\n", decrypted);
    }
    else {
        printf("Authentication failed!\n");
    }

    // 清理
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

// 测试用例2: 验证认证失败情况
void test_authentication_failure() {
    printf("=== Test 2: Authentication Failure ===\n");

    // 测试数据
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef };
    const char* plaintext = "This message will be tampered with";
    size_t plain_len = strlen(plaintext);

    // 分配缓冲区
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // 加密
    sm4_gcm_encrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        (uint8_t*)plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // 篡改密文
    ciphertext[5] ^= 0x01;

    // 解密
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // 检查结果
    if (ret == 0) {
        printf("ERROR: Authentication should have failed but didn't!\n");
        printf("Decrypted: %s\n", decrypted);
    }
    else {
        printf("Correctly detected authentication failure\n");
    }

    // 清理
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

// 测试用例3: 空AAD和空明文测试
void test_empty_aad_and_plaintext() {
    printf("=== Test 3: Empty AAD and Plaintext ===\n");

    // 测试数据
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    // 分配缓冲区
    uint8_t ciphertext[1] = { 0 };
    uint8_t decrypted[1] = { 0 };
    uint8_t tag[16];

    // 加密 (空AAD和空明文)
    sm4_gcm_encrypt(key, iv, sizeof(iv), NULL, 0, NULL, 0, ciphertext, tag, sizeof(tag));

    print_hex("Tag for empty input", tag, sizeof(tag));

    // 解密
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), NULL, 0,
        ciphertext, 0, tag, sizeof(tag), decrypted);

    // 检查结果
    if (ret == 0) {
        printf("Authentication successful for empty input\n");
    }
    else {
        printf("ERROR: Authentication failed for empty input\n");
    }

    printf("\n");
}

// 测试用例4: 长消息测试
void test_long_message() {
    printf("=== Test 4: Long Message Test ===\n");

    // 测试数据
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    // 生成长明文 (10KB)
    size_t plain_len = 10 * 1024;
    uint8_t* plaintext = (uint8_t*)malloc(plain_len);
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!plaintext || !ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // 填充测试数据
    for (size_t i = 0; i < plain_len; i++) {
        plaintext[i] = (uint8_t)(i % 256);
    }

    printf("Testing with %zu bytes message...\n", plain_len);

    // 加密
    sm4_gcm_encrypt(key, iv, sizeof(iv), NULL, 0,
        plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // 解密
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), NULL, 0,
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // 检查结果
    if (ret == 0) {
        if (memcmp(plaintext, decrypted, plain_len) == 0) {
            printf("Success: Long message encrypted and decrypted correctly\n");
        }
        else {
            printf("ERROR: Decrypted data doesn't match original\n");
        }
    }
    else {
        printf("ERROR: Authentication failed for long message\n");
    }

    // 清理
    free(plaintext);
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

int main() {
    printf("SM4-GCM Implementation Test\n\n");

    // 运行测试用例
    test_basic_encrypt_decrypt();
    test_authentication_failure();
    test_empty_aad_and_plaintext();
    test_long_message();

    printf("All tests completed.\n");
    return 0;
}