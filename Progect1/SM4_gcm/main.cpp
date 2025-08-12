#include "sm4_gcm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ��ӡʮ����������
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

// ��������1: �������ܽ���
void test_basic_encrypt_decrypt() {
    printf("=== Test 1: Basic Encrypt/Decrypt ===\n");

    // ��������
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

    // ���仺����
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // ��ӡ��������
    print_hex("Key", key, sizeof(key));
    print_hex("IV", iv, sizeof(iv));
    print_hex("AAD", aad, sizeof(aad));
    printf("Plaintext: %s\n", plaintext);

    // ����
    sm4_gcm_encrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        (uint8_t*)plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // ��ӡ���ܽ��
    print_hex("Ciphertext", ciphertext, plain_len);
    print_hex("Tag", tag, sizeof(tag));

    // ����
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // ��ӡ���ܽ��
    if (ret == 0) {
        printf("Decryption successful!\n");
        printf("Decrypted: %s\n", decrypted);
    }
    else {
        printf("Authentication failed!\n");
    }

    // ����
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

// ��������2: ��֤��֤ʧ�����
void test_authentication_failure() {
    printf("=== Test 2: Authentication Failure ===\n");

    // ��������
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

    // ���仺����
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // ����
    sm4_gcm_encrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        (uint8_t*)plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // �۸�����
    ciphertext[5] ^= 0x01;

    // ����
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), aad, sizeof(aad),
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // �����
    if (ret == 0) {
        printf("ERROR: Authentication should have failed but didn't!\n");
        printf("Decrypted: %s\n", decrypted);
    }
    else {
        printf("Correctly detected authentication failure\n");
    }

    // ����
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

// ��������3: ��AAD�Ϳ����Ĳ���
void test_empty_aad_and_plaintext() {
    printf("=== Test 3: Empty AAD and Plaintext ===\n");

    // ��������
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    // ���仺����
    uint8_t ciphertext[1] = { 0 };
    uint8_t decrypted[1] = { 0 };
    uint8_t tag[16];

    // ���� (��AAD�Ϳ�����)
    sm4_gcm_encrypt(key, iv, sizeof(iv), NULL, 0, NULL, 0, ciphertext, tag, sizeof(tag));

    print_hex("Tag for empty input", tag, sizeof(tag));

    // ����
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), NULL, 0,
        ciphertext, 0, tag, sizeof(tag), decrypted);

    // �����
    if (ret == 0) {
        printf("Authentication successful for empty input\n");
    }
    else {
        printf("ERROR: Authentication failed for empty input\n");
    }

    printf("\n");
}

// ��������4: ����Ϣ����
void test_long_message() {
    printf("=== Test 4: Long Message Test ===\n");

    // ��������
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98
    };

    // ���ɳ����� (10KB)
    size_t plain_len = 10 * 1024;
    uint8_t* plaintext = (uint8_t*)malloc(plain_len);
    uint8_t* ciphertext = (uint8_t*)malloc(plain_len);
    uint8_t* decrypted = (uint8_t*)malloc(plain_len);
    uint8_t tag[16];

    if (!plaintext || !ciphertext || !decrypted) {
        perror("Memory allocation failed");
        exit(1);
    }

    // ����������
    for (size_t i = 0; i < plain_len; i++) {
        plaintext[i] = (uint8_t)(i % 256);
    }

    printf("Testing with %zu bytes message...\n", plain_len);

    // ����
    sm4_gcm_encrypt(key, iv, sizeof(iv), NULL, 0,
        plaintext, plain_len, ciphertext, tag, sizeof(tag));

    // ����
    int ret = sm4_gcm_decrypt(key, iv, sizeof(iv), NULL, 0,
        ciphertext, plain_len, tag, sizeof(tag), decrypted);

    // �����
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

    // ����
    free(plaintext);
    free(ciphertext);
    free(decrypted);

    printf("\n");
}

int main() {
    printf("SM4-GCM Implementation Test\n\n");

    // ���в�������
    test_basic_encrypt_decrypt();
    test_authentication_failure();
    test_empty_aad_and_plaintext();
    test_long_message();

    printf("All tests completed.\n");
    return 0;
}