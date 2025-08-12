#include <immintrin.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdint>


using namespace std;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

const uint32_t T_j[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

inline __m256i ROTL32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

inline __m256i P0(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x, 9)), ROTL32(x, 17));
}

inline __m256i P1(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x, 15)), ROTL32(x, 23));
}

inline __m256i FF(__m256i x, __m256i y, __m256i z, int j) {
    return (j < 16) ? _mm256_xor_si256(_mm256_xor_si256(x, y), z)
                    : _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z)), _mm256_and_si256(y, z));
}

inline __m256i GG(__m256i x, __m256i y, __m256i z, int j) {
    return (j < 16) ? _mm256_xor_si256(_mm256_xor_si256(x, y), z)
                    : _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z));
}

void sm3_avx2_compress(
    __m256i V[8], // A~H vectors for 8 blocks
    const uint8_t M[8][64] // 8 blocks of 64 bytes
) {
    __m256i W[68], W1[64];

    for (int i = 0; i < 16; i++) {
        alignas(32) uint32_t w[8];
        for (int j = 0; j < 8; j++) {
            w[j] = (M[j][4*i] << 24) | (M[j][4*i+1] << 16) | (M[j][4*i+2] << 8) | (M[j][4*i+3]);
        }
        W[i] = _mm256_load_si256((__m256i*)w);
    }

    for (int i = 16; i < 68; i++) {
        W[i] = _mm256_xor_si256(
            P1(_mm256_xor_si256(
                _mm256_xor_si256(W[i-16], W[i-9]),
                ROTL32(W[i-3], 15))),
            _mm256_xor_si256(ROTL32(W[i-13], 7), W[i-6]));
    }

    for (int i = 0; i < 64; i++) {
        W1[i] = _mm256_xor_si256(W[i], W[i+4]);
    }

    __m256i A = V[0], B = V[1], C = V[2], D = V[3];
    __m256i E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        __m256i T = _mm256_set1_epi32(T_j[j]);
        __m256i SS1 = ROTL32(_mm256_add_epi32(ROTL32(A, 12), _mm256_add_epi32(E, ROTL32(T, j % 32))), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, ROTL32(A, 12));
        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(FF(A, B, C, j), D), _mm256_add_epi32(SS2, W1[j]));
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(GG(E, F, G, j), H), _mm256_add_epi32(SS1, W[j]));

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);
}

void print_hash(__m256i V[8]) {
    alignas(32) uint32_t output[8][8];
    for (int i = 0; i < 8; i++) {
        _mm256_store_si256((__m256i*)output[i], V[i]);
    }

    for (int j = 0; j < 8; j++) {
        cout << "Block " << j << " hash: ";
        for (int i = 0; i < 8; i++) {
            cout << hex << setw(8) << setfill('0') << output[i][j];
        }
        cout << endl;
    }
}

int main() {
    uint8_t msg[8][64] = {0};
    const char* base = "abcdefgh";
    for (int i = 0; i < 8; i++) {
        strncpy((char*)msg[i], base + i, 1); // 简单初始化每块一个字符
        msg[i][1] = 0x80;
        uint64_t bit_len = 8;
        msg[i][56 + 7] = (bit_len >> 0) & 0xFF;
    }

    __m256i V[8];
    for (int i = 0; i < 8; i++) {
        V[i] = _mm256_set1_epi32(IV[i]);
    }

    sm3_avx2_compress(V, msg);
    print_hash(V);
    return 0;
}
