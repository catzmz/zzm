#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <immintrin.h>
#include <chrono>
#include <cassert>

// 常量定义
constexpr uint32_t IV[] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

constexpr uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 工具函数
inline uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

inline uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
inline uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

// 消息扩展
void MessageExpansion(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16)
            | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 68; ++i) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15))
            ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; ++i) {
        W1[i] = W[i] ^ W[i + 4];
    }
}

// 压缩函数
void Compression(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    MessageExpansion(block, W, W1);

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j % 32)), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SM3哈希主函数
std::vector<uint8_t> SM3(const uint8_t* msg, size_t len) {
    // 消息填充
    uint64_t bit_len = len * 8;
    size_t pad_len = ((len + 8 + 1 + 63) / 64) * 64;
    std::vector<uint8_t> padded(pad_len, 0);
    memcpy(padded.data(), msg, len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; ++i) {
        padded[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    // 处理消息块
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < pad_len; i += 64) {
        Compression(V, &padded[i]);
    }

    // 生成摘要
    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (V[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (V[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (V[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = V[i] & 0xFF;
    }
    return digest;
}

// SIMD优化版本
#ifdef __AVX2__

inline __m256i _mm256_rotl_epi32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n));
}

void Compression_SIMD(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    MessageExpansion(block, W, W1);

    __m256i v_A = _mm256_set1_epi32(V[0]);
    __m256i v_B = _mm256_set1_epi32(V[1]);
    __m256i v_C = _mm256_set1_epi32(V[2]);
    __m256i v_D = _mm256_set1_epi32(V[3]);
    __m256i v_E = _mm256_set1_epi32(V[4]);
    __m256i v_F = _mm256_set1_epi32(V[5]);
    __m256i v_G = _mm256_set1_epi32(V[6]);
    __m256i v_H = _mm256_set1_epi32(V[7]);

    for (int j = 0; j < 64; j += 4) {
        // 处理4轮并行
        __m256i v_T = _mm256_set_epi32(T[j + 3], T[j + 2], T[j + 1], T[j], 0, 0, 0, 0);
        __m256i v_W = _mm256_set_epi32(W[j + 3], W[j + 2], W[j + 1], W[j], 0, 0, 0, 0);
        __m256i v_W1 = _mm256_set_epi32(W1[j + 3], W1[j + 2], W1[j + 1], W1[j], 0, 0, 0, 0);

        __m256i v_SS1 = _mm256_rotl_epi32(
            _mm256_add_epi32(
                _mm256_rotl_epi32(v_A, 12),
                _mm256_add_epi32(v_E, _mm256_rotl_epi32(v_T, j % 32))
            ), 7);

        __m256i v_SS2 = _mm256_xor_si256(v_SS1, _mm256_rotl_epi32(v_A, 12));

        __m256i v_TT1 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_set1_epi32(FF(V[0], V[1], V[2], j)),
                    v_D),
                _mm256_add_epi32(v_SS2, v_W1));

        __m256i v_TT2 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_set1_epi32(GG(V[4], V[5], V[6], j)),
                    v_H),
                _mm256_add_epi32(v_SS1, v_W));

        v_D = v_C; v_C = _mm256_rotl_epi32(v_B, 9); v_B = v_A; v_A = v_TT1;
        v_H = v_G; v_G = _mm256_rotl_epi32(v_F, 19); v_F = v_E;
        v_E = _mm256_xor_si256(
            _mm256_xor_si256(v_TT2, _mm256_rotl_epi32(v_TT2, 9)),
            _mm256_rotl_epi32(v_TT2, 17));
    }

    alignas(32) uint32_t res[8];
    _mm256_store_si256((__m256i*)res, v_A);
    V[0] ^= res[0]; V[1] ^= res[1]; V[2] ^= res[2]; V[3] ^= res[3];
    V[4] ^= res[4]; V[5] ^= res[5]; V[6] ^= res[6]; V[7] ^= res[7];
}

std::vector<uint8_t> SM3_SIMD(const uint8_t* msg, size_t len) {
    // 消息填充（与基础版本相同）
    uint64_t bit_len = len * 8;
    size_t pad_len = ((len + 8 + 1 + 63) / 64) * 64;
    std::vector<uint8_t> padded(pad_len, 0);
    memcpy(padded.data(), msg, len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; ++i) {
        padded[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < pad_len; i += 64) {
        Compression_SIMD(V, &padded[i]);
    }

    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (V[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (V[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (V[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = V[i] & 0xFF;
    }
    return digest;
}
#endif

// 测试验证
void test_vectors() {
    struct TestCase {
        const char* input;
        const char* expected;
    } tests[] = {
        {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
        {"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"}
    };

    for (auto& test : tests) {
        auto digest = SM3((const uint8_t*)test.input, strlen(test.input));
        std::string hex;
        for (auto b : digest) {
            char buf[3];
            sprintf_s(buf, sizeof(buf), "%02x", b);
            hex += buf;
        }

        std::cout << "Test '" << test.input << "':\n";
        std::cout << "  Expected: " << test.expected << "\n";
        std::cout << "  Actual:   " << hex << "\n";
        assert(hex == test.expected && "Test failed");
    }
    std::cout << "All tests passed!\n";
}

// 性能对比
void benchmark() {
    const size_t SIZE = 1 << 24; // 16MB数据
    std::vector<uint8_t> data(SIZE);
    for (auto& b : data) b = rand() % 256;

    // 基础版本
    auto start = std::chrono::high_resolution_clock::now();
    auto hash = SM3(data.data(), data.size());
    auto end = std::chrono::high_resolution_clock::now();
    auto baseline_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // SIMD版本
#ifdef __AVX2__
    start = std::chrono::high_resolution_clock::now();
    auto hash_simd = SM3_SIMD(data.data(), data.size());
    end = std::chrono::high_resolution_clock::now();
    auto simd_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    assert(hash == hash_simd && "Hash mismatch between versions");
#endif

    std::cout << "\nPerformance Results (16MB data):\n";
    std::cout << "  Baseline: " << baseline_time << "ms\n";
#ifdef __AVX2__
    std::cout << "  SIMD:     " << simd_time << "ms ("
        << (baseline_time * 100 / simd_time) << "% of baseline)\n";
#endif
}

int main() {
    std::cout << "SM3 Hash Algorithm Implementation\n";
    std::cout << "================================\n";

    test_vectors();
    benchmark();

    // 示例用法
    const char* sample = "Hello, SM3!";
    auto sample_hash = SM3((const uint8_t*)sample, strlen(sample));

    std::cout << "\nSample hash for '" << sample << "':\n";
    for (auto b : sample_hash) {
        printf("%02x", b);
    }
    std::cout << "\n";

    return 0;
}
