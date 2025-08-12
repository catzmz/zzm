#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>
#include <cstdint>

using namespace std;

// SM3哈希算法实现
class SM3 {
public:
    static constexpr uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    static constexpr uint32_t T[64] = {
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
    };

    static vector<uint8_t> hash(const vector<uint8_t>& message) {
        uint64_t bit_len = message.size() * 8;
        size_t pad_len = ((message.size() + 8 + 1 + 63) / 64) * 64;
        vector<uint8_t> padded(pad_len, 0);
        copy(message.begin(), message.end(), padded.begin());
        padded[message.size()] = 0x80;

        for (int i = 0; i < 8; ++i) {
            padded[pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
        }

        uint32_t V[8];
        copy(begin(IV), end(IV), begin(V));

        for (size_t i = 0; i < pad_len; i += 64) {
            compress(V, padded.data() + i);
        }

        vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (V[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (V[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (V[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = V[i] & 0xFF;
        }
        return digest;
    }

    // 长度扩展攻击函数
    static vector<uint8_t> length_extension_attack(
        const vector<uint8_t>& original_hash,
        const vector<uint8_t>& extension,
        uint64_t original_length
    ) {
        // 从原始哈希恢复内部状态
        uint32_t V[8];
        for (int i = 0; i < 8; ++i) {
            V[i] = (original_hash[4 * i] << 24) |
                (original_hash[4 * i + 1] << 16) |
                (original_hash[4 * i + 2] << 8) |
                original_hash[4 * i + 3];
        }

        // 计算原始消息的填充
        uint64_t original_padded_len = ((original_length + 1 + 8 + 63) / 64) * 64;
        uint64_t total_bit_len = (original_padded_len + extension.size()) * 8;

        // 对新消息进行填充
        size_t pad_len = ((extension.size() + 1 + 8 + 63) / 64) * 64;
        vector<uint8_t> padded(pad_len, 0);
        copy(extension.begin(), extension.end(), padded.begin());
        padded[extension.size()] = 0x80;
        for (int i = 0; i < 8; ++i) {
            padded[pad_len - 8 + i] = (total_bit_len >> (56 - i * 8)) & 0xFF;
        }

        // 使用恢复的状态继续计算
        for (size_t i = 0; i < pad_len; i += 64) {
            compress(V, padded.data() + i);
        }

        // 生成伪造哈希
        vector<uint8_t> forged_hash(32);
        for (int i = 0; i < 8; ++i) {
            forged_hash[4 * i] = (V[i] >> 24) & 0xFF;
            forged_hash[4 * i + 1] = (V[i] >> 16) & 0xFF;
            forged_hash[4 * i + 2] = (V[i] >> 8) & 0xFF;
            forged_hash[4 * i + 3] = V[i] & 0xFF;
        }
        return forged_hash;
    }

private:
    static inline uint32_t ROTL(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    static void compress(uint32_t V[8], const uint8_t block[64]) {
        uint32_t W[68], W1[64];

        // 消息扩展
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

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        // 压缩函数
        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j % 32)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }
};

// 辅助函数
void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label;
    for (uint8_t byte : data) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << dec << endl;
}

vector<uint8_t> string_to_bytes(const string& s) {
    return vector<uint8_t>(s.begin(), s.end());
}

// 计算原始消息的填充
vector<uint8_t> calculate_padding(uint64_t original_length) {
    uint64_t padded_len = ((original_length + 1 + 8 + 63) / 64) * 64;
    uint64_t padding_len = padded_len - original_length;
    vector<uint8_t> padding(padding_len, 0);
    padding[0] = 0x80;
    uint64_t bit_len = original_length * 8;
    for (int i = 0; i < 8; ++i) {
        padding[padding_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
    }
    return padding;
}

int main() {
    // 1. 模拟服务器端计算 key || message 的哈希
    string key = "secret_key";
    string message = "original_message";
    vector<uint8_t> full_message = string_to_bytes(key + message);
    vector<uint8_t> original_hash = SM3::hash(full_message);
    print_hex("原hash: ", original_hash);

    // 2. 攻击者知道 original_hash 和 message.length() + key.length()
    //    但不知道 key 的具体内容
    uint64_t known_length = key.length() + message.length();
    string extension = "malicious_extension";

    // 3. 攻击者伪造 new_hash = H(key || message || padding || extension)
    vector<uint8_t> forged_hash = SM3::length_extension_attack(
        original_hash,
        string_to_bytes(extension),
        known_length
    );
    print_hex("伪造hash: ", forged_hash);

    // 4. 服务器端实际计算 key || message || padding || extension 的哈希
    vector<uint8_t> padding = calculate_padding(known_length);
    vector<uint8_t> legitimate_message = full_message;
    legitimate_message.insert(legitimate_message.end(), padding.begin(), padding.end());
    legitimate_message.insert(legitimate_message.end(), extension.begin(), extension.end());
    vector<uint8_t> legitimate_hash = SM3::hash(legitimate_message);
    print_hex("合法hash: ", legitimate_hash);

    // 5. 验证攻击是否成功
    if (forged_hash == legitimate_hash) {
        cout << "\n攻击成功" << endl;
    }
    else {
        cout << "\n攻击失败。" << endl;
    }

    return 0;
}
