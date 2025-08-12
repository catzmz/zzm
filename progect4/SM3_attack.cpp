#include <iostream>
#include <cstring>
#include <iomanip>
#include <vector>
#include <stdint.h>
#include <string>
#include <stdexcept>

using namespace std;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

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
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

void sm3_compress(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (B[4 * i] << 24) | (B[4 * i + 1] << 16) | (B[4 * i + 2] << 8) | (B[4 * i + 3]);
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15))
             ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    uint32_t A = V[0], B_ = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T_j[j], j % 32)), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = ((j < 16) ? FF0(A, B_, C) : FF1(A, B_, C)) + D + SS2 + W1[j];
        uint32_t TT2 = ((j < 16) ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[j];
        D = C;
        C = ROTL(B_, 9);
        B_ = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B_; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

vector<uint8_t> sm3_hash(const vector<uint8_t>& message) {
    size_t len = message.size();
    uint64_t bit_len = len * 8;
    size_t padded_len = ((len + 1 + 8 + 63) / 64) * 64;
    vector<uint8_t> padded(padded_len, 0);
    memcpy(padded.data(), message.data(), len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 1 - i] = (bit_len >> (8 * i)) & 0xff;
    }
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(V, padded.data() + i);
    }
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (V[i] >> 24) & 0xff;
        digest[4 * i + 1] = (V[i] >> 16) & 0xff;
        digest[4 * i + 2] = (V[i] >> 8) & 0xff;
        digest[4 * i + 3] = V[i] & 0xff;
    }
    return digest;
}


//打印哈希值
void print_hash(const string& label, const vector<uint8_t>& hash) {
    cout << label;
    for (uint8_t byte : hash) {
        cout << hex << setw(2) << setfill('0') << (int)byte;
    }
    cout << dec << endl;
}

//攻击 从一个已知的状态和长度继续计算哈希
vector<uint8_t> sm3_hash_continue(const vector<uint8_t>& extension, const vector<uint8_t>& original_hash, uint64_t original_total_len) {
    //从原始哈希中恢复内部状态
    uint32_t V[8];
    for (int i = 0; i < 8; ++i) {
        V[i] = (original_hash[4 * i] << 24) | (original_hash[4 * i + 1] << 16) | (original_hash[4 * i + 2] << 8) | (original_hash[4 * i + 3]);
    }

    //要添加的数据，并计算新的填充
    uint64_t original_padded_len = ((original_total_len + 1 + 8 + 63) / 64) * 64;
    vector<uint8_t> message_to_pad = extension;
    uint64_t total_bit_len = (original_padded_len + message_to_pad.size()) * 8;
    size_t padded_len = ((message_to_pad.size() + 1 + 8 + 63) / 64) * 64;
    
    vector<uint8_t> padded(padded_len, 0);
    memcpy(padded.data(), message_to_pad.data(), message_to_pad.size());
    padded[message_to_pad.size()] = 0x80;
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 1 - i] = (total_bit_len >> (8 * i)) & 0xff;
    }
    
    //使用恢复的状态V，对新数据块进行压缩
    for (size_t i = 0; i < padded.size(); i += 64) {
        sm3_compress(V, padded.data() + i);
    }

    //生成伪造哈希
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (V[i] >> 24) & 0xff;
        digest[4 * i + 1] = (V[i] >> 16) & 0xff;
        digest[4 * i + 2] = (V[i] >> 8) & 0xff;
        digest[4 * i + 3] = V[i] & 0xff;
    }
    return digest;
}


int main() {
    string secret_key = "secret_key"; // 密钥
    string original_data = "plaintext";   // 原始数据
    string extension_data = "faketext"; // 攻击者想添加的数据

    // 计算原始哈希
    vector<uint8_t> msg1(secret_key.begin(), secret_key.end());
    msg1.insert(msg1.end(), original_data.begin(), original_data.end());
    vector<uint8_t> original_hash = sm3_hash(msg1);
    
    //伪造新哈
    vector<uint8_t> ext_vec(extension_data.begin(), extension_data.end());
    vector<uint8_t> forged_hash = sm3_hash_continue(ext_vec, original_hash, secret_key.length() + original_data.length());

    // 攻击者计算原始填充
    uint64_t original_len = secret_key.length() + original_data.length();
    uint64_t padded_len = ((original_len + 1 + 8 + 63) / 64) * 64;
    size_t padding_len = padded_len - original_len;
    vector<uint8_t> padding(padding_len);
    padding[0] = 0x80;
    uint64_t bit_len = original_len * 8;
    for(int i=0; i<8; ++i) padding[padding_len - 1 - i] = (bit_len >> (i*8)) & 0xff;
    
    // 服务器用密钥验证攻击者构造的完整消息
    vector<uint8_t> msg2 = msg1;
    msg2.insert(msg2.end(), padding.begin(), padding.end());
    msg2.insert(msg2.end(), extension_data.begin(), extension_data.end());
    vector<uint8_t> legitimate_hash = sm3_hash(msg2);
    
    cout << "原始哈希:   "; print_hash("", original_hash);
    cout << "伪造的哈希: "; print_hash("", forged_hash);
    cout << "合法的哈希: "; print_hash("", legitimate_hash);
    
    if (forged_hash == legitimate_hash) {
        cout << "\n攻击成功，伪造哈希与合法哈希一致" << endl;
    } else {
        cout << "\n攻击失败" << endl;
    }

    return 0;
}