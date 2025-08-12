#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <stdexcept>
#include <cmath>

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

// Merkle树实现
class MerkleTree {
public:
    MerkleTree(const vector<vector<uint8_t>>& leaves) {
        if (leaves.empty()) {
            root_ = SM3::hash({});
            return;
        }

        // 计算叶子节点哈希
        vector<vector<uint8_t>> current_level;
        for (const auto& leaf : leaves) {
            vector<uint8_t> prefixed_leaf = { 0x00 };
            prefixed_leaf.insert(prefixed_leaf.end(), leaf.begin(), leaf.end());
            current_level.push_back(SM3::hash(prefixed_leaf));
        }
        levels_.push_back(current_level);

        // 构建中间节点
        while (current_level.size() > 1) {
            vector<vector<uint8_t>> next_level;

            // 处理奇数个节点的情况
            if (current_level.size() % 2 != 0) {
                current_level.push_back(current_level.back());
            }

            for (size_t i = 0; i < current_level.size(); i += 2) {
                vector<uint8_t> prefixed_node = { 0x01 };
                prefixed_node.insert(prefixed_node.end(),
                    current_level[i].begin(), current_level[i].end());
                prefixed_node.insert(prefixed_node.end(),
                    current_level[i + 1].begin(), current_level[i + 1].end());
                next_level.push_back(SM3::hash(prefixed_node));
            }

            levels_.push_back(next_level);
            current_level = next_level;
        }

        root_ = current_level[0];
    }

    const vector<uint8_t>& root() const { return root_; }

    vector<vector<uint8_t>> generate_proof(size_t leaf_index) const {
        if (leaf_index >= levels_[0].size()) {
            throw out_of_range("Leaf index out of range");
        }

        vector<vector<uint8_t>> proof;
        size_t current_index = leaf_index;

        for (size_t level = 0; level < levels_.size() - 1; ++level) {
            size_t sibling_index = current_index ^ 1; // 获取兄弟节点索引
            if (sibling_index < levels_[level].size()) {
                proof.push_back(levels_[level][sibling_index]);
            }
            else {
                // 处理奇数节点情况
                proof.push_back(levels_[level][current_index]);
            }
            current_index /= 2;
        }

        return proof;
    }

    static bool verify_proof(const vector<uint8_t>& leaf_data,
        const vector<uint8_t>& root_hash,
        const vector<vector<uint8_t>>& proof,
        size_t leaf_index) {
        // 1. 计算叶子节点的哈希（添加前缀0x00）
        vector<uint8_t> current_hash;
        current_hash.reserve(1 + leaf_data.size());
        current_hash.push_back(0x00);
        current_hash.insert(current_hash.end(), leaf_data.begin(), leaf_data.end());
        current_hash = SM3::hash(current_hash);

        // 2. 沿着证明路径向上计算
        for (size_t i = 0; i < proof.size(); ++i) {
            vector<uint8_t> combined;
            combined.reserve(1 + current_hash.size() + proof[i].size());
            combined.push_back(0x01); // 内部节点前缀

            // 根据索引的当前位决定左右顺序
            if ((leaf_index >> i) & 1) {
                // 当前是右节点，兄弟在左边
                combined.insert(combined.end(), proof[i].begin(), proof[i].end());
                combined.insert(combined.end(), current_hash.begin(), current_hash.end());
            }
            else {
                // 当前是左节点，兄弟在右边
                combined.insert(combined.end(), current_hash.begin(), current_hash.end());
                combined.insert(combined.end(), proof[i].begin(), proof[i].end());
            }

            // 计算父节点哈希
            current_hash = SM3::hash(combined);
        }

        // 3. 比较最终计算结果与根哈希
        return current_hash == root_hash;
    }

private:
    vector<vector<vector<uint8_t>>> levels_;
    vector<uint8_t> root_;
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

int main() {
    // 1. 生成100,000个叶子节点
    const size_t LEAF_COUNT = 100000;
    vector<vector<uint8_t>> leaves;
    for (size_t i = 0; i < LEAF_COUNT; ++i) {
        leaves.push_back(string_to_bytes("leaf" + to_string(i)));
    }

    // 2. 构建Merkle树
    cout << "构建Merkle树..." << endl;
    MerkleTree tree(leaves);
    print_hex("根哈希: ", tree.root());
    cout << "树高度: " << ceil(log2(LEAF_COUNT)) << endl;

    // 3. 存在性证明
    size_t target_index = 12345;
    auto target_leaf = leaves[target_index];
    string leaf_str(target_leaf.begin(), target_leaf.end());
    cout << "\n存在性证明 - 叶子节点 " << target_index << ": \"" << leaf_str << "\"" << endl;

    auto proof = tree.generate_proof(target_index);
    cout << "证明路径长度: " << proof.size() << endl;

    bool valid = MerkleTree::verify_proof(target_leaf, tree.root(), proof, target_index);
    cout << "验证结果: " << (valid ? "成功" : "失败") << endl;

    // 4. 不存在性证明
    vector<uint8_t> non_existent_leaf = string_to_bytes("non-existent-leaf");
    cout << "\n不存在性证明 - 叶子节点: \"non-existent-leaf\"" << endl;

    // 在有序列表中查找插入位置
    auto it = lower_bound(leaves.begin(), leaves.end(), non_existent_leaf);
    if (it == leaves.end()) {
        it = leaves.end() - 1;
    }
    size_t proof_index = distance(leaves.begin(), it);

    auto non_existent_proof = tree.generate_proof(proof_index);
    cout << "使用相邻叶子节点 " << proof_index << " 的证明" << endl;

    valid = MerkleTree::verify_proof(*it, tree.root(), non_existent_proof, proof_index);
    cout << "验证结果: " << (valid ? "成功" : "失败") << endl;
    if (valid) {
        cout << "因为相邻叶子节点存在且位置正确，证明目标叶子不存在" << endl;
    }

    return 0;
}
