#include <iostream>
#include <cstring>
#include <iomanip>
#include <vector>
#include <string>
#include <stdint.h>
#include <algorithm>
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
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

void sm3_compress(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    for(int i=0;i<16;i++) W[i]=(B[4*i]<<24)|(B[4*i+1]<<16)|(B[4*i+2]<<8)|(B[4*i+3]);
    for(int i=16;i<68;i++) W[i]=P1(W[i-16]^W[i-9]^ROTL(W[i-3],15))^ROTL(W[i-13],7)^W[i-6];
    for(int i=0;i<64;i++) W1[i]=W[i]^W[i+4];
    uint32_t A=V[0],B_=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];
    for(int j=0;j<64;j++) {
        uint32_t SS1=ROTL((ROTL(A,12)+E+ROTL(T_j[j],j%32)),7);
        uint32_t SS2=SS1^ROTL(A,12);
        uint32_t TT1=((j<16)?FF0(A,B_,C):FF1(A,B_,C))+D+SS2+W1[j];
        uint32_t TT2=((j<16)?GG0(E,F,G):GG1(E,F,G))+H+SS1+W[j];
        D=C; C=ROTL(B_,9); B_=A; A=TT1; H=G; G=ROTL(F,19); F=E; E=P0(TT2);
    }
    V[0]^=A; V[1]^=B_; V[2]^=C; V[3]^=D; V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
}
vector<uint8_t> sm3_hash(const uint8_t* message, size_t len) {
    uint64_t bit_len = len*8;
    size_t padded_len = ((len+1+8+63)/64)*64;
    vector<uint8_t> padded(padded_len, 0);
    memcpy(padded.data(),message,len);
    padded[len]=0x80;
    for(int i=0;i<8;i++) padded[padded_len-1-i]=(bit_len>>(8*i))&0xff;
    uint32_t V[8];
    memcpy(V,IV,sizeof(IV));
    for(size_t i=0;i<padded.size();i+=64) sm3_compress(V,padded.data()+i);
    vector<uint8_t> digest(32);
    for(int i=0;i<8;i++) {
        digest[4*i]=(V[i]>>24)&0xff; digest[4*i+1]=(V[i]>>16)&0xff;
        digest[4*i+2]=(V[i]>>8)&0xff; digest[4*i+3]=V[i]&0xff;
    }
    return digest;
}
vector<uint8_t> sm3_hash_vec(const vector<uint8_t>& message) {
    return sm3_hash(message.data(), message.size());
}

void print_hash(const string& label, const vector<uint8_t>& hash) {
    cout << label;
    for (uint8_t byte : hash) cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    cout << dec << endl;
}

class MerkleTree {
private:
    vector<vector<uint8_t>> leaves;
    vector<vector<vector<uint8_t>>> levels; // 存储每一层的哈希值
    vector<uint8_t> root;

    //叶子哈希
    vector<uint8_t> hash_leaf(const vector<uint8_t>& data) {
        vector<uint8_t> prefixed_data = {0x00};
        prefixed_data.insert(prefixed_data.end(), data.begin(), data.end());
        return sm3_hash_vec(prefixed_data);
    }

    //内部节点哈希
    vector<uint8_t> hash_internal_node(const vector<uint8_t>& left, const vector<uint8_t>& right) {
        vector<uint8_t> prefixed_data = {0x01};
        prefixed_data.insert(prefixed_data.end(), left.begin(), left.end());
        prefixed_data.insert(prefixed_data.end(), right.begin(), right.end());
        return sm3_hash_vec(prefixed_data);
    }

public:
    //构建树
    MerkleTree(const vector<vector<uint8_t>>& initial_leaves) : leaves(initial_leaves) {
        if (leaves.empty()) {
            root = sm3_hash_vec({}); // 空树的根哈希
            return;
        }

        // 计算第一层
        vector<vector<uint8_t>> current_level;
        for (const auto& leaf : leaves) {
            current_level.push_back(hash_leaf(leaf));
        }
        levels.push_back(current_level);

        // 自底向上构建树
        while (current_level.size() > 1) {
            vector<vector<uint8_t>> next_level;
            // 如果当前层节点数为奇数，复制最后一个节点
            if (current_level.size() % 2 != 0) {
                current_level.push_back(current_level.back());
            }
            
            for (size_t i = 0; i < current_level.size(); i += 2) {
                next_level.push_back(hash_internal_node(current_level[i], current_level[i + 1]));
            }
            levels.push_back(next_level);
            current_level = next_level;
        }
        root = current_level[0];
    }

    const vector<uint8_t>& getRoot() const {
        return root;
    }
    
    // 生成存在性证明
    vector<vector<uint8_t>> generateInclusionProof(size_t leaf_index) const {
        if (leaf_index >= leaves.size()) {
            throw out_of_range("Leaf index out of range.");
        }
        vector<vector<uint8_t>> proof;
        size_t current_index = leaf_index;

        // 遍历除根节点外的所有层
        for (size_t i = 0; i < levels.size() - 1; ++i) {
            const auto& current_level = levels[i];
            size_t sibling_index = (current_index % 2 == 0) ? current_index + 1 : current_index - 1;
            
            if (sibling_index < current_level.size()) {
                // 如果兄弟节点存在，则添加到证明中
                proof.push_back(current_level[sibling_index]);
            } else {
                // 如果兄弟节点不存在（意味着当前节点是奇数层的最后一个）
                // 则将节点自身添加到证明中，因为它是与自己进行哈希的
                proof.push_back(current_level[current_index]);
            }
            current_index /= 2;
        }
        return proof;
    }

    //存在性证明
    static bool verifyInclusionProof(const vector<uint8_t>& leaf_data, size_t leaf_index, const vector<vector<uint8_t>>& proof, const vector<uint8_t>& root_hash) {
        vector<uint8_t> prefixed_leaf = {0x00};
        prefixed_leaf.insert(prefixed_leaf.end(), leaf_data.begin(), leaf_data.end());
        vector<uint8_t> computed_hash = sm3_hash_vec(prefixed_leaf);

        size_t current_index = leaf_index;
        for (const auto& proof_hash : proof) {
            vector<uint8_t> combined;
            combined.push_back(0x01);
            if (current_index % 2 == 0) { // 当前哈希是左节点
                combined.insert(combined.end(), computed_hash.begin(), computed_hash.end());
                combined.insert(combined.end(), proof_hash.begin(), proof_hash.end());
            } else { // 当前哈希是右节点
                combined.insert(combined.end(), proof_hash.begin(), proof_hash.end());
                combined.insert(combined.end(), computed_hash.begin(), computed_hash.end());
            }
            computed_hash = sm3_hash_vec(combined);
            current_index /= 2;
        }
        return computed_hash == root_hash;
    }
};


int main() {

    // 生成叶子节点数据
    const int LEAF_COUNT = 100000;
    vector<vector<uint8_t>> leaves_data;
    for (int i = 0; i < LEAF_COUNT; ++i) {
        string leaf_str = "leaf-data-" + to_string(i);
        leaves_data.emplace_back(leaf_str.begin(), leaf_str.end());
    }

    // 对叶子数据排序
    sort(leaves_data.begin(), leaves_data.end());

    //构建 Merkle 树
    cout << "构建 Merkle 树：" << endl;
    MerkleTree tree(leaves_data);
    const auto& root_hash = tree.getRoot();
    print_hash("MT构建完成，根哈希为: ", root_hash);
    
    // 4. 存在性证明 (Inclusion Proof)
    cout << "存在性证明：" << endl;
    string target_leaf_str = "leaf-data-88888";
    vector<uint8_t> target_leaf_data(target_leaf_str.begin(), target_leaf_str.end());
    
    // 找到排序后目标叶子的索引
    auto it = lower_bound(leaves_data.begin(), leaves_data.end(), target_leaf_data);
    size_t target_index = distance(leaves_data.begin(), it);

    cout << "   目标叶子: \"" << target_leaf_str << "\", 索引: " << target_index << endl;
    
    auto inclusion_proof = tree.generateInclusionProof(target_index);
    cout << "   生成的证明路径长度为: " << inclusion_proof.size() << " 个哈希" << endl;
    
    bool is_valid_inclusion = MerkleTree::verifyInclusionProof(target_leaf_data, target_index, inclusion_proof, root_hash);
    if (is_valid_inclusion) {
        cout << "存在性证明验证成功" << endl;
    } else {
        cout << "存在性证明验证失败" << endl;
    }


    //不存在性证明
    string non_existent_leaf_str = "this-leaf-does-not-exist";
    vector<uint8_t> non_existent_leaf_data(non_existent_leaf_str.begin(), non_existent_leaf_str.end());
    cout << non_existent_leaf_str<< "不存在性证明：" << endl;
    
    // 在排好序的叶子中，找到这个不存在的元素若存在则应该在的位置，为该位置的元素提供一个存在性证明
    // 如果证明成功，就说明那个位置已经被占了，从而证明目标元素不存在
    auto non_existent_it = lower_bound(leaves_data.begin(), leaves_data.end(), non_existent_leaf_data);
    size_t proof_for_index = distance(leaves_data.begin(), non_existent_it);
    
    if (proof_for_index >= leaves_data.size()) {
         proof_for_index = leaves_data.size() - 1;
    }
    
    vector<uint8_t> proof_for_leaf_data = leaves_data[proof_for_index];
    string proof_for_leaf_str(proof_for_leaf_data.begin(), proof_for_leaf_data.end());

    cout << "通过证明叶子节点 \"" << proof_for_leaf_str << "\" (索引 " << proof_for_index << ") 的存在性。" << endl;
    
    auto non_inclusion_proof = tree.generateInclusionProof(proof_for_index);
    bool is_valid_non_inclusion = MerkleTree::verifyInclusionProof(proof_for_leaf_data, proof_for_index, non_inclusion_proof, root_hash);

    if (is_valid_non_inclusion) {
        cout << "不存在性证明验证成功" << endl;
    } else {
        cout << "不存在性证明验证失败" << endl;
    }
    
    return 0;
}