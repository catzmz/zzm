# 1. SM3 基本实现与性能优化
## 基础原理
SM3 是一种国产密码哈希算法，采用 Merkle–Damgård 结构，处理 512-bit 消息块，输出 256-bit 哈希值。核心步骤包括：

填充：按规则补足消息长度（追加 0x80、0x00、64-bit 消息长度）。

迭代压缩：对每个块调用压缩函数，更新 8 个 32-bit 中间状态（V0-V7），最终拼接为哈希值。

## 优化方向

SIMD/AVX2：利用单指令多数据（SIMD）并行处理多个消息块或压缩步骤，例如同时计算多个消息块的布尔函数或循环移位。

预计算常量：将算法中的固定常量（如 T_j）预先存储，减少运行时计算。

循环展开：手动展开压缩函数的循环，减少分支预测开销。

# 2. 长度扩展攻击（Length-Extension Attack）
## 攻击原理
SM3 的 Merkle–Damgård 结构 导致内部状态等价于哈希输出。攻击者已知 H(key || msg) 和 msg 的长度时：

构造填充：在 msg 后补 0x80、0x00 和长度字段，形成合法填充块 padding。

扩展数据：将 H(key || msg) 作为初始状态，继续压缩新数据 extension，得到伪造哈希 H'。

验证攻击：服务器计算 H(key || msg || padding || extension) 会与 H' 匹配，因为两者共享相同的初始状态。

## 关键点

攻击者无需知道 key，仅需哈希值和原始消息长度。

填充规则必须严格遵循（如大端长度编码）。

# 3. Merkle 树构建与证明
## 构建规则（RFC6962）

叶子节点：leaf_hash = SM3(0x00 || data)（前缀 0x00 标识叶子）。

内部节点：node_hash = SM3(0x01 || left_hash || right_hash)（前缀 0x01 标识内部节点）。

平衡处理：若节点数为奇数，复制最后一个节点保证完全二叉树结构。

## 存在性证明

路径构造：从目标叶子到根路径上的所有兄弟节点哈希及方向（左/右）。

验证：逐层计算父节点哈希，最终与根哈希比对。

## 不存在性证明

有序性：假设叶子按字典序排列，找到目标数据相邻的两个叶子。

证明：提供这两个叶子的存在性证明，并验证目标数据不在两者之间。

# 关键代码逻辑
```python
def length_extension_attack(original_hash, original_length, extension):
    # 构造填充
    padding = b'\x80' + b'\x00' * ((56 - (original_length + 1) % 64) % 64)
    padding += (original_length * 8).to_bytes(8, 'big')  # 64-bit 长度
    
    # 将 original_hash 作为初始状态，继续处理 extension
    forged_hash = SM3(extension, initial_state=original_hash)
    
    # 服务器计算的合法哈希
    legitimate_hash = SM3(key + msg + padding + extension)
    
    return forged_hash == legitimate_hash
```
## Merkle 树存在性验证
```python
def verify_proof(leaf_hash, proof, root_hash):
    current_hash = leaf_hash
    for sibling_hash, direction in proof:
        if direction == 'left':
            current_hash = SM3(0x01 + sibling_hash + current_hash)
        else:
            current_hash = SM3(0x01 + current_hash + sibling_hash)
    return current_hash == root_hash
```
## 实验结果

### 1. SM3 优化
<img width="965" height="577" alt="image" src="https://github.com/user-attachments/assets/eff9f0d2-9a12-4700-82b6-7539072ae324" />


### 2. Length-Extension Attack 


<img width="1483" height="762" alt="image" src="https://github.com/user-attachments/assets/4ad545e5-8a6a-4018-8c05-c83f0caa8f50" />


### 3. Merkle 树运行结果

<img width="995" height="570" alt="image" src="https://github.com/user-attachments/assets/3c7645a8-8cfb-4912-9ea9-6541e656864b" />


