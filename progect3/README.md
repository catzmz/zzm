# 实现思路
## Poseidon2 参数

提供了两个参数组合 (n,t,d)=(256,3,5) 或 (256,2,5)

 n=256 是安全参数（位长），t 是状态大小，d 是S-box的指数。

先选择一个，例如 (256,3,5)，即状态长度 3，非线性指数 5。

## 电路设计

公开输入(public input)：Poseidon2的哈希值（digest）

隐私输入(private input)：哈希的原象（原始输入block）

只考虑单个block输入，不考虑多块输入的拼接

## 电路实现

需在circom里实现Poseidon2哈希函数

主要包括：

状态初始化

多轮的S-box非线性映射（每轮指数d次方）

轮常数和MDS矩阵的线性层（矩阵乘法）


## 证明生成

使用Groth16证明系统生成zkSNARK证明

公开哈希值，证明你知道一个原象满足哈希值等于公开值

# 具体步骤示例
## 1. 创建Poseidon2电路文件 poseidon2.circom
```python
pragma circom 2.0.0;

template Poseidon2(t) {
    // 状态数组大小t
    signal input in[t];     // 私密输入，block数据
    signal output out;      // 输出哈希值 (这里只输出第一个状态元素作为哈希结果)

    // 轮常数和MDS矩阵（需根据论文填充）
    // 这里简化，只用伪造常数和矩阵演示结构

    // 假设进行r轮，每轮：
    // 1) 对每个状态元素执行sbox，即 x^5
    // 2) 加入轮常数
    // 3) 乘以MDS矩阵

    // 具体参数如下（演示用，非真实参数）
    var rounds = 8; // 实际轮数要参考论文
    var rc = [
        [1,2,3],
        [4,5,6],
        [7,8,9],
        [10,11,12],
        [13,14,15],
        [16,17,18],
        [19,20,21],
        [22,23,24]
    ];
    var mds = [
        [2,3,1],
        [1,2,3],
        [3,1,2]
    ];

    signal state[t];
    for (var i = 0; i < t; i++) {
        state[i] <== in[i];
    }

    for (var r = 0; r < rounds; r++) {
        // S-box: x^5
        for (var i = 0; i < t; i++) {
            var x = state[i];
            // pow5 = x^5 = x*x*x*x*x
            // 为性能，展开乘法，不用pow函数
            signal pow5 = x * x * x * x * x;
            state[i] <== pow5 + rc[r][i];
        }

        // MDS矩阵乘法
        signal newState[t];
        for (var i = 0; i < t; i++) {
            newState[i] <== 0;
            for (var j = 0; j < t; j++) {
                newState[i] <== newState[i] + mds[i][j] * state[j];
            }
        }
        for (var i = 0; i < t; i++) {
            state[i] <== newState[i];
        }
    }

    out <== state[0];
}

component main = Poseidon2(3);
```
## 2. 编写 poseidon2_test.circom 作为主电路示例
```python
pragma circom 2.0.0;

include "poseidon2.circom";

template Poseidon2Verifier() {
    signal input hash;       // 公开输入，poseidon2哈希值
    signal private input preimage[3]; // 私有输入，3元素block

    component poseidon = Poseidon2(3);
    for (var i=0; i<3; i++) {
        poseidon.in[i] <== preimage[i];
    }

    // 断言计算哈希等于公开哈希
    poseidon.out === hash;
}

component main = Poseidon2Verifier();
```
## 3. 编译、生成证明和验证
```python
# 编译电路
circom poseidon2_test.circom --r1cs --wasm --sym -o build

# 生成trusted setup
snarkjs groth16 setup build/poseidon2_test.r1cs pot12_final.ptau poseidon2_test_0000.zkey
snarkjs groth16 contribute poseidon2_test_0000.zkey poseidon2_test_final.zkey

# 生成证明
# 假设生成信号输入文件 input.json
snarkjs groth16 prove poseidon2_test_final.zkey witness.wtns proof.json public.json

# 验证证明
snarkjs groth16 verify verification_key.json public.json proof.json

```

