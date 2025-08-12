# 1. 实验原理
本实验实现了一个隐私保护的集合交集求和协议（Private Intersection-Sum），目标是在不泄露双方原始数据的情况下，计算两个私有集合的交集元素的关联数值之和。


<img width="800" height="539" alt="image" src="https://github.com/user-attachments/assets/28559fd1-9681-4af7-ba74-0370234cca48" />

## 核心密码学技术
DDH（Decisional Diffie-Hellman）假设

用于保护集合元素的隐私，确保双方无法推断非交集成员。

通过双盲化（H(v)^(k1·k2)）隐藏原始标识符。

## Paillier 同态加密

支持密文加法运算 Enc(a) ⊙ Enc(b) = Enc(a + b)，用于安全求和。

只有 P2 能解密最终结果，P1 无法获取中间值。

## 随机预言机（Random Oracle）

使用哈希函数 H: 𝒰 → 𝒢 将标识符映射到群元素，模拟理想哈希。

## 关键实现
```python
# P1 第一轮
def party1_round1(V):
    return [pow(H(v), k1, p) for v in V]  # 发送 {H(v)^k1}

# P2 第二轮
def party2_round2(C_list, W):
    Z = [pow(c, k2, p) for c in C_list]    # 计算 {H(v)^(k1·k2)}
    D_E_pairs = [(pow(H(w), k2, p), Enc(t)) for w, t in W]
    return Z, D_E_pairs                    # 发送 Z 和 {(H(w)^k2, Enc(t))}

# P1 第三轮
def party1_round3(Z, D_E_pairs):
    sum_ciphertext = Enc(0)
    for D, E in D_E_pairs:
        if pow(D, k1, p) in Z:             # 检查是否在交集中
            sum_ciphertext += E            # 同态求和
    return sum_ciphertext                  # 发送 Enc(Σtⱼ)
```
# 实验结果
<img width="1281" height="417" alt="image" src="https://github.com/user-attachments/assets/eab05fe6-2c49-41da-bbc0-71687722355e" />

