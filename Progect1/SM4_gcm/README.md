# 一. SM4-GCM基本原理
SM4-GCM结合了CTR模式的加密和GMAC的认证功能，具有以下特点：

- 并行计算能力

- 高效认证加密

# 1.1 GCM模式结构
GCM包含两个主要部分：

- 加密部分：使用CTR模式加密

- 认证部分：使用GHASH函数计算认证标签

# 2. 关键优化技术
# 1. 密钥扩展（Key Schedule）
- 函数：sm4_key_schedule
   - 作用：输入 128 位密钥 key，结合系统参数 FK、CK 生成 32 个轮密钥 rk（每个 32 位）。
   - 核心公式是 SM4 轮函数（sm4_round）+ 密钥异或。

# 2. SM4 单块加密（Block Cipher）
- 函数：sm4_encrypt_block
  - 作用：对 128 位明文块进行 32 轮 SM4 加密。

输出 128 位密文块。

在 GCM 中的用途：

生成哈希子密钥 H = E_K(0¹²⁸)

生成计数器模式的密钥流。

# 3. Galois域乘法（GHASH核心）
函数：gf128_mul

作用：

在 GF(2¹²⁸) 有限域上进行多项式乘法（模一个固定不可约多项式）。

用于计算消息认证码（MAC）。

# 4. 初始化（Init）
函数：sm4_gcm_init

作用：

生成轮密钥 rk

计算哈希子密钥 H

根据 IV 计算初始计数器块 J0

如果 IV 长度是 12 字节：J0 = IV || 0x00000001

否则：J0 = GHASH_H(IV || padding || len(IV))

清零 len_aad、len_plain（后续计算标签时要用）。

# 5. 处理附加认证数据（AAD）
函数：sm4_gcm_aad

作用：

把 AAD 按 128 位块分组，每块与当前 GHASH 状态异或，然后做一次 gf128_mul。

更新 len_aad。

# 6. 加密 / 解密（CTR模式 + GHASH）
函数：sm4_gcm_crypt

加密过程：

复制 J0 为计数器，先自增 1。

每次用 SM4 加密计数器，得到密钥流。

明文 XOR 密钥流 → 得到密文。

将密文块 XOR 到 GHASH 状态，并执行 gf128_mul。

解密过程（相同函数）：

因为 CTR 模式加密和解密是同一操作（只换输入是密文），同样会更新 GHASH（这里用密文块参与认证）。

# 7. 生成认证标签
函数：sm4_gcm_tag

作用：

构造长度块：len(AAD) 和 len(Ciphertext)（比特数）。

把 GHASH 状态与长度块 XOR 并做一次 gf128_mul → 得到 S。

计算 T = E_K(J0) ⊕ S。

截取前 tag_len 字节作为认证标签。


# 运行结果
<img width="600" height="629" alt="image" src="https://github.com/user-attachments/assets/dec378b6-8b88-4337-9b5b-81d6d483d656" />
