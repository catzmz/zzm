# SM2实现
# 1. 参数初始化
## SM2 的实现首先需要初始化标准参数：

定义椭圆曲线参数：素数域 p、曲线方程系数 a 和 b

指定基点 G（生成元）及其阶 n

生成密钥对：随机选择私钥 d，计算公钥 P = d×G

# 2. 椭圆曲线基础运算
点加法
实现椭圆曲线上两个点的加法运算，处理各种特殊情况：

一个点是无穷远点的情况

两点相同的情况（转为倍点运算）

两点x坐标相同但y坐标不同的情况（结果为无穷远点）

一般情况下的点加法

点倍乘
实现椭圆曲线上一个点的倍乘运算（即点加自身），使用斜率公式计算。

标量乘法
实现 k×P 的高效计算，采用滑动窗口优化方法：

预计算常用点以加速运算

将标量 k 表示为二进制形式

使用窗口技术减少加法运算次数

组合预计算结果得到最终点

# 3. 加密/解密实现
加密过程
对明文进行编码处理

生成随机数 k

计算椭圆曲线点 C1 = k×G

计算共享秘密 S = k×P（P 是接收方公钥）

使用密钥派生函数 (KDF) 从 S 的坐标派生对称密钥

用对称密钥加密明文得到密文 C2

计算消息认证码 C3（使用SM3哈希）

输出密文 (C1, C2, C3)

解密过程
从密文中提取 C1 并验证其在曲线上

计算共享秘密 S = d×C1（d 是接收方私钥）

使用 KDF 从 S 的坐标派生对称密钥

用对称密钥解密密文 C2 得到明文

验证消息认证码 C3 的正确性

# 4. 签名/验签实现
签名过程
计算 ZA（用户标识和系统参数的哈希）

组合 ZA 和待签名消息进行哈希得到 e

生成随机数 k

计算椭圆曲线点 (x1, y1) = k×G

计算 r = (e + x1) mod n

计算 s = ((1 + d)^-1 × (k - r×d)) mod n

输出签名 (r, s)

验签过程
验证 r 和 s 在有效范围内

计算 ZA 和消息哈希 e

计算 t = (r + s) mod n

计算椭圆曲线点 (x1, y1) = s×G + t×P

验证 R = (e + x1) mod n 是否等于 r

# sm2实现结果
<img width="1278" height="135" alt="image" src="https://github.com/user-attachments/assets/50de86eb-0b1b-4131-86e8-7f6d97f4efc5" />






# 基于做poc验证


## 推导文档

给定两条使用相同k的签名：

第一条签名：

text
r1 = (e1 + x1) mod n
s1 = (1 + d)^-1 * (k - r1*d) mod n
第二条签名：

text
r2 = (e2 + x1) mod n  # 注意x1相同因为k相同
s2 = (1 + d)^-1 * (k - r2*d) mod n
由于k相同，我们可以建立方程组：

从s1和s2的表达式可以得到：

text
s1*(1 + d) ≡ k - r1*d mod n
s2*(1 + d) ≡ k - r2*d mod n
将两式相减：

text
(s1 - s2)*(1 + d) ≡ (r2 - r1)*d mod n
展开并整理：

text
(s1 - s2) + (s1 - s2)*d ≡ (r2 - r1)*d mod n
将所有含d的项移到一边：

text
(s1 - s2) ≡ [(r2 - r1) - (s1 - s2)]*d mod n
最终得到私钥d的表达式：

text
d ≡ (s1 - s2) * [(r2 - r1 - s1 + s2)^-1] mod n

# 实验结果
<img width="1489" height="510" alt="image" src="https://github.com/user-attachments/assets/6b1b88c6-1ebc-481f-b31f-6e23d53d95f5" />

# 伪造中本聪的数字签名
## . 伪造方法分析
### (1) 随机数（k）重用攻击
ECDSA 签名公式：

r = (k × G).x mod N

s = (H(m) + r × d) × k⁻¹ mod N

如果同一个 k 被用于两个不同的签名，攻击者可以解方程求出私钥 d：

已知两个签名 (r, s1) 和 (r, s2)，对应消息 m1 和 m2：

s1 = (H(m1) + r × d) × k⁻¹ mod N

s2 = (H(m2) + r × d) × k⁻¹ mod N

联立方程解出 d。但实际不可行：
<img width="1348" height="364" alt="image" src="https://github.com/user-attachments/assets/af5f001f-3169-4eae-8d9d-42bdc722fb92" />


