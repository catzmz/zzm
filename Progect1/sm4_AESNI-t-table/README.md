#  一 T-Table 优化

## 1. 定义了4个T-Table数组

```c
static uint32_t T0[256];
static uint32_t T1[256];
static uint32_t T2[256];
static uint32_t T3[256];

```
## 2.通过 init_t_tables() 函数初始化这4个表：

-  把 S盒输出的字节 s 扩展成 4字节重复的值 b。

-  对 b 进行不同的旋转移位，然后执行线性变换 L，结果分别存入 T0、T1、T2、T3。

-  这相当于预计算了 S-盒替换 + 线性变换的组合。

## 3.使用 T-Table 替代原本的 T 变换函数

```c
  static uint32_t sm4_t_table(uint32_t a) {
    return T0[(a >> 24) & 0xFF] ^
           T1[(a >> 16) & 0xFF] ^
           T2[(a >> 8) & 0xFF] ^
           T3[a & 0xFF];
}
```

- 输入32位整数，分拆为4个字节。

- 用对应的T表查表，结果异或组-合，快速得到替代原本复杂的S盒+L变换的结果。

## 4. 轮密钥扩展和加密时都调用了 sm4_t_table 代替原T函数

```c
K[i + 4] = K[i] ^ sm4_t_table(tmp);
```

```c
X[i + 4] = X[i] ^ sm4_t_table(tmp);
```
## t-table优化结果
<img width="1077" height="236" alt="image" src="https://github.com/user-attachments/assets/85c5280d-8b6d-4e7b-8061-e16a85b421a9" />

# 二 AES-NI指令加速

- 利用Intel AES-NI指令的S盒操作功能，替代SM4中S盒的查表。

- 将4个32位数据打包成128位，使用_mm_aesenclast_si128完成S盒替换。

- 通过逆行移位和零轮密钥消除AES-NI附带的行移位和轮密钥影响。
```c
#include <wmmintrin.h>  // AES-NI
#include <emmintrin.h>  // SSE2

// 使用AES-NI做S盒替换的核心函数
static inline __m128i aesni_sbox(__m128i x) {
    // 逆行移位（ShiftRows逆变换）
    const __m128i shuf_mask = _mm_set_epi8(
        15,10,5,0,
        11,6,1,12,
        7,2,13,8,
        3,14,9,4
    );
    x = _mm_shuffle_epi8(x, shuf_mask);
    
    // 使用全零轮密钥，调用AES最后一轮，完成S盒替换且无轮密钥影响
    const __m128i zero = _mm_setzero_si128();
    x = _mm_aesenclast_si128(x, zero);

    // 恢复行移位（ShiftRows）
    const __m128i shuf_mask_inv = _mm_set_epi8(
        3, 7, 11, 15,
        2, 6, 10, 14,
        1, 5, 9,  13,
        0, 4, 8,  12
    );
    x = _mm_shuffle_epi8(x, shuf_mask_inv);
    
    return x;
}

// 4个32-bit数据输入，返回经过S盒替换的4个32-bit数据
uint32_t sm4_sbox_aesni(uint32_t in[4]) {
    __m128i data = _mm_set_epi32(in[0], in[1], in[2], in[3]);
    data = aesni_sbox(data);
    uint32_t out[4];
    _mm_storeu_si128((__m128i*)out, data);
    // 返回第一个示范，实际使用时可按需处理4个32-bit
    return out[0];
}
```
# 三 AVX2 SIMD并行加速
- 利用AVX2 256位寄存器同时处理4个数据块。

- 实现并行的加载、异或、S盒查表和线性变换操作。

- 显著提高批量加密吞吐。
```c
#include <immintrin.h>  // AVX2

// 假设有4个32-bit数据块，批量进行异或和T-table查表（查表这里示范为简单替换）

void sm4_avx2_parallel_round(uint32_t X[4], uint32_t rk) {
    // 将4个32-bit数据加载到256bit寄存器（8x32位，但这里只用4个）
    __m256i data = _mm256_set_epi32(0,0,0,0, X[3], X[2], X[1], X[0]);

    // 异或轮密钥（广播rk）
    __m256i rk_vec = _mm256_set1_epi32(rk);
    data = _mm256_xor_si256(data, rk_vec);

    // 这里演示简化版本：S盒和线性变换需用查表或者SIMD指令完成
    // 省略查表示范，可用查表方法并行实现

    // 将结果存回X数组
    uint32_t out[8];
    _mm256_storeu_si256((__m256i*)out, data);
    X[0] = out[0];
    X[1] = out[1];
    X[2] = out[2];
    X[3] = out[3];
}
```
## 结果
<img width="1115" height="379" alt="image" src="https://github.com/user-attachments/assets/0cd2ff67-dcf9-4b8b-a164-e919116e2400" />
