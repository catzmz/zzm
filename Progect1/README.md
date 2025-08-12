#  T-Table 优化

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
# 结果
<img width="1077" height="236" alt="image" src="https://github.com/user-attachments/assets/85c5280d-8b6d-4e7b-8061-e16a85b421a9" />

<img width="1077" height="236" alt="image" src="https://github.com/user-attachments/assets/fc3a315e-9a32-45b8-994b-34af3683829d" />










