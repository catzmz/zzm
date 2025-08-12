# 赵梓萌 202200460072 
# 详细内容见各个项目readme.md
# Project 1: 做SM4的软件实现和优化 
a): 从基本实现出发 优化SM4的软件执行效率，至少应该覆盖T-table、AESNI以及最新的指令集（GFNI、VPROLD等）
b): 基于SM4的实现，做SM4-GCM工作模式的软件优化实现

# Project 2: 基于数字水印的图片泄露检测 
编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等

# Project 3: 用circom实现poseidon2哈希算法的电路
1) poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)
2）电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可。
3) 用Groth16算法生成证明
参考文档：
1. poseidon2哈希算法https://eprint.iacr.org/2023/323.pdf
2. circom说明文档https://docs.circom.io/
3. circom电路样例 https://github.com/iden3/circomlib


# Project 4: SM3的软件实现与优化 
a）：与Project 1类似，从SM3的基本软件实现出发，参考付勇老师的PPT，不断对SM3的软件执行效率进行改进
b）：基于sm3的实现，验证length-extension attack
c）：基于sm3的实现，根据RFC6962构建Merkle树（10w叶子节点），并构建叶子的存在性证明和不存在性证明


# Project 5: SM2的软件实现优化 
a). 考虑到SM2用C 语言来做比较复杂，大家看可以考虑用python来做 sm2的 基础实现以及各种算法的改进尝试
b). 20250713-wen-sm2-public.pdf 中提到的关于签名算法的误用 分别基于做poc验证，给出推导文档以及验证代码
c). 伪造中本聪的数字签名

# Project 6:  Google Password Checkup验证
来自刘巍然老师的报告  google password checkup，参考论文 https://eprint.iacr.org/2019/723.pdf 的 section 3.1 ，也即 Figure 2 中展示的协议，尝试实现该协议，（编程语言不限）。
