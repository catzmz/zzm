# 1. 核心原理
本系统基于离散小波变换(DWT)和奇异值分解(SVD)的混合算法，通过频域和矩阵分解的结合实现鲁棒性水印：

频域特性（DWT）：

将图像分解为低频(LL)、水平(LH)、垂直(HL)和高频(HH)子带

水印嵌入在低频分量(LL)中，平衡不可见性和鲁棒性

矩阵稳定性（SVD）：

对低频子带进行SVD分解：A = U·S·V^T

奇异值(S)具有稳定性，对常见图像处理操作不敏感

# 2. 关键方法实现
## (1) 水印嵌入流程
```python
def embed_watermark():
    # 1. 预处理
    host_img = 读取宿主图像(YUV取Y通道)
    watermark = 读取水印图像(灰度化+缩放到宿主1/2尺寸)

    # 2. DWT分解
    host_LL, (LH,HL,HH) = pywt.dwt2(宿主Y通道, 'haar')
    wm_LL, _ = pywt.dwt2(水印图像, 'haar')

    # 3. SVD嵌入
    U_host, S_host, V_host = svd(host_LL)
    _, S_wm, _ = svd(wm_LL)
    S_modified = S_host + α * S_wm  # α为嵌入强度因子
    new_LL = U_host @ diag(S_modified) @ V_host

    # 4. 逆变换重建
    embedded_y = pywt.idwt2((new_LL, (LH,HL,HH)), 'haar')
    合并Y通道并保存结果
```
# (2) 水印提取流程
```python
def extract_watermark():
    # 1. 预处理
    marked_img = 读取含水印图像(Y通道)
    original_img = 读取原图(Y通道)
    original_wm = 读取原始水印(用于尺寸参考)

    # 2. DWT分解
    marked_LL, _ = pywt.dwt2(含水印Y通道)
    original_LL, _ = pywt.dwt2(原始Y通道)
    wm_LL, _ = pywt.dwt2(原始水印)

    # 3. SVD提取
    U_marked, S_marked, V_marked = svd(marked_LL)
    _, S_original, _ = svd(original_LL)
    S_extracted = (S_marked - S_original) / α

    # 4. 重建水印
    extracted_LL = U_wm @ diag(S_extracted) @ V_wm
    reconstructed = pywt.idwt2((extracted_LL, 原始高频子带))
```
## 3. 鲁棒性设计
攻击类型	防御机制
JPEG压缩	低频分量嵌入+SVD稳定性
噪声	小波阈值去噪能力
几何变换	通过宿主图像尺寸归一化处理
对比度调整	YUV色彩空间分离，仅修改亮度(Y)通道
裁剪/旋转	水印分散在多个DWT系数中
## 4. 关键技术点
频域选择：

选择Haar小波因其计算效率高且适合图像处理

LL子带包含图像主要能量，修改后视觉影响小

强度控制：
```python
self.embedding_factor = 0.05  # 典型值范围0.01-0.1
```
过小：鲁棒性不足

过大：影响图像质量

矩阵维度处理：

动态调整SVD分解后的矩阵维度：
```python
diag_length = min(rows, cols, len(extracted_S))
np.fill_diagonal(sigma_matrix[:diag_length, :diag_length], ...)
```



diag_length = min(rows, cols, len(extracted_S))
np.fill_diagonal(sigma_matrix[:diag_length, :diag_length], ...)
