import cv2
import numpy as np
import pywt
import os
from typing import Tuple, Optional, Dict, Any


class DigitalWatermarkProcessor:
    """
    基于DWT-SVD的数字水印处理系统
    实现水印嵌入、提取和鲁棒性测试功能
    """

    def __init__(self, embedding_strength: float = 0.1):
        """
        初始化水印处理器
        :param embedding_strength: 水印嵌入强度系数
        """
        self.embedding_factor = embedding_strength
        self.wavelet_type = 'haar'  # 使用haar小波基

    def _matrix_decomposition(self, matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        执行矩阵奇异值分解
        :param matrix: 输入矩阵
        :return: (U矩阵, 奇异值数组, V矩阵)
        """
        return np.linalg.svd(matrix, full_matrices=False)

    def _insert_watermark(self,
                          host_coefficients: Tuple[np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]],
                          mark_coefficients: Tuple[np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]]) -> Tuple[
        np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """
        在宿主图像系数中嵌入水印
        """
        # 获取低频分量
        host_LL = host_coefficients[0]
        mark_LL = mark_coefficients[0]

        # 执行SVD分解
        host_U, host_S, host_V = self._matrix_decomposition(host_LL)
        _, mark_S, _ = self._matrix_decomposition(mark_LL)

        # 调整水印奇异值长度
        adjusted_mark_S = np.pad(mark_S[:len(host_S)], (0, len(host_S) - len(mark_S)), 'constant')

        # 嵌入水印
        modified_S = host_S + self.embedding_factor * adjusted_mark_S

        # 重建低频分量
        sigma_matrix = np.diag(modified_S)
        modified_LL = host_U @ sigma_matrix @ host_V

        return (modified_LL, host_coefficients[1])

    def _retrieve_watermark(self,
                            marked_coefficients: Tuple[np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]],
                            original_coefficients: Tuple[np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]],
                            original_mark_LL: np.ndarray) -> np.ndarray:
        """
        从含水印图像中提取水印
        """
        # 分解含水印图像和原始图像
        marked_U, marked_S, marked_V = self._matrix_decomposition(marked_coefficients[0])
        _, original_S, _ = self._matrix_decomposition(original_coefficients[0])

        # 提取水印奇异值
        extracted_S = (marked_S - original_S) / self.embedding_factor

        # 获取原始水印矩阵信息
        mark_U, _, mark_V = self._matrix_decomposition(original_mark_LL)
        rows, cols = original_mark_LL.shape

        # 重建水印低频分量
        sigma_matrix = np.zeros((rows, cols))
        diag_length = min(rows, cols, len(extracted_S))
        np.fill_diagonal(sigma_matrix[:diag_length, :diag_length], extracted_S[:diag_length])

        return mark_U @ sigma_matrix @ mark_V

    def embed_watermark(self,
                        host_image_path: str,
                        watermark_image_path: str,
                        output_path: str) -> np.ndarray:
        """
        将水印嵌入宿主图像
        """
        # 读取并预处理图像
        host_img = cv2.imread(host_image_path)
        if host_img is None:
            raise FileNotFoundError(f"宿主图像未找到: {host_image_path}")

        height, width = host_img.shape[:2]
        y_channel = cv2.cvtColor(host_img, cv2.COLOR_BGR2YUV)[:, :, 0]

        watermark_img = cv2.imread(watermark_image_path, cv2.IMREAD_GRAYSCALE)
        if watermark_img is None:
            raise FileNotFoundError(f"水印图像未找到: {watermark_image_path}")

        resized_watermark = cv2.resize(watermark_img, (width // 2, height // 2))

        # 小波变换
        host_coeffs = pywt.dwt2(y_channel, self.wavelet_type)
        watermark_coeffs = pywt.dwt2(resized_watermark, self.wavelet_type)

        # 嵌入水印
        modified_coeffs = self._insert_watermark(host_coeffs, watermark_coeffs)

        # 逆变换重建图像
        modified_y = pywt.idwt2(modified_coeffs, self.wavelet_type)
        modified_y = cv2.resize(modified_y, (width, height))

        # 合并通道并保存
        output_img = host_img.copy()
        output_img[:, :, 0] = np.clip(modified_y, 0, 255).astype('uint8')
        cv2.imwrite(output_path, output_img)

        print(f"水印嵌入完成，结果保存至: {output_path}")
        return output_img

    def extract_watermark(self,
                          marked_image_path: str,
                          original_image_path: str,
                          original_watermark_path: str,
                          output_path: str,
                          output_size: Tuple[int, int] = (128, 128)) -> np.ndarray:
        """
        从含水印图像中提取水印
        """
        # 读取并预处理图像
        original_img = cv2.imread(original_image_path)
        marked_img = cv2.imread(marked_image_path)

        if original_img is None or marked_img is None:
            raise FileNotFoundError("原始图像或含水印图像未找到")

        # 确保尺寸一致
        orig_height, orig_width = original_img.shape[:2]
        if marked_img.shape[:2] != (orig_height, orig_width):
            marked_img = cv2.resize(marked_img, (orig_width, orig_height))

        # 获取Y通道
        original_y = cv2.cvtColor(original_img, cv2.COLOR_BGR2YUV)[:, :, 0]
        marked_y = cv2.cvtColor(marked_img, cv2.COLOR_BGR2YUV)[:, :, 0]

        # 读取原始水印作为参考
        original_watermark = cv2.imread(original_watermark_path, cv2.IMREAD_GRAYSCALE)
        if original_watermark is None:
            raise FileNotFoundError(f"原始水印图像未找到: {original_watermark_path}")

        resized_watermark = cv2.resize(original_watermark, (orig_width // 2, orig_height // 2))

        # 小波变换
        marked_coeffs = pywt.dwt2(marked_y, self.wavelet_type)
        original_coeffs = pywt.dwt2(original_y, self.wavelet_type)
        watermark_coeffs = pywt.dwt2(resized_watermark, self.wavelet_type)

        # 提取水印
        extracted_LL = self._retrieve_watermark(marked_coeffs, original_coeffs, watermark_coeffs[0])
        extracted_coeffs = (extracted_LL, watermark_coeffs[1])

        # 逆变换重建水印
        reconstructed_watermark = pywt.idwt2(extracted_coeffs, self.wavelet_type)
        reconstructed_watermark = cv2.resize(reconstructed_watermark, output_size)

        # 归一化并保存
        cv2.normalize(reconstructed_watermark, reconstructed_watermark, 0, 255, cv2.NORM_MINMAX)
        cv2.imwrite(output_path, reconstructed_watermark.astype('uint8'))

        return reconstructed_watermark


def compute_similarity(image1: np.ndarray, image2: np.ndarray) -> float:
    """
    计算两幅图像的归一化相关系数
    """
    if image1 is None or image2 is None:
        return 0.0

    # 转换为浮点型并调整尺寸
    img1 = image1.astype(np.float64)
    img2 = cv2.resize(image2, (image1.shape[1], image1.shape[0])).astype(np.float64)

    # 计算分子和分母
    numerator = np.sum(img1 * img2)
    denominator = np.sqrt(np.sum(img1 ** 2)) * np.sqrt(np.sum(img2 ** 2))

    return numerator / denominator if denominator != 0 else 0.0


def evaluate_robustness(processor: DigitalWatermarkProcessor,
                        test_parameters: Dict[str, Any]) -> None:
    """
    评估水印系统的鲁棒性
    """
    print("\n=== 水印鲁棒性测试 ===")

    # 创建测试目录
    os.makedirs(test_parameters['output_dir'], exist_ok=True)

    # 定义各种攻击类型
    attack_methods = {
        '无攻击': lambda x: x,
        'JPEG压缩(50)': lambda x: (cv2.imencode('.jpg', x, [cv2.IMWRITE_JPEG_QUALITY, 50])[1].tobytes(), '.jpg'),
        '高斯噪声(20)': lambda x: cv2.add(x, np.random.normal(0, 20, x.shape).astype('uint8')),
        '水平翻转': lambda x: cv2.flip(x, 1),
        '对比度增强(1.5x)': lambda x: cv2.convertScaleAbs(x, alpha=1.5, beta=0),
        '中心裁剪(25%)': lambda x: x[x.shape[0] // 8:-x.shape[0] // 8, x.shape[1] // 8:-x.shape[1] // 8],
        '旋转(5度)': lambda x: cv2.warpAffine(
            x,
            cv2.getRotationMatrix2D((x.shape[1] / 2, x.shape[0] / 2), 5, 1.0),
            (x.shape[1], x.shape[0])
        )
    }

    # 加载原始水印
    original_mark = cv2.imread(test_parameters['watermark_path'], 0)

    for attack_name, attack_func in attack_methods.items():
        try:
            # 应用攻击
            attacked_img = attack_func(cv2.imread(test_parameters['marked_image_path']))
            file_ext = '.png'

            # 特殊处理JPEG压缩
            if isinstance(attacked_img, tuple):
                attacked_img, file_ext = attacked_img
                attacked_img = cv2.imdecode(np.frombuffer(attacked_img, np.uint8), cv2.IMREAD_COLOR)

            # 保存攻击后的图像
            attack_path = os.path.join(
                test_parameters['output_dir'],
                f"attacked_{attack_name.replace(' ', '_').replace('(', '').replace(')', '')}{file_ext}"
            )
            cv2.imwrite(attack_path, attacked_img)

            # 提取水印
            extracted_path = os.path.join(
                test_parameters['output_dir'],
                f"extracted_{attack_name.replace(' ', '_').replace('(', '').replace(')', '')}.png"
            )
            extracted = processor.extract_watermark(
                attack_path,
                test_parameters['original_image_path'],
                test_parameters['watermark_path'],
                extracted_path
            )

            # 计算相似度
            similarity = compute_similarity(original_mark, extracted)
            print(f"{attack_name:<20} | 相似度: {similarity:.4f}")

        except Exception as e:
            print(f"{attack_name:<20} | 失败: {str(e)}")


if __name__ == '__main__':
    # 配置路径
    PROJECT_DIR = r"E:\desktop\AIsecurity\task1"
    PATHS = {
        'original': os.path.join(PROJECT_DIR, "picture.png"),
        'watermark': os.path.join(PROJECT_DIR, "water.png"),
        'marked': os.path.join(PROJECT_DIR, "picture_watermarked.png"),
        'extracted': os.path.join(PROJECT_DIR, "watermark_extracted.png"),
        'test_results': os.path.join(PROJECT_DIR, "robustness_tests")
    }

    # 初始化处理器
    watermark_system = DigitalWatermarkProcessor(embedding_strength=0.05)

    # 1. 嵌入水印
    try:
        marked_image = watermark_system.embed_watermark(
            PATHS['original'],
            PATHS['watermark'],
            PATHS['marked']
        )
    except Exception as e:
        print(f"水印嵌入失败: {str(e)}")
        exit(1)

    # 2. 提取水印
    try:
        extracted_mark = watermark_system.extract_watermark(
            PATHS['marked'],
            PATHS['original'],
            PATHS['watermark'],
            PATHS['extracted']
        )

        # 计算相似度
        original_mark = cv2.imread(PATHS['watermark'], 0)
        similarity_score = compute_similarity(original_mark, extracted_mark)
        print(f"\n初始提取水印相似度: {similarity_score:.4f}")
    except Exception as e:
        print(f"水印提取失败: {str(e)}")
        exit(1)

    # 3. 鲁棒性测试
    test_config = {
        'original_image_path': PATHS['original'],
        'watermark_path': PATHS['watermark'],
        'marked_image_path': PATHS['marked'],
        'output_dir': PATHS['test_results']
    }

    evaluate_robustness(watermark_system, test_config)