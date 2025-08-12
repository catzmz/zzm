from gmssl import sm3, func
from Crypto.Util.number import *
import hashlib
import os
from random import SystemRandom
from typing import Tuple


class SM2:
    def __init__(self) -> None:
        # 国密SM2标准参数
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.G = (0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
                  0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)

        # 安全随机数生成
        self.rand_gen = SystemRandom()
        self.d = self.rand_gen.randint(1, self.n - 1)
        self.P = self.optimized_mul(self.d, self.G)
        self._entropy = os.urandom(32)  # 增强随机性

    def is_on_curve(self, P):
        """验证点是否在曲线上"""
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, P, Q):
        """椭圆曲线点加法"""
        if not P:
            return Q
        if not Q:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if y1 != y2:
                return None
            return self.double(P)

        lam = (y2 - y1) * inverse(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def double(self, P):
        """椭圆曲线点倍乘"""
        if not P:
            return P

        x, y = P
        lam = (3 * x * x + self.a) * inverse(2 * y, self.p) % self.p
        x3 = (lam * lam - 2 * x) % self.p
        y3 = (lam * (x - x3) - y) % self.p
        return (x3, y3)

    def optimized_mul(self, k, P):
        """滑动窗口优化的标量乘法"""
        # 预计算2^i * P的点
        precomp = [None] * 16
        precomp[0] = None
        precomp[1] = P
        for i in range(2, 16, 2):
            precomp[i] = self.double(precomp[i // 2])
            precomp[i + 1] = self.add(precomp[i], P)

        # 滑动窗口处理
        acc = None
        window_size = 4
        k_bin = bin(k)[2:]
        n = len(k_bin)
        i = n - 1

        while i >= 0:
            if k_bin[i] == '0':
                acc = self.double(acc) if acc else None
                i -= 1
            else:
                l = max(0, i - window_size + 1)
                while k_bin[l] == '0':
                    l += 1
                w = int(k_bin[l:i + 1], 2)
                for _ in range(i - l + 1):
                    acc = self.double(acc) if acc else None
                if w > 0:
                    acc = self.add(acc, precomp[w])
                i = l - 1
        return acc

    def get_ZA(self, user_id: str = "default") -> str:
        """计算ZA哈希值"""
        a_bytes = self.a.to_bytes(32, "big")
        b_bytes = self.b.to_bytes(32, "big")
        Gx_bytes = self.G[0].to_bytes(32, "big")
        Gy_bytes = self.G[1].to_bytes(32, "big")
        Px_bytes = self.P[0].to_bytes(32, "big")
        Py_bytes = self.P[1].to_bytes(32, "big")

        # 用户ID长度(比特数)
        entl = len(user_id.encode('utf-8')) * 8
        entl_bytes = entl.to_bytes(2, 'big')

        # 拼接所有数据
        data = (b'\x00' + entl_bytes + user_id.encode('utf-8') +
                a_bytes + b_bytes + Gx_bytes + Gy_bytes +
                Px_bytes + Py_bytes)

        # 计算SM3哈希
        return sm3.sm3_hash(func.bytes_to_list(data))

    def faulty_sign_with_fixed_k(self, m: str, k: int, user_id: str = "default") -> Tuple[bytes, bytes]:
        """有缺陷的签名函数，使用固定的k值"""
        ZA = self.get_ZA(user_id)
        M = ZA + m
        e = int(sm3.sm3_hash(func.bytes_to_list(M.encode())), 16)

        G = self.G
        x1, y1 = self.optimized_mul(k, G)
        if x1 is None:
            raise ValueError("Invalid k value")

        r = (e + x1) % self.n
        if r == 0 or (r + k) == self.n:
            raise ValueError("Invalid r, try another k")

        s = (inverse(1 + self.d, self.n) * (k - r * self.d)) % self.n
        if s == 0:
            raise ValueError("Invalid s, try another k")

        return (r.to_bytes(32, "big"), s.to_bytes(32, "big"))


def recover_private_key_from_reused_k(sig1: Tuple[bytes, bytes], sig2: Tuple[bytes, bytes],
                                      e1: int, e2: int, n: int) -> int:
    """
    从两条使用相同k的签名中恢复私钥
    :param sig1: 第一条签名 (r1, s1) 字节形式
    :param sig2: 第二条签名 (r2, s2) 字节形式
    :param e1: 第一条消息的哈希值(int)
    :param e2: 第二条消息的哈希值(int)
    :param n: 曲线阶数
    :return: 恢复的私钥d
    """
    r1 = int.from_bytes(sig1[0], 'big')
    s1 = int.from_bytes(sig1[1], 'big')
    r2 = int.from_bytes(sig2[0], 'big')
    s2 = int.from_bytes(sig2[1], 'big')

    numerator = (s1 - s2) % n
    denominator = (s2 - s1 + r2 - r1) % n

    try:
        d = (numerator * inverse(denominator, n)) % n
    except ValueError:
        raise ValueError("无法恢复私钥，可能k值不同或签名无效")

    return d


def demo_k_reuse_attack_with_sm2_class():
    """使用SM2类演示k值重用攻击"""
    print("=== 使用SM2类演示k值重用攻击 ===")

    # 1. 受害者生成密钥对
    victim = SM2()
    private_key = victim.d
    print(f"[+] 受害者真实私钥: {hex(private_key)}")

    # 2. 受害者使用有缺陷的签名实现（重用k值）
    reused_k = 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
    print(f"[!] 受害者错误地重用了k值: {hex(reused_k)}")

    # 对两条不同消息签名
    msg1 = "Pay Alice 100 BTC"
    msg2 = "Pay Bob 1000 BTC"

    print("\n[+] 生成两条使用相同k的签名...")
    try:
        sig1 = victim.faulty_sign_with_fixed_k(msg1, reused_k)
        sig2 = victim.faulty_sign_with_fixed_k(msg2, reused_k)
        print(f"    消息1签名 (r1, s1): ({int.from_bytes(sig1[0], 'big')}, {int.from_bytes(sig1[1], 'big')})")
        print(f"    消息2签名 (r2, s2): ({int.from_bytes(sig2[0], 'big')}, {int.from_bytes(sig2[1], 'big')})")
    except ValueError as e:
        print(f"[-] 签名生成失败: {e}")
        return

    # 3. 攻击者获取签名和原始消息
    # 计算e1和e2 (Hash(ZA || M))
    ZA = victim.get_ZA()
    e1 = int(sm3.sm3_hash(func.bytes_to_list((ZA + msg1).encode())), 16)
    e2 = int(sm3.sm3_hash(func.bytes_to_list((ZA + msg2).encode())), 16)

    # 4. 恢复私钥
    print("\n[+] 攻击者尝试恢复私钥...")
    try:
        recovered_key = recover_private_key_from_reused_k(sig1, sig2, e1, e2, victim.n)
        print(f"    恢复的私钥: {hex(recovered_key)}")

        if recovered_key == private_key:
            print("[+] 攻击成功! 恢复的私钥与真实私钥匹配")
        else:
            print("[-] 攻击失败! 恢复的私钥不正确")
    except ValueError as e:
        print(f"[-] 错误: {e}")


if __name__ == "__main__":
    demo_k_reuse_attack_with_sm2_class()
