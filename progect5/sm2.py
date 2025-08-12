from math import ceil

from gmssl import sm3, func
from Crypto.Util.number import *
from random import SystemRandom
import hmac
import binascii
import os
import hashlib

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

    def k_gen(self, m):
        """基于HMAC-SM3的确定性k生成(RFC 6979风格)"""
        h1 = sm3.sm3_hash(func.bytes_to_list(m))
        V = b'\x01' * 32
        K = b'\x00' * 32

        # 自定义HMAC-SM3实现
        def hmac_sm3(key, msg):
            block_size = 64
            if len(key) > block_size:
                key = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(key)))
            if len(key) < block_size:
                key += b'\x00' * (block_size - len(key))
            o_key_pad = bytes([x ^ 0x5c for x in key])
            i_key_pad = bytes([x ^ 0x36 for x in key])
            return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(o_key_pad + bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(i_key_pad + msg))))))

        # HMAC迭代
        K = hmac_sm3(K, V + b'\x00' + self.d.to_bytes(32, "big") + h1.encode())
        V = hmac_sm3(K, V)
        K = hmac_sm3(K, V + b'\x01' + self.d.to_bytes(32, "big") + h1.encode())
        V = hmac_sm3(K, V)

        while True:
            T = b''
            while len(T) < 32:
                V = hmac_sm3(K, V)
                T += V

            k = int.from_bytes(T, "big")
            if 0 < k < self.n:
                return k
            K = hmac_sm3(K, V + b'\x00')
            V = hmac_sm3(K, V)
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

    def kdf(self, z, klen):
        """密钥派生函数"""
        klen = int(klen)
        ct = 1
        rcnt = ceil(klen / 32)
        zin = func.bytes_to_list(z)
        ha = ""

        for i in range(rcnt):
            msg = zin + func.bytes_to_list(('%08x' % ct).encode('utf8'))
            ha += sm3.sm3_hash(msg)
            ct += 1

        return bytes.fromhex(ha[:klen * 2])

    def enc(self, m, P):
        """SM2加密"""
        if not self.is_on_curve(P):
            raise ValueError("Invalid public key")
        if not isinstance(m, str):
            raise TypeError("Message must be string")

        M = m.encode()
        klen = len(M)
        while True:
            k = self.rand_gen.randint(1, self.n - 1)
            C1 = self.optimized_mul(k, self.G)
            if C1:
                break

        S = self.optimized_mul(k, P)
        if not S:
            raise ValueError("Encryption failed")

        x1, y1 = C1
        x2, y2 = S
        x1_bytes = x1.to_bytes(32, "big")
        y1_bytes = y1.to_bytes(32, "big")
        x2_bytes = x2.to_bytes(32, "big")
        y2_bytes = y2.to_bytes(32, "big")

        t = self.kdf(x2_bytes + y2_bytes, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF produced zero key")

        C2 = bytes(i ^ j for i, j in zip(M, t))
        C3 = sm3.sm3_hash(func.bytes_to_list(x2_bytes + M + y2_bytes))
        return (x1_bytes + y1_bytes, C2, C3)

    def dec(self, c):
        """SM2解密"""
        C1, C2, C3 = c
        if len(C1) != 64:
            raise ValueError("Invalid ciphertext")

        x1 = int.from_bytes(C1[:32], "big")
        y1 = int.from_bytes(C1[32:], "big")
        kG = (x1, y1)

        if not self.is_on_curve(kG):
            raise ValueError("Invalid ciphertext")

        S = self.optimized_mul(self.d, kG)
        if not S:
            raise ValueError("Decryption failed")

        x2, y2 = S
        x2_bytes = x2.to_bytes(32, "big")
        y2_bytes = y2.to_bytes(32, "big")

        t = self.kdf(x2_bytes + y2_bytes, len(C2))
        if all(b == 0 for b in t):
            raise ValueError("KDF produced zero key")

        M = bytes(i ^ j for i, j in zip(C2, t))
        u = sm3.sm3_hash(func.bytes_to_list(x2_bytes + M + y2_bytes))

        if u != C3:
            raise ValueError("MAC verification failed")

        return M.decode()

    def sign(self, m):
        """SM2签名"""
        if not isinstance(m, str):
            raise TypeError("Message must be string")

        ZA = self.get_ZA()
        M = ZA + m
        e = int(sm3.sm3_hash(func.bytes_to_list(M.encode())), 16)

        G = self.G
        r, s = 0, 0

        while r == 0 or (r + k) == self.n or s == 0:
            k = self.k_gen(M.encode())
            x1, y1 = self.optimized_mul(k, G)
            r = (e + x1) % self.n
            s = (inverse(1 + self.d, self.n) * (k - r * self.d)) % self.n

        return (r.to_bytes(32, "big"), s.to_bytes(32, "big"))

    def get_ZA(self):
        """计算ZA哈希值"""
        a_bytes = self.a.to_bytes(32, "big")
        b_bytes = self.b.to_bytes(32, "big")
        Gx_bytes = self.G[0].to_bytes(32, "big")
        Gy_bytes = self.G[1].to_bytes(32, "big")
        Px_bytes = self.P[0].to_bytes(32, "big")
        Py_bytes = self.P[1].to_bytes(32, "big")

        return sm3.sm3_hash(func.bytes_to_list(
            b'\x00' + a_bytes + b_bytes + Gx_bytes + Gy_bytes + Px_bytes + Py_bytes
        ))

    def vrfy(self, m, sig, P):
        """SM2验签"""
        if not isinstance(m, str):
            raise TypeError("Message must be string")
        if not isinstance(sig, tuple) or len(sig) != 2:
            raise TypeError("Signature must be a tuple of (r, s)")
        if not self.is_on_curve(P):
            raise ValueError("Invalid public key")

        r = int.from_bytes(sig[0], "big")
        s = int.from_bytes(sig[1], "big")

        if not (0 < r < self.n and 0 < s < self.n):
            return False

        ZA = self.get_ZA()
        M = ZA + m
        e = int(sm3.sm3_hash(func.bytes_to_list(M.encode())), 16)
        t = (r + s) % self.n

        if t == 0:
            return False

        P1 = self.optimized_mul(s, self.G)
        P2 = self.optimized_mul(t, P)
        x1, y1 = self.add(P1, P2)

        if (e + x1) % self.n == r:
            return True
        return False

def test_sm2():
    print("=== SM2 算法测试 ===")

    # 初始化
    alice = SM2()
    bob = SM2()

    # 加密/解密测试
    msg = "Hello SM2"
    print(f"\n原始消息: {msg}")
    cipher = alice.enc(msg, bob.P)
    C3_hex = cipher[2]  # 已经是十六进制字符串，直接打印
    print(f"加密结果: C1={cipher[0].hex()[:16]}..., C2={cipher[1].hex()[:16]}..., C3={C3_hex}")
    dec_msg = bob.dec(cipher)
    print(f"解密结果: {dec_msg}")
    assert dec_msg == msg, "加解密测试失败"

    # 签名/验签测试
    msg = "Test message"
    print(f"\n签名消息: {msg}")
    sig = alice.sign(msg)
    print(f"签名结果: r={int.from_bytes(sig[0], 'big')}, s={int.from_bytes(sig[1], 'big')}")
    verify = alice.vrfy(msg, sig, alice.P)
    print(f"验签结果: {'成功' if verify else '失败'}")
    assert verify, "签名验证失败"

    # 错误签名测试
    fake_sig = (sig[0], (int.from_bytes(sig[1], 'big') + 1).to_bytes(32, 'big'))
    verify = alice.vrfy(msg, fake_sig, alice.P)
    print(f"伪造签名测试: {'应失败' if not verify else '漏洞!'}")
    assert not verify, "伪造签名检测失败"

    print("\n所有测试通过！")

if __name__ == "__main__":
    test_sm2()
