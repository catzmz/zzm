import hashlib
from typing import Tuple, Optional

# SM2椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 素数域
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  # 曲线系数a
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93  # 曲线系数b
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123  # 曲线阶数
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7  # 基点x坐标
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0  # 基点y坐标

# 类型别名
Point = Tuple[int, int]


def inv(a: int, n: int) -> int:
    """模逆运算 - 使用您提供的实现"""
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    lm, hm, low, high = 1, 0, a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def point_add(p: Optional[Point], q: Optional[Point]) -> Optional[Point]:
    """椭圆曲线点加法"""
    if p is None:
        return q
    if q is None:
        return p

    x1, y1 = p
    x2, y2 = q

    # 处理点相加的特殊情况
    if x1 == x2 and y1 != y2:
        return None  # 点相加结果为无穷远点
    if x1 == x2:
        # 相同点相加（点倍乘）
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        # 不同点相加
        lam = (y2 - y1) * inv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, point: Point) -> Optional[Point]:
    """椭圆曲线标量乘法（快速幂算法）"""
    result = None
    current = point

    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2

    return result


def compute_za(user_id: str, public_key: Point) -> bytes:
    """计算SM2的ZA值（用户标识和系统参数的哈希）"""
    # 将各参数转换为字节串
    entl = len(user_id.encode('utf-8')) * 8
    entl_bytes = entl.to_bytes(2, 'big')
    a_bytes = A.to_bytes(32, 'big')
    b_bytes = B.to_bytes(32, 'big')
    gx_bytes = Gx.to_bytes(32, 'big')
    gy_bytes = Gy.to_bytes(32, 'big')
    px_bytes = public_key[0].to_bytes(32, 'big')
    py_bytes = public_key[1].to_bytes(32, 'big')

    # 拼接所有数据并计算哈希
    data = entl_bytes + user_id.encode('utf-8') + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
    return hashlib.sha256(data).digest()  # 实际应用应使用SM3


def sm2_sign(private_key: int, message: bytes, k: int, user_id: str = "default") -> Tuple[int, int]:
    """SM2签名函数（故意设计为可以重用k值）"""
    public_key = scalar_mult(private_key, (Gx, Gy))
    if public_key is None:
        raise ValueError("无效的公钥生成")

    za = compute_za(user_id, public_key)

    # 计算 e = Hash(ZA || M)
    e = int.from_bytes(hashlib.sha256(za + message).digest(), 'big')

    # 计算签名
    point = scalar_mult(k, (Gx, Gy))
    if point is None:
        raise ValueError("无效的k值")

    x1, _ = point
    r = (e + x1) % N
    if r == 0 or (r + k) == N:
        raise ValueError("无效的r值，请选择不同的k")

    s = (inv(1 + private_key, N) * (k - r * private_key)) % N
    if s == 0:
        raise ValueError("无效的s值，请选择不同的k")

    return (r, s)


def recover_private_key_from_reused_k(sig1: Tuple[int, int], sig2: Tuple[int, int],
                                      e1: int, e2: int) -> int:
    """
    从两条使用相同k的签名中恢复私钥
    :param sig1: 第一条签名 (r1, s1)
    :param sig2: 第二条签名 (r2, s2)
    :param e1: 第一条消息的哈希值
    :param e2: 第二条消息的哈希值
    :return: 恢复的私钥d
    """
    r1, s1 = sig1
    r2, s2 = sig2

    # 因为k相同，所以r1 = e1 + x1 mod n, r2 = e2 + x1 mod n
    # 所以x1 = r1 - e1 = r2 - e2 mod n
    # 推导出 (r1 - e1) ≡ (r2 - e2) mod n

    # 从签名方程推导私钥
    numerator = (s1 - s2) % N
    denominator = (s2 - s1 + r2 - r1) % N

    try:
        d = (numerator * inv(denominator, N)) % N
    except ZeroDivisionError:
        raise ValueError("无法恢复私钥，可能k值不同或签名无效")

    return d


def demo_k_reuse_attack():
    """演示k值重用攻击"""
    print("=== SM2签名算法k值重用攻击演示 ===")

    # 1. 受害者生成密钥对
    private_key = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    print(f"[+] 受害者真实私钥: {hex(private_key)}")

    # 2. 受害者使用有缺陷的签名实现（重用k值）
    reused_k = 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
    print(f"[!] 受害者错误地重用了k值: {hex(reused_k)}")

    # 对两条不同消息签名
    msg1 = b"Pay Alice 100 BTC"
    msg2 = b"Pay Bob 1000 BTC"

    print("\n[+] 生成两条使用相同k的签名...")
    try:
        sig1 = sm2_sign(private_key, msg1, reused_k)
        sig2 = sm2_sign(private_key, msg2, reused_k)
        print(f"    消息1签名 (r1, s1): ({hex(sig1[0])}, {hex(sig1[1])})")
        print(f"    消息2签名 (r2, s2): ({hex(sig2[0])}, {hex(sig2[1])})")
    except ValueError as e:
        print(f"[-] 签名生成失败: {e}")
        return

    # 3. 攻击者获取签名和原始消息
    # 计算e1和e2 (Hash(ZA || M))
    user_id = "victim@example.com"
    public_key = scalar_mult(private_key, (Gx, Gy))
    if public_key is None:
        print("[-] 无法生成公钥")
        return

    za = compute_za(user_id, public_key)
    e1 = int.from_bytes(hashlib.sha256(za + msg1).digest(), 'big')
    e2 = int.from_bytes(hashlib.sha256(za + msg2).digest(), 'big')

    # 4. 恢复私钥
    print("\n[+] 攻击者尝试恢复私钥...")
    try:
        recovered_key = recover_private_key_from_reused_k(sig1, sig2, e1, e2)
        print(f"    恢复的私钥: {hex(recovered_key)}")

        if recovered_key == private_key:
            print("[+] 攻击成功! 恢复的私钥与真实私钥匹配")
        else:
            print("[-] 攻击失败! 恢复的私钥不正确")
    except ValueError as e:
        print(f"[-] 错误: {e}")


if __name__ == "__main__":
    demo_k_reuse_attack()
