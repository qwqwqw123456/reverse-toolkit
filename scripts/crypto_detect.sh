#!/bin/bash
# 加密算法识别工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/crypto_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 加密算法识别 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 常见加密常量检测..."
echo "--- AES 常量 ---"
strings "$TARGET" 2>/dev/null | grep -iE "aes|rijndael" | head -10 || echo "(无 AES 特征)"

echo ""
echo "--- RSA 常量 ---"
strings "$TARGET" 2>/dev/null | grep -iE "rsa|public key|private key|modulus|exponent" | head -10 || echo "(无 RSA 特征)"

echo ""
echo "--- 哈希算法 ---"
strings "$TARGET" 2>/dev/null | grep -iE "md5|sha1|sha256|sha512|hmac" | head -10 || echo "(无哈希算法特征)"

echo ""
echo "--- 其他算法 ---"
strings "$TARGET" 2>/dev/null | grep -iE "des|3des|blowfish|twofish|cast|idea|rc4|rc5|rc6|tea|xtea|serpent|camellia|sm4|sm3|sm2" | head -15 || echo "(无其他算法特征)"

echo ""
echo "[2] 加密相关字符串..."
strings "$TARGET" 2>/dev/null | grep -iE "encrypt|decrypt|cipher|key|iv|nonce|salt|hash|digest|sign|verify" | head -30 || echo "(无加密相关字符串)"

echo ""
echo "[3] 常见加密库特征..."
strings "$TARGET" 2>/dev/null | grep -iE "openssl|libcrypto|libssl|bcrypt|sodium|nacl|mbedtls|wolfssl|gnutls|cryptoapi|cng" | head -15 || echo "(无加密库特征)"

echo ""
echo "输出目录: $OUTPUT_DIR"
