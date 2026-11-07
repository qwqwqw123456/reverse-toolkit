#!/bin/bash
# 哈希计算与文件指纹工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/hash_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 文件哈希计算 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 基础哈希..."
echo "MD5:    $(md5sum "$TARGET" | cut -d' ' -f1)"
echo "SHA1:   $(sha1sum "$TARGET" | cut -d' ' -f1)"
echo "SHA256: $(sha256sum "$TARGET" | cut -d' ' -f1)"

echo ""
echo "[2] 文件信息..."
echo "大小: $(du -h "$TARGET" | cut -f1)"
echo "类型: $(file "$TARGET")"

echo ""
echo "[3]  entropy 熵值（检测加密/压缩）..."
if command -v entropy >/dev/null 2>&1; then
    entropy "$TARGET" 2>/dev/null || echo "(entropy 工具未安装)"
else
    echo "entropy 工具未安装，用 python 计算:"
    python3 -c "
import math, sys
data = open('$TARGET', 'rb').read()
if not data:
    print('文件为空')
    sys.exit(0)
freq = [0]*256
for b in data:
    freq[b] += 1
ent = -sum((f/len(data)) * math.log2(f/len(data)) for f in freq if f > 0)
print(f'熵值: {ent:.4f} / 8.0')
if ent > 7.0:
    print('→ 高熵，可能是加密/压缩/壳')
elif ent > 6.0:
    print('→ 中熵，可能是代码+数据混合')
else:
    print('→ 低熵，普通代码')
"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
