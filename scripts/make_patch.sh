#!/bin/bash
# 补丁生成工具 - 生成二进制补丁
set -e

TARGET="$1"
PATCH_OFFSET="$2"
PATCH_BYTES="$3"
OUTPUT_DIR="${4:-$(pwd)/patch_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ] || [ -z "$PATCH_OFFSET" ] || [ -z "$PATCH_BYTES" ]; then
    echo "用法: make_patch.sh <目标文件> <偏移地址(十六进制)> <补丁字节(十六进制, 如: 9090)>"
    echo "示例: make_patch.sh ./target 0x1234 9090"
    exit 1
fi

echo "=== 补丁生成 ==="
echo "目标: $TARGET"
echo "偏移: $PATCH_OFFSET"
echo "补丁字节: $PATCH_BYTES"
echo ""

# 备份原始文件
cp "$TARGET" "$OUTPUT_DIR/$(basename "$TARGET").bak"
echo "✅ 原始文件已备份: $(basename "$TARGET").bak"

# 用 python 生成补丁
python3 << EOF
import os

target = "$TARGET"
offset = int("$PATCH_OFFSET", 16)
patch_bytes = bytes.fromhex("$PATCH_BYTES")

# 读取原始数据
with open(target, 'rb') as f:
    data = bytearray(f.read())

# 记录原始字节
original = data[offset:offset+len(patch_bytes)]
print(f"原始字节: {original.hex()}")
print(f"补丁字节: {patch_bytes.hex()}")

# 应用补丁
data[offset:offset+len(patch_bytes)] = patch_bytes

# 写入补丁后的文件
patched_path = "$OUTPUT_DIR/$(os.path.basename(target)).patched"
with open(patched_path, 'wb') as f:
    f.write(data)

print(f"✅ 补丁文件已生成: {patched_path}")
print(f"补丁大小: {len(patch_bytes)} 字节")
EOF

echo ""
echo "输出目录: $OUTPUT_DIR"
