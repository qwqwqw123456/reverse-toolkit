#!/bin/bash
# 二进制对比工具 - 对比两个二进制文件的差异
set -e

TARGET1="$1"
TARGET2="$2"
OUTPUT_DIR="${3:-$(pwd)/diff_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET1" ] || [ -z "$TARGET2" ]; then
    echo "用法: bin_diff.sh <文件1> <文件2> [输出目录]"
    exit 1
fi

echo "=== 二进制对比 ==="
echo "文件1: $TARGET1"
echo "文件2: $TARGET2"
echo ""

echo "[1] 基本信息对比..."
echo "--- 文件1 ---"
file "$TARGET1"
echo "大小: $(du -h "$TARGET1" | cut -f1)"
echo "MD5: $(md5sum "$TARGET1" | cut -d' ' -f1)"

echo ""
echo "--- 文件2 ---"
file "$TARGET2"
echo "大小: $(du -h "$TARGET2" | cut -f1)"
echo "MD5: $(md5sum "$TARGET2" | cut -d' ' -f1)"

echo ""
echo "[2] 字符串差异..."
echo "--- 仅在文件1中出现的字符串 ---"
diff <(strings -n 6 "$TARGET1" | sort -u) <(strings -n 6 "$TARGET2" | sort -u) | grep "^<" | head -30 > "$OUTPUT_DIR/strings_only_in_1.txt"
cat "$OUTPUT_DIR/strings_only_in_1.txt"

echo ""
echo "--- 仅在文件2中出现的字符串 ---"
diff <(strings -n 6 "$TARGET1" | sort -u) <(strings -n 6 "$TARGET2" | sort -u) | grep "^>" | head -30 > "$OUTPUT_DIR/strings_only_in_2.txt"
cat "$OUTPUT_DIR/strings_only_in_2.txt"

echo ""
echo "[3] 节区差异..."
if command -v objdump >/dev/null 2>&1; then
    echo "--- 文件1 节区 ---"
    objdump -h "$TARGET1" 2>/dev/null | tail -n +4 | head -20 > "$OUTPUT_DIR/sections_1.txt"
    
    echo "--- 文件2 节区 ---"
    objdump -h "$TARGET2" 2>/dev/null | tail -n +4 | head -20 > "$OUTPUT_DIR/sections_2.txt"
    
    echo "节区差异见: $OUTPUT_DIR/sections_1.txt 和 sections_2.txt"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
