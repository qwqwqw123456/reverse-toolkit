#!/bin/bash
# 节区/段分析工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/sections_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 节区/段分析 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 节区列表..."
if command -v objdump >/dev/null 2>&1; then
    objdump -h "$TARGET" 2>/dev/null | tee "$OUTPUT_DIR/sections.txt"
fi

echo ""
echo "[2] 可执行节区检测..."
echo "--- 可疑节区（名称异常） ---"
strings "$TARGET" 2>/dev/null | grep -iE "\.upx|\.aspack|\.themida|\.enigma|\.vmp|\.boot|\.packed|\.crunch|\.petite|\.fsg|\.nspack|\.text|\.data|\.rdata|\.bss|\.plt|\.got|\.reloc" | head -20 || echo "(无明显节区名)"

echo ""
echo "[3] 节区权限分析..."
echo "常见节区权限:"
echo "  .text  - 代码段，RX（可读可执行）"
echo "  .rdata - 只读数据，R"
echo "  .data  - 可读写数据，RW"
echo "  .bss   - 未初始化数据，RW"
echo "  .plt   - 过程链接表，R"
echo "  .got   - 全局偏移表，RW"
echo ""
echo "可疑点:"
echo "  - 有 W 权限的可执行节区（可能是壳）"
echo "  - 节区名异常（.upx, .themida 等）"
echo "  - 节区大小异常（过大或过小）"

echo ""
echo "输出目录: $OUTPUT_DIR"
