#!/bin/bash
# 字符串高级提取工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/strings_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 字符串高级提取 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 普通字符串（长度 >= 6）..."
strings -n 6 "$TARGET" 2>/dev/null | head -200 > "$OUTPUT_DIR/strings_basic.txt"
echo "提取: $(wc -l < "$OUTPUT_DIR/strings_basic.txt") 条"

echo ""
echo "[2] 敏感字符串分类..."
echo "--- 密码/密钥相关 ---"
strings -n 4 "$TARGET" 2>/dev/null | grep -iE "password|passwd|pwd|secret|key|token|api_key|apikey|private" | head -30 > "$OUTPUT_DIR/strings_sensitive.txt"
echo "密码相关: $(wc -l < "$OUTPUT_DIR/strings_sensitive.txt") 条"

echo ""
echo "--- URL/网络相关 ---"
strings -n 8 "$TARGET" 2>/dev/null | grep -iE "http://|https://|ftp://|tcp://|udp://|ws://|wss://" | head -30 > "$OUTPUT_DIR/strings_url.txt"
echo "URL 相关: $(wc -l < "$OUTPUT_DIR/strings_url.txt") 条"

echo ""
echo "--- 文件路径相关 ---"
strings -n 6 "$TARGET" 2>/dev/null | grep -E "/[a-zA-Z0-9_/]+\.[a-zA-Z]{2,4}" | head -30 > "$OUTPUT_DIR/strings_paths.txt"
echo "路径相关: $(wc -l < "$OUTPUT_DIR/strings_paths.txt") 条"

echo ""
echo "--- 注册表相关（Windows） ---"
strings -n 6 "$TARGET" 2>/dev/null | grep -iE "HKEY_|Software\\\\|Microsoft\\\\|CurrentVersion\\\\Run" | head -20 > "$OUTPUT_DIR/strings_registry.txt"
echo "注册表相关: $(wc -l < "$OUTPUT_DIR/strings_registry.txt") 条"

echo ""
echo "--- 错误信息相关 ---"
strings -n 6 "$TARGET" 2>/dev/null | grep -iE "error|fail|exception|invalid|warning|fatal" | head -30 > "$OUTPUT_DIR/strings_errors.txt"
echo "错误信息: $(wc -l < "$OUTPUT_DIR/strings_errors.txt") 条"

echo ""
echo "[3] Unicode 字符串..."
strings -e l -n 4 "$TARGET" 2>/dev/null | head -50 > "$OUTPUT_DIR/strings_unicode.txt"
echo "Unicode 字符串: $(wc -l < "$OUTPUT_DIR/strings_unicode.txt") 条"

echo ""
echo "输出目录: $OUTPUT_DIR"
