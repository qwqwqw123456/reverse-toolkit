#!/bin/bash
# Radare2 后端 - 轻量级反编译分析

set -e

TARGET="$1"
OUTPUT_DIR="$2"
FOCUS_KEYWORD="$3"

echo "  [1/5] 文件基础信息..."
file "$TARGET" > "$OUTPUT_DIR/01_file.txt"
echo "" >> "$OUTPUT_DIR/01_file.txt"
echo "=== 架构信息 ===" >> "$OUTPUT_DIR/01_file.txt"
r2 -q -c "iI" "$TARGET" 2>/dev/null | head -20 >> "$OUTPUT_DIR/01_file.txt" || echo "(r2 分析失败)" >> "$OUTPUT_DIR/01_file.txt"

echo "  [2/5] 提取字符串..."
strings "$TARGET" | sort -u > "$OUTPUT_DIR/02_strings_raw.txt"
grep -E '^[[:print:]]{4,}$' "$OUTPUT_DIR/02_strings_raw.txt" | head -200 > "$OUTPUT_DIR/02_strings.txt"
rm "$OUTPUT_DIR/02_strings_raw.txt"

echo "  [3/5] Radare2 函数分析..."
mkdir -p "$OUTPUT_DIR/decompiled"

# 列出所有函数
r2 -q -c "aaa; afl" "$TARGET" 2>/dev/null > "$OUTPUT_DIR/decompiled/_functions.txt" || echo "函数分析失败" > "$OUTPUT_DIR/decompiled/_functions.txt"

# 生成函数索引
echo "函数清单（前 50 个）" > "$OUTPUT_DIR/decompiled/_index.txt"
head -50 "$OUTPUT_DIR/decompiled/_functions.txt" >> "$OUTPUT_DIR/decompiled/_index.txt"
echo "" >> "$OUTPUT_DIR/decompiled/_index.txt"
echo "函数总数: $(wc -l < "$OUTPUT_DIR/decompiled/_functions.txt")" >> "$OUTPUT_DIR/decompiled/_index.txt"

echo "  [4/5] 交叉引用分析..."
# 字符串交叉引用
r2 -q -c "aaa; iz~?" "$TARGET" 2>/dev/null > "$OUTPUT_DIR/decompiled/_xref_strings.txt" || echo "字符串引用分析失败" > "$OUTPUT_DIR/decompiled/_xref_strings.txt"

echo "  [5/5] 生成摘要报告..."
cat > "$OUTPUT_DIR/summary.md" << EOF
# 逆向分析报告 (Radare2 后端)

## 基本信息
- 目标文件: $TARGET
- 分析工具: Radare2
- 分析时间: $(date)

## 文件信息
\`\`\`
$(head -5 "$OUTPUT_DIR/01_file.txt")
\`\`\`

## 关键字符串（前 20 条）
\`\`\`
$(head -20 "$OUTPUT_DIR/02_strings.txt")
\`\`\`

## 函数统计
$(if [ -f "$OUTPUT_DIR/decompiled/_index.txt" ]; then cat "$OUTPUT_DIR/decompiled/_index.txt"; else echo "N/A"; fi)

## 聚焦检索
$(if [ -n "$FOCUS_KEYWORD" ]; then
    echo "关键词: $FOCUS_KEYWORD"
    echo ""
    echo "=== 字符串匹配 ==="
    grep -i "$FOCUS_KEYWORD" "$OUTPUT_DIR/02_strings.txt" | head -10 || echo "(无匹配)"
else
    echo "未指定聚焦关键词"
fi)

## 注意
Radare2 后端是轻量版，功能不如 Ghidra 全面。
如需完整反编译伪代码，请使用 Ghidra 后端。
EOF

echo "  ✅ Radare2 后端完成"
