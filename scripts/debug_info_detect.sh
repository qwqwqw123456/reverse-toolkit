#!/bin/bash
# 调试信息检测工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/debuginfo_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 调试信息检测 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 调试符号检测..."
if command -v readelf >/dev/null 2>&1; then
    readelf -S "$TARGET" 2>/dev/null | grep -E "debug|\.symtab|\.strtab|\.debug_info|\.debug_line|\.debug_abbrev|\.debug_aranges" > "$OUTPUT_DIR/debug_sections.txt" || echo "(无调试节区)"
    echo "调试节区:"
    cat "$OUTPUT_DIR/debug_sections.txt"
fi

echo ""
echo "[2] Stripped 状态..."
file "$TARGET" | grep -q "not stripped" && echo "未剥离符号（有调试信息）" || echo "已剥离符号（无调试信息）"

echo ""
echo "[3] 符号表检测..."
if command -v nm >/dev/null 2>&1; then
    nm "$TARGET" 2>/dev/null | head -20 > "$OUTPUT_DIR/symbols.txt" || echo "(无符号表)"
    echo "符号数量: $(wc -l < "$OUTPUT_DIR/symbols.txt")"
fi

echo ""
echo "[4] PDB 符号检测（Windows）..."
strings "$TARGET" 2>/dev/null | grep -iE "\.pdb|Program Debug Database" | head -10 || echo "(无 PDB 路径字符串)"

echo ""
echo "[5] 异常处理信息..."
if command -v readelf >/dev/null 2>&1; then
    readelf -S "$TARGET" 2>/dev/null | grep -E "eh_frame|gcc_except_table|\.ARM\.ex_idx|\.pdata" > "$OUTPUT_DIR/exception_info.txt" || echo "(无异常处理节区)"
    echo "异常处理节区:"
    cat "$OUTPUT_DIR/exception_info.txt"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
