#!/bin/bash
# 导入表/导出表分析工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/imports_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 导入表/导出表分析 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 导入函数分析..."
if command -v objdump >/dev/null 2>&1; then
    objdump -p "$TARGET" 2>/dev/null | grep -A 100 "DLL Name" | head -80 > "$OUTPUT_DIR/imports.txt" || echo "(非 PE 文件)"
fi

if command -v readelf >/dev/null 2>&1; then
    echo "--- ELF 动态符号 ---"
    readelf -s "$TARGET" 2>/dev/null | grep -E "FUNC|OBJECT" | head -50 > "$OUTPUT_DIR/imports.txt"
fi

echo ""
echo "[2] 危险导入检测..."
echo "--- 敏感 API 列表 ---"
strings "$TARGET" 2>/dev/null | grep -iE "CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx|CreateProcess|WinExec|ShellExecute|system|exec|popen|connect|socket|send|recv|InternetOpen|URLDownload|CryptEncrypt|CryptDecrypt|RegSetValue|CreateService|StartService" | head -30 || echo "(未检测到明显敏感 API)"

echo ""
echo "[3] 导出函数分析..."
if command -v readelf >/dev/null 2>&1; then
    readelf -s "$TARGET" 2>/dev/null | grep -E "FUNC.*GLOBAL" | head -30 || echo "(无导出函数)"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
