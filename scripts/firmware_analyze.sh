#!/bin/bash
# 固件分析工具 - 固件提取 + 解包 + 漏洞扫描
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/firmware_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 固件分析 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 文件基础信息..."
file "$TARGET" | tee "$OUTPUT_DIR/01_file.txt"
echo ""
echo "大小: $(du -h "$TARGET" | cut -f1)"

echo ""
echo "[2] 固件结构分析..."
if command -v binwalk >/dev/null 2>&1; then
    echo "--- binwalk 分析 ---"
    binwalk "$TARGET" | tee "$OUTPUT_DIR/02_binwalk.txt"
else
    echo "binwalk 未安装，跳过固件结构分析"
    echo "安装: sudo apt install binwalk"
fi

echo ""
echo "[3] 提取文件系统..."
if command -v binwalk >/dev/null 2>&1; then
    echo "--- 提取固件内容 ---"
    binwalk -e "$TARGET" --directory "$OUTPUT_DIR/extracted" 2>&1 | tail -10
    echo "提取完成: $OUTPUT_DIR/extracted/"
else
    echo "binwalk 未安装，跳过提取"
fi

echo ""
echo "[4] 常见漏洞扫描（提取后）..."
if [ -d "$OUTPUT_DIR/extracted" ]; then
    echo "--- 硬编码凭证检测 ---"
    grep -rE "root:|admin:|password|passwd|secret|key" "$OUTPUT_DIR/extracted/" 2>/dev/null | grep -v "\.txt:" | head -20 || echo "(未检测到明显凭证)"
    
    echo ""
    echo "--- 危险函数检测 ---"
    grep -rE "system\(|exec[lv]*\(|popen\(|strcpy\(|sprintf\(" "$OUTPUT_DIR/extracted/" 2>/dev/null | head -20 || echo "(未检测到明显危险函数)"
    
    echo ""
    echo "--- 开放端口/服务检测 ---"
    grep -rE "telnet|ftp|ssh|http|https|tftpd" "$OUTPUT_DIR/extracted/etc/" 2>/dev/null | head -15 || echo "(未检测到明显服务配置)"
else
    echo "固件未提取，跳过漏洞扫描"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
echo "提取的文件系统: $OUTPUT_DIR/extracted/"
