#!/bin/bash
# 渐进式分析 - 第一轮：概览模式（不跑 Ghidra，快速出结果）
# 用途：第一轮分析，先给用户一个全貌，判断要不要深入
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/overview_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 第一轮：概览模式（快速分析，不跑 Ghidra） ==="
echo "目标: $TARGET"
echo ""

echo "[1/5] 文件指纹..."
file "$TARGET" > "$OUTPUT_DIR/01_file.txt"
cat "$OUTPUT_DIR/01_file.txt"

echo ""
echo "大小: $(du -h "$TARGET" | cut -f1)"
echo "MD5: $(md5sum "$TARGET" | cut -d' ' -f1)"
echo "SHA256: $(sha256sum "$TARGET" | cut -d' ' -f1)"

echo ""
echo "[2/5] 熵值分析（判断是否加壳）..."
python3 -c "
import math
data = open('$TARGET', 'rb').read()
if not data:
    print('文件为空')
else:
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = -sum((f/len(data)) * math.log2(f/len(data)) for f in freq if f > 0)
    print(f'熵值: {ent:.2f} / 8.0')
    if ent > 7.0:
        print('→ 高熵，可能加壳或加密')
    elif ent > 6.0:
        print('→ 中熵，代码+数据混合')
    else:
        print('→ 低熵，普通代码')
"

echo ""
echo "[3/5] 壳特征检测..."
strings "$TARGET" 2>/dev/null | grep -iE "upx|aspack|themida|vmprotect|enigma|winlicense|armadillo|zprotect|svkp|acprotect|obsidium|pecompact|mpress|fsg|petite|nspack|tElock|asprotect" | head -15 || echo "(未检测到常见壳特征字符串)"

echo ""
echo "[4/5] 可疑字符串分类..."
echo "--- URL/网络 ---"
strings -n 8 "$TARGET" 2>/dev/null | grep -iE "http://|https://|ftp://|ws://|wss://" | head -15 || echo "(无)"

echo ""
echo "--- IP 地址 ---"
strings -n 7 "$TARGET" 2>/dev/null | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -15 || echo "(无)"

echo ""
echo "--- 敏感信息 ---"
strings -n 6 "$TARGET" 2>/dev/null | grep -iE "password|passwd|secret|key|token|api_key|private" | head -15 || echo "(无)"

echo ""
echo "--- 执行相关 ---"
strings -n 6 "$TARGET" 2>/dev/null | grep -iE "system|exec|shell|cmd|command|CreateProcess|WinExec" | head -15 || echo "(无)"

echo ""
echo "[5/5] 导入函数概览（危险 API）..."
strings "$TARGET" 2>/dev/null | grep -iE "CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx|connect|socket|send|recv|URLDownload|InternetOpen|RegSetValue|CreateService|StartService|CryptEncrypt|CryptDecrypt" | head -20 || echo "(无明显危险 API 字符串)"

echo ""
echo "=== 第一轮概览完成 ==="
echo ""
echo "下一步建议："
echo "  1. 如果发现可疑 URL/IP/API → 跑第二轮深挖（focus_func.sh）"
echo "  2. 如果发现加壳 → 跑脱壳分析（unpacker.sh）"
echo "  3. 如果都正常 → 跑完整反编译（analyze.sh）"
echo ""
echo "输出目录: $OUTPUT_DIR"
