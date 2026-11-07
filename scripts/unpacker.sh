#!/bin/bash
# 脱壳分析工具 v2.0 - 识别壳类型 + 自动脱 UPX + 脱壳建议
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/unpack_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 脱壳分析 v2.0 ==="
echo "目标: $TARGET"
echo ""

echo "[1/4] 识别壳类型..."
# 检查常见壳特征
echo "--- 字符串特征检测 ---"
strings "$TARGET" 2>/dev/null | grep -iE "upx|aspack|themida|vmprotect|enigma|winlicense|armadillo|zprotect|svkp|acprotect|obsidium|pecompact|mpress|fsg|petite|nspack|tElock|asprotect" | head -20 > "$OUTPUT_DIR/shell_strings.txt"
cat "$OUTPUT_DIR/shell_strings.txt" || echo "(未检测到常见壳特征字符串)"

echo ""
echo "--- 节区名检测 ---"
if command -v readelf >/dev/null 2>&1; then
    readelf -S "$TARGET" 2>/dev/null | grep -iE "\.upx|\.aspack|\.themida|\.enigma|\.vmp|\.boot|\.packed|\.crunch|\.petite|\.fsg|\.nspack" | head -10 > "$OUTPUT_DIR/shell_sections.txt" || true
    cat "$OUTPUT_DIR/shell_sections.txt" || echo "(无已知壳区段名)"
fi

echo ""
echo "[2/4] 熵值分析（判断是否加壳）..."
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
        print('→ 高熵，大概率加壳或加密')
    elif ent > 6.0:
        print('→ 中熵，可能加壳')
    else:
        print('→ 低熵，可能未加壳')
" | tee "$OUTPUT_DIR/entropy.txt"

echo ""
echo "[3/4] 自动脱 UPX 壳..."
# 检测是否是 UPX 壳
if strings "$TARGET" 2>/dev/null | grep -q "UPX!"; then
    echo "✅ 检测到 UPX 壳"
    
    if command -v upx >/dev/null 2>&1; then
        echo "✅ upx 工具已安装"
        
        # 备份原文件
        cp "$TARGET" "$OUTPUT_DIR/$(basename "$TARGET").packed"
        echo "✅ 原始加壳文件已备份"
        
        # 尝试脱壳
        cp "$TARGET" "$OUTPUT_DIR/$(basename "$TARGET").unpacked"
        if upx -d "$OUTPUT_DIR/$(basename "$TARGET").unpacked" > "$OUTPUT_DIR/upx_output.txt" 2>&1; then
            echo "✅ UPX 脱壳成功！"
            echo "脱壳后文件: $OUTPUT_DIR/$(basename "$TARGET").unpacked"
            echo "脱壳后大小: $(du -h "$OUTPUT_DIR/$(basename "$TARGET").unpacked" | cut -f1)"
        else
            echo "⚠️ UPX 脱壳失败"
            cat "$OUTPUT_DIR/upx_output.txt"
        fi
    else
        echo "⚠️ upx 工具未安装"
        echo "安装: sudo apt install upx"
    fi
else
    echo "未检测到 UPX 壳特征"
fi

echo ""
echo "[4/4] 脱壳难度评估与建议..."
echo "壳类型对照表:"
echo "  简单壳: UPX, FSG, Petite, MPress      → 可自动脱壳 ✅"
echo "  中等壳: ASPack, ASProtect, NSPack      → 需手动脱壳"
echo "  强壳:   Themida, VMProtect, Enigma     → 极难脱壳，建议动态调试"
echo "  虚拟机壳: VMProtect, Themida VM         → 需反虚拟化分析"
echo ""
echo "脱壳步骤建议:"
echo "  1. 简单壳（UPX）：自动脱壳工具直接解"
echo "  2. 中等壳：找 OEP（入口点）→ 内存 dump → 修复 IAT"
echo "  3. 强壳：动态调试，内存 dump，不追求完整脱壳"
echo "  4. 虚拟机壳：反虚拟化分析，逐条解释"

echo ""
echo "输出目录: $OUTPUT_DIR"
