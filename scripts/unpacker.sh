#!/bin/bash
# 脱壳分析工具 v2.1 - 三特征交叉验证 + 置信度评分
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/unpack_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 脱壳分析 v2.1 ==="
echo "目标: $TARGET"
echo ""

echo "[1/5] 识别壳类型（多特征交叉验证）..."

# 特征 1：字符串特征
echo "--- 特征 1: 字符串特征 ---"
strings "$TARGET" 2>/dev/null | grep -iE "upx|aspack|themida|vmprotect|enigma|winlicense|armadillo|zprotect|svkp|acprotect|obsidium|pecompact|mpress|fsg|petite|nspack|tElock|asprotect" | sort -u > "$OUTPUT_DIR/shell_strings.txt"
str_count=$(wc -l < "$OUTPUT_DIR/shell_strings.txt")
echo "  命中 $str_count 个壳特征字符串"
cat "$OUTPUT_DIR/shell_strings.txt" | head -10

echo ""
echo "--- 特征 2: 节区名特征 ---"
section_count=0
if command -v readelf >/dev/null 2>&1; then
    readelf -S "$TARGET" 2>/dev/null | grep -iE "\.upx|\.aspack|\.themida|\.enigma|\.vmp|\.boot|\.packed|\.crunch|\.petite|\.fsg|\.nspack" > "$OUTPUT_DIR/shell_sections.txt" || true
    section_count=$(wc -l < "$OUTPUT_DIR/shell_sections.txt")
    echo "  命中 $section_count 个可疑节区名"
    cat "$OUTPUT_DIR/shell_sections.txt"
fi

echo ""
echo "--- 特征 3: 熵值分析 ---"
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

# 读取熵值
ENTROPY=$(python3 -c "
import math
data = open('$TARGET', 'rb').read()
freq = [0]*256
for b in data:
    freq[b] += 1
ent = -sum((f/len(data)) * math.log2(f/len(data)) for f in freq if f > 0)
print(f'{ent:.2f}')
")

echo ""
echo "--- 综合判断 ---"
# 综合评分：字符串 + 节区名 + 熵值
shell_score=0
shell_details=""

if [ "$str_count" -ge 1 ]; then
    shell_score=$((shell_score + 3))
    shell_details="$shell_details 字符串特征(+3); "
fi

if [ "$section_count" -ge 1 ]; then
    shell_score=$((shell_score + 3))
    shell_details="$shell_details 节区名特征(+3); "
fi

if (( $(echo "$ENTROPY > 7.0" | bc -l 2>/dev/null || echo 0) )); then
    shell_score=$((shell_score + 3))
    shell_details="$shell_details 高熵值(+3); "
elif (( $(echo "$ENTROPY > 6.0" | bc -l 2>/dev/null || echo 0) )); then
    shell_score=$((shell_score + 1))
    shell_details="$shell_details 中熵值(+1); "
fi

echo "  综合评分: $shell_score / 9"
echo "  依据: $shell_details"

# 置信度判定
if [ "$shell_score" -ge 6 ]; then
    echo "  🔴 高置信度：大概率加壳"
elif [ "$shell_score" -ge 3 ]; then
    echo "  🟡 中置信度：可能加壳，建议人工确认"
else
    echo "  🟢 低置信度：大概率未加壳"
fi

echo ""
echo "[3/5] 自动脱 UPX 壳..."
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
echo "[4/5] 壳类型对照表..."
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
