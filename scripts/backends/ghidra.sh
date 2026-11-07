#!/bin/bash
# Ghidra 后端 v4.2 - 智能降噪 + 结构化报告
# 输出：summary.md 体检报告（不是一坨代码）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET="$1"
OUTPUT_DIR="$2"
FOCUS_KEYWORD="$3"

# 环境探测
detect_ghidra() {
  [ -n "${GHIDRA_HOME:-}" ] && [ -d "$GHIDRA_HOME" ] && { echo "$GHIDRA_HOME"; return 0; }
  for p in "$HOME/tools"/ghidra_* "$HOME"/ghidra_* /opt/ghidra_*; do
    [ -d "$p" ] && [ -x "$p/support/analyzeHeadless" ] && { echo "$p"; return 0; }
  done
  return 1
}
detect_jdk25() {
  [ -n "${JAVA_HOME_25:-}" ] && [ -d "$JAVA_HOME_25" ] && { echo "$JAVA_HOME_25"; return 0; }
  for p in "$HOME/tools"/jdk-25* "$HOME"/jdk-25* /opt/jdk-25*; do
    [ -d "$p" ] && [ -x "$p/bin/java" ] && { echo "$p"; return 0; }
  done
  return 1
}

GHIDRA_HOME="$(detect_ghidra)" || { echo "❌ 找不到 Ghidra"; exit 1; }
JAVA_HOME_25="$(detect_jdk25)" || { echo "❌ 找不到 JDK 25"; exit 1; }
export JAVA_HOME="$JAVA_HOME_25"
export PATH="$JAVA_HOME/bin:$PATH"

WORK_DIR="/tmp/rea_work_$$"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUTPUT_DIR/decompiled" "$WORK_DIR"

echo "  [1/4] 快速侦察 + 熵值分析..."
FILE_INFO=$(file "$TARGET")
echo "  $FILE_INFO"

STRIPPED="未知"
if echo "$FILE_INFO" | grep -q "not stripped"; then
  STRIPPED="否（保留符号）"
elif echo "$FILE_INFO" | grep -qi "stripped"; then
  STRIPPED="是（无符号）"
fi

# 计算熵值
ENTROPY=$(python3 -c "
import math
data = open('$TARGET', 'rb').read()
if not data:
    print('0.00')
else:
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = -sum((f/len(data)) * math.log2(f/len(data)) for f in freq if f > 0)
    print(f'{ent:.2f}')
")

echo "  熵值: $ENTROPY / 8.0"
if (( $(echo "$ENTROPY > 7.0" | bc -l 2>/dev/null || echo 0) )); then
  ENTROPY_NOTE="⚠️ 高熵，可能加壳或加密"
elif (( $(echo "$ENTROPY > 6.0" | bc -l 2>/dev/null || echo 0) )); then
  ENTROPY_NOTE="中熵，代码+数据混合"
else
  ENTROPY_NOTE="低熵，普通代码"
fi
echo "  $ENTROPY_NOTE"

# 基础信息
{
  echo "文件: $(basename "$TARGET")"
  echo "大小: $(du -h "$TARGET" | cut -f1)"
  echo "架构: $(echo "$FILE_INFO" | grep -o 'x86-64\|ARM\|aarch64\|32-bit\|64-bit' | head -1)"
  echo "Stripped: $STRIPPED"
  echo "熵值: $ENTROPY"
} > "$OUTPUT_DIR/01_basic.txt"

if command -v readelf >/dev/null 2>&1; then
  readelf -h "$TARGET" 2>/dev/null | grep -E "Class|Machine|Entry point" >> "$OUTPUT_DIR/01_basic.txt" || true
fi

echo "  [2/4] 字符串提取 + 分类..."
strings -n 6 "$TARGET" 2>/dev/null > "$OUTPUT_DIR/02_strings_all.txt" || true

# 分类提取
grep -iE "http://|https://|ftp://|ws://" "$OUTPUT_DIR/02_strings_all.txt" | head -30 > "$OUTPUT_DIR/strings_url.txt" || true
grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" "$OUTPUT_DIR/02_strings_all.txt" | head -20 > "$OUTPUT_DIR/strings_ip.txt" || true
grep -iE "password|passwd|secret|key|token|api_key" "$OUTPUT_DIR/02_strings_all.txt" | head -20 > "$OUTPUT_DIR/strings_secret.txt" || true
grep -iE "socket|connect|send|recv|bind|listen" "$OUTPUT_DIR/02_strings_all.txt" | head -20 > "$OUTPUT_DIR/strings_net.txt" || true
grep -iE "system|exec|shell|cmd|command" "$OUTPUT_DIR/02_strings_all.txt" | head -20 > "$OUTPUT_DIR/strings_exec.txt" || true

echo "  URL: $(wc -l < "$OUTPUT_DIR/strings_url.txt" 2>/dev/null || echo 0)"
echo "  IP: $(wc -l < "$OUTPUT_DIR/strings_ip.txt" 2>/dev/null || echo 0)"
echo "  敏感: $(wc -l < "$OUTPUT_DIR/strings_secret.txt" 2>/dev/null || echo 0)"

echo "  [3/4] Ghidra 反编译（智能降噪版，300s 超时）..."
GPROJ="$WORK_DIR/project"
mkdir -p "$GPROJ"

GHIDRA_SUCCESS=false
if timeout 300 "$GHIDRA_HOME/support/analyzeHeadless" \
  "$GPROJ" REA_Proj \
  -import "$TARGET" \
  -scriptPath "$PARENT_DIR" \
  -postScript ExportDecompiled.java "$OUTPUT_DIR/decompiled" 20 \
  > "$OUTPUT_DIR/03_ghidra.log" 2>&1; then
  echo "  ✅ Ghidra 分析成功"
  GHIDRA_SUCCESS=true
else
  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 124 ]; then
    echo "  ⚠️ Ghidra 分析超时 (300s)，触发优雅降级"
  else
    echo "  ⚠️ Ghidra 分析失败 (exit=$EXIT_CODE)，触发优雅降级"
  fi
  echo "  降级模式：仅输出概览结果，不跑完整反编译"
  tail -10 "$OUTPUT_DIR/03_ghidra.log"
fi

echo "  [4/4] 生成结构化体检报告..."
DEC="$OUTPUT_DIR/decompiled"

# 读取元数据
TOTAL_FUNCS="?"
DANGEROUS_FUNCS="?"
EXPORTED_FUNCS="?"
if [ "$GHIDRA_SUCCESS" = true ] && [ -f "$DEC/_meta.txt" ]; then
  TOTAL_FUNCS=$(grep "total_functions=" "$DEC/_meta.txt" | cut -d= -f2)
  DANGEROUS_FUNCS=$(grep "dangerous_functions=" "$DEC/_meta.txt" | cut -d= -f2)
  EXPORTED_FUNCS=$(grep "functions_exported_full=" "$DEC/_meta.txt" | cut -d= -f2)
fi

{
  echo "# 逆向分析体检报告: $(basename "$TARGET")"
  echo ""
  if [ "$GHIDRA_SUCCESS" = false ]; then
    echo "> ⚠️ **降级模式**：Ghidra 分析超时/失败，仅输出概览结果。"
    echo "> 建议：稍后重试，或用 overview.sh 先做基础侦察。"
    echo ""
  fi
  echo "## 1. 文件指纹"
  echo '```'
  cat "$OUTPUT_DIR/01_basic.txt"
  echo '```'
  echo ""
  echo "- 熵值: $ENTROPY → $ENTROPY_NOTE"
  echo ""

  if [ -n "$FOCUS_KEYWORD" ]; then
    echo "## 2. 聚焦检索: \"$FOCUS_KEYWORD\""
    echo ""
    echo '```'
    grep -i "$FOCUS_KEYWORD" "$OUTPUT_DIR/02_strings_all.txt" | head -15 || echo "(字符串无命中)"
    if [ "$GHIDRA_SUCCESS" = true ]; then
      grep -i "$FOCUS_KEYWORD" "$DEC/_xref_strings.txt" 2>/dev/null | head -15 || echo "(XRef 无命中)"
    fi
    echo '```'
    echo ""
  fi

  echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 3 || echo 2 ). 核心字符串分类"
  echo ""
  echo "### URL 地址"
  echo '```'
  cat "$OUTPUT_DIR/strings_url.txt" 2>/dev/null || echo "(无)"
  echo '```'
  echo ""
  echo "### IP 地址"
  echo '```'
  cat "$OUTPUT_DIR/strings_ip.txt" 2>/dev/null || echo "(无)"
  echo '```'
  echo ""
  echo "### 敏感信息"
  echo '```'
  cat "$OUTPUT_DIR/strings_secret.txt" 2>/dev/null || echo "(无)"
  echo '```'
  echo ""
  echo "### 执行相关"
  echo '```'
  cat "$OUTPUT_DIR/strings_exec.txt" 2>/dev/null || echo "(无)"
  echo '```'
  echo ""

  if [ "$GHIDRA_SUCCESS" = true ]; then
    echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 4 || echo 3 ). 函数统计"
    echo ""
    echo "| 指标 | 数值 |"
    echo "|------|------|"
    echo "| 总函数数 | $TOTAL_FUNCS |"
    echo "| 完整反编译（Top 20 + callees） | $EXPORTED_FUNCS |"
    echo "| 危险函数 | $DANGEROUS_FUNCS |"
    echo ""

    echo "### 危险函数列表（三级分级）"
    echo '```'
    cat "$DEC/_dangerous.txt" 2>/dev/null || echo "(未检测到危险函数)"
    echo '```'
    echo ""
  else
    echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 4 || echo 3 ). 函数分析"
    echo ""
    echo "⚠️ 降级模式：Ghidra 未运行，无函数级数据。"
    echo ""
  fi

  echo "### 核心函数（加权排序，前 20）"
  echo '```'
  if [ "$GHIDRA_SUCCESS" = true ]; then
    head -20 "$DEC/_index.txt" 2>/dev/null || echo "(无函数清单)"
  else
    echo "降级模式：无函数清单"
  fi
  echo '```'
  echo ""

  echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 5 || echo 4 ). 字符串 → 函数交叉引用"
  echo ""
  echo '```'
  if [ "$GHIDRA_SUCCESS" = true ]; then
    head -30 "$DEC/_xref_strings.txt" 2>/dev/null || echo "(无 XRef 数据)"
  else
    echo "降级模式：无 XRef 数据"
  fi
  echo '```'
  echo ""

  # 核心函数伪代码预览（每个函数最多 80 行，防止 Token 爆炸）
  if [ "$GHIDRA_SUCCESS" = true ]; then
    echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 6 || echo 5 ). 核心函数伪代码预览"
    echo ""
    echo "> 每个函数最多展示前 80 行，完整代码见 \`decompiled/<addr>_<name>.c\`"
    echo ""
    
    # 取前 5 个 [TOP] 函数做预览
    top5=$(grep "\[TOP\]" "$DEC/_index.txt" | head -5 | cut -f1,2 | tr '\t' '_')
    for func_info in $top5; do
      addr=$(echo "$func_info" | cut -d_ -f1)
      c_file=$(ls "$DEC"/${addr}_*.c 2>/dev/null | head -1)
      if [ -n "$c_file" ] && [ -f "$c_file" ]; then
        func_name=$(basename "$c_file" .c | sed 's/^[0-9a-f]*_//')
        echo "### $func_name"
        echo '```c'
        head -80 "$c_file"
        total_lines=$(wc -l < "$c_file")
        if [ "$total_lines" -gt 80 ]; then
          echo "// ... [代码过长已截断，共 $total_lines 行] ..."
        fi
        echo '```'
        echo ""
      fi
    done
  fi

  echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 7 || echo 6 ). 调用图（前 30 条边）"
  echo ""
  echo '```'
  if [ "$GHIDRA_SUCCESS" = true ]; then
    head -30 "$DEC/_callgraph.txt" 2>/dev/null || echo "(无调用图)"
  else
    echo "降级模式：无调用图"
  fi
  echo '```'
  echo ""

  echo "## $( [ -n "$FOCUS_KEYWORD" ] && echo 8 || echo 7 ). 产物索引"
  echo ""
  if [ "$GHIDRA_SUCCESS" = true ]; then
    echo "- 完整伪代码: \`decompiled/<addr>_<name>.c\`（Top 20 + callees）"
    echo "- 全部函数清单: \`decompiled/_index.txt\`"
    echo "- 危险函数: \`decompiled/_dangerous.txt\`"
    echo "- 字符串 XRef: \`decompiled/_xref_strings.txt\`"
    echo "- 调用图: \`decompiled/_callgraph.txt\`"
    echo "- 跳过清单: \`decompiled/_skipped.txt\`"
  else
    echo "- 基础信息: \`01_basic.txt\`"
    echo "- 字符串分类: \`strings_url.txt\` / \`strings_ip.txt\` / \`strings_secret.txt\`"
    echo "- Ghidra 日志: \`03_ghidra.log\`（查看错误原因）"
  fi
} > "$OUTPUT_DIR/summary.md"

echo "  ✅ 结构化报告已生成: summary.md"
if [ "$GHIDRA_SUCCESS" = true ]; then
  echo "  ✅ Ghidra 后端 v4.2 完成（完整模式）"
else
  echo "  ⚠️ Ghidra 后端 v4.2 完成（降级模式）"
fi
