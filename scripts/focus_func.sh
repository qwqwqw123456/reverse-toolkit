#!/bin/bash
# 渐进式分析 - 第二轮：聚焦函数深挖模式
# 用途：根据第一轮发现的可疑字符串/API，深挖特定函数的伪代码
set -euo pipefail

TARGET="$1"
FOCUS="$2"
OUTPUT_DIR="${3:-$(pwd)/focus_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ] || [ -z "$FOCUS" ]; then
    echo "用法: focus_func.sh <目标二进制> <关键词> [输出目录]"
    echo "示例: focus_func.sh ./target \"CreateProcessA\""
    echo "      focus_func.sh ./target \"http://\""
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$SCRIPT_DIR"

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

WORK_DIR="/tmp/rea_focus_$$"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUTPUT_DIR/decompiled" "$WORK_DIR"

echo "=== 第二轮：聚焦深挖模式 ==="
echo "目标: $TARGET"
echo "关键词: $FOCUS"
echo ""

echo "[1/3] 在字符串中定位关键词..."
strings -n 4 "$TARGET" 2>/dev/null | grep -i "$FOCUS" | head -10

echo ""
echo "[2/3] Ghidra 反编译 + 聚焦提取..."
GPROJ="$WORK_DIR/project"
mkdir -p "$GPROJ"

if timeout 900 "$GHIDRA_HOME/support/analyzeHeadless" \
  "$GPROJ" REA_Proj \
  -import "$TARGET" \
  -scriptPath "$PARENT_DIR" \
  -postScript ExportDecompiled.java "$OUTPUT_DIR/decompiled" 50 \
  > "$OUTPUT_DIR/03_ghidra.log" 2>&1; then
  echo "  ✅ Ghidra 分析完成"
else
  echo "  ⚠️ Ghidra 分析失败"
  exit 1
fi

echo ""
echo "[3/3] 提取聚焦相关的函数..."
DEC="$OUTPUT_DIR/decompiled"

echo "--- 包含关键词的字符串引用 ---"
grep -i "$FOCUS" "$DEC/_xref_strings.txt" 2>/dev/null | head -20 || echo "(无直接命中)"

echo ""
echo "--- 包含关键词的函数名 ---"
grep -i "$FOCUS" "$DEC/_index.txt" 2>/dev/null | head -20 || echo "(无直接命中)"

echo ""
echo "--- 危险函数列表 ---"
cat "$DEC/_dangerous.txt" 2>/dev/null | head -20 || echo "(无)"

echo ""
echo "=== 第二轮深挖完成 ==="
echo "输出目录: $OUTPUT_DIR"
echo ""
echo "下一步建议："
echo "  1. 打开 decompiled/ 目录，查看聚焦相关的函数伪代码"
echo "  2. 找到核心函数后，人工分析其逻辑"
