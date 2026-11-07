#!/bin/bash
# ============================================================
# APK 安卓专项分析
# 用法: ./apk_analyze.sh <app.apk> [输出目录]
# 阶段1: androguard 解析 manifest（package/权限/Activity/主入口/签名）
# 阶段2: 提取 classes*.dex 逐个走 Ghidra 反编译
# 阶段3: 生成安卓专项摘要 summary_apk.md
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APK="${1:?用法: apk_analyze.sh <app.apk> [输出目录]}"
OUT_DIR="${2:-$(pwd)/apk_out_$(date +%s)}"
WORK_DIR="/tmp/rea_apk_$$"
trap 'rm -rf "$WORK_DIR"' EXIT

if [ ! -f "$APK" ]; then
  echo "ERROR: APK 不存在: $APK"; exit 1
fi
if ! command -v python3 >/dev/null || ! python3 -c "import androguard" 2>/dev/null; then
  echo "ERROR: 需要 androguard（pip3 install androguard）"; exit 1
fi

mkdir -p "$OUT_DIR" "$WORK_DIR"

echo "========== [1/3] APK 结构解析（androguard） =========="
python3 "$SCRIPT_DIR/apk_info.py" "$APK" 2>/dev/null | tee "$OUT_DIR/apk_manifest.txt"

echo ""
echo "========== [2/3] dex 反编译（Ghidra 链路） =========="
mkdir -p "$OUT_DIR/decompiled"
cd "$WORK_DIR"
unzip -o -q "$APK" "classes*.dex" 2>/dev/null || { echo "WARN: 未找到 classes*.dex"; }
for dex in classes*.dex; do
  [ -f "$dex" ] || { echo "无 dex 文件"; break; }
  echo "--- 分析 $dex ($(stat -c%s "$dex") bytes) ---"
  bash "$SCRIPT_DIR/analyze.sh" "$WORK_DIR/$dex" "$OUT_DIR/decompiled/dex_${dex%.dex}" >/dev/null 2>&1 || \
    echo "WARN: $dex 分析失败"
done

echo ""
echo "========== [3/3] 生成 APK 摘要 =========="
SUMMARY="$OUT_DIR/summary_apk.md"
{
  echo "# APK 分析摘要: $(basename "$APK")"
  echo ""
  echo "## 1. Manifest 关键信息"
  echo '```'
  head -8 "$OUT_DIR/apk_manifest.txt"
  echo '```'
  echo ""
  echo "## 2. 权限（前20）"
  echo '```'
  grep -a -A20 "permissions(" "$OUT_DIR/apk_manifest.txt" | head -22
  echo '```'
  echo ""
  echo "## 3. 组件清单"
  echo '```'
  sed -n '/activities(/,$p' "$OUT_DIR/apk_manifest.txt" | head -60
  echo '```'
  echo ""
  echo "## 4. dex 反编译统计"
  echo ""
  for m in "$OUT_DIR"/decompiled/dex_*/decompiled/_meta.txt; do
    [ -f "$m" ] && { echo "- $m"; cat "$m"; }
  done
  echo ""
  echo "## 5. 完整产物"
  echo "- Manifest: \`apk_manifest.txt\`"
  echo "- 每 dex 函数清单: \`decompiled/dex_*/decompiled/_index.txt\`"
  echo "- 每 dex 字符串XRef: \`decompiled/dex_*/decompiled/_xref_strings.txt\`"
} > "$SUMMARY"

echo "APK 摘要: $SUMMARY"
echo "分析完成。输出目录: $OUT_DIR"
