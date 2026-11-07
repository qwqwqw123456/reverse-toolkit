#!/bin/bash
# ============================================================
# 分析工具总闸（快速全景）
# 用法: ./toolbox.sh <目标> 
# 一个命令输出目标全景：文件信息 / 哈希 / 架构符号 / 安全属性(checksec) / 字符串 / 熵
# 深度反编译请用 analyze.sh（Ghidra 全链路）
# ============================================================
set -uo pipefail

TARGET="${1:?用法: toolbox.sh <目标二进制>}"
if [ ! -f "$TARGET" ]; then echo "ERROR: 目标不存在: $TARGET"; exit 1; fi

echo "========== 1. 文件信息 =========="
file "$TARGET"
echo "大小: $(stat -c%s "$TARGET") bytes"

echo ""
echo "========== 2. 哈希指纹 =========="
echo "SHA256: $(sha256sum "$TARGET" | cut -d' ' -f1)"
echo "MD5   : $(md5sum "$TARGET" | cut -d' ' -f1)"

echo ""
echo "========== 3. 架构与入口 =========="
if command -v readelf >/dev/null; then
  readelf -h "$TARGET" 2>/dev/null | grep -E "Class|Data|Machine|Type|Entry point" || true
fi
if command -v nm >/dev/null; then
  SYMS=$(nm "$TARGET" 2>/dev/null | wc -l)
  echo "符号表: $SYMS 条 (stripped 则为0)"
fi

echo ""
echo "========== 4. 安全属性 (checksec 简易版) =========="
# NX / RELRO / PIE / Canary 四项
NXN="已启用"; RELRO="无"; PIEN="否"; CANARY="否"
# GNU_STACK 标志: 含 E=栈可执行=NX未启用; RW=NX已启用
STACKFLAGS=$(readelf -l "$TARGET" 2>/dev/null | grep -A1 "GNU_STACK" | tail -1 | awk '{print $NF}')
case "$STACKFLAGS" in
  *E*) NXN="未启用（栈可执行）" ;;
  "")  NXN="未知" ;;
esac
readelf -d "$TARGET" 2>/dev/null | grep -q "BIND_NOW" && RELRO="FULL"
readelf -d "$TARGET" 2>/dev/null | grep -q "GNU_RELRO" && [ "$RELRO" = "无" ] && RELRO="PARTIAL"
readelf -h "$TARGET" 2>/dev/null | grep -q "Type:.*DYN" && PIEN="是"
strings "$TARGET" 2>/dev/null | grep -q "__stack_chk_fail" && CANARY="是"
echo "NX(堆栈不可执行): $NXN"
echo "RELRO: $RELRO"
echo "PIE: $PIEN"
echo "Stack Canary: $CANARY"

echo ""
echo "========== 5. 字符串统计 =========="
STR_TOTAL=$(strings -n 6 "$TARGET" 2>/dev/null | wc -l)
STR_WIDE=$(strings -n 6 -e l "$TARGET" 2>/dev/null | wc -l)
echo "ASCII 字符串(>=6): $STR_TOTAL 条"
echo "UTF-16/宽字符串:   $STR_WIDE 条"
echo "--- 最长/特征字符串 Top 10 ---"
strings -n 6 "$TARGET" 2>/dev/null | awk '{print length, $0}' | sort -rn | head -10 | cut -d' ' -f2-

echo ""
echo "========== 6. 关键词检索（密码/密钥/URL/命令） =========="
for kw in "password" "secret" "api" "http://" "https://" "token" "key" "BEGIN" "perl" "python" "flag"; do
  C=$(strings -n 5 "$TARGET" 2>/dev/null | grep -ci "$kw" || true)
  [ "$C" -gt 0 ] && echo "  [$kw]: $C 处"
done

echo ""
echo "========== 7. 熵估算（加密/压缩信号） =========="
python3 - "$TARGET" <<'PYEOF' 2>/dev/null || echo "熵计算跳过"
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
if len(data) > 64*1024*1024:
    data = data[:64*1024*1024]  # 大文件采样前 64MB
freq = collections.Counter(data)
n = len(data)
ent = -sum((c/n)*math.log2(c/n) for c in freq.values())
print("样本 %.1fMB 熵 = %.2f bit/byte (典型: 文本4-5, 压缩/加密7-8)" % (n/1048576, ent))
PYEOF

echo ""
echo "========== 8. 深度分析提示 =========="
echo "需要反编译/函数级分析时运行: analyze.sh $TARGET <输出目录>"
