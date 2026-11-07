#!/bin/bash
# ============================================================
# Reverse-Toolkit 一键安装脚本
# 自动检测环境并安装缺失依赖
# ============================================================
set -euo pipefail

echo "=========================================="
echo "Reverse-Toolkit 一键安装"
echo "=========================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_status=0

# 检测命令
check_cmd() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}✅ $1${NC}: $($1 --version 2>&1 | head -1)"
        return 0
    else
        echo -e "  ${RED}❌ $1${NC}: 未安装"
        return 1
    fi
}

# 检测 Python 包
check_pip() {
    if python3 -c "import $1" &> /dev/null; then
        echo -e "  ${GREEN}✅ python3-$1${NC}: 已安装"
        return 0
    else
        echo -e "  ${YELLOW}⚠️  python3-$1${NC}: 未安装"
        return 1
    fi
}

echo "【1/5】检测系统基础依赖..."
echo ""

check_cmd python3 || check_status=1
check_cmd strings || check_status=1
check_cmd file || check_status=1
check_cmd readelf || check_status=1

echo ""
echo "【2/5】检测逆向工具..."
echo ""

check_cmd upx || echo -e "  ${YELLOW}建议安装: upx（脱壳用）${NC}"
check_cmd yara || echo -e "  ${YELLOW}建议安装: yara（恶意特征扫描）${NC}"
check_cmd r2 || echo -e "  ${YELLOW}建议安装: radare2（轻量反编译后端）${NC}"

echo ""
echo "【3/5】检测 Python 依赖..."
echo ""

check_pip mcp || echo -e "  ${YELLOW}需要安装: pip install mcp${NC}"

echo ""
echo "【4/5】检测 Ghidra..."
echo ""

# 检测 Ghidra
GHIDRA_FOUND=false
for p in "$HOME/tools"/ghidra_* "$HOME"/ghidra_* /opt/ghidra_*; do
    if [ -d "$p" ] && [ -x "$p/support/analyzeHeadless" ]; then
        echo -e "  ${GREEN}✅ Ghidra${NC}: $p"
        GHIDRA_FOUND=true
        break
    fi
done
if [ "$GHIDRA_FOUND" = false ]; then
    echo -e "  ${YELLOW}⚠️  Ghidra${NC}: 未找到（完整反编译需要）"
fi

# 检测 JDK 25
JAVA_FOUND=false
for p in "$HOME/tools"/jdk-25* "$HOME"/jdk-25* /opt/jdk-25*; do
    if [ -d "$p" ] && [ -x "$p/bin/java" ]; then
        echo -e "  ${GREEN}✅ JDK 25${NC}: $p"
        JAVA_FOUND=true
        break
    fi
done
if [ "$JAVA_FOUND" = false ]; then
    echo -e "  ${YELLOW}⚠️  JDK 25${NC}: 未找到（Ghidra 12.2 需要）"
fi

echo ""
echo "【5/5】安装缺失依赖..."
echo ""

# 安装 Python 依赖
echo "安装 Python 包..."
pip3 install mcp 2>&1 | tail -3 || echo -e "  ${YELLOW}pip install mcp 失败，请手动安装${NC}"

echo ""
echo "=========================================="
echo "安装检查完成！"
echo "=========================================="
echo ""

if [ $check_status -eq 0 ]; then
    echo -e "${GREEN}基础环境就绪！${NC}"
else
    echo -e "${YELLOW}部分基础依赖缺失，请先安装。${NC}"
fi

echo ""
echo "快速开始:"
echo "  1. 快速概览: bash scripts/overview.sh <目标>"
echo "  2. 完整报告: python3 scripts/generate_report.py <目标>"
echo "  3. MCP 模式: python3 mcp_server.py"
echo ""
echo "详细文档: 见 README.md"
