#!/bin/bash
# 统一逆向工具包 - 入口脚本
# 自动检测可用后端工具，选择最佳工具执行分析

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKENDS_DIR="$SCRIPT_DIR/backends"

# 默认参数
TARGET=""
OUTPUT_DIR=""
BACKEND="auto"
FOCUS_KEYWORD=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "用法: bash analyze.sh <目标二进制> [输出目录] [选项]"
    echo ""
    echo "选项:"
    echo "  --backend <工具>   指定后端工具: ghidra / ida / hopper / r2 / auto(默认)"
    echo "  --focus <关键词>   聚焦检索关键词"
    echo "  -h, --help        显示帮助"
    echo ""
    echo "示例:"
    echo "  bash analyze.sh ./target"
    echo "  bash analyze.sh ./target ./output --backend ghidra"
    echo "  bash analyze.sh ./target --focus 'login'"
}

# 检测后端工具是否可用
check_backend() {
    local backend=$1
    case $backend in
        ghidra)
            # 自动探测 Ghidra 路径：环境变量 → 常见安装位置
            local ghidra_home="${GHIDRA_HOME:-}"
            if [ -z "$ghidra_home" ]; then
                for p in "$HOME/tools"/ghidra_* "$HOME"/ghidra_* /opt/ghidra_*; do
                    [ -d "$p" ] && [ -f "$p/support/analyzeHeadless" ] && ghidra_home="$p" && break
                done
            fi
            if [ -n "$ghidra_home" ] && [ -f "$ghidra_home/support/analyzeHeadless" ]; then
                echo "✅ Ghidra 可用: $ghidra_home"
                return 0
            else
                echo "❌ Ghidra 未找到（设置 GHIDRA_HOME 环境变量）"
                return 1
            fi
            ;;
        r2)
            if command -v r2 &> /dev/null; then
                echo "✅ Radare2 可用"
                return 0
            else
                echo "❌ Radare2 未找到"
                return 1
            fi
            ;;
        ida)
            if command -v ida64 &> /dev/null || command -v ida &> /dev/null; then
                echo "✅ IDA Pro 可用"
                return 0
            else
                echo "❌ IDA Pro 未找到"
                return 1
            fi
            ;;
        hopper)
            if command -v hopper &> /dev/null; then
                echo "✅ Hopper 可用"
                return 0
            else
                echo "❌ Hopper 未找到 (macOS 专属)"
                return 1
            fi
            ;;
        *)
            echo "❌ 未知后端: $backend"
            return 1
            ;;
    esac
}

# 自动选择最佳后端
select_best_backend() {
    echo -e "${YELLOW}🔍 自动检测可用后端工具...${NC}" >&2
    
    # 优先级: Ghidra > IDA > Hopper > Radare2
    if check_backend ghidra >&2; then
        echo -e "${GREEN}✅ 选择后端: Ghidra${NC}" >&2
        echo "ghidra"
        return
    fi
    
    if check_backend ida >&2; then
        echo -e "${GREEN}✅ 选择后端: IDA Pro${NC}" >&2
        echo "ida"
        return
    fi
    
    if check_backend hopper >&2; then
        echo -e "${GREEN}✅ 选择后端: Hopper${NC}" >&2
        echo "hopper"
        return
    fi
    
    if check_backend r2 >&2; then
        echo -e "${GREEN}✅ 选择后端: Radare2${NC}" >&2
        echo "r2"
        return
    fi
    
    echo -e "${RED}❌ 没有可用的逆向工具！请安装 Ghidra 或 Radare2${NC}" >&2
    exit 1
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend)
            BACKEND="$2"
            shift 2
            ;;
        --focus)
            FOCUS_KEYWORD="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo -e "${RED}未知选项: $1${NC}"
            usage
            exit 1
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            elif [ -z "$OUTPUT_DIR" ]; then
                OUTPUT_DIR="$1"
            fi
            shift
            ;;
    esac
done

# 检查目标文件
if [ -z "$TARGET" ]; then
    echo -e "${RED}❌ 错误: 请指定目标二进制文件${NC}"
    usage
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo -e "${RED}❌ 错误: 文件不存在: $TARGET${NC}"
    exit 1
fi

# 设置默认输出目录
if [ -z "$OUTPUT_DIR" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="rea_out_${TIMESTAMP}"
fi

# ===== 环境自检 =====
echo -e "${YELLOW}🔍 环境自检...${NC}"
ENV_OK=true

# 必需工具
for tool in python3 strings file readelf; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "  ❌ 缺少必需工具: $tool"
        ENV_OK=false
    else
        echo -e "  ✅ $tool"
    fi
done

# 可选工具提示
echo ""
echo "可选工具:"
if command -v upx &> /dev/null; then
    echo -e "  ✅ upx (脱壳)"
else
    echo -e "  ⚠️ upx 未安装（脱壳分析不可用）"
fi

if command -v yara &> /dev/null; then
    echo -e "  ✅ yara (恶意特征扫描)"
else
    echo -e "  ⚠️ yara 未安装（YARA 扫描降级为手动模式）"
fi

if command -v binwalk &> /dev/null; then
    echo -e "  ✅ binwalk (固件分析)"
else
    echo -e "  ⚠️ binwalk 未安装（固件分析不可用）"
fi

if [ "$ENV_OK" = false ]; then
    echo -e "${RED}❌ 缺少必需工具，无法继续${NC}"
    exit 1
fi
echo ""

# 选择后端
if [ "$BACKEND" = "auto" ]; then
    BACKEND=$(select_best_backend)
else
    echo -e "${YELLOW}🔧 指定后端: $BACKEND${NC}"
    check_backend $BACKEND
fi

echo ""
echo "=========================================="
echo "  逆向工程分析"
echo "=========================================="
echo "  目标: $TARGET"
echo "  输出: $OUTPUT_DIR"
echo "  后端: $BACKEND"
if [ -n "$FOCUS_KEYWORD" ]; then
    echo "  聚焦: $FOCUS_KEYWORD"
fi
echo "=========================================="
echo ""

# 调用对应后端脚本
mkdir -p "$OUTPUT_DIR"

case $BACKEND in
    ghidra)
        echo -e "${GREEN}🚀 启动 Ghidra 后端...${NC}"
        bash "$BACKENDS_DIR/ghidra.sh" "$TARGET" "$OUTPUT_DIR" "$FOCUS_KEYWORD"
        ;;
    r2)
        echo -e "${GREEN}🚀 启动 Radare2 后端...${NC}"
        bash "$BACKENDS_DIR/r2.sh" "$TARGET" "$OUTPUT_DIR" "$FOCUS_KEYWORD"
        ;;
    ida)
        echo -e "${YELLOW}⚠️ IDA 后端尚未实现，请使用 Ghidra${NC}"
        exit 1
        ;;
    hopper)
        echo -e "${YELLOW}⚠️ Hopper 后端尚未实现，请使用 Ghidra${NC}"
        exit 1
        ;;
    *)
        echo -e "${RED}❌ 未知后端: $BACKEND${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ 分析完成！${NC}"
echo "输出目录: $OUTPUT_DIR"
echo "先看 summary.md 了解全貌"
