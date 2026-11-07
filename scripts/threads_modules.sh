#!/bin/bash
# 线程与模块分析工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/threads_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 线程与模块分析 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 线程相关 API 检测..."
strings "$TARGET" 2>/dev/null | grep -iE "CreateThread|_beginthread|pthread_create|std::thread|std::async|fork|clone" | head -20 > "$OUTPUT_DIR/thread_apis.txt"
echo "线程 API: $(wc -l < "$OUTPUT_DIR/thread_apis.txt") 条"
cat "$OUTPUT_DIR/thread_apis.txt"

echo ""
echo "[2] 同步原语检测..."
strings "$TARGET" 2>/dev/null | grep -iE "mutex|critical_section|semaphore|event|condition_variable|spinlock|rwlock|barrier" | head -20 > "$OUTPUT_DIR/sync_apis.txt"
echo "同步原语: $(wc -l < "$OUTPUT_DIR/sync_apis.txt") 条"
cat "$OUTPUT_DIR/sync_apis.txt"

echo ""
echo "[3] 模块加载检测..."
strings "$TARGET" 2>/dev/null | grep -iE "LoadLibrary|dlopen|GetProcAddress|dlsym|module|library|\.dll|\.so|\.dylib" | head -30 > "$OUTPUT_DIR/module_apis.txt"
echo "模块加载 API: $(wc -l < "$OUTPUT_DIR/module_apis.txt") 条"
cat "$OUTPUT_DIR/module_apis.txt"

echo ""
echo "[4] 动态库依赖检测..."
if command -v readelf >/dev/null 2>&1; then
    readelf -d "$TARGET" 2>/dev/null | grep NEEDED > "$OUTPUT_DIR/dependencies.txt" || echo "(无动态库依赖)"
    echo "动态库依赖:"
    cat "$OUTPUT_DIR/dependencies.txt"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
