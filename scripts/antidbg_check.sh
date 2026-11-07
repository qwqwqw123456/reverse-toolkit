#!/bin/bash
# 反调试检测工具 - 检测二进制中的反调试手段
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/antidbg_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 反调试检测分析 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 检测反调试 API 调用..."
echo "--- 常见反调试函数 ---"
strings "$TARGET" 2>/dev/null | grep -iE "IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|NtQuerySystemInformation|OutputDebugString|DebugActiveProcess|FindWindow|FindWindowA|GetForegroundWindow|Process32Next|CreateToolhelp32Snapshot" | head -20 || echo "(未检测到常见反调试 API 字符串)"

echo ""
echo "--- 调试器进程名检测 ---"
strings "$TARGET" 2>/dev/null | grep -iE "x64dbg|x32dbg|ollydbg|ida|ghidra|windbg|gdb|lldb|debugger" | head -15 || echo "(未检测到调试器进程名字符串)"

echo ""
echo "[2] 检测反虚拟机手段..."
strings "$TARGET" 2>/dev/null | grep -iE "vmware|virtualbox|vbox|qemu|xen|hyper-v|vmsrvc|vmtools|vm3dservice|virtual machine" | head -15 || echo "(未检测到反虚拟机字符串)"

echo ""
echo "[3] 检测常见反调试手段对照..."
echo "反调试类型对照表:"
echo "  用户态 API: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess"
echo "  进程检测:   CreateToolhelp32Snapshot, Process32Next, 查找调试器进程名"
echo "  窗口检测:   FindWindow 查找调试器窗口"
echo "  时间检测:   GetTickCount, QueryPerformanceCounter 检测运行时间"
echo "  硬件断点:   检测 DR0-DR7 寄存器"
echo "  异常检测:   故意触发异常，检测是否被调试器捕获"
echo "  钩子检测:   检测是否被 Hook"

echo ""
echo "[4] 绕过建议..."
echo "1. 用户态 API 反调试: Patch 掉检测函数，或 Hook 它返回 false"
echo "2. 进程检测: 重命名调试器，或用 Hide 插件隐藏"
echo "3. 时间检测: 调试器设置，跳过时间检测"
echo "4. 硬件断点检测: 不用硬件断点，用软件断点"
echo "5. 异常检测: 调试器设置忽略异常"

echo ""
echo "输出目录: $OUTPUT_DIR"
