#!/bin/bash
# 持久化机制检测工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/persist_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 持久化机制检测 ==="
echo "目标: $TARGET"
echo ""

echo "[1] 注册表启动项检测（Windows）..."
strings "$TARGET" 2>/dev/null | grep -iE "HKEY_|Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce|CurrentVersion\\\\Explorer|Shell Folders|Startup" | head -20 > "$OUTPUT_DIR/registry_persist.txt"
echo "注册表持久化: $(wc -l < "$OUTPUT_DIR/registry_persist.txt") 条"
cat "$OUTPUT_DIR/registry_persist.txt"

echo ""
echo "[2] 服务检测（Windows/Linux）..."
strings "$TARGET" 2>/dev/null | grep -iE "CreateService|StartService|OpenSCManager|services\.msc|systemd|systemctl|/etc/systemd|/etc/init.d|crontab|cron\.d|crontab\.d" | head -20 > "$OUTPUT_DIR/service_persist.txt"
echo "服务持久化: $(wc -l < "$OUTPUT_DIR/service_persist.txt") 条"
cat "$OUTPUT_DIR/service_persist.txt"

echo ""
echo "[3] 启动文件夹检测..."
strings "$TARGET" 2>/dev/null | grep -iE "Startup|startup.*folder|启动|autostart|autoexec|\.bashrc|\.bash_profile|\.profile|\.zshrc" | head -20 > "$OUTPUT_DIR/startup_persist.txt"
echo "启动文件夹持久化: $(wc -l < "$OUTPUT_DIR/startup_persist.txt") 条"
cat "$OUTPUT_DIR/startup_persist.txt"

echo ""
echo "[4] 计划任务检测..."
strings "$TARGET" 2>/dev/null | grep -iE "schtasks|Task Scheduler|at\.exe|cron|crontab|anacron|systemd-timer" | head -15 > "$OUTPUT_DIR/task_persist.txt"
echo "计划任务持久化: $(wc -l < "$OUTPUT_DIR/task_persist.txt") 条"
cat "$OUTPUT_DIR/task_persist.txt"

echo ""
echo "[5] DLL 注入检测..."
strings "$TARGET" 2>/dev/null | grep -iE "CreateRemoteThread|LoadLibrary|DllLoad|AppInit_DLLs|AppInit|IFEO|Image File Execution Options" | head -15 > "$OUTPUT_DIR/dll_inject.txt"
echo "DLL 注入特征: $(wc -l < "$OUTPUT_DIR/dll_inject.txt") 条"
cat "$OUTPUT_DIR/dll_inject.txt"

echo ""
echo "输出目录: $OUTPUT_DIR"
