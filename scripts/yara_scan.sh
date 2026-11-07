#!/bin/bash
# 外挂：YARA 扫描工具 - 检测已知恶意软件特征
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/yara_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== YARA 恶意特征扫描 ==="
echo "目标: $TARGET"
echo ""

# 检查 yara 是否安装
if ! command -v yara >/dev/null 2>&1; then
    echo "⚠️ yara 未安装"
    echo "安装: sudo apt install yara"
    echo ""
    echo "--- 手动检测（用 strings 模拟）---"
    
    echo "常见恶意软件家族特征字符串:"
    strings "$TARGET" 2>/dev/null | grep -iE "metasploit|meterpreter|cobalt|stitch|beacon|emotet|trickbot|ryuk|cont|wanna|locky|crypt|ransom|trojan|backdoor|rat|keylog|spy|inject|hook" | head -30 > "$OUTPUT_DIR/manual_indicators.txt"
    
    echo "检测到的可疑特征:"
    cat "$OUTPUT_DIR/manual_indicators.txt" || echo "(无明显特征)"
    
    echo ""
    echo "--- 常见 C2 特征（长字符串匹配，减少误报）---"
    strings -n 8 "$TARGET" 2>/dev/null | grep -iE "command.*control|callback|reverse.*shell|beacon|checkin|meterpreter|cobalt.*strike" | head -20 > "$OUTPUT_DIR/c2_indicators.txt"
    cat "$OUTPUT_DIR/c2_indicators.txt" || echo "(无明显 C2 特征)"
    
    echo ""
    echo "输出目录: $OUTPUT_DIR"
    exit 0
fi

echo "✅ yara 已安装: $(yara --version)"

# 内置基础 YARA 规则
cat > "$OUTPUT_DIR/basic_rules.yar" << 'YARA_RULES'
rule UPX_Packed {
    meta:
        description = "Detects UPX packed files"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        all of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Generic Cobalt Strike Beacon signature"
        severity = "critical"
    strings:
        $s1 = "beacon.dll" ascii nocase
        $s2 = "ReflectiveLoader" ascii
        $s3 = "%s (%d) state: %s" ascii
        $s4 = "cobaltstrike" ascii nocase
    condition:
        any of them
}

rule Ransomware_Indicators {
    meta:
        description = "Generic ransomware indicators"
        severity = "critical"
    strings:
        $s1 = "ransom" ascii nocase
        $s2 = "your files are encrypted" ascii nocase
        $s3 = "bitcoin" ascii nocase
        $s4 = "decrypt" ascii nocase
        $s5 = "wanna" ascii nocase
        $s6 = "locky" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Network {
    meta:
        description = "Suspicious network indicators (long strings only to reduce false positives)"
        severity = "medium"
    strings:
        $s1 = "URLDownloadToFile" ascii
        $s2 = "InternetOpenA" ascii
        $s3 = "InternetOpenW" ascii
        $s4 = "HttpSendRequest" ascii
        $s5 = "WSAStartup" ascii
        $s6 = "gethostbyname" ascii
    condition:
        2 of them
}

rule Suspicious_Execution {
    meta:
        description = "Suspicious execution indicators (long strings only)"
        severity = "high"
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "WriteProcessMemory" ascii
        $s3 = "CreateProcessA" ascii
        $s4 = "CreateProcessW" ascii
        $s5 = "WinExec" ascii
        $s6 = "system" ascii fullword
    condition:
        2 of them
}

rule Suspicious_Persistence {
    meta:
        description = "Suspicious persistence indicators (long strings only)"
        severity = "high"
    strings:
        $s1 = "CurrentVersion\\Run" ascii
        $s2 = "CreateServiceA" ascii
        $s3 = "CreateServiceW" ascii
        $s4 = "StartServiceA" ascii
        $s5 = "schtasks" ascii
        $s6 = "crontab" ascii fullword
    condition:
        2 of them
}

rule Possible_Malware {
    meta:
        description = "Possible malware indicators"
        severity = "critical"
    strings:
        $s1 = "meterpreter" ascii
        $s2 = "metasploit" ascii
        $s3 = "cobalt" ascii
        $s4 = "beacon" ascii
        $s5 = "emotet" ascii
        $s6 = "trickbot" ascii
        $s7 = "ransom" ascii
        $s8 = "crypt" ascii
    condition:
        1 of them
}

rule Packed_Binary {
    meta:
        description = "Packed binary indicators"
        severity = "medium"
    strings:
        $s1 = "UPX!" ascii
        $s2 = ".upx" ascii
        $s3 = "aspack" ascii
        $s4 = "themida" ascii
        $s5 = "vmprotect" ascii
        $s6 = "enigma" ascii
    condition:
        1 of them
}
YARA_RULES

echo ""
echo "[1/2] 运行基础 YARA 规则扫描..."
yara -r "$OUTPUT_DIR/basic_rules.yar" "$TARGET" > "$OUTPUT_DIR/yara_results.txt" 2>&1 || true

echo "扫描结果:"
cat "$OUTPUT_DIR/yara_results.txt" || echo "(无规则匹配)"

echo ""
echo "[2/2] 如果有第三方规则库，也可以扫描..."
echo "用法: yara -r /path/to/rules/ $TARGET"

echo ""
echo "输出目录: $OUTPUT_DIR"
echo "结果文件: $OUTPUT_DIR/yara_results.txt"
