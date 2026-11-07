#!/bin/bash
# 网络相关字符串检测工具
set -e

TARGET="$1"
OUTPUT_DIR="${2:-$(pwd)/net_out_$(date +%s)}"
mkdir -p "$OUTPUT_DIR"

echo "=== 网络相关检测 ==="
echo "目标: $TARGET"
echo ""

echo "[1] URL 检测..."
strings -n 8 "$TARGET" 2>/dev/null | grep -iE "http://|https://|ftp://|ws://|wss://|tcp://|udp://" | head -30 > "$OUTPUT_DIR/urls.txt"
echo "URL 数量: $(wc -l < "$OUTPUT_DIR/urls.txt")"
cat "$OUTPUT_DIR/urls.txt"

echo ""
echo "[2] IP 地址检测..."
strings -n 7 "$TARGET" 2>/dev/null | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -30 > "$OUTPUT_DIR/ips.txt"
echo "IP 数量: $(wc -l < "$OUTPUT_DIR/ips.txt")"
cat "$OUTPUT_DIR/ips.txt"

echo ""
echo "[3] 域名检测..."
strings -n 6 "$TARGET" 2>/dev/null | grep -E "[a-zA-Z0-9-]+\.[a-zA-Z]{2,}" | grep -vE "\.(txt|dat|bin|exe|dll|so|cpp|h|py|java|class)$" | head -30 > "$OUTPUT_DIR/domains.txt"
echo "域名数量: $(wc -l < "$OUTPUT_DIR/domains.txt")"
cat "$OUTPUT_DIR/domains.txt"

echo ""
echo "[4] 网络 API 检测..."
strings "$TARGET" 2>/dev/null | grep -iE "socket|connect|send|recv|bind|listen|accept|gethostbyname|inet_addr|WSAStartup|InternetOpen|HttpOpenRequest|URLDownload|WinHttp|WinInet|curl|libcurl" | head -30 > "$OUTPUT_DIR/net_apis.txt"
echo "网络 API 数量: $(wc -l < "$OUTPUT_DIR/net_apis.txt")"
cat "$OUTPUT_DIR/net_apis.txt"

echo ""
echo "[5] C2 特征检测（可疑）..."
strings "$TARGET" 2>/dev/null | grep -iE "c2|command.*control|beacon|callback|reverse.*shell|bind.*shell|meterpreter|cobalt|beacon|payload" | head -20 > "$OUTPUT_DIR/c2_indicators.txt"
echo "C2 特征数量: $(wc -l < "$OUTPUT_DIR/c2_indicators.txt")"
if [ -s "$OUTPUT_DIR/c2_indicators.txt" ]; then
    echo "⚠️ 检测到可疑 C2 特征:"
    cat "$OUTPUT_DIR/c2_indicators.txt"
fi

echo ""
echo "输出目录: $OUTPUT_DIR"
