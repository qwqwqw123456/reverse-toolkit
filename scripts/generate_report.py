#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动报告生成工具 v1.0
把多个分析工具的结果汇总成一份完整的 Markdown 报告
"""
import subprocess
import os
import sys
import re
import json
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_script(script_name, args, timeout=60):
    """运行 shell 脚本并返回输出"""
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.exists(script_path):
        return f"[ERROR] 脚本不存在: {script_name}"
    try:
        result = subprocess.run(
            ["bash", script_path] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + (("\n--- stderr ---\n" + result.stderr) if result.stderr else "")
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {script_name} 超时"
    except Exception as e:
        return f"[EXCEPTION] {type(e).__name__}: {str(e)}"

def extract_iocs(text):
    """从文本中提取 IOC"""
    iocs = {
        "urls": [],
        "ips": [],
        "domains": [],
        "hashes": {},
        "sensitive_strings": []
    }
    
    # URL
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    iocs["urls"] = list(set(urls))[:20]
    
    # IP
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    iocs["ips"] = list(set(ips))[:20]
    
    # 域名
    domains = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', text)
    iocs["domains"] = list(set(domains))[:20]
    
    # 敏感字符串
    sensitive = re.findall(r'(?:password|passwd|secret|key|token|api_key|private)[^\n]*', text, re.I)
    iocs["sensitive_strings"] = list(set(sensitive))[:20]
    
    return iocs

def calculate_risk_score(overview_output, threats_output, imports_output):
    """计算风险评分"""
    score = 0
    reasons = []
    
    # 熵值
    entropy_match = re.search(r'熵值:\s*([\d.]+)', overview_output)
    if entropy_match:
        entropy = float(entropy_match.group(1))
        if entropy > 7.0:
            score += 30
            reasons.append(f"高熵值 {entropy:.2f}（可能加壳/加密）")
        elif entropy > 6.0:
            score += 15
            reasons.append(f"中熵值 {entropy:.2f}")
    
    # 加壳检测
    if "UPX!" in overview_output or "upx" in overview_output.lower():
        score += 20
        reasons.append("检测到 UPX 壳")
    
    # 危险 API
    dangerous_apis = ["system", "execve", "CreateProcess", "CreateRemoteThread", 
                      "WriteProcessMemory", "WinExec", "ShellExecute", "popen"]
    api_count = 0
    for api in dangerous_apis:
        if api.lower() in imports_output.lower():
            api_count += 1
    if api_count >= 5:
        score += 30
        reasons.append(f"检测到 {api_count} 个高危执行 API")
    elif api_count >= 2:
        score += 15
        reasons.append(f"检测到 {api_count} 个高危执行 API")
    
    # 网络特征
    if "socket" in imports_output.lower() or "connect" in imports_output.lower():
        score += 10
        reasons.append("包含网络连接 API")
    
    # YARA 命中
    if "critical" in threats_output.lower() or "Critical" in threats_output:
        score += 25
        reasons.append("YARA 检测到严重恶意特征")
    elif "medium" in threats_output.lower():
        score += 10
        reasons.append("YARA 检测到中等可疑特征")
    
    # 评级
    if score >= 70:
        level = "严重"
        emoji = "🔴"
    elif score >= 40:
        level = "高"
        emoji = "🟠"
    elif score >= 20:
        level = "中"
        emoji = "🟡"
    else:
        level = "低"
        emoji = "🟢"
    
    return score, level, emoji, reasons

def generate_report(target_path, output_dir=None):
    """生成完整报告"""
    if not os.path.exists(target_path):
        print(f"[ERROR] 文件不存在: {target_path}")
        return
    
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(target_path), f"report_{os.path.basename(target_path)}")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"=== 自动报告生成 ===")
    print(f"目标: {target_path}")
    print(f"输出: {output_dir}")
    print()
    
    # Step 1: 快速概览
    print("[1/6] 收集概览信息...")
    overview = run_script("overview.sh", [target_path])
    
    # Step 2: 字符串提取
    print("[2/6] 提取字符串分类...")
    strings = run_script("strings_extract.sh", [target_path])
    
    # Step 3: 导入表分析
    print("[3/6] 分析导入表...")
    imports = run_script("imports_exports.sh", [target_path])
    
    # Step 4: 威胁扫描
    print("[4/6] 威胁特征扫描...")
    threats = run_script("yara_scan.sh", [target_path])
    
    # Step 5: 网络特征
    print("[5/6] 检测网络特征...")
    network = run_script("net_detect.sh", [target_path])
    
    # Step 6: 加密检测
    print("[6/6] 检测加密算法...")
    crypto = run_script("crypto_detect.sh", [target_path])
    
    # 汇总提取 IOC
    all_text = overview + strings + imports + threats + network + crypto
    iocs = extract_iocs(all_text)
    
    # 计算风险评分
    score, level, emoji, reasons = calculate_risk_score(overview, threats, imports)
    
    # 生成 Markdown 报告
    report = f"""# 逆向分析报告: {os.path.basename(target_path)}

> 生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## {emoji} 风险评级: {level} ({score}/100)

**评分依据:**
"""
    for r in reasons:
        report += f"- {r}\n"
    
    report += f"""
---

## 1. 文件指纹

```
{overview[:800]}
```

---

## 2. 字符串分类

```
{strings[:1000]}
```

---

## 3. 导入表 / 危险 API

```
{imports[:800]}
```

---

## 4. 威胁特征扫描

```
{threats[:600]}
```

---

## 5. 网络特征

```
{network[:600]}
```

---

## 6. 加密算法检测

```
{crypto[:400]}
```

---

## 7. IOC 指标

### URL
```
{chr(10).join(iocs["urls"]) if iocs["urls"] else "(无)"}
```

### IP 地址
```
{chr(10).join(iocs["ips"]) if iocs["ips"] else "(无)"}
```

### 敏感字符串
```
{chr(10).join(iocs["sensitive_strings"]) if iocs["sensitive_strings"] else "(无)"}
```

---

## 8. 后续建议

"""
    if level == "严重":
        report += "- ⚠️ 建议立即隔离并深入分析\n"
        report += "- 使用 focus_on_function 深挖核心函数\n"
        report += "- 检查是否有 C2 通信\n"
    elif level == "高":
        report += "- 建议完整反编译分析\n"
        report += "- 关注危险函数的调用链\n"
    else:
        report += "- 可选择性深入分析\n"
        report += "- 根据业务需求决定是否需要完整反编译\n"
    
    report += f"""
---

*报告由 reverse-toolkit v5.0 自动生成*
"""
    
    # 保存报告
    report_path = os.path.join(output_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    
    # 保存 IOC JSON
    ioc_path = os.path.join(output_dir, "iocs.json")
    with open(ioc_path, "w", encoding="utf-8") as f:
        json.dump(iocs, f, ensure_ascii=False, indent=2)
    
    print()
    print(f"✅ 报告已生成: {report_path}")
    print(f"✅ IOC 已导出: {ioc_path}")
    print(f"风险评级: {emoji} {level} ({score}/100)")
    
    return report_path

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: generate_report.py <目标二进制> [输出目录]")
        sys.exit(1)
    
    target = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    generate_report(target, out_dir)
