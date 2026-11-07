#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse-Toolkit MCP Server v5.0-alpha
把逆向工具包封装成 AI 可自主调用的 Tool 集合
"""
import subprocess
import os
from mcp.server.fastmcp import FastMCP

# 初始化 MCP 服务器
mcp = FastMCP("Reverse-Toolkit")

# 脚本目录（绝对路径，防止工作目录变化导致找不到脚本）
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")

def run_script(script_name: str, args: list, max_output: int = 8000, timeout: int = 600) -> str:
    """统一执行 Shell 脚本并截断输出"""
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        return f"[ERROR] 脚本不存在: {script_path}"
    
    # 把所有路径参数转成绝对路径
    abs_args = []
    for a in args:
        if os.path.exists(a):
            abs_args.append(os.path.abspath(a))
        else:
            abs_args.append(a)
    
    try:
        result = subprocess.run(
            ["bash", script_path] + abs_args,
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout
        if result.stderr and result.stderr.strip():
            output += "\n--- stderr ---\n" + result.stderr
        
        # 截断防爆
        if len(output) > max_output:
            output = output[:max_output] + f"\n... [输出已截断，共 {len(output)} 字符，完整结果见输出目录]"
        
        if result.returncode != 0:
            output = f"[WARN] 脚本退出码 {result.returncode}\n" + output
        
        return output
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] 执行超时（{timeout}s）: {script_name}"
    except Exception as e:
        return f"[EXCEPTION] {type(e).__name__}: {str(e)}"


@mcp.tool()
def get_overview(file_path: str) -> str:
    """
    快速概览：获取二进制文件的基础信息（文件指纹、熵值、壳检测、可疑字符串分类）。
    
    使用时机：分析任何样本的第一步，先做快速侦察。
    特点：不跑 Ghidra，速度快（< 1秒），输出简洁。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        文件类型、大小、MD5、熵值、是否加壳、可疑字符串分类（URL/IP/敏感信息/执行相关）
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("overview.sh", [file_path])


@mcp.tool()
def quick_check(file_path: str) -> str:
    """
    快速全景检查：一个命令出全貌，比 overview 更详细。
    
    包含：文件信息、哈希指纹、架构入口、安全属性（NX/RELRO/PIE/Canary）、
          字符串统计、关键词检索（密码/密钥/URL）、熵估算。
    
    使用时机：想要快速了解样本全貌，但还不需要完整反编译。
    特点：不跑 Ghidra，速度快，信息密度高。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        完整的快速体检报告
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("toolbox.sh", [file_path], max_output=6000)


@mcp.tool()
def unpack_binary(file_path: str) -> str:
    """
    检测并自动脱壳（支持 UPX）。
    
    ⚠️ 重要：仅在 get_overview 或 scan_threats 确认文件包含 UPX 等加壳特征时，才允许调用此工具！
    无壳文件请勿调用！如果熵值 < 6.0，说明没有加壳，直接跳过此工具。
    
    使用时机：仅在 get_overview 或 scan_threats 发现高熵（>7.0）或 UPX/加壳特征时调用！
    注意：传入参数必须是原始加壳文件的路径。
    
    返回：
        脱壳结果 + 脱壳后文件的新路径
    
    🔴 关键提醒：脱壳成功后，后续所有分析必须使用返回的新文件路径！
    绝对不要继续用原文件路径分析！
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    result = run_script("unpacker.sh", [file_path])
    # 尝试提取脱壳后的路径
    if ".unpacked" in result:
        lines = result.split('\n')
        for line in lines:
            if ".unpacked" in line and ('/' in line or '\\' in line):
                unpacked_path = line.strip()
                result += f"\n\n{'='*50}\n✅ 脱壳完成！后续分析请使用此路径：\n{unpacked_path}\n{'='*50}"
                break
    return result


@mcp.tool()
def scan_threats(file_path: str) -> str:
    """
    YARA 恶意特征扫描：检测已知恶意软件家族和可疑特征。
    
    检测内容：
    - 加壳特征（UPX、ASPack、Themida、VMProtect 等）
    - 恶意软件家族（Cobalt Strike、勒索软件、Metasploit 等）
    - C2 通信特征
    - 可疑网络/执行/持久化 API
    
    使用时机：overview 之后，判断样本是否有恶意倾向。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        命中的规则列表和严重程度
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("yara_scan.sh", [file_path])


@mcp.tool()
def get_strings(file_path: str) -> str:
    """
    高级字符串提取：自动分类敏感字符串。
    
    分类：密码/密钥、URL/网络、文件路径、注册表、错误信息、Unicode 字符串。
    
    使用时机：overview 之后，想快速找硬编码线索（密码、URL、IP）。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        分类后的字符串列表
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("strings_extract.sh", [file_path])


@mcp.tool()
def check_imports(file_path: str) -> str:
    """
    导入表/导出表分析：列出导入的系统 API，标记敏感/危险函数。
    
    检测：CreateRemoteThread、WriteProcessMemory、CreateProcess、system、
          socket、connect、URLDownload、RegSetValue 等高危 API。
    
    使用时机：快速判断样本调用了哪些系统能力，有没有恶意行为倾向。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        导入函数列表 + 敏感 API 标记
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("imports_exports.sh", [file_path])


@mcp.tool()
def detect_crypto(file_path: str) -> str:
    """
    加密算法识别：检测样本中是否内置了加密/解密功能。
    
    检测：AES、RSA、MD5、SHA1/SHA256、DES、Blowfish、RC4、国密 SM2/SM3/SM4 等，
          以及 OpenSSL、libcrypto 等加密库特征。
    
    使用时机：怀疑样本有加密通信或加密存储功能时调用。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        检测到的加密算法和库特征
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("crypto_detect.sh", [file_path])


@mcp.tool()
def detect_network(file_path: str) -> str:
    """
    网络特征检测：提取样本中的网络相关 IOC。
    
    提取：URL 地址、IP 地址、域名、网络 API、C2 通信特征。
    
    使用时机：找 C2 服务器地址、端口、域名等威胁情报指标。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        URL、IP、域名、网络 API、C2 特征列表
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("net_detect.sh", [file_path])


@mcp.tool()
def check_antidbg(file_path: str) -> str:
    """
    反调试/反虚拟机检测：识别样本是否有防调试、防分析手段。
    
    检测：IsDebuggerPresent、CreateToolhelp32Snapshot、调试器进程名检测、
          VMware/VirtualBox/QEMU 等虚拟机特征。
    
    使用时机：后续要做动态调试之前，先看看有没有反调试。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        检测到的反调试手段和绕过建议
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("antidbg_check.sh", [file_path])


@mcp.tool()
def focus_on_function(binary_path: str, keyword: str) -> str:
    """
    聚焦深挖：针对特定关键词，提取相关函数的伪代码。
    
    参数：
        binary_path: 目标二进制文件的绝对路径
        keyword: 搜索关键词，可以是函数名（如 "system"）、字符串（如 "http://"）、API 名（如 "CreateProcess"）
    
    使用时机：overview 和 strings 分析发现可疑点后，深挖具体实现。
    特点：跑 Ghidra 反编译，只提取相关函数，速度比 full_analysis 快。
    
    返回：
        包含关键词的函数列表、它们的伪代码预览、交叉引用
    """
    if not os.path.exists(binary_path):
        return f"[ERROR] 文件不存在: {binary_path}"
    return run_script("focus_func.sh", [binary_path, keyword], max_output=10000)


@mcp.tool()
def full_analysis(file_path: str, focus_keyword: str = "") -> str:
    """
    完整分析：Ghidra 全量反编译 + 智能降噪 + 结构化 Markdown 报告。
    
    输出内容：
    - 文件指纹 + 熵值分析
    - 字符串自动分类（URL/IP/敏感信息/执行相关）
    - 函数统计（总函数数、危险函数数）
    - Top 20 核心函数（按危险 API 权重 + XREF 加权排序）
    - 危险函数列表（三级分级）
    - 字符串 → 函数交叉引用
    - 核心函数伪代码预览（每个最多 80 行，防止 Token 爆炸）
    - 调用图
    
    使用时机：前面的快速侦察已经有了初步判断，需要深入分析核心逻辑时。
    注意：耗时较长（小文件 30s，大文件 1-5 分钟），大文件自动截断防爆。
    
    参数：
        file_path: 目标二进制文件的绝对路径
        focus_keyword: 可选，聚焦关键词，在报告中插入聚焦检索
    返回：
        完整的结构化 Markdown 体检报告
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    args = [file_path]
    if focus_keyword:
        args += ["--focus", focus_keyword]
    return run_script("analyze.sh", args, max_output=15000)


@mcp.tool()
def generate_full_report(file_path: str) -> str:
    """
    一键生成完整分析报告：汇总所有快速检测结果，自动评级风险。
    
    包含：
    - 文件指纹 + 熵值 + 壳检测
    - 字符串自动分类
    - 导入表 + 危险 API
    - YARA 威胁扫描
    - 网络特征 + 加密检测
    - IOC 指标提取（URL/IP/敏感字符串）
    - 自动风险评级（低/中/高/严重）+ 评分依据
    - 后续建议
    
    使用时机：想要一份完整的快速体检报告，不需要完整反编译时。
    特点：不跑 Ghidra，速度快（< 30 秒），输出结构化 Markdown 报告。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        完整的 Markdown 分析报告 + 风险评级
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    return run_script("generate_report.py", [file_path], max_output=15000)


@mcp.tool()
def risk_check(file_path: str) -> str:
    """
    快速风险评级：自动打分并给出低/中/高/严重四级评级。
    
    评分依据：
    - 熵值（高熵 = 可能加壳/加密）
    - 危险 API 数量（执行/网络/注入类）
    - 网络特征（socket/connect/URL 下载）
    - YARA 威胁命中
    
    使用时机：快速判断样本的危险程度，决定要不要深入分析。
    特点：速度极快（< 5 秒），只返回评级和理由。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        风险等级 + 评分 + 评分依据列表
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    
    # 文件大小基线：大文件链接的库多，API 检测要降权，防止误报
    file_size = os.path.getsize(file_path)
    if file_size > 1024 * 1024:  # > 1MB
        api_weight = 0.3
        size_note = f"大文件（{file_size//1024}K），API 检测权重已降权"
    elif file_size > 100 * 1024:  # > 100K
        api_weight = 0.6
        size_note = f"中等文件（{file_size//1024}K），API 检测权重部分降权"
    else:
        api_weight = 1.0
        size_note = f"小文件（{file_size//1024}K）"
    
    # 调用概览和威胁扫描，然后做简单评分
    overview = run_script("overview.sh", [file_path], max_output=2000)
    threats = run_script("yara_scan.sh", [file_path], max_output=1500)
    imports = run_script("imports_exports.sh", [file_path], max_output=1500)
    
    score = 0
    reasons = []
    reasons.append(size_note)
    
    # 熵值
    import re
    entropy_match = re.search(r'熵值:\s*([\d.]+)', overview)
    if entropy_match:
        entropy = float(entropy_match.group(1))
        if entropy > 7.0:
            score += 30
            reasons.append(f"高熵值 {entropy:.2f}（可能加壳/加密）")
        elif entropy > 6.0:
            score += 15
            reasons.append(f"中熵值 {entropy:.2f}")
    
    # 加壳
    if "UPX!" in overview or "upx" in overview.lower():
        score += 20
        reasons.append("检测到 UPX 壳")
    
    # 用 readelf 提取真正的动态导入符号（比 grep 字符串准确得多）
    imported_funcs = set()
    try:
        result = subprocess.run(
            ["readelf", "--dyn-syms", "--wide", file_path],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 8 and parts[3] == 'FUNC':
                func_name = parts[7]
                # 去掉版本后缀（@GLIBC_2.2.5 这种）
                func_name = func_name.split('@')[0]
                imported_funcs.add(func_name)
    except Exception:
        # readelf 失败就降级到空集合
        pass
    
    # 危险 API（按文件大小权重降权）
    dangerous = ["system", "execve", "execl", "execv", "popen"]
    api_count = sum(1 for api in dangerous if api in imported_funcs)
    api_score = int(api_count * 10 * api_weight)  # 满分按 api_count*10 算，再乘权重
    if api_score >= 30:
        score += 30
        reasons.append(f"导入表中检测到 {api_count} 个高危执行 API（加权后 {api_score} 分）")
    elif api_score >= 10:
        score += api_score
        reasons.append(f"导入表中检测到 {api_count} 个高危执行 API（加权后 {api_score} 分）")
    
    # 网络 API（也看导入表）
    net_apis = ["socket", "connect", "send", "recv", "gethostbyname"]
    net_count = sum(1 for api in net_apis if api in imported_funcs)
    net_score = int(net_count * 3 * api_weight)  # 每个网络 API 3 分
    if net_score > 0:
        score += net_score
        reasons.append(f"导入表中检测到 {net_count} 个网络 API（加权后 {net_score} 分）")
    
    # YARA
    if "critical" in threats.lower():
        score += 25
        reasons.append("YARA 检测到严重恶意特征")
    elif "medium" in threats.lower():
        score += 10
        reasons.append("YARA 检测到中等可疑特征")
    
    # 评级
    if score >= 70:
        level, emoji = "严重", "🔴"
    elif score >= 40:
        level, emoji = "高", "🟠"
    elif score >= 20:
        level, emoji = "中", "🟡"
    else:
        level, emoji = "低", "🟢"
    
    result = f"风险评级: {emoji} {level} ({score}/100)\n\n评分依据:\n"
    for r in reasons:
        result += f"- {r}\n"
    
    return result


@mcp.tool()
def extract_iocs(file_path: str) -> str:
    """
    IOC 统一提取：从二进制中提取所有威胁情报指标。
    
    提取内容：
    - URL 地址（http/https/ftp）
    - IP 地址
    - 域名
    - 敏感字符串（密码/密钥/token）
    - 危险 API
    
    使用时机：需要快速提取样本的 IOC 指标，用于威胁情报共享或黑名单。
    特点：速度快，输出结构化，可直接导入 SIEM 或防火墙。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        分类整理后的 IOC 列表
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    
    import re
    
    # 提取所有字符串
    strings_out = run_script("strings_extract.sh", [file_path], max_output=5000)
    net_out = run_script("net_detect.sh", [file_path], max_output=2000)
    
    all_text = strings_out + net_out
    
    # URL
    urls = list(set(re.findall(r'https?://[^\s<>"\']+', all_text)))[:20]
    
    # IP
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', all_text)))[:20]
    
    # 敏感字符串
    sensitive = list(set(re.findall(r'(?:password|passwd|secret|key|token|api_key|private)[^\n]*', all_text, re.I)))[:20]
    
    # 危险 API
    dangerous_apis = ["CreateRemoteThread", "WriteProcessMemory", "CreateProcess", 
                      "WinExec", "ShellExecute", "system", "popen", "execve",
                      "connect", "socket", "send", "recv", "URLDownload"]
    found_apis = [api for api in dangerous_apis if api.lower() in all_text.lower()]
    
    result = "=== IOC 指标提取 ===\n\n"
    result += f"URL ({len(urls)}):\n"
    result += "\n".join(f"  - {u}" for u in urls) if urls else "  (无)"
    result += "\n\n"
    
    result += f"IP 地址 ({len(ips)}):\n"
    result += "\n".join(f"  - {ip}" for ip in ips) if ips else "  (无)"
    result += "\n\n"
    
    result += f"敏感字符串 ({len(sensitive)}):\n"
    result += "\n".join(f"  - {s.strip()}" for s in sensitive) if sensitive else "  (无)"
    result += "\n\n"
    
    result += f"危险 API ({len(found_apis)}):\n"
    result += "\n".join(f"  - {api}" for api in found_apis) if found_apis else "  (无)"
    
    return result


@mcp.tool()
def generate_attack_chain(file_path: str) -> str:
    """
    自动生成攻击链 Mermaid 图：根据检测到的特征，还原攻击者行为路径。
    
    攻击阶段：
    - 初始访问（网络特征/文件入侵）
    - 执行（危险执行 API）
    - 持久化（注册表/服务/启动项）
    - 权限提升（反调试/注入）
    - 命令与控制（网络通信/C2）
    - 数据窃取（加密/文件操作）
    
    使用时机：分析完样本后，想要可视化展示攻击流程时。
    特点：自动根据检测到的特征生成 Mermaid 流程图，可直接粘贴到 Markdown。
    
    参数：
        file_path: 目标二进制文件的绝对路径
    返回：
        Mermaid 格式的攻击链图 + 各阶段检测依据
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    
    import re
    
    # 收集各阶段检测结果
    overview = run_script("overview.sh", [file_path], max_output=2000)
    net_out = run_script("net_detect.sh", [file_path], max_output=1500)
    persist_out = run_script("persist_detect.sh", [file_path], max_output=1500)
    antidbg_out = run_script("antidbg_check.sh", [file_path], max_output=1500)
    crypto_out = run_script("crypto_detect.sh", [file_path], max_output=1000)
    
    all_text = overview + net_out + persist_out + antidbg_out + crypto_out
    
    # 检测各阶段特征（严格交叉验证，减少误报）
    stages = []
    
    # 初始访问：要有实际的 URL 或 IP，不能只匹配 socket/connect
    has_url = bool(re.search(r'https?://[^\s]{5,}', net_out, re.I))
    has_ip = bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', net_out))
    if has_url or has_ip:
        stages.append(("初始访问", "检测到实际 URL/IP 网络地址", "#e74c3c"))
    
    # 执行：至少 2 个高危执行 API，不能只匹配 system
    exec_apis = re.findall(r'\b(system|popen|execve|CreateProcess|WinExec|ShellExecute)\b', all_text, re.I)
    if len(exec_apis) >= 2:
        stages.append(("执行", f"检测到 {len(exec_apis)} 个命令执行 API", "#f39c12"))
    
    # 持久化
    has_persist = bool(re.search(r'CurrentVersion\\\\Run|CreateService|StartService|crontab|Startup', all_text, re.I))
    if has_persist:
        stages.append(("持久化", "检测到持久化机制", "#9b59b6"))
    
    # 反调试：至少 2 个反调试特征，不能只匹配一个
    antidbg_features = re.findall(r'\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|CreateToolhelp32Snapshot|VMware|VirtualBox|vboxservice)\b', all_text, re.I)
    if len(antidbg_features) >= 2:
        stages.append(("防御规避", f"检测到 {len(antidbg_features)} 个反调试特征", "#34495e"))
    
    # 命令与控制
    has_c2 = bool(re.search(r'C2|beacon|callback|reverse.*shell|meterpreter|cobalt', all_text, re.I))
    if has_c2:
        stages.append(("命令与控制", "检测到 C2 通信特征", "#e67e22"))
    
    # 数据加密
    has_crypto = bool(re.search(r'\bAES\b|\bRSA\b|encrypt|decrypt|CryptEncrypt|CryptDecrypt', all_text, re.I))
    if has_crypto:
        stages.append(("数据加密", "检测到加密功能", "#16a085"))
    
    # 如果没有检测到任何恶意特征
    if not stages:
        return "未检测到明显的攻击链特征，样本风险较低。\n\n建议：可进一步深入分析确认。"
    
    # 生成 Mermaid 图
    mermaid = "```mermaid\nflowchart TD\n"
    mermaid += "    Start([样本分析])\n"
    
    prev = "Start"
    for i, (stage, desc, color) in enumerate(stages):
        node_id = f"S{i}"
        mermaid += f'    {node_id}["{stage}<br/>{desc}"]\n'
        mermaid += f"    {prev} --> {node_id}\n"
        mermaid += f"    style {node_id} fill:{color},color:#fff\n"
        prev = node_id
    
    mermaid += "```"
    
    result = "=== 攻击链可视化 ===\n\n"
    result += mermaid
    result += "\n\n---\n\n各阶段检测依据:\n"
    for stage, desc, _ in stages:
        result += f"- **{stage}**: {desc}\n"
    
    result += f"\n共检测到 {len(stages)} 个攻击阶段。"
    
    return result


if __name__ == "__main__":
    print("Reverse-Toolkit MCP Server v5.0-alpha 启动中...")
    print(f"脚本目录: {SCRIPTS_DIR}")
    print(f"工具数量: 15")
    mcp.run()
