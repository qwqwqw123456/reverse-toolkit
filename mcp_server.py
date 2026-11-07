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

def run_script(script_name: str, args: list, max_output: int = 8000) -> str:
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
            capture_output=True, text=True, timeout=300
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
        return f"[TIMEOUT] 执行超时（300s）: {script_name}"
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
    
    使用时机：仅在 get_overview 或 scan_threats 发现高熵（>7.0）或 UPX/加壳特征时调用！
    注意：传入参数必须是原始加壳文件的路径。
    
    返回：
        脱壳结果 + 脱壳后文件的新路径（后续分析请使用这个新路径！）
    
    重要：脱壳后请使用返回的新文件路径进行后续分析，不要继续用原文件！
    """
    if not os.path.exists(file_path):
        return f"[ERROR] 文件不存在: {file_path}"
    result = run_script("unpacker.sh", [file_path])
    # 尝试提取脱壳后的路径
    if ".unpacked" in result:
        lines = result.split('\n')
        for line in lines:
            if ".unpacked" in line and ('/' in line or '\\' in line):
                result += f"\n\n[提示] 脱壳后文件路径: {line.strip()}"
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


if __name__ == "__main__":
    print("Reverse-Toolkit MCP Server v5.0-alpha 启动中...")
    print(f"脚本目录: {SCRIPTS_DIR}")
    print(f"工具数量: 11")
    mcp.run()
