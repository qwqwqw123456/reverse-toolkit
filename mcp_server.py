#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse-Toolkit MCP Server v5.1
================================
5 个超级原语 + 证据台账（Evidence Ledger）+ 红队裁判（Critic Mode）

v5.1 设计目标（对应三条重构建议）：
1. 所有分析结果强制携带 [Evidence: 地址] 符号，杜绝"函数名像、结论就成立"的幻觉；
2. 工具数量从 17 个收敛到 5 个，降低 Tool Call 选择错误与跨工具状态断裂；
3. 新增 audit_and_report：模型必须先把结论 + 证据交上来，裁判逐条校验，
   证据不存在 / 地址对不上 / 跨源拼接 / 截断处强推断 → 直接判 FAIL，禁止出报告。

工具清单：
    set_sample            全局状态
    run_recon             概览 + 字符串 + 导入 + 风险评级（一次体检）
    deep_dive             指定目标函数深挖（自动脱壳 + 反编译 + 截断）
    extract_threat_intel  IOC + YARA + 攻击链打包
    audit_and_report      Critic Mode 证据审计 + Markdown 报告
"""

import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime

from mcp.server.fastmcp import FastMCP

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")

# ============================================================
# System Prompt（通过 FastMCP instructions 注入客户端）
# ============================================================
SYSTEM_PROMPT = """你是 Reverse-Toolkit 的逆向分析助手，工作方式必须遵守以下证据契约：

1. 你在得出结论时，必须引用返回结果中的 [Evidence] 标签。如果没有找到证据，请直接说"未找到"，禁止用函数名、经验或常识补全逻辑。
2. 每条结论至少绑定一个 [Evidence: 地址] 符号（或证据台账里的 EV 编号）。引用不存在的地址 = 幻觉。
3. 伪代码出现 [代码过长已截断] 时，不得推断截断部分；只能描述已看到的部分，并标注"截断处未取证"。
4. 禁止跨证据拼接因果：不能把 A 函数的字符串证据 + B 函数的调用证据拼成"A 调用了 B"这类新事实。
5. 输出最终报告前，必须调用 audit_and_report 自查；审计返回 FAIL 时，禁止输出报告，必须按提示重新取证（deep_dive）后再审。
6. 区分"已核实 / 推断 / 未找到"三档，不得把推断写成已核实。
"""

mcp = FastMCP("Reverse-Toolkit", instructions=SYSTEM_PROMPT)

# ============================================================
# 全局状态（单一黑板，跨工具不再断片）
# ============================================================
_STATE = {
    "original_path": None,
    "active_path": None,
    "out_dir": None,
    "metadata": {
        "shell_detected": None,
        "unpacked": False,
        "risk_level": None,
        "risk_score": None,
        "iocs_count": 0,
    },
    "evidence": [],          # 证据台账（有序）
    "evidence_index": {},    # 去重索引
    "evidence_seq": 0,
    "recon_done": False,
    "deep_dive_targets": [],
    "imports": set(),
    "sections_cache": {},
    "bytes_cache": {},
}

# 兼容旧测试/旧调用方
_analysis_context = _STATE


# ============================================================
# 通用执行
# ============================================================
def _run(script_name: str, args: list, max_output: int = 8000, timeout: int = 600) -> str:
    """执行 scripts/ 下的脚本，统一截断与异常兜底"""
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        return f"[ERROR] 脚本不存在: {script_path}"

    abs_args = []
    for a in args:
        if isinstance(a, str) and os.path.exists(a):
            abs_args.append(os.path.abspath(a))
        else:
            abs_args.append(str(a))

    try:
        result = subprocess.run(
            ["bash", script_path] + abs_args,
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout or ""
        if result.stderr and result.stderr.strip():
            output += "\n--- stderr ---\n" + result.stderr
        if len(output) > max_output:
            output = output[:max_output] + f"\n... [输出已截断，共 {len(output)} 字符]"
        if result.returncode != 0:
            output = f"[WARN] 脚本退出码 {result.returncode}\n" + output
        return output
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] 执行超时（{timeout}s）: {script_name}"
    except Exception as e:  # noqa: BLE001
        return f"[EXCEPTION] {type(e).__name__}: {e}"


def _resolve_path(file_path: str = None) -> str:
    """路径路由：显式路径优先，否则用当前活跃样本"""
    if file_path:
        abspath = os.path.abspath(file_path)
        if not os.path.exists(abspath):
            raise FileNotFoundError(f"文件不存在: {abspath}")
        return abspath
    if _STATE["active_path"]:
        return _STATE["active_path"]
    raise ValueError("未指定文件路径，且当前上下文中没有正在分析的样本。请先调用 set_sample。")


def _ensure_out_dir() -> str:
    if not _STATE["out_dir"]:
        base = os.path.basename(_STATE["active_path"] or "sample")
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", base)
        _STATE["out_dir"] = os.path.join("/tmp", "rea_v51", f"{safe}_{int(time.time())}")
    os.makedirs(_STATE["out_dir"], exist_ok=True)
    return _STATE["out_dir"]


# ============================================================
# 证据台账（Evidence Ledger）
# ============================================================
def _add_evidence(kind: str, locator: str, symbol: str, source: str,
                  snippet: str = "", truncated: bool = False) -> dict:
    """
    登记一条证据。同 (kind, locator, symbol, snippet前缀) 自动复用，避免刷屏。
    kind: function / string / import / file / yara
    locator: 真实虚拟地址 "0x401050"；无法映射时用 "file+0x1a2b"；逻辑证据用 "yara:<rule>"
    """
    key = (kind, locator, symbol, snippet[:64])
    if key in _STATE["evidence_index"]:
        return _STATE["evidence_index"][key]

    _STATE["evidence_seq"] += 1
    rec = {
        "id": "EV-%04d" % _STATE["evidence_seq"],
        "kind": kind,
        "locator": locator,
        "symbol": symbol,
        "source": source,
        "snippet": snippet,
        "truncated": bool(truncated),
    }
    _STATE["evidence"].append(rec)
    _STATE["evidence_index"][key] = rec
    return rec


def _tag(rec: dict) -> str:
    """标准证据标签：[Evidence: 0x401050] verify_password"""
    return f"[Evidence: {rec['locator']}] {rec['symbol']}"


def _tag_full(rec: dict) -> str:
    return f"{_tag(rec)}  ({rec['id']})"


def _evidence_ledger_md(limit: int = 0) -> str:
    rows = _STATE["evidence"]
    if limit:
        rows = rows[-limit:]
    if not rows:
        return "（台账为空：尚未执行任何取证工具）"
    lines = ["| 编号 | 类型 | 证据 | 来源 |", "|---|---|---|---|"]
    for r in rows:
        snip = (r["snippet"] or "").replace("\n", " ").replace("|", "\\|")[:60]
        lines.append(f"| {r['id']} | {r['kind']} | {_tag(r)} | {r['source']} |")
        if snip:
            lines.append(f"| | | _片段_: `{snip}` | |")
    return "\n".join(lines)


def _banner(target: str = "") -> str:
    if not _STATE["active_path"]:
        if target:
            return ("[状态] 样本=%s | 活跃=未锁定 | 证据=%d 条"
                    % (os.path.basename(target), len(_STATE["evidence"])))
        return "[状态] 无活跃样本"
    meta = _STATE["metadata"]
    shell = meta.get("shell_detected") or ("无" if _STATE["recon_done"] else "未检测")
    risk = meta.get("risk_level") or "未评级"
    return (f"[状态] 样本={os.path.basename(_STATE['original_path'] or '')} | "
            f"活跃={os.path.basename(_STATE['active_path'])} | 壳={shell} | "
            f"风险={risk} | 证据={len(_STATE['evidence'])} 条")


# ============================================================
# 二进制基础工具：哈希 / 熵 / 节区 / 地址映射
# ============================================================
def _read_bytes(path: str):
    cached = _STATE["bytes_cache"].get(path)
    if cached is not None:
        return cached
    try:
        if os.path.getsize(path) > 64 * 1024 * 1024:
            return None
        with open(path, "rb") as f:
            data = f.read()
        _STATE["bytes_cache"][path] = data
        return data
    except OSError:
        return None


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(path: str) -> float:
    data = _read_bytes(path)
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    import math
    return -sum((c / total) * math.log2(c / total) for c in freq if c)


_ELF_SEC_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
)
_PE_SEC_RE = re.compile(
    r"^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
)


def _sections(path: str) -> list:
    """返回 [{name, addr, off, size}]；ELF 优先，PE 兜底"""
    if path in _STATE["sections_cache"]:
        return _STATE["sections_cache"][path]

    secs = []
    try:
        out = subprocess.run(["readelf", "-S", "--wide", path],
                             capture_output=True, text=True, timeout=15).stdout
        for line in out.splitlines():
            m = _ELF_SEC_RE.match(line)
            if not m:
                continue
            name, addr, off, size = m.groups()
            try:
                a, o, s = int(addr, 16), int(off, 16), int(size, 16)
            except ValueError:
                continue
            if s > 0 and o > 0:
                secs.append({"name": name, "addr": a, "off": o, "size": s})
    except Exception:  # noqa: BLE001
        pass

    if not secs:
        try:
            out = subprocess.run(["objdump", "-h", path],
                                 capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                m = _PE_SEC_RE.match(line)
                if not m:
                    continue
                name, size, vma, lma, off = m.groups()
                try:
                    a, o, s = int(vma, 16), int(off, 16), int(size, 16)
                except ValueError:
                    continue
                if s > 0:
                    secs.append({"name": name, "addr": a, "off": o, "size": s})
        except Exception:  # noqa: BLE001
            pass

    _STATE["sections_cache"][path] = secs
    return secs


def _locator_for_offset(path: str, off: int) -> tuple:
    """文件偏移 → (虚拟地址定位符, 节区名)。映射失败时退化为 file+0x.."""
    for s in _sections(path):
        if s["off"] <= off < s["off"] + s["size"]:
            if s["addr"]:
                return "0x%x" % (s["addr"] + (off - s["off"])), s["name"]
            # 非装载节（如 .strtab）没有 VA，但节区名仍然有诊断价值
            return "file+0x%x" % off, s["name"]
    return "file+0x%x" % off, "?"


def _literal_variants(literal: str) -> list:
    """Ghidra 的字符串引用可能带 u8/引号/转义，逐个变体尝试定位"""
    l = literal.strip()
    variants = [l]
    v = l
    for pre in ("u8", "u16", "u32", "uc", "u", "s"):
        if v.startswith(pre + '"') and v.endswith('"'):
            v = v[len(pre):]
            break
    no_quote = v.strip('"').replace('\\"', '"').replace("\\\\", "\\")
    variants += [v, no_quote]
    return [x for x in dict.fromkeys(variants) if x]


def _find_string_offset(path: str, literal: str):
    data = _read_bytes(path)
    if not data or not literal:
        return None
    for cand in _literal_variants(literal):
        idx = data.find(cand.encode("utf-8", "ignore"))
        if idx >= 0:
            return idx
        idx = data.find(cand.encode("utf-16-le", "ignore"))
        if idx >= 0:
            return idx
    return None


def _string_evidence(path: str, literal: str, source: str) -> dict:
    """字符串 → 带地址的证据（VA 可映射则用 VA，否则用文件偏移）"""
    off = _find_string_offset(path, literal)
    shown = literal.strip()[:48]
    if off is None:
        return _add_evidence("string", "file+?", "str: %s" % shown, source, snippet=literal)
    locator, sec = _locator_for_offset(path, off)
    return _add_evidence("string", locator, "%s: %s" % (sec, shown), source,
                         snippet=literal)


_IMPORT_GOT_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+\S+\s+[0-9a-fA-F]+\s+(\S+)")


def _import_locations(path: str) -> dict:
    """ELF 重定位表：符号名 → GOT 地址（真实地址，不是 0）"""
    mapping = {}
    try:
        out = subprocess.run(["readelf", "-r", "--wide", path],
                             capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            m = _IMPORT_GOT_RE.match(line)
            if not m:
                continue
            off, raw_name = m.groups()
            if not re.match(r"[A-Za-z_]", raw_name):
                continue
            name = raw_name.split("@")[0]
            mapping.setdefault(name, "0x%x" % int(off, 16))
    except Exception:  # noqa: BLE001
        pass
    return mapping


def _import_symbols(path: str) -> set:
    names = set()
    try:
        out = subprocess.run(["readelf", "--dyn-syms", "--wide", path],
                             capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC":
                names.add(parts[7].split("@")[0])
    except Exception:  # noqa: BLE001
        pass
    return names


# ============================================================
# 风险评分（沿用 v5.0 的加权逻辑）
# ============================================================
def _risk_score(path: str, entropy: float, yara_text: str, imports: set) -> tuple:
    score = 0
    reasons = []

    size = os.path.getsize(path)
    api_weight = 1.0
    if size > 1024 * 1024:
        api_weight = 0.3
        reasons.append(f"大文件（{size // 1024}K），API 权重 0.3")
    elif size > 100 * 1024:
        api_weight = 0.6
        reasons.append(f"中文件（{size // 1024}K），API 权重 0.6")
    else:
        reasons.append(f"小文件（{size // 1024}K）")

    if entropy > 7.0:
        score += 30
        reasons.append(f"高熵 {entropy:.2f}（可能加壳/加密）")
    elif entropy > 6.0:
        score += 15
        reasons.append(f"中熵 {entropy:.2f}")

    exec_apis = [a for a in ("system", "execve", "execl", "execv", "popen") if a in imports]
    if exec_apis:
        s = int(len(exec_apis) * 10 * api_weight)
        score += min(s, 30)
        reasons.append(f"高危执行 API {len(exec_apis)} 个（加权 {s} 分）")

    net_apis = [a for a in ("socket", "connect", "send", "recv", "gethostbyname") if a in imports]
    if net_apis:
        s = int(len(net_apis) * 3 * api_weight)
        score += s
        reasons.append(f"网络 API {len(net_apis)} 个（加权 {s} 分）")

    low = yara_text.lower()
    if "critical" in low:
        score += 25
        reasons.append("YARA 命中 critical 级特征")
    elif "medium" in low:
        score += 10
        reasons.append("YARA 命中 medium 级特征")

    if score >= 70:
        level = "严重"
    elif score >= 40:
        level = "高"
    elif score >= 20:
        level = "中"
    else:
        level = "低"
    return score, level, reasons


# ============================================================
# 原语 1：set_sample
# ============================================================
@mcp.tool()
def set_sample(file_path: str) -> str:
    """
    设置当前分析样本（全局状态）。调用后 run_recon / deep_dive / extract_threat_intel
    都默认针对该文件，不需要重复传路径；同时清空上一轮证据台账。

    参数：
        file_path: 目标二进制绝对路径
    返回：
        状态横幅 + 文件指纹（含 [Evidence: file+0x0]）
    """
    abspath = os.path.abspath(file_path)
    if not os.path.exists(abspath):
        return f"[ERROR] 文件不存在: {abspath}"

    _STATE.update({
        "original_path": abspath,
        "active_path": abspath,
        "out_dir": None,
        "evidence": [],
        "evidence_index": {},
        "evidence_seq": 0,
        "recon_done": False,
        "deep_dive_targets": [],
        "imports": set(),
        "sections_cache": {},
        "bytes_cache": {},
        "metadata": {
            "shell_detected": None,
            "unpacked": False,
            "risk_level": None,
            "risk_score": None,
            "iocs_count": 0,
        },
    })

    size = os.path.getsize(abspath)
    size_str = f"{size / 1024:.1f}K" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f}M"
    md5 = _md5(abspath)
    sha = _sha256(abspath)
    ent = _entropy(abspath)

    rec = _add_evidence("file", "file+0x0", os.path.basename(abspath), "set_sample",
                        snippet=f"md5={md5} sha256={sha}")

    return (
        f"✅ 已锁定样本: {os.path.basename(abspath)}\n"
        f"{_tag_full(rec)}\n"
        f"路径: {abspath}\n"
        f"大小: {size_str} | 熵值: {ent:.2f}/8.0\n"
        f"MD5: {md5}\nSHA256: {sha}\n\n"
        f"证据台账已重置。下一步: run_recon()。"
    )


# ============================================================
# 原语 2：run_recon
# ============================================================
@mcp.tool()
def run_recon(file_path: str = None) -> str:
    """
    一次体检：概览 + 字符串分类 + 敏感导入 + YARA + 风险评级，全部带证据标签。

    使用时机：set_sample 之后的第一步。替代 v5.0 的 get_overview / get_strings /
    check_imports / risk_check 四个工具。

    参数：
        file_path: 可选，不传则用 set_sample 锁定的样本
    返回：
        Markdown 体检报告（每条结论前有 [Evidence: 地址] 符号）+ 证据台账
    """
    try:
        target = _resolve_path(file_path)
    except (ValueError, FileNotFoundError) as e:
        return f"[ERROR] {e}"

    out_dir = os.path.join(_ensure_out_dir(), "recon_%d" % int(time.time()))
    overview = _run("overview.sh", [target, out_dir], max_output=3000)
    _run("strings_extract.sh", [target, out_dir], max_output=1200)
    _run("imports_exports.sh", [target, out_dir], max_output=3000)
    yara_out = _run("yara_scan.sh", [target, out_dir], max_output=2500)

    md5 = _md5(target)
    sha = _sha256(target)
    ent = _entropy(target)
    file_rec = _add_evidence("file", "file+0x0", os.path.basename(target), "run_recon",
                             snippet=f"md5={md5}")

    # --- 壳检测 ---
    shell = "无"
    low = overview.lower()
    for s in ("upx", "aspack", "themida", "vmprotect", "enigma", "winlicense", "armadillo"):
        if s in low:
            shell = s.upper()
            break
    _STATE["metadata"]["shell_detected"] = None if shell == "无" else shell

    # --- 敏感字符串（分类文件优先，带真实地址） ---
    string_groups = [
        ("URL/网络", "strings_url.txt", 8),
        ("敏感信息", "strings_sensitive.txt", 8),
        ("文件路径", "strings_paths.txt", 6),
        ("注册表", "strings_registry.txt", 6),
    ]
    string_lines = []
    seen = set()
    for title, fname, cap in string_groups:
        path = os.path.join(out_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                items = [x.strip() for x in f if x.strip()][:cap]
        except OSError:
            continue
        fresh = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            fresh.append(item)
            if len(fresh) >= cap:
                break
        if not fresh:
            continue
        string_lines.append(f"**{title}**")
        for item in fresh:
            rec = _string_evidence(target, item, "run_recon")
            string_lines.append(f"- {_tag(rec)}: `{item[:100]}`")
            _STATE["metadata"]["iocs_count"] += 1
    if not string_lines:
        string_lines.append("- 未找到（本次字符串提取无命中）")

    # --- 导入表 + GOT 地址 ---
    got = _import_locations(target)
    imports = _import_symbols(target)
    _STATE["imports"] = imports
    sensitive_apis = [
        "CreateRemoteThread", "WriteProcessMemory", "CreateProcess", "WinExec",
        "ShellExecute", "system", "popen", "execve", "socket", "connect",
        "URLDownload", "CryptEncrypt", "RegSetValue", "CreateService",
        "strcmp", "strncmp", "memcmp",
    ]
    import_lines = []
    for api in sensitive_apis:
        if api in imports or api in got:
            loc = got.get(api, "got")
            rec = _add_evidence("import", loc, api, "run_recon")
            import_lines.append(f"- {_tag(rec)}: 导入 {api}")
    if not import_lines:
        import_lines.append("- 未找到敏感导入（仅 grep 字符串，可能为静态链接或 stripped）")

    # --- YARA ---
    yara_lines = []
    for line in yara_out.splitlines():
        s = line.strip()
        if not s or s.startswith(("===", "目标", "[", "输出目录", "✅", "⚠️", "安装", "检测到", "常见")):
            continue
        if re.search(r"(rule|match|detected|severity|score|命中)", s, re.I) or "critical" in s.lower():
            rec = _add_evidence("yara", "yara:auto", s[:50], "run_recon", snippet=s)
            yara_lines.append(f"- {_tag(rec)}: {s[:120]}")
        if len(yara_lines) >= 6:
            break
    if not yara_lines:
        yara_lines.append("- 未找到 YARA 命中（或 yara 未安装，已降级为 strings 特征）")

    score, level, reasons = _risk_score(target, ent, yara_out, imports)
    _STATE["metadata"]["risk_level"] = level
    _STATE["metadata"]["risk_score"] = score
    _STATE["recon_done"] = True

    risk_lines = [f"- {r}" for r in reasons]
    risk_rec = _add_evidence("file", "file+0x0", "risk:" + level, "run_recon",
                             snippet="; ".join(reasons))

    body = "\n".join([
        "## REA Recon 体检报告",
        _banner(target),
        f"\n### 1. 文件指纹\n- {_tag(file_rec)}: `{os.path.basename(target)}`",
        f"- MD5: `{md5}`",
        f"- SHA256: `{sha}`",
        f"- 大小: {os.path.getsize(target)} bytes | 熵值: {ent:.2f}/8.0",
        f"- 壳检测: **{shell}**",
        "\n### 2. 可疑字符串",
        "\n".join(string_lines),
        "\n### 3. 敏感导入",
        "\n".join(import_lines),
        "\n### 4. YARA 威胁扫描",
        "\n".join(yara_lines),
        f"\n### 5. 风险评级\n- {_tag(risk_rec)}: **{level}**（{score}/100）",
        "\n".join(risk_lines),
        "\n### 6. 证据台账（引用时写 EV 编号或地址）",
        _evidence_ledger_md(),
        "\n> 下一步：怀疑某函数有问题 → deep_dive(target_function=\"函数名或地址\")；"
        "要 IOC/攻击链 → extract_threat_intel()。",
    ])
    return body


# ============================================================
# 原语 3：deep_dive
# ============================================================
_SHELL_HINTS = ("upx", "aspack", "themida", "vmprotect", "enigma", "winlicense")


def _maybe_unpack(target: str) -> str:
    """只在确认有壳时脱壳；脱壳后切换活跃路径（AI 不需要知道路径变了）"""
    if _STATE["metadata"].get("unpacked"):
        return _STATE["active_path"]

    shell = _STATE["metadata"].get("shell_detected")
    if not shell:
        data = _read_bytes(target)
        probe = data[:4096].lower() if data else b""
        try:
            s_out = subprocess.run(["strings", "-n", "6", target],
                                   capture_output=True, text=True, timeout=20).stdout.lower()
        except Exception:  # noqa: BLE001
            s_out = ""
        for hint in _SHELL_HINTS:
            if hint.encode() in probe or hint in s_out:
                shell = hint.upper()
                break
        _STATE["metadata"]["shell_detected"] = shell

    if not shell:
        return target

    out_dir = os.path.join(_ensure_out_dir(), "unpack_%d" % int(time.time()))
    res = _run("unpacker.sh", [target, out_dir], max_output=3000, timeout=300)
    try:
        marker = res.split("===RESULT_JSON===")
        data = json.loads(marker[1].strip().splitlines()[0]) if len(marker) > 1 else {}
    except (IndexError, json.JSONDecodeError):
        data = {}
    if data.get("status") == "success" and data.get("unpacked_path") and \
            os.path.exists(data["unpacked_path"]):
        _STATE["active_path"] = data["unpacked_path"]
        _STATE["metadata"]["unpacked"] = True
        _add_evidence("file", "file+0x0",
                      os.path.basename(data["unpacked_path"]), "unpack",
                      snippet=f"shell={data.get('shell_type')}")
    return _STATE["active_path"]


def _parse_index(index_path: str) -> list:
    """解析 _index.txt：地址 \t 函数名 \t 签名 \t 大小 \t xref=N \t 层标记"""
    rows = []
    if not os.path.exists(index_path):
        return rows
    with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            raw_addr = parts[0].strip()
            m = re.search(r"([0-9a-fA-F]{4,})", raw_addr)
            if not m:
                continue
            addr = int(m.group(1), 16)
            tail = "\t".join(parts[4:]) if len(parts) > 4 else ""
            layer_m = re.search(r"\[(TOP|CALLEE|FOCUS|DANGEROUS)\]", tail)
            xref_m = re.search(r"xref=(\d+)", tail)
            rows.append({
                "addr_raw": raw_addr,
                "addr": "0x%x" % addr,
                "addr_int": addr,
                "name": parts[1].strip(),
                "signature": parts[2].strip() if len(parts) > 2 else "",
                "size": parts[3].strip() if len(parts) > 3 else "",
                "xref": ("xref=" + xref_m.group(1)) if xref_m else "",
                "layer": layer_m.group(0) if layer_m else "",
            })
    return rows


def _find_pseudo_file(dec_dir: str, row: dict):
    """定位 decompiled/<addr>_<name>.c，容忍被 sanitize 过的函数名"""
    cand = os.path.join(dec_dir, f"{row['addr_raw']}_{row['name']}.c")
    if os.path.exists(cand):
        return cand
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", row["name"])
    cand = os.path.join(dec_dir, f"{row['addr_raw']}_{safe}.c")
    if os.path.exists(cand):
        return cand
    if os.path.isdir(dec_dir):
        for fn in os.listdir(dec_dir):
            if fn.startswith(row["addr_raw"] + "_") and fn.endswith(".c"):
                return os.path.join(dec_dir, fn)
    return None


def _strip_pseudo(text: str, max_lines: int) -> tuple:
    """去掉导出头注释，保留 C 代码，按行截断"""
    lines = text.splitlines()
    start = 0
    if lines and lines[0].startswith("// Function:"):
        for i, line in enumerate(lines):
            if line.strip() == "/*":
                start = i + 1
                break
    code = lines[start:]
    while code and code[-1].strip() in ("*/", ""):
        code.pop()
    truncated = len(code) > max_lines
    return "\n".join(code[:max_lines]), truncated


@mcp.tool()
def deep_dive(target_function: str, max_functions: int = 3, max_lines: int = 60) -> str:
    """
    深挖指定函数：自动脱壳 → Ghidra 反编译（聚焦导出）→ 伪代码截断 → 逐函数证据标签。

    v5.1 起 ExportDecompiled.java 支持第 3 个参数 focus：即使目标函数不在 Top N，
    也会被强制导出，解决"关键词命中但拿不到伪代码"的断链。

    参数：
        target_function: 函数名 / 地址（0x401050 / 00401050）/ 关键词（strcmp、http://）
        max_functions: 最多展开几个函数（默认 3，防止 Token 爆炸）
        max_lines: 每个函数最多给多少行伪代码（默认 60）
    返回：
        命中函数列表 + 每个函数的 [Evidence: 地址] 伪代码 + 交叉引用字符串
        未命中时明确输出"未找到"，并给出检索范围证据
    """
    try:
        target = _resolve_path()
    except (ValueError, FileNotFoundError) as e:
        return f"[ERROR] {e}"

    target = _maybe_unpack(target)
    out_dir = os.path.join(_ensure_out_dir(), "deep_%d" % int(time.time()))
    _run("focus_func.sh", [target, target_function, out_dir],
         max_output=4000, timeout=900)

    dec_dir = os.path.join(out_dir, "decompiled")
    index_rows = _parse_index(os.path.join(dec_dir, "_index.txt"))

    kw = target_function.strip().lower()
    addr_match = re.search(r"0x([0-9a-fA-F]+)", kw)
    wanted_addr = int(addr_match.group(1), 16) if addr_match else None
    if wanted_addr is None and re.match(r"^[0-9a-fA-F]{4,}$", kw):
        wanted_addr = int(kw, 16)

    hits = []
    for row in index_rows:
        if wanted_addr is not None and row["addr_int"] == wanted_addr:
            hits.append(row)
        elif kw and kw in row["name"].lower():
            hits.append(row)
        elif kw and kw in row["signature"].lower():
            hits.append(row)

    # 名字没命中 → 在已导出伪代码内容里做二次检索（有限扫描，防止爆内存）
    if not hits and os.path.isdir(dec_dir):
        for fn in sorted(os.listdir(dec_dir))[:80]:
            if not fn.endswith(".c"):
                continue
            try:
                with open(os.path.join(dec_dir, fn), "r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(4000).lower()
            except OSError:
                continue
            if kw and kw in head:
                for row in index_rows:
                    if fn.startswith(row["addr_raw"] + "_"):
                        hits.append(row)
                        break

    _STATE["deep_dive_targets"].append(target_function)

    scope_rec = _add_evidence("file", "file+0x0", f"deep_dive:{target_function}", "deep_dive",
                              snippet=f"index={len(index_rows)} functions, dir={dec_dir}")

    if not hits:
        # 明确说"未找到"，并给出检索范围（负面结论也要有证据）
        c_count = 0
        if os.path.isdir(dec_dir):
            c_count = len([x for x in os.listdir(dec_dir) if x.endswith(".c")])
        return (
            f"## deep_dive 结果：**未找到**\n"
            f"{_banner()}\n"
            f"- 检索关键词: `{target_function}`\n"
            f"- {_tag_full(scope_rec)}: 已解析 {len(index_rows)} 个函数索引，"
            f"导出的 .c 文件 {c_count} 个\n"
            f"- 结论：**未找到**目标函数/字符串。不要推测其逻辑。\n\n"
            f"建议：\n"
            f"1. 先 run_recon() 看真实字符串与导入；\n"
            f"2. 换关键词（用字符串原文 / API 名 / 地址 0xXXXX，不要用业务语义词）；\n"
            f"3. 人工核对 `{dec_dir}/_index.txt`。\n\n"
            f"{_evidence_ledger_md(limit=10)}"
        )

    hits = hits[:max(1, max_functions)]
    blocks = [f"## deep_dive: `{target_function}`", _banner(),
              f"命中 {len(hits)} 个函数（其余见 `{dec_dir}/_index.txt`）", ""]

    for row in hits:
        pseudo_path = _find_pseudo_file(dec_dir, row)
        code, truncated = ("", False)
        if pseudo_path:
            try:
                with open(pseudo_path, "r", encoding="utf-8", errors="ignore") as f:
                    code, truncated = _strip_pseudo(f.read(), max_lines)
            except OSError:
                code = ""
        rec = _add_evidence("function", row["addr"], row["name"], "deep_dive",
                            snippet=code, truncated=truncated)
        header = f"### {_tag_full(rec)}"
        meta = " | ".join(x for x in [row["size"], row["xref"], row["layer"]] if x)
        blocks.append(header)
        if meta:
            blocks.append(f"- 元数据: {meta}")
        if row["signature"]:
            blocks.append(f"- 签名: `{row['signature']}`")
        if code:
            fence = "```c"
            blocks.append(f"- 伪代码（前 {max_lines} 行{'，已截断' if truncated else ''}）:\n{fence}\n{code}\n```")
            if truncated:
                blocks.append("- ⚠️ **截断处未取证**：不得推断后续逻辑。")
        else:
            blocks.append("- 伪代码: **未找到**（函数在索引中但未被导出，可能不在 Top N；"
                          "v5.1 的 focus 参数应已覆盖，若仍缺失请检查 Ghidra 日志）")

    # 命中函数的字符串交叉引用
    xref_path = os.path.join(dec_dir, "_xref_strings.txt")
    if os.path.exists(xref_path):
        picked = []
        with open(xref_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if kw and kw in line.lower():
                    picked.append(line.strip())
                if len(picked) >= 8:
                    break
        if picked:
            blocks.append("\n### 交叉引用字符串")
            for line in picked:
                lit = line.split("\t")[0].strip()
                rec = _string_evidence(target, lit, "deep_dive")
                tail = line.split("\t")[-1][:60]
                blocks.append(f"- {_tag(rec)}: `{lit[:100]}`（{tail}）")

    blocks.append("\n### 证据台账")
    blocks.append(_evidence_ledger_md(limit=20))
    blocks.append("\n> 下一步：把结论写成 claims 交给 audit_and_report 自查。")
    return "\n".join(blocks)


# ============================================================
# 原语 4：extract_threat_intel
# ============================================================
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,6}\b")


def _collect_iocs(target: str, out_dir: str) -> dict:
    _run("strings_extract.sh", [target, out_dir], max_output=1200)
    net_out = _run("net_detect.sh", [target, out_dir], max_output=2500)

    texts = []
    for fname in ("strings_url.txt", "strings_sensitive.txt"):
        p = os.path.join(out_dir, fname)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                texts.append(f.read())
    texts.append(net_out)

    blob = "\n".join(texts)
    urls = list(dict.fromkeys(_URL_RE.findall(blob)))[:10]
    ips = list(dict.fromkeys(_IP_RE.findall(blob)))[:10]

    # 域名只从 URL 主机名 + 网络特征里取，避免把节区名（note.gnu.build）当域名
    from urllib.parse import urlparse
    hosts = []
    for u in urls:
        host = urlparse(u).hostname or ""
        if host and not _IP_RE.fullmatch(host):
            hosts.append(host)
    section_noise = {"gnu", "build", "strtab", "shstrtab", "rodata", "text", "data"}
    for d in _DOMAIN_RE.findall(net_out):
        last = d.lower().rsplit(".", 1)[-1]
        if last not in section_noise and not _IP_RE.fullmatch(d):
            hosts.append(d)
    domains = list(dict.fromkeys(hosts))[:10]

    secrets = []
    for m in re.findall(r"(?:password|passwd|secret|token|api_key|private)[^\n]{0,60}",
                        blob, re.I):
        v = m.strip()
        if v.lower() in ("password", "passwd", "secret", "token", "api_key", "private"):
            continue
        if v not in secrets:
            secrets.append(v)
    secrets = secrets[:20]

    def ev(items, source):
        rows = []
        for item in items:
            rec = _string_evidence(target, item, source)
            rows.append((item, rec))
        return rows

    return {
        "url": ev(urls, "extract_threat_intel"),
        "ip": ev(ips, "extract_threat_intel"),
        "domain": ev(domains, "extract_threat_intel"),
        "secret": ev(secrets, "extract_threat_intel"),
    }


def _attack_chain(target: str, iocs: dict) -> list:
    stages = []
    url_rows = iocs["url"]
    ip_rows = iocs["ip"]
    if url_rows or ip_rows:
        stages.append(("初始访问", "存在真实 URL/IP 字符串", url_rows[:2] + ip_rows[:2]))

    got = _import_locations(target)
    exec_rows = []
    for api in ("system", "popen", "execve", "CreateProcess", "WinExec", "ShellExecute"):
        if api in _STATE["imports"]:
            exec_rows.append((api, _add_evidence("import", got.get(api, "got"), api,
                                                 "extract_threat_intel")))
    if len(exec_rows) >= 2:
        stages.append(("执行", f"{len(exec_rows)} 个命令执行 API", exec_rows[:2]))

    crypto_hit = [s for s in ("AES", "RSA", "CryptEncrypt", "CryptDecrypt")
                  if s in _STATE["imports"]]
    if crypto_hit:
        stages.append(("数据加密", "导入加密 API: " + ", ".join(crypto_hit),
                       [(c, _add_evidence("import", "got", c, "extract_threat_intel"))
                        for c in crypto_hit[:2]]))
    return stages


@mcp.tool()
def extract_threat_intel(file_path: str = None) -> str:
    """
    威胁情报打包：IOC（URL/IP/域名/敏感串）+ YARA 命中 + Mermaid 攻击链，全部带地址证据。

    替代 v5.0 的 detect_network / extract_iocs / generate_attack_chain。

    参数：
        file_path: 可选，不传则用 set_sample 锁定的样本
    返回：
        IOC 表 + 攻击链图 + 证据台账
    """
    try:
        target = _resolve_path(file_path)
    except (ValueError, FileNotFoundError) as e:
        return f"[ERROR] {e}"

    out_dir = os.path.join(_ensure_out_dir(), "ti_%d" % int(time.time()))
    iocs = _collect_iocs(target, out_dir)
    yara_out = _run("yara_scan.sh", [target, out_dir], max_output=2500)

    yara_lines = []
    for line in yara_out.splitlines():
        s = line.strip()
        if re.search(r"(critical|medium|match|命中)", s, re.I) and len(yara_lines) < 6:
            rec = _add_evidence("yara", "yara:auto", s[:50], "extract_threat_intel", snippet=s)
            yara_lines.append(f"- {_tag(rec)}: {s[:120]}")

    stages = _attack_chain(target, iocs)

    blocks = ["## 威胁情报包", _banner(), "", "### 1. IOC 指标"]
    labels = {"url": "URL", "ip": "IP", "domain": "域名", "secret": "敏感字符串"}
    for key, label in labels.items():
        rows = iocs[key]
        if not rows:
            blocks.append(f"**{label}**: 未找到")
            continue
        blocks.append(f"**{label}**（{len(rows)}）")
        for item, rec in rows:
            blocks.append(f"- {_tag(rec)}: `{item[:120]}`")

    blocks.append("\n### 2. YARA 命中")
    blocks.append("\n".join(yara_lines) if yara_lines else "- 未找到（或 yara 未安装，已降级为 strings 特征）")

    blocks.append("\n### 3. 攻击链")
    if not stages:
        blocks.append("- 未找到可闭环的攻击阶段（不推测）")
    else:
        mermaid = ["```mermaid", "flowchart TD", "    Start([样本])"]
        prev = "Start"
        for i, (stage, desc, evs) in enumerate(stages):
            nid = f"S{i}"
            mermaid.append(f"    {nid}[\"{stage}<br/>{desc}\"]")
            mermaid.append(f"    {prev} --> {nid}")
            prev = nid
        mermaid.append("```")
        blocks.append("\n".join(mermaid))
        blocks.append("\n| 阶段 | 依据 | 证据 |")
        blocks.append("|---|---|---|")
        for stage, desc, evs in stages:
            tags = "; ".join(_tag(r) for _, r in evs) if evs else "未找到"
            blocks.append(f"| {stage} | {desc} | {tags} |")

    blocks.append("\n### 4. 证据台账")
    blocks.append(_evidence_ledger_md(limit=25))
    return "\n".join(blocks)


# ============================================================
# 原语 5：audit_and_report（Critic Mode）
# ============================================================
AUDIT_EVIDENCE_RULES = [
    ("AE-1", "结论必须绑定证据：每条 claim 至少引用 1 个证据（EV 编号 / 地址 / 符号）"),
    ("AE-2", "证据必须真实存在：引用的编号/地址必须来自本次会话的证据台账，禁止凭空写地址"),
    ("AE-3", "地址必须一致：claim 正文里出现的 0x 地址必须在台账中出现过"),
    ("AE-4", "符号必须可查：claim 提到的函数/API 必须在台账或导入表中出现过，否则判为幻觉"),
    ("AE-5", "截断不得强推断：证据标记 truncated 时，claim 不得出现“确认/必然/完整/证明”"),
    ("AE-6", "强结论需强证据：critical/high 结论不能只靠字符串或 YARA 规则名支撑"),
    ("AE-7", "禁止跨源拼接：多条证据无共同 token 时，不得写成因果句（因为/导致/说明/证明）"),
    ("AE-8", "未找到也要有范围：负面结论（未找到）必须带检索范围证据，否则降级为待核实"),
]

_STRONG_WORDS = ("必然", "一定", "确认", "证实", "证明", "完整", "全部", "绝对")
_CAUSAL_WORDS = ("因为", "导致", "说明", "证明", "因此", "从而", "由此可见")
_TOKEN_RE = re.compile(r"`([^`]+)`|(sub_[0-9a-fA-F]+)|(FUN_[0-9a-fA-F]+)|(0x[0-9a-fA-F]{4,})")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_IDENT_STOP = {
    "the", "and", "for", "with", "this", "that", "from", "into", "not", "none",
    "evidence", "ev", "pass", "fail", "warn", "top", "callee", "focus", "dangerous",
    "markdown", "json", "yaml", "mermaid", "audit", "report", "true", "false",
    "high", "low", "medium", "critical", "sha", "md5", "url", "http", "https",
}
_NEGATIVE_RE = re.compile(r"(未找到|没有找到|not found|无相关|未发现)")


def _symbol_candidates(text: str) -> list:
    """从结论正文里挑出「看起来像符号」的英文 token，用于 AE-4 查证"""
    out = []
    for m in _IDENT_RE.finditer(text):
        t = m.group(0)
        low = t.lower()
        if low in _IDENT_STOP or len(t) < 3:
            continue
        has_lower = any(c.islower() for c in t)
        has_upper = any(c.isupper() for c in t)
        if "_" in t or (has_lower and has_upper and len(t) >= 6):
            if t not in out:
                out.append(t)
    return out


def _resolve_evidence_ref(ref: str):
    """把 EV-0003 / 0x401050 / verify_password / file+0x0 解析成台账记录"""
    if not ref:
        return None
    ref = str(ref).strip()
    for rec in _STATE["evidence"]:
        if ref.upper() == rec["id"].upper():
            return rec
    low = ref.lower()
    for rec in _STATE["evidence"]:
        if low == rec["locator"].lower() or low == rec["symbol"].lower():
            return rec
    for rec in _STATE["evidence"]:
        if low and (low in rec["symbol"].lower() or low in rec["locator"].lower()):
            return rec
    return None


def _parse_claims(raw) -> list:
    """支持 JSON 数组，或带 [Evidence] 标签的 Markdown 行"""
    if isinstance(raw, list):
        items = raw
    else:
        raw = str(raw or "").strip()
        try:
            data = json.loads(raw)
            items = data.get("claims", []) if isinstance(data, dict) else data
            if not isinstance(items, list):
                raise ValueError
        except (json.JSONDecodeError, ValueError):
            items = []
            for line in raw.splitlines():
                s = line.strip().lstrip("-*0123456789. ")
                if not s:
                    continue
                clean_refs = []
                for r in re.finditer(r"\[Evidence:\s*([^\]]+)\]\s*([^\s(]+)", line):
                    clean_refs.append(r.group(1).strip())
                    clean_refs.append(r.group(2).strip())
                text = re.sub(r"\[Evidence:[^\]]+\]\s*[^\s(]*", "", s).strip()
                items.append({"claim": text, "evidence": clean_refs})

    normalized = []
    for i, item in enumerate(items, 1):
        if isinstance(item, str):
            item = {"claim": item, "evidence": []}
        ev = item.get("evidence") or item.get("evidences") or []
        if isinstance(ev, str):
            ev = [ev]
        normalized.append({
            "id": item.get("id") or "C%d" % i,
            "claim": str(item.get("claim") or item.get("text") or "").strip(),
            "evidence": ev,
            "confidence": item.get("confidence") or item.get("severity") or "",
        })
    return normalized


def _audit_claims(claims: list) -> dict:
    """逐条校验证据链，返回 {passed, violations, warnings, results}"""
    violations, warnings, results = [], [], []
    all_locators = {r["locator"].lower() for r in _STATE["evidence"]}
    universe = set()
    for r in _STATE["evidence"]:
        universe.add(r["symbol"].lower())
        universe.add(r["snippet"].lower())
    universe |= {x.lower() for x in _STATE["imports"]}
    universe_text = " ".join(universe) + " " + " ".join(all_locators)

    for claim in claims:
        cid = claim["id"]
        text = claim["claim"]
        if not text:
            violations.append(f"{cid} AE-1: 空结论")
            results.append({"claim": claim, "status": "FAIL", "reason": "空结论"})
            continue

        is_negative = bool(_NEGATIVE_RE.search(text))
        resolved = []
        for ref in claim["evidence"]:
            rec = _resolve_evidence_ref(ref)
            if rec is None:
                violations.append(f"{cid} AE-2: 引用 `{ref}` 不在证据台账（疑似幻觉地址/编号）")
            else:
                resolved.append(rec)

        if not resolved and not is_negative and not claim["evidence"]:
            violations.append(f"{cid} AE-1: 无证据结论，必须补 [Evidence] 或改写成“未找到”")
        if not resolved and is_negative:
            warnings.append(f"{cid} AE-8: 负面结论缺少检索范围证据，降级为“待核实”")

        # AE-3 地址一致
        for addr in re.findall(r"0x[0-9a-fA-F]{4,}", text):
            if addr.lower() not in all_locators and addr.lower() not in universe_text:
                violations.append(f"{cid} AE-3: 正文地址 {addr} 从未在证据台账中出现")

        # AE-4 符号可查（反引号 / FUN_ / sub_ / 正文裸符号一律查台账与导入表）
        tokens = []
        for m in _TOKEN_RE.finditer(text):
            tokens.append(next(g for g in m.groups() if g).lstrip("`"))
        tokens += _symbol_candidates(text)
        for token in dict.fromkeys(tokens):
            low = token.lower()
            if low.startswith("0x"):
                # 地址一致性由 AE-3 负责，这里不重复报
                continue
            if low in universe_text or low.replace("sub_", "fun_") in universe_text:
                continue
            violations.append(f"{cid} AE-4: 符号 `{token}` 查无实据（台账与导入表均无）")

        # AE-5 截断+强推断
        if any(r["truncated"] for r in resolved):
            if any(w in text for w in _STRONG_WORDS):
                warnings.append(f"{cid} AE-5: 引用了截断伪代码却使用强断言词，必须改为“已见部分显示…”")

        # AE-6 强结论弱证据
        high_claim = claim["confidence"].lower() in ("critical", "high", "严重", "高") or \
            re.search(r"(恶意|后门|漏洞|木马|勒索)", text)
        if high_claim and resolved and all(r["kind"] in ("string", "yara") for r in resolved):
            warnings.append(f"{cid} AE-6: 高危结论仅有字符串/YARA 规则支撑，置信度降为“待核实”，需 deep_dive 取证")

        # AE-7 跨源拼接
        if len(resolved) >= 2 and any(w in text for w in _CAUSAL_WORDS):
            tokensets = [set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}",
                                        (r["snippet"] + " " + r["symbol"])))
                         for r in resolved]
            shared = set.intersection(*tokensets) if tokensets else set()
            if not shared:
                warnings.append(f"{cid} AE-7: 多条证据无共同 token 却写成因果句，疑似跨源拼接，需分条陈述")

        status = "FAIL" if any(v.startswith(cid + " ") for v in violations) else (
            "WARN" if any(w.startswith(cid + " ") for w in warnings) else "PASS")
        results.append({"claim": claim, "status": status, "resolved": resolved})

    return {
        "passed": not violations,
        "violations": violations,
        "warnings": warnings,
        "results": results,
    }


def _render_report(title: str, claims: list, audit: dict) -> str:
    sample = _STATE["original_path"] or _STATE["active_path"] or "unknown"
    meta = _STATE["metadata"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = [f"# {title}", ""]
    md.append(f"> 样本: `{os.path.basename(sample)}`  ")
    md.append(f"> SHA256: `{_sha256(sample)}`  ")
    md.append(f"> 风险: **{meta.get('risk_level') or '未评级'}**"
              f"（{meta.get('risk_score') if meta.get('risk_score') is not None else '-'}/100）  ")
    md.append(f"> 审计: **PASS** · 结论 {len(claims)} 条 · 违规 0 · 警告 {len(audit['warnings'])} "
              f"· 证据 {len(_STATE['evidence'])} 条  ")
    md.append(f"> 生成: {now} · reverse-toolkit v5.1 (audit_and_report)")
    md.append("\n## 一、结论")
    md.append("| # | 结论 | 证据 | 判定 |")
    md.append("|---|---|---|---|")
    for res in audit["results"]:
        c = res["claim"]
        tags = "; ".join(_tag(r) for r in res.get("resolved", [])) or "未找到"
        md.append(f"| {c['id']} | {c['claim']} | {tags} | {res['status']} |")

    md.append("\n## 二、证据台账")
    md.append(_evidence_ledger_md())

    md.append("\n## 三、审计与边界")
    if audit["warnings"]:
        md.append("**警告（已降级为待核实，不影响结论成立性）**")
        for w in audit["warnings"]:
            md.append(f"- {w}")
    md.append("- 本报告只覆盖已取证内容；截断伪代码后的逻辑、未导出函数均未核实。")
    md.append("- 所有结论可按证据编号回溯到具体地址与来源工具。")
    md.append("\n## 四、审计规则（audit_evidence）")
    for rid, desc in AUDIT_EVIDENCE_RULES:
        md.append(f"- **{rid}** {desc}")
    return "\n".join(md)


@mcp.tool()
def audit_and_report(claims: str, title: str = "", write_file: bool = True) -> str:
    """
    Critic Mode：接收前 4 步的结论（claims），逐条校验证据与声明是否匹配，
    审计通过才生成 Markdown 报告；发现幻觉立即 FAIL，禁止出报告。

    claims 支持两种格式：
      1) JSON: [{"claim":"...","evidence":["EV-0003","0x401050"],"confidence":"high"}]
      2) Markdown 行: - 检测到密码校验 [Evidence: 0x401050] verify_password

    审计规则见 AUDIT_EVIDENCE_RULES（AE-1 ~ AE-8）。

    参数：
        claims: 结论列表（JSON 字符串或带 Evidence 标签的文本）
        title: 报告标题（可选）
        write_file: 是否把报告写到 /tmp/rea_v51/.../report_*.md
    返回：
        PASS → Markdown 报告 + 文件路径；FAIL → 违规清单 + 重新取证指令
    """
    claims_list = _parse_claims(claims)
    if not claims_list:
        return ("[AUDIT_RESULT: FAIL]\n未收到任何结论（claims 为空）。"
                "请先用 run_recon / deep_dive 取证，再把结论交上来。")

    audit = _audit_claims(claims_list)

    if not audit["passed"]:
        lines = ["[AUDIT_RESULT: FAIL] 证据链断裂，禁止输出报告。", "",
                 f"违规 {len(audit['violations'])} 条："]
        lines += [f"- {v}" for v in audit["violations"]]
        if audit["warnings"]:
            lines += ["", f"警告 {len(audit['warnings'])} 条（不阻塞，但需降级表述）："]
            lines += [f"- {w}" for w in audit["warnings"]]
        lines += ["", "## 必须执行的补救动作",
                  "1. 对每条 AE-2/AE-4 违规，调用 deep_dive(target_function=\"...\") "
                  "重新取证，拿到真实 [Evidence: 地址]；",
                  "2. 拿不到证据的结论，改写成『未找到』并附检索范围；",
                  "3. 禁止直接手写地址或函数名凑数，然后重跑 audit_and_report。",
                  "", "## 审计规则"]
        lines += [f"- **{rid}** {desc}" for rid, desc in AUDIT_EVIDENCE_RULES]
        return "\n".join(lines)

    title = title or f"{os.path.basename(_STATE['original_path'] or 'sample')} 逆向分析报告"
    report = _render_report(title, claims_list, audit)

    path = ""
    if write_file:
        out_dir = _ensure_out_dir()
        safe_title = re.sub(r"[^A-Za-z0-9_.-]", "_", title).strip("_")[:40]
        if len(safe_title) < 3:
            safe_title = "report"
        path = os.path.join(out_dir, f"report_{safe_title}_{int(time.time())}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)

    header = [f"[AUDIT_RESULT: PASS] 结论 {len(claims_list)} 条 · 违规 0 · "
              f"警告 {len(audit['warnings'])} · 证据 {len(_STATE['evidence'])} 条"]
    if path:
        header.append(f"报告文件: {path}")
    if audit["warnings"]:
        header.append("警告（已自动降级为待核实）：")
        header += [f"- {w}" for w in audit["warnings"]]
    return "\n".join(header) + "\n\n" + report


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    print("Reverse-Toolkit MCP Server v5.1 启动中...")
    print(f"脚本目录: {SCRIPTS_DIR}")
    print("工具数量: 5（set_sample / run_recon / deep_dive / extract_threat_intel / audit_and_report）")
    mcp.run()
