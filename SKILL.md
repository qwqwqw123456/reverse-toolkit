---
name: reverse-toolkit
version: 5.1
updated: 2026-11-08
description: 统一逆向工程工具包 v5.1 - 具备可信度审计能力的智能逆向分析师。5 个超级原语（set_sample / run_recon / deep_dive / extract_threat_intel / audit_and_report），所有分析结果强制携带 [Evidence: 地址] 函数名与地址；内置 Critic Mode 证据裁判，证据与声明不匹配直接判 FAIL、禁止出报告。封装 Ghidra / IDA / Hopper / Radare2 多后端，智能降噪（Top N + 聚焦强制导出），20+ 专项分析模块。合规红线：仅分析用户有权分析的二进制。
---

# 统一逆向工程工具包 (Reverse Toolkit) v5.1

> v5.1 的核心变化：从"17 个方便脚本"升级为"具备可信度审计能力的分析助理"。
> 工具做减法（17 → 5），证据做加法（每条结论都能回溯到地址）。

## 一、v5.1 两个硬约束

### 1. 证据标签（Evidence Tag）

所有分析工具的输出都强制携带证据标签：

```text
[Evidence: 0x401050] verify_password: 检测到密码校验逻辑，调用了 strcmp
```

- `0x401050` 是真实虚拟地址（字符串用 VA；映射失败才退化为 `file+0x...`）
- `verify_password` 是符号名（字符串证据的符号是节区名，如 `.rodata`）
- 每条证据在台账里有唯一编号 `EV-0001`，结论可以引用编号，也可以引用地址/符号
- `audit_and_report` 的现场输出会附「证据台账」，模型必须从台账里取证据

### 2. System Prompt（必须原样注入客户端）

```text
你在得出结论时，必须引用返回结果中的 [Evidence] 标签。如果没有找到证据，请直接说"未找到"。
禁止用函数名、经验或常识补全逻辑；引用不存在的地址 = 幻觉。
伪代码出现 [代码过长已截断] 时，不得推断截断部分。
禁止跨证据拼接因果；区分"已核实 / 推断 / 未找到"三档。
输出最终报告前，必须调用 audit_and_report 自查；FAIL 时禁止输出报告。
```

> 该 Prompt 已写入 `mcp_server.py` 的 `SYSTEM_PROMPT`，通过 FastMCP 的 `instructions`
> 参数注入客户端；如果客户端不支持 instructions，请把上面这段手动加入 Agent 的
> System Prompt。

## 二、5 个超级原语

| # | 工具 | 一句话职责 | 合并了 v5.0 的哪些工具 |
|---|------|-----------|----------------------|
| 1 | `set_sample(file_path)` | 锁定样本 + 重置证据台账 | set_sample / get_context |
| 2 | `run_recon()` | 一次体检：概览 + 字符串 + 导入 + YARA + 风险评级 | get_overview / quick_check / get_strings / check_imports / detect_crypto / risk_check / scan_threats |
| 3 | `deep_dive(target_function)` | 指定函数深挖：自动脱壳 + 聚焦反编译 + 伪代码截断 | unpack_binary / focus_on_function / full_analysis / generate_full_report |
| 4 | `extract_threat_intel()` | IOC + YARA + 攻击链打包 | detect_network / extract_iocs / generate_attack_chain / check_antidbg（部分） |
| 5 | `audit_and_report(claims)` | Critic Mode：证据审计 + Markdown 报告 | 新增（无对应旧工具） |

### 为什么合并

- 工具超过 20 个，模型选错工具的概率显著上升；
- 旧版每个工具单独返回，模型需要自己拼状态，容易跨工具断片；
- 合并后每个原语返回"完整可引用的证据块"，模型只需顺序调用，不再猜。

## 三、标准工作流（必须按此顺序）

```text
set_sample(path)
      ↓
run_recon()                     ← 建立证据台账（文件/字符串/导入/YARA/风险）
      ↓
deep_dive("可疑函数/地址")       ← 拿到函数级 [Evidence: 0x...]
      ↓
extract_threat_intel()          ← 需要 IOC / 攻击链时
      ↓
audit_and_report(claims)         ← 强制自查，PASS 才允许输出报告
```

规则：

1. 没有 `run_recon` 就直接 `audit_and_report`，台账为空，所有结论都会因 AE-2 判 FAIL；
2. `deep_dive` 返回"未找到"时，禁止编造函数逻辑，按返回的建议换关键词或看 `_index.txt`；
3. 最终报告只能由 `audit_and_report` 生成，不允许模型手写报告绕过审计。

## 四、Critic Mode：audit_and_report 的 8 条裁判规则

| 规则 | 内容 | 判定 |
|-----|------|------|
| AE-1 | 每条结论至少引用 1 个证据（EV 编号 / 地址 / 符号） | 无证据 → FAIL |
| AE-2 | 引用的编号/地址必须存在于本次证据台账 | 不存在 → FAIL（幻觉） |
| AE-3 | 结论正文里出现的 0x 地址必须在台账出现过 | 不一致 → FAIL |
| AE-4 | 结论提到的函数/API 必须在台账或导入表出现 | 查无实据 → FAIL |
| AE-5 | 证据标记 truncated 时，结论不得用"确认/必然/完整/证明" | 强推断 → WARN |
| AE-6 | 高危结论不能只靠字符串/YARA 规则名支撑 | 弱证据 → WARN + 降级"待核实" |
| AE-7 | 多条证据无共同 token 时，不得写成因果句 | 跨源拼接 → WARN |
| AE-8 | "未找到"结论必须带检索范围证据 | 缺范围 → WARN + 降级 |

FAIL 时工具直接返回违规清单和补救动作（重新取证），**不生成报告**；
WARN 时报告仍然生成，但对应结论自动降级为"待核实"。

### claims 输入格式

JSON（推荐，便于自动化）：

```json
[
  {"id": "C1", "claim": "verify_password 使用 strcmp 比较明文口令", "evidence": ["0x401050", "strcmp"], "confidence": "high"},
  {"id": "C2", "claim": "样本会连接 10.0.0.5:4444", "evidence": ["EV-0007"], "confidence": "medium"},
  {"id": "C3", "claim": "未找到反调试逻辑", "evidence": ["0x0"], "confidence": "low"}
]
```

Markdown 行（模型直接复制粘贴工具输出时）：

```text
- verify_password 使用 strcmp 比较明文口令 [Evidence: 0x401050] verify_password
- 样本会连接 10.0.0.5:4444 [Evidence: 0x402010] .rodata
```

## 五、v5.0 → v5.1 的保留能力

### 智能降噪（未变）
- 黑名单过滤：external、thunk、空函数体、`_` 开头库函数、LIB_FUNCTIONS 黑名单
- 危险 API 三级分级：极高危（执行/网络，权重 10）、高危（文件/注册表，权重 5）、中危（内存操作，权重 2）
- 加权得分排序：`得分 = 极高危*10 + 高危*5 + 中危*2 + XREF*1`
- 只导出 Top N 核心函数 + 它们的一层 callees
- **v5.1 新增 FOCUS 强制导出**：`ExportDecompiled.java` 接收第 3 个参数 focus，
  即使目标函数不在 Top N，也会被强制反编译导出（解决 `deep_dive` 命中索引却拿不到伪代码）

### 结构化输出（未变）
- Markdown 体检报告：文件指纹 → 字符串分类 → 函数统计 → 危险函数 → 交叉引用 → 伪代码预览
- 大文件截断：每个函数最多 80 行（工具参数 `max_lines` 可调），标注 `[代码过长已截断]`

### 渐进式分析（未变，但入口收敛）
| 轮次 | 旧入口 | v5.1 入口 |
|-----|--------|-----------|
| 第一轮 | `overview.sh` | `run_recon()` |
| 第二轮 | `focus_func.sh` | `deep_dive(target_function)` |
| 第三轮 | `analyze.sh` | `deep_dive("main")` / 直接跑脚本 |

### 外挂扩展（未变）
查壳 + 自动脱 UPX（`unpacker.sh`）、YARA 扫描（`yara_scan.sh`）、熵值分析（`hash_calc.sh`）。

## 六、模块清单（25 个脚本，未删除）

| 模块 | 脚本 | 功能 |
|-----|------|------|
| 统一入口 | `analyze.sh` | 完整反编译 |
| 概览模式 | `overview.sh` | 快速概览 |
| 聚焦深挖 | `focus_func.sh` | 特定函数深挖（v5.1 传 focus 参数） |
| Ghidra 后端 | `backends/ghidra.sh` | 智能降噪 + 结构化报告 |
| Ghidra 导出 | `ExportDecompiled.java` | Top N + FOCUS 强制导出 + 危险标记 |
| 脱壳 | `unpacker.sh` | 壳识别 + 自动脱 UPX |
| 反调试 | `antidbg_check.sh` | 反调试/反虚拟机检测 |
| YARA | `yara_scan.sh` | 内置规则扫描 |
| 导入导出 | `imports_exports.sh` | 敏感 API 检测 |
| 节区 | `sections_analysis.sh` | 节区与权限 |
| 加密识别 | `crypto_detect.sh` | AES/RSA/国密常量 |
| 哈希/熵 | `hash_calc.sh` | MD5/SHA + 熵值 |
| 字符串 | `strings_extract.sh` | 分类提取 |
| 二进制对比 | `bin_diff.sh` | 两样本差异 |
| 补丁 | `make_patch.sh` | 生成补丁 |
| 网络特征 | `net_detect.sh` | URL/IP/C2 |
| 持久化 | `persist_detect.sh` | 注册表/服务/启动项 |
| 调试信息 | `debug_info_detect.sh` | 符号/PDB |
| 线程模块 | `threads_modules.sh` | 线程 API/依赖 |
| APK | `apk_analyze.sh` / `apk_info.py` | APK 分析 |
| 固件 | `firmware_analyze.sh` | 固件提取 |
| 工具箱 | `toolbox.sh` | 辅助体检 |
| 报告 | `generate_report.py` | 快速报告 |

## 七、AI 分析防幻觉守则（v5.1 强化）

1. **[Evidence] 即事实**：没有标签的内容只能当线索，不能写进结论；
2. **[TOP]/[CALLEE]/[FOCUS] 三层含义**：TOP 是加权核心函数，CALLEE 是核心函数的直接子函数，FOCUS 是按关键词强制导出的目标函数；
3. **截断处理**：看到 `[代码过长已截断]` 直接声明"截断处未取证"，禁止续写；
4. **反编译失败标记**：`undefined4`、`halt_baddata()`、`FUN_xxx` 不得强行解释；
5. **库函数不是业务逻辑**：`malloc`/`strcpy`/`strcmp` 只作为行为证据，不作为"核心业务"；
6. **负面结论也要范围**："未找到"必须说明检索了多少函数、看了哪个目录。

## 八、环境要求

### 必需
- Python 3
- strings / objdump / file / readelf（系统自带）

### 可选后端
- **Ghidra**：`GHIDRA_HOME`（推荐，v5.1 的 FOCUS 导出依赖它）
- **JDK 25**：Ghidra 12.x 需要
- **Radare2** / **IDA Pro** / **Hopper**：按需

### 可选工具
- `binwalk`（固件）、`upx`（脱壳）、`yara`（特征扫描）

## 九、合规红线

仅分析用户有权分析的二进制文件。
不用于：破解付费软件 / 绕过授权 / 窃取商业机密 / 制作恶意软件 / 任何违法犯罪活动。

## 十、验收自检（交付前必须跑）

```bash
python3 -m pytest -q test_core.py            # 或 python3 test_core.py
# 手动三步：
# 1) python3 -c "from mcp_server import *; print(set_sample('/bin/ls'))"
# 2) print(run_recon())   → 输出里必须每条都有 [Evidence: 0x...]
# 3) print(audit_and_report('[{"claim":"x","evidence":["0xdeadbeef"]}]'))
#    → 必须是 [AUDIT_RESULT: FAIL]，且不生成报告
```
