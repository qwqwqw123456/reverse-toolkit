# Reverse-Toolkit：基于 Ghidra 与 LLM 的自动化逆向分析框架

> 从 2210 个函数里自动定位漏洞核心，把枯燥的反编译变成可视化的攻击链分析。

![CI](https://github.com/qwqwqw123456/reverse-toolkit/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/badge/version-v5.0--stable-blue)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen)
![MCP](https://img.shields.io/badge/MCP-17--tools-orange)
![Ghidra](https://img.shields.io/badge/Ghidra-12.2-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🎯 这是什么？

Reverse-Toolkit 是一个统一的逆向工程工具包，把 Ghidra 反编译引擎与大语言模型（LLM）结合，实现自动化的二进制分析与漏洞挖掘。

**核心能力：**
- 🤖 **MCP Agent 模式（v5.0）**：17 个工具封装成 MCP Server，AI 自主编排分析流程
- 🧠 **智能降噪**：从几千个函数里精准提炼核心业务函数，过滤库函数噪音
- 📊 **结构化输出**：自动生成 Markdown 体检报告，不是一坨 C 代码
- 🔄 **渐进式分析**：三轮工作流，先看全貌再决定深挖哪里
- 🛡️ **防爆防幻觉**：大文件截断 + AI 分析守则，防止 Token 爆炸和胡编乱造
- 🔽 **优雅降级**：缺 YARA 走 strings 模式，缺 UPX 先分析字符串，环境不完美也能跑
- 🎯 **风险评级**：自动打分低/中/高/严重，附评分依据
- 📈 **攻击链可视化**：自动生成 Mermaid 攻击流程图
- 🧊 **通用脱壳器**：基于 unicorn 引擎模拟执行，突破"只能识别不能脱壳"的边界

---

## 🚀 实战效果：Shellshock 攻击链自动还原

```mermaid
flowchart TD
    ENV[外部输入<br/>HTTP 请求头 → 环境变量] --> INIT[initialize_shell_variables<br/>初始化 Shell 变量]
    
    INIT --> PARSE[parse_and_execute<br/>★ 漏洞核心函数 2371B]
    
    subgraph parse_and_execute 内部
        direction TB
        RESET[reset_parser<br/>重置解析器]
        READ[push_stream<br/>读取输入流]
        CMD[parse_command<br/>语法解析]
        EXEC[execute_command_internal<br/>命令执行]
        CLEAN[parse_and_execute_cleanup<br/>清理资源]
    end
    
    PARSE --> RESET
    RESET --> READ
    READ --> CMD
    CMD --> EXEC
    EXEC --> CLEAN
    
    EXEC --> VARS[find_variable<br/>变量查找]
    EXEC --> ERR[builtin_error<br/>错误处理]
    EXEC --> DISPOSE[dispose_words<br/>资源清理]
    
    style ENV fill:#e74c3c,color:#fff
    style PARSE fill:#f39c12,color:#fff,stroke:#e74c3c,stroke-width:3px
    style EXEC fill:#e74c3c,color:#fff
```

**从 2210 个函数中，自动定位到 Shellshock 漏洞核心函数 `parse_and_execute`，并还原完整攻击链。**

---

## 🤖 AI 自主编排：一句话分析整个样本（v5.0）

**你只需要说一句话：**
> "帮我分析一下这个样本，提取 IOC，评估风险，生成攻击链报告。"

**AI 会自主决策并调用 17 个工具，完成完整分析：**

| 步骤 | AI 决策 | 调用工具 | 输出 |
|------|---------|----------|------|
| 1 | 先快速侦察 | `get_overview` | 发现高熵 7.81 + UPX 特征 |
| 2 | 确认加壳，脱壳 | `unpack_binary` | 自动脱 UPX 壳，返回新路径 |
| 3 | 提取威胁情报 | `extract_iocs` | C2 地址、IP、危险 API 清单 |
| 4 | 检查防御规避 | `check_antidbg` | 检测到反调试 API |
| 5 | 生成攻击链 | `generate_attack_chain` | 自动输出 Mermaid 攻击链图 |
| 6 | 风险评级 | `risk_check` | 🔴 严重（85/100）+ 评分依据 |
| 7 | 完整报告 | `generate_full_report` | 一键输出 Markdown 体检报告 |

**全局状态黑板（v5.0-stable 新特性）：**
- `set_sample`：锁定当前样本，后续工具无需重复传路径
- `get_context`：随时查看当前分析状态
- 脱壳成功后，活跃路径自动切换到脱壳后文件，AI 甚至不用知道路径变了

---

## 📦 功能特性

### 级别一：智能降噪
- 自动过滤 external / thunk / 库函数黑名单（468 个噪音函数）
- 危险 API 三级分级：极高危（执行/网络，权重 10）、高危（文件/注册表，权重 5）、中危（内存操作，权重 2）
- 加权得分排序：`极高危*10 + 高危*5 + 中危*2 + XREF*1`
- callees 递归导出（1 层深度），目标函数 + 子函数一起带出来

### 级别二：结构化输出
- 输出 Markdown 体检报告，大模型一眼抓住重点
- 字符串自动分类：URL / IP / 敏感信息 / 执行相关
- 熵值分析（阈值 7.0，对齐业界标准）
- 大文件截断防爆：每个函数伪代码预览最多 80 行

### 级别三：渐进式分析
| 轮次 | 脚本 | 做什么 |
|-----|------|--------|
| 第一轮 | `overview.sh` | 快速概览：文件指纹 + 熵值 + 壳检测 + 可疑字符串 |
| 第二轮 | `focus_func.sh` | 聚焦深挖：根据可疑点，深挖特定函数 |
| 第三轮 | `analyze.sh` | 完整分析：全局反编译 + 结构化报告 |

### 级别四：外挂扩展
| 模块 | 脚本 | 功能 |
|-----|------|------|
| 脱壳 | `unpacker.sh` | 三特征交叉验证 + UPX 自动脱壳 + JSON 结构化输出 |
| 通用脱壳 | `generic_unpacker.py` | unicorn 模拟执行 + 内存 dump |
| YARA 扫描 | `yara_scan.sh` | 内置 UPX / Cobalt Strike / 勒索软件规则 |
| 熵值分析 | `hash_calc.sh` | 判断是否加壳/加密 |
| 反调试检测 | `antidbg_check.sh` | 检测反调试/反虚拟机特征 |
| 更多... | 20+ 专项模块 | 导入表、节区、加密、网络、持久化... |

---

## 🛠️ 快速开始

### 方式一：MCP Agent 模式（v5.0 推荐）

一句话让 AI 自动完成全流程分析，不用手动跑脚本。

**安装依赖：**
```bash
pip install -r requirements.txt
```

**配置 Claude Desktop：**

编辑 `claude_desktop_config.json`：
```json
{
  "mcpServers": {
    "reverse-toolkit": {
      "command": "python3",
      "args": ["/你的路径/reverse-toolkit/mcp_server.py"]
    }
  }
}
```

重启 Claude Desktop，看到小锤子图标亮起，直接说：
> 帮我分析这个文件 /tmp/suspicious.bin，看看它是不是恶意的，核心逻辑是什么。

AI 会自主决策：先概览 → 发现加壳 → 自动脱壳 → YARA 扫描 → 深挖函数 → 输出攻击链报告。

**17 个可调用工具：**
| 工具 | 用途 |
|------|------|
| `set_sample` | 锁定当前分析样本（第一步必用） |
| `get_context` | 查看当前分析上下文 |
| `get_overview` | 快速概览 |
| `quick_check` | 全景检查（含 checksec） |
| `unpack_binary` | 自动脱 UPX 壳 |
| `scan_threats` | YARA 恶意特征扫描 |
| `get_strings` | 字符串分类提取 |
| `check_imports` | 导入表+敏感 API |
| `detect_crypto` | 加密算法识别 |
| `detect_network` | 网络/C2 特征 |
| `check_antidbg` | 反调试检测 |
| `focus_on_function` | 聚焦深挖特定函数 |
| `full_analysis` | 完整 Ghidra 反编译 |
| `generate_full_report` | 一键完整报告 |
| `risk_check` | 快速风险评级 |
| `extract_iocs` | IOC 统一提取 |
| `generate_attack_chain` | 攻击链 Mermaid 图 |

---

### 方式二：Docker 一键部署

```bash
docker build -t reverse-toolkit .
docker run -it reverse-toolkit
```

---

### 方式三：命令行模式

### 环境要求
- Ghidra 12.2（需要 JDK 25）
- Python 3.8+
- 辅助工具：strings / file / readelf（系统自带）

### 一键分析
```bash
# 快速概览（不跑 Ghidra，10 秒出结果）
bash scripts/overview.sh ./target_binary

# 完整分析（自动选择最佳后端）
bash scripts/analyze.sh ./target_binary ./output_dir

# 聚焦深挖关键词
bash scripts/focus_func.sh ./target_binary "password"

# 脱壳检测（三特征交叉验证）
bash scripts/unpacker.sh ./target_binary
```

---

## 📊 压测数据

### /bin/bash (1.4MB) 压测结果

| 指标 | 修复前 | 修复后 | 提升 |
|------|--------|--------|------|
| 总函数数 | 2678 | 2210 | 过滤 468 个库函数 |
| 危险函数数 | 812 | 318 | 降 60% |
| Top 20 内容 | 全是 free/malloc/strlen | 全是 find_variable/builtin_error 等业务函数 | 核心业务上浮 |

### 风险评级误报修复效果

| 样本 | 修复前 | 修复后 | 说明 |
|------|--------|--------|------|
| /bin/ls | 🟠 高危 40/100 | 🟢 低危 0/100 | readelf 方案 + 大小降权 |
| /usr/bin/python3 | 🟠 高危 40/100 | 🟢 低危 18/100 | 大文件权重降权 |

---

## ✅ 工程化

- **8 个单元测试**：`python test_core.py` 一键跑通
- **GitHub Actions CI**：每次 push 自动跑测试
- **Dockerfile**：一键容器化部署
- **全局状态管理**：AI 不用记路径，工具自动接力

---

## 🧠 AI 分析防幻觉守则

读取伪代码时，AI 必须遵守：

1. **[TOP] 标记**：加权得分排序的核心业务函数，优先分析
2. **[CALLEE] 标记**：Top 函数直接调用的子函数
3. **截断标记**：看到 `[代码过长已截断]`，禁止猜测被截断部分的逻辑
4. **反编译失败**：`undefined4` / `halt_baddata()` 是反编译失败特征，不要强行解释
5. **证据优先**：所有结论必须基于实际代码，禁止基于函数名猜测
6. **库函数识别**：malloc/free/strcpy 是标准库，不是核心分析对象

---

## ⚠️ 合规声明

**本工具仅用于安全研究和授权测试。**
- 仅分析你有权分析的二进制文件
- 不用于破解付费软件、绕过 DRM/授权、窃取商业机密
- 恶意软件分析仅限防御研究目的
- 使用本工具产生的任何后果由使用者自行承担

---

## 📝 更新日志

### v5.0-stable
- **全局状态黑板**：set_sample / get_context 工具，AI 不用记路径
- **JSON 结构化通讯**：shell 脚本输出标准 JSON，Python 层自动解析
- **脱壳自动接力**：脱壳成功后，活跃路径自动切换
- **工程化完善**：8 个单元测试 + GitHub Actions CI + Dockerfile
- MCP 工具升级到 17 个

### v5.0-beta
- **脱壳能力升级**：三特征交叉验证壳检测（字符串+节区+熵值，9分制置信度评分）
- **通用脱壳器原型**：基于 unicorn 引擎模拟执行，加载 ld.so + libc，内存 dump
- **风险评级误报修复**：改用 readelf 动态符号表 + 文件大小基线降权
- **攻击链误报优化**：从单字符串匹配改为多特征交叉验证
- **超时优化**：默认超时从 300s 提升到 600s
- MCP 工具升级到 15 个：新增报告生成、风险评级、IOC 提取、攻击链可视化

### v5.0-alpha
- MCP Server 封装：11 个工具暴露给 AI 自主调用
- Docstring 强警告：防止 AI 乱调工具
- 输出分级截断：6K/8K/10K/15K 按需喂食
- 统一错误前缀：[ERROR]/[TIMEOUT]/[EXCEPTION] 触发 AI 纠错
- 优雅降级：缺依赖自动走手动模式

### v4.2-stable
- 黑名单过滤：external/thunk/_开头库函数/LIB_FUNCTIONS
- 危险 API 三级分级：极高危(10)/高危(5)/中危(2)/基础库(0)
- 加权得分排序：极高危*10 + 高危*5 + 中危*2 + XREF*1
- callees 递归导出：1 层深度，Set 去重
- 大文件截断防爆：每个函数预览 80 行
- AI 防幻觉守则：6 条规则
- 环境自检：入口自动检测依赖

---

## 📄 License

MIT License
