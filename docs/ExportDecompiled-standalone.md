# ExportDecompiled.java — 把 Ghidra 的几千个函数压成 Top 20 业务函数

> 一个单文件 Ghidra 脚本，专治「MCP 把全部伪代码倒给 LLM 导致 Token 爆炸 + 模型降智」。
> 可独立使用，也可无缝挂到任何基于 Ghidra 的 MCP 框架（REA、reverse-toolkit 等）。

## 1. 它解决什么问题

Ghidra MCP 的常见做法是 `get_functions()` → 把函数列表塞给 AI → AI 逐个要伪代码。
后果有两条：

- **Token 爆炸**：一个中等样本 3000+ 函数，全量伪代码几十 MB，直接撑爆上下文。
- **AI 降智**：99% 的代码是 `malloc / waiter / __libc_csu_init` 这类噪声，真正有业务含义的
  只有十来个。信噪比太低，模型会把「随机字符串」当成「C2 地址」。

`ExportDecompiled.java` 的做法是**先排序、再过滤、只导出值得看的部分**，并且
额外提供一个 `focus` 参数，保证「你想看的那个函数」永远不会被 Top N 漏掉。

## 2. 机制

| 阶段 | 规则 | 目的 |
|---|---|---|
| 黑名单 | `_init/_fini/_start/frame_dummy/register_tm_clones/__libc_csu_*` 等 | 直接剔除 CRT 噪声 |
| 危险 API 加权 | 命中 `strcmp/system/socket/CreateProcess/...` | 认证、命令执行、网络优先 |
| 交叉引用加权 | `xref` 越多越靠前 | 被大量调用的通常是核心逻辑 |
| 体积降权 | 极小 stub（< 16 bytes）降权 | 去掉 thunk/跳板 |
| Top N | 默认 50，可配置 | 控制导出规模 |
| Callees | Top 函数直接调用的函数再补一层 | 保留调用链上下文 |
| **FOCUS** | 第 3 个参数填函数名或入口地址（支持 16 进制包含匹配） | **不在 Top N 也强制导出** |

FOCUS 是 v5.1 新增的关键补丁。没有它会出现这种断链：

```text
_index.txt 里有 verify_password
decompiled/ 里没有 verify_password.c   ← AI 说"索引里有"却拿不到伪代码
```

## 3. 用法

### 3.1 在 Ghidra GUI 里跑

1. `File > Script Manager > +`，添加 `scripts/ExportDecompiled.java`
2. 选中已分析的样本 → 右键 `ExportDecompiled.java` → Run
3. 参数：`outputDir`（必填）、`topN`（默认 50）、`focus`（可选）

### 3.2 命令行（analyzeHeadless）

```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj sample_proj \
  -import /tmp/sample \
  -scriptPath ./scripts \
  -postScript ExportDecompiled.java /tmp/out 50 verify_password \
  -deleteProject
```

第三个参数 `verify_password` 就是 focus：无论它排第几，都会出现在
`/tmp/out/decompiled/` 下，并在 `_index.txt` 里标记 `[FOCUS]`。

### 3.3 在 reverse-toolkit 里跑

`deep_dive(target_function="verify_password")` 会自动把 target 作为 focus 透传：

```text
scripts/focus_func.sh  →  ghidra.sh  →  ExportDecompiled.java <out> <topN> <focus>
```

对应改动只有两行：`focus_func.sh` 传 `"$FOCUS"`，`ghidra.sh` 传 `"${FOCUS_KEYWORD:-}"`。

### 3.4 挂到别的 MCP 框架

任何能执行 Ghidra headless 的框架都可以复用，只要：

1. 把本文件放进 `-scriptPath`；
2. `-postScript ExportDecompiled.java <outDir> <topN> <focus>`；
3. 读取 `<outDir>/_index.txt` 和 `<outDir>/decompiled/*.c`。

不需要改它的内部逻辑，不需要适配 API。

## 4. 输出结构

```text
<outDir>/
├── _index.txt                 # 地址 \t 函数名 \t 签名 \t 大小 \t xref=N \t 层标记
├── decompiled/
│   ├── 00101169_verify_password.c
│   └── 0010206e_zz_target.c
└── strings_*.txt              # url / sensitive / paths / registry 分类
```

`_index.txt` 的层标记取值：

- `[TOP]` — 排名进入 Top N
- `[CALLEE]` — 作为 Top 函数的被调者被补充导出
- `[FOCUS]` — 由 focus 参数强制导出
- `[DANGEROUS]` — 命中危险 API

压缩包内每个 `.c` 文件头部都带 `// Function: name @ addr` 与调用者列表，
AI 可以直接引用，不必再回查索引。

## 5. 实测行为（本机 Ghidra 12.2 + JDK 25）

样本 75 个符号函数，`zz_target` 未被任何函数调用（xref 最低），Top 50 不可能包含它：

```text
$ deep_dive("zz_target", max_functions=1)
### [Evidence: 0x10206e] zz_target  (EV-0005)
- 元数据: 26 bytes | xref=3 | [FOCUS]
- 伪代码:
    int zz_target(int param_1)
    {
      return param_1 * 7 + 3;
    }
```

对照组（8 函数的样本，verify_password 本来就在 Top 内）：

```text
### [Evidence: 0x101169] verify_password  (EV-0007)
- 元数据: 48 bytes | xref=4 | [TOP]
- 伪代码:
    iVar1 = strcmp(param_1,"s3cr3t");
    return iVar1 == 0;
```

## 6. 边界

- 只导出**反编译成功**的函数；`Decompiler failed` 的会记在 `_index.txt` 但无 `.c`。
- 截断由调用方控制（reverse-toolkit 的 `max_lines`），脚本本身不截断。
- 不对伪代码做语义推断，排序只基于静态特征（API / xref / 体积）。
- 加壳样本必须在脱壳后跑，否则导出的是壳代码。

## 7. 许可

跟随 reverse-toolkit 主仓库（当前仓库根目录未附 LICENSE 文件，独立发布前请补一份，建议 MIT）。单独发布时保留文件头注释即可。
