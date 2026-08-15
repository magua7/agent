# Security Agent Kernel

一个从零实现的、轻量且证据驱动的 Security Agent Runtime，用于**明确授权**的网络安全任务。

当前版本是可运行的 MVP：它能把 localhost 服务发现任务转换为结构化 `TaskSpec`，生成计划，按 capability 选择真实工具，保存完整原始证据，生成引用证据的 Finding，并且只有在独立 Verifier 验证通过后才会完成任务。

> Alpha 软件。它不是授权证明、强沙箱或生产安全控制。只可用于你拥有或已获得明确书面授权的目标。

## 已实现

- 无第三方框架依赖的领域模型：Task、版本化 Plan/DAG、Action、Evidence、Finding、Verification、Run。
- UI 无关的异步 `AgentRuntime.run(task)` 执行循环。
- Planner、Agent、Verifier、Replanner 相互独立；模型不能直接宣告完成。
- capability 驱动的 Tool Registry、统一执行器、输入校验、范围策略、超时、输出上限、审计参数脱敏。
- 四个结构化工具：`network_scan`、`http_request`、`file_read`、`file_search`。
- `network_scan` 默认使用真实、有界的 asyncio TCP connect；应用可显式注入可信的 nmap 绝对路径以使用无 shell 的 `nmap -sT`，并始终记录实际 engine。
- 完整 Evidence 与有界 LLM preview 分离；SHA-256 完整性检查及显式 `evidence-get/search`。
- SQLite 持久化 runs、版本化 plans/nodes、actions、evidence、findings、events；支持并发独立 Run。
- OpenAI-compatible HTTP Provider（不依赖厂商 SDK）及离线 `FakeLLMProvider`。
- 确定性本地 Agent，以及 JSON 强校验的 LLM Planner/Agent。
- 基于标准 `SKILL.md` frontmatter 与仓库可信 `skills/policy.json` 的 Skill Catalog；支持有界相关性选择、故障隔离和渐进加载。
- 机器可读 CLI、事件总线、真实 localhost E2E、失败重试/replan、并发隔离测试。
- 可选 SEC-GO 产品层：本地管理员、用户隔离任务、REST/SSE、产品 CLI 和 React Web 界面。

完整边界见 [SEC-GO 产品使用与部署](docs/PRODUCT.md)、[架构说明](docs/ARCHITECTURE.md)、[领域模型](docs/DOMAIN_MODEL.md)、[Skill Catalog 与信任策略](docs/SKILLS.md) 和 [扩展点](docs/EXTENSION_POINTS.md)。

## SEC-GO 产品快速开始

产品层使用独立的 `sec-go` 入口和 `data/sec-go.db`，需要可选 Web 依赖。请先按
[管理员安全说明](docs/PRODUCT.md#首次初始化与管理员安全) 配置首次初始化凭据，再执行：

```bash
python -m pip install -e ".[web]"
sec-go init
sec-go serve --host 127.0.0.1 --port 8000
```

首次启动若未配置环境变量会创建 `admin / secgo`，该默认凭据仅供本机开发。真实使用前
必须在首次初始化前设置 `SEC_GO_ADMIN_PASSWORD` 和至少 32 字节的
`SEC_GO_SECRET_KEY`。当前没有密码修改 API，已创建账号不会因修改环境变量而自动轮换
密码。

Windows 和 Linux 包装脚本、API、前端构建、SQLite 表结构及单进程/loopback-only 限制
见 [产品文档](docs/PRODUCT.md)。

## 快速开始

需要 Python 3.11 或更高版本。

```bash
python -m pip install -e .
```

先启动一个只监听 loopback 的测试服务：

```bash
python -m http.server 8765 --bind 127.0.0.1
```

另开终端运行 Agent：

```bash
security-agent scan-local --target 127.0.0.1 --ports 8765,8766
```

也可以直接使用模块入口：

```bash
python -m security_agent.interfaces.cli scan-local --ports 8765,8766
```

结果以 JSON 输出，包含 run/plan 状态、Evidence ID/hash 和引用证据的 Finding。默认数据库位于 `runtime-data/security-agent.sqlite3`。

显式读取完整证据：

```bash
security-agent evidence-get <evidence-id>
security-agent evidence-search <run-id> "open_ports"
security-agent show-run <run-id>
```

`scan-local` 故意只接受 `localhost` 或 loopback IP。库级工具也会对 Task 中的精确 host/IP/CIDR 和文件根执行 scope 检查。

## 核心流程

```text
User intent + explicit scope
  -> TaskInterpreter -> TaskSpec
  -> Planner -> validated Plan(version 1)
  -> Agent requests a capability
  -> ToolRegistry -> policy/schema gate -> Tool execution
  -> ActionRecord + complete raw Evidence
  -> bounded evidence observation
  -> independent node Verifier
       success: independently corroborated Finding is verified; other drafts stay unverified
                + succeeded node
       failure: Plan(version + 1) retry or fail closed
  -> independent run Verifier
  -> completed only when VerificationResult.success is true
```

LLM、外部 Skill 正文、Knowledge 和目标返回内容都按不可信输入处理。Skill 只提供过程性知识，不能注册工具、扩大 scope、授予审批或改变运行状态；LLM 只提出计划、动作和观察。状态迁移、scope、工具能力、证据来源与完成条件均由确定性代码控制。

## 目录

```text
docs/                         架构、领域模型、Skill 信任策略、扩展设计与调研
frontend/                     React/TypeScript/Vite 产品界面
skills/                       105 个外部 Skill + 1 个项目自有 Skill、可信 policy.json；白盒包暂缓
scripts/                      SEC-GO 启动包装与 Skill 语料迁移工具
src/security_agent/
  application/                Auth、Task、Run 产品服务与产品存储端口
  domain/                     纯 stdlib 领域对象和状态机
  contracts/                  LLM/Tool/Repository/Event/Skill/Agent ports
  engine/                     Planner、Runtime、Executor、Context、Verifier、Replanner
  infrastructure/
    llm/                      Fake 与 OpenAI-compatible adapters
    skills/                   文件 Skill 与空 Knowledge adapter
    storage/                  Kernel 审计库与 users/tasks 产品投影
    tools/                    四个 scope-aware 本地工具
  interfaces/                 Kernel/Product CLI 与 FastAPI 边界
tests/                        单元、存储、并发、FakeLLM、真实 localhost E2E
```

## 添加 Skill

当前目录已适配 106 个非白盒条目：105 个外部 Skill 加 1 个项目自有示例。每个 Skill 独占 `skills/` 下的一个子目录，必须包含 UTF-8 `SKILL.md`；目录名必须与 frontmatter 中的 `name` 相同：

```text
D:\挑战杯\zhiyugo\skills\<skill-name>\
  SKILL.md
```

`SKILL.md` 使用标准 YAML frontmatter，而且只放用于发现的 `name` 与 `description`：

```markdown
---
name: web-recon
description: >-
  Map an explicitly authorized web target before deeper testing. Use when the
  task needs bounded endpoint, technology, and documentation discovery.
---

# Web reconnaissance
```

如果你找到的是单个 Markdown 文件，把它放入同名子目录并规范为 `SKILL.md`，不要直接散放在 `skills/` 根目录。`skill.yaml` 不再是每个 Skill 的必需文件；它仅作为项目自有或旧格式 Skill 的可选兼容清单，而且不能凭自身把外部目录变成可信来源。正常加载仍需要仓库 policy；旧格式自动信任开关默认关闭。

frontmatter 只负责描述“它是什么、何时适用”，永远不负责授权。启用状态、任务类型、角色、风险等级、所需 capability、人工审批提示和资源加载方式统一由仓库维护的 [`skills/policy.json`](skills/policy.json) 控制。支持的任务类型为 `generic`、`pentest`、`incident_response`、`code_audit`、`reverse_analysis` 和 `ctf`。

默认只启用经过策略审查的安全子集。外部 `active` 与全部 `lab_only` 组默认禁用；`lab_only` 也不会进入正常选择。项目自有、范围严格受限的 `local-service-discovery` 是显式例外，但它仍受 loopback scope 与工具执行策略约束。`human_approval_required` 只是随指导内容传播的风险元数据，不能注册或授权任何工具。当前本地运行时仅提供 `network.scan`、`http.request`、`file.read`、`file.search` 和同一文件搜索工具声明的 `code.search`。

Skill 正文及其命令示例一律按不可信输入处理。运行时先按任务类型、启用状态、可用 capability 与风险过滤，再做有界 top-k 相关性选择；只会按需读取 `SKILL.md` 明确链接的受限 Markdown 资源，不递归注入整个目录。单个目录损坏时默认隔离并报告诊断，严格模式用于 CI 或发布检查。

这些 Skill 已从原先面向 Claude Code 的写法改造成 ZhiyuGo 工作流：正文顶部的受管契约明确 `role`、`risk` 与默认启用状态；跨 Skill 关系只保留 canonical name 路由提示，不会在一次 Run 中动态加载；shell、浏览器、MCP 和子 Agent 操作都改为 capability gap。较长的 leaf 正文会把高级材料拆到同目录 `TECHNIQUE_REFERENCE.md`，主正文保持在上下文预算内。迁移脚本可重复运行，并支持只读一致性检查：

```powershell
python -X utf8 -B scripts/adapt_skill_corpus.py --root skills
python -X utf8 -B scripts/adapt_skill_corpus.py --root skills --check
```

可用管理命令如下；它们只检查、列出或读取目录，不会执行 Skill 附带脚本：

```powershell
security-agent skills list --root "D:\挑战杯\zhiyugo\skills"
security-agent skills doctor --root "D:\挑战杯\zhiyugo\skills" --strict
security-agent skills recommend --root "D:\挑战杯\zhiyugo\skills" --task-type ctf "分析一个本地 PCAP 样本"
security-agent skills show --root "D:\挑战杯\zhiyugo\skills" traffic-analysis-pcap --body
security-agent skills resource --root "D:\挑战杯\zhiyugo\skills" memory-forensics-volatility VOLATILITY_CHEATSHEET.md
```

`list` 查看策略目录，`doctor` 检查 frontmatter、策略覆盖与隔离诊断，`recommend` 只对默认可选集合做有界推荐，`show` 显式读取一个 Skill，`resource` 只读取正文直接链接且仍在同目录内的 Markdown。读取 disabled/lab-only 正文或资源分别需要显式的 `--allow-disabled` / `--allow-lab-only`；列出或展示高风险条目不等于允许其运行。

仓库中的 Skill 不会因当前工作目录而被隐式加载。运行时显式指定可信目录：

```powershell
security-agent scan-local --target 127.0.0.1 --ports 8765 --skills "D:\挑战杯\zhiyugo\skills"
```

库方式调用时，将同一路径传给 `build_local_runtime(..., skills_root=Path(...))`。现有 [local-service-discovery](skills/local-service-discovery/) 可作为项目自有 Skill 与旧格式兼容示例；完整契约见 [Skill Catalog 与信任策略](docs/SKILLS.md)。

`build_local_runtime` 默认仍使用可离线复现的确定性 Planner/Agent，它不会根据外部正文发明新动作。宿主只有在显式传入 `llm_provider=` 时才会组合 `StructuredLLMPlanner` 与结构化 LLM Agent，并消费经过 policy、capability、风险和 top-k 过滤后的 Skill 上下文；工具 scope 与 Verifier 边界保持不变。

为保持核心安装包轻量，wheel 只携带项目自有的 `local-service-discovery` 与其内置 policy；根目录下的 105 个外部 Skill 是私有源码仓库资产，不会被静默塞进 wheel。使用完整目录时必须显式传入仓库中的 `skills/` 路径。

`php-audit-skills` 属于白盒代码审计包，包含可执行脚本、环境变更及独立编排流程，当前按用户要求暂缓适配，并由 `.gitignore` 忽略。后续应作为经过独立审查的插件或受限进程接入，不能由文本 Skill Provider 直接信任。

## 依赖策略

Core 安装仅有一个小型运行依赖：

```text
httpx>=0.27,<1
```

领域层和 SQLite 均只使用标准库。`web` extra 为已经实现的产品 API/认证安装
`bcrypt`、`fastapi` 和轻量 `uvicorn`；`mcp`、`knowledge` extras 当前为空，仅表示下一阶段
接口预留：

```bash
python -m pip install -e ".[web]"
python -m pip install -e ".[mcp]"
python -m pip install -e ".[knowledge]"
python -m pip install -e ".[dev]"
```

## 开发与验收

```bash
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
mypy
```

测试覆盖 TaskSpec 验证、DAG/依赖、节点/Run 状态机、工具注册/执行、路径与网络 scope、Evidence 原文与哈希、Finding 引用、Verifier 接受/拒绝、工具失败、版本化 replan、SQLite、FakeLLM 完整工作流、并发 Run 隔离及真实 localhost 端到端运行。全部测试都使用 loopback、临时目录、mock transport 或 fake provider，不依赖公网攻击目标。

## 安全边界和已知限制

- 当前没有 arbitrary shell/Python tool，也没有 exploit 自动化。
- 外部 Skill 中的 `allowed-tools`、命令或审批文字都只是非可信文本；`skills/policy.json` 的人工审批字段同样不能绕过 Tool Registry、scope 或执行策略。
- 默认策略不会自动选择高风险外部 `active` 或任何 `lab_only` 指导；目录可见、正文可读与操作获准是三个不同状态。
- TCP connect/nmap 是宿主机进程中的受限工具，不是 OS 级沙箱；未来高风险执行器必须放入低权限独立进程/容器/VM。
- SQLite 原始 Evidence 当前是明文。HTTP 敏感响应头会在 metadata 中脱敏，但响应正文或文件内容仍可能含敏感数据；数据库权限、保留期、加密和删除策略由部署者负责。
- Verifier 能确定性验证动作来源、hash、引用、状态和 criteria coverage；通用自然语言 criterion 的语义真实性仍依赖 Agent assessment，关键结论应增加专用结构化验证器或人工复核。
- OpenAI-compatible adapter 限制响应大小并要求远程 HTTPS，但尚未提供自动重试、限流或字段级数据外发策略。
- SQLite 适合单机、单写入者轻量运行，不是分布式队列；跨 plan/run/evidence/action 的完整 checkpoint 事务与 CAS revision 尚未实现。
- SEC-GO 产品编排依赖当前进程内的任务表，固定单 worker；重启不会自动恢复活动任务。
- 当前产品支持边界是 API 与目标均为 loopback；没有公网 TLS、速率限制、账号锁定或多进程协调。

## Roadmap（尚未实现）

- 可选 MCP Tool Adapter 与连接生命周期。
- Markdown/JSON + SQLite FTS5 Knowledge Provider。
- 可真正阻断执行的人工审批工作流，以及独立进程执行沙箱。
- checkpoint/resume、加密/TTL Evidence、确定性报告生成。
- 可插拔 AgentDispatcher 下的受预算约束 Multi-Agent 策略。

以上内容均未作为“已完成能力”宣传。

## Clean-room 与使用权

核心 Runtime、领域模型、执行策略和项目结构为独立实现；参考项目仅用于提炼通用架构需求，没有迁移其核心源码。`skills/` 下的外部 Skill 语料不属于这项核心代码 clean-room 声明，它们具有独立的来源、修订版本、完整性与使用条款生命周期。相关调研见 [REFERENCE_RESEARCH.md](docs/REFERENCE_RESEARCH.md)，语料治理要求见 [SKILLS.md](docs/SKILLS.md)。

本仓库当前为私有项目，未提供开源许可证，保留项目自有内容的权利；但“私有”不会自动把外部 Skill 语料转化为项目自有内容。在分享或重新分发任何外部语料前，必须核对其来源与适用条款。
