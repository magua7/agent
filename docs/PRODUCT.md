# SEC-GO 产品层使用与部署说明

SEC-GO 是 Security Agent Kernel 之上的本地产品层。它把同一个经过验证器约束的
Agent Runtime 暴露为人类可读 CLI、Bearer REST API、可重放 SSE 和 React Web
界面，同时保持 Kernel 不依赖 FastAPI 或前端框架。

当前版本定位为单机、单进程、loopback-only 的 MVP。它不是公网服务、分布式任务
平台或攻击自动化系统。只可对明确授权的本机回环目标执行任务。

## 能力边界

当前已经实现：

- 本地管理员初始化、bcrypt 密码校验和 8 小时 HS256 Bearer Token；
- 按用户隔离的任务创建、列表、详情、取消、Evidence 原文读取；
- 真实 Agent Runtime 后台运行，以及 Plan、Evidence、Finding、Verification 和报告投影；
- SQLite 持久化和可用数字游标重放的 SSE 审计时间线；
- React 18 产品界面，包括登录、任务切换、Plan DAG、Evidence、Finding 和报告；
- Windows、Linux/macOS 启动包装脚本和 `sec-go` Python 入口。

当前明确没有实现：

- 用户注册、密码修改、密码找回、Token 刷新/撤销和角色管理；
- 远程目标、任意 shell、自动 exploit 或操作系统级执行沙箱；
- 多进程任务协调、分布式队列、宕机恢复或 checkpoint/resume；
- MCP Tool Adapter、持久化知识库和真正的 Multi-Agent 调度。

## 架构和目录

```text
Browser / sec-go CLI
        |
        v
interfaces/api + interfaces/product_cli
        |
        v
application/AuthService + TaskService + RunService
        |
        +--------------------+
        |                    |
        v                    v
SQLiteProductStore       AgentRuntime
users / tasks            Planner -> Agent -> Tool -> Verifier
        |                    |
        +----------+---------+
                   v
             data/sec-go.db
     runs / plans / plan_nodes / actions /
        evidence / findings / events
```

关键目录：

```text
src/security_agent/
  domain/                         Kernel 领域模型和状态机
  contracts/                      Tool、Agent、Skill、Knowledge、存储等端口
  engine/                         AgentRuntime、Planner、Executor、Verifier、Replanner
  application/
    bootstrap.py                  产品组合根、默认路径和环境变量
    auth_service.py               bcrypt 与 JWT
    task_service.py               用户任务和安全的 UI/API 投影
    run_service.py                单进程后台运行、并发上限和取消
    models.py / ports.py          产品模型与仓储端口
  infrastructure/storage/
    sqlite.py                     Kernel 审计存储
    product.py                    users/tasks 与用户隔离投影
  interfaces/
    api/                          FastAPI 路由、依赖和 schema
    product_cli.py                sec-go init/run/serve
  main.py                         默认 ASGI 入口
frontend/
  src/product/                    当前 SEC-GO React 产品界面
  dist/                           npm run build 的生产静态产物
scripts/sec-go.bat                Windows 包装脚本
scripts/sec-go.sh                 Linux/macOS 包装脚本
```

前端只依赖公开 JSON/SSE 契约，不导入 Kernel。API 只调用 Application Service，不让
HTTP 处理器直接拼装 Agent Runtime。

## 安装

需要 Python 3.11 或更高版本。产品 CLI 会创建/校验 bcrypt 管理员，因此产品层应安装
`web` extra：

```bash
python -m pip install -e ".[web]"
```

只运行 Kernel CLI 时仍可安装轻量 Core：

```bash
python -m pip install -e .
```

两个入口用途不同：

- `security-agent`：Kernel 的机器可读开发/诊断 CLI；
- `sec-go`：产品 CLI，提供 `init`、`run` 和 `serve`。

## 首次初始化与管理员安全

如果没有配置环境变量，首次产品启动会创建本地账号 `admin / secgo`。这个默认值仅供
本机开发演示，不能用于真实数据或任何可被其他用户访问的环境。

应在第一次 `init` 或 `serve` 之前设置高强度密码：

```text
SEC_GO_ADMIN_USERNAME=<管理员用户名>
SEC_GO_ADMIN_PASSWORD=<高强度且唯一的密码>
```

重要限制：管理员只会在用户不存在时创建。账号已经写入数据库后，再修改上述环境变量
不会轮换现有密码。当前版本没有密码修改 API；如果曾以默认密码初始化，不要继续用于
真实数据，应停止服务并使用新的数据库和安全凭据重新初始化。不要把密码写入仓库、命令
历史、截图或前端环境变量。

JWT 密钥有两种来源：

- 配置 `SEC_GO_SECRET_KEY`，其 UTF-8 长度必须至少为 32 字节；
- 不配置时，在数据库目录生成 `.sec-go-secret`。

应限制 `data/`、`sec-go.db` 和 `.sec-go-secret` 的文件系统权限，并排除版本控制。更换
JWT 密钥会使现有 Token 失效。当前 Token 默认有效期为 8 小时，没有刷新或服务端撤销
列表。

## Windows 启动

以下命令适用于 PowerShell，并假设当前目录为仓库根目录：

```powershell
py -3.11 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e ".[web]"

$env:SEC_GO_ADMIN_USERNAME = "admin"
$env:SEC_GO_ADMIN_PASSWORD = "请替换为高强度唯一密码"
$env:SEC_GO_SECRET_KEY = "请替换为至少32字节的随机密钥"

.\scripts\sec-go.bat init
.\scripts\sec-go.bat serve --host 127.0.0.1 --port 8000
```

也可以在安装后直接使用入口：

```powershell
sec-go init
sec-go serve --host 127.0.0.1 --port 8000
```

访问 `http://127.0.0.1:8000/`。若尚未构建前端，根路径会返回 API 提示，交互式 OpenAPI
位于 `http://127.0.0.1:8000/docs`。

`sec-go.bat` 会优先使用 `.venv\Scripts\python.exe`，否则寻找可用的 Python 3.11+，并把
仓库 `src/` 放入 `PYTHONPATH`。

## Linux/macOS 启动

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[web]'

export SEC_GO_ADMIN_USERNAME='admin'
export SEC_GO_ADMIN_PASSWORD='请替换为高强度唯一密码'
export SEC_GO_SECRET_KEY='请替换为至少32字节的随机密钥'

sh scripts/sec-go.sh init
sh scripts/sec-go.sh serve --host 127.0.0.1 --port 8000
```

脚本优先使用 `.venv/bin/python`，并拒绝 Python 3.10 及更早版本。

## 产品 CLI

查看实际参数：

```bash
sec-go --help
sec-go run --help
sec-go serve --help
```

初始化默认数据库和管理员：

```bash
sec-go init
sec-go init --db data/sec-go.db
```

执行一个授权的 localhost 任务并等待结果：

```bash
sec-go run "分析本机测试服务的暴露端口" \
  --title "本机服务检查" \
  --target 127.0.0.1 \
  --ports 22,80,443,8000 \
  --max-seconds 120
```

机器可读输出：

```bash
sec-go run "检查 localhost 服务" --target localhost --ports 8000 --json
```

`run` 还支持 `--db` 和 `--skills`。目标必须是 `localhost` 或显式 loopback IP，端口必须
是 1 到 128 个 `1..65535` 的唯一整数。运行成功返回退出码 0，验证失败或产品错误返回
非零退出码。

`serve` 没有 `--db` 参数。服务使用自定义数据库时，请配置 `SEC_GO_DB`：

```bash
export SEC_GO_DB=/absolute/path/to/sec-go.db
sec-go serve --host 127.0.0.1 --port 8000
```

## 环境变量

| 变量 | 默认值 | 作用 |
| --- | --- | --- |
| `SEC_GO_ROOT` | 源码仓库根目录或当前目录 | 产品根目录解析 |
| `SEC_GO_DB` | `<root>/data/sec-go.db` | 完整数据库路径，优先级最高 |
| `SEC_GO_DATA_DIR` | `<root>/data` | 未设置 `SEC_GO_DB` 时的数据目录 |
| `SEC_GO_SKILLS_DIR` | `<root>/skills`（存在 policy 时） | 显式可信 Skill Catalog |
| `SEC_GO_ADMIN_USERNAME` | `admin` | 首次创建的管理员名 |
| `SEC_GO_ADMIN_PASSWORD` | `secgo` | 首次创建的管理员密码；生产禁止默认值 |
| `SEC_GO_SECRET_KEY` | 自动生成本地文件 | JWT 签名密钥，至少 32 UTF-8 字节 |
| `SEC_GO_HOST` | `127.0.0.1` | 仅 `python -m security_agent.main` 的监听地址 |
| `SEC_GO_PORT` | `8000` | 仅 `python -m security_agent.main` 的监听端口 |

`sec-go serve` 使用它自己的 `--host`、`--port` 参数；不要误以为 `SEC_GO_HOST` 会覆盖该
子命令的显式默认值。

## HTTP API

API 默认位于 `http://127.0.0.1:8000`。除健康检查、登录、OpenAPI 和静态前端外，产品
资源都需要：

```http
Authorization: Bearer <access_token>
```

已实现路由：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/health` | 无认证健康检查 |
| `POST` | `/api/auth/login` | 用户名和密码换取 Bearer Token |
| `GET` | `/api/auth/me` | 校验 Token 并返回当前用户 |
| `GET` | `/api/tasks` | 当前用户的任务列表 |
| `POST` | `/api/tasks` | 创建并异步启动任务，返回 HTTP 202 |
| `GET` | `/api/tasks/{task_id}` | Task/Run/Plan/Evidence 摘要/Finding/报告详情 |
| `POST` | `/api/tasks/{task_id}/cancel` | 取消本进程仍在运行的任务 |
| `GET` | `/api/tasks/{task_id}/evidence/{evidence_id}` | 显式读取完整 Evidence 原文与哈希校验结果 |
| `GET` | `/api/tasks/{task_id}/events` | Bearer SSE 时间线与断线重放 |

登录请求：

```json
{
  "username": "admin",
  "password": "<password>"
}
```

创建任务请求：

```json
{
  "title": "本机服务检查",
  "description": "分析明确授权的 localhost 测试服务",
  "target": "127.0.0.1",
  "ports": [8000, 8080]
}
```

请求 schema 拒绝未知字段。非 loopback 目标返回 422；访问其他用户的任务、事件或
Evidence 返回 404，避免暴露资源是否存在。任务详情只包含 Evidence 摘要；完整原文必须
通过 Evidence 专用路由显式请求。

SSE 通过 `Last-Event-ID` 接受非负数字游标。游标来自 SQLite `events.rowid`，服务按升序
重放遗漏事件，空闲时发送注释心跳，终态后关闭流。因为 SSE 需要 Bearer Header，前端
使用 `fetch()` 流而不是原生 `EventSource`。

## SQLite 数据模型

产品表与 Kernel 审计表位于同一个 `data/sec-go.db`，以便 Task、Run 和证据链使用同一
持久化边界。

产品投影表：

- `users`：`id`、大小写不敏感的唯一 `username`、bcrypt `password_hash`、`created_at`；
- `tasks`：`user_id` 所有权、标题、描述、序列化 `TaskSpec`、产品状态、唯一 `run_id` 和
  时间戳。

Kernel 审计表：

- `runs`：Task 快照、当前 Plan 版本、Run 状态、计数和错误；
- `plans`、`plan_nodes`：版本化 DAG 和节点执行状态；
- `actions`：每次工具尝试、参数、耗时、结果和 Evidence 引用；
- `evidence`：完整原文、SHA-256、来源与元数据；
- `findings`：严重度、置信度、验证状态和 Evidence 引用；
- `events`：可供 SSE 重放的不可变事件记录。

`tasks.run_id` 允许在 Kernel 首次写入 `runs` 前预分配，因此没有直接外键到 `runs`；后续
投影始终按同一 `run_id` 读取 Kernel 审计记录。用户隔离在 Repository 和 Application
Service 两层执行。

数据库启用 WAL 和外键约束，但当前没有通用迁移框架。原始 Evidence 是明文，可能包含
响应正文或文件内容；必须把整个数据库视为敏感审计资产。不要在服务运行时用普通文件
复制冒充一致性备份，应停服备份或使用 SQLite 的一致性备份机制。

## 前端开发

需要 Node.js 22.18 或更高版本。后端先在 `127.0.0.1:8000` 启动，然后：

Windows PowerShell：

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run dev
```

Linux/macOS：

```bash
cd frontend
npm ci
npm run dev
```

Vite 固定监听 `127.0.0.1:5173`，并把 `/api` 代理到 `http://127.0.0.1:8000`。开发时保持
`VITE_API_BASE_URL` 为空即可。当前 FastAPI 服务没有配置通用 CORS，产品支持边界是同源
部署或 Vite 本地代理，不应把前端直接指向任意跨源 API。

前端验证：

```bash
npm test
npm run build
```

## 前端生产构建

在源码仓库中生成静态产物：

```bash
cd frontend
npm ci
npm run build
cd ..
sec-go serve --host 127.0.0.1 --port 8000
```

`npm run build` 生成 `frontend/dist/`。FastAPI 启动时检测该目录：存在时同源提供 SPA、
静态资源和 `/api`；不存在时根路径只返回 API 提示。源码 checkout 是当前生产静态发现
方式，Python wheel 尚未打包前端产物。

`npm run preview` 只用于检查 Vite 构建结果，不代替 SEC-GO API。生产仍应保持同源和
loopback；当前版本没有 TLS、反向代理信任或公网部署加固。

## 依赖与体积策略

依赖按边界拆分：

- Core 运行时只依赖 `httpx`；领域模型和 SQLite 使用标准库；
- `web` extra 才安装 `bcrypt`、`fastapi` 和不带 `standard` 大型附加项的 `uvicorn`；
- `mcp`、`knowledge` extra 当前为空，表示接口预留而非已实现 adapter；
- Ruff、mypy 只在 `dev` extra；
- React、XYFlow、Markdown、Vite 等只存在于 `frontend/node_modules`，不会进入 Python Core
  依赖；
- Vite 将 React、Plan Graph 和 Markdown 引擎拆为独立 chunk；
- Python wheel 只携带项目自有内置 Skill，不静默打包完整私有 Skill 语料库或前端
  `node_modules`。

因此，CLI-only Kernel 不需要 FastAPI、bcrypt、Node.js 或浏览器；只有运行产品层时才
安装对应依赖。

本次 Windows 验收的实测值（文件逻辑大小，四舍五入）如下：

| 项目 | 大小 |
| --- | ---: |
| 前端源码与锁文件（排除 `node_modules`、`dist`） | 0.66 MiB |
| 前端完整开发 `node_modules` | 98.22 MiB |
| 前端生产 `dist` | 0.62 MiB |
| Backend `src/` + `scripts/`（排除 Python 缓存） | 0.47 MiB |
| 已安装的 Core/Web Python 包及其主要传递依赖 | 16.50 MiB |
| 原仓库源码与 Skill 语料（同步前、排除 `.git`） | 10.28 MiB |

按此口径，共同开发工作集约 126 MiB，低于 150 MiB 目标；数字不包含 Python/Node
解释器本体、`.git`、缓存和运行数据库。部署时不携带 `node_modules`，只保留 0.62 MiB
静态构建和约 16.50 MiB Python 运行依赖，体积会显著更小。不同包版本与文件系统分配
单元会让磁盘“占用空间”略有变化，因此以锁文件和构建产物为交付基准，不提交依赖目录。

## 单进程和 loopback-only 限制

当前部署模型必须满足：

- Uvicorn `workers=1`；不要使用多 worker、Gunicorn 多进程或多个服务实例共享任务；
- API 监听 `127.0.0.1`，Vite 监听 `127.0.0.1`；虽然 CLI 接受其他 `--host` 文本，但
  `0.0.0.0` 和公网监听不在受支持安全边界内；
- TaskService 只接受 `localhost`、IPv4 loopback 或 IPv6 loopback，工具层仍会再次校验
  scope；
- 默认最多同时运行 2 个任务，调度和取消状态保存在当前进程内；
- 重启会中断活动任务，已落库审计记录仍在，但不会自动续跑、重排队或恢复；
- SQLite 适合单机轻量写入，不是分布式锁、队列或跨节点协调器；
- 当前没有公网认证加固、TLS、速率限制、账号锁定、CSRF/CORS 部署方案或外部身份提供商。

`sec-go serve --host 0.0.0.0` 能被参数解析器接受，不代表项目承诺其安全性。当前版本请勿
这样部署。

## 下一阶段接口预留（均未实现）

下表只描述现有端口如何承接下一阶段工作，不表示对应功能已经可用。

| 方向 | 已存在的稳定接缝 | 下一阶段规划 |
| --- | --- | --- |
| MCP | `Tool`、`ToolRegistryPort`、`ToolExecutionContext`、capability 与风险策略 | 实现可选 MCP Tool Adapter、连接生命周期、超时/取消、schema 转换、来源标记和审计；`mcp` extra 当前为空 |
| Skill | `SkillProvider`、`SkillDocument`、`SkillPolicy` 与 `skills/policy.json` | 增加来源清单、版本/完整性治理、受控更新和高风险 Skill 独立执行边界；现有文本 Skill 仍不能自行注册工具或授权操作 |
| 知识库 | `KnowledgeProvider.search/get`、`KnowledgeDocument`；当前组合使用 `NullKnowledgeProvider` | 实现带来源、哈希、分块上限和权限边界的 Markdown/JSON 摄取及 SQLite FTS5 检索；`knowledge` extra 当前为空 |
| Multi-Agent | `Agent`、`AgentDispatcher`、PlanNode `assigned_agent` 和事件端口 | 实现受步骤、时间、Token、并发和风险预算约束的调度器；保持每个动作经 ToolExecutor、scope、Evidence 和 Verifier，不允许子 Agent 绕过策略 |

这些扩展应继续遵循四条原则：Core 不依赖产品框架；外部内容按不可信输入处理；所有工具
能力必须显式注册；完成状态只能由确定性状态机和独立验证器接受。

## 验收

后端：

```bash
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
mypy
```

前端：

```bash
cd frontend
npm test
npm run build
```

更底层的 Kernel 设计见 [ARCHITECTURE.md](ARCHITECTURE.md)、
[DOMAIN_MODEL.md](DOMAIN_MODEL.md)、[SKILLS.md](SKILLS.md) 和
[EXTENSION_POINTS.md](EXTENSION_POINTS.md)。
