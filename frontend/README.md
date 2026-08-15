# SEC-GO Frontend

SEC-GO 的独立 Web 客户端，使用 React 18、TypeScript、Vite、Tailwind CSS。

它只依赖公开 JSON/SSE 契约，不导入 Security Agent Kernel。当前产品界面覆盖：

- Bearer 登录与 `/api/auth/me` 会话校验；
- 明确 loopback 目标和 TCP 端口的授权任务创建；
- 多个 Task/Run 并发执行和自由切换；
- 基于 `PlanNode.dependencies` 的 Plan DAG；
- 可重放 SSE 审计时间线；
- Evidence 摘要、按需原文和内容哈希校验状态；
- Finding、Verification 与 Markdown Report；
- 任意 REST/SSE 401 自动清理会话并返回登录页。

旧的会话/聊天状态、思维链展示、运行时审批和从工具文本猜测攻击图不属于当前 SEC-GO UI。

## 本地开发

需要 Node.js 22.18 或更高版本（测试直接使用 Node 的 TypeScript type stripping）：

```bash
npm ci
npm run dev
```

Vite 默认监听 `127.0.0.1:5173`，并把 `/api` 代理到
`http://127.0.0.1:8000`。请保持 `VITE_API_BASE_URL` 为空；后端有意不开放
CORS，开发代理与生产静态托管都使用同源 `/api`，避免把 Bearer Token 发送给
意外配置的跨域地址。

生产环境运行 `npm run build` 后，FastAPI 会直接托管 `frontend/dist`。

## 验证

```bash
npm test
npm run build
```

测试覆盖 loopback/端口授权边界、冻结的 Task Detail DTO、事件状态映射、SSE 分帧和数字 `Last-Event-ID` 游标。生产构建把 React、React Flow 和 Markdown 引擎拆成独立 chunk。

## API 契约

认证：

- `POST /api/auth/login`
- `GET /api/auth/me`

任务：

- `GET /api/tasks`
- `POST /api/tasks`
- `GET /api/tasks/{task_id}`
- `POST /api/tasks/{task_id}/cancel`
- `GET /api/tasks/{task_id}/evidence/{evidence_id}`
- `GET /api/tasks/{task_id}/events`

SSE 使用 `fetch()` 而不是原生 `EventSource`，因为请求需要 `Authorization: Bearer ...`。重连时会发送数字 `Last-Event-ID`，并按 `event_id` 去重。

## 代码入口

- `src/App.tsx`：薄产品入口。
- `src/product/SecGoApp.tsx`：认证门和整体界面。
- `src/product/useSecGoController.ts`：认证、并发任务、详情、Evidence 与 SSE 状态。
- `src/product/api.ts`：公开 REST 客户端。
- `src/product/sse.ts`、`sseParser.ts`：Bearer SSE 与可测试分帧器。
- `src/product/model.ts`：后端 DTO 归一化和授权输入校验。
- `src/product/components/`：SEC-GO 产品组件。

访问令牌只保存在 `sessionStorage`。报告 Markdown 不启用原始 HTML，链接协议受限，Evidence 元数据中的敏感键在展示前会再次脱敏。
