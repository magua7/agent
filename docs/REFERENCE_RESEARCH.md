# Clean-room Reference Research

调研日期：2026-08-14。

本项目从空仓库开始实现。以下仓库只用于识别通用需求和常见风险；没有复制源码、提示词、Tool Schema、Skill 语料、报告模板、测试夹具或独特目录结构。

## KoGFuzi/TianGong

一手资料：[仓库 README](https://github.com/KoGFuzi/TianGong)、[核心引擎](https://github.com/KoGFuzi/TianGong/blob/main/kernel/handoff-engine.ts)、[工具执行器](https://github.com/KoGFuzi/TianGong/blob/main/tool/executor.ts)。

抽象出的需求：Core/UI 事件边界、run-local context、能力化工具协议、执行预算、可替换 Provider。没有采用固定角色/handoff 拓扑、全局 resolver/event bus、字符串 shell 策略、MCP 名称路由或其目录布局。

仓库 README 声称 MIT，但调研时根目录没有完整 `LICENSE`，GitHub 元数据返回 `license: null`。因此本项目不把其代码视为可复用实现来源。

## magua7/zhiyugo

一手资料：[仓库 README](https://github.com/magua7/zhiyugo/blob/main/README.md)、[AgentState](https://github.com/magua7/zhiyugo/blob/main/zhiyugo/agent/agent_state.py)、[CI](https://github.com/magua7/zhiyugo/blob/main/.github/workflows/ci.yml)。

抽象出的需求：raw evidence 与模型 preview 分离、Finding 引用、run 恢复所需的事件/版本设计、CLI/Web 共享应用服务。没有采用其 AgentState 字段、内置工具、MCP/插件实现、Skill、CLI/TUI/Web、Prompt 或目录。

许可证尤其不明确：调研时主分支没有 `LICENSE`，GitHub [仓库元数据](https://api.github.com/repos/magua7/zhiyugo) 为 `license: null`，提交历史含 [Removed MIT license](https://github.com/magua7/zhiyugo/commit/affebe69)，而部分项目元数据仍写 MIT。按不可复用处理。

## Netw0rkNoob/VulnClaw

一手资料：[仓库 README](https://github.com/Netw0rkNoob/VulnClaw/blob/main/README.md)、[核心包](https://github.com/Netw0rkNoob/VulnClaw/tree/main/vulnclaw)、[LICENSE](https://github.com/Netw0rkNoob/VulnClaw/blob/main/LICENSE)。

抽象出的需求：证据账本、有界上下文、完成 evidence gate、统一工具生命周期、scope/动作/预算策略、多界面复用。没有采用其 solve loop、AgentState、工具实现、Skill/KB、Prompt、报告/PoC 模板或大型内置工具模块。

VulnClaw 使用 MIT License；即使如此，本项目仍选择独立实现而不是派生或复制，从而满足本任务的 clean-room 约束。

## 独立设计结果

本项目采用自己定义的：

- frozen domain values + verifier-gated transition；
- versioned plan snapshots and stale-write protection；
- capability request → central executor → action/evidence pair；
- exact criterion assessments with hard provenance validation；
- separate `contracts / engine / infrastructure / interfaces` dependency direction；
- no shell tool、no MCP/Web/KB runtime dependency in MVP。
