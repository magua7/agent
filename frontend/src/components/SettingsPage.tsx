import { Check, Eye, EyeOff, Key, Loader2, Pencil, Plus, Power, Save, Server, Trash2, Wrench } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { deleteLlmSetting, getLlmSettings, saveLlmSettings, type LlmProviderConfig } from "../api/settings"
import { useToast } from "./Toast"

interface ProviderMeta {
  label: string
  color: string
  base_url: string
  models: string[]
}

const PROVIDER_META: Record<string, ProviderMeta> = {
  deepseek: {
    label: "DeepSeek",
    color: "#6366f1",
    base_url: "https://api.deepseek.com",
    models: ["deepseek-chat", "deepseek-reasoner", "deepseek-v3", "deepseek-r1"],
  },
  openai: {
    label: "OpenAI",
    color: "#10b981",
    base_url: "https://api.openai.com/v1",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
  },
  anthropic: {
    label: "Anthropic",
    color: "#f59e0b",
    base_url: "https://api.anthropic.com",
    models: ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
  },
  moonshot: {
    label: "Moonshot",
    color: "#d946ef",
    base_url: "https://api.moonshot.cn/v1",
    models: ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
  },
  qwen: {
    label: "通义千问",
    color: "#0ea5e9",
    base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    models: ["qwen-plus", "qwen-max", "qwen-turbo", "qwen2.5-72b-instruct"],
  },
  glm: {
    label: "智谱 GLM",
    color: "#06b6d4",
    base_url: "https://open.bigmodel.cn/api/paas/v4",
    models: ["glm-4-plus", "glm-4-air", "glm-4-flash"],
  },
}

const CUSTOM_OPTION = "__custom__"
const DEFAULT_COLOR = "#64748b"

type SaveStatus = "idle" | "saving" | "saved" | "error"

function ProviderIcon({ name, color }: { name: string; color: string }) {
  return (
    <div
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-sm font-bold text-white shadow-sm"
      style={{ background: color }}
    >
      {name.slice(0, 2).toUpperCase()}
    </div>
  )
}

export function SettingsPage() {
  const { toast } = useToast()
  const [providers, setProviders] = useState<LlmProviderConfig[]>([])
  const [active, setActive] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [providerKey, setProviderKey] = useState<string>("deepseek")
  const [customName, setCustomName] = useState("")
  const [isCustom, setIsCustom] = useState(false)
  const [apiKey, setApiKey] = useState("")
  const [model, setModel] = useState("")
  const [baseUrl, setBaseUrl] = useState("")
  const [showKey, setShowKey] = useState(false)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle")
  const [editingName, setEditingName] = useState<string | null>(null)

  const formRef = useRef<HTMLDivElement>(null)
  const presetKeys = useMemo(() => Object.keys(PROVIDER_META), [])

  const activeName = isCustom ? customName.trim() : providerKey
  const existingProvider = providers.find(p => p.provider === activeName)
  const modelSuggestions = isCustom ? [] : (PROVIDER_META[providerKey]?.models || [])

  const refresh = useCallback(async () => {
    try {
      const data = await getLlmSettings()
      setProviders(data.providers || [])
      setActive(data.active || null)
    } catch {
      setError("无法加载设置")
    }
  }, [])

  useEffect(() => {
    refresh()
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [refresh])

  const resetForm = useCallback((toKey = "deepseek") => {
    setEditingName(null)
    const meta = PROVIDER_META[toKey]
    setProviderKey(toKey)
    setIsCustom(false)
    setCustomName("")
    setApiKey("")
    setModel(meta?.models[0] || "")
    setBaseUrl(meta?.base_url || "")
  }, [])

  const handleSelectProvider = useCallback((key: string) => {
    setEditingName(null)
    if (key === CUSTOM_OPTION) {
      setIsCustom(true)
      setCustomName("")
      setApiKey("")
      setModel("")
      setBaseUrl("")
      return
    }
    setIsCustom(false)
    setProviderKey(key)
    const existing = providers.find(p => p.provider === key)
    if (existing) {
      setApiKey("")
      setModel(existing.model)
      setBaseUrl(existing.base_url)
    } else {
      const meta = PROVIDER_META[key]
      setApiKey("")
      setModel(meta?.models[0] || "")
      setBaseUrl(meta?.base_url || "")
    }
  }, [providers])

  const handleEdit = useCallback((p: LlmProviderConfig) => {
    setEditingName(p.provider)
    if (PROVIDER_META[p.provider]) {
      setProviderKey(p.provider)
      setIsCustom(false)
      setCustomName("")
    } else {
      setProviderKey(CUSTOM_OPTION)
      setIsCustom(true)
      setCustomName(p.provider)
    }
    setApiKey("")
    setModel(p.model)
    setBaseUrl(p.base_url)
    setTimeout(() => formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50)
  }, [])

  const handleSave = useCallback(async () => {
    if (!activeName) return
    setSaveStatus("saving")
    try {
      await saveLlmSettings({
        provider: activeName,
        api_key: apiKey,
        model,
        base_url: baseUrl,
      })
      setSaveStatus("saved")
      setApiKey("")
      await refresh()
      toast("info", editingName ? `已更新「${activeName}」并设为当前` : `已添加「${activeName}」并设为当前`)
      setTimeout(() => {
        setSaveStatus("idle")
        resetForm()
      }, 800)
    } catch (e) {
      setSaveStatus("error")
      toast("error", "保存失败")
      setTimeout(() => setSaveStatus("idle"), 3000)
    }
  }, [activeName, apiKey, model, baseUrl, editingName, refresh, resetForm, toast])

  const handleActivate = useCallback(async (p: LlmProviderConfig) => {
    try {
      await saveLlmSettings({
        provider: p.provider,
        api_key: "",
        model: p.model,
        base_url: p.base_url,
      })
      await refresh()
      toast("info", `已切换当前使用为「${p.provider}」`)
    } catch {
      toast("error", "切换失败")
    }
  }, [refresh, toast])

  const handleDelete = useCallback(async (p: LlmProviderConfig) => {
    if (!window.confirm(`确定删除供应商「${p.provider}」？`)) return
    try {
      await deleteLlmSetting(p.provider)
      await refresh()
      toast("info", `已删除「${p.provider}」`)
      if (editingName === p.provider) resetForm()
    } catch {
      toast("error", "删除失败")
    }
  }, [editingName, refresh, resetForm, toast])

  const canSave = activeName.length > 0 && (
    !existingProvider
      ? apiKey.length > 0 && model.length > 0 && baseUrl.length > 0
      : apiKey.length > 0 || model !== existingProvider.model || baseUrl !== existingProvider.base_url
  )

  if (loading) {
    return (
      <main className="flex min-h-[calc(100vh-4.5rem)] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-cyan-500" />
      </main>
    )
  }

  return (
    <main className="min-h-[calc(100vh-4.5rem)] overflow-y-auto px-6 py-10">
      <div className="app-content-shell mx-auto max-w-3xl">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">设置</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            配置 LLM 供应商（支持添加多个，切换当前使用）和 MCP 工具
          </p>
        </div>

        {/* ── 已配置供应商列表 ── */}
        <section className="surface-card-strong mb-6 rounded-[32px] p-6 md:p-8">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-100 text-emerald-600 dark:bg-emerald-900/50 dark:text-emerald-300">
              <Key className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">已配置供应商</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                {active ? `当前使用：${active}` : "尚未选择当前使用的供应商"} · 可添加多个，随时切换
              </p>
            </div>
          </div>

          {error && (
            <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
              {error}
            </div>
          )}

          {providers.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-white/70 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-950/40 dark:text-slate-400">
              还没有配置任何供应商。在下方选择预设或「自定义」添加一个。
            </div>
          ) : (
            <div className="space-y-2.5">
              {providers.map(p => {
                const meta = PROVIDER_META[p.provider]
                const label = meta?.label || p.provider
                const color = meta?.color || DEFAULT_COLOR
                const isActive = p.provider === active
                const isEditing = editingName === p.provider
                return (
                  <div
                    key={p.provider}
                    className={`flex items-center gap-3 rounded-2xl border p-4 transition ${
                      isActive
                        ? "border-emerald-300 bg-emerald-50/60 dark:border-emerald-800 dark:bg-emerald-950/20"
                        : "border-slate-200 bg-white/80 hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950/50 dark:hover:border-slate-600"
                    }`}
                  >
                    <ProviderIcon name={label} color={color} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-sm font-semibold text-slate-800 dark:text-slate-200">{label}</span>
                        {isActive && (
                          <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">
                            当前使用
                          </span>
                        )}
                        {isEditing && (
                          <span className="rounded-full bg-cyan-100 px-2 py-0.5 text-xs font-medium text-cyan-700 dark:bg-cyan-900/50 dark:text-cyan-300">
                            编辑中
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 truncate text-xs text-slate-500 dark:text-slate-400">
                        {p.model} · {p.base_url}
                      </div>
                      <div className="text-xs text-slate-400 dark:text-slate-500">密钥 {p.api_key}</div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => handleEdit(p)}
                        title="编辑"
                        className="flex h-8 w-8 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 transition hover:border-cyan-300 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-cyan-600 dark:hover:text-cyan-300"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      {!isActive && (
                        <button
                          type="button"
                          onClick={() => handleActivate(p)}
                          title="设为当前使用"
                          className="flex h-8 w-8 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 transition hover:border-emerald-300 hover:text-emerald-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-emerald-600 dark:hover:text-emerald-300"
                        >
                          <Power className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleDelete(p)}
                        title="删除"
                        className="flex h-8 w-8 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 transition hover:border-red-300 hover:text-red-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-red-700 dark:hover:text-red-400"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>

        {/* ── 添加 / 编辑供应商表单 ── */}
        <section ref={formRef} className="surface-card-strong mb-6 rounded-[32px] p-6 md:p-8">
          <div className="mb-6 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-100 text-cyan-600 dark:bg-cyan-900/50 dark:text-cyan-300">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                  {editingName ? `编辑供应商：${editingName}` : "添加供应商"}
                </h2>
                <p className="text-sm text-slate-500 dark:text-slate-400">API 密钥加密存储，前端不可见明文</p>
              </div>
            </div>
            {editingName && (
              <button
                type="button"
                onClick={() => resetForm()}
                className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-500 transition hover:border-cyan-300 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-cyan-600 dark:hover:text-cyan-300"
              >
                <Plus className="h-3.5 w-3.5" />
                新建
              </button>
            )}
          </div>

          <div className="space-y-6">
            {/* Provider tiles */}
            <div>
              <div className="mb-2 text-sm font-medium text-slate-700 dark:text-slate-300">选择预设</div>
              <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
                {presetKeys.map(key => {
                  const meta = PROVIDER_META[key]
                  const activeTile = !isCustom && providerKey === key
                  const configured = providers.some(p => p.provider === key)
                  return (
                    <button
                      key={key}
                      type="button"
                      onClick={() => handleSelectProvider(key)}
                      className={`flex items-center gap-2.5 rounded-2xl border p-3 text-left transition ${
                        activeTile
                          ? "border-cyan-400 bg-cyan-50/80 shadow-sm ring-1 ring-cyan-200 dark:border-cyan-500 dark:bg-cyan-950/40 dark:ring-cyan-800"
                          : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950/40 dark:hover:border-slate-600 dark:hover:bg-slate-900"
                      }`}
                    >
                      <ProviderIcon name={meta.label} color={meta.color} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium text-slate-800 dark:text-slate-200">
                          {meta.label}
                        </div>
                        {configured && (
                          <div className="flex items-center gap-1 text-xs text-emerald-500">
                            <Key className="h-3 w-3" />
                            已配置
                          </div>
                        )}
                      </div>
                    </button>
                  )
                })}

                {/* Custom tile */}
                <button
                  type="button"
                  onClick={() => handleSelectProvider(CUSTOM_OPTION)}
                  className={`flex items-center justify-center gap-2 rounded-2xl border-2 border-dashed p-3 transition ${
                    isCustom
                      ? "border-cyan-400 bg-cyan-50/80 text-cyan-700 dark:border-cyan-500 dark:bg-cyan-950/40 dark:text-cyan-300"
                      : "border-slate-300 text-slate-400 hover:border-cyan-400 hover:text-cyan-600 dark:border-slate-700 dark:text-slate-500 dark:hover:border-cyan-500 dark:hover:text-cyan-400"
                  }`}
                >
                  <Plus className="h-4 w-4" />
                  <span className="text-sm font-medium">自定义</span>
                </button>
              </div>

              {isCustom && (
                <div className="mt-3">
                  <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">供应商名称</label>
                  <input
                    type="text"
                    value={customName}
                    onChange={e => setCustomName(e.target.value)}
                    placeholder="如 my-relay"
                    className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 placeholder-slate-400 focus:border-cyan-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-cyan-400"
                  />
                </div>
              )}
            </div>

            {/* Base URL */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">Base URL</label>
              <input
                type="text"
                value={baseUrl}
                onChange={e => setBaseUrl(e.target.value)}
                placeholder="https://api.example.com/v1"
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 placeholder-slate-400 focus:border-cyan-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-cyan-400"
              />
            </div>

            {/* API Key */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
                API 密钥
                {existingProvider && !apiKey && (
                  <span className="ml-2 text-xs font-normal text-slate-400">已配置：{existingProvider.api_key}</span>
                )}
              </label>
              <div className="relative">
                <input
                  type={showKey ? "text" : "password"}
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder={existingProvider ? "输入新密钥以替换" : "sk-..."}
                  className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 pr-10 text-sm text-slate-900 placeholder-slate-400 focus:border-cyan-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-cyan-400"
                />
                <button
                  type="button"
                  onClick={() => setShowKey(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                >
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Model */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
                模型
                <span className="ml-2 text-xs font-normal text-slate-400">可自由填写</span>
              </label>
              <input
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder="如 deepseek-chat / gpt-4o"
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 placeholder-slate-400 focus:border-cyan-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-cyan-400"
              />
              {modelSuggestions.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <span className="text-xs text-slate-400 dark:text-slate-500">常用模型：</span>
                  {modelSuggestions.map(m => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setModel(m)}
                      className={`rounded-full border px-2.5 py-1 text-xs transition ${
                        model === m
                          ? "border-cyan-400 bg-cyan-50 text-cyan-700 dark:border-cyan-600 dark:bg-cyan-950/40 dark:text-cyan-300"
                          : "border-slate-200 bg-white text-slate-500 hover:border-cyan-300 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-cyan-700 dark:hover:text-cyan-400"
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Save */}
            <div className="flex items-center gap-3 pt-2">
              <button
                type="button"
                onClick={handleSave}
                disabled={!canSave || saveStatus === "saving"}
                className="inline-flex items-center gap-2 rounded-full bg-cyan-600 px-6 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-700 disabled:bg-slate-200 disabled:text-slate-400 dark:disabled:bg-slate-800 dark:disabled:text-slate-500"
              >
                {saveStatus === "saving" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : saveStatus === "saved" ? (
                  <Check className="h-4 w-4" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                {saveStatus === "saving" ? "保存中..." : saveStatus === "saved" ? "已保存" : saveStatus === "error" ? "保存失败" : editingName ? "保存修改" : "添加并设为当前"}
              </button>
              {existingProvider && (
                <span className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Key className="h-3 w-3" />
                  已配置
                </span>
              )}
            </div>
          </div>
        </section>

        {/* MCP Tool Management (placeholder) */}
        <section className="surface-card-strong rounded-[32px] p-6 md:p-8">
          <button type="button" className="flex w-full items-center justify-between text-left">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-100 text-purple-600 dark:bg-purple-900/50 dark:text-purple-300">
                <Wrench className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">MCP 工具</h2>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  管理智能体可用的 MCP 工具（即将推出）
                </p>
              </div>
            </div>
          </button>
        </section>
      </div>
    </main>
  )
}
