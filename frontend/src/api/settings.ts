import { requestJson } from "./client"

export interface LlmProviderConfig {
  provider: string
  api_key: string
  model: string
  base_url: string
  updated_at?: string
}

export interface LlmSettingsResponse {
  providers: LlmProviderConfig[]
  active?: string | null
}

export async function getLlmSettings(): Promise<LlmSettingsResponse> {
  return requestJson<LlmSettingsResponse>("/api/settings/llm")
}

export async function saveLlmSettings(config: {
  provider: string
  api_key: string
  model: string
  base_url: string
}): Promise<{ provider: string; status: string }> {
  return requestJson<{ provider: string; status: string }>("/api/settings/llm", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  })
}

export async function deleteLlmSetting(provider: string): Promise<{ provider: string; status: string }> {
  return requestJson<{ provider: string; status: string }>(
    `/api/settings/llm/${encodeURIComponent(provider)}`,
    { method: "DELETE" },
  )
}
