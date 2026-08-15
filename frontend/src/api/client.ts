interface ApiResponse<T> {
  success: boolean
  data?: T
  code?: string
  message?: string
}

export async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, init)
  const contentType = resp.headers.get("content-type") || ""

  let payload: ApiResponse<T> | null = null
  if (contentType.includes("application/json")) {
    payload = await resp.json()
  }

  if (!resp.ok) {
    const message = payload?.message || payload?.code || `HTTP ${resp.status}`
    throw new Error(message)
  }

  if (!payload) {
    throw new Error("响应不是 JSON")
  }

  if (!payload.success) {
    throw new Error(payload.message || payload.code || "请求失败")
  }

  return payload.data as T
}
