const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1').replace(/\/$/, '')
let accessToken = null

export function setToken(value) { accessToken = value }

async function refresh() {
  const response = await fetch(`${API_URL}/auth/refresh`, { method: 'POST', credentials: 'include' })
  if (!response.ok) return false
  const data = await response.json()
  accessToken = data.access_token
  return true
}

export async function api(path, options = {}, retry = true) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers }
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`
  const response = await fetch(`${API_URL}${path}`, { ...options, headers, credentials: 'include' })
  if (response.status === 401 && retry && await refresh()) return api(path, options, false)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(Array.isArray(body.detail) ? body.detail[0]?.msg : body.detail || 'Request failed')
  }
  if (response.status === 204) return null
  return response.json()
}

export async function downloadReport(scanId) {
  let response = await fetch(`${API_URL}/reports/${scanId}.html`, {
    credentials: 'include', headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  })
  if (response.status === 401 && await refresh()) {
    response = await fetch(`${API_URL}/reports/${scanId}.html`, { credentials: 'include', headers: { Authorization: `Bearer ${accessToken}` } })
  }
  if (!response.ok) throw new Error('Report download failed')
  const link = document.createElement('a')
  link.href = URL.createObjectURL(await response.blob())
  link.download = `aegisscan-${scanId}.html`
  link.click()
  URL.revokeObjectURL(link.href)
}
