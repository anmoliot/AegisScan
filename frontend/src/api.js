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

// ASM API functions
export async function getAssets() { return api('/asm/assets') }
export async function createAsset(domain) { return api('/asm/assets', { method: 'POST', body: JSON.stringify({ domain }) }) }
export async function discoverAsset(id) { return api(`/asm/assets/${id}/discover`, { method: 'POST' }) }
export async function getSubdomains(id) { return api(`/asm/assets/${id}/subdomains`) }
export async function getCertificates(id) { return api(`/asm/assets/${id}/certificates`) }

// Monitoring API functions
export async function getSchedules() { return api('/monitoring/schedules') }
export async function createSchedule(assetId, frequency) { return api('/monitoring/schedules', { method: 'POST', body: JSON.stringify({ asset_id: assetId, frequency }) }) }
export async function getAlerts() { return api('/monitoring/alerts') }
export async function acknowledgeAlert(id) { return api(`/monitoring/alerts/${id}/acknowledge`, { method: 'PATCH' }) }

// Graph API functions
export async function getGraph(id) { return api(`/graph/assets/${id}`) }
export async function getAttackPaths(id) { return api(`/graph/attack-paths/${id}`) }

// Risk API functions
export async function getRiskDashboard() { return api('/risk/dashboard') }
export async function getRiskScore(id) { return api(`/risk/score/${id}`) }

