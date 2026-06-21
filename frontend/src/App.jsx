import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, downloadReport, setToken } from './api'
import './App.css'

const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

function Logo() {
  return <div className="brand">
    <span className="logo-mark" aria-hidden="true">
      <svg viewBox="0 0 42 42" role="img">
        <path d="M21 4 34 9v10c0 8.7-5.2 15.6-13 19-7.8-3.4-13-10.3-13-19V9l13-5Z" />
        <path d="M14 23.5 19 28l9.5-13" />
      </svg>
    </span>
    <span className="brand-copy"><strong>AegisScan</strong><small>Exposure platform</small></span>
  </div>
}

function Auth({ onAuthenticated }) {
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({ email: '', password: '', display_name: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const data = await api(`/auth/${mode}`, { method: 'POST', body: JSON.stringify(form) }, false)
      setToken(data.access_token)
      onAuthenticated(await api('/auth/me'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return <main className="auth-shell">
    <section className="auth-story">
      <Logo />
      <div>
        <p className="eyebrow">AUTHORIZED SECURITY TESTING</p>
        <h1>See the cracks<br />before they spread.</h1>
        <p>Focused web security checks, clean evidence, and reports your team can act on.</p>
      </div>
      <small>Built for owned and explicitly authorized targets.</small>
    </section>
    <section className="auth-panel">
      <form className="auth-card" onSubmit={submit}>
        <p className="eyebrow">{mode === 'login' ? 'WELCOME BACK' : 'CREATE ACCOUNT'}</p>
        <h2>{mode === 'login' ? 'Sign in to your workspace' : 'Start scanning safely'}</h2>
        {mode === 'register' && <label>Display name<input value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} autoComplete="name" /></label>}
        <label>Email<input type="email" required value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} autoComplete="email" /></label>
        <label>Password<input type="password" required minLength="10" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>
        {error && <p className="error">{error}</p>}
        <button className="primary" disabled={busy}>{busy ? 'Please wait...' : mode === 'login' ? 'Sign in' : 'Create account'}</button>
        <button type="button" className="link" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}>{mode === 'login' ? 'Need an account? Register' : 'Already registered? Sign in'}</button>
      </form>
    </section>
  </main>
}

function buildMetrics(scans) {
  const findings = scans.flatMap(scan => scan.findings || [])
  const high = findings.filter(f => ['critical', 'high'].includes(f.severity)).length
  const active = scans.filter(scan => ['queued', 'running'].includes(scan.status)).length
  const failed = scans.filter(scan => scan.status === 'failed').length
  const hosts = new Set(scans.map(scan => scan.target_host).filter(Boolean)).size
  const requests = scans.reduce((sum, scan) => sum + (scan.request_count || 0), 0)
  const exposureScore = Math.max(0, Math.min(100, Math.round(100 - (high * 12) - (failed * 8) - (findings.length * 2))))
  return { findings, high, active, failed, hosts, requests, exposureScore }
}

function OverviewPage({ scans, metrics, onNewScan, onNavigate, onOpenScan }) {
  const latest = scans.slice(0, 4)
  return <section className="content overview-layout">
    <div className="hero-row">
      <div>
        <p className="eyebrow neon">AI-ASSISTED ATTACK SURFACE INTELLIGENCE</p>
        <h1>Executive Overview</h1>
        <p className="hero-copy">Exposure intelligence, scan coverage, and evidence-led web risk operations for authorized assets.</p>
      </div>
      <div className="hero-actions">
        <button className="secondary dark" onClick={() => onNavigate('reports')}>Live operations</button>
        <button className="primary glow" onClick={onNewScan}>Assess asset</button>
      </div>
    </div>

    <div className="posture-grid">
      <MetricCard title="Exposure posture" value={metrics.exposureScore > 74 ? 'controlled' : metrics.exposureScore > 45 ? 'elevated' : 'critical'} hint={`${metrics.exposureScore}/100 offensive score`} hot />
      <MetricCard title="Surface signals" value={metrics.requests || scans.length} hint="requests and scan signals" />
      <MetricCard title="Attack paths" value={metrics.findings.length} hint="correlated findings" hot />
      <MetricCard title="Scan coverage" value={scans.length} hint={`${metrics.active} active now`} />
    </div>

    <div className="kpi-grid">
      <KpiCard title="Exposure score" value={metrics.exposureScore} hint="authorized surface" />
      <KpiCard title="Tracked assets" value={metrics.hosts} hint={`${metrics.requests} requests`} />
      <KpiCard title="Open findings" value={metrics.findings.length} hint={`${metrics.high} high`} />
      <KpiCard title="Live operations" value={metrics.active} hint="queued or running" />
    </div>

    <div className="dashboard-grid">
      <section className="panel score-panel">
        <PanelTitle title="Organization exposure score" meta={metrics.exposureScore > 74 ? 'controlled' : 'elevated'} />
        <div className="donut-wrap">
          <div className="donut" style={{ '--score': `${metrics.exposureScore * 3.6}deg` }}><strong>{metrics.exposureScore}</strong><span>Exposure</span></div>
        </div>
        <RiskLine label="High severity" value={metrics.high} />
        <RiskLine label="Risk gate failures" value={metrics.failed} />
        <RiskLine label="Total scans" value={scans.length} />
      </section>

      <section className="panel insights-panel">
        <PanelTitle title="Operational insights" meta={metrics.high ? 'elevated' : 'stable'} />
        <div className="insight-grid">
          <Insight text={metrics.high ? 'Prioritize high severity findings before expanding scan coverage.' : 'No high severity findings are currently open.'} />
          <Insight text="Validate ownership before each assessment and keep evidence attached to every finding." />
          <Insight text={metrics.active ? 'A scan is running. Review the result once processing completes.' : 'Start a fresh scan against the highest-risk authorized target.'} />
        </div>
      </section>

      <aside className="triage-panel">
        <p className="eyebrow neon">AI TRIAGE</p>
        <h3>Overview</h3>
        <p>Prioritize exploitable web exposure, identify boundary drift, and hand off clear remediation evidence.</p>
        <dl>
          <dt>Active telemetry</dt><dd>{metrics.active ? 'Live' : 'Idle'}</dd>
          <dt>Exposure policy</dt><dd>Enforced</dd>
          <dt>Scope</dt><dd>Authorized</dd>
        </dl>
      </aside>
    </div>

    <section className="panel latest-panel">
      <PanelTitle title="Recent assessments" meta={`${latest.length} shown`} />
      {latest.map(scan => <button className="scan-row compact" key={scan.id} onClick={() => onOpenScan(scan.id)}>
        <span><strong>{scan.target_host}</strong><small>{scan.target_url}</small></span>
        <Status value={scan.status} />
        <span className="count">{scan.findings?.length || 0}</span>
        <span>{new Date(scan.created_at).toLocaleString()}</span>
      </button>)}
      {!latest.length && <div className="empty tight"><span>+</span><h3>No telemetry yet</h3><p>Run your first authorized assessment to populate the overview.</p><button className="primary" onClick={onNewScan}>Assess first asset</button></div>}
    </section>
  </section>
}

function NewScan({ plugins, onCreated, onCancel }) {
  const [target, setTarget] = useState('https://')
  const [selected, setSelected] = useState(plugins.map(p => p.name))
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const toggle = name => setSelected(value => value.includes(name) ? value.filter(x => x !== name) : [...value, name])

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      onCreated(await api('/scans', {
        method: 'POST',
        body: JSON.stringify({ target_url: target, authorization_confirmed: confirmed, enabled_plugins: selected }),
      }))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return <section className="content">
    <button className="back" onClick={onCancel}>Back to scans</button>
    <div className="page-head">
      <div><p className="eyebrow neon">NEW ASSESSMENT</p><h1>Scan a web target</h1></div>
    </div>
    <form className="scan-form" onSubmit={submit}>
      <label className="target-label">Target URL<input type="url" required value={target} onChange={e => setTarget(e.target.value)} placeholder="https://example.com/?q=test" /></label>
      <div>
        <h3>Checks</h3>
        <p className="muted">Active checks use harmless, tightly bounded query mutations.</p>
        <div className="plugin-grid">{plugins.map(plugin => <label className={`plugin ${selected.includes(plugin.name) ? 'selected' : ''}`} key={plugin.name}>
          <input type="checkbox" checked={selected.includes(plugin.name)} onChange={() => toggle(plugin.name)} />
          <span><strong>{plugin.name.replaceAll('_', ' ')}</strong><small>{plugin.description}</small></span>
          {plugin.active && <em>ACTIVE</em>}
        </label>)}</div>
      </div>
      <label className="consent"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} /><span>I own this target or have explicit permission to test it.</span></label>
      {error && <p className="error">{error}</p>}
      <button className="primary wide" disabled={busy || !confirmed || !selected.length}>{busy ? 'Validating target...' : 'Start authorized scan'}</button>
    </form>
  </section>
}

function ScanDetail({ scan, onBack }) {
  const findings = [...(scan.findings || [])].sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity])
  return <section className="content">
    <button className="back" onClick={onBack}>Scan history</button>
    <div className="page-head">
      <div><p className="eyebrow neon">SCAN RESULT</p><h1>{scan.target_host}</h1><p className="muted url">{scan.target_url}</p></div>
      <div className="actions"><Status value={scan.status} /><button className="secondary dark" disabled={scan.status !== 'completed'} onClick={() => downloadReport(scan.id)}>Download report</button></div>
    </div>
    <ScanStats scan={scan} />
    {scan.error_message && <p className="notice">{scan.error_message}</p>}
    <h2>Findings</h2>
    <FindingList findings={findings} emptyTitle="No findings from enabled checks" emptyText="This does not guarantee the target is vulnerability-free." />
  </section>
}

function ScanHistory({ scans, error, query, onNewScan, onOpenScan }) {
  const filtered = filterScans(scans, query)
  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">SECURITY OVERVIEW</p><h1>Scan history</h1><p className="muted">Recent authorized assessments and findings.</p></div>
      <button className="primary glow" onClick={onNewScan}>New scan</button>
    </div>
    {error && <p className="error">{error}</p>}
    <div className="scan-list">
      <div className="scan-row header"><span>Target</span><span>Status</span><span>Findings</span><span>Created</span></div>
      {filtered.map(scan => <button className="scan-row" key={scan.id} onClick={() => onOpenScan(scan.id)}>
        <span><strong>{scan.target_host}</strong><small>{scan.target_url}</small></span>
        <Status value={scan.status} />
        <span className="count">{scan.findings?.length || 0}</span>
        <span>{new Date(scan.created_at).toLocaleString()}</span>
      </button>)}
    </div>
    {!filtered.length && <div className="empty"><span>+</span><h3>No scans found</h3><p>Run a focused assessment or adjust the search term.</p><button className="primary" onClick={onNewScan}>Create scan</button></div>}
  </section>
}

function FindingsPage({ scans, query, onOpenScan }) {
  const findings = scans.flatMap(scan => (scan.findings || []).map(finding => ({ ...finding, scan })))
    .filter(finding => matchesQuery([finding.title, finding.description, finding.plugin, finding.scan.target_host, finding.severity], query))
    .sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity])

  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">FINDING CENTER</p><h1>Findings</h1><p className="muted">All saved findings across completed scans.</p></div>
    </div>
    <FindingList findings={findings} renderMeta={finding => <button className="mini-link" onClick={() => onOpenScan(finding.scan.id)}>{finding.scan.target_host}</button>} emptyTitle="No findings yet" emptyText="Completed scans with detected issues will appear here." />
  </section>
}

function ReportsPage({ scans, query }) {
  const completed = filterScans(scans, query).filter(scan => scan.status === 'completed')
  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">EVIDENCE EXPORTS</p><h1>Reports</h1><p className="muted">Download HTML reports for completed authorized scans.</p></div>
    </div>
    <div className="report-grid">
      {completed.map(scan => <article className="report-card" key={scan.id}>
        <div><Status value={scan.status} /><h3>{scan.target_host}</h3><p className="url">{scan.target_url}</p></div>
        <div className="report-meta"><span>{scan.findings?.length || 0} findings</span><span>{new Date(scan.created_at).toLocaleString()}</span></div>
        <button className="secondary dark" onClick={() => downloadReport(scan.id)}>Download HTML</button>
      </article>)}
    </div>
    {!completed.length && <div className="empty"><span>R</span><h3>No reports ready</h3><p>Reports become available after a scan completes.</p></div>}
  </section>
}

function FindingList({ findings, renderMeta, emptyTitle, emptyText }) {
  return <div className="findings">
    {findings.map(f => <article className="finding" key={`${f.id}-${f.scan?.id || ''}`}>
      <div className="finding-top"><Severity value={f.severity} /><span>{f.plugin.replaceAll('_', ' ')}</span><span>{f.confidence} confidence</span>{renderMeta?.(f)}</div>
      <h3>{f.title}</h3>
      <p>{f.description}</p>
      <dl><dt>Evidence</dt><dd>{f.evidence}</dd><dt>Remediation</dt><dd>{f.remediation}</dd></dl>
    </article>)}
    {!findings.length && <div className="empty"><span>OK</span><h3>{emptyTitle}</h3><p>{emptyText}</p></div>}
  </div>
}

function ScanStats({ scan }) {
  const findings = scan.findings || []
  return <div className="stats">
    <Stat value={findings.length} label="Findings" />
    <Stat value={findings.filter(f => ['critical', 'high'].includes(f.severity)).length} label="High risk" />
    <Stat value={scan.request_count} label="Requests" />
    <Stat value={scan.enabled_plugins.length} label="Checks" />
  </div>
}

function Dashboard({ user, onLogout }) {
  const [scans, setScans] = useState([])
  const [plugins, setPlugins] = useState([])
  const [page, setPage] = useState('overview')
  const [selectedId, setSelectedId] = useState(null)
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [scanData, pluginData] = await Promise.all([api('/scans'), api('/scans/plugins')])
      setScans(scanData)
      setPlugins(pluginData)
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => { const timer = setTimeout(load, 0); return () => clearTimeout(timer) }, [load])
  useEffect(() => {
    if (!scans.some(s => ['queued', 'running'].includes(s.status))) return undefined
    const timer = setInterval(load, 2500)
    return () => clearInterval(timer)
  }, [scans, load])

  const metrics = useMemo(() => buildMetrics(scans), [scans])
  const selected = useMemo(() => scans.find(s => s.id === selectedId), [scans, selectedId])
  const openScan = id => { setSelectedId(id); setPage('detail') }
  const goNewScan = () => setPage('new')
  const activePage = page === 'detail' || page === 'new' ? 'scans' : page

  let content
  if (page === 'new') content = <NewScan plugins={plugins} onCancel={() => setPage('scans')} onCreated={scan => { setScans([scan, ...scans]); setSelectedId(scan.id); setPage('detail') }} />
  else if (page === 'detail' && selected) content = <ScanDetail scan={selected} onBack={() => setPage('scans')} />
  else if (page === 'scans') content = <ScanHistory scans={scans} query={query} error={error} onNewScan={goNewScan} onOpenScan={openScan} />
  else if (page === 'findings') content = <FindingsPage scans={scans} query={query} onOpenScan={openScan} />
  else if (page === 'reports') content = <ReportsPage scans={scans} query={query} />
  else content = <OverviewPage scans={scans} metrics={metrics} onNewScan={goNewScan} onNavigate={setPage} onOpenScan={openScan} />

  return <Shell user={user} activePage={activePage} query={query} onQuery={setQuery} onNavigate={setPage} onNewScan={goNewScan} onLogout={onLogout}>{content}</Shell>
}

function Shell({ user, activePage, query, onQuery, onNavigate, onNewScan, onLogout, children }) {
  const navItems = [
    { id: 'overview', label: 'Executive', icon: 'E' },
    { id: 'scans', label: 'Scans', icon: 'S' },
    { id: 'findings', label: 'Findings', icon: 'F' },
    { id: 'reports', label: 'Reports', icon: 'R' },
  ]

  return <div className="app-shell">
    <aside>
      <Logo />
      <nav aria-label="Main navigation">
        {navItems.map(item => <button type="button" className={activePage === item.id ? 'active' : ''} key={item.id} onClick={() => onNavigate(item.id)}>
          <span>{item.icon}</span><b>{item.label}</b>
        </button>)}
      </nav>
      <div className="edition">CYBERPUNK EDITION</div>
      <div className="user">
        <span>{(user.display_name || user.email)[0].toUpperCase()}</span>
        <div><strong>{user.display_name || 'Security analyst'}</strong><small>{user.email}</small></div>
        <button onClick={onLogout} title="Sign out">Out</button>
      </div>
    </aside>
    <main>
      <header className="topbar">
        <div className="workspace"><span>WORKSPACE</span><strong>AegisScan / Global Exposure</strong></div>
        <label className="command"><span>Search</span><input value={query} onChange={event => onQuery(event.target.value)} placeholder="Add domain, API, or internet-facing asset" /></label>
        <div className="top-actions">
          <button className="primary glow" onClick={onNewScan}>Assess Asset</button>
          <button className="secondary dark" onClick={() => onNavigate('findings')}>Analyze Exposure</button>
          <button className="secondary dark" onClick={() => onNavigate('reports')}>Start Monitoring</button>
        </div>
      </header>
      {children}
    </main>
  </div>
}

function MetricCard({ title, value, hint, hot }) {
  return <article className={`metric-card ${hot ? 'hot' : ''}`}><span>{title}</span><strong>{value}</strong><small>{hint}</small></article>
}
function KpiCard({ title, value, hint }) {
  return <article className="kpi-card"><span>{title}</span><strong>{value}</strong><small>{hint}</small></article>
}
function PanelTitle({ title, meta }) {
  return <div className="panel-title"><h3>{title}</h3><span>{meta}</span></div>
}
function RiskLine({ label, value }) {
  return <div className="risk-line"><span>{label}</span><strong>{value}</strong></div>
}
function Insight({ text }) {
  return <article className="insight"><span>Insight</span><strong>{text}</strong></article>
}
function Status({ value }) { return <span className={`status ${value}`}>{['queued', 'running'].includes(value) && <i />}{value}</span> }
function Severity({ value }) { return <span className={`severity ${value}`}>{value}</span> }
function Stat({ value, label }) { return <div><strong>{value}</strong><span>{label}</span></div> }

function matchesQuery(values, query) {
  const normalized = query.trim().toLowerCase()
  if (!normalized) return true
  return values.some(value => String(value || '').toLowerCase().includes(normalized))
}
function filterScans(scans, query) {
  return scans.filter(scan => matchesQuery([scan.target_host, scan.target_url, scan.status], query))
}

export default function App() {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  useEffect(() => { api('/auth/me').then(setUser).catch(() => {}).finally(() => setReady(true)) }, [])

  async function logout() {
    try {
      await api('/auth/logout', { method: 'POST' })
    } finally {
      setToken(null)
      setUser(null)
    }
  }

  if (!ready) return <div className="loading"><Logo /><span /></div>
  return user ? <Dashboard user={user} onLogout={logout} /> : <Auth onAuthenticated={setUser} />
}
