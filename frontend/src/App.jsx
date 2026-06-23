import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  api, downloadReport, setToken,
  getAssets, createAsset, discoverAsset, getSubdomains, getCertificates,
  getSchedules, createSchedule, getAlerts, acknowledgeAlert,
  getGraph, getAttackPaths,
  getRiskDashboard, getRiskScore
} from './api'
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
  const [aiReport, setAiReport] = useState(null)
  const [loadingAi, setLoadingAi] = useState(false)

  async function getAiAnalysis() {
    setLoadingAi(true)
    try {
      const result = await api(`/ai/analyze/${scan.id}`, { method: 'POST' })
      setAiReport(result)
    } catch (e) {
      console.error(e)
    } finally {
      setLoadingAi(false)
    }
  }

  return <section className="content">
    <button className="back" onClick={onBack}>Scan history</button>
    <div className="page-head">
      <div><p className="eyebrow neon">SCAN RESULT</p><h1>{scan.target_host}</h1><p className="muted url">{scan.target_url}</p></div>
      <div className="actions">
        <Status value={scan.status} />
        <button className="secondary dark" disabled={scan.status !== 'completed'} onClick={() => downloadReport(scan.id)}>Download report</button>
        <button className="primary glow" disabled={scan.status !== 'completed'} onClick={getAiAnalysis}>
          {loadingAi ? 'Analyzing...' : 'Gemini AI Triage'}
        </button>
      </div>
    </div>
    <ScanStats scan={scan} />
    {scan.error_message && <p className="notice">{scan.error_message}</p>}
    
    {aiReport && (
      <div className="panel ai-report-container" style={{ marginTop: '20px', padding: '20px' }}>
        <h3>Gemini AI Risk Prioritization Insights</h3>
        <p className="ai-text" style={{ whiteSpace: 'pre-line', color: 'var(--neon-blue)' }}>{aiReport.insights}</p>
        <h4 style={{ marginTop: '15px' }}>Prioritized Remediation Checklist</h4>
        <ul className="remediation-list">
          {aiReport.remediation_plan?.map((item, idx) => (
            <li key={idx} style={{ marginBottom: '10px' }}>
              <strong>{item.title} ({item.severity})</strong> - Score: {item.priority_score}<br />
              <span className="muted">{item.action}</span>
            </li>
          ))}
        </ul>
      </div>
    )}

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

function AssetsPage() {
  const [assets, setAssets] = useState([])
  const [newDomain, setNewDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [activeAsset, setActiveAsset] = useState(null)
  const [subdomains, setSubdomains] = useState([])
  const [certs, setCerts] = useState([])

  const loadAssets = useCallback(async () => {
    try {
      const data = await getAssets()
      setAssets(data)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => { loadAssets() }, [loadAssets])

  async function register(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await createAsset(newDomain)
      setNewDomain('')
      loadAssets()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function runDiscovery(id) {
    setBusy(true)
    try {
      await discoverAsset(id)
      loadAssets()
      if (activeAsset?.id === id) {
        selectAsset(activeAsset)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function selectAsset(asset) {
    setActiveAsset(asset)
    setSubdomains([])
    setCerts([])
    try {
      const [subs, certificates] = await Promise.all([
        getSubdomains(asset.id),
        getCertificates(asset.id)
      ])
      setSubdomains(subs)
      setCerts(certificates)
    } catch (err) {
      console.error(err)
    }
  }

  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">ASM INVENTORY</p><h1>Attack Surface Assets</h1></div>
    </div>
    {error && <p className="error">{error}</p>}
    <form className="scan-form" onSubmit={register} style={{ marginBottom: '20px' }}>
      <label className="target-label">
        Register Root Domain
        <input type="text" required value={newDomain} onChange={e => setNewDomain(e.target.value)} placeholder="example.com" />
      </label>
      <button className="primary" disabled={busy} style={{ marginTop: '10px' }}>
        {busy ? 'Processing...' : 'Register Asset'}
      </button>
    </form>

    <div className="dashboard-grid">
      <div className="panel" style={{ flex: 1 }}>
        <h3>Registered Domains</h3>
        <div className="scan-list">
          {assets.map(asset => (
            <div className={`scan-row compact ${activeAsset?.id === asset.id ? 'active' : ''}`} key={asset.id} style={{ cursor: 'pointer', padding: '12px' }} onClick={() => selectAsset(asset)}>
              <span><strong>{asset.domain}</strong><small>{asset.status}</small></span>
              <span>Score: {asset.exposure_score}</span>
              <button className="primary mini-link" onClick={(e) => { e.stopPropagation(); runDiscovery(asset.id) }}>
                Discover
              </button>
            </div>
          ))}
          {!assets.length && <p className="muted">No domains registered.</p>}
        </div>
      </div>

      {activeAsset && (
        <div className="panel" style={{ flex: 1 }}>
          <h3>Asset details: {activeAsset.domain}</h3>
          <p className="muted">Discovered Subdomains and certificates.</p>
          
          <h4 style={{ marginTop: '15px' }}>Subdomains ({subdomains.length})</h4>
          <ul className="remediation-list">
            {subdomains.map(sub => (
              <li key={sub.id} style={{ marginBottom: '8px' }}>
                <strong>{sub.hostname}</strong> - IPs: {sub.ip_addresses?.join(', ') || 'None'}
                {sub.services?.length > 0 && (
                  <div style={{ marginLeft: '10px', fontSize: '0.85em', color: 'var(--neon-blue)' }}>
                    Ports: {sub.services.map(s => `${s.port}/${s.protocol}`).join(', ')}
                  </div>
                )}
              </li>
            ))}
          </ul>

          <h4 style={{ marginTop: '15px' }}>Active SSL Certificates ({certs.length})</h4>
          <ul className="remediation-list">
            {certs.map(c => (
              <li key={c.id} style={{ marginBottom: '8px', fontSize: '0.9em' }}>
                <strong>Subject:</strong> {c.subject}<br />
                <strong>Issuer:</strong> {c.issuer}<br />
                <span className="muted">Expires: {new Date(c.not_after).toLocaleDateString()}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  </section>
}

function MonitoringPage() {
  const [schedules, setSchedules] = useState([])
  const [alerts, setAlerts] = useState([])
  const [assets, setAssets] = useState([])
  const [assetId, setAssetId] = useState('')
  const [frequency, setFrequency] = useState('daily')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const loadData = useCallback(async () => {
    try {
      const [scheds, alrts, asts] = await Promise.all([
        getSchedules(),
        getAlerts(),
        getAssets()
      ])
      setSchedules(scheds)
      setAlerts(alrts)
      setAssets(asts)
      if (asts.length > 0 && !assetId) setAssetId(asts[0].id)
    } catch (e) {
      setError(e.message)
    }
  }, [assetId])

  useEffect(() => { loadData() }, [loadData])

  async function create(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await createSchedule(assetId, frequency)
      loadData()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function ack(id) {
    try {
      await acknowledgeAlert(id)
      loadData()
    } catch (err) {
      console.error(err)
    }
  }

  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">CONTINUOUS SECURITY VALIDATION</p><h1>Monitoring Schedules & Alerts</h1></div>
    </div>
    {error && <p className="error">{error}</p>}
    <form className="scan-form" onSubmit={create} style={{ marginBottom: '20px' }}>
      <label className="target-label">
        Select Asset Domain
        <select value={assetId} onChange={e => setAssetId(e.target.value)}>
          {assets.map(a => <option value={a.id} key={a.id}>{a.domain}</option>)}
        </select>
      </label>
      <label className="target-label" style={{ marginTop: '10px' }}>
        Frequency
        <select value={frequency} onChange={e => setFrequency(e.target.value)}>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </label>
      <button className="primary" disabled={busy || !assetId} style={{ marginTop: '15px' }}>
        Configure Monitor
      </button>
    </form>

    <div className="dashboard-grid">
      <div className="panel" style={{ flex: 1 }}>
        <h3>Active Schedules</h3>
        <div className="scan-list">
          {schedules.map(s => (
            <div className="scan-row compact" key={s.id}>
              <span><strong>Asset ID: {s.asset_id.slice(0, 8)}...</strong><small>Interval: {s.frequency}</small></span>
              <span>Enabled: {s.enabled ? 'Yes' : 'No'}</span>
            </div>
          ))}
          {!schedules.length && <p className="muted">No monitoring configured.</p>}
        </div>
      </div>

      <div className="panel" style={{ flex: 1 }}>
        <h3>Security Alerts</h3>
        <div className="scan-list">
          {alerts.map(a => (
            <div className="scan-row compact" key={a.id} style={{ borderColor: a.acknowledged ? 'var(--dark-fill)' : 'var(--neon-pink)' }}>
              <span>
                <strong>{a.alert_type} ({a.severity})</strong><br />
                <small>{a.message}</small>
              </span>
              {!a.acknowledged && (
                <button className="primary mini-link" onClick={() => ack(a.id)}>
                  Acknowledge
                </button>
              )}
            </div>
          ))}
          {!alerts.length && <p className="muted">No alerts raised.</p>}
        </div>
      </div>
    </div>
  </section>
}

function GraphPage() {
  const [assets, setAssets] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [graphData, setGraphData] = useState(null)
  const [attackPaths, setAttackPaths] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    getAssets().then(data => {
      setAssets(data)
      if (data.length > 0) {
        setSelectedId(data[0].id)
      }
    }).catch(e => setError(e.message))
  }, [])

  async function loadGraph() {
    if (!selectedId) return
    try {
      const [graph, paths] = await Promise.all([
        getGraph(selectedId),
        getAttackPaths(selectedId)
      ])
      setGraphData(graph)
      setAttackPaths(paths.attack_paths || [])
    } catch (e) {
      setError(e.message)
    }
  }

  // Generate simple circular SVG positions for the graph nodes
  const renderedNodes = useMemo(() => {
    if (!graphData || !graphData.nodes) return []
    const nodes = graphData.nodes
    const center = { x: 300, y: 300 }
    
    return nodes.map((node, index) => {
      if (node.type === 'asset') {
        return { ...node, x: center.x, y: center.y }
      }
      // Distribute other nodes in circular layers depending on type
      let radius = 100
      if (node.type === 'subdomain') radius = 100
      if (node.type === 'service') radius = 180
      if (node.type === 'finding') radius = 240
      
      const angle = (index * 2 * Math.PI) / (nodes.length - 1 || 1)
      return {
        ...node,
        x: center.x + radius * Math.cos(angle),
        y: center.y + radius * Math.sin(angle)
      }
    })
  }, [graphData])

  const nodeMap = useMemo(() => {
    return new Map(renderedNodes.map(n => [n.id, n]))
  }, [renderedNodes])

  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">VISUAL EXPOSURE GRAPH</p><h1>Attack Surface Relationships</h1></div>
    </div>
    {error && <p className="error">{error}</p>}
    <div className="scan-form" style={{ marginBottom: '20px', display: 'flex', gap: '15px', alignItems: 'center' }}>
      <select value={selectedId} onChange={e => setSelectedId(e.target.value)}>
        <option value="">Select Asset...</option>
        {assets.map(a => <option value={a.id} key={a.id}>{a.domain}</option>)}
      </select>
      <button className="primary" onClick={loadGraph} disabled={!selectedId}>
        Render Graph
      </button>
    </div>

    <div className="dashboard-grid" style={{ alignItems: 'flex-start' }}>
      {graphData && (
        <div className="panel" style={{ flex: 2, display: 'flex', justifyContent: 'center', background: 'var(--panel-bg)' }}>
          <svg width="600" height="600" style={{ border: '1px solid var(--neon-blue)', borderRadius: '8px' }}>
            {/* Draw Edges */}
            {graphData.edges?.map((edge, idx) => {
              const src = nodeMap.get(edge.source)
              const tgt = nodeMap.get(edge.target)
              if (!src || !tgt) return null
              return (
                <line
                  key={idx}
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={edge.relationship === 'has_finding' ? 'var(--neon-pink)' : 'var(--dark-fill)'}
                  strokeWidth="2"
                />
              )
            })}
            
            {/* Draw Nodes */}
            {renderedNodes.map(node => (
              <g key={node.id}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.type === 'asset' ? 14 : node.type === 'finding' ? 10 : 8}
                  fill={node.type === 'asset' ? 'var(--neon-cyan)' : node.type === 'finding' ? 'var(--neon-pink)' : 'var(--neon-blue)'}
                />
                <text
                  x={node.x + 12}
                  y={node.y + 4}
                  fill="#ffffff"
                  fontSize="10"
                  fontWeight="bold"
                >
                  {node.label}
                </text>
              </g>
            ))}
          </svg>
        </div>
      )}

      {attackPaths.length > 0 && (
        <div className="panel" style={{ flex: 1 }}>
          <h3>Critical Attack Chains</h3>
          <p className="muted">Traced paths from root host to exposed findings.</p>
          <div className="scan-list">
            {attackPaths.map((path, idx) => (
              <div className="scan-row compact" key={idx} style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                <strong style={{ color: 'var(--neon-pink)' }}>Chain Criticality: {path.criticality_score}</strong>
                <span style={{ fontSize: '0.85em', marginTop: '5px' }}>
                  {path.chain.map(c => c.label).join(' ➔ ')}
                </span>
                <p style={{ fontSize: '0.8em', color: '#aaaaaa', marginTop: '3px' }}>{path.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  </section>
}

function RiskPage() {
  const [dashboard, setDashboard] = useState(null)
  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [assets, setAssets] = useState([])
  const [aiReport, setAiReport] = useState(null)
  const [loadingAi, setLoadingAi] = useState(false)
  const [error, setError] = useState('')

  const loadData = useCallback(async () => {
    try {
      const [dash, asts] = await Promise.all([
        getRiskDashboard(),
        getAssets()
      ])
      setDashboard(dash)
      setAssets(asts)
      if (asts.length > 0 && !selectedAssetId) setSelectedAssetId(asts[0].id)
    } catch (e) {
      setError(e.message)
    }
  }, [selectedAssetId])

  useEffect(() => { loadData() }, [loadData])

  async function fetchSummary() {
    if (!selectedAssetId) return
    setLoadingAi(true)
    try {
      const result = await api(`/ai/summary/${selectedAssetId}`)
      setAiReport(result)
    } catch (e) {
      console.error(e)
    } finally {
      setLoadingAi(false)
    }
  }

  return <section className="content">
    <div className="page-head">
      <div><p className="eyebrow neon">EXPOSURE INTELLIGENCE</p><h1>Exposure Scoring Dashboard</h1></div>
    </div>
    {error && <p className="error">{error}</p>}

    {dashboard && (
      <>
        <div className="posture-grid">
          <MetricCard title="Average Exposure Score" value={`${dashboard.average_exposure_score}/100`} hint="organization-wide" hot />
          <MetricCard title="Critical Assets" value={dashboard.assets_at_risk?.critical || 0} hint="Score >= 75" hot />
          <MetricCard title="High Risk Assets" value={dashboard.assets_at_risk?.high || 0} hint="Score >= 50" />
          <MetricCard title="Total Monitored" value={dashboard.total_assets || 0} hint="registered domains" />
        </div>

        <div className="dashboard-grid" style={{ marginTop: '20px' }}>
          <div className="panel" style={{ flex: 1 }}>
            <h3>Defensive Prioritization (Gemini Assistant)</h3>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
              <select value={selectedAssetId} onChange={e => setSelectedAssetId(e.target.value)}>
                {assets.map(a => <option value={a.id} key={a.id}>{a.domain}</option>)}
              </select>
              <button className="primary" onClick={fetchSummary} disabled={!selectedAssetId || loadingAi}>
                {loadingAi ? 'Generating Summary...' : 'Get AI Summary'}
              </button>
            </div>
            {aiReport && (
              <div className="notice" style={{ padding: '15px', borderRadius: '4px', whiteSpace: 'pre-line' }}>
                <strong>AI Executive Risk Summary:</strong><br />
                {aiReport.summary}
              </div>
            )}
          </div>

          <div className="panel" style={{ flex: 1 }}>
            <h3>Top Actionable Remediation Checklist</h3>
            <ul className="remediation-list">
              {dashboard.top_findings?.map((f, idx) => (
                <li key={idx} style={{ borderLeft: '3px solid var(--neon-pink)', paddingLeft: '10px', marginBottom: '12px' }}>
                  <strong>{f.priority_label}</strong> - {f.title}<br />
                  <span className="muted" style={{ fontSize: '0.85em' }}>URL: {f.url}</span><br />
                  <span className="muted" style={{ fontSize: '0.85em' }}>Remediation: {f.priority_score >= 80 ? 'Patch instantly' : 'Resolve in next sprint cycle'}</span>
                </li>
              ))}
              {!dashboard.top_findings?.length && <p className="muted">No open findings to prioritize.</p>}
            </ul>
          </div>
        </div>
      </>
    )}
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
  const activePage = ['detail', 'new'].includes(page) ? 'scans' : page

  let content
  if (page === 'new') content = <NewScan plugins={plugins} onCancel={() => setPage('scans')} onCreated={scan => { setScans([scan, ...scans]); setSelectedId(scan.id); setPage('detail') }} />
  else if (page === 'detail' && selected) content = <ScanDetail scan={selected} onBack={() => setPage('scans')} />
  else if (page === 'scans') content = <ScanHistory scans={scans} query={query} error={error} onNewScan={goNewScan} onOpenScan={openScan} />
  else if (page === 'findings') content = <FindingsPage scans={scans} query={query} onOpenScan={openScan} />
  else if (page === 'reports') content = <ReportsPage scans={scans} query={query} />
  else if (page === 'assets') content = <AssetsPage />
  else if (page === 'monitoring') content = <MonitoringPage />
  else if (page === 'graph') content = <GraphPage />
  else if (page === 'risk') content = <RiskPage />
  else content = <OverviewPage scans={scans} metrics={metrics} onNewScan={goNewScan} onNavigate={setPage} onOpenScan={openScan} />

  return <Shell user={user} activePage={activePage} query={query} onQuery={setQuery} onNavigate={setPage} onNewScan={goNewScan} onLogout={onLogout}>{content}</Shell>
}

function Shell({ user, activePage, query, onQuery, onNavigate, onNewScan, onLogout, children }) {
  const navItems = [
    { id: 'overview', label: 'Executive', icon: 'E' },
    { id: 'scans', label: 'Scans', icon: 'S' },
    { id: 'findings', label: 'Findings', icon: 'F' },
    { id: 'reports', label: 'Reports', icon: 'R' },
    { id: 'assets', label: 'Assets', icon: 'A' },
    { id: 'monitoring', label: 'Monitoring', icon: 'M' },
    { id: 'graph', label: 'Graph', icon: 'G' },
    { id: 'risk', label: 'Risk', icon: 'K' },
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
