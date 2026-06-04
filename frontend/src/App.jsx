import { useState, useEffect, useRef } from 'react'
import './App.css'

// ─── Stage metadata for the progress bar ────────────────────────────────────
const STAGES = [
  {
    key: 'validating',
    label: 'Validating URL',
    detail: 'Checking the URL format, stripping tracking parameters, and normalising the address.',
    icon: '🔍',
  },
  {
    key: 'safe_browsing',
    label: 'Google Safe Browsing',
    detail: 'Querying Google\'s database of millions of known malware, phishing and scam sites.',
    icon: '🛡️',
  },
  {
    key: 'structure',
    label: 'Structure Analysis',
    detail: 'Inspecting the URL for IP-based hosts, suspicious domain extensions, and typosquatting patterns.',
    icon: '🧩',
  },
  {
    key: 'domain_age',
    label: 'Domain Age Check',
    detail: 'Looking up WHOIS records to see how old the domain is — newly registered domains are much riskier.',
    icon: '📅',
  },
  {
    key: 'redirect',
    label: 'Redirect Chain',
    detail: 'Following any redirects to find where the link actually leads, and flagging suspicious hops or shorteners.',
    icon: '🔀',
  },
  {
    key: 'sandbox',
    label: 'Sandbox Preview',
    detail: 'Fetching the page content — without running any JavaScript — and scanning for phishing forms, hidden iframes, and obfuscated scripts.',
    icon: '🧪',
  },
]

// Map backend stage strings to our stage keys
function stageKeyFromLabel(label) {
  if (!label) return null
  const l = label.toLowerCase()
  if (l.includes('validat')) return 'validating'
  if (l.includes('safe browsing') || l.includes('google')) return 'safe_browsing'
  if (l.includes('structure')) return 'structure'
  if (l.includes('domain age') || l.includes('whois')) return 'domain_age'
  if (l.includes('redirect')) return 'redirect'
  if (l.includes('sandbox') || l.includes('preview')) return 'sandbox'
  return null
}

// ─── Progress Bar Component ──────────────────────────────────────────────────
function ProgressBar({ currentStageLabel }) {
  const activeKey = stageKeyFromLabel(currentStageLabel)
  const activeIndex = activeKey ? STAGES.findIndex(s => s.key === activeKey) : -1
  const activeStage = activeIndex >= 0 ? STAGES[activeIndex] : null
  const pct = activeIndex >= 0 ? Math.round(((activeIndex + 1) / STAGES.length) * 100) : 5

  return (
    <div className="progress-wrap">
      <div className="progress-header">
        <span className="progress-stage-name">
          {activeStage ? `${activeStage.icon} ${activeStage.label}` : '⏳ Starting…'}
        </span>
        <span className="progress-pct">{pct}%</span>
      </div>
      {activeStage && (
        <p className="progress-stage-detail">{activeStage.detail}</p>
      )}
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="progress-steps">
        {STAGES.map((s, i) => {
          const done = i < activeIndex
          const active = i === activeIndex
          return (
            <div
              key={s.key}
              className={`progress-step ${done ? 'done' : ''} ${active ? 'active' : ''}`}
              title={s.label}
            >
              <div className="step-dot">{done ? '✓' : active ? s.icon : ''}</div>
              <span className="step-label">{s.label}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Risk Score Gauge ────────────────────────────────────────────────────────
function RiskGauge({ score }) {
  const color = score >= 60 ? '#e53e3e' : score >= 30 ? '#dd6b20' : '#38a169'
  const label = score >= 60 ? 'High Risk' : score >= 30 ? 'Medium Risk' : 'Low Risk'
  const r = 38, cx = 48, cy = 48
  const circ = Math.PI * r // half-circle
  const filled = circ * (score / 100)

  return (
    <div className="risk-gauge">
      <svg viewBox="0 0 96 56" width="120">
        {/* Track */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke="#e2e8f0" strokeWidth="10" strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${filled} ${circ}`}
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
      </svg>
      <div className="gauge-label">
        <span className="gauge-score" style={{ color }}>{score}</span>
        <span className="gauge-sub">{label}</span>
      </div>
    </div>
  )
}

// ─── Verdict Badge ───────────────────────────────────────────────────────────
function VerdictBadge({ verdict }) {
  const map = {
    UNSAFE:   { color: 'badge-unsafe',   icon: '🚨', text: 'Unsafe' },
    SAFE:     { color: 'badge-safe',     icon: '✅', text: 'Safe' },
    UNSURE:   { color: 'badge-unsure',   icon: '⚠️', text: 'Caution' },
  }
  const b = map[verdict] || map.UNSURE
  return <span className={`verdict-badge ${b.color}`}>{b.icon} {b.text}</span>
}

// ─── Collapsible Section ─────────────────────────────────────────────────────
function Section({ title, icon, flagged, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className={`section ${flagged ? 'section-flagged' : ''}`}>
      <button className="section-header" onClick={() => setOpen(o => !o)}>
        <span className="section-icon">{icon}</span>
        <span className="section-title">{title}</span>
        {flagged && <span className="section-flag">⚠ Issues found</span>}
        <span className="section-chevron">{open ? '▲' : '▼'}</span>
      </button>
      {open && <div className="section-body">{children}</div>}
    </div>
  )
}

// ─── Finding Row ─────────────────────────────────────────────────────────────
function Finding({ f }) {
  return (
    <div className={`finding ${f.flagged ? 'finding-bad' : 'finding-ok'}`}>
      <span className="finding-icon">{f.flagged ? '🔴' : '🟢'}</span>
      <p className="finding-text">{f.explanation}</p>
    </div>
  )
}

// ─── Shortened URL Detection Panel ──────────────────────────────────────────
function ShortenerPanel({ redirectAnalysis, inputUrl }) {
  if (!redirectAnalysis) return null
  const isShortener = redirectAnalysis.passedThroughShortener || redirectAnalysis.hops?.some(h => h.isShortener)
  if (!isShortener) return null

  const finalUrl = redirectAnalysis.finalUrl
  return (
    <div className="shortener-panel">
      <div className="shortener-header">🔗 Shortened URL Detected</div>
      <p className="shortener-body">
        This link goes through a URL shortener. Shortened links hide the real destination — we've followed the chain to reveal it.
      </p>
      <div className="shortener-chain">
        <div className="chain-item chain-start">
          <span className="chain-label">Original</span>
          <code>{inputUrl}</code>
        </div>
        <div className="chain-arrow">↓</div>
        {redirectAnalysis.hops?.filter(h => h.isShortener).map((h, i) => (
          <div key={i}>
            <div className="chain-item chain-mid">
              <span className="chain-label">Via shortener</span>
              <code>{h.url}</code>
            </div>
            <div className="chain-arrow">↓</div>
          </div>
        ))}
        <div className="chain-item chain-end">
          <span className="chain-label">Final destination</span>
          <code>{finalUrl || 'Unknown'}</code>
        </div>
      </div>
    </div>
  )
}

// ─── Redirect Chain Hops ─────────────────────────────────────────────────────
function RedirectHops({ hops }) {
  if (!hops || hops.length === 0) return <p className="muted">No redirects followed.</p>
  return (
    <div className="hops">
      {hops.map((hop, i) => (
        <div key={i} className={`hop ${hop.suspicious ? 'hop-suspicious' : ''}`}>
          <span className="hop-num">{i + 1}</span>
          <div className="hop-info">
            <code className="hop-url">{hop.url}</code>
            <div className="hop-meta">
              {hop.statusCode && <span className="tag">{hop.statusCode}</span>}
              {hop.crossOrigin && <span className="tag tag-warn">Cross-origin</span>}
              {hop.isShortener && <span className="tag tag-info">Shortener</span>}
              {hop.schemeDowngrade && <span className="tag tag-bad">HTTPS→HTTP</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Sandbox Details ─────────────────────────────────────────────────────────
function SandboxDetails({ sandbox }) {
  if (!sandbox) return null

  const { available, riskScore, matchedKeywords, fakeLoginForms, suspiciousScripts,
          hiddenIframes, metaRefreshUrls, sslIssues, missingSecHeaders, dataUriAbuses } = sandbox

  if (!available) {
    return (
      <div className="sandbox-unavailable">
        <p>🔒 The page could not be fetched for static analysis — the site may be offline, geo-blocked, or rate-limiting crawlers.</p>
        <p className="muted">This does not mean the URL is safe; it just means automated page inspection wasn't possible.</p>
      </div>
    )
  }

  return (
    <div className="sandbox-details">
      <div className="sandbox-score-row">
        <RiskGauge score={riskScore ?? 0} />
        <div className="sandbox-score-explain">
          <strong>Sandbox Risk Score</strong>
          <p>A 0–100 score based on the passive page analysis. A higher number means more suspicious signals were detected on the page itself.</p>
        </div>
      </div>

      {matchedKeywords?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">🪤 Phishing Keywords Found on Page</p>
          <p className="muted small">These pressure phrases are commonly used to trick visitors into handing over passwords or payment details.</p>
          <div className="keyword-chips">
            {matchedKeywords.map((kw, i) => <span key={i} className="chip chip-bad">{kw}</span>)}
          </div>
        </div>
      )}

      {fakeLoginForms?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">🎣 Suspicious Login Forms Detected</p>
          <p className="muted small">The page contains form fields that collect credentials but submit to an unusual location — a classic phishing pattern.</p>
          {fakeLoginForms.map((f, i) => (
            <div key={i} className="code-block">
              <span className="tag tag-bad">Action: {f.action || 'unknown'}</span>
              {f.hasPasswordField && <span className="tag tag-bad">Password field</span>}
            </div>
          ))}
        </div>
      )}

      {suspiciousScripts?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">⚠️ Suspicious Scripts Found</p>
          <p className="muted small">Scripts matching known obfuscation or data-exfiltration patterns were found. This could be used to steal cookies, keystrokes, or form data.</p>
          {suspiciousScripts.map((s, i) => (
            <div key={i} className="code-block">
              <code>{s.pattern || s.src || JSON.stringify(s)}</code>
            </div>
          ))}
        </div>
      )}

      {hiddenIframes?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">🕳️ Hidden Iframes</p>
          <p className="muted small">Invisible frames embedded in the page can silently load another website, steal clicks, or run malicious code without your knowledge.</p>
          {hiddenIframes.map((f, i) => <div key={i} className="code-block"><code>{f.src || JSON.stringify(f)}</code></div>)}
        </div>
      )}

      {metaRefreshUrls?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">⏩ Meta-Refresh Redirects</p>
          <p className="muted small">The page will automatically redirect your browser to another site after a short delay — a trick used to bypass link scanners.</p>
          {metaRefreshUrls.map((u, i) => <div key={i} className="code-block"><code>{u}</code></div>)}
        </div>
      )}

      {sslIssues?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">🔓 SSL / Certificate Issues</p>
          <p className="muted small">Problems with the site's HTTPS certificate. This means your connection may not be encrypted or the certificate may have been issued to a different site.</p>
          {sslIssues.map((s, i) => <div key={i} className="finding finding-bad"><span>🔴</span><p>{s.issue}</p></div>)}
        </div>
      )}

      {missingSecHeaders?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">🛡️ Missing Security Headers</p>
          <p className="muted small">Legitimate sites use these HTTP headers to protect visitors. Their absence doesn't mean a site is dangerous, but it's a quality signal.</p>
          <div className="keyword-chips">
            {missingSecHeaders.map((h, i) => <span key={i} className="chip chip-warn">{h}</span>)}
          </div>
        </div>
      )}

      {dataUriAbuses?.length > 0 && (
        <div className="sandbox-group">
          <p className="sandbox-group-title">💣 Data-URI Abuse</p>
          <p className="muted small">Scripts or frames using data: URIs to embed executable code directly in the page — a technique used to evade URL filters.</p>
          {dataUriAbuses.map((d, i) => <div key={i} className="code-block"><code>{d.context || JSON.stringify(d)}</code></div>)}
        </div>
      )}
    </div>
  )
}

// ─── Main Results View ────────────────────────────────────────────────────────
function Results({ result }) {
  const { url, verdict, message, threats, structureAnalysis } = result
  const sa = structureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const sandbox = sa.sandboxPreview || null

  const hasSandboxRisk = sandbox && (
    (sandbox.matchedKeywords?.length > 0) ||
    (sandbox.fakeLoginForms?.length > 0) ||
    (sandbox.suspiciousScripts?.length > 0) ||
    (sandbox.hiddenIframes?.length > 0) ||
    (sandbox.sslIssues?.length > 0)
  )

  return (
    <div className={`results-wrap ${verdict === 'UNSAFE' ? 'result-unsafe' : verdict === 'SAFE' ? 'result-safe' : 'result-unsure'}`}>
      {/* Top summary row */}
      <div className="result-summary">
        <div className="result-url-row">
          <span className="result-url-label">Checked URL</span>
          <code className="result-url">{url}</code>
        </div>
        <div className="result-verdict-row">
          <VerdictBadge verdict={verdict} />
          <p className="result-message">{message}</p>
        </div>
      </div>

      {/* Google threats */}
      {threats?.length > 0 && (
        <div className="threat-list">
          <p className="threat-title">🚨 Google Safe Browsing Threats</p>
          {threats.map((t, i) => (
            <div key={i} className="threat-item">
              <strong>{t.threatType}</strong>
              <span className="muted"> — {t.platformType}</span>
              <p className="muted small">
                {t.threatType === 'MALWARE' && 'This site has been flagged for distributing software that can damage your device or steal data.'}
                {t.threatType === 'SOCIAL_ENGINEERING' && 'This site has been flagged for impersonating trusted brands to trick users into giving up passwords or financial information (phishing).'}
                {t.threatType === 'UNWANTED_SOFTWARE' && 'This site may install unwanted programs without your consent — adware, browser hijackers, or similar.'}
                {!['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'].includes(t.threatType) && 'This URL matches a threat category in Google\'s Safe Browsing database.'}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Shortened URL panel */}
      <ShortenerPanel redirectAnalysis={redirect} inputUrl={url} />

      {/* Collapsible sections */}
      <div className="sections">

        {/* Structure */}
        <Section
          title="URL & Domain Structure"
          icon="🧩"
          flagged={sa.findings?.some(f => f.flagged)}
          defaultOpen={true}
        >
          <div className="meta-grid">
            <div className="meta-item"><span className="meta-key">Host</span><span className="meta-val">{sa.hostname || '—'}</span></div>
            <div className="meta-item"><span className="meta-key">Registered Domain</span><span className="meta-val">{sa.registeredDomainFull || '—'}</span></div>
            <div className="meta-item"><span className="meta-key">TLD</span><span className="meta-val">.{sa.tld || '—'}</span></div>
            <div className="meta-item">
              <span className="meta-key">Domain Age</span>
              <span className="meta-val">
                {sa.domainAge?.available
                  ? `${sa.domainAge.domainAgeDays} days`
                  : 'Could not retrieve'}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-key">New Domain Risk</span>
              <span className={`meta-val ${sa.domainAge?.isNewDomain ? 'val-bad' : 'val-good'}`}>
                {sa.domainAge?.isNewDomain === true ? '⚠ Yes — registered recently' : sa.domainAge?.isNewDomain === false ? '✓ No' : '—'}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-key">IP-Based Host</span>
              <span className={`meta-val ${sa.isIpBased ? 'val-bad' : 'val-good'}`}>
                {sa.isIpBased ? '⚠ Yes' : '✓ No'}
              </span>
            </div>
          </div>
          <div className="findings-list">
            {sa.findings?.map((f, i) => <Finding key={i} f={f} />)}
          </div>
        </Section>

        {/* Redirect Chain */}
        <Section
          title="Redirect Chain"
          icon="🔀"
          flagged={sa.hasRedirectRisk}
        >
          {redirect.tooManyRedirects && (
            <div className="finding finding-bad">
              <span>🔴</span>
              <p>Too many redirects ({redirect.hopCount}). Excessive redirects often indicate cloaking — showing a different page to scanners than to real visitors.</p>
            </div>
          )}
          {redirect.finalUrl && (
            <div className="meta-item" style={{marginBottom:'12px'}}>
              <span className="meta-key">Final Destination</span>
              <code className="meta-val">{redirect.finalUrl}</code>
            </div>
          )}
          {redirect.finalUrlCategories?.length > 0 && (
            <div className="keyword-chips" style={{marginBottom:'12px'}}>
              {redirect.finalUrlCategories.map((c, i) => <span key={i} className="chip chip-info">{c.replace(/_/g,' ')}</span>)}
            </div>
          )}
          <RedirectHops hops={redirect.hops} />
        </Section>

        {/* Sandbox */}
        <Section
          title="Sandbox Page Analysis"
          icon="🧪"
          flagged={hasSandboxRisk}
          defaultOpen={hasSandboxRisk}
        >
          <SandboxDetails sandbox={sandbox} />
        </Section>

      </div>

      <p className="disclaimer">
        ⚠ This tool cannot guarantee that any URL is 100% safe. Threats evolve constantly. Always exercise caution before entering personal information on unfamiliar sites.
      </p>
    </div>
  )
}

// ─── Info Panel ──────────────────────────────────────────────────────────────
function InfoPanel({ onClose }) {
  return (
    <div className="info-overlay" onClick={onClose}>
      <div className="info-modal" onClick={e => e.stopPropagation()}>
        <button className="info-close" onClick={onClose}>✕</button>
        <h2>How ZEB Checks URLs</h2>
        <p className="info-intro">ZEB runs up to six independent checks, from fast database lookups to full passive page analysis. Here's what each one does and why it matters.</p>
        <div className="info-checks">
          {STAGES.map(s => (
            <div key={s.key} className="info-check">
              <span className="info-check-icon">{s.icon}</span>
              <div>
                <strong>{s.label}</strong>
                <p>{s.detail}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="info-shortener">
          <span className="info-check-icon">🔗</span>
          <div>
            <strong>Shortened URL Safety</strong>
            <p>Links from bit.ly, tinyurl.com, t.co and other shorteners hide their true destination. ZEB follows the entire redirect chain to reveal the final URL and analyses it for all the checks above.</p>
          </div>
        </div>
        <p className="info-caveat">No automated tool can guarantee 100% safety. ZEB is one layer of protection — always use your own judgement too.</p>
      </div>
    </div>
  )
}

// ─── App Root ─────────────────────────────────────────────────────────────────
export default function App() {
  const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [showInfo, setShowInfo] = useState(false)
  const [currentStage, setCurrentStage] = useState('')
  const [sessionId, setSessionId] = useState(null)
  const inputRef = useRef(null)

  // Poll for progress
  useEffect(() => {
    if (!sessionId || !loading) return
    const iv = setInterval(async () => {
      try {
        const r = await fetch(`${apiBaseUrl}/api/check-progress/?sessionId=${sessionId}`)
        const d = await r.json()
        if (d.currentStage) setCurrentStage(d.currentStage)
      } catch {}
    }, 350)
    return () => clearInterval(iv)
  }, [sessionId, loading, apiBaseUrl])

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setResult(null)
    setCurrentStage('')

    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please enter a URL to check.')
      inputRef.current?.focus()
      return
    }

    const sid = crypto.randomUUID()
    setSessionId(sid)
    setLoading(true)
    setCurrentStage('Validating URL format...')

    try {
      const res = await fetch(`${apiBaseUrl}/api/check-url/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed, sessionId: sid }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Could not check URL safety. Please try again.')
        return
      }
      setResult(data)
    } catch {
      setError('Network error — could not reach the backend. Check your connection and try again.')
    } finally {
      setLoading(false)
      setCurrentStage('')
    }
  }

  return (
    <div className="page">
      {showInfo && <InfoPanel onClose={() => setShowInfo(false)} />}

      <main className="card">
        {/* Header */}
        <div className="card-header">
          <div className="logo-row">
            <span className="logo-icon">🛡️</span>
            <div>
              <h1>ZEB</h1>
              <p className="tagline">URL Safety Checker</p>
            </div>
          </div>
          <button
            className="info-btn"
            onClick={() => setShowInfo(true)}
            aria-label="How it works"
          >
            ? How it works
          </button>
        </div>

        <p className="subtitle">
          Paste any URL — including shortened links like bit.ly — to check it for malware, phishing, suspicious redirects, and more before you click.
        </p>

        {/* Input form */}
        <form className="checker-form" onSubmit={handleSubmit}>
          <div className="input-wrap">
            <span className="input-icon">🔗</span>
            <input
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com or bit.ly/abc123"
              aria-label="URL to check"
              disabled={loading}
              autoComplete="off"
              spellCheck={false}
            />
            {url && !loading && (
              <button type="button" className="clear-btn" onClick={() => { setUrl(''); setResult(null); setError(''); inputRef.current?.focus() }}>✕</button>
            )}
          </div>
          <button type="submit" className="submit-btn" disabled={loading}>
            {loading ? <span className="spinner" /> : '🔍 Check URL'}
          </button>
        </form>

        {/* Progress bar */}
        {loading && <ProgressBar currentStageLabel={currentStage} />}

        {/* Error */}
        {error && (
          <div className="error-banner">
            <span>❌</span>
            <p>{error}</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && <Results result={result} />}
      </main>
    </div>
  )
}
