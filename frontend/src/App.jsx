import { useState, useEffect, useRef } from 'react'
import {
  LuShield,
  LuShieldCheck,
  LuShieldAlert,
  LuShieldX,
  LuSearch,
  LuLink,
  LuExternalLink,
  LuCopy,
  LuCheck,
  LuX,
  LuClipboard,
  LuChevronDown,
  LuInfo,
  LuArrowDown,
  LuCalendar,
  LuNetwork,
  LuCode,
  LuSun,
  LuMoon,
  LuGlobe,
  LuTriangleAlert,
  LuCircleAlert,
  LuCircleCheck,
  LuCircleX,
  LuEyeOff,
  LuKey,
  LuFileCode,
  LuRefreshCw,
  LuLock,
  LuLockOpen,
  LuFileText,
  LuActivity,
} from 'react-icons/lu'

import './App.css'

// ─── Stage Metadata for Multi-Stage Progress Scanner ─────────────────────────
const STAGES = [
  {
    key: 'validating',
    label: 'Validating URL',
    detail: 'Sanitising address format, stripping tracking parameters, and resolving host protocols.',
    icon: <LuSearch />,
  },
  {
    key: 'safe_browsing',
    label: 'Google Safe Browsing',
    detail: 'Querying global databases for known malware distributions, phishing vectors, and malicious feeds.',
    icon: <LuShield />,
  },
  {
    key: 'structure',
    label: 'Structure Analysis',
    detail: 'Inspecting hostname entropy, IP-based routing, suspicious TLDs, and typosquatting impersonation.',
    icon: <LuNetwork />,
  },
  {
    key: 'domain_age',
    label: 'Domain Age & WHOIS',
    detail: 'Querying registrar records for registration velocity; newly minted domains carry significantly higher risk.',
    icon: <LuCalendar />,
  },
  {
    key: 'redirect',
    label: 'Redirect Chain',
    detail: 'Tracing HTTP redirect hops, resolving obfuscated shorteners, and identifying protocol downgrades.',
    icon: <LuActivity />,
  },
  {
    key: 'sandbox',
    label: 'Sandbox Passive Preview',
    detail: 'Safely parsing DOM markup without executing JavaScript to detect credential harvesting forms and exfiltration scripts.',
    icon: <LuCode />,
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

// ─── Precision Risk Gauge Component ──────────────────────────────────────────
function RiskGauge({ score }) {
  const safeScore = Math.max(0, Math.min(100, score ?? 0))
  const color = safeScore >= 60 ? 'var(--danger-accent)' : safeScore >= 30 ? 'var(--warn-accent)' : 'var(--safe-accent)'
  const label = safeScore >= 60 ? 'High Risk' : safeScore >= 30 ? 'Medium Risk' : 'Low Risk'
  
  const r = 38
  const cx = 48
  const cy = 48
  const circ = Math.PI * r
  const filled = circ * (safeScore / 100)

  return (
    <div className="risk-gauge-dial">
      <svg viewBox="0 0 96 54" width="124" aria-label={`Risk gauge showing ${safeScore}/100`}>
        {/* Track */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="var(--border-card)"
          strokeWidth="8"
          strokeLinecap="round"
        />
        {/* Gauge Arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circ}`}
          style={{ transition: 'stroke-dasharray 0.6s cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>
      <div className="gauge-caption">
        <span className="gauge-score-number" style={{ color }}>{safeScore}</span>
        <span className="gauge-risk-status" style={{ color }}>{label}</span>
      </div>
    </div>
  )
}

// ─── Multi-Stage Progress Stepper ────────────────────────────────────────────
function ProgressBar({ currentStageLabel }) {
  const activeKey = stageKeyFromLabel(currentStageLabel)
  const activeIndex = activeKey ? STAGES.findIndex(s => s.key === activeKey) : 0
  const activeStage = STAGES[activeIndex] || STAGES[0]
  const pct = Math.round(((activeIndex + 1) / STAGES.length) * 100)

  return (
    <div className="progress-card" role="progressbar" aria-valuenow={pct} aria-valuemin="0" aria-valuemax="100">
      <div className="progress-top-row">
        <div className="active-stage-indicator">
          <span className="micro-spinner" />
          <span className="stage-step-count">STAGE {activeIndex + 1}/{STAGES.length}</span>
          <span>{activeStage.label}</span>
        </div>
        <span className="progress-pct-badge">{pct}%</span>
      </div>

      <p className="stage-detail-paragraph">{activeStage.detail}</p>

      <div className="progress-track-rail">
        <div className="progress-track-fill" style={{ width: `${pct}%` }} />
      </div>

      <div className="stepper-steps-grid">
        {STAGES.map((s, idx) => {
          const isDone = idx < activeIndex
          const isActive = idx === activeIndex
          return (
            <div
              key={s.key}
              className={`stepper-node ${isDone ? 'done' : ''} ${isActive ? 'active' : ''} ${!isDone && !isActive ? 'pending' : ''}`}
              title={`${s.label}: ${s.detail}`}
            >
              <span className="step-marker-icon">
                {isDone ? <LuCircleCheck /> : isActive ? <LuActivity /> : <span style={{ fontSize: '0.65rem' }}>{idx + 1}</span>}
              </span>
              <span className="step-node-name">{s.label}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Collapsible Accordion Section ───────────────────────────────────────────
function CollapsibleSection({ title, icon, flaggedCount, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="accordion-section">
      <button
        type="button"
        className="accordion-trigger"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
      >
        <div className="accordion-title-cluster">
          <span className="accordion-section-icon">{icon}</span>
          <span className="accordion-section-label">{title}</span>
          {flaggedCount > 0 && (
            <span className="section-flag-badge">
              <LuCircleAlert /> {flaggedCount} {flaggedCount === 1 ? 'flag' : 'flags'}
            </span>
          )}
        </div>
        <span className={`accordion-chevron-box ${open ? 'open' : ''}`}>
          <LuChevronDown />
        </span>
      </button>
      {open && <div className="accordion-body-container">{children}</div>}
    </div>
  )
}

// ─── Technical "How It Works" Modal ──────────────────────────────────────────
function InfoModal({ onClose }) {
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-dialog" onClick={e => e.stopPropagation()}>
        <div className="modal-header-section">
          <div className="modal-title-lockup">
            <LuShield style={{ color: 'var(--c-400)', fontSize: '1.4rem' }} />
            <h2 id="modal-title">How ZEB Inspects Links</h2>
          </div>
          <button type="button" className="modal-close-icon-btn" onClick={onClose} aria-label="Close modal">
            <LuX />
          </button>
        </div>

        <div className="modal-body-section">
          <p className="modal-lead-paragraph">
            ZEB employs a multi-tiered security pipeline combining real-time commercial threat intelligence with passive heuristic and content analysis. Each engine evaluates distinct attack surfaces before rendering a consolidated verdict.
          </p>

          <div className="engine-check-grid">
            {STAGES.map(s => (
              <div key={s.key} className="engine-check-card">
                <span className="engine-card-icon">{s.icon}</span>
                <div className="engine-card-details">
                  <strong>{s.label}</strong>
                  <p>{s.detail}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="modal-safety-notice">
            <strong>Passive Sandbox Guarantee:</strong> ZEB fetches DOM markup in a sandboxed parser without executing client-side scripts, keeping your machine insulated from drive-by downloads or zero-day browser exploits.
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Results Presentation Component ──────────────────────────────────────────
function ResultsView({ result, onReset }) {
  const [copiedKey, setCopiedKey] = useState(null)
  const { url, verdict, message, threats, structureAnalysis } = result
  const sa = structureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const sandbox = sa.sandboxPreview || null

  const isSafe = verdict === 'SAFE'
  const isUnsafe = verdict === 'UNSAFE'
  const isUnsure = !isSafe && !isUnsafe

  const flaggedFindingsCount = sa.findings?.filter(f => f.flagged).length || 0
  const hasShortener = redirect.passedThroughShortener || redirect.hops?.some(h => h.isShortener)
  const hopCount = redirect.hopCount ?? (redirect.hops?.length || 0)

  // Copy helper
  function handleCopy(text, key) {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  // Generate full markdown report for export
  function copyFullReport() {
    const report = [
      `# ZEB URL Security Report`,
      `• Target URL: ${url}`,
      `• Verdict: ${verdict}`,
      `• Summary: ${message}`,
      `• Hostname: ${sa.hostname || 'N/A'}`,
      `• Registered Domain: ${sa.registeredDomainFull || 'N/A'}`,
      `• Domain Age: ${sa.domainAge?.available ? `${sa.domainAge.domainAgeDays} days` : 'Unknown'}`,
      `• Redirect Hops: ${hopCount}`,
      `• Final Destination: ${redirect.finalUrl || url}`,
      `• Sandbox Risk Score: ${sandbox?.riskScore ?? 'N/A'}/100`,
      threats?.length > 0 ? `• Threats Detected: ${threats.map(t => t.threatType).join(', ')}` : '• Threats: None detected via Google Safe Browsing',
    ].join('\n')
    handleCopy(report, 'full-report')
  }

  return (
    <div className={`results-shell ${isSafe ? 'status-safe' : isUnsafe ? 'status-unsafe' : isUnsure ? 'status-unsure' : ''}`}>
      {/* Top Verdict Hero */}
      <div className="verdict-hero">
        <div className="verdict-header-row">
          <div className={`verdict-badge-prominent ${isSafe ? 'badge-prominent-safe' : isUnsafe ? 'badge-prominent-unsafe' : isUnsure ? 'badge-prominent-unsure' : ''}`}>
            {isSafe ? <LuShieldCheck /> : isUnsafe ? <LuShieldX /> : <LuShieldAlert />}
            <span>VERDICT: {verdict}</span>
          </div>

          <div className="quick-stats-strip">
            <span className="quick-stat-item">
              <LuGlobe style={{ marginRight: 4 }} />
              {sa.hostname || 'Domain'}
            </span>
            <span className="quick-stat-item">
              <LuActivity style={{ marginRight: 4 }} />
              {hopCount} {hopCount === 1 ? 'Hop' : 'Hops'}
            </span>
            {sandbox?.available && (
              <span className="quick-stat-item">
                <LuCode style={{ marginRight: 4 }} />
                Score: {sandbox.riskScore ?? 0}/100
              </span>
            )}
          </div>
        </div>

        {/* Target URL Console Row */}
        <div className="target-url-console">
          <div className="target-url-group">
            <span className="target-url-label">TARGET:</span>
            <code className="target-url-code" title={url}>{url}</code>
          </div>
          <div className="url-action-btns">
            <button
              type="button"
              className={`copy-mini-btn ${copiedKey === 'target-url' ? 'copied' : ''}`}
              onClick={() => handleCopy(url, 'target-url')}
              aria-label="Copy inspected URL"
            >
              {copiedKey === 'target-url' ? <><LuCheck /> Copied</> : <><LuCopy /> Copy URL</>}
            </button>
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="copy-mini-btn"
              title="Open URL in separate tab (Caution)"
            >
              <LuExternalLink /> Visit
            </a>
          </div>
        </div>

        <p className="verdict-explanation-msg">{message}</p>
      </div>

      {/* Google Safe Browsing Threats Banner (if present) */}
      {threats?.length > 0 && (
        <div className="threat-module">
          <div className="threat-module-title">
            <LuTriangleAlert />
            <span>Google Safe Browsing Threats Identified</span>
          </div>
          {threats.map((t, idx) => (
            <div key={idx} className="threat-record">
              <div className="threat-record-header">
                <span className="threat-badge">{t.threatType}</span>
                <span className="threat-platform">Platform: {t.platformType}</span>
              </div>
              <p className="threat-explanation">
                {t.threatType === 'MALWARE' && 'Confirmed host for malware distribution capable of damaging hardware or extracting sensitive credentials.'}
                {t.threatType === 'SOCIAL_ENGINEERING' && 'Deceptive phishing surface impersonating trusted entities to harvest login credentials or payment data.'}
                {t.threatType === 'UNWANTED_SOFTWARE' && 'Distributes unwanted toolbars, adware, or background crypto-mining software.'}
                {!['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'].includes(t.threatType) && 'Matches verified malicious pattern in Google threat databases.'}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Shortener & Redirect Pipeline */}
      {hasShortener && (
        <div className="shortener-pipeline-card">
          <div className="pipeline-header">
            <LuNetwork />
            <span>Obfuscated Shortener Chain Detected</span>
          </div>
          <p className="pipeline-desc">
            This URL passes through a shortening gateway to mask its final destination. ZEB navigated the redirect chain to expose the terminal endpoint.
          </p>

          <div className="pipeline-chain">
            <div className="chain-hop-box origin">
              <div className="chain-hop-meta">
                <span className="chain-hop-tag">Initial Entrypoint</span>
                <code className="chain-hop-url">{url}</code>
              </div>
            </div>

            <div className="chain-arrow-separator">
              <LuArrowDown />
            </div>

            {redirect.hops?.filter(h => h.isShortener).map((hop, i) => (
              <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div className="chain-hop-box intermediate">
                  <div className="chain-hop-meta">
                    <span className="chain-hop-tag">Shortener Gateway ({hop.statusCode || '301'})</span>
                    <code className="chain-hop-url">{hop.url}</code>
                  </div>
                </div>
                <div className="chain-arrow-separator">
                  <LuArrowDown />
                </div>
              </div>
            ))}

            <div className="chain-hop-box destination">
              <div className="chain-hop-meta">
                <span className="chain-hop-tag" style={{ color: 'var(--safe-text)' }}>Resolved Final Destination</span>
                <code className="chain-hop-url">{redirect.finalUrl || url}</code>
              </div>
              <button
                type="button"
                className={`copy-mini-btn ${copiedKey === 'final-url' ? 'copied' : ''}`}
                onClick={() => handleCopy(redirect.finalUrl || url, 'final-url')}
                aria-label="Copy resolved destination URL"
              >
                {copiedKey === 'final-url' ? <><LuCheck /> Copied</> : <><LuCopy /> Copy Destination</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Collapsible Sections Accordion */}
      <div className="sections-accordion">
        {/* Section 1: Domain Architecture */}
        <CollapsibleSection
          title="URL & Domain Architecture"
          icon={<LuGlobe />}
          flaggedCount={flaggedFindingsCount}
          defaultOpen={true}
        >
          <div className="metric-tiles-grid">
            <div className="metric-tile">
              <span className="metric-tile-label">Hostname</span>
              <span className="metric-tile-value" title={sa.hostname}>{sa.hostname || '—'}</span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Registered Domain</span>
              <span className="metric-tile-value" title={sa.registeredDomainFull}>{sa.registeredDomainFull || '—'}</span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">TLD Zone</span>
              <span className="metric-tile-value">.{sa.tld || '—'}</span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Domain Age</span>
              <span className="metric-tile-value">
                {sa.domainAge?.available ? `${sa.domainAge.domainAgeDays} days` : 'Lookup Unavailable'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Velocity Risk</span>
              <span className={`metric-tile-value ${sa.domainAge?.isNewDomain ? 'val-danger' : 'val-safe'}`}>
                {sa.domainAge?.isNewDomain ? 'High (Recent Reg)' : 'Verified Historical'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Host Routing</span>
              <span className={`metric-tile-value ${sa.isIpBased ? 'val-warn' : 'val-safe'}`}>
                {sa.isIpBased ? 'Direct IP Host' : 'Named DNS Domain'}
              </span>
            </div>
          </div>

          {/* Structural findings */}
          <div className="findings-stream">
            {sa.findings?.map((f, i) => (
              <div key={i} className={`finding-row ${f.flagged ? 'flagged' : 'clean'}`}>
                <span className="finding-dot">
                  {f.flagged ? <LuCircleAlert /> : <LuCircleCheck />}
                </span>
                <span className="finding-desc">{f.explanation}</span>
              </div>
            ))}
          </div>
        </CollapsibleSection>

        {/* Section 2: Redirect Chain */}
        <CollapsibleSection
          title="Redirect Chain & Protocol Integrity"
          icon={<LuNetwork />}
          flaggedCount={redirect.tooManyRedirects || redirect.hops?.some(h => h.suspicious) ? 1 : 0}
          defaultOpen={false}
        >
          {redirect.tooManyRedirects && (
            <div className="finding-row flagged" style={{ marginBottom: 12 }}>
              <span className="finding-dot"><LuCircleAlert /></span>
              <span className="finding-desc">
                Excessive redirect count ({redirect.hopCount} hops). Often employed by cloaking networks to evade automated inspection.
              </span>
            </div>
          )}

          {redirect.hops && redirect.hops.length > 0 ? (
            <div className="hops-stream">
              {redirect.hops.map((hop, i) => (
                <div key={i} className={`hop-card ${hop.suspicious ? 'hop-warn' : ''}`}>
                  <span className="hop-index-badge">{i + 1}</span>
                  <div className="hop-content">
                    <code className="hop-url-text">{hop.url}</code>
                    <div className="hop-tags-cluster">
                      {hop.statusCode && <span className="meta-chip">HTTP {hop.statusCode}</span>}
                      {hop.crossOrigin && <span className="meta-chip chip-warn">Cross-Origin</span>}
                      {hop.isShortener && <span className="meta-chip chip-info">Shortener</span>}
                      {hop.schemeDowngrade && <span className="meta-chip chip-bad">HTTPS → HTTP Downgrade</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="finding-desc" style={{ color: 'var(--text-muted)', fontSize: '0.84rem' }}>
              Direct destination reached with zero intermediate redirects.
            </p>
          )}
        </CollapsibleSection>

        {/* Section 3: Passive Sandbox Preview */}
        <CollapsibleSection
          title="Passive Sandbox & Content Scan"
          icon={<LuCode />}
          flaggedCount={sandbox?.riskScore >= 25 ? 1 : 0}
          defaultOpen={sandbox?.riskScore >= 25}
        >
          {sandbox?.available ? (
            <div>
              <div className="sandbox-hero-cluster">
                <RiskGauge score={sandbox.riskScore ?? 0} />
                <div className="sandbox-hero-explain">
                  <strong>Static Heuristic Risk Metric</strong>
                  <p>
                    Evaluated passively across HTML markup, metadata tags, and form actions. Higher values signal aggressive credential-harvesting indicators or obfuscated evasion scripts.
                  </p>
                </div>
              </div>

              {sandbox.matchedKeywords?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuKey /> Phishing Keywords Found
                  </div>
                  <p className="sandbox-group-subtitle">Urgency pressure keywords frequently associated with unauthorized password resets or billing fraud.</p>
                  <div className="chips-cloud">
                    {sandbox.matchedKeywords.map((kw, i) => (
                      <span key={i} className="meta-chip chip-bad">{kw}</span>
                    ))}
                  </div>
                </div>
              )}

              {sandbox.fakeLoginForms?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuFileCode /> Suspicious Form Actions
                  </div>
                  <p className="sandbox-group-subtitle">Credential-accepting form fields submitting payloads to foreign or unusual endpoints.</p>
                  {sandbox.fakeLoginForms.map((f, i) => (
                    <div key={i} className="code-box-display">
                      <span>Action: {f.action || 'Unknown'}</span>
                      {f.hasPasswordField && <span style={{ marginLeft: 10, color: 'var(--danger-text)' }}>[Password Input Detected]</span>}
                    </div>
                  ))}
                </div>
              )}

              {sandbox.suspiciousScripts?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuCircleAlert /> Obfuscated Scripts
                  </div>
                  <p className="sandbox-group-subtitle">Script blocks matching known hex-encoding or evaluation wrappers.</p>
                  {sandbox.suspiciousScripts.map((s, i) => (
                    <div key={i} className="code-box-display">
                      <code>{s.pattern || s.src || JSON.stringify(s)}</code>
                    </div>
                  ))}
                </div>
              )}

              {sandbox.hiddenIframes?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuEyeOff /> Zero-Pixel Hidden IFrames
                  </div>
                  <p className="sandbox-group-subtitle">Invisible embedded frames capable of silent clickjacking or foreign session hijacking.</p>
                  {sandbox.hiddenIframes.map((f, i) => (
                    <div key={i} className="code-box-display">
                      <code>{f.src || JSON.stringify(f)}</code>
                    </div>
                  ))}
                </div>
              )}

              {sandbox.sslIssues?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuLockOpen /> SSL / TLS Certificate Issues
                  </div>
                  {sandbox.sslIssues.map((s, i) => (
                    <div key={i} className="finding-row flagged">
                      <span className="finding-dot"><LuCircleAlert /></span>
                      <span className="finding-desc">{s.issue}</span>
                    </div>
                  ))}
                </div>
              )}

              {sandbox.missingSecHeaders?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LuShield /> Missing Hardening Headers
                  </div>
                  <p className="sandbox-group-subtitle">Recommended HTTP security headers absent from target server response.</p>
                  <div className="chips-cloud">
                    {sandbox.missingSecHeaders.map((h, i) => (
                      <span key={i} className="meta-chip chip-warn">{h}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="finding-row clean">
              <span className="finding-dot"><LuLock /></span>
              <span className="finding-desc">
                Static page preview could not be fetched (site may be behind geo-restrictions, Cloudflare bot-checks, or offline).
              </span>
            </div>
          )}
        </CollapsibleSection>
      </div>

      {/* Report Action Bar */}
      <div className="report-action-bar">
        <span className="report-notice-text">
          <LuInfo /> Automated passive scan completed safely.
        </span>

        <div className="report-btns-group">
          <button
            type="button"
            className="action-icon-btn"
            onClick={copyFullReport}
          >
            {copiedKey === 'full-report' ? <><LuCheck /> Copied Report</> : <><LuFileText /> Copy Report</>}
          </button>
          <button
            type="button"
            className="action-icon-btn"
            onClick={onReset}
          >
            <LuRefreshCw /> Scan Another URL
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Application Console Root ───────────────────────────────────────────
export default function App() {
  const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [showInfo, setShowInfo] = useState(false)
  const [currentStage, setCurrentStage] = useState('')
  const [sessionId, setSessionId] = useState(null)

  // Theme state: defaults to Charcoal Dark mode to honor user palette preview
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('zeb-theme') || 'dark'
  })

  const inputRef = useRef(null)

  // Sync theme with documentElement
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('zeb-theme', theme)
  }, [theme])

  function toggleTheme() {
    setTheme(t => (t === 'dark' ? 'light' : 'dark'))
  }

  // Global keyboard shortcuts: "/" or "Ctrl+K" focuses input, "Esc" closes modal
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        if (e.key === 'Escape') {
          e.target.blur()
        }
        return
      }
      if (e.key === '/' || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault()
        inputRef.current?.focus()
      } else if (e.key === '?') {
        e.preventDefault()
        setShowInfo(true)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Poll progress during active scan
  useEffect(() => {
    if (!sessionId || !loading) return
    const iv = setInterval(async () => {
      try {
        const r = await fetch(`${apiBaseUrl}/api/check-progress/?sessionId=${sessionId}`)
        const d = await r.json()
        if (d.currentStage) setCurrentStage(d.currentStage)
      } catch (_err) {
        void _err
      }
    }, 350)
    return () => clearInterval(iv)
  }, [sessionId, loading, apiBaseUrl])

  async function handleSubmit(e) {
    if (e) e.preventDefault()
    setError('')
    setResult(null)
    setCurrentStage('')

    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please provide a valid web URL or shortened link to inspect.')
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
        setError(data.error || 'Could not complete safety audit. Please verify server connectivity.')
        return
      }
      setResult(data)
    } catch {
      setError('Network communication failed. Please ensure the backend server is running.')
    } finally {
      setLoading(false)
      setCurrentStage('')
    }
  }

  // Quick preset test selector
  function handleSelectPreset(presetUrl) {
    setUrl(presetUrl)
    setError('')
    setResult(null)
    inputRef.current?.focus()
  }

  // Paste helper
  async function handlePaste() {
    try {
      const text = await navigator.clipboard.readText()
      if (text) {
        setUrl(text)
        setError('')
        inputRef.current?.focus()
      }
    } catch (_err) {
      void _err
    }
  }

  return (
    <div className="page">
      {showInfo && <InfoModal onClose={() => setShowInfo(false)} />}

      <main className="card">
        {/* Header Bar */}
        <div className="card-header-bar">
          <div className="brand-lockup">
            <div className="shield-badge">
              <LuShield />
            </div>
            <div className="brand-info">
              <div className="brand-title-row">
                <h1 className="brand-name">ZEB</h1>
                <span className="version-chip">v2.4 Engine</span>
              </div>
              <div className="engine-status-row">
                <span className="status-beacon" />
                <span className="engine-status-text">Passive Threat Heuristics Active</span>
              </div>
            </div>
          </div>

          <div className="header-actions">
            <button
              type="button"
              className="action-icon-btn"
              onClick={() => setShowInfo(true)}
              title="Inspect checking methodology (?)"
            >
              <LuInfo />
              <span>How it works</span>
              <kbd className="kbd-hint">?</kbd>
            </button>

            <button
              type="button"
              className="action-icon-btn"
              onClick={toggleTheme}
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
              aria-label="Toggle visual theme"
            >
              {theme === 'dark' ? <LuSun /> : <LuMoon />}
            </button>
          </div>
        </div>

        {/* Card Content Area */}
        <div className="card-content">
          <p className="console-description">
            Inspect any web link, domain, or shortened redirect before interacting. Passive scanners check Google threat feeds, WHOIS registration velocity, and DOM phishing heuristics.
          </p>

          {/* Search Form */}
          <form className="checker-form" onSubmit={handleSubmit}>
            <div className="input-shell">
              <span className="input-leading-icon">
                <LuLink />
              </span>
              <input
                ref={inputRef}
                type="text"
                className="url-input-field"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="Paste URL (e.g. github.com, bit.ly/sample, http://192.168.1.1)"
                aria-label="URL to inspect"
                disabled={loading}
                autoComplete="off"
                spellCheck={false}
              />
              <div className="input-trailing-actions">
                {url && !loading && (
                  <button
                    type="button"
                    className="input-util-btn"
                    onClick={() => { setUrl(''); setResult(null); setError(''); inputRef.current?.focus() }}
                    title="Clear input"
                  >
                    <LuX />
                  </button>
                )}
                {!url && !loading && (
                  <button
                    type="button"
                    className="input-util-btn"
                    onClick={handlePaste}
                    title="Paste from clipboard"
                  >
                    <LuClipboard />
                  </button>
                )}
              </div>
            </div>

            <button type="submit" className="check-submit-btn" disabled={loading}>
              {loading ? (
                <>
                  <span className="micro-spinner" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <LuSearch />
                  <span>Check URL</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Test Presets */}
          <div className="quick-presets-row">
            <span className="presets-label">Test Samples:</span>
            <button
              type="button"
              className="preset-pill"
              onClick={() => handleSelectPreset('https://github.com')}
            >
              <span>Clean:</span> <code>github.com</code>
            </button>
            <button
              type="button"
              className="preset-pill"
              onClick={() => handleSelectPreset('https://bit.ly/3xSecurityDemo')}
            >
              <span>Shortener:</span> <code>bit.ly/sample</code>
            </button>
            <button
              type="button"
              className="preset-pill"
              onClick={() => handleSelectPreset('http://192.168.1.1/login')}
            >
              <span>IP Host:</span> <code>192.168.1.1</code>
            </button>
          </div>

          {/* Real-time Multi-Stage Progress Scanner */}
          {loading && <ProgressBar currentStageLabel={currentStage} />}

          {/* Error Banner */}
          {error && (
            <div className="error-banner" role="alert">
              <span className="error-banner-icon">
                <LuCircleX />
              </span>
              <div className="error-banner-content">
                <div className="error-banner-title">Inspection Error</div>
                <div className="error-banner-desc">{error}</div>
              </div>
            </div>
          )}

          {/* Comprehensive Results Display */}
          {result && !loading && (
            <ResultsView
              result={result}
              onReset={() => {
                setResult(null)
                setUrl('')
                setError('')
                inputRef.current?.focus()
              }}
            />
          )}
        </div>
      </main>
    </div>
  )
}
