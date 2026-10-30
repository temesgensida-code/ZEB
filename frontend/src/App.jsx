import React, { useState, useEffect, useRef } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldWarning,
  ShieldSlash,
  MagnifyingGlass,
  Link as LinkIcon,
  ArrowSquareOut,
  Copy,
  Check,
  X,
  ClipboardText,
  CaretDown,
  Info,
  ArrowDown,
  CalendarBlank,
  ShareNetwork,
  Code,
  FileCode,
  Eye,
  FileText,
  Pulse,
  Lock,
  LockOpen,
  Warning,
  WarningCircle,
  CheckCircle,
  XCircle,
  Globe,
  Database,
  DownloadSimple,
  TerminalWindow,
} from '@phosphor-icons/react'

import './App.css'
import { ThemeSwitch } from './components/ThemeSwitch'
import { LinkDissector } from './components/LinkDissector'
import { InteractivePipelineDemo } from './components/InteractivePipelineDemo'
import { SafePreviewModal } from './components/SafePreviewModal'
import { ReportExportModal } from './components/ReportExportModal'
import { DeveloperPortal } from './views/DeveloperPortal'
import { defangUrl } from './utils/stixGenerator'

// ─── Stage Metadata for Multi-Stage Progress Scanner ─────────────────────────
const STAGES = [
  {
    key: 'validating',
    label: 'Validating URL',
    detail: 'Sanitising address format, stripping tracking parameters, and resolving host protocols.',
    icon: <MagnifyingGlass size={16} weight="bold" />,
  },
  {
    key: 'safe_browsing',
    label: 'Multi-Engine Threat Feeds',
    detail: 'Querying global databases for known malware distributions, phishing vectors, and malicious feeds.',
    icon: <Shield size={16} weight="bold" />,
  },
  {
    key: 'structure',
    label: 'Structure & Homographs',
    detail: 'Inspecting hostname entropy, IP-based routing, Unicode confusables, and typosquatting impersonation.',
    icon: <ShareNetwork size={16} weight="bold" />,
  },
  {
    key: 'infrastructure',
    label: 'Infrastructure & DNS',
    detail: 'Querying Bulletproof ASNs, Fast-Flux nameserver volatility, and TLS certificate issuance recency.',
    icon: <Database size={16} weight="bold" />,
  },
  {
    key: 'redirect',
    label: 'Redirect Chain',
    detail: 'Tracing HTTP redirect hops, resolving obfuscated shorteners, and identifying protocol downgrades.',
    icon: <Pulse size={16} weight="bold" />,
  },
  {
    key: 'sandbox',
    label: 'DOM & Web3 Sandbox',
    detail: 'Auditing forms, Permit2 crypto signatures, Telegram exfiltration sinks, and drive-by download traps.',
    icon: <Code size={16} weight="bold" />,
  },
]

function stageKeyFromLabel(label) {
  if (!label) return null
  const l = label.toLowerCase()
  if (l.includes('validat')) return 'validating'
  if (l.includes('safe browsing') || l.includes('google') || l.includes('threat')) return 'safe_browsing'
  if (l.includes('structure') || l.includes('homograph')) return 'structure'
  if (l.includes('domain age') || l.includes('whois') || l.includes('infrastruct') || l.includes('dns')) return 'infrastructure'
  if (l.includes('redirect')) return 'redirect'
  if (l.includes('sandbox') || l.includes('preview') || l.includes('dom')) return 'sandbox'
  return null
}

// ─── Precision Risk Gauge Component ──────────────────────────────────────────
function RiskGauge({ score }) {
  const safeScore = Math.max(0, Math.min(100, score ?? 0))
  const color = safeScore >= 60 ? 'var(--risk-danger-accent)' : safeScore >= 30 ? 'var(--risk-warn-accent)' : 'var(--risk-safe-accent)'
  const label = safeScore >= 60 ? 'High Risk' : safeScore >= 30 ? 'Medium Risk' : 'Low Risk'

  const r = 38
  const cx = 48
  const cy = 48
  const circ = Math.PI * r
  const filled = circ * (safeScore / 100)

  return (
    <div className="risk-gauge-dial">
      <svg viewBox="0 0 96 54" width="124" aria-label={`Risk gauge showing ${safeScore}/100`}>
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="var(--border-muted)"
          strokeWidth="7"
          strokeLinecap="round"
        />
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circ}`}
          style={{ transition: 'stroke-dasharray 0.5s cubic-bezier(0.16, 1, 0.3, 1)' }}
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
              className={`stepper-node ${isDone ? 'done' : ''} ${isActive ? 'active' : ''}`}
              title={`${s.label}: ${s.detail}`}
            >
              <span className="step-marker-icon">
                {isDone ? <CheckCircle size={14} weight="bold" /> : isActive ? <Pulse size={14} weight="bold" /> : <span style={{ fontSize: '0.65rem' }}>{idx + 1}</span>}
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
              <WarningCircle size={12} weight="bold" /> {flaggedCount} {flaggedCount === 1 ? 'flag' : 'flags'}
            </span>
          )}
        </div>
        <span className={`accordion-chevron-box ${open ? 'open' : ''}`}>
          <CaretDown size={14} weight="bold" />
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
            <Shield size={20} weight="bold" />
            <h2 id="modal-title" className="modal-heading-text">How ZEB Inspects Links</h2>
          </div>
          <button type="button" className="mech-btn modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={16} weight="bold" />
          </button>
        </div>

        <div className="modal-body-section">
          <p className="modal-lead-paragraph">
            ZEB employs a multi-tiered security pipeline combining real-time commercial threat feeds with passive heuristic and network analysis. Each engine evaluates distinct attack surfaces before rendering a consolidated verdict.
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
            <strong>Passive Sandbox Guarantee:</strong> ZEB evaluates URLs and DOM markup in isolated cloud containers without executing untrusted scripts on your workstation, keeping your browser insulated from zero-day exploits.
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Results Presentation Component ──────────────────────────────────────────
function ResultsView({ result, onReset, onOpenSafePreview, onOpenExportReport }) {
  const [copiedKey, setCopiedKey] = useState(null)
  const { url, verdict, message, threats, structureAnalysis } = result
  const sa = structureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const infra = sa.infrastructureAnalysis || {}
  const domThreats = sandbox.domThreats || {}
  const web3 = domThreats.web3Signatures || {}
  const payloads = domThreats.payloadDownloads || {}
  const credHarvester = domThreats.credentialHarvesters || {}
  const visual = sandbox.visualMatching || {}

  const isSafe = verdict === 'SAFE'
  const isUnsafe = verdict === 'UNSAFE'

  const flaggedFindingsCount = sa.findings?.filter(f => f.flagged).length || 0
  const hasShortener = redirect.passedThroughShortener || redirect.hops?.some(h => h.isShortener)
  const hopCount = redirect.hopCount ?? (redirect.hops?.length || 0)

  function handleCopy(text, key) {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  return (
    <div className={`results-shell ${isSafe ? 'status-safe' : isUnsafe ? 'status-unsafe' : 'status-unsure'}`}>
      {/* Pillar 6.1: Interactive Link Dissector */}
      <LinkDissector url={url} structureAnalysis={structureAnalysis} />

      {/* Top Verdict Hero */}
      <div className="verdict-hero">
        <div className="verdict-header-row">
          <div className={`verdict-badge-prominent ${isSafe ? 'badge-prominent-safe' : isUnsafe ? 'badge-prominent-unsafe' : 'badge-prominent-unsure'}`}>
            {isSafe ? <ShieldCheck size={20} weight="bold" /> : isUnsafe ? <ShieldSlash size={20} weight="bold" /> : <ShieldWarning size={20} weight="bold" />}
            <span>VERDICT: {verdict}</span>
          </div>

          <div className="quick-stats-strip">
            <span className="quick-stat-item">
              <Globe size={13} weight="bold" />
              {sa.hostname || 'Domain'}
            </span>
            <span className="quick-stat-item">
              <Pulse size={13} weight="bold" />
              {hopCount} {hopCount === 1 ? 'Hop' : 'Hops'}
            </span>
            <span className="quick-stat-item">
              <Code size={13} weight="bold" />
              Risk: {sandbox.riskScore ?? 0}/100
            </span>
            {infra.asnInfo && (
              <span className={`quick-stat-item ${infra.asnInfo.isHighAbuse ? 'val-danger' : ''}`}>
                <Database size={13} weight="bold" />
                AS{infra.asnInfo.asn}
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
              className={`copy-mini-btn ${copiedKey === 'defang' ? 'copied' : ''}`}
              onClick={() => handleCopy(defangUrl(url), 'defang')}
              title="Copy defanged link (safe for Slack/Teams)"
            >
              {copiedKey === 'defang' ? <><Check size={12} weight="bold" /> Copied Defanged</> : <><Copy size={12} weight="bold" /> Defang URL</>}
            </button>
            <button
              type="button"
              className={`copy-mini-btn ${copiedKey === 'target-url' ? 'copied' : ''}`}
              onClick={() => handleCopy(url, 'target-url')}
              aria-label="Copy inspected URL"
            >
              {copiedKey === 'target-url' ? <><Check size={12} weight="bold" /> Copied</> : <><Copy size={12} weight="bold" /> Copy</>}
            </button>
            <button
              type="button"
              className="copy-mini-btn"
              onClick={onOpenSafePreview}
              title="Inspect page in isolated cloud sandbox"
            >
              <Eye size={12} weight="bold" /> Safe Preview
            </button>
            <button
              type="button"
              className="copy-mini-btn"
              onClick={onOpenExportReport}
              title="Export Incident Report (Markdown, Defanged, STIX 2.1)"
            >
              <DownloadSimple size={12} weight="bold" /> Export Report
            </button>
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="copy-mini-btn"
              title="Open URL in separate browser tab (Caution)"
            >
              <ArrowSquareOut size={12} weight="bold" /> Visit
            </a>
          </div>
        </div>

        <p className="verdict-explanation-msg">{message}</p>
      </div>

      {/* Visual Brand Impersonation Alert */}
      {visual.detected && (
        <div className="threat-module">
          <div className="threat-module-title">
            <Warning size={16} weight="bold" />
            <span>Visual Brand Impersonation Detected</span>
          </div>
          <div className="threat-record">
            <div className="threat-record-header">
              <span className="threat-badge">VISUAL CLONE</span>
              <span className="threat-platform">Targeted Brand: {visual.brand}</span>
            </div>
            <p className="threat-explanation">
              Page layout displays {Math.round((visual.similarityScore || 0) * 100)}% visual similarity to official {visual.brand} login portals, indicating an active phishing credential harvester.
            </p>
          </div>
        </div>
      )}

      {/* Web3 Wallet Drainer Alert */}
      {web3.hasWeb3Drainer && (
        <div className="threat-module">
          <div className="threat-module-title">
            <ShieldSlash size={16} weight="bold" />
            <span>Web3 Crypto Drainer Signatures Detected</span>
          </div>
          <div className="threat-record">
            <div className="threat-record-header">
              <span className="threat-badge">WALLET THEFT</span>
              <span className="threat-platform">Signature: {web3.detectedPatterns?.join(', ')}</span>
            </div>
            <p className="threat-explanation">
              Embedded scripts execute malicious Permit2 / eth_sign approvals to drain connected Ethereum/EVM wallets without user awareness.
            </p>
          </div>
        </div>
      )}

      {/* Malicious Download Alert */}
      {payloads.isMaliciousDownload && (
        <div className="threat-module">
          <div className="threat-module-title">
            <Warning size={16} weight="bold" />
            <span>Drive-by Download / Malicious Payload Trap</span>
          </div>
          <div className="threat-record">
            <div className="threat-record-header">
              <span className="threat-badge">DANGEROUS PAYLOAD</span>
              <span className="threat-platform">Signals: {payloads.flags?.join(', ')}</span>
            </div>
            <p className="threat-explanation">
              Direct download or double extension trap (.pdf.exe) detected in server response headers or markup.
            </p>
          </div>
        </div>
      )}

      {/* Bulletproof Host Alert */}
      {infra.asnInfo?.isHighAbuse && (
        <div className="threat-module">
          <div className="threat-module-title">
            <Database size={16} weight="bold" />
            <span>Bulletproof Hosting Infrastructure Identified</span>
          </div>
          <div className="threat-record">
            <div className="threat-record-header">
              <span className="threat-badge">BULLETPROOF ASN</span>
              <span className="threat-platform">AS{infra.asnInfo.asn} ({infra.asnInfo.org})</span>
            </div>
            <p className="threat-explanation">
              Host resides within an Autonomous System known for ignoring DMCA takedowns and harboring criminal cyber-infrastructure.
            </p>
          </div>
        </div>
      )}

      {/* Multi-Engine Threats Banner */}
      {threats?.length > 0 && (
        <div className="threat-module">
          <div className="threat-module-title">
            <Warning size={16} weight="bold" />
            <span>Multi-Engine Threat Intelligence Matches</span>
          </div>
          {threats.map((t, idx) => (
            <div key={idx} className="threat-record">
              <div className="threat-record-header">
                <span className="threat-badge">{t.threatType}</span>
                <span className="threat-platform">Engine: {t.engine || 'Google Safe Browsing'} | Platform: {t.platformType}</span>
              </div>
              <p className="threat-explanation">
                {t.threatType === 'MALWARE' && 'Confirmed host for malware distribution capable of damaging systems or extracting credentials.'}
                {t.threatType === 'SOCIAL_ENGINEERING' && 'Deceptive phishing surface impersonating trusted entities to harvest login credentials.'}
                {t.threatType === 'UNWANTED_SOFTWARE' && 'Distributes unwanted toolbars, adware, or background crypto-mining software.'}
                {!['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'].includes(t.threatType) && 'Matches verified malicious pattern in security databases.'}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Shortener & Redirect Pipeline */}
      {hasShortener && (
        <div className="shortener-pipeline-card">
          <div className="pipeline-header">
            <ShareNetwork size={16} weight="bold" />
            <span>Obfuscated Shortener Chain Detected</span>
          </div>
          <p className="pipeline-desc">
            This URL passes through a shortening gateway to mask its final destination. ZEB traversed the redirect hops to expose the terminal endpoint.
          </p>

          <div className="pipeline-chain">
            <div className="chain-hop-box origin">
              <div className="chain-hop-meta">
                <span className="chain-hop-tag">Initial Entrypoint</span>
                <code className="chain-hop-url">{url}</code>
              </div>
            </div>

            <div className="chain-arrow-separator">
              <ArrowDown size={14} weight="bold" />
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
                  <ArrowDown size={14} weight="bold" />
                </div>
              </div>
            ))}

            <div className="chain-hop-box destination">
              <div className="chain-hop-meta">
                <span className="chain-hop-tag" style={{ color: 'var(--risk-safe-text)' }}>Resolved Final Destination</span>
                <code className="chain-hop-url">{redirect.finalUrl || url}</code>
              </div>
              <button
                type="button"
                className={`copy-mini-btn ${copiedKey === 'final-url' ? 'copied' : ''}`}
                onClick={() => handleCopy(redirect.finalUrl || url, 'final-url')}
                aria-label="Copy resolved destination URL"
              >
                {copiedKey === 'final-url' ? <><Check size={12} weight="bold" /> Copied</> : <><Copy size={12} weight="bold" /> Copy Destination</>}
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
          icon={<Globe size={16} weight="bold" />}
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

          <div className="findings-stream">
            {sa.findings?.map((f, i) => (
              <div key={i} className={`finding-row ${f.flagged ? 'flagged' : 'clean'}`}>
                <span className="finding-dot">
                  {f.flagged ? <WarningCircle size={14} weight="bold" /> : <CheckCircle size={14} weight="bold" />}
                </span>
                <span className="finding-desc">{f.explanation}</span>
              </div>
            ))}
          </div>
        </CollapsibleSection>

        {/* Section 2: Infrastructure & Network Security */}
        <CollapsibleSection
          title="Infrastructure, Network & DNS Audit"
          icon={<Database size={16} weight="bold" />}
          flaggedCount={infra.asnInfo?.isHighAbuse || infra.dnsAudit?.fastFluxDetected || infra.sslAudit?.isVeryRecent ? 1 : 0}
          defaultOpen={false}
        >
          <div className="metric-tiles-grid">
            <div className="metric-tile">
              <span className="metric-tile-label">Resolved IP</span>
              <span className="metric-tile-value">{infra.resolvedIp || 'N/A'}</span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Autonomous System</span>
              <span className="metric-tile-value">
                {infra.asnInfo ? `AS${infra.asnInfo.asn}` : 'N/A'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Hosting Provider</span>
              <span className="metric-tile-value" title={infra.asnInfo?.org}>
                {infra.asnInfo?.org || 'N/A'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Bulletproof Status</span>
              <span className={`metric-tile-value ${infra.asnInfo?.isHighAbuse ? 'val-danger' : 'val-safe'}`}>
                {infra.asnInfo?.isHighAbuse ? 'High Abuse Host' : 'Standard Host'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">Fast-Flux DNS</span>
              <span className={`metric-tile-value ${infra.dnsAudit?.fastFluxDetected ? 'val-danger' : 'val-safe'}`}>
                {infra.dnsAudit?.fastFluxDetected ? 'Detected' : 'Normal'}
              </span>
            </div>
            <div className="metric-tile">
              <span className="metric-tile-label">SSL Cert Recency</span>
              <span className={`metric-tile-value ${infra.sslAudit?.isVeryRecent ? 'val-danger' : 'val-safe'}`}>
                {infra.sslAudit?.ageDays !== undefined ? `${infra.sslAudit.ageDays} days old` : 'Unknown'}
              </span>
            </div>
          </div>
        </CollapsibleSection>

        {/* Section 3: Deep DOM, Form Actions & Payloads */}
        <CollapsibleSection
          title="Deep DOM, Form Action & Payload Inspection"
          icon={<Code size={16} weight="bold" />}
          flaggedCount={sandbox.riskScore >= 25 ? 1 : 0}
          defaultOpen={sandbox.riskScore >= 25}
        >
          {sandbox.available ? (
            <div>
              <div className="sandbox-hero-cluster">
                <RiskGauge score={sandbox.riskScore ?? 0} />
                <div className="sandbox-hero-explain">
                  <strong>Static Heuristic Risk Metric</strong>
                  <p>
                    Passively evaluated across HTML markup, metadata tags, and form actions. Higher values signal aggressive credential-harvesting indicators or obfuscated evasion scripts.
                  </p>
                </div>
              </div>

              {sandbox.matchedKeywords?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <FileText size={14} weight="bold" /> Phishing Keywords Found
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
                    <FileCode size={14} weight="bold" /> Suspicious Form Actions
                  </div>
                  <p className="sandbox-group-subtitle">Credential-accepting form fields submitting payloads to foreign or unusual endpoints.</p>
                  {sandbox.fakeLoginForms.map((f, i) => (
                    <div key={i} className="code-box-display">
                      <span>Action: {f.action || 'Unknown'}</span>
                      {f.hasPasswordField && <span style={{ marginLeft: 10, color: 'var(--risk-danger-text)' }}>[Password Input Detected]</span>}
                    </div>
                  ))}
                </div>
              )}

              {credHarvester.hiddenOverlays?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <Eye size={14} weight="bold" /> Clickjacking Hidden Overlays
                  </div>
                  <p className="sandbox-group-subtitle">Transparent overlay elements with opacity: 0 and z-index: 9999 hijacking pointer events.</p>
                  {credHarvester.hiddenOverlays.map((o, i) => (
                    <div key={i} className="code-box-display">
                      <code>{o.tag} {JSON.stringify(o.style)}</code>
                    </div>
                  ))}
                </div>
              )}

              {sandbox.sslIssues?.length > 0 && (
                <div className="sandbox-group-block">
                  <div className="sandbox-group-title">
                    <LockOpen size={14} weight="bold" /> SSL / TLS Certificate Issues
                  </div>
                  {sandbox.sslIssues.map((s, i) => (
                    <div key={i} className="finding-row flagged">
                      <span className="finding-dot"><WarningCircle size={14} weight="bold" /></span>
                      <span className="finding-desc">{s.issue}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="finding-row clean">
              <span className="finding-dot"><Lock size={14} weight="bold" /></span>
              <span className="finding-desc">
                Static page preview could not be fetched (site may be behind geo-restrictions, bot-checks, or offline).
              </span>
            </div>
          )}
        </CollapsibleSection>

        {/* Section 4: Redirect Chain & Protocol Integrity */}
        <CollapsibleSection
          title="Redirect Chain & Protocol Integrity"
          icon={<ShareNetwork size={16} weight="bold" />}
          flaggedCount={redirect.tooManyRedirects || redirect.hops?.some(h => h.suspicious) ? 1 : 0}
          defaultOpen={false}
        >
          {redirect.tooManyRedirects && (
            <div className="finding-row flagged" style={{ marginBottom: 12 }}>
              <span className="finding-dot"><WarningCircle size={14} weight="bold" /></span>
              <span className="finding-desc">
                Excessive redirect count ({redirect.hopCount} hops). Often employed by cloaking networks to evade automated inspection.
              </span>
            </div>
          )}

          {redirect.hops && redirect.hops.length > 0 ? (
            <div className="pipeline-chain">
              {redirect.hops.map((hop, i) => (
                <div key={i} className="chain-hop-box">
                  <div className="chain-hop-meta">
                    <span className="chain-hop-tag">Hop {i + 1} ({hop.statusCode ? `HTTP ${hop.statusCode}` : 'Direct'})</span>
                    <code className="chain-hop-url">{hop.url}</code>
                  </div>
                  <div className="chips-cloud">
                    {hop.crossOrigin && <span className="meta-chip chip-warn">Cross-Origin</span>}
                    {hop.isShortener && <span className="meta-chip">Shortener</span>}
                    {hop.schemeDowngrade && <span className="meta-chip chip-bad">HTTPS → HTTP Downgrade</span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="finding-desc" style={{ color: 'var(--text-muted)' }}>
              Direct destination reached with zero intermediate redirects.
            </p>
          )}
        </CollapsibleSection>
      </div>

      {/* Bottom Action Bar */}
      <div className="report-action-bar">
        <span className="report-notice-text">
          <Info size={14} weight="bold" /> Automated passive safety audit complete.
        </span>

        <div className="report-btns-group">
          <button
            type="button"
            className="mech-btn"
            onClick={onOpenExportReport}
          >
            <DownloadSimple size={14} weight="bold" /> Export Threat Dossier
          </button>
          <button
            type="button"
            className="mech-btn mech-btn-primary"
            onClick={onReset}
          >
            <Pulse size={14} weight="bold" /> Scan Another URL
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
  const [showSafePreview, setShowSafePreview] = useState(false)
  const [showExportModal, setShowExportModal] = useState(false)
  const [currentStage, setCurrentStage] = useState('')
  const [sessionId, setSessionId] = useState(null)
  const [activeEditorialTab, setActiveEditorialTab] = useState('telemetry') // 'telemetry' | 'methodology' | 'faq'
  const [currentView, setCurrentView] = useState('inspector') // 'inspector' | 'developer'

  // Pure Monochrome Theme & System Adaptation: defaults to system or saved preference
  const [themePreference, setThemePreference] = useState(() => {
    return localStorage.getItem('zeb-theme-pref') || 'system'
  })

  // Mobile Bottom Info Accordions ('fall down' disclosure state)
  const [mobileOpenSections, setMobileOpenSections] = useState({
    telemetry: true,
    methodology: false,
    faq: false,
  })

  function toggleMobileSection(key) {
    setMobileOpenSections(prev => ({
      ...prev,
      [key]: !prev[key],
    }))
  }

  const inputRef = useRef(null)

  useEffect(() => {
    const mql = window.matchMedia('(prefers-color-scheme: dark)')

    function applyEffectiveTheme() {
      let resolved = themePreference
      if (themePreference === 'system') {
        resolved = mql.matches ? 'dark' : 'light'
      }
      document.documentElement.setAttribute('data-theme', resolved)
      localStorage.setItem('zeb-theme', resolved)
      localStorage.setItem('zeb-theme-pref', themePreference)
    }

    applyEffectiveTheme()

    function handleSystemThemeChange(e) {
      if (themePreference === 'system') {
        const resolved = e.matches ? 'dark' : 'light'
        document.documentElement.setAttribute('data-theme', resolved)
        localStorage.setItem('zeb-theme', resolved)
      }
    }

    mql.addEventListener('change', handleSystemThemeChange)
    return () => mql.removeEventListener('change', handleSystemThemeChange)
  }, [themePreference])

  // Keyboard shortcuts
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

  function handleSelectPreset(presetUrl) {
    setUrl(presetUrl)
    setError('')
    setResult(null)
    inputRef.current?.focus()
  }

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
      {/* Modals */}
      {showInfo && <InfoModal onClose={() => setShowInfo(false)} />}
      {showSafePreview && <SafePreviewModal result={result} onClose={() => setShowSafePreview(false)} />}
      {showExportModal && <ReportExportModal result={result} onClose={() => setShowExportModal(false)} />}

      {/* Cardless Layout Shell */}
      <div className="layout-shell">
        {/* Navigation Bar */}
        <header className="top-nav-bar">
          <div className="brand-lockup">
            <div className="brand-glyph-prefix" aria-hidden="true">
              <Shield size={22} weight="bold" />
            </div>
            <div className="brand-title-wrap">
              <span className="brand-name-bold">ZEB</span>
              <span className="brand-name-italic">Security</span>
              <span className="brand-badge-version">v2.4</span>
            </div>
          </div>

          <div className="nav-actions-cluster">
            <nav className="header-links-row" aria-label="Main Navigation">
              <button
                type="button"
                className={`header-nav-link ${currentView === 'inspector' ? 'active' : ''}`}
                onClick={() => setCurrentView('inspector')}
                title="URL Threat Inspector"
              >
                <span>URL Inspector</span>
              </button>

              <button
                type="button"
                className={`header-nav-link ${currentView === 'developer' ? 'active' : ''}`}
                onClick={() => setCurrentView('developer')}
                title="Developer API & Keys Management"
              >
                <span>Developer API</span>
              </button>

              <button
                type="button"
                className="header-nav-link"
                onClick={() => setShowInfo(true)}
                title="Inspect checking methodology (?)"
              >
                <span>How it works</span>
              </button>
            </nav>

            {/* Cubic 3-Way Theme Switcher with System Adaptation */}
            <ThemeSwitch
              themePreference={themePreference}
              onSelectTheme={setThemePreference}
            />
          </div>
        </header>

        {currentView === 'developer' ? (
          <DeveloperPortal onBackToInspector={() => setCurrentView('inspector')} />
        ) : (
          <>

        {/* Cardless Editorial Hero */}
        <section className="cardless-hero-section">
          <div className="breadcrumb-pill-row">
            <span className="breadcrumb-pill">
              <ShieldCheck size={12} weight="bold" />
              <span>SECURITY CORE</span>
              <span>/</span>
              <span>ACTIVE HEURISTICS</span>
            </span>
          </div>

          <h1 className="hero-headline">Zero-Trust Link Inspector</h1>

          <div className="hero-author-meta">
            <span className="status-live-beacon" />
            <span>Continuous Passive URL Heuristics & Consensus Engine</span>
          </div>

          <p className="hero-lead-text">
            Deconstructs obfuscated redirect chains, unpacks hex/decimal IP routing, identifies zero-hour homograph lures, and audits client-side DOM forms without executing untrusted scripts.
          </p>
        </section>

        {/* Search Input Form */}
        <form className="checker-form" onSubmit={handleSubmit}>
          <div className="input-shell">
            <span className="input-leading-icon">
              <LinkIcon size={18} weight="bold" />
            </span>
            <input
              ref={inputRef}
              type="text"
              className="url-input-field"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="Paste URL (e.g. github.com, bit.ly/sample, http://2130706433/login)"
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
                  <X size={14} weight="bold" />
                </button>
              )}
              {!url && !loading && (
                <button
                  type="button"
                  className="input-util-btn"
                  onClick={handlePaste}
                  title="Paste from clipboard"
                >
                  <ClipboardText size={14} weight="bold" />
                </button>
              )}
            </div>
          </div>

          <div className="form-action-row">
            <div className="quick-presets-row">
              <span className="presets-label">Samples:</span>
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

            <button type="submit" className="check-submit-btn" disabled={loading}>
              {loading ? (
                <>
                  <span className="micro-spinner" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <MagnifyingGlass size={16} weight="bold" />
                  <span>Inspect URL</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Real-time Multi-Stage Progress Scanner */}
        {loading && <ProgressBar currentStageLabel={currentStage} />}

        {/* Error Banner */}
        {error && (
          <div className="threat-module" role="alert" style={{ marginTop: 16 }}>
            <div className="threat-module-title">
              <XCircle size={16} weight="bold" />
              <span>Inspection Error</span>
            </div>
            <p className="threat-explanation">{error}</p>
          </div>
        )}

        {/* Inline Animated Interactive Pipeline Demo (Always available on canvas) */}
        {!result && (
          <InteractivePipelineDemo onSelectScenarioUrl={handleSelectPreset} />
        )}

        {/* Results View */}
        {result && !loading && (
          <ResultsView
            result={result}
            onReset={() => {
              setResult(null)
              setUrl('')
              setError('')
              inputRef.current?.focus()
            }}
            onOpenSafePreview={() => setShowSafePreview(true)}
            onOpenExportReport={() => setShowExportModal(true)}
          />
        )}

        {/* Bottom Information: Desktop Horizontal Tabs */}
        <div className="editorial-tabs-desktop">
          <div className="editorial-tabs-bar" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={activeEditorialTab === 'telemetry'}
              className={`editorial-tab-btn ${activeEditorialTab === 'telemetry' ? 'active' : ''}`}
              onClick={() => setActiveEditorialTab('telemetry')}
            >
              Engine Specifications
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeEditorialTab === 'methodology'}
              className={`editorial-tab-btn ${activeEditorialTab === 'methodology' ? 'active' : ''}`}
              onClick={() => setActiveEditorialTab('methodology')}
            >
              Detection Architecture
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeEditorialTab === 'faq'}
              className={`editorial-tab-btn ${activeEditorialTab === 'faq' ? 'active' : ''}`}
              onClick={() => setActiveEditorialTab('faq')}
            >
              Technical FAQ
            </button>
          </div>

          <div className="editorial-content-pane">
            {activeEditorialTab === 'telemetry' && (
              <>
                <p className="hero-lead-text" style={{ marginBottom: 16 }}>
                  ZEB v2.4 operates a passive hybrid detection matrix designed to analyze zero-hour attack vectors without local workstation compromise.
                </p>
                <div className="engine-check-grid">
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><ShareNetwork size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 1: URL Exposing & De-obfuscation</strong>
                      <p>Decodes decimal Dword, octal, and hex IP addresses. Unrolls recursive Base64 parameters and traces shortener hops.</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Shield size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 2: Multi-Engine Intelligence</strong>
                      <p>Consensus arbitration across commercial reputation feeds with zero-panic degradation if external APIs fail.</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Database size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 3: Infrastructure & DNS</strong>
                      <p>Evaluates Fast-Flux DNS, Autonomous System bulletproof hosting, and TLS certificate age thresholds (&lt;24 hours).</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Code size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 5: Deep DOM & Web3 Sniffer</strong>
                      <p>Detects unencrypted passwords, clickjacking traps, Permit2 signatures, and dangerous MIME payload traps.</p>
                    </div>
                  </div>
                </div>
              </>
            )}

            {activeEditorialTab === 'methodology' && (
              <p className="hero-lead-text">
                Traditional URL checkers rely solely on commercial domain blocklists, leaving users vulnerable to zero-hour campaigns. ZEB analyzes the intrinsic physical properties of the URL, the hosting network topology, and the destination DOM payload to identify deception before domain registries flag the host.
              </p>
            )}

            {activeEditorialTab === 'faq' && (
              <div className="findings-stream">
                <div className="finding-row clean">
                  <span className="finding-dot"><CheckCircle size={14} weight="bold" /></span>
                  <span className="finding-desc">
                    <strong>Can inspecting a URL trigger a malware download on my computer?</strong> No. All fetches, DNS resolutions, and DOM audits occur passively on isolated backend workers. No client-side scripts run on your device.
                  </span>
                </div>
                <div className="finding-row clean">
                  <span className="finding-dot"><CheckCircle size={14} weight="bold" /></span>
                  <span className="finding-desc">
                    <strong>What is link defanging?</strong> Defanging alters the URL format (e.g. converting `http` to `hxxp` and dots to `[.]`) so that communication tools like Slack, Teams, and Jira do not automatically generate clickable links or preview cards.
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Bottom Information: Mobile Fall-Down Collapsible Accordion */}
        <div className="editorial-accordion-mobile" role="region" aria-label="Engine specifications and technical details">
          {/* Accordion Item 1: Engine Specifications */}
          <div className="editorial-accordion-item">
            <button
              type="button"
              className={`editorial-accordion-header ${mobileOpenSections.telemetry ? 'open' : ''}`}
              onClick={() => toggleMobileSection('telemetry')}
              aria-expanded={mobileOpenSections.telemetry}
            >
              <span>Engine Specifications</span>
              <CaretDown size={16} weight="bold" className="accordion-caret" />
            </button>
            <div className={`editorial-accordion-body ${mobileOpenSections.telemetry ? 'open' : ''}`}>
              <div className="editorial-accordion-content">
                <p className="hero-lead-text" style={{ marginBottom: 14 }}>
                  ZEB v2.4 operates a passive hybrid detection matrix designed to analyze zero-hour attack vectors without local workstation compromise.
                </p>
                <div className="engine-check-grid">
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><ShareNetwork size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 1: URL Exposing & De-obfuscation</strong>
                      <p>Decodes decimal Dword, octal, and hex IP addresses. Unrolls recursive Base64 parameters and traces shortener hops.</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Shield size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 2: Multi-Engine Intelligence</strong>
                      <p>Consensus arbitration across commercial reputation feeds with zero-panic degradation if external APIs fail.</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Database size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 3: Infrastructure & DNS</strong>
                      <p>Evaluates Fast-Flux DNS, Autonomous System bulletproof hosting, and TLS certificate age thresholds (&lt;24 hours).</p>
                    </div>
                  </div>
                  <div className="engine-check-card">
                    <span className="engine-card-icon"><Code size={18} weight="bold" /></span>
                    <div className="engine-card-details">
                      <strong>Pillar 5: Deep DOM & Web3 Sniffer</strong>
                      <p>Detects unencrypted passwords, clickjacking traps, Permit2 signatures, and dangerous MIME payload traps.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Accordion Item 2: Detection Architecture */}
          <div className="editorial-accordion-item">
            <button
              type="button"
              className={`editorial-accordion-header ${mobileOpenSections.methodology ? 'open' : ''}`}
              onClick={() => toggleMobileSection('methodology')}
              aria-expanded={mobileOpenSections.methodology}
            >
              <span>Detection Architecture</span>
              <CaretDown size={16} weight="bold" className="accordion-caret" />
            </button>
            <div className={`editorial-accordion-body ${mobileOpenSections.methodology ? 'open' : ''}`}>
              <div className="editorial-accordion-content">
                <p className="hero-lead-text">
                  Traditional URL checkers rely solely on commercial domain blocklists, leaving users vulnerable to zero-hour campaigns. ZEB analyzes the intrinsic physical properties of the URL, the hosting network topology, and the destination DOM payload to identify deception before domain registries flag the host.
                </p>
              </div>
            </div>
          </div>

          {/* Accordion Item 3: Technical FAQ */}
          <div className="editorial-accordion-item">
            <button
              type="button"
              className={`editorial-accordion-header ${mobileOpenSections.faq ? 'open' : ''}`}
              onClick={() => toggleMobileSection('faq')}
              aria-expanded={mobileOpenSections.faq}
            >
              <span>Technical FAQ</span>
              <CaretDown size={16} weight="bold" className="accordion-caret" />
            </button>
            <div className={`editorial-accordion-body ${mobileOpenSections.faq ? 'open' : ''}`}>
              <div className="editorial-accordion-content">
                <div className="findings-stream">
                  <div className="finding-row clean">
                    <span className="finding-dot"><CheckCircle size={14} weight="bold" /></span>
                    <span className="finding-desc">
                      <strong>Can inspecting a URL trigger a malware download on my computer?</strong> No. All fetches, DNS resolutions, and DOM audits occur passively on isolated backend workers. No client-side scripts run on your device.
                    </span>
                  </div>
                  <div className="finding-row clean">
                    <span className="finding-dot"><CheckCircle size={14} weight="bold" /></span>
                    <span className="finding-desc">
                      <strong>What is link defanging?</strong> Defanging alters the URL format (e.g. converting `http` to `hxxp` and dots to `[.]`) so that communication tools like Slack, Teams, and Jira do not automatically generate clickable links or preview cards.
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
          </>
        )}
      </div>
    </div>
  )
}
