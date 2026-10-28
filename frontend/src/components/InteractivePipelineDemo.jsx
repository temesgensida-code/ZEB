import React, { useState } from 'react'
import {
  ShieldCheck,
  ShieldWarning,
  ShieldSlash,
  ShareNetwork,
  Cpu,
  Lock,
  Code,
  Gauge,
  Play,
  ArrowRight,
  CheckCircle,
  WarningCircle,
  XCircle,
} from '@phosphor-icons/react'

const DEMO_SCENARIOS = [
  {
    id: 'clean',
    title: 'Clean Domain',
    url: 'https://github.com/security',
    category: 'VERIFIED REPOSITORY',
    verdict: 'SAFE',
    riskScore: 0,
    accentClass: 'demo-safe',
    icon: ShieldCheck,
    summary: 'Standard HTTPS TLSv1.3 session. Established 16-year domain age. Clean commercial threat feeds and verified authoritative nameservers.',
    stages: [
      { name: 'URL De-obfuscation', status: 'clean', detail: 'No userinfo bait, canonical domain formatting, standard port 443.' },
      { name: 'Multi-Engine Intel', status: 'clean', detail: '0 engines flagged on Google Safe Browsing and threat feeds.' },
      { name: 'DNS & ASN Audit', status: 'clean', detail: 'AS36459 (GitHub Inc). 0% Fast-Flux score. 12+ month TLS cert.' },
      { name: 'DOM & Web3 Audit', status: 'clean', detail: 'Standard authentication headers. Zero wallet drainers or payload traps.' },
      { name: 'Consensus Score', status: 'clean', detail: 'Risk: 0/100 (Safe / Low Risk)' },
    ],
  },
  {
    id: 'phish',
    title: 'Obfuscated Phish',
    url: 'http://2130706433:login-verify@microsoft-sec.top/auth',
    category: 'CREDENTIAL HARVESTER',
    verdict: 'UNSAFE',
    riskScore: 96,
    accentClass: 'demo-danger',
    icon: ShieldSlash,
    summary: 'Dword encoded IP (127.0.0.1) masked behind userinfo spoofing bait. Free DV TLS certificate issued 2.1 hours ago. Form action submits passwords to foreign Telegram webhook.',
    stages: [
      { name: 'URL De-obfuscation', status: 'danger', detail: 'Decimal Dword IP unpacked. Deceptive userinfo (@) spoofing Microsoft.' },
      { name: 'Multi-Engine Intel', status: 'danger', detail: 'Matches known phishing lure feed patterns.' },
      { name: 'DNS & ASN Audit', status: 'danger', detail: 'High-abuse hosting provider. SSL certificate age < 24 hours.' },
      { name: 'DOM & Web3 Audit', status: 'danger', detail: 'Password input on unencrypted origin. Form exfiltrates to foreign sink.' },
      { name: 'Consensus Score', status: 'danger', detail: 'Risk: 96/100 (Critical Malicious Threat)' },
    ],
  },
  {
    id: 'web3',
    title: 'Web3 Wallet Drainer',
    url: 'https://claim-airdrop-eth2.xyz/connect',
    category: 'CRYPTO ASSET THEFT',
    verdict: 'UNSAFE',
    riskScore: 88,
    accentClass: 'demo-warn',
    icon: ShieldWarning,
    summary: 'Newly registered .xyz domain hosting embedded Permit2 and Seaport drainer scripts designed to hijack ERC-20 allowances via eth_sign.',
    stages: [
      { name: 'URL De-obfuscation', status: 'warning', detail: 'High-abuse .xyz TLD zone with deceptive brand keywords (claim-airdrop).' },
      { name: 'Multi-Engine Intel', status: 'warning', detail: 'Zero-hour campaign; pending reputation database indexing.' },
      { name: 'DNS & ASN Audit', status: 'danger', detail: 'Registered 3 days ago. Bulletproof reverse proxy detected.' },
      { name: 'DOM & Web3 Audit', status: 'danger', detail: 'Permit2 signature sniffer & eth_sign stealth drainer detected in DOM.' },
      { name: 'Consensus Score', status: 'danger', detail: 'Risk: 88/100 (High Risk Phishing / Theft)' },
    ],
  },
]

export function InteractivePipelineDemo({ onSelectScenarioUrl }) {
  const [selectedId, setSelectedId] = useState('phish')
  const scenario = DEMO_SCENARIOS.find(s => s.id === selectedId) || DEMO_SCENARIOS[1]
  const IconComp = scenario.icon

  return (
    <div className="pipeline-demo-card">
      <div className="demo-header-strip">
        <div className="demo-title-group">
          <Cpu size={16} weight="bold" />
          <span className="demo-title-text">Interactive Inspection Engine Simulation</span>
          <span className="demo-badge">LIVE SIMULATION</span>
        </div>
        <div className="demo-selector-tabs" role="tablist" aria-label="Simulation Scenarios">
          {DEMO_SCENARIOS.map(s => (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={selectedId === s.id}
              className={`demo-scenario-btn ${selectedId === s.id ? 'active' : ''} ${s.accentClass}`}
              onClick={() => setSelectedId(s.id)}
            >
              <span>{s.title}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Scenario Overview */}
      <div className="demo-scenario-body">
        <div className="scenario-meta-row">
          <div className="scenario-url-pill">
            <span className="url-label">SIMULATED INPUT:</span>
            <code className="url-string">{scenario.url}</code>
          </div>
          <div className={`scenario-verdict-pill ${scenario.accentClass}`}>
            <IconComp size={15} weight="bold" />
            <span>VERDICT: {scenario.verdict} ({scenario.riskScore}/100)</span>
          </div>
          {onSelectScenarioUrl && (
            <button
              type="button"
              className="mech-btn demo-test-btn"
              onClick={() => onSelectScenarioUrl(scenario.url)}
              title="Load this test sample into real URL inspector"
            >
              <Play size={12} weight="bold" />
              <span>Test In Live Inspector</span>
            </button>
          )}
        </div>

        <p className="scenario-summary-lead">{scenario.summary}</p>

        {/* 5 Pipeline Stages */}
        <div className="pipeline-stages-grid">
          {scenario.stages.map((stg, idx) => {
            const isDanger = stg.status === 'danger'
            const isWarn = stg.status === 'warning'
            const isClean = stg.status === 'clean'

            return (
              <div
                key={idx}
                className={`pipeline-stage-box ${isDanger ? 'stage-danger' : isWarn ? 'stage-warn' : 'stage-clean'}`}
              >
                <div className="stage-top-bar">
                  <span className="stage-index">0{idx + 1}</span>
                  <span className="stage-status-icon">
                    {isClean && <CheckCircle size={14} weight="bold" />}
                    {isWarn && <WarningCircle size={14} weight="bold" />}
                    {isDanger && <XCircle size={14} weight="bold" />}
                  </span>
                </div>
                <div className="stage-name">{stg.name}</div>
                <div className="stage-detail-txt">{stg.detail}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
