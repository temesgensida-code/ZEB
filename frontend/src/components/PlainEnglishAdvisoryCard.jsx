import React from 'react'
import {
  ShieldSlash,
  ShieldCheck,
  ShieldWarning,
  Warning,
  CheckCircle,
  Prohibit,
  XCircle,
  ArrowRight,
  BookOpen,
  Lightbulb,
} from '@phosphor-icons/react'
import { getDetectedTopicsForScan, SECURITY_KNOWLEDGE_BASE } from '../data/securityKnowledgeBase'

export default function PlainEnglishAdvisoryCard({ result, onOpenExplainer }) {
  if (!result) return null

  const verdict = result.verdict || 'UNSURE'
  const isUnsafe = verdict === 'UNSAFE'
  const isSafe = verdict === 'SAFE'
  const isInspecting = verdict === 'INSPECTING...'

  const sa = result.structureAnalysis || {}
  const infra = sa.infrastructureAnalysis || sa.infrastructure || {}
  const ssl = infra.sslDeep || infra.sslAudit || {}
  const asn = infra.asn || infra.asnInfo || {}
  const dns = infra.dns || infra.dnsAudit || {}
  const sandbox = sa.sandboxPreview || {}
  const detectedTopicIds = getDetectedTopicsForScan(result)
  const primaryTopicId = detectedTopicIds[0] || (isUnsafe ? 'google_safe_browsing' : 'domain_age')
  const primaryTopic = SECURITY_KNOWLEDGE_BASE[primaryTopicId]

  // Construct a concise 2-sentence conversational narrative for non-technical users
  let headline = ''
  let narrative = ''
  let statusTheme = 'safe' // 'danger' | 'warning' | 'safe'

  if (isUnsafe) {
    statusTheme = 'danger'
    headline = 'High-Risk Deceptive Website Detected'

    if (sa.hasTyposquattingSignal) {
      narrative = `This link imitates a well-known brand and was set up to fool you into thinking it is legitimate. It is very likely a counterfeit website designed to capture your login credentials or personal information.`
    } else if (ssl.isVeryRecent && sa.domainAge?.isNewDomain) {
      narrative = `This website was created just days ago and uses a fresh security certificate. It has virtually no established reputation and exhibits hallmarks of a short-lived scam campaign.`
    } else if (asn.isHighAbuse) {
      narrative = `This link is hosted on a network known for harboring cybercriminals and ignoring abuse takedown requests. It is extremely unsafe to visit.`
    } else if (result.threats && result.threats.length > 0) {
      narrative = `This address has been confirmed as malicious on international cybersecurity threat databases. Visiting this site could compromise your personal security.`
    } else {
      narrative = `Our security engines identified critical red flags indicating this website is unsafe. Criminals frequently use links like this to steal accounts or install malicious programs.`
    }
  } else if (!isSafe && !isInspecting) {
    statusTheme = 'warning'
    headline = 'Suspicious Signals Detected — Proceed With Caution'

    if (sa.domainAge?.isNewDomain) {
      narrative = `This website is very new with zero established history, meaning it has not yet built a verified track record. Exercise extra caution before trusting it with sensitive information.`
    } else if (ssl.isVeryRecent) {
      narrative = `This website recently renewed or generated a new security certificate. While this can happen normally, scammers frequently use fresh certificates for fast attacks.`
    } else {

      narrative = `While not conclusively confirmed as malicious, this link exhibits unusual technical characteristics. We advise against entering passwords or financial data.`
    }
  } else if (isSafe) {
    statusTheme = 'safe'
    headline = 'Looks Clean — No Critical Threats Detected'
    narrative = `This website possesses a mature domain history, a verified security certificate, and clean threat intelligence records. No deceptive traps or credential harvesters were found.`
  } else {
    statusTheme = 'inspecting'
    headline = 'Scanning Security Heuristics in Real-Time...'
    narrative = `Evaluating domain history, SSL certificate recency, hosting reputation, and page scripts in isolated cloud containers.`
  }

  return (
    <div className={`plain-advisory-card advisory-${statusTheme}`}>
      <div className="advisory-top-banner">
        <div className="advisory-badge-wrap">
          <span className="advisory-traffic-light">
            {statusTheme === 'danger' && <ShieldSlash size={18} weight="bold" />}
            {statusTheme === 'warning' && <Warning size={18} weight="bold" />}
            {statusTheme === 'safe' && <ShieldCheck size={18} weight="bold" />}
            {statusTheme === 'inspecting' && <span className="micro-spinner" />}
          </span>

          <div className="advisory-title-group">
            <span className="advisory-eyebrow">PLAIN-ENGLISH SUMMARY</span>
            <h3 className="advisory-headline">{headline}</h3>
          </div>
        </div>

        {detectedTopicIds.length > 0 && (
          <button
            type="button"
            className="advisory-explain-btn"
            onClick={() => onOpenExplainer(primaryTopicId)}
            title="Explore comprehensive plain-English breakdown with real-world analogies"
          >
            <BookOpen size={14} weight="bold" />
            <span>Explain the Dangers</span>
            <ArrowRight size={13} weight="bold" />
          </button>
        )}
      </div>

      <p className="advisory-narrative-text">{narrative}</p>

      {/* Immediate Action Checklist for everyday users */}
      <div className="advisory-action-checklist">
        <div className="advisory-checklist-header">
          <Lightbulb size={14} weight="bold" />
          <span>What Should You Do?</span>
        </div>
        <div className="advisory-action-items">
          {statusTheme === 'danger' && (
            <>
              <div className="advisory-action-item action-critical">
                <Prohibit size={15} weight="bold" />
                <span><strong>Do not type any passwords, emails, or credit card numbers</strong> on this page.</span>
              </div>
              <div className="advisory-action-item action-critical">
                <XCircle size={15} weight="bold" />
                <span><strong>Close the browser tab immediately</strong> without clicking any buttons or links inside.</span>
              </div>
              <div className="advisory-action-item">
                <Warning size={15} weight="bold" />
                <span><strong>If you already entered your password:</strong> Go immediately to the real company's official site, change your password, and enable Two-Factor Authentication.</span>
              </div>
            </>
          )}

          {statusTheme === 'warning' && (
            <>
              <div className="advisory-action-item action-warn">
                <Warning size={15} weight="bold" />
                <span><strong>Double-check who sent you this link.</strong> Only proceed if you know and trust the sender personally.</span>
              </div>
              <div className="advisory-action-item">
                <Prohibit size={15} weight="bold" />
                <span><strong>Avoid typing financial or login credentials.</strong> Legitimate services rarely use brand-new or unusual domains.</span>
              </div>
            </>
          )}

          {statusTheme === 'safe' && (
            <>
              <div className="advisory-action-item action-clean">
                <CheckCircle size={15} weight="bold" />
                <span><strong>Address looks authentic.</strong> The domain has verified history and active encryption.</span>
              </div>
              <div className="advisory-action-item">
                <CheckCircle size={15} weight="bold" />
                <span><strong>Good internet practice:</strong> Always check that the URL in your browser matches the site you intend to visit before logging in.</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
