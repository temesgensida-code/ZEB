import { defangUrl } from './stixGenerator'

/**
 * Generates an authoritative, professional SOC incident brief.
 * STRICT ZERO-EMOJI POLICY: Uses clean ASCII brackets and Markdown for corporate Slack/Teams/Jira.
 *
 * @param {object} result - The inspection result object
 * @param {string} [permalinkUrl] - Optional permalink to reload this inspection
 * @returns {string} Plain-text/Markdown formatted incident card without any emojis
 */
export function generateIncidentCard(result, permalinkUrl) {
  if (!result) return ''

  const url = result.url || ''
  const defanged = defangUrl(url)
  const verdict = (result.verdict || 'UNKNOWN').toUpperCase()
  const sa = result.structureAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const infra = sa.infrastructureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const threats = result.threats || []
  const findings = sa.findings || []

  const riskScore = sandbox.riskScore ?? result.riskScore ?? 0
  const hostname = sa.hostname || 'Unknown Host'
  const resolvedIp = infra.resolvedIp || 'Not Resolved'
  const asn = infra.asnInfo?.asn ? `AS${infra.asnInfo.asn} (${infra.asnInfo.org || 'Unknown Org'})` : 'N/A'
  const hopCount = redirect.hopCount ?? (redirect.hops?.length || 0)

  // Threat signals compilation
  const threatSignals = []

  // Threat feed matches
  threats.forEach(t => {
    threatSignals.push(`[FLAGGED] Multi-engine blacklist match: ${t.engine || 'Google Safe Browsing'} (${t.threatType || 'THREAT'})`)
  })

  // Flagged findings from structureAnalysis
  findings.filter(f => f.flagged).forEach(f => {
    threatSignals.push(`[FLAGGED] ${f.explanation || f.type}`)
  })

  // Visual brand clone
  if (sandbox.visualMatching?.detected) {
    const brand = sandbox.visualMatching.brand || 'Known Brand'
    const score = Math.round((sandbox.visualMatching.similarityScore || 0) * 100)
    threatSignals.push(`[FLAGGED] Visual brand impersonation: Masquerading as ${brand} (${score}% layout match)`)
  }

  // Web3 drainer
  if (sandbox.domThreats?.web3Signatures?.hasWeb3Drainer) {
    threatSignals.push(`[FLAGGED] Web3 wallet drainer signature: Malicious Permit2 / blind-signing contract calls detected`)
  }

  // Executable payload
  if (sandbox.domThreats?.payloadDownloads?.isMaliciousDownload) {
    threatSignals.push(`[FLAGGED] Malicious payload trap: Executable or masqueraded double-extension download detected`)
  }

  // Bulletproof ASN
  if (infra.asnInfo?.isHighAbuse) {
    threatSignals.push(`[FLAGGED] Bulletproof hosting network: AS${infra.asnInfo.asn} is flagged for recurring abuse infrastructure`)
  }

  // Suspicious redirect
  if (redirect.passedThroughShortener) {
    threatSignals.push(`[FLAGGED] Obfuscated redirect: Entrypoint passed through URL shortening gateway to cloak terminal endpoint`)
  }

  // Domain age
  if (sa.domainAge?.isNewDomain) {
    const days = sa.domainAge.domainAgeDays ?? 'Recent'
    threatSignals.push(`[FLAGGED] Domain registration recency: Domain registered ${days} days ago (Velocity Trap threshold: < 30 days)`)
  }

  // If no threats flagged
  if (threatSignals.length === 0) {
    threatSignals.push(`[CLEAN] All evaluated heuristics and threat intelligence feeds returned zero high-confidence deception signals.`)
  }

  // Determine recommended actions
  const recommendedActions = []
  if (verdict === 'UNSAFE' || riskScore >= 60) {
    recommendedActions.push(`1. Enforce domain and IP block on perimeter border firewalls and internal DNS resolvers.`)
    recommendedActions.push(`2. Search mail transport logs for incoming messages containing this link and purge instances.`)
    recommendedActions.push(`3. If users accessed this URL, revoke active session tokens and enforce credential reset.`)
  } else if (verdict === 'SUSPICIOUS' || riskScore >= 30) {
    recommendedActions.push(`1. Exercise caution before submitting credentials, API keys, or enterprise secrets on this host.`)
    recommendedActions.push(`2. Inspect destination DOM markup inside an isolated cloud sandbox environment.`)
    recommendedActions.push(`3. Monitor outbound egress traffic for anomalous connections toward ${hostname}.`)
  } else {
    recommendedActions.push(`1. Link meets baseline passive security hygiene standards. Standard web browsing policy applies.`)
    recommendedActions.push(`2. Maintain zero-trust verification if page requests administrative or financial credentials.`)
  }

  const timestampIso = new Date().toISOString()
  const permalink = permalinkUrl || (typeof window !== 'undefined' ? `${window.location.origin}${window.location.pathname}?url=${encodeURIComponent(url)}` : '')

  return [
    `================================================================================`,
    `[ZEB SECURITY INCIDENT BRIEF]`,
    `================================================================================`,
    `TARGET URL      : ${defanged}`,
    `RAW DESTINATION : ${url}`,
    `FINAL VERDICT   : [${verdict}] (Composite Risk Score: ${riskScore}/100)`,
    `HOST RESOLUTION : ${hostname} | IP: ${resolvedIp} | ASN: ${asn}`,
    `REDIRECT CHAIN  : ${hopCount} ${hopCount === 1 ? 'Hop' : 'Hops'} (Final: ${defangUrl(redirect.finalUrl || url)})`,
    ``,
    `DETECTED THREAT SIGNATURES & ANOMALIES:`,
    ...threatSignals.map(sig => `- ${sig}`),
    ``,
    `RECOMMENDED SOC ACTIONS:`,
    ...recommendedActions,
    ``,
    `AUDIT METADATA:`,
    `Timestamp       : ${timestampIso}`,
    `Engine          : ZEB Security Core v2.4 (Zero-Script Cloud Isolation Matrix)`,
    permalink ? `Investigation   : ${permalink}` : null,
    `================================================================================`,
  ].filter(Boolean).join('\n')
}
