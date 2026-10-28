/**
 * STIX 2.1 Threat Intelligence Bundle Generator & Incident Exporter
 * Generates machine-readable STIX 2.1 JSON and human-readable Markdown/Defanged IOCs.
 */

/**
 * Defang a URL so it cannot be accidentally clicked or trigger automatic unfurlings in Slack/Teams/Jira.
 * e.g. https://bad.com/login -> hxxps[://]bad[.]com/login
 */
export function defangUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return ''
  return rawUrl
    .replace(/^https?:\/\//i, match => match.toLowerCase().startsWith('https') ? 'hxxps[://]' : 'hxxp[://]')
    .replace(/\./g, '[.]')
}

/**
 * Defang an IP address: 192.168.1.1 -> 192[.]168[.]1[.]1
 */
export function defangIp(ip) {
  if (!ip || typeof ip !== 'string') return ''
  return ip.replace(/\./g, '[.]')
}

/**
 * Generate formatted plain-text IOC block
 */
export function generateDefangedIocBlock(scanResult = {}) {
  const { url, verdict, structureAnalysis } = scanResult
  const sa = structureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const infra = sa.infrastructureAnalysis || {}
  const ip = infra.resolvedIp || sa.resolvedIp || 'N/A'
  const asn = infra.asnInfo?.asn ? `AS${infra.asnInfo.asn} (${infra.asnInfo.org || 'Unknown'})` : 'N/A'

  return [
    `Target URL : ${defangUrl(url)}`,
    `Final URL  : ${defangUrl(redirect.finalUrl || url)}`,
    `Host       : ${defangUrl(sa.hostname || '')}`,
    `IP Address : ${defangIp(ip)}`,
    `ASN        : ${asn}`,
    `Verdict    : ${verdict || 'UNKNOWN'}`,
    `Timestamp  : ${new Date().toISOString()}`,
    `Scanned By : ZEB Security v2.4`,
  ].join('\n')
}

/**
 * Generate formatted Markdown Incident Dossier for ticketing systems (Jira, GitHub, Slack)
 */
export function generateMarkdownReport(scanResult = {}) {
  const { url, verdict, message, threats, structureAnalysis } = scanResult
  const sa = structureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const infra = sa.infrastructureAnalysis || {}
  const domThreats = sandbox.domThreats || {}
  const web3 = domThreats.web3Signatures || {}
  const payloads = domThreats.payloadDownloads || {}
  const visual = sandbox.visualMatching || {}

  const isUnsafe = verdict === 'UNSAFE'
  const verdictIcon = isUnsafe ? '🚨' : verdict === 'SAFE' ? '✅' : '⚠️'
  const defanged = defangUrl(url)
  const finalDefanged = defangUrl(redirect.finalUrl || url)
  const now = new Date().toUTCString()

  const findingsList = []
  if (threats?.length) {
    threats.forEach(t => findingsList.push(`- **Commercial Threat Feed**: ${t.threatType} (${t.platformType})`))
  }
  if (visual.detected) {
    findingsList.push(`- **Visual Brand Impersonation**: Detected ${visual.brand} (${Math.round((visual.similarityScore || 0) * 100)}% visual match)`)
  }
  if (web3.hasWeb3Drainer) {
    findingsList.push(`- **Web3 Wallet Drainer**: Found ${web3.detectedPatterns?.join(', ') || 'malicious contract signatures'}`)
  }
  if (payloads.isMaliciousDownload) {
    findingsList.push(`- **Drive-By Download**: Dangerous extension/MIME (${payloads.flags?.join(', ') || 'executable payload'})`)
  }
  if (sa.findings?.length) {
    sa.findings.filter(f => f.flagged).forEach(f => findingsList.push(`- **Structural Heuristic**: ${f.explanation}`))
  }
  if (findingsList.length === 0) {
    findingsList.push('- No critical threat indicators flagged by active heuristics.')
  }

  const hopsText = (redirect.hops && redirect.hops.length > 0)
    ? redirect.hops.map((h, i) => `${i + 1}. \`${defangUrl(h.url)}\` (${h.statusCode || '30x'}${h.isShortener ? ' - Shortener' : ''})`).join('\n')
    : '`Direct destination reached with zero intermediate redirects.`'

  return `# 🛡️ ZEB Threat Intelligence Incident Report
**Generated**: ${now} | **Verdict**: ${verdictIcon} **${verdict || 'UNKNOWN'}**

### 📌 Target Overview
- **Target URL**: \`${url}\`
- **Defanged URL**: \`${defanged}\`
- **Final Destination**: \`${finalDefanged}\`
- **Consolidated Summary**: ${message || 'Passive safety audit completed.'}
- **Heuristic Risk Score**: ${sandbox.riskScore ?? 0}/100

### 🌐 Network & Infrastructure Indicators
- **Hostname**: \`${sa.hostname || 'N/A'}\`
- **Registered Domain**: \`${sa.registeredDomainFull || 'N/A'}\`
- **Destination IP**: \`${infra.resolvedIp || 'N/A'}\`
- **ASN & Operator**: \`${infra.asnInfo ? `AS${infra.asnInfo.asn} (${infra.asnInfo.org})` : 'N/A'}\`
- **Bulletproof / High-Abuse Host**: ${infra.asnInfo?.isHighAbuse ? '🚨 YES (Bulletproof Infrastructure)' : 'No known abuse flag'}
- **Domain Age**: ${sa.domainAge?.available ? `${sa.domainAge.domainAgeDays} days (${sa.domainAge.isNewDomain ? 'Newly Registered Domain' : 'Established'})` : 'Lookup Unavailable'}
- **SSL Certificate**: ${infra.sslAudit?.ageDays !== undefined ? `Issued ${infra.sslAudit.ageDays} days ago by ${infra.sslAudit.issuer || 'Unknown'}` : 'N/A'}
- **DNS Fast-Flux Risk**: ${infra.dnsAudit?.fastFluxDetected ? '🚨 Fast-Flux Detected' : 'Normal'}

### 🔍 Threat Findings & Indicators
${findingsList.join('\n')}

### 🔄 Redirect Traversal Chain
${hopsText}

---
*Generated by ZEB Security v2.4 (Zero-Trust Link Intelligence Engine)*
`
}

/**
 * Generate a standard STIX 2.1 JSON Threat Intelligence Bundle
 */
export function generateStixBundle(scanResult = {}) {
  const { url, verdict, message, structureAnalysis } = scanResult
  const sa = structureAnalysis || {}
  const infra = sa.infrastructureAnalysis || {}
  const now = new Date().toISOString()
  const randomSuffix = () => Math.random().toString(36).substring(2, 10)

  const bundleId = `bundle--${randomSuffix()}-${randomSuffix()}`
  const indicatorId = `indicator--${randomSuffix()}-${randomSuffix()}`
  const domainId = `domain-name--${randomSuffix()}`

  const isMalicious = verdict === 'UNSAFE'
  const confidence = isMalicious ? 90 : verdict === 'SAFE' ? 10 : 50

  const labels = ['malicious-activity']
  if (isMalicious) {
    labels.push('phishing', 'social-engineering')
  }

  const objects = [
    {
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: now,
      modified: now,
      name: `ZEB URL Threat Indicator: ${sa.hostname || url}`,
      description: message || `Threat audit for ${url}`,
      indicator_types: isMalicious ? ['malicious-activity'] : ['benign'],
      pattern: `[url:value = '${url.replace(/'/g, "\\'")}']`,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: now,
      confidence: confidence,
      labels: labels,
      external_references: [
        {
          source_name: 'ZEB Security Platform',
          description: 'Zero-Trust Passive Link Intelligence Platform v2.4',
        },
      ],
    },
    {
      type: 'domain-name',
      spec_version: '2.1',
      id: domainId,
      value: sa.hostname || 'unknown-host',
    },
  ]

  if (infra.resolvedIp) {
    const ipId = `ipv4-addr--${randomSuffix()}`
    objects.push({
      type: 'ipv4-addr',
      spec_version: '2.1',
      id: ipId,
      value: infra.resolvedIp,
    })

    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${randomSuffix()}`,
      created: now,
      modified: now,
      relationship_type: 'resolves-to',
      source_ref: domainId,
      target_ref: ipId,
    })
  }

  return {
    type: 'bundle',
    id: bundleId,
    objects: objects,
  }
}
