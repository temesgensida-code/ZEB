/**
 * riskDecomposer.js
 *
 * Transparent Mathematical Risk Score Decomposition Engine.
 * Evaluates the inspection result and maps every heuristic, infrastructure signal,
 * threat feed match, and DOM sniffer finding to its exact mathematical point contribution.
 */

export function decomposeRiskScore(result) {
  if (!result) {
    return {
      rawCalculatedScore: 0,
      compositeScore: 0,
      activePointsTotal: 0,
      activeRuleCount: 0,
      totalRulesAudited: 0,
      categories: [],
      activeDeductionsList: [],
    }
  }

  const sa = result.structureAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const infra = sa.infrastructureAnalysis || {}
  const redirect = sa.redirectAnalysis || {}
  const threats = result.threats || []
  const findings = sa.findings || []
  const domThreats = sandbox.domThreats || {}
  const web3 = domThreats.web3Signatures || {}
  const payloads = domThreats.payloadDownloads || {}
  const visual = sandbox.visualMatching || {}
  const ssl = infra.sslDeep || infra.sslAudit || {}

  // Helper to check if a specific finding type was flagged
  const hasFlaggedFinding = (typePrefix) => {
    return findings.some(f => f.flagged && f.type && f.type.toLowerCase().includes(typePrefix.toLowerCase()))
  }

  // 1. Threat Intelligence & Blacklists (Max 50 pts)
  const catThreatIntel = {
    id: 'threat_intel',
    title: 'Threat Intelligence & Reputation Feeds',
    description: 'Multi-engine consensus arbitration across global threat feeds and zero-hour signature databases.',
    maxPossiblePoints: 50,
    rules: [
      {
        id: 'google_safe_browsing',
        label: 'Commercial Threat Feed Match (Malware / Social Engineering)',
        points: 40,
        isActive: Boolean(threats.length > 0 || hasFlaggedFinding('safe_browsing')),
        detail: threats.length > 0
          ? `Matched on ${threats.map(t => `${t.engine || 'Safe Browsing'} (${t.threatType})`).join(', ')}`
          : 'Zero matches on Google Safe Browsing and commercial feeds',
        explainerTopic: 'google_safe_browsing',
      },
      {
        id: 'exfiltration_sink',
        label: 'Outbound Exfiltration Sink / Command & Control Endpoint',
        points: 50,
        isActive: Boolean(sandbox.linkXRay?.exfiltrationSinksDetected?.length > 0 || hasFlaggedFinding('exfiltration')),
        detail: sandbox.linkXRay?.exfiltrationSinksDetected?.length > 0
          ? `Detected exfiltration endpoint: ${sandbox.linkXRay.exfiltrationSinksDetected.join(', ')}`
          : 'No data exfiltration webhooks or bot relays detected',
        explainerTopic: 'phishing_keywords',
      },
    ],
  }

  // 2. Domain Architecture & Velocity (Max 35 pts)
  const isDomainNew = Boolean(sa.domainAge?.isNewDomain || (sa.domainAge?.available && sa.domainAge.domainAgeDays < 30))
  const isDirectIp = Boolean(sa.isIpBased)
  const isSuspiciousTld = Boolean(sa.hasSuspiciousTld || hasFlaggedFinding('tld'))
  const isTyposquat = Boolean(sa.hasTyposquattingSignal || visual.detected || hasFlaggedFinding('typo'))

  const catDomain = {
    id: 'domain_velocity',
    title: 'Domain Architecture & Registration Velocity',
    description: 'Detection of throwaway velocity traps, high-abuse registrar zones, and brand impersonation lures.',
    maxPossiblePoints: 40,
    rules: [
      {
        id: 'domain_age',
        label: 'Domain Registration Velocity Trap (< 30 Days)',
        points: 25,
        isActive: isDomainNew,
        detail: sa.domainAge?.available
          ? `Domain registered ${sa.domainAge.domainAgeDays} days ago`
          : (isDomainNew ? 'Recently registered domain identified' : 'Verified historical registration'),
        explainerTopic: 'domain_age',
      },
      {
        id: 'typosquatting',
        label: 'Visual Lookalike / Brand Impersonation Domain',
        points: 25,
        isActive: isTyposquat,
        detail: visual.detected
          ? `Masquerading as ${visual.brand} (${Math.round((visual.similarityScore || 0) * 100)}% visual match)`
          : (isTyposquat ? 'Confusable homograph or typosquatting signature detected' : 'Authentic domain anatomy'),
        explainerTopic: 'typosquatting',
      },
      {
        id: 'suspicious_tld',
        label: 'High-Abuse / Suspicious TLD Zone',
        points: 15,
        isActive: isSuspiciousTld,
        detail: isSuspiciousTld ? `Domain zone .${sa.tld} has high historical abuse ratio` : `Standard top-level domain (.${sa.tld || 'com'})`,
        explainerTopic: 'suspicious_tld',
      },
      {
        id: 'ip_host',
        label: 'Direct IP Routing (Bypassing Named DNS)',
        points: 20,
        isActive: isDirectIp,
        detail: isDirectIp ? 'Raw IP host address in URL without legitimate hostname' : 'Valid DNS hostname resolution',
        explainerTopic: 'ip_host',
      },
    ],
  }

  // 3. Infrastructure & Network Topology (Max 35 pts)
  const isBulletproofAsn = Boolean(infra.asnInfo?.isHighAbuse || hasFlaggedFinding('bulletproof'))
  const isFastFlux = Boolean(infra.dnsAudit?.fastFluxDetected || hasFlaggedFinding('fast_flux'))
  const isRecentSsl = Boolean(ssl.isVeryRecent || (ssl.certAgeHours !== undefined && ssl.certAgeHours < 48) || hasFlaggedFinding('ssl'))

  const catInfrastructure = {
    id: 'infrastructure',
    title: 'Infrastructure & Network Topology',
    description: 'Detection of bulletproof hosting providers, fast-flux DNS rotation, and freshly minted certificates.',
    maxPossiblePoints: 35,
    rules: [
      {
        id: 'bulletproof_asn',
        label: 'Bulletproof / High-Abuse Autonomous System (ASN)',
        points: 25,
        isActive: isBulletproofAsn,
        detail: infra.asnInfo?.asn
          ? `AS${infra.asnInfo.asn} (${infra.asnInfo.org || 'Host'}) flagged for cybercrime tolerance`
          : (isBulletproofAsn ? 'Autonomous System associated with persistent abuse' : 'Reputable enterprise network operator'),
        explainerTopic: 'bulletproof_asn',
      },
      {
        id: 'ssl_recency',
        label: 'Brand-New SSL/TLS Certificate (< 48 Hours)',
        points: 20,
        isActive: isRecentSsl,
        detail: isRecentSsl
          ? `Certificate issued ${ssl.certAgeHours ?? '< 24'} hours ago`
          : 'Mature, regularly renewed encryption certificate',
        explainerTopic: 'ssl_recency',
      },
      {
        id: 'fast_flux',
        label: 'Fast-Flux DNS Volatility / Rapid IP Rotation',
        points: 20,
        isActive: isFastFlux,
        detail: isFastFlux ? 'Multiple volatile A-records rotating with low TTL (< 300s)' : 'Stable, static DNS infrastructure',
        explainerTopic: 'fast_flux',
      },
    ],
  }

  // 4. Payload & Deep DOM Sniffer (Max 50 pts)
  const isWeb3Drainer = Boolean(web3.hasWeb3Drainer || hasFlaggedFinding('web3'))
  const isMaliciousDownload = Boolean(payloads.isMaliciousDownload || hasFlaggedFinding('executable') || hasFlaggedFinding('download'))
  const hasFakeForm = Boolean(sandbox.fakeLoginForms?.length > 0 || hasFlaggedFinding('form') || hasFlaggedFinding('credential'))
  const hasClickjacking = Boolean(sandbox.payloadInspection?.clickjacking?.hasClickjackingOverlays || hasFlaggedFinding('clickjacking'))
  const hasLurePhrases = Boolean(sandbox.matchedKeywords?.length > 0 || sandbox.extractedText?.lureHits?.length > 0 || hasFlaggedFinding('phishing'))

  const catPayloadDom = {
    id: 'payload_dom',
    title: 'Payload Inspection & DOM Sniffer',
    description: 'Passive audit of client-side forms, Web3 smart contract calls, clickjacking traps, and executable downloads.',
    maxPossiblePoints: 50,
    rules: [
      {
        id: 'web3_drainer',
        label: 'Web3 Permit2 / Blind-Signing Wallet Drainer',
        points: 40,
        isActive: isWeb3Drainer,
        detail: isWeb3Drainer ? 'Embedded contract call scripts requesting unconstrained token allowances' : 'Zero Web3 drainer signatures found',
        explainerTopic: 'web3_drainer',
      },
      {
        id: 'drive_by_download',
        label: 'Drive-by Executable or Double-Extension Trap (.pdf.exe)',
        points: 45,
        isActive: isMaliciousDownload,
        detail: isMaliciousDownload ? 'Direct executable download triggered without explicit user gesture' : 'No automatic binary downloads detected',
        explainerTopic: 'drive_by_download',
      },
      {
        id: 'fake_login_form',
        label: 'Deceptive Credential Harvester / Insecure Login Form',
        points: 35,
        isActive: hasFakeForm,
        detail: hasFakeForm ? 'HTML form capturing password/identity targeting external endpoint' : 'No deceptive credential forms present',
        explainerTopic: 'fake_login_form',
      },
      {
        id: 'clickjacking_overlay',
        label: 'Clickjacking Transparent Overlay Trap',
        points: 25,
        isActive: hasClickjacking,
        detail: hasClickjacking ? 'Invisible high z-index overlay layer covering viewport' : 'Standard DOM presentation layering',
        explainerTopic: 'clickjacking_overlay',
      },
      {
        id: 'phishing_keywords',
        label: 'High-Density Phishing & Urgency Lure Phrases',
        points: 20,
        isActive: hasLurePhrases,
        detail: hasLurePhrases ? 'High concentration of artificial urgency keywords (e.g. "Account Suspended")' : 'Neutral linguistic tone in DOM text',
        explainerTopic: 'phishing_keywords',
      },
    ],
  }

  // 5. Structural Deception & Obfuscation (Max 30 pts)
  const isShortener = Boolean(redirect.passedThroughShortener || redirect.hops?.some(h => h.isShortener))
  const isSchemeDowngrade = Boolean(redirect.hops?.some(h => h.isDowngrade) || hasFlaggedFinding('downgrade'))
  const isHighEntropy = Boolean(sa.hasHighEntropy || (sandbox.urlEntropyScore && sandbox.urlEntropyScore > 3.8) || hasFlaggedFinding('entropy'))

  const catStructure = {
    id: 'structural_deception',
    title: 'Structural Deception & Redirection Obfuscation',
    description: 'Analysis of Shannon character entropy, homoglyph confusables, and multi-hop cloaking.',
    maxPossiblePoints: 30,
    rules: [
      {
        id: 'redirect_chain',
        label: 'Multi-Hop Obfuscated Redirect Shortener',
        points: 15,
        isActive: isShortener,
        detail: isShortener ? `URL routed through shortener gateway (${redirect.hops?.length || 2} hops)` : 'Direct terminal URL endpoint',
        explainerTopic: 'redirect_chain',
      },
      {
        id: 'scheme_downgrade',
        label: 'Cryptographic Protocol Downgrade (HTTPS → HTTP)',
        points: 25,
        isActive: isSchemeDowngrade,
        detail: isSchemeDowngrade ? 'Insecure redirect stripped TLS encryption in transit' : 'Secure HTTPS maintained across all hops',
        explainerTopic: 'scheme_downgrade',
      },
      {
        id: 'entropy_homograph',
        label: 'High Character Entropy / Unicode Confusable Script',
        points: 15,
        isActive: isHighEntropy,
        detail: isHighEntropy ? 'Excessive randomized entropy indicates obfuscated payload string' : 'Standard lexical structure',
        explainerTopic: 'typosquatting',
      },
    ],
  }

  const allCategories = [catThreatIntel, catDomain, catInfrastructure, catPayloadDom, catStructure]

  // Calculate active points and aggregate active deductions
  let rawCalculatedScore = 0
  let activeRuleCount = 0
  let totalRulesAudited = 0
  const activeDeductionsList = []

  allCategories.forEach(cat => {
    let catActivePoints = 0
    cat.rules.forEach(rule => {
      totalRulesAudited += 1
      if (rule.isActive) {
        catActivePoints += rule.points
        activeRuleCount += 1
        activeDeductionsList.push({
          ...rule,
          categoryTitle: cat.title,
          categoryId: cat.id,
        })
      }
    })
    cat.activePoints = catActivePoints
    rawCalculatedScore += catActivePoints
  })

  // The actual risk score in result is clamped between 0 and 100
  const backendRiskScore = sandbox.riskScore ?? result.riskScore ?? 0
  const compositeScore = Math.max(backendRiskScore, Math.min(100, rawCalculatedScore))

  return {
    rawCalculatedScore,
    compositeScore,
    activePointsTotal: rawCalculatedScore,
    activeRuleCount,
    totalRulesAudited,
    categories: allCategories,
    activeDeductionsList,
  }
}
