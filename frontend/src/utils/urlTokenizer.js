/**
 * URL Tokenizer for Interactive Link Dissector (Pillar 6.1)
 * Deconstructs raw and normalized URLs into typed semantic tokens with security risk classifications.
 */

export function parseAndClassifyTokens(rawUrl, structureAnalysis = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return []
  }

  const tokens = []
  const sa = structureAnalysis || {}
  const userinfoData = sa.userinfoAnalysis || {}
  const ipObf = sa.ipObfuscation || {}
  const idn = sa.idnAnalysis || {}
  const redirectData = sa.redirectAnalysis || {}

  let urlString = rawUrl.trim()

  // 1. Extract Scheme
  let scheme = ''
  const schemeMatch = urlString.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)/)
  if (schemeMatch) {
    scheme = schemeMatch[1]
    const schemeLower = scheme.toLowerCase()
    let schemeRisk = 'safe'
    let schemeLabel = 'SCHEME'
    let schemeExp = 'Encrypted HTTPS protocol verifying server identity and encrypting data in transit.'

    if (schemeLower.startsWith('http://')) {
      schemeRisk = 'warning'
      schemeExp = 'Unencrypted HTTP connection. Passwords, session cookies, and sensitive inputs can be intercepted in transit.'
    } else if (schemeLower.startsWith('javascript:') || schemeLower.startsWith('data:')) {
      schemeRisk = 'danger'
      schemeLabel = 'DANGEROUS PROTOCOL'
      schemeExp = 'Executable or inline data protocol capable of running arbitrary scripts immediately.'
    }

    tokens.push({
      type: 'scheme',
      rawText: scheme,
      label: schemeLabel,
      riskLevel: schemeRisk,
      explanation: schemeExp,
      isDeceptive: false,
    })
    urlString = urlString.slice(scheme.length)
  }

  // 2. Extract Authority (Userinfo + Host + Port) vs Path/Query
  let authority = ''
  let pathAndQuery = ''
  const slashIdx = urlString.indexOf('/')
  const questionIdx = urlString.indexOf('?')

  let pathSplitIdx = -1
  if (slashIdx !== -1 && questionIdx !== -1) {
    pathSplitIdx = Math.min(slashIdx, questionIdx)
  } else if (slashIdx !== -1) {
    pathSplitIdx = slashIdx
  } else if (questionIdx !== -1) {
    pathSplitIdx = questionIdx
  }

  if (pathSplitIdx !== -1) {
    authority = urlString.slice(0, pathSplitIdx)
    pathAndQuery = urlString.slice(pathSplitIdx)
  } else {
    authority = urlString
    pathAndQuery = ''
  }

  // 3. Userinfo (@ deception)
  let hostAndPort = authority
  if (authority.includes('@')) {
    const atIdx = authority.lastIndexOf('@')
    const userinfo = authority.slice(0, atIdx)
    hostAndPort = authority.slice(atIdx + 1)

    const isDeceptive = Boolean(userinfoData.flagged || userinfo.includes('.com') || userinfo.includes('login'))
    tokens.push({
      type: 'userinfo',
      rawText: `${userinfo}@`,
      label: isDeceptive ? 'CRITICAL SPOOF' : 'USERINFO',
      riskLevel: 'danger',
      explanation: isDeceptive
        ? `DECEPTIVE BAIT: Attackers place trusted brand names ('${userinfo}') before the '@' symbol. Browsers completely ignore this prefix and route you to the host following the '@'.`
        : `Embedded authentication credentials/userinfo: '${userinfo}'.`,
      isDeceptive: true,
    })
  }

  // 4. Host and Port
  let host = hostAndPort
  let port = ''
  const portMatch = hostAndPort.match(/:(\d+)$/)
  if (portMatch) {
    port = portMatch[1]
    host = hostAndPort.slice(0, -portMatch[0].length)
  }

  // 5. Break down Host into Subdomains, SLD, TLD
  const isIp = Boolean(sa.isIpBased || /^\d+\.\d+\.\d+\.\d+$/.test(host))
  const isObfuscatedIp = Boolean(ipObf.isObfuscated)

  if (isObfuscatedIp) {
    tokens.push({
      type: 'domain',
      rawText: host,
      label: 'OBFUSCATED IP',
      riskLevel: 'danger',
      explanation: `Attackers encoded the IP as an alternate format (${ipObf.format || 'numeric'}) resolving to canonical IP '${ipObf.decodedIp}'.`,
      isDeceptive: true,
    })
  } else if (isIp) {
    tokens.push({
      type: 'domain',
      rawText: host,
      label: 'RAW IP HOST',
      riskLevel: 'warning',
      explanation: 'The link points to a raw IP address instead of a domain name, bypassing domain reputation registries.',
      isDeceptive: false,
    })
  } else {
    // Normal domain breakdown
    const parts = host.split('.')
    if (parts.length > 2) {
      const subdomains = parts.slice(0, -2).join('.')
      const sld = parts[parts.length - 2]
      const tld = parts[parts.length - 1]

      const hasSubdomainSpoof = /paypal|microsoft|google|apple|chase|bank|login|secure|verify/i.test(subdomains)
      tokens.push({
        type: 'subdomain',
        rawText: `${subdomains}.`,
        label: hasSubdomainSpoof ? 'DECEPTIVE SUBDOMAIN' : 'SUBDOMAIN',
        riskLevel: hasSubdomainSpoof ? 'danger' : 'info',
        explanation: hasSubdomainSpoof
          ? `Subdomain Impersonation: '${subdomains}' mimics a trusted brand, but the real domain operator is registered under '${sld}.${tld}'.`
          : `Subdomain cluster: '${subdomains}'.`,
        isDeceptive: hasSubdomainSpoof,
      })

      const hasTyposquat = Boolean(sa.hasTyposquattingSignal)
      const hasHomograph = Boolean(idn.hasMixedScript || idn.confusableGlyphs?.length)
      const sldRisk = (hasTyposquat || hasHomograph) ? 'danger' : 'safe'

      tokens.push({
        type: 'domain',
        rawText: sld,
        label: hasHomograph ? 'HOMOGRAPH SLD' : (hasTyposquat ? 'TYPOSQUAT SLD' : 'REGISTERED DOMAIN'),
        riskLevel: sldRisk,
        explanation: hasHomograph
          ? `Unicode Confusable: Domain uses look-alike characters mapping to ASCII skeleton '${idn.skeleton || sld}'.`
          : (hasTyposquat ? 'Domain resembles brand name with character substitution.' : `Primary registered second-level domain: '${sld}'.`),
        isDeceptive: hasTyposquat || hasHomograph,
      })

      const isSuspTld = Boolean(sa.hasSuspiciousTld)
      tokens.push({
        type: 'tld',
        rawText: `.${tld}`,
        label: isSuspTld ? 'HIGH-RISK TLD' : 'TLD',
        riskLevel: isSuspTld ? 'warning' : 'safe',
        explanation: isSuspTld
          ? `The top-level domain '.${tld}' has low registration friction and is frequently abused in phishing campaigns.`
          : `Top-level domain: '.${tld}'.`,
        isDeceptive: false,
      })
    } else if (parts.length === 2) {
      const sld = parts[0]
      const tld = parts[1]

      const hasTyposquat = Boolean(sa.hasTyposquattingSignal)
      tokens.push({
        type: 'domain',
        rawText: sld,
        label: hasTyposquat ? 'TYPOSQUAT SLD' : 'REGISTERED DOMAIN',
        riskLevel: hasTyposquat ? 'danger' : 'safe',
        explanation: hasTyposquat ? 'Domain resembles brand name with character substitution.' : `Registered domain: '${sld}'.`,
        isDeceptive: hasTyposquat,
      })

      const isSuspTld = Boolean(sa.hasSuspiciousTld)
      tokens.push({
        type: 'tld',
        rawText: `.${tld}`,
        label: isSuspTld ? 'HIGH-RISK TLD' : 'TLD',
        riskLevel: isSuspTld ? 'warning' : 'safe',
        explanation: isSuspTld ? `Top-level domain '.${tld}' is associated with high phishing abuse.` : `Top-level domain: '.${tld}'.`,
        isDeceptive: false,
      })
    } else {
      tokens.push({
        type: 'domain',
        rawText: host,
        label: 'HOST',
        riskLevel: 'info',
        explanation: `Destination hostname: '${host}'.`,
        isDeceptive: false,
      })
    }
  }

  // 6. Port
  if (port) {
    const isStandard = port === '80' || port === '443'
    tokens.push({
      type: 'port',
      rawText: `:${port}`,
      label: isStandard ? 'STANDARD PORT' : 'NON-STANDARD PORT',
      riskLevel: isStandard ? 'safe' : 'warning',
      explanation: isStandard
        ? `Standard web port ${port}.`
        : `Non-standard network port ${port}. Phishing kits frequently host payloads on non-standard ports to bypass proxies.`,
      isDeceptive: !isStandard,
    })
  }

  // 7. Path and Query
  if (pathAndQuery) {
    const qIdx = pathAndQuery.indexOf('?')
    const pathPart = qIdx !== -1 ? pathAndQuery.slice(0, qIdx) : pathAndQuery
    const queryPart = qIdx !== -1 ? pathAndQuery.slice(qIdx) : ''

    if (pathPart) {
      tokens.push({
        type: 'path',
        rawText: pathPart,
        label: 'PATH',
        riskLevel: 'info',
        explanation: `Resource endpoint path: '${pathPart}'.`,
        isDeceptive: false,
      })
    }

    if (queryPart) {
      const unrolled = redirectData.unrolledParameters || []
      const hasUnrolled = unrolled.length > 0
      tokens.push({
        type: 'param',
        rawText: queryPart,
        label: hasUnrolled ? 'UNROLLED PARAMETER' : 'QUERY PARAMS',
        riskLevel: hasUnrolled ? 'warning' : 'info',
        explanation: hasUnrolled
          ? `Nested destination URL was extracted from parameter '${unrolled[0].param}' (${unrolled[0].encoding}).`
          : `Query string parameters: '${queryPart}'.`,
        isDeceptive: hasUnrolled,
      })
    }
  }

  return tokens
}
