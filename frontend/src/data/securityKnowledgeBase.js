/**
 * securityKnowledgeBase.js
 * 
 * Centralized, non-technical cybersecurity knowledge base for ZEB.
 * Translates complex technical telemetry into relatable, human-readable
 * 4-part guides with real-world analogies, attacker tricks, personal danger assessments,
 * actionable user advice, and live scan telemetry extractors.
 */

export const SECURITY_KNOWLEDGE_BASE = {
  ssl_recency: {
    id: 'ssl_recency',
    title: 'Brand-New Security Certificate (Hours or Days Old)',
    technicalTerm: 'SSL/TLS Certificate Issue Recency',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'An SSL certificate is like a website\'s digital passport or tamper-evident seal. It normally encrypts your connection and confirms the server\'s technical setup. However, having a certificate does NOT mean a website is trustworthy—virtually all modern phishing sites have SSL certificates today! When a certificate was created only hours or days ago, it means the website was set up just moments before you were sent the link.',
      analogy: 'Think of an SSL padlock like a locked door. It keeps eavesdroppers from peeking into the room, but it doesn\'t tell you whether the person inside is a bank teller or a masked robber.',
    },
    theAttackersTrick: 'Cybercriminals spin up fake websites and immediately request free, automated security certificates. Because security agencies take anywhere from 12 to 48 hours to discover and block scam sites, attackers rush to send thousands of phishing texts and emails during those first critical hours before anyone catches them.',
    whatCouldHappenToYou: 'If you type your login password, credit card number, or identity details on this page, the attacker intercepts them directly behind the "secure" green padlock.',
    whatYouShouldDo: 'Never enter passwords or payment details on a website with a certificate issued only hours or days ago. Legitimate services like Google, Microsoft, Amazon, or banks use certificates that have been active and routinely renewed for years.',
    extractTelemetry: (result) => {
      const sa = result?.structureAnalysis || {}
      const infra = sa.infrastructureAnalysis || sa.infrastructure || {}
      const ssl = infra.sslDeep || infra.sslAudit || {}
      const hours = ssl.certAgeHours ?? ssl.ageHours
      const days = ssl.ageDays ?? (hours !== undefined && hours !== null ? Math.floor(hours / 24) : undefined)
      if (hours !== undefined && hours !== null && hours < 48) {
        return `Certificate was issued approximately ${hours} hours ago.`
      }
      if (days !== undefined && days !== null) {
        return `Certificate is only ${days} days old.`
      }
      if (ssl.isVeryRecent) {
        return `Certificate was issued less than 24 hours ago.`
      }
      return null
    },
  },


  domain_age: {
    id: 'domain_age',
    title: 'Freshly Registered Web Address (Zero History)',
    technicalTerm: 'WHOIS Domain Registration Age & Velocity',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'This web address was purchased and registered very recently. Legitimate companies, stores, and online services have existed for months or years. A newly registered domain has zero established reputation on the internet.',
      analogy: 'Imagine a pop-up storefront that appeared overnight in an empty alleyway with no business permit, no registered owner, and cardboard signs. You wouldn\'t hand them your credit card.',
    },
    theAttackersTrick: 'Over 70% of online scams and phishing campaigns use brand-new "disposable" web addresses registered within the past 14 days. Attackers launch a quick blitz, harvest hundreds of passwords or payments, and abandon the website before law enforcement or domain registrars shut them down.',
    whatCouldHappenToYou: 'Extreme risk of entering a credential phishing trap, buying from a fake store that takes your money and disappears, or downloading malicious malware files.',
    whatYouShouldDo: 'If this link claims to come from a major organization (such as PayPal, Netflix, your bank, or a parcel courier like FedEx/USPS), it is virtually guaranteed to be fraudulent. Close the page immediately.',
    extractTelemetry: (result) => {
      const age = result?.structureAnalysis?.domainAge
      if (!age?.available || age.domainAgeDays === undefined) return null
      return `Domain registered only ${age.domainAgeDays} days ago (${age.createdDate || 'Recent'}).`
    },
  },

  typosquatting: {
    id: 'typosquatting',
    title: 'Brand Name Mimic / Lookalike Domain',
    technicalTerm: 'Typosquatting & Deceptive Lookalike Hostname',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'The website address deliberately imitates a well-known, trusted brand by swapping letters, inserting hyphens, or replacing letters with similar-looking characters (such as replacing the letter "o" with the number "0", or "l" with "1").',
      analogy: 'Like counterfeit money or a knockoff watch where the brand name is spelled "Rolox" instead of "Rolex"—designed to trick anyone who glances at it quickly without double-checking.',
    },
    theAttackersTrick: 'Human eyes recognize words by their overall shape rather than reading every character. Scammers register names like "paypa1-security.com" or "arnazon.com" hoping that when you are on your phone or in a rush, you will assume it is the real company.',
    whatCouldHappenToYou: 'Typing your login credentials hands total control of your real account to criminals, leading to identity theft and unauthorized financial transactions.',
    whatYouShouldDo: 'Do not interact with the page. To access your real account, manually type the company\'s official address into your browser address bar or use an official mobile app.',
    extractTelemetry: (result) => {
      const sa = result?.structureAnalysis
      if (sa?.hasTyposquattingSignal) {
        return `Domain '${sa.registeredDomain}' appears to mimic a protected brand.`
      }
      return null
    },
  },

  ip_host: {
    id: 'ip_host',
    title: 'Raw IP Address Instead of a Normal Website Name',
    technicalTerm: 'Direct IP-Based Routing (IPv4/IPv6)',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'Normal websites have readable names like "wikipedia.org". This link uses a raw number sequence (like "192.168.1.1").',
      analogy: 'Like someone asking you to visit a business that has no sign, no street address, and only cryptic GPS coordinates written on a napkin.',
    },
    theAttackersTrick: 'Registering a real domain name leaves a paper trail and costs money. Hackers often host scam tools or malware directly on raw IP addresses to bypass domain security filters and avoid registration identity checks.',
    whatCouldHappenToYou: 'Direct IP links frequently host exploit kits, automated file downloaders, or botnet command servers designed to compromise your device.',
    whatYouShouldDo: 'Never click or enter any information on raw IP links unless you are a network engineer accessing private home equipment on your local network.',
    extractTelemetry: (result) => {
      const hostname = result?.structureAnalysis?.hostname
      if (result?.structureAnalysis?.isIpBased) {
        return `Connecting directly to numeric host: ${hostname}`
      }
      return null
    },
  },

  bulletproof_asn: {
    id: 'bulletproof_asn',
    title: 'Bulletproof / Criminal Hosting Network',
    technicalTerm: 'High-Abuse Autonomous System (ASN)',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'Every website lives on an internet service provider called an Autonomous System (ASN). This website is hosted on a network infamous for harboring criminal cyber-infrastructure and refusing to cooperate with law enforcement or security takedown notices.',
      analogy: 'Imagine a physical building in an unregulated lawless zone that rents office space to pickpockets and counterfeiters while refusing to let the police enter.',
    },
    theAttackersTrick: 'Mainstream hosting companies (like Amazon AWS, Google Cloud, Microsoft Azure) quickly shut down scammers when reported. Professional cybercriminals pay extra money to "bulletproof" hosting providers who promise never to delete their scam operations.',
    whatCouldHappenToYou: 'You are dealing with organized cybercrime syndicates. The site likely hosts malicious downloads, ransomware droppers, or aggressive card-cloning systems.',
    whatYouShouldDo: 'Disconnect immediately. Do not click any links or download anything from this network.',
    extractTelemetry: (result) => {
      const sa = result?.structureAnalysis || {}
      const infra = sa.infrastructureAnalysis || sa.infrastructure || {}
      const asn = infra.asn || infra.asnInfo
      if (asn?.isHighAbuse) {
        return `Hosted on AS${asn.asn} (${asn.org || 'Unverified Provider'}), flagged for extreme abuse tolerance.`
      }
      return null
    },
  },

  fast_flux: {
    id: 'fast_flux',
    title: 'Fast-Flux DNS (Rapid IP-Address Shifting)',
    technicalTerm: 'Fast-Flux DNS Evasion Architecture',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'Normally, a website\'s address points steadily to one or two reliable servers. Fast-Flux means the website is rapidly changing its underlying server address every few minutes across dozens of compromised computers worldwide.',
      analogy: 'Like a fugitive constantly switching cars, burner phones, and disguises every 5 minutes to stay one step ahead of the authorities.',
    },
    theAttackersTrick: 'When security teams discover a scam site, they block the server\'s IP address. Fast-Flux uses a revolving network of infected home and office computers as relays, making it extremely difficult for cybersecurity teams to take the site down.',
    whatCouldHappenToYou: 'Indicates high-level malware distribution, banking trojans, or international ransomware rings.',
    whatYouShouldDo: 'Close your browser tab immediately. Do not accept any software updates or browser permission prompts from this website.',
    extractTelemetry: (result) => {
      const sa = result?.structureAnalysis || {}
      const infra = sa.infrastructureAnalysis || sa.infrastructure || {}
      const dns = infra.dns || infra.dnsAudit
      if (dns?.fastFluxDetected) {
        return `Detected ${dns.ipCount || 'multiple'} rapidly revolving IP addresses with short TTL.`
      }
      return null
    },

  },

  redirect_chain: {
    id: 'redirect_chain',
    title: 'Hidden Redirect Bounces & Shortener Traps',
    technicalTerm: 'Obfuscated Multi-Hop Redirect Chain',
    severity: 'MEDIUM',
    inPlainEnglish: {
      definition: 'The link you clicked is not the real destination—it quickly bounces your browser through multiple secret jumps and shorteners before landing on the final page.',
      analogy: 'Like getting into a taxi that drives through 3 different dark alleys and changes license plates before dropping you off at an unexpected location.',
    },
    theAttackersTrick: 'Automated scanners often only check the first link, which looks innocent (like bit.ly or a trusted URL shortener). Once approved, the link redirects humans to a dangerous phishing or malware page that was hidden from the initial test.',
    whatCouldHappenToYou: 'You end up on a malicious page without realizing you were steered away from the site you intended to visit.',
    whatYouShouldDo: 'Check the "Resolved Final Destination" shown in ZEB. Only proceed if you trust that final destination address.',
    extractTelemetry: (result) => {
      const red = result?.structureAnalysis?.redirectAnalysis
      if (red?.hopCount > 1 || red?.tooManyRedirects) {
        return `Traversed ${red.hopCount} redirect jumps to reach: ${red.finalUrl}`
      }
      return null
    },
  },

  scheme_downgrade: {
    id: 'scheme_downgrade',
    title: 'Insecure Encryption Downgrade (HTTPS to HTTP)',
    technicalTerm: 'Cross-Scheme SSL Stripping',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'The link started out looking secure (with "https://"), but along the way it quietly stripped away encryption and switched to raw, unencrypted "http://".',
      analogy: 'Like starting a phone conversation on a secure scrambler phone, then someone secretly switching you over to a public loudspeaker.',
    },
    theAttackersTrick: 'Stripping away encryption allows bad actors on your local Wi-Fi (such as in coffee shops, hotels, or airports) to spy on everything you view and type without needing a counterfeit certificate.',
    whatCouldHappenToYou: 'Anyone sharing your internet connection can capture your passwords, read your private messages, or inject rogue advertisements into the page.',
    whatYouShouldDo: 'Never type passwords or payment information on an unencrypted "http://" website.',
    extractTelemetry: (result) => {
      const hops = result?.structureAnalysis?.redirectAnalysis?.hops || []
      const downgrade = hops.some(h => h.schemeDowngrade)
      if (downgrade) {
        return 'Connection secretly dropped security encryption during redirect hops.'
      }
      return null
    },
  },

  phishing_keywords: {
    id: 'phishing_keywords',
    title: 'Manufactured Panic & Phishing Urgency Words',
    technicalTerm: 'Social Engineering Keyword Pressure Indicators',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'The page or address uses high-pressure words like "Account Suspended", "Action Required Immediately", "Unauthorized Transaction Detected", or "Verify Within 24 Hours".',
      analogy: 'Like a street swindler yelling that your jacket is on fire so that you panic and take it off, handing it over with your wallet inside.',
    },
    theAttackersTrick: 'Scammers deliberately make you panic so that your adrenaline spikes and your critical thinking turns off. When people are frightened of losing money or access, they are far more likely to type their password without checking the website address.',
    whatCouldHappenToYou: 'Falling victim to credential harvesting or phone-based refund/helpdesk scams.',
    whatYouShouldDo: 'Stop and breathe. Legitimate organizations never send panicked 10-minute ultimatums. Open your official banking or email app directly to check your true status.',
    extractTelemetry: (result) => {
      const kw = result?.structureAnalysis?.sandboxPreview?.matchedKeywords
      if (kw && kw.length > 0) {
        return `Found urgency keywords: ${kw.slice(0, 4).join(', ')}`
      }
      return null
    },
  },

  fake_login_form: {
    id: 'fake_login_form',
    title: 'Deceptive Login Form / Credential Trap',
    technicalTerm: 'Unauthorized Credential-Harvesting Form Action',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'The website displays username and password boxes, but when you click "Sign In", your details are secretly transmitted to an unauthorized external server rather than the real company.',
      analogy: 'Like a fake ATM machine installed on a street corner that swallows your card and PIN while displaying a fake "Out of Order" message.',
    },
    theAttackersTrick: 'Attackers create a pixel-perfect replica of a familiar login screen (e.g. Microsoft 365, Google, Apple ID). When submitted, the form sends your password directly to the attacker\'s database before redirecting you to the real website so you suspect nothing.',
    whatCouldHappenToYou: 'Immediate takeover of your account, password theft across other sites where you use the same password, and unauthorized access to your private emails and photos.',
    whatYouShouldDo: 'DO NOT enter your password. If you already typed it, go immediately to the real company\'s website, change your password, and enable Two-Factor Authentication (2FA).',
    extractTelemetry: (result) => {
      const forms = result?.structureAnalysis?.sandboxPreview?.fakeLoginForms
      if (forms && forms.length > 0) {
        return `Found login form submitting credentials to foreign endpoint: ${forms[0]?.action || 'External target'}`
      }
      return null
    },
  },

  web3_drainer: {
    id: 'web3_drainer',
    title: 'Crypto Wallet Drainer Script',
    technicalTerm: 'Malicious Web3 Smart Contract Approval Trap',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'This website contains malicious scripts designed to connect to your cryptocurrency wallet (such as MetaMask, Phantom, or Coinbase Wallet) and trick you into signing an "Unlimited Approval" transaction.',
      analogy: 'Like handing a complete stranger a signed blank check giving them legal permission to empty your entire bank account.',
    },
    theAttackersTrick: 'Scammers advertise free cryptocurrency airdrops, exclusive NFT mints, or investment rewards. The wallet approval popup looks harmless (e.g. "Permit2" or "Sign to verify"), but technically authorises a smart contract to sweep all tokens out of your wallet in a fraction of a second.',
    whatCouldHappenToYou: 'Instant, irreversible loss of all crypto tokens and NFTs stored in your connected wallet. Because blockchain transactions are permanent, lost funds cannot be recovered.',
    whatYouShouldDo: 'Reject any transaction or connection requests immediately. Never sign approvals on websites discovered via Discord, Telegram, or Twitter direct messages.',
    extractTelemetry: (result) => {
      const w3 = result?.structureAnalysis?.sandboxPreview?.domThreats?.web3Signatures
      if (w3?.hasWeb3Drainer) {
        return `Identified wallet draining signatures: ${w3.detectedPatterns?.join(', ') || 'Permit2 / eth_sign'}`
      }
      return null
    },
  },

  drive_by_download: {
    id: 'drive_by_download',
    title: 'Deceptive File Download / Malicious Payload',
    technicalTerm: 'Drive-By Download & Masquerading Extension',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'The website attempts to automatically download a dangerous program onto your computer, or disguises a harmful software program with a fake file extension (like "receipt.pdf.exe").',
      analogy: 'Like receiving a parcel labelled "Holiday Photo Album" that actually contains a surveillance camera or lock-picker.',
    },
    theAttackersTrick: 'Attackers know that operating systems sometimes hide file extensions by default, so a file named "Invoice.pdf.exe" only displays as "Invoice.pdf". If you double-click it expecting a document, an executable virus runs silently in the background.',
    whatCouldHappenToYou: 'Ransomware locking all your files and demanding ransom, keyloggers recording every password you type, or remote hackers accessing your webcam and files.',
    whatYouShouldDo: 'If a file downloaded automatically, do NOT open it! Go to your Downloads folder and delete it immediately. Run an antivirus scan on your system.',
    extractTelemetry: (result) => {
      const dl = result?.structureAnalysis?.sandboxPreview?.domThreats?.payloadDownloads
      if (dl?.isMaliciousDownload) {
        return `Dangerous payload flags detected: ${dl.flags?.join(', ') || 'Executable masquerading'}`
      }
      return null
    },
  },

  clickjacking_overlay: {
    id: 'clickjacking_overlay',
    title: 'Invisible Click Trap (Clickjacking)',
    technicalTerm: 'Hidden Transparent Pointer Overlay (Clickjacking)',
    severity: 'HIGH',
    inPlainEnglish: {
      definition: 'The page places an invisible, transparent layer over the screen. When you think you are clicking a harmless button or playing a video, your click is secretly redirected to an action underneath.',
      analogy: 'Like placing a clear sheet of glass with fake buttons over an expensive purchase contract so that when you press "Play", you actually authorize a charge.',
    },
    theAttackersTrick: 'Deceptive websites overlay invisible frames over social media, email, or shopping sessions to trick you into liking posts, transferring money, or granting account permissions without knowing it.',
    whatCouldHappenToYou: 'Unintended account authorizations, accidental purchases, or malware downloads.',
    whatYouShouldDo: 'Do not click anywhere on the page. Close the browser tab directly using keyboard shortcuts (Ctrl+W or Cmd+W) or the browser tab "X".',
    extractTelemetry: (result) => {
      const ov = result?.structureAnalysis?.sandboxPreview?.domThreats?.credentialHarvesters?.hiddenOverlays
      if (ov && ov.length > 0) {
        return `Found ${ov.length} invisible transparent overlay layer(s) hijacking user clicks.`
      }
      return null
    },
  },

  suspicious_tld: {
    id: 'suspicious_tld',
    title: 'High-Abuse Domain Ending (.top, .xyz, .click, etc.)',
    technicalTerm: 'Abused Top-Level Domain Extension (TLD)',
    severity: 'MEDIUM',
    inPlainEnglish: {
      definition: 'The ending of the web address (the Top-Level Domain) is an extension overwhelmingly favored by scammers because it costs only pennies to buy and has virtually no identity verification.',
      analogy: 'Like receiving official banking correspondence written on scrap cardboard rather than branded corporate stationery.',
    },
    theAttackersTrick: 'While legitimate companies invest in established .com, .org, or official country domains, scammers buy hundreds of $0.50 disposable domains across obscure extensions to blast spam before being taken down.',
    whatCouldHappenToYou: 'Higher probability of counterfeit goods, sweepstakes scams, or malicious redirect portals.',
    whatYouShouldDo: 'Be skeptical. If your real bank or service normally uses .com or an official country domain (like .co.uk), an address using .top, .buzz, or .click is almost certainly an impersonation.',
    extractTelemetry: (result) => {
      const sa = result?.structureAnalysis
      if (sa?.hasSuspiciousTld) {
        return `Domain ends with '.${sa.tld}', a zone heavily associated with automated spam campaigns.`
      }
      return null
    },
  },

  google_safe_browsing: {
    id: 'google_safe_browsing',
    title: 'Confirmed Malicious on Global Threat Databases',
    technicalTerm: 'Google Safe Browsing & Verified Threat Intelligence Match',
    severity: 'CRITICAL',
    inPlainEnglish: {
      definition: 'This specific website has already been discovered, analyzed, and officially blacklisted by international cybersecurity organizations and Google\'s Safe Browsing network.',
      analogy: 'Like a criminal whose photo is on the Most Wanted board at every police station—there is no doubt they are active and dangerous.',
    },
    theAttackersTrick: 'This link has been caught in the act of distributing malware, stealing passwords via phishing, or tricking users into installing deceptive software.',
    whatCouldHappenToYou: 'Severe damage to your device, stolen passwords, or compromised bank accounts.',
    whatYouShouldDo: 'Do NOT visit this website under any circumstances. If someone sent you this link, warn them that their account may be hacked.',
    extractTelemetry: (result) => {
      const threats = result?.threats
      if (threats && threats.length > 0) {
        return `Matches verified threat: ${threats.map(t => t.threatType).join(', ')}`
      }
      return null
    },
  },
}

/**
 * Helper to identify all knowledge base topics that were flagged
 * as suspicious or critical in the current scan result.
 */
export function getDetectedTopicsForScan(result) {
  if (!result) return []
  const sa = result.structureAnalysis || {}
  const infra = sa.infrastructureAnalysis || sa.infrastructure || {}
  const ssl = infra.sslDeep || infra.sslAudit || {}
  const asn = infra.asn || infra.asnInfo || {}
  const dns = infra.dns || infra.dnsAudit || {}
  const sandbox = sa.sandboxPreview || {}
  const domThreats = sandbox.domThreats || {}
  const redirect = sa.redirectAnalysis || {}

  const detected = []

  // Safe Browsing / Threat intel
  if (result.threats?.length > 0) {
    detected.push('google_safe_browsing')
  }

  // Typosquatting
  if (sa.hasTyposquattingSignal) {
    detected.push('typosquatting')
  }

  // Raw IP Host
  if (sa.isIpBased) {
    detected.push('ip_host')
  }

  // Fresh SSL
  if (ssl.isVeryRecent) {
    detected.push('ssl_recency')
  }

  // New Domain
  if (sa.domainAge?.isNewDomain) {
    detected.push('domain_age')
  }

  // Bulletproof ASN
  if (asn.isHighAbuse) {
    detected.push('bulletproof_asn')
  }

  // Fast-Flux DNS
  if (dns.fastFluxDetected) {
    detected.push('fast_flux')
  }


  // Web3 Drainer
  if (domThreats.web3Signatures?.hasWeb3Drainer) {
    detected.push('web3_drainer')
  }

  // Malicious download
  if (domThreats.payloadDownloads?.isMaliciousDownload) {
    detected.push('drive_by_download')
  }

  // Fake Login Form
  if (sandbox.fakeLoginForms?.length > 0) {
    detected.push('fake_login_form')
  }

  // Clickjacking Overlay
  if (domThreats.credentialHarvesters?.hiddenOverlays?.length > 0) {
    detected.push('clickjacking_overlay')
  }

  // Phishing keywords
  if (sandbox.matchedKeywords?.length > 0) {
    detected.push('phishing_keywords')
  }

  // Redirect hops / shortener
  if (redirect.tooManyRedirects || redirect.passedThroughShortener || redirect.hops?.length > 2) {
    detected.push('redirect_chain')
  }

  // HTTPS downgrade
  if (redirect.hops?.some(h => h.schemeDowngrade)) {
    detected.push('scheme_downgrade')
  }

  // Suspicious TLD
  if (sa.hasSuspiciousTld) {
    detected.push('suspicious_tld')
  }

  // Deduplicate preserving order
  return Array.from(new Set(detected))
}
