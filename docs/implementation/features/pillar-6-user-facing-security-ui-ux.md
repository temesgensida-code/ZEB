# Feature Implementation Spec: Pillar 6 User-Facing Security UI/UX Improvements

## 1. Executive Summary & Design Principles

### 1.1 Problem Statement
A URL security scanner is only as effective as the end-user's ability to comprehend the risks and take informed defensive action:
1. **Opaque Link Presentation**: Users view URLs as monolithic strings. They cannot distinguish the difference between a subdomain prefix (`paypal.com.attacker.xyz`) and the true registered root domain (`attacker.xyz`), making them highly vulnerable to deceptive subdomain clustering and userinfo spoofing.
2. **Fear of Malicious Content vs Need for Inspection**: Security analysts, incident responders, and curious users often need to see what a suspicious webpage looks like or read its contents to confirm a phishing campaign, but loading the site in their local browser risks drive-by malware downloads, zero-day browser exploits, or pixel-tracking beacons.
3. **Accidental Clicks in Collaboration Channels**: When users share links with IT teams, colleagues, or ticketing systems (Slack, Teams, Jira), chat platforms automatically fetch rich link unfurlings, triggering the phishing site or risking accidental user clicks.
4. **Tedious Manual Reporting**: SOC analysts spend hours manually copying IOCs (IPs, domains, hashes, redirect chains) into incident tickets instead of exporting standardized STIX/JSON or formatted Markdown threat dossiers.

### 1.2 Target Objectives
- **Interactive "Link Dissector" (Visual Anatomy Breakdown)**: Decompose any URL into color-coded, interactive tokens (Scheme, Userinfo, Subdomains, Registered Domain, TLD, Port, Path, and Decoded Query Parameters) with contextual educational tooltips.
- **Safe Cloud Previewer & Isolated Text Stripper**:
  - **Sanitized Cloud Screenshot Modal**: View the cloud-rendered page visually as a static WebP/PNG with complete isolation from client-side scripts, cookies, or trackers.
  - **De-Scripted Text-Only DOM Reader ("Safe Text Mode")**: View the raw semantic text of the page with highlighted phishing lure phrases, stripped of all executable scripts and tracking pixels.
- **Defanged IOC Sharing & Multi-Format Incident Exporters**:
  - One-click **Defanged Copy** (`hxxps[://]domain[.]xyz/path`).
  - **Markdown Incident Dossier**: One-click formatted report optimized for Jira/GitHub/Notion.
  - **STIX 2.1 / JSON Export**: Standardized threat intelligence bundle ready for direct ingestion into SIEM/SOAR platforms (Splunk, Elastic, Sentinel).

---

## 2. Pillar 6 Architecture & Component Hierarchy

```mermaid
flowchart TD
    ScanData["Consolidated Scan Result Payload<br/>(URL, Verdict, Exposure, Infrastructure, Threat Intel)"] --> ResultsContainer["ResultsView (App.jsx)"]
    
    subgraph UIComponents["User-Facing Security Components"]
        ResultsContainer --> LinkDissector["6.1 Interactive Link Dissector<br/>(Tokenized Visual Anatomy Bar)"]
        ResultsContainer --> SafeSandboxViewer["6.2 Safe Preview & Isolated Sandbox"]
        ResultsContainer --> ExportToolbar["6.3 Action Toolbar & Incident Exporter"]
    end

    subgraph DissectorTokens["Link Dissector Token Grid"]
        LinkDissector --> TokScheme["Scheme: https:// (Encrypted / Clean)"]
        LinkDissector --> TokUserinfo["Userinfo: Spoofed Brand Bait (Red Alert)"]
        LinkDissector --> TokSubdomain["Subdomain: paypal.security (Deceptive)"]
        LinkDissector --> TokSLD["Domain (SLD): attacker-host (Impersonator)"]
        LinkDissector --> TokTLD["TLD: .xyz (High-Abuse Registry)"]
        LinkDissector --> TokPort["Port: :8080 (Non-Standard)"]
        LinkDissector --> TokParams["Query Parameters: Decoded & Unnested Chips"]
    end

    subgraph SandboxModes["Safe Inspection Modes"]
        SafeSandboxViewer --> VisualPreview["Sanitized Visual Screenshot Viewer<br/>(Zero JS, Zero Cookies, Cloud Rendered)"]
        SafeSandboxViewer --> TextStripper["De-Scripted Safe Text Reader<br/>(Markdown View + Lure Phrase Highlighting)"]
    end

    subgraph ExportFormats["Incident Export Formats"]
        ExportToolbar --> CopyDefang["One-Click Defanged Copy<br/>(hxxps[://]attacker[.]com/path)"]
        ExportToolbar --> ExportMD["Copy Markdown Incident Dossier<br/>(For Jira, Slack, Teams)"]
        ExportToolbar --> ExportSTIX["Download STIX 2.1 / JSON Bundle<br/>(For SIEM / SOAR Ingestion)"]
    end
```

---

## 3. Sub-Pillar 6.1: Interactive "Link Dissector" (URL Anatomy Breakdown)

### 3.1 Token Decomposition Specifications
The Link Dissector decomposes a raw or normalized URL into discrete semantic chunks:

```
[ https:// ] [ paypal.com:update@ ] [ account.security ] . [ login-verification ] . [ xyz ] : [ 8080 ] / [ webscr?dest=... ]
   Scheme        Userinfo Bait        Subdomain Cluster          SLD (Domain)         TLD      Port           Path & Query
  (Secure)     (CRITICAL SPOOF)     (DECEPTIVE PREFIX)        (BRAND LOOKALIKE)    (HIGH ABUSE) (RISK)       (UNROLLED PARAM)
```

#### Token Metadata Schema
```typescript
interface DissectedToken {
  type: 'scheme' | 'userinfo' | 'subdomain' | 'domain' | 'tld' | 'port' | 'path' | 'param';
  rawText: string;
  decodedText?: string;
  riskLevel: 'safe' | 'info' | 'warning' | 'danger';
  label: string;
  explanation: string;
  isDeceptive: boolean;
}
```

### 3.2 Token Evaluation Rules
1. **Scheme**:
   - `https://`: Safe (Green) — "TLS encrypted connection".
   - `http://`: Warning (Amber) — "Unencrypted connection; credentials can be intercepted".
   - `javascript:` / `data:`: Danger (Red) — "Dangerous protocol capable of immediate code execution".
2. **Userinfo Bait**:
   - Present with `@`: Danger (Red) — *"Deceptive Credentials! Attackers place 'paypal.com' before the '@' sign to trick you. Browsers discard this and visit the domain after the '@'."*
3. **Subdomain Cluster**:
   - Contains Brand Keywords: Danger (Red) — *"Subdomain Impersonation: 'paypal' is placed inside a subdomain prefix to deceive users. The actual domain operator is the entity following this segment."*
   - Excessive Dots ($> 3$ subdomains): Warning (Amber) — *"High subdomain depth often used in domain generation algorithms (DGAs)."*
4. **Second-Level Domain (SLD)**:
   - Matches Typosquatting / Homograph: Danger (Red) — *"Resembles target brand with character substitutions."*
   - Obfuscated IP: Danger (Red) — *"Raw or obfuscated IP address instead of domain name."*
5. **Top-Level Domain (TLD)**:
   - In `SUSPICIOUS_TLDS`: Warning (Amber) — *"Top-level domain '.{tld}' is associated with free registries and high rates of malicious campaigns."*
6. **Query Parameters**:
   - Each parameter rendered as a distinct pill/chip. Hovering exposes whether it contains an unpacked base64/open-redirect target.

### 3.3 UI Component Implementation (`LinkDissector.jsx`)
```jsx
export function LinkDissector({ url, structureAnalysis }) {
  const tokens = parseAndClassifyTokens(url, structureAnalysis)

  return (
    <div className="link-dissector-card">
      <div className="dissector-header">
        <LuNetwork className="dissector-icon" />
        <h4>Interactive Link Dissector (URL Anatomy Breakdown)</h4>
        <span className="dissector-hint">Hover or click any segment for contextual threat analysis</span>
      </div>

      <div className="token-rail">
        {tokens.map((token, idx) => (
          <div key={idx} className={`token-pill token-${token.riskLevel} ${token.isDeceptive ? 'pulse-deceptive' : ''}`}>
            <span className="token-text">{token.rawText}</span>
            <span className="token-type-tag">{token.label}</span>
            <div className="token-popover">
              <strong>{token.label}</strong>
              <p>{token.explanation}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
```

---

## 4. Sub-Pillar 6.2: Safe Preview & Isolated Link Sandbox

### 4.1 Sanitized Visual Cloud Screenshot Viewer
Allows users and analysts to visually inspect the destination website without risking local browser exploitation:
- **Insulation Guarantee**:
  - The screenshot is captured by the isolated headless Playwright worker or sandbox renderer.
  - Rendered in the UI as a static WebP/JPEG data URI or blob.
  - Zero outbound connections to the target server from the user's browser.
  - No cookies, local storage, or canvas fingerprinting can reach the attacker's server.
- **Interactive Screenshot Features**:
  - Full-screen modal with zoom/pan capabilities.
  - Visual watermark: `[ZEB ISOLATED CLOUD SANDBOX - SAFE PREVIEW]`.
  - Visual brand comparison diff side-by-side if `visualMatching.detected` is True.

### 4.2 De-Scripted Text-Only DOM Reader ("Safe Text Mode")
For low-bandwidth inspection or security analysis of text lures:
- **Stripping Pipeline**:
  - Remove all `<script>`, `<style>`, `<noscript>`, `<iframe>`, `<object>`, `<embed>`, and `<svg>` tags.
  - Remove all inline event handlers (`onclick`, `onload`, `onerror`).
  - Extract inner text and format into clean, readable Markdown blocks.
- **Threat Keyword Highlighting**:
  - Automatically highlight detected phishing lure phrases in bold amber/red:
    - Urgency triggers: *"account suspended"*, *"immediate action required"*, *"locked"*.
    - Financial triggers: *"update payment"*, *"confirm identity"*, *"wallet verification"*.

---

## 5. Sub-Pillar 6.3: Defanged Indicators & Exportable Incident Reports

### 5.1 One-Click Defanged Copy
Beside the target URL in `ResultsView`, provide quick-action buttons:
- **Defang URL**: Copies `hxxps[://]domain[.]xyz/path` to the clipboard.
- **Defang IOC Bundle**: Copies formatted indicator block:
  ```text
  URL: hxxps[://]login-update-paypal[.]xyz/webscr
  Host: login-update-paypal[.]xyz
  IP: 195[.]123[.]245[.]12
  ASN: AS200019 (ALEXHOST)
  Verdict: UNSAFE (Phishing Lure)
  ```

### 5.2 Formatted Markdown Incident Dossier Exporter
Generates a structured report ready for immediate pasting into ticketing systems:

```markdown
# 🛡️ ZEB Threat Intelligence Incident Report
**Generated**: 2026-10-26 14:00 UTC | **Verdict**: 🚨 **UNSAFE** (High Risk)

### 📌 Target Overview
- **Target URL**: `https://evil-phish.xyz/login`
- **Defanged URL**: `hxxps[://]evil-phish[.]xyz/login`
- **Risk Score**: 92/100
- **Summary**: Identified as an active credential harvester targeting Microsoft 365 credentials.

### 🌐 Network & Infrastructure Indicators
- **Canonical Host**: `evil-phish.xyz`
- **Destination IP**: `195.123.245.12`
- **Hosting ASN**: `AS200019 (ALEXHOST - High Risk Bulletproof)`
- **Domain Age**: 4 days (Newly Registered Domain)
- **SSL Certificate**: Issued 6.2 hours ago by Let's Encrypt (Disposable Cert)
- **MX Records**: None configured (No mail infrastructure)

### 🔍 Threat Findings
1. `CRITICAL_VISUAL_BRAND_IMPERSONATION`: 93.2% visual similarity to Microsoft 365 Login.
2. `KNOWN_EXFILTRATION_SINK`: Form action submits passwords to `https://api.telegram.org/bot7123...`.
3. `NEW_DOMAIN_RISK`: Registered 4 days ago.

### 🔄 Redirect Traversal
`https://bit.ly/3xabc` (301) ➔ `https://evil-phish.xyz/login` (200 OK)
```

### 5.3 Structured STIX 2.1 / JSON Threat Bundle
Generates a machine-readable STIX 2.1 JSON bundle for direct import into enterprise SIEMs (Splunk, Elastic, Microsoft Sentinel) and Threat Intelligence Platforms (MISP, OpenCTI):

```json
{
  "type": "bundle",
  "id": "bundle--579048dc-317e-4cdd-9ec6-4bea2cfca2dc",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--9f2b842a-81f1-432a-bc91-23910cbe44ef",
      "created": "2026-10-26T14:00:00.000Z",
      "name": "Malicious Phishing URL: evil-phish.xyz",
      "pattern": "[url:value = 'https://evil-phish.xyz/login']",
      "pattern_type": "stix",
      "valid_from": "2026-10-26T14:00:00.000Z",
      "confidence": 92,
      "labels": ["malicious-activity", "phishing", "credential-theft"],
      "description": "Visual impersonation clone of Microsoft 365 exfiltrating credentials to Telegram."
    },
    {
      "type": "domain-name",
      "id": "domain-name--123",
      "value": "evil-phish.xyz"
    },
    {
      "type": "ipv4-addr",
      "id": "ipv4-addr--456",
      "value": "195.123.245.12"
    }
  ]
}
```

---

## 6. Frontend File Specifications & Style Rules

### 6.1 Component Architecture in `frontend/src/`
- `frontend/src/components/LinkDissector.jsx`: Token breakdown component with popovers.
- `frontend/src/components/SafePreviewModal.jsx`: Full-screen modal with image zoom/pan & text-only reader toggle.
- `frontend/src/components/ReportExportModal.jsx`: Markdown, Defanged IOC, and STIX 2.1 JSON exporters.
- `frontend/src/utils/urlTokenizer.js`: Pure functional tokenizer decomposing URLs into typed tokens.
- `frontend/src/utils/stixGenerator.js`: STIX 2.1 bundle serializer.
- `frontend/src/App.css`: Token styles, pulsing animations for deceptive parts, and modal layouts.

### 6.2 Token Color Palette
```css
:root {
  --token-safe-bg: rgba(16, 185, 129, 0.12);
  --token-safe-border: #10b981;
  --token-warn-bg: rgba(245, 158, 11, 0.12);
  --token-warn-border: #f59e0b;
  --token-danger-bg: rgba(239, 68, 68, 0.14);
  --token-danger-border: #ef4444;
  --token-deceptive-pulse: rgba(239, 68, 68, 0.4);
}
```

---

## 7. Step-by-Step Implementation Tasks

### Task 6.1: Build URL Tokenizer Engine [COMPLETED & VERIFIED]
- Create `frontend/src/utils/urlTokenizer.js`:
  - Extract scheme, userinfo, subdomains, SLD, TLD, port, path, and query parameters.
  - Cross-reference with `structureAnalysis` findings to tag `isDeceptive` and assign risk levels (`safe`, `warning`, `danger`).

### Task 6.2: Build Interactive Link Dissector Component [COMPLETED & VERIFIED]
- Create `frontend/src/components/LinkDissector.jsx`:
  - Render color-coded token pills.
  - Implement hover popovers with contextual security explanations.
  - Mount inside `ResultsView` in `App.jsx`.

### Task 6.3: Build Safe Cloud Preview & Text-Only Reader [COMPLETED & VERIFIED]
- Create `frontend/src/components/SafePreviewModal.jsx`:
  - Render static screenshot viewer with full-screen zoom.
  - Add tab toggle: **"Visual Screenshot"** vs **"Safe Text Reader"**.
  - In Text Reader mode, render cleaned DOM text with highlighted urgency/financial lure keywords.

### Task 6.4: Build Multi-Format Exporters (Defanged, Markdown, STIX) [COMPLETED & VERIFIED]
- Create `frontend/src/utils/stixGenerator.js`:
  - Format STIX 2.1 bundle with Indicator, Domain, and IPv4 SDOs.
- In `frontend/src/components/ReportExportModal.jsx`:
  - Add tabs for **"Markdown Dossier"**, **"Defanged IOCs"**, and **"STIX 2.1 JSON"**.
  - Add download `.json` and copy-to-clipboard buttons with toast confirmation.

### Task 6.5: Integrate into `App.jsx` and `App.css` [COMPLETED & VERIFIED]
- Mount `LinkDissector` at the top of `ResultsView`.
- Add "Safe Preview" and "Export Threat Report" action buttons to the results header.
- Add responsive styling for mobile viewports.

---

## 8. Test Suite & Validation Matrix

| Test ID | Component | Input / Scenario | Expected UI Behavior |
| :--- | :--- | :--- | :--- |
| **UT-6.1** | Link Dissector | `https://paypal.com:login@evil.xyz/webscr` | Userinfo highlighted in pulsing red with `CRITICAL SPOOF` label |
| **UT-6.2** | Link Dissector | `https://login.security.chase.com.evil.xyz/` | Subdomains tagged in amber; `evil.xyz` highlighted as true domain |
| **UT-6.3** | Link Dissector | `http://insecure-login.top:8080/` | Scheme tagged in red (HTTP); port 8080 tagged in amber |
| **UT-6.4** | Safe Preview | Valid base64 screenshot in scan result | Modal renders image with zoom controls; zero outbound network calls |
| **UT-6.5** | Safe Text Mode | Phishing DOM with `<script>` and "account suspended" | Scripts removed; "account suspended" highlighted in bold red |
| **UT-6.6** | STIX Export | Click "Export STIX 2.1" | Valid JSON conforming to STIX 2.1 specification generated and downloaded |
| **UT-6.7** | Defanged Copy | Click "Copy Defanged Link" on `https://bad.com` | Clipboard receives `hxxps[://]bad[.]com` |

---

## 9. Security & Operational Boundaries
- **XSS Immunity in Tokenizer**: All URL components rendered inside the Link Dissector are strictly escaped as text nodes, preventing DOM XSS via payload URLs.
- **Air-Gapped Cloud Preview**: Screenshots must **only** be rendered as static raster data URIs (`data:image/webp;base64,...`) or object URLs—never via an active `<iframe>` pointing to the live malicious target.
- **Client-Side STIX Generation**: Threat bundles are generated entirely in JavaScript in the user's browser, eliminating server storage and preserving analyst privacy.
