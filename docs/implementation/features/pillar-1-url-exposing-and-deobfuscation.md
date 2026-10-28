# Feature Implementation Spec: Pillar 1 Total URL Exposing & De-obfuscation

## 1. Executive Summary & Architectural Overview

### 1.1 Problem Statement
Modern cyber threats systematically evade detection through multi-layered obfuscation. Attackers rarely present naked destination URLs directly linked to malicious infrastructure. Instead, they exploit:
1. **Multi-hop open redirects and parameter nesting** on trusted domains to bypass email gateways and spam filters.
2. **Alternative numerical IPv4 encodings** (Dword, Hex, Octal, mixed-base) to slip past string-matching blocklists.
3. **Deceptive RFC 3986 userinfo syntax** (`user:pass@host`) to visually mimic high-profile brands.
4. **Internationalized Domain Name (IDN) homographs** and mixed-script Unicode glyphs to fool human eyes.
5. **Cross-origin `<form action>` targets and exfiltration sinks** (Telegram, Discord, Google Forms) that harvest credentials while hosting the lure on innocent platforms.
6. **2D QR code image encapsulation ("Quishing")** to bypass optical text filters and lure victims onto mobile devices.

The objective of **Pillar 1: Total URL Exposing & De-obfuscation** is to strip away every concealment layer, reconstructing and exposing the true canonical destination, intermediate traversal hops, structural anomalies, and outbound data sinks.

---

### 1.2 Pillar 1 System Architecture

```mermaid
flowchart TD
    subgraph Ingestion["Sub-Pillar 1.5: Multi-Modal Ingestion"]
        InputText["Raw String / Defanged URL"] --> DefangParser["Defang Sanitizer & Re-fanger"]
        InputQR["QR Code Image (Upload / Paste)"] --> QRDecoder["Client/Server QR Matrix Decoder"]
        DefangParser & QRDecoder --> CanonicalCandidate["Candidate Raw URL"]
    end

    subgraph HostDecoding["Sub-Pillar 1.2 & 1.4: Host De-cloaking"]
        CanonicalCandidate --> HostParser["Hostname & Authority Analyzer"]
        HostParser --> IPDecoder["1.2 Obfuscated IP Decoder<br/>(Dword, Octal, Hex, IPv6-mapped)"]
        HostParser --> UserinfoDecloak["1.2 Userinfo Exploit Isolator<br/>(user@evil.com deception)"]
        HostParser --> IDNResolver["1.4 Dual Punycode & Confusables<br/>(TR39 Script Audit, Glyph Diffs)"]
    end

    subgraph Unrolling["Sub-Pillar 1.1: Deep Traversal & Unrolling"]
        IPDecoder & UserinfoDecloak & IDNResolver --> UnrollLoop["Recursive Parameter & Redirect Unroller"]
        UnrollLoop --> OpenRedirectScan["Nested Parameter Unpacker (Base64/Hex/URL)"]
        UnrollLoop --> NetworkChainTrace["Network Traversal (HTTP 3xx, Meta Refresh, JS)"]
        NetworkChainTrace --> FinalResolvedLanding["Final Canonical Destination"]
    end

    subgraph LinkXRay["Sub-Pillar 1.3: DOM Link X-Ray"]
        FinalResolvedLanding --> PassiveDOM["Sandboxed DOM & Asset Inspector"]
        PassiveDOM --> FormAudit["Form Action & Credential Sink Auditor"]
        PassiveDOM --> AssetTree["Outbound Asset & Hidden IFrame Map"]
    end

    subgraph Presentation["Consolidated Exposure Output"]
        FormAudit & AssetTree --> UnifiedPayload["Exposed URL Security Dossier"]
        UnifiedPayload --> UIComponents["Frontend Link Dissector & Visual Dossier"]
    end
```

---

## 2. Sub-Pillar 1.1: Deep Recursive Parameter & Redirect Unrolling

### 2.1 Threat Mechanics & Gaps
Phishing links frequently bounce through legitimate platforms (Google AMP, LinkedIn, Facebook, SendGrid, or open redirects on corporate portals) to bypass automated scanners.
- **Current Limitations**: [`redirect_chain.py`](file:///home/temesgensida/tom/django_react/zeb/backend/service/url_checks/redirect_chain.py) only traces standard HTTP 3xx status codes via `requests.get(allow_redirects=True)`. It misses:
  - Nested parameters (`?dest=https://legit.com?url=https://evil.xyz`).
  - Base64 or Hex-encoded parameters (`?redirect=aHR0cHM6Ly9iaXQubHkvZXhhbXBsZQ==`).
  - HTML `<meta http-equiv="refresh">` tags and inline JavaScript redirects (`window.location = "..."`).
  - SSRF protection (a redirect hop pointing to `169.254.169.254` or internal IP would be naively fetched).

### 2.2 Algorithmic Logic
```mermaid
flowchart TD
    Start["Input URL"] --> Step1["Step 1: Recursive Parameter Unpacker"]
    
    subgraph ParamUnpacker["Static Recursive Parameter Extraction"]
        Step1 --> ExtractParams["Extract Query Parameters"]
        ExtractParams --> CheckOpenKeys{"Matches Known Open-Redirect Keys?"}
        CheckOpenKeys -- Yes --> DecodeCandidate["Multi-Stage Decoder<br/>(URL-decode, Base64, Hex)"]
        DecodeCandidate --> ValidateURL{"Valid HTTP/HTTPS Scheme?"}
        ValidateURL -- Yes --> RecursiveLoop["Recurse Unpack Embedded URL"]
        RecursiveLoop --> ExtractParams
        ValidateURL -- No --> StaticDone["Static Unrolling Complete"]
        CheckOpenKeys -- No --> StaticDone
    end

    StaticDone --> Step2["Step 2: Network Traversal Loop"]
    
    subgraph NetworkTraversal["Active Network Hop Traversal (Max 10 Hops)"]
        Step2 --> SSRFCheck["SSRF Guard: Resolve IP & Block RFC1918 / Metadata"]
        SSRFCheck -- Blocked --> AbortSSRF["Halt: SSRF Destination Blocked"]
        SSRFCheck -- Clean --> FetchHead["HTTP GET (Stream=True, Max 64KB, Timeout 2.5s)"]
        
        FetchHead --> Check3xx{"HTTP 3xx?"}
        Check3xx -- Yes --> Record3xx["Record Hop (3xx)"] --> NextHop["Set Current URL = Location"]
        
        Check3xx -- No --> CheckRefreshHeader{"HTTP Refresh Header?"}
        CheckRefreshHeader -- Yes --> RecordRefresh["Record Hop (HTTP_REFRESH)"] --> NextHop
        
        CheckRefreshHeader -- No --> CheckMetaRefresh{"HTML Meta Refresh?"}
        CheckMetaRefresh -- Yes --> RecordMeta["Record Hop (META_REFRESH)"] --> NextHop
        
        CheckMetaRefresh -- No --> CheckJSRedirect{"Simple Inline JS Redirect?"}
        CheckJSRedirect -- Yes --> RecordJS["Record Hop (JS_REDIRECT)"] --> NextHop
        
        CheckJSRedirect -- No --> Terminal["Terminal URL Reached"]
        
        NextHop --> CycleCheck{"Seen in Visited Set?"}
        CycleCheck -- Yes --> LoopTrap["Flag: REDIRECT_LOOP_DETECTED"]
        CycleCheck -- No --> HopLimitCheck{"Hop Count >= 10?"}
        HopLimitCheck -- Yes --> MaxHopTrap["Flag: EXCESSIVE_REDIRECT_HOPS"]
        HopLimitCheck -- No --> SSRFCheck
    end
```

#### Recursive Parameter Unpacking Algorithm
```python
def unpack_nested_url_parameters(url: str, max_depth: int = 5) -> tuple[str, list[dict]]:
    """
    Recursively inspects query parameters for nested destination URLs.
    Supports percent-encoding (up to 3 levels), Base64 (standard/URL-safe), and Hex.
    Returns (terminal_url, unpacked_trail).
    """
```
1. Parse query string with `urllib.parse.parse_qsl()`.
2. Inspect keys matching `OPEN_REDIRECT_PARAMS` (expanded in [`constants.py`](file:///home/temesgensida/tom/django_react/zeb/backend/service/url_checks/constants.py): `url`, `redirect`, `dest`, `target`, `next`, `return_to`, `link`, `q`, `u`, `r`, `site`, `dest_url`).
3. For candidate values:
   - **Trial 1 (Percent-Decode)**: Repeatedly `unquote()` up to 3 times.
   - **Trial 2 (Base64)**: If length $\ge 16$ and matches Base64 alphabet, pad with `=` and attempt `urlsafe_b64decode()`. Check if decodable bytes form a valid `http://` or `https://` URL.
   - **Trial 3 (Hex)**: Scan for `\x68\x74\x74\x70...` sequences.
4. If a valid URL is discovered, record the step in `unpacked_trail` and recurse up to `max_depth`.

#### Network Traversal & Evasion Handling
1. **Explicit Hop Traversal**: Set `allow_redirects=False` in requests to intercept every hop individually.
2. **SSRF Guard**: Before connecting, resolve destination hostname via `socket.getaddrinfo()`. If IP belongs to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, or IPv6 equivalents, abort with `SSRF_ATTEMPT_BLOCKED`.
3. **Non-3xx Redirect Traversal**:
   - Inspect `Refresh:` response header.
   - Fast regex scan on first $64\text{ KB}$ of HTML body for `<meta http-equiv="refresh" content="...; url=...">`.
   - Fast regex scan for `window.location = "..."` or `location.replace("...")`.
4. **Loop & Starvation Safeguards**: Maintain a `visited_urls` set. Abort immediately if a loop is detected or if hop count exceeds 10 hops.

---

## 3. Sub-Pillar 1.2: Obfuscated IP & Alternative Host Representation Decoder

### 3.1 Threat Mechanics & Gaps
Operating system socket layers (`inet_aton`, `getaddrinfo`) accept non-standard IPv4 representations:
- **Dword (32-bit Integer)**: `http://2130706433/` (`127.0.0.1`)
- **Hexadecimal (Dotted or Full uint32)**: `http://0x7f000001/` or `http://0x7f.0x0.0x0.0x1/`
- **Octal (Leading Zeroes)**: `http://0177.0.0.1/` (POSIX parses `0177` as octal = `127`)
- **IPv6-Mapped IPv4**: `http://[::ffff:127.0.0.1]`
- **Userinfo Deception (`RFC 3986`)**: `https://paypal.com:account-update@evil-site.com/`. Browsers discard the credentials before the `@` symbol and navigate to `evil-site.com`, but unsuspecting users believe they are on PayPal.

### 3.2 Algorithmic Logic
```mermaid
flowchart TD
    RawHost["Extracted Host String"] --> CheckUserinfo{"Contains Userinfo '@'?"}
    
    subgraph UserinfoDeception["1. Userinfo De-cloaking Engine"]
        CheckUserinfo -- Yes --> SplitUserinfo["Split: userinfo @ host"]
        SplitUserinfo --> AnalyzeUserinfo["Analyze Prefix: Contains brand names, TLDs (.com), or 'login'?"]
        AnalyzeUserinfo --> FlagUserinfo["Flag: DECEPTIVE_USERINFO_ATTACK"]
        CheckUserinfo -- No --> HostString["Host String"]
        SplitUserinfo --> HostString
    end

    HostString --> ParseHostType{"Host Format Classifier"}
    
    subgraph IPDecoder["2. Comprehensive Numeric IP Decoder"]
        ParseHostType -- "Single Integer (0 - 4294967295)" --> DecodeDword["Dword Decoder<br/>(Shift & Mask 32-bit uint)"]
        ParseHostType -- "Single Hex (0x...)" --> DecodeHexDword["Hex Dword Decoder<br/>(Parse base 16 uint32)"]
        ParseHostType -- "Dotted Parts (1 to 4 segments)" --> ParseDottedParts["Multi-Segment Mixed-Base Parser"]
        
        ParseDottedParts --> OctalDetect{"Starts with '0' & is digits?"}
        OctalDetect -- Yes --> DecodeOctal["Parse as Base-8 (Octal)"]
        
        ParseDottedParts --> HexDetect{"Starts with '0x'?"}
        HexDetect -- Yes --> DecodeHex["Parse as Base-16 (Hex)"]
        
        ParseDottedParts --> DecDetect{"Standard decimal digits?"}
        DecDetect -- Yes --> DecodeDec["Parse as Base-10 (Decimal)"]
        
        DecodeOctal & DecodeHex & DecodeDec --> AssembleOctets["Synthesize 4 Octets<br/>Check range 0-255"]
        ParseHostType -- "IPv6 Mapped ([::ffff:...])" --> DecodeIPv6Mapped["Extract Underlying IPv4"]
        
        DecodeDword & DecodeHexDword & AssembleOctets & DecodeIPv6Mapped --> CanonicalIP["Canonical Dotted-Decimal IP<br/>(e.g. 127.0.0.1)"]
    end
```

#### Numeric IP Decoding Specification
```python
def decode_obfuscated_ip(hostname: str) -> tuple[str | None, str | None]:
    """
    Parses non-standard IPv4 representations replicating POSIX inet_aton rules.
    Returns (canonical_dotted_decimal_ip, obfuscation_type) or (None, None).
    """
```
1. **Single Token (Dword / Hex Dword)**:
   - If regex `^0x[0-9a-fA-F]+$`: parse as hex integer. If $0 \le V \le 4294967295$, convert via byte shifts to `X.X.X.X` (`HEX_DWORD`).
   - If regex `^\d+$`: parse as decimal integer. If $0 \le V \le 4294967295$, convert via byte shifts to `X.X.X.X` (`DWORD`).
2. **Multi-Segment Dotted Notation (1 to 4 segments)**:
   - For each part:
     - Starts with `0x`/`0X`: parse as hex (`base 16`).
     - Starts with `0` and length $> 1$: parse as octal (`base 8`).
     - Else: parse as decimal (`base 10`).
   - Reconstruct canonical dotted-decimal and return with type (`DOTTED_HEX`, `DOTTED_OCTAL`, `MIXED_BASE`).
3. **IPv6-Mapped IPv4**: Extract and validate IPv4 payload inside `[::ffff:...]`.

#### Userinfo Deception Auditor
```python
def extract_and_audit_userinfo(url: str) -> dict:
    """
    Isolates fake credential prefix preceding '@' and audits for brand spoofing.
    """
```
- If authority contains `@`:
  - Check if `userinfo` contains words from `BRAND_KEYWORDS` (`paypal`, `microsoft`, `google`, `apple`) or top-level domain endings (`.com`, `.net`, `.org`).
  - Flag `USERINFO_DECEPTION_ATTACK` (Critical Severity).
  - Clean URL to point to the actual destination host while displaying the spoofed prefix in findings.

---

## 4. Sub-Pillar 1.3: Outbound Form Action & Asset Destination Map ("Link X-Ray")

### 4.1 Threat Mechanics & Gaps
Phishing sites often host lure pages on benign platforms (Netlify, Vercel, GitHub Pages, Firebase) while the HTML `<form action="...">` routes stolen passwords to external attacker drops:
- **Telegram Bot API**: `https://api.telegram.org/bot<token>/sendMessage`
- **Discord Webhooks**: `https://discord.com/api/webhooks/<id>/<token>`
- **Google Forms**: `https://docs.google.com/forms/d/e/.../formResponse`
- **Public Form Backends**: Formspree, FormSubmit, Web3Forms, Formkeep
- **Raw IP Gateways**: `http://185.x.x.x/gate.php`
- **Current Limitations**: [`sandbox_preview.py`](file:///home/temesgensida/tom/django_react/zeb/backend/service/url_checks/sandbox_preview.py) checks if a password input exists, but **never resolves or audits the `<form action>` target**.

### 4.2 Algorithmic Logic
```mermaid
flowchart TD
    HTML["Parsed DOM (BeautifulSoup)"] --> FormAuditor["1. Form Action & Credential Auditor"]
    HTML --> AssetAuditor["2. Outbound Asset & IFrame Harvester"]
    
    subgraph FormAuditorEngine["Form Security Auditing"]
        FormAuditor --> ExtractForms["Enumerate all <form> tags"]
        ExtractForms --> InspectInputs["Scan Fields: type=password, name=card, ssn, pin, email"]
        InspectInputs --> ResolveAction["Resolve action URL (Relative -> Absolute)"]
        
        ResolveAction --> CompareOrigin{"Target Origin == Page Host Origin?"}
        CompareOrigin -- No --> FlagCrossOrigin["Flag: CROSS_ORIGIN_FORM_ACTION<br/>(Severity: HIGH)"]
        CompareOrigin -- Yes --> CheckLocalSink["Verify Same-Domain Endpoint"]
        
        ResolveAction --> CheckSinkRules{"Matches Known Exfiltration Sink?<br/>(Telegram, Discord, Google Forms, Formspree)"}
        CheckSinkRules -- Yes --> FlagSink["Flag: KNOWN_EXFILTRATION_SINK<br/>(Severity: CRITICAL)"]
        
        ResolveAction --> CheckIPAction{"Action is Raw IP Address?"}
        CheckIPAction -- Yes --> FlagRawIP["Flag: RAW_IP_FORM_ACTION<br/>(Severity: HIGH)"]
    end

    subgraph AssetAuditorEngine["Link X-Ray Asset Extraction"]
        AssetAuditor --> ParseScripts["Harvest <script src='...'>"]
        AssetAuditor --> ParseIframes["Harvest <iframe src='...'>"]
        AssetAuditor --> ParseLinks["Harvest External <a href='...'>"]
        
        ParseScripts & ParseIframes & ParseLinks --> GroupDomains["Group by eTLD+1 Domain"]
        GroupDomains --> IdentifyThirdParties["Filter Internal vs Third-Party External"]
        IdentifyThirdParties --> BuildAssetTree["Compile Asset Tree Dossier"]
    end
```

#### Exfiltration Sink Pattern Registry
```python
EXFILTRATION_SINK_PATTERNS = [
    (r'^https?://api\.telegram\.org/bot[^/]+/sendMessage', 'TELEGRAM_BOT_API'),
    (r'^https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', 'DISCORD_WEBHOOK'),
    (r'^https?://docs\.google\.com/forms/d/e/[^/]+/formResponse', 'GOOGLE_FORMS_DROP'),
    (r'^https?://formspree\.io/f/[A-Za-z0-9]+', 'FORMSPREE_SERVICE'),
    (r'^https?://formsubmit\.co/', 'FORMSUBMIT_SERVICE'),
    (r'^https?://api\.web3forms\.com/submit', 'WEB3FORMS_SERVICE'),
    (r'^https?://formkeep\.com/f/', 'FORMKEEP_SERVICE'),
]
```

#### Form & Asset Inspection Procedure
1. Extract all `<form>` tags. Correlate sensitive inputs (`password`, `credit card`, `cvv`, `ssn`, `email`).
2. Resolve relative `action` URLs against the page's canonical URL using `urllib.parse.urljoin()`.
3. Extract `action` eTLD+1 using `tldextract`:
   - If action matches `EXFILTRATION_SINK_PATTERNS`: Flag `EXFILTRATION_SINK_DETECTED` (Critical).
   - If action is a raw IP: Flag `RAW_IP_FORM_ACTION` (High).
   - If action domain $\ne$ page domain and password input exists: Flag `CROSS_ORIGIN_CREDENTIAL_FORM` (Critical).
4. Asset Inventory: Group all `<script src>`, `<iframe src>`, and outbound `<a href>` links by domain. Flag hidden zero-pixel iframes (`width="0"`, `height="0"`, `display:none`).

---

## 5. Sub-Pillar 1.4: Dual Punycode & IDN Confusable Highlighting

### 5.1 Threat Mechanics & Gaps
Internationalized Domain Names allow Unicode glyphs that are visually identical to Latin characters (e.g. Cyrillic `а` `U+0430` vs Latin `a` `U+0061`).
- **Mixed-Script Spoofing**: Replacing single characters inside brands (e.g. `аpple.com` -> `xn--pple-43d.com`).
- **Whole-Script Spoofing**: Using entire foreign alphabets to mimic brand skeletons.
- **Current Limitations**: [`sandbox_preview.py`](file:///home/temesgensida/tom/django_react/zeb/backend/service/url_checks/sandbox_preview.py#L100) only raises a generic flag if `xn--` is present, but fails to identify which characters are fake or display the dual Punycode/Unicode representation.

### 5.2 Algorithmic Logic
```mermaid
flowchart TD
    Host["Extracted Domain Name / Host"] --> PunycodeCheck{"Starts with 'xn--' or contains non-ASCII?"}
    
    subgraph DualRepresentation["1. Dual Representation Normalizer"]
        PunycodeCheck -- "Has xn--" --> DecodePunycode["Decode via idna.decode() -> Unicode Glyph"]
        PunycodeCheck -- "Has non-ASCII" --> EncodePunycode["Encode via idna.encode() -> Punycode (xn--)"]
        PunycodeCheck -- "Pure ASCII" --> AsciiPass["Both forms identical"]
        
        DecodePunycode & EncodePunycode & AsciiPass --> DualTuple["(unicode_host, punycode_host)"]
    end

    DualTuple --> ScriptAnalysis["2. Unicode Script & Confusable Engine"]
    
    subgraph TR39Engine["TR39 Script & Confusable Inspection"]
        ScriptAnalysis --> CharLoop["Iterate through each character"]
        CharLoop --> GetScript["Determine Script via unicodedata / Unicode DB<br/>(Latin, Cyrillic, Greek, etc.)"]
        CharLoop --> CheckConfusable["Check TR39 Confusable Table<br/>(Map to ASCII skeleton)"]
        
        GetScript --> ScriptHistogram["Compute Script Histogram<br/>e.g. {'Latin': 7, 'Cyrillic': 1}"]
        CheckConfusable --> FlagGlyph["Record Confusable Glyph Detail:<br/>Index, Char, Codepoint, Script, Replaces"]
        
        ScriptHistogram --> MixedScriptCheck{"Contains >= 2 distinct scripts?"}
        MixedScriptCheck -- Yes --> FlagMixedScript["Flag: MIXED_SCRIPT_HOMOGRAPH<br/>(Severity: CRITICAL)"]
        MixedScriptCheck -- No --> SkeletonCheck["Compare Skeleton against Brand Dictionaries"]
        
        SkeletonCheck -- Brand Match Found --> FlagWholeScript["Flag: WHOLE_SCRIPT_HOMOGRAPH<br/>(Severity: CRITICAL)"]
    end
```

#### Unicode TR39 Confusable & Positional Diff Engine
```python
def analyze_idn_homographs(hostname: str) -> dict:
    """
    Performs Unicode TR39 script audit, extracts positional confusable glyphs,
    and returns dual Unicode/Punycode representations.
    """
```
1. **Dual Form Mapping**: Use `idna.decode()` and `idna.encode()` to establish both the human-rendered Unicode string and the raw DNS Punycode string (`xn--...`).
2. **Positional Character Audit**:
   - For character $c_i$ at index $i$, query `unicodedata.name(c_i)` to determine script family (Latin, Cyrillic, Greek, etc.).
   - Check against expanded TR39 confusables table.
   - Record: index, character, codepoint (`U+0430`), script family, and Latin equivalent (`a`).
3. **Attack Classification**:
   - If script histogram contains both `Latin` and foreign scripts (`Cyrillic`/`Greek`): Flag `MIXED_SCRIPT_HOMOGRAPH`.
   - Reconstruct an ASCII skeleton. If skeleton matches `BRAND_KEYWORDS` while original host uses foreign scripts: Flag `WHOLE_SCRIPT_HOMOGRAPH`.

---

## 6. Sub-Pillar 1.5: Multi-Modal Ingestion: QR Codes & Defanged URLs

### 6.1 Threat Mechanics & Gaps
- **Quishing (QR Phishing)**: Attackers embed target links in QR code images inside email attachments. Standard text-based scanners fail to detect them, and users scan with mobile devices bypassing enterprise defenses.
- **Defanged Indicators**: Incident responders paste sanitized URLs like `hxxps[://]evil[.]com/login`. Current ZEB sanitization chokes on bracketed dots, producing parsing errors.

### 6.2 Algorithmic Logic
```mermaid
flowchart TD
    subgraph MultiModalInput["Multi-Modal Ingestion Channels"]
        TextIn["Pasted Text / String Input"] --> CheckDefang{"Contains Defang Patterns?<br/>(hxxp, [.], [:], etc.)"}
        ImageDrop["Image Drag-and-Drop / Upload"] --> ClientQR["Client-Side QR Decoder<br/>(BarcodeDetector API / jsQR)"]
        ImagePaste["Clipboard Image Paste (Ctrl+V)"] --> ClientQR
    end

    subgraph NormalizationLayer["Sanitization & Re-fanging"]
        CheckDefang -- Yes --> ReFang["Re-fang Engine<br/>Convert to Canonical http[s]://..."]
        CheckDefang -- No --> PassText["Pass Raw URL"]
        
        ClientQR -- Decoded Successfully --> ExtractQRText["Extract Embedded URL"]
        ClientQR -- Decode Failed --> BackendFallback["POST /api/v1/decode-qr/<br/>(Pillow + pyzbar)"]
        BackendFallback --> ExtractQRText
        
        ExtractQRText --> ReFang
        ReFang & PassText --> CanonicalTarget["Canonical URL for Pipeline"]
    end

    subgraph SafeExport["Safe Export Features"]
        PipelineOutput["Scan Completed"] --> DefangTool["Defanging Exporter<br/>Convert https://evil.com -> hxxps[://]evil[.]com"]
        DefangTool --> CopyBtn["One-Click 'Copy Defanged URL' Button"]
    end
```

#### Re-fanging & Defanging Functions
```python
def refang_url(candidate: str) -> str:
    """Transforms hxxp[s], [.], [:], [/] brackets into valid canonical URLs."""
    val = candidate.strip()
    val = re.sub(r'^hxxps(\[:\/\/\]|\[:\/\/?|\(\:\/\/\)|\:\/\/)', 'https://', val, flags=re.I)
    val = re.sub(r'^hxxp(\[:\/\/\]|\[:\/\/?|\(\:\/\/\)|\:\/\/)', 'http://', val, flags=re.I)
    val = re.sub(r'^h\[tt\]ps(\[:\/\/\]|\:\/\/)', 'https://', val, flags=re.I)
    val = re.sub(r'^h\[tt\]p(\[:\/\/\]|\:\/\/)', 'http://', val, flags=re.I)
    val = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]', '.', val, flags=re.I)
    val = re.sub(r'\[\:\]|\(\:\)|\[colon\]', ':', val, flags=re.I)
    val = re.sub(r'\[\/\]|\(\/\)|\[slash\]', '/', val, flags=re.I)
    return val

def defang_url(url: str) -> str:
    """Converts https://evil.com/path -> hxxps[://]evil[.]com/path for safe sharing."""
    defanged = re.sub(r'^https://', 'hxxps[://]', url, flags=re.I)
    defanged = re.sub(r'^http://', 'hxxp[://]', defanged, flags=re.I)
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc:
        defanged_host = parsed.netloc.replace('.', '[.]')
        defanged = defanged.replace(parsed.netloc, defanged_host, 1)
    return defanged
```

#### Quishing Processing Architecture
- **Client-Side (Zero Server Overhead)**: When an image file is dropped or pasted, query native `window.BarcodeDetector`. Fallback to `jsQR` via HTML5 Canvas.
- **Backend Fallback**: Dedicated endpoint `POST /api/service/decode-qr/` using PIL + `pyzbar` with auto-contrast optimization for skewed/low-contrast photos.

---

## 7. Unified Response Schema & Data Contracts

All Sub-Pillars contribute to an enriched `urlExposure` section in `UrlSafetyCheckView`:

```json
{
  "url": "https://deobfuscated-canonical.com/login",
  "rawInput": "hxxps[://]0x7f.1@legit.org/out?url=aHR0cHM6Ly9iaXQubHkvZXhhbXBsZQ==",
  "verdict": "UNSAFE",
  "urlExposure": {
    "originalInputType": "DEFANGED_URL",
    "hostAnalysis": {
      "rawHost": "0x7f.1@legit.org",
      "canonicalHost": "127.0.0.1",
      "userinfoDeception": {
        "detected": true,
        "deceptivePrefix": "0x7f.1",
        "targetHost": "legit.org"
      },
      "ipEncoding": {
        "isObfuscated": true,
        "format": "HEX",
        "decodedIp": "127.0.0.1"
      },
      "idn": {
        "isIdn": false,
        "punycode": "127.0.0.1",
        "unicode": "127.0.0.1",
        "hasMixedScript": false,
        "confusableGlyphs": []
      }
    },
    "traversal": {
      "initialUrl": "http://127.0.0.1/out?url=aHR0cHM6Ly9iaXQubHkvZXhhbXBsZQ==",
      "unrolledParameters": [
        {
          "param": "url",
          "encoding": "BASE64",
          "extractedUrl": "https://bit.ly/example"
        }
      ],
      "hops": [
        {
          "hopNumber": 1,
          "url": "https://bit.ly/example",
          "hopType": "SHORTENER",
          "statusCode": 301
        },
        {
          "hopNumber": 2,
          "url": "https://final-destination.xyz/login",
          "hopType": "TERMINAL",
          "statusCode": 200
        }
      ],
      "totalHops": 2,
      "finalUrl": "https://final-destination.xyz/login"
    },
    "linkXRay": {
      "forms": [
        {
          "action": "https://api.telegram.org/bot12345/sendMessage",
          "method": "POST",
          "hasPasswordField": true,
          "isCrossOrigin": true,
          "isExfiltrationSink": true,
          "sinkType": "TELEGRAM_BOT_API"
        }
      ],
      "externalAssetCount": 14,
      "hiddenIframesCount": 1
    }
  }
}
```

---

## 8. Step-by-Step Implementation Roadmap

| Step | Component | Target Files | Key Deliverable | Status |
| :--- | :--- | :--- | :--- | :--- |
| **8.1** | Constants & Encodings | `backend/service/url_checks/constants.py` | Expanded open redirect params, exfiltration sink regexes, TR39 confusables | **COMPLETED** |
| **8.2** | De-obfuscation Routines | `backend/service/url_checks/common.py` | `decode_obfuscated_ip()`, `extract_and_audit_userinfo()`, `refang_url()`, `defang_url()` | **COMPLETED** |
| **8.3** | Parameter & Hop Traversal | `backend/service/url_checks/redirect_chain.py` | `unpack_nested_url_parameters()`, loop-safe HTTP/Meta/JS traversal, SSRF IP guard | **COMPLETED** |
| **8.4** | IDN & Script Audit | `backend/service/url_checks/structure.py` | `analyze_idn_homographs()`, script histogram, positional character diff | **COMPLETED** |
| **8.5** | Form & Asset Link X-Ray | `backend/service/url_checks/sandbox_preview.py` | `audit_dom_forms()`, exfiltration sink detection, external asset harvester | **COMPLETED** |
| **8.6** | View & Verdict Integration | `backend/service/views.py` | Pipeline wiring, zero-panic SSRF abort handling, updated `_build_verdict()` | **COMPLETED** |
| **8.7** | Frontend Link Dissector | `frontend/src/App.jsx` | QR dropzone/paste, IdnVisualDiff component, Link X-Ray accordion, Defanged Copy | Scheduled in Phase 6 |


---

## 9. Comprehensive Test Suite & Validation Matrix

| Test ID | Sub-Pillar | Input / Scenario | Expected Output | Verification Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **UT-P1.1** | 1.1 Traversal | `https://site.com/?dest=aHR0cHM6Ly9ldmlsLnh5eg==` | Extracted: `https://evil.xyz` | Base64 parameter unwrap |
| **UT-P1.2** | 1.1 Traversal | HTML with `<meta http-equiv="refresh" content="0; url=https://bad.com">` | Hop 2: `https://bad.com` (`META_REFRESH`) | Traversal across non-3xx hops |
| **UT-P1.3** | 1.1 Traversal | Open redirect pointing to `http://169.254.169.254/` | `SSRF_ATTEMPT_BLOCKED` | Halts before contacting metadata IP |
| **UT-P1.4** | 1.2 Host | `http://2130706433/` | Decoded: `127.0.0.1` (`DWORD`) | 32-bit uint host decoded |
| **UT-P1.5** | 1.2 Host | `http://0177.0.0.1/` | Decoded: `127.0.0.1` (`DOTTED_OCTAL`) | POSIX octal leading zero decoded |
| **UT-P1.6** | 1.2 Host | `https://paypal.com:login@evil-drop.com/` | `USERINFO_DECEPTION_ATTACK` | Real destination `evil-drop.com` isolated |
| **UT-P1.7** | 1.3 Link X-Ray | `<form action="https://api.telegram.org/bot1/send"><input type="password"></form>` | `EXFILTRATION_SINK_DETECTED` | `sinkType == 'TELEGRAM_BOT_API'` |
| **UT-P1.8** | 1.3 Link X-Ray | `<iframe src="https://bad.com" width="0" height="0"></iframe>` | `SANDBOX_HIDDEN_IFRAME` | Recorded in `hiddenIframes` |
| **UT-P1.9** | 1.4 IDN | `xn--pple-43d.com` (`аpple.com`) | `MIXED_SCRIPT_HOMOGRAPH` | Character 0 flagged as Cyrillic 'а' (U+0430) |
| **UT-P1.10**| 1.5 Ingestion | `hxxps[://]attacker[.]com/login` | Re-fanged: `https://attacker.com/login` | Bracketed defang patterns neutralized |

---

## 10. Security & Operational Guardrails
- **SSRF Immunity**: At every hop during redirect unrolling or asset crawling, DNS resolution verifies destination IP does not belong to private/internal CIDR blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`).
- **Resource Starvation Limits**: Redirect traversal capped at 10 hops; HTML preview read stream capped at $64\text{ KB}$ for traversal checks and $1\text{ MB}$ for full DOM previews.
- **Client-Side Heavy Lifting**: QR decoding executes in browser WebAssembly/Canvas whenever possible ($< 100\text{ms}$), minimizing backend image processing workloads.
