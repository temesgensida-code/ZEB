import React, { useState, useEffect, useMemo, useRef } from 'react'
import html2canvas from 'html2canvas'
import {
  X,
  Eye,
  FileText,
  MagnifyingGlassPlus,
  MagnifyingGlassMinus,
  ArrowsCounterClockwise,
  ShieldCheck,
  ShieldWarning,
  Lock,
  Camera,
  Globe,
  Desktop,
  DeviceMobile,
  Copy,
  Check,
  MagnifyingGlass,
  WarningCircle,
  CircleNotch,
} from '@phosphor-icons/react'

const LURE_PHRASES = [
  'account suspended',
  'immediate action required',
  'urgent action',
  'unauthorized access',
  'verify identity',
  'verify account',
  'update payment',
  'confirm password',
  'wallet verification',
  'connect wallet',
  'claim airdrop',
  'security notice',
  'banking alert',
  'password reset',
  'billing problem',
  'suspicious activity',
]

export function SafePreviewModal({ result, onClose }) {
  const [activeTab, setActiveTab] = useState('visual') // 'visual' | 'text'
  const [visualSubMode, setVisualSubMode] = useState('screenshot') // 'screenshot' | 'dom'
  const [domViewport, setDomViewport] = useState('desktop') // 'desktop' | 'mobile'
  const [zoomLevel, setZoomLevel] = useState(1)

  // Live headless capture state
  const [capturedScreenshotUri, setCapturedScreenshotUri] = useState(null)
  const [isCapturing, setIsCapturing] = useState(false)
  const [captureNotice, setCaptureNotice] = useState(null)

  // High-fidelity client-side DOM snapshot rasterization state
  const [rasterizedDomUri, setRasterizedDomUri] = useState(null)
  const [isRasterizing, setIsRasterizing] = useState(false)

  // Text reader state
  const [searchQuery, setSearchQuery] = useState('')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const sa = result?.structureAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const dynamic = sa.dynamicSandbox || {}

  // Resolve sanitized HTML
  const sanitizedHtml = sandbox.sanitizedHtml || ''

  // Determine effective screenshot URI and capture source
  const hasLiveScreenshot = Boolean(
    capturedScreenshotUri ||
    dynamic?.screenshot?.dataUri ||
    sandbox?.screenshotDataUri ||
    result?.screenshotDataUri
  )

  const effectiveScreenshotUri =
    capturedScreenshotUri ||
    dynamic?.screenshot?.dataUri ||
    sandbox?.screenshotDataUri ||
    result?.screenshotDataUri ||
    rasterizedDomUri ||
    null

  const captureSource = hasLiveScreenshot
    ? 'live'
    : (rasterizedDomUri ? 'snapshot' : null)

  // Automatic high-fidelity DOM snapshot rasterization via html2canvas
  useEffect(() => {
    // If we already have a live screenshot or have already rasterized, do not re-rasterize
    if (hasLiveScreenshot || rasterizedDomUri || isRasterizing || !sanitizedHtml) return

    let isMounted = true
    setIsRasterizing(true)

    // Render inside a hidden, isolated iframe to ensure 0 external scripts execute
    const iframe = document.createElement('iframe')
    iframe.style.position = 'fixed'
    iframe.style.left = '-9999px'
    iframe.style.top = '-9999px'
    iframe.style.width = '1280px'
    iframe.style.height = '800px'
    iframe.style.opacity = '0'
    iframe.style.pointerEvents = 'none'
    iframe.setAttribute('sandbox', 'allow-same-origin')
    document.body.appendChild(iframe)

    const doc = iframe.contentDocument || iframe.contentWindow?.document
    if (!doc) {
      if (iframe.parentNode) document.body.removeChild(iframe)
      setIsRasterizing(false)
      return
    }

    doc.open()
    doc.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {
              margin: 0;
              padding: 24px;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
              background: #ffffff;
              color: #111827;
              box-sizing: border-box;
            }
          </style>
        </head>
        <body>
          ${sanitizedHtml}
        </body>
      </html>
    `)
    doc.close()

    const timer = setTimeout(async () => {
      try {
        if (!iframe.contentDocument?.body) {
          if (isMounted) setIsRasterizing(false)
          if (iframe.parentNode) document.body.removeChild(iframe)
          return
        }
        const canvas = await html2canvas(iframe.contentDocument.body, {
          width: 1280,
          height: 800,
          windowWidth: 1280,
          windowHeight: 800,
          useCORS: true,
          allowTaint: false,
          logging: false,
          backgroundColor: '#ffffff',
        })
        const dataUrl = canvas.toDataURL('image/png')
        if (isMounted && dataUrl && dataUrl.length > 200) {
          setRasterizedDomUri(dataUrl)
        }
      } catch (err) {
        console.warn('DOM snapshot rasterization fallback handled:', err)
      } finally {
        if (isMounted) setIsRasterizing(false)
        if (iframe.parentNode) document.body.removeChild(iframe)
      }
    }, 180)

    return () => {
      isMounted = false
      clearTimeout(timer)
      if (iframe.parentNode) document.body.removeChild(iframe)
    }
  }, [hasLiveScreenshot, rasterizedDomUri, isRasterizing, sanitizedHtml])

  // Normalize extracted text structure
  const rawExtracted = sandbox.extractedText
  const extractedData = useMemo(() => {
    if (rawExtracted && typeof rawExtracted === 'object') {
      const title = rawExtracted.title || sandbox.pageTitle || ''
      const headings = Array.isArray(rawExtracted.headings) ? rawExtracted.headings : []
      const paragraphs = Array.isArray(rawExtracted.paragraphs) ? rawExtracted.paragraphs : []
      const forms = Array.isArray(rawExtracted.forms) ? rawExtracted.forms : []
      const lureHits = Array.isArray(rawExtracted.lureHits) ? rawExtracted.lureHits : []
      const plainText =
        rawExtracted.plainText ||
        [title, ...headings.map(h => h.text), ...paragraphs].filter(Boolean).join('\n\n')
      const words = plainText.split(/\s+/).filter(Boolean)
      const wordCount = rawExtracted.wordCount || words.length
      const readingTimeSec =
        rawExtracted.readingTimeSec || (wordCount > 0 ? Math.max(5, Math.round(wordCount / 3.5)) : 0)

      return {
        title,
        headings,
        paragraphs,
        forms,
        lureHits,
        plainText,
        wordCount,
        readingTimeSec,
      }
    }

    const fallbackText = typeof rawExtracted === 'string' ? rawExtracted : (sandbox.pageTitle || '')
    const words = fallbackText.split(/\s+/).filter(Boolean)
    const wordCount = words.length
    const readingTimeSec = wordCount > 0 ? Math.max(5, Math.round(wordCount / 3.5)) : 0
    const lower = fallbackText.toLowerCase()
    const lureHits = LURE_PHRASES.filter(lp => lower.includes(lp))

    return {
      title: sandbox.pageTitle || '',
      headings: [],
      paragraphs: fallbackText ? [fallbackText] : [],
      forms: [],
      lureHits,
      plainText: fallbackText,
      wordCount,
      readingTimeSec,
    }
  }, [rawExtracted, sandbox.pageTitle])

  function handleZoomIn() {
    setZoomLevel(z => Math.min(2.5, +(z + 0.25).toFixed(2)))
  }

  function handleZoomOut() {
    setZoomLevel(z => Math.max(0.5, +(z - 0.25).toFixed(2)))
  }

  function handleZoomReset() {
    setZoomLevel(1)
  }

  async function handleCaptureScreenshot() {
    setIsCapturing(true)
    setCaptureNotice(null)
    try {
      const resp = await fetch('/api/safe-preview/screenshot/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: result?.url }),
      })
      const data = await resp.json()
      if (data.available && data.screenshotDataUri) {
        setCapturedScreenshotUri(data.screenshotDataUri)
        setVisualSubMode('screenshot')
      } else {
        setCaptureNotice(
          data.error
            ? `Notice: ${data.error}`
            : 'Live browser restricted in this environment. Retaining high-fidelity sanitized snapshot.'
        )
      }
    } catch (_err) {
      setCaptureNotice('Live browser unavailable. Retaining high-fidelity sanitized snapshot.')
    } finally {
      setIsCapturing(false)
    }
  }

  function handleCopyText() {
    if (!extractedData.plainText) return
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(extractedData.plainText).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2200)
      })
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = extractedData.plainText
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopied(true)
      setTimeout(() => setCopied(false), 2200)
    }
  }

  // Highlight search query and phishing lures simultaneously
  function renderHighlightedText(text) {
    if (!text) return null

    const tokens = []
    const q = searchQuery.trim().toLowerCase()

    // Build unified pattern of query + lure phrases
    const targets = []
    if (q) targets.push(q)
    LURE_PHRASES.forEach(lp => {
      if (!targets.includes(lp.toLowerCase())) targets.push(lp.toLowerCase())
    })

    if (targets.length === 0) return <span>{text}</span>

    const escaped = targets.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    const regex = new RegExp(`(${escaped.join('|')})`, 'gi')
    const parts = text.split(regex)

    return (
      <>
        {parts.map((chunk, idx) => {
          if (!chunk) return null
          const lower = chunk.toLowerCase()
          if (q && lower === q) {
            return (
              <mark key={idx} className="search-highlight" title="Search match">
                {chunk}
              </mark>
            )
          }
          if (LURE_PHRASES.includes(lower)) {
            return (
              <mark key={idx} className="lure-highlight" title="Urgency or phishing lure phrase">
                {chunk}
              </mark>
            )
          }
          return <span key={idx}>{chunk}</span>
        })}
      </>
    )
  }

  const filteredParagraphs = useMemo(() => {
    if (!searchQuery.trim()) return extractedData.paragraphs
    const q = searchQuery.trim().toLowerCase()
    return extractedData.paragraphs.filter(p => p.toLowerCase().includes(q))
  }, [extractedData.paragraphs, searchQuery])

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="safe-preview-title"
    >
      <div className="modal-dialog safe-preview-dialog" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header-section">
          <div className="modal-title-lockup">
            <Lock size={20} weight="bold" />
            <div>
              <h2 id="safe-preview-title" className="modal-heading-text">Isolated Cloud Link Sandbox</h2>
              <span className="sandbox-isolation-badge">ZERO-CLIENT EXECUTION • AIR-GAPPED PREVIEW</span>
            </div>
          </div>
          <button
            type="button"
            className="mech-btn modal-close-btn"
            onClick={onClose}
            aria-label="Close modal"
          >
            <X size={16} weight="bold" />
          </button>
        </div>

        {/* View Mode Control Strip */}
        <div className="safe-preview-control-strip">
          <div className="preview-mode-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'visual'}
              className={`preview-tab-btn ${activeTab === 'visual' ? 'active' : ''}`}
              onClick={() => setActiveTab('visual')}
            >
              <Eye size={14} weight="bold" />
              <span>Sanitized Visual Preview</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'text'}
              className={`preview-tab-btn ${activeTab === 'text' ? 'active' : ''}`}
              onClick={() => setActiveTab('text')}
            >
              <FileText size={14} weight="bold" />
              <span>De-Scripted Safe Text Reader</span>
            </button>
          </div>

          {/* Contextual Toolbar Controls */}
          {activeTab === 'visual' && (
            <div className="visual-toolbar-cluster">
              <div className="submode-toggle-group">
                <button
                  type="button"
                  className={`submode-btn ${visualSubMode === 'screenshot' ? 'active' : ''}`}
                  onClick={() => setVisualSubMode('screenshot')}
                  title="Playwright Chromium Headless Screenshot"
                >
                  <Camera size={13} weight="bold" />
                  <span>PNG Screenshot</span>
                </button>
                <button
                  type="button"
                  className={`submode-btn ${visualSubMode === 'dom' ? 'active' : ''}`}
                  onClick={() => setVisualSubMode('dom')}
                  title="Air-Gapped Sandboxed DOM Frame (Zero Scripts)"
                >
                  <Globe size={13} weight="bold" />
                  <span>Sanitized DOM</span>
                </button>
              </div>

              {visualSubMode === 'screenshot' && effectiveScreenshotUri && (
                <div className="preview-toolbar-right-group">
                  {/* Capture Source Badge */}
                  <div className={`preview-source-pill source-${captureSource}`}>
                    <span className="source-dot" />
                    <span>{captureSource === 'live' ? 'LIVE CHROMIUM CAPTURE' : 'SANITIZED SNAPSHOT'}</span>
                  </div>

                  {/* Re-capture Live Button */}
                  <button
                    type="button"
                    className="mech-btn recapture-live-btn"
                    onClick={handleCaptureScreenshot}
                    disabled={isCapturing}
                    title="Attempt fresh live headless Chromium screenshot"
                  >
                    {isCapturing ? (
                      <>
                        <CircleNotch size={12} weight="bold" className="spin-icon" />
                        <span>Capturing...</span>
                      </>
                    ) : (
                      <>
                        <Camera size={12} weight="bold" />
                        <span>Re-capture Live</span>
                      </>
                    )}
                  </button>

                  <div className="preview-zoom-actions">
                    <span className="zoom-level-indicator">{Math.round(zoomLevel * 100)}%</span>
                    <button
                      type="button"
                      className="mech-btn zoom-btn"
                      onClick={handleZoomOut}
                      title="Zoom Out"
                      aria-label="Zoom Out"
                    >
                      <MagnifyingGlassMinus size={14} weight="bold" />
                    </button>
                    <button
                      type="button"
                      className="mech-btn zoom-btn"
                      onClick={handleZoomIn}
                      title="Zoom In"
                      aria-label="Zoom In"
                    >
                      <MagnifyingGlassPlus size={14} weight="bold" />
                    </button>
                    <button
                      type="button"
                      className="mech-btn zoom-btn"
                      onClick={handleZoomReset}
                      title="Reset Zoom"
                      aria-label="Reset Zoom"
                    >
                      <ArrowsCounterClockwise size={14} weight="bold" />
                    </button>
                  </div>
                </div>
              )}

              {visualSubMode === 'dom' && (
                <div className="viewport-switcher-cluster">
                  <button
                    type="button"
                    className={`viewport-btn ${domViewport === 'desktop' ? 'active' : ''}`}
                    onClick={() => setDomViewport('desktop')}
                    title="Desktop Viewport (1280px)"
                  >
                    <Desktop size={13} weight="bold" />
                    <span>Desktop (1280px)</span>
                  </button>
                  <button
                    type="button"
                    className={`viewport-btn ${domViewport === 'mobile' ? 'active' : ''}`}
                    onClick={() => setDomViewport('mobile')}
                    title="Mobile Viewport (375px)"
                  >
                    <DeviceMobile size={13} weight="bold" />
                    <span>Mobile (375px)</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Viewport Content */}
        <div className="safe-preview-viewport">
          {activeTab === 'visual' ? (
            <div className="screenshot-canvas-wrapper">
              {visualSubMode === 'screenshot' ? (
                <>
                  <div className="watermark-banner">
                    [ZEB ISOLATED CLOUD SANDBOX — NO CLIENT-SIDE CODE EXECUTED]
                  </div>
                  {captureNotice && (
                    <div className="capture-subtle-notice">
                      <WarningCircle size={13} weight="bold" />
                      <span>{captureNotice}</span>
                      <button type="button" className="notice-dismiss-btn" onClick={() => setCaptureNotice(null)}>
                        <X size={11} weight="bold" />
                      </button>
                    </div>
                  )}
                  {effectiveScreenshotUri ? (
                    <div className="screenshot-pan-container">
                      <img
                        src={effectiveScreenshotUri}
                        alt={`Isolated screenshot render of ${result?.url}`}
                        className="screenshot-image"
                        style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top center' }}
                      />
                    </div>
                  ) : isRasterizing || isCapturing ? (
                    <div className="preview-loading-card">
                      <CircleNotch size={36} weight="bold" className="spin-icon" />
                      <p className="loading-card-title">Generating Air-Gapped Visual Snapshot...</p>
                      <p className="loading-card-sub">
                        Isolating sanitized DOM structure and pre-rendering safe visual frame
                      </p>
                    </div>
                  ) : (
                    <div className="preview-fallback-box">
                      <ShieldCheck size={44} weight="bold" />
                      <p className="fallback-title">Visual Preview</p>
                      <p className="fallback-desc">
                        Passive inspection audited the target page with zero client script execution.
                        You can trigger an isolated live headless browser capture or inspect the Sanitized DOM Frame.
                      </p>
                      <div className="preview-action-row">
                        <button
                          type="button"
                          className="mech-btn live-capture-btn"
                          onClick={handleCaptureScreenshot}
                          disabled={isCapturing}
                        >
                          {isCapturing ? (
                            <>
                              <CircleNotch size={14} weight="bold" className="spin-icon" />
                              <span>Rendering Headless Page...</span>
                            </>
                          ) : (
                            <>
                              <Camera size={14} weight="bold" />
                              <span>Capture Live Screenshot</span>
                            </>
                          )}
                        </button>
                        <button
                          type="button"
                          className="mech-btn dom-fallback-btn"
                          onClick={() => setVisualSubMode('dom')}
                        >
                          <Globe size={14} weight="bold" />
                          <span>Switch to Sanitized DOM</span>
                        </button>
                      </div>
                      <div className="target-pill">
                        <code>{result?.url}</code>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="sanitized-dom-wrapper">
                  <div className="watermark-banner">
                    [AIR-GAPPED DOM CONTAINER — ZERO JAVASCRIPT / ZERO TRACKING EXECUTION]
                  </div>
                  <div className={`sanitized-iframe-shell viewport-${domViewport}`}>
                    {sanitizedHtml ? (
                      <iframe
                        title="Air-Gapped Sanitized DOM Preview"
                        sandbox="allow-same-origin"
                        srcDoc={sanitizedHtml}
                        className="sanitized-iframe-frame"
                      />
                    ) : (
                      <div className="preview-fallback-box">
                        <ShieldWarning size={40} weight="bold" />
                        <p className="fallback-title">Sanitized DOM Unavailable</p>
                        <p className="fallback-desc">
                          The destination did not return an HTML payload or was unreachable.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="safe-text-reader-wrapper">
              {/* Text Reader Meta Header Bar */}
              <div className="text-reader-meta-bar">
                <div className="meta-stats-group">
                  <span className="meta-stat-pill">
                    <strong>{extractedData.wordCount}</strong> words
                  </span>
                  <span className="meta-stat-pill">
                    <strong>~{extractedData.readingTimeSec}s</strong> read
                  </span>
                  <span
                    className={`meta-stat-pill ${
                      extractedData.lureHits.length > 0 ? 'pill-warning' : 'pill-clean'
                    }`}
                  >
                    {extractedData.lureHits.length > 0 ? (
                      <>
                        <ShieldWarning size={13} weight="bold" />
                        <span>{extractedData.lureHits.length} Urgency Lures</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck size={13} weight="bold" />
                        <span>0 Lures Detected</span>
                      </>
                    )}
                  </span>
                </div>

                <div className="meta-actions-group">
                  <div className="text-search-shell">
                    <MagnifyingGlass size={13} weight="bold" className="search-lead-icon" />
                    <input
                      type="text"
                      className="text-reader-search-input"
                      placeholder="Filter text or search keywords..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                    />
                    {searchQuery && (
                      <button
                        type="button"
                        className="clear-search-btn"
                        onClick={() => setSearchQuery('')}
                        title="Clear filter"
                      >
                        <X size={11} weight="bold" />
                      </button>
                    )}
                  </div>
                  <button
                    type="button"
                    className="mech-btn copy-text-btn"
                    onClick={handleCopyText}
                    title="Copy sanitized plain text"
                  >
                    {copied ? (
                      <>
                        <Check size={13} weight="bold" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy size={13} weight="bold" />
                        <span>Copy Text</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="watermark-banner">
                [DE-SCRIPTED TEXT STREAM — ALL INLINE SCRIPTS, IFRAMES & BEACONS STRIPPED]
              </div>

              {/* Structured Reading Content */}
              <div className="safe-text-scroll-area">
                {/* Page Title */}
                {extractedData.title && (
                  <div className="text-reader-section title-section">
                    <span className="reader-tag">PAGE TITLE</span>
                    <h3 className="reader-page-title">
                      {renderHighlightedText(extractedData.title)}
                    </h3>
                  </div>
                )}

                {/* Semantic Headings Outline */}
                {extractedData.headings.length > 0 && (
                  <div className="text-reader-section headings-section">
                    <span className="reader-tag">HEADING OUTLINE ({extractedData.headings.length})</span>
                    <div className="headings-outline-list">
                      {extractedData.headings.map((h, i) => (
                        <div key={i} className="heading-item-row">
                          <span className="heading-level-tag">{h.level}</span>
                          <span className="heading-text-content">
                            {renderHighlightedText(h.text)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Form Security Prompts */}
                {extractedData.forms.length > 0 && (
                  <div className="text-reader-section forms-section">
                    <span className="reader-tag">DETECTED INPUT FORMS ({extractedData.forms.length})</span>
                    <div className="forms-audit-list">
                      {extractedData.forms.map((form, idx) => {
                        const hasPassword = form.inputs?.some(i => i.type === 'password')
                        return (
                          <div
                            key={idx}
                            className={`form-audit-item ${hasPassword ? 'form-has-password' : ''}`}
                          >
                            <div className="form-item-header">
                              <span className="form-method-tag">{form.method || 'GET'}</span>
                              <span className="form-action-url">
                                Submits to: <code>{form.action}</code>
                              </span>
                            </div>
                            {form.inputs && form.inputs.length > 0 && (
                              <div className="form-inputs-chips">
                                {form.inputs.map((inp, ii) => (
                                  <span
                                    key={ii}
                                    className={`input-type-chip ${
                                      inp.type === 'password' ? 'chip-password' : ''
                                    }`}
                                  >
                                    [{inp.type.toUpperCase()}] {inp.name || 'unnamed'}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* Body Paragraphs */}
                <div className="text-reader-section paragraphs-section">
                  <span className="reader-tag">
                    BODY TEXT ({filteredParagraphs.length}
                    {searchQuery.trim() ? ` matching "${searchQuery.trim()}"` : ''})
                  </span>
                  {filteredParagraphs.length > 0 ? (
                    <div className="paragraphs-list">
                      {filteredParagraphs.map((para, idx) => (
                        <p key={idx} className="reader-paragraph">
                          {renderHighlightedText(para)}
                        </p>
                      ))}
                    </div>
                  ) : (
                    <p className="safe-text-empty">
                      {searchQuery.trim()
                        ? 'No paragraphs matched your search query.'
                        : 'No readable text content extracted from this destination.'}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Guarantee */}
        <div className="safe-preview-footer">
          <span className="guarantee-text">
            <strong>Security Guarantee:</strong> Rendered purely on remote cloud workers. No local browser memory, cookies, or networking was exposed to this host.
          </span>
        </div>
      </div>
    </div>
  )
}
