import React, { useState, useEffect } from 'react'
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
]

export function SafePreviewModal({ result, onClose }) {
  const [activeTab, setActiveTab] = useState('visual') // 'visual' | 'text'
  const [zoomLevel, setZoomLevel] = useState(1)

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const sa = result?.structureAnalysis || {}
  const sandbox = sa.sandboxPreview || {}
  const screenshotUri = sandbox.screenshotDataUri || null
  const extractedText = sandbox.extractedText || sandbox.pageTitle || 'No raw DOM text available for this target.'

  function handleZoomIn() {
    setZoomLevel(z => Math.min(2.5, +(z + 0.25).toFixed(2)))
  }

  function handleZoomOut() {
    setZoomLevel(z => Math.max(0.5, +(z - 0.25).toFixed(2)))
  }

  function handleZoomReset() {
    setZoomLevel(1)
  }

  // Highlight lure phrases in text mode
  function renderHighlightedText(text) {
    if (!text) return <p className="safe-text-empty">No text content available.</p>

    const regex = new RegExp(`(${LURE_PHRASES.join('|')})`, 'gi')
    const parts = text.split(regex)

    return (
      <div className="safe-text-block">
        {parts.map((chunk, idx) => {
          const isLure = LURE_PHRASES.some(lp => lp.toLowerCase() === chunk.toLowerCase())
          if (isLure) {
            return (
              <mark key={idx} className="lure-highlight" title="Suspicious urgency/phishing lure phrase">
                {chunk}
              </mark>
            )
          }
          return <span key={idx}>{chunk}</span>
        })}
      </div>
    )
  }

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="safe-preview-title">
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
          <button type="button" className="mech-btn modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={16} weight="bold" />
          </button>
        </div>

        {/* View Mode Tabs & Controls */}
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
              <span>Sanitized Screenshot</span>
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

          {activeTab === 'visual' && screenshotUri && (
            <div className="preview-zoom-actions">
              <span className="zoom-level-indicator">{Math.round(zoomLevel * 100)}%</span>
              <button type="button" className="mech-btn zoom-btn" onClick={handleZoomOut} title="Zoom Out" aria-label="Zoom Out">
                <MagnifyingGlassMinus size={14} weight="bold" />
              </button>
              <button type="button" className="mech-btn zoom-btn" onClick={handleZoomIn} title="Zoom In" aria-label="Zoom In">
                <MagnifyingGlassPlus size={14} weight="bold" />
              </button>
              <button type="button" className="mech-btn zoom-btn" onClick={handleZoomReset} title="Reset Zoom" aria-label="Reset Zoom">
                <ArrowsCounterClockwise size={14} weight="bold" />
              </button>
            </div>
          )}
        </div>

        {/* Body Content */}
        <div className="safe-preview-viewport">
          {activeTab === 'visual' ? (
            <div className="screenshot-canvas-wrapper">
              <div className="watermark-banner">
                [ZEB ISOLATED CLOUD SANDBOX — NO CLIENT-SIDE CODE EXECUTED]
              </div>
              {screenshotUri ? (
                <div className="screenshot-pan-container">
                  <img
                    src={screenshotUri}
                    alt={`Isolated render of ${result?.url}`}
                    className="screenshot-image"
                    style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top center' }}
                  />
                </div>
              ) : (
                <div className="preview-fallback-box">
                  <ShieldCheck size={44} weight="bold" />
                  <p className="fallback-title">Visual Screenshot Render</p>
                  <p className="fallback-desc">
                    Headless visual rendering is active for supported environments. The target page DOM was passively audited with zero script execution.
                  </p>
                  <div className="target-pill">
                    <code>{result?.url}</code>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="safe-text-reader-wrapper">
              <div className="watermark-banner">
                [DE-SCRIPTED TEXT STREAM — ALL INLINE SCRIPTS, IFRAMES & BEACONS STRIPPED]
              </div>
              <div className="safe-text-scroll-area">
                {renderHighlightedText(extractedText)}
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
