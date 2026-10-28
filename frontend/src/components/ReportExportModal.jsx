import React, { useState, useEffect } from 'react'
import {
  X,
  FileText,
  Copy,
  Check,
  DownloadSimple,
  ShieldCheck,
  ShareNetwork,
  Code,
} from '@phosphor-icons/react'
import {
  defangUrl,
  generateDefangedIocBlock,
  generateMarkdownReport,
  generateStixBundle,
} from '../utils/stixGenerator'

export function ReportExportModal({ result, onClose }) {
  const [activeTab, setActiveTab] = useState('markdown') // 'markdown' | 'defanged' | 'stix'
  const [copiedKey, setCopiedKey] = useState(null)

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const markdownContent = generateMarkdownReport(result)
  const defangedBlock = generateDefangedIocBlock(result)
  const stixBundle = generateStixBundle(result)
  const stixJsonString = JSON.stringify(stixBundle, null, 2)

  function handleCopy(text, key) {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  function handleDownloadStix() {
    const blob = new Blob([stixJsonString], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const host = result?.structureAnalysis?.hostname || 'threat-bundle'
    a.href = url
    a.download = `stix-2.1-${host}-${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  function handleDownloadMarkdown() {
    const blob = new Blob([markdownContent], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const host = result?.structureAnalysis?.hostname || 'incident-report'
    a.href = url
    a.download = `threat-report-${host}-${Date.now()}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="export-modal-title">
      <div className="modal-dialog export-modal-dialog" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header-section">
          <div className="modal-title-lockup">
            <ShareNetwork size={20} weight="bold" />
            <div>
              <h2 id="export-modal-title" className="modal-heading-text">Security Incident Dossier & Exporter</h2>
              <span className="sandbox-isolation-badge">MULTI-FORMAT THREAT INTELLIGENCE PACK</span>
            </div>
          </div>
          <button type="button" className="mech-btn modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={16} weight="bold" />
          </button>
        </div>

        {/* Tab Strip */}
        <div className="export-tabs-strip" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'markdown'}
            className={`export-tab-btn ${activeTab === 'markdown' ? 'active' : ''}`}
            onClick={() => setActiveTab('markdown')}
          >
            <FileText size={14} weight="bold" />
            <span>Markdown Dossier</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'defanged'}
            className={`export-tab-btn ${activeTab === 'defanged' ? 'active' : ''}`}
            onClick={() => setActiveTab('defanged')}
          >
            <ShieldCheck size={14} weight="bold" />
            <span>Defanged IOCs</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'stix'}
            className={`export-tab-btn ${activeTab === 'stix' ? 'active' : ''}`}
            onClick={() => setActiveTab('stix')}
          >
            <Code size={14} weight="bold" />
            <span>STIX 2.1 / JSON</span>
          </button>
        </div>

        {/* Content Box */}
        <div className="export-content-body">
          {activeTab === 'markdown' && (
            <div className="export-panel">
              <div className="export-panel-header">
                <span className="panel-desc">Formatted markdown report for ticketing systems (Jira, GitHub, Slack, Notion).</span>
                <div className="panel-actions">
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={() => handleCopy(markdownContent, 'md-content')}
                  >
                    {copiedKey === 'md-content' ? <><Check size={14} weight="bold" /> Copied</> : <><Copy size={14} weight="bold" /> Copy Markdown</>}
                  </button>
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={handleDownloadMarkdown}
                  >
                    <DownloadSimple size={14} weight="bold" /> Download .md
                  </button>
                </div>
              </div>
              <textarea
                readOnly
                className="export-code-textarea"
                value={markdownContent}
                rows={16}
                aria-label="Markdown Incident Dossier"
              />
            </div>
          )}

          {activeTab === 'defanged' && (
            <div className="export-panel">
              <div className="export-panel-header">
                <span className="panel-desc">Defanged indicators safe to paste into chat without generating click targets or web unfurlings.</span>
                <div className="panel-actions">
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={() => handleCopy(defangUrl(result?.url), 'defanged-url')}
                  >
                    {copiedKey === 'defanged-url' ? <><Check size={14} weight="bold" /> Copied URL</> : <><Copy size={14} weight="bold" /> Copy Defanged URL</>}
                  </button>
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={() => handleCopy(defangedBlock, 'defanged-block')}
                  >
                    {copiedKey === 'defanged-block' ? <><Check size={14} weight="bold" /> Copied Block</> : <><Copy size={14} weight="bold" /> Copy IOC Block</>}
                  </button>
                </div>
              </div>
              <textarea
                readOnly
                className="export-code-textarea"
                value={defangedBlock}
                rows={12}
                aria-label="Defanged Indicators"
              />
            </div>
          )}

          {activeTab === 'stix' && (
            <div className="export-panel">
              <div className="export-panel-header">
                <span className="panel-desc">OASIS STIX 2.1 JSON bundle for automated SIEM / SOAR ingestion (Splunk, Elastic, Sentinel, OpenCTI).</span>
                <div className="panel-actions">
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={() => handleCopy(stixJsonString, 'stix-content')}
                  >
                    {copiedKey === 'stix-content' ? <><Check size={14} weight="bold" /> Copied JSON</> : <><Copy size={14} weight="bold" /> Copy JSON</>}
                  </button>
                  <button
                    type="button"
                    className="mech-btn panel-action-btn"
                    onClick={handleDownloadStix}
                  >
                    <DownloadSimple size={14} weight="bold" /> Download STIX .json
                  </button>
                </div>
              </div>
              <textarea
                readOnly
                className="export-code-textarea"
                value={stixJsonString}
                rows={16}
                aria-label="STIX 2.1 JSON Bundle"
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="safe-preview-footer">
          <span className="guarantee-text">
            Generated client-side in browser memory. Threat data is not stored or shared externally.
          </span>
        </div>
      </div>
    </div>
  )
}
