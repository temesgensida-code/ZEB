import React, { useState, useEffect, useMemo } from 'react'
import {
  X,
  BookOpen,
  Warning,
  ShieldWarning,
  ShieldCheck,
  Lightbulb,
  MaskSad,
  LockKey,
  MagnifyingGlass,
  CheckCircle,
  Pulse,
  Info,
} from '@phosphor-icons/react'
import {
  SECURITY_KNOWLEDGE_BASE,
  getDetectedTopicsForScan,
} from '../data/securityKnowledgeBase'

export default function SecurityExplainerDrawer({
  isOpen,
  onClose,
  activeTopicId,
  onSelectTopic,
  result,
}) {
  const [activeTab, setActiveTab] = useState('current') // 'current' | 'glossary'
  const [searchQuery, setSearchQuery] = useState('')

  // Close on Escape key press
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  // Prevent background body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [isOpen])

  const detectedTopicIds = useMemo(() => {
    return getDetectedTopicsForScan(result)
  }, [result])

  const currentTopic = useMemo(() => {
    return SECURITY_KNOWLEDGE_BASE[activeTopicId] || SECURITY_KNOWLEDGE_BASE.ssl_recency
  }, [activeTopicId])

  const liveTelemetry = useMemo(() => {
    if (!currentTopic || !currentTopic.extractTelemetry) return null
    return currentTopic.extractTelemetry(result)
  }, [currentTopic, result])

  // Filtered glossary topics based on search query
  const glossaryEntries = useMemo(() => {
    const all = Object.values(SECURITY_KNOWLEDGE_BASE)
    if (!searchQuery.trim()) return all
    const q = searchQuery.toLowerCase()
    return all.filter(
      t =>
        t.title.toLowerCase().includes(q) ||
        t.technicalTerm.toLowerCase().includes(q) ||
        t.inPlainEnglish.definition.toLowerCase().includes(q)
    )
  }, [searchQuery])

  if (!isOpen) return null

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="explainer-modal-title"
    >
      <div
        className="modal-dialog explainer-modal-dialog"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header Section (matching InfoModal) */}
        <div className="modal-header-section">
          <div className="modal-title-lockup">
            <BookOpen size={20} weight="bold" />
            <div>
              <h2 id="explainer-modal-title" className="modal-heading-text">
                Explain This Risk
              </h2>
              <span className="sandbox-isolation-badge">
                PASSIVE THREAT INTELLIGENCE & PLAIN-ENGLISH ADVISOR
              </span>
            </div>
          </div>
          <button
            type="button"
            className="mech-btn modal-close-btn"
            onClick={onClose}
            aria-label="Close Security Explainer"
          >
            <X size={16} weight="bold" />
          </button>
        </div>

        {/* Navigation Tabs: Issues in Current Scan vs. Threat Encyclopedia */}
        <div className="drawer-nav-tabs">
          <button
            type="button"
            className={`drawer-tab-btn ${activeTab === 'current' ? 'active' : ''}`}
            onClick={() => setActiveTab('current')}
          >
            <Pulse size={14} weight="bold" />
            <span>Issues in This Scan ({detectedTopicIds.length})</span>
          </button>
          <button
            type="button"
            className={`drawer-tab-btn ${activeTab === 'glossary' ? 'active' : ''}`}
            onClick={() => setActiveTab('glossary')}
          >
            <MagnifyingGlass size={14} weight="bold" />
            <span>Threat Encyclopedia</span>
          </button>
        </div>

        {/* Contextual Topics Selector Bar */}
        {activeTab === 'current' ? (
          <div className="drawer-detected-strip">
            <span className="detected-strip-label">FLAGGED IN THIS SCAN:</span>
            <div className="detected-pills-row">
              {detectedTopicIds.length > 0 ? (
                detectedTopicIds.map(tid => {
                  const item = SECURITY_KNOWLEDGE_BASE[tid]
                  if (!item) return null
                  const isActive = tid === activeTopicId
                  return (
                    <button
                      key={tid}
                      type="button"
                      className={`detected-mini-pill ${isActive ? 'active' : ''} sev-${item.severity.toLowerCase()}`}
                      onClick={() => onSelectTopic(tid)}
                    >
                      <span className="micro-sev-dot" />
                      <span>{item.title.split('(')[0].trim()}</span>
                    </button>
                  )
                })
              ) : (
                <span className="clean-scan-note">
                  <CheckCircle size={13} weight="bold" /> No critical threat flags detected in this URL.
                </span>
              )}
            </div>
          </div>
        ) : (
          <div className="drawer-search-bar-wrap">
            <div className="drawer-search-input-box">
              <MagnifyingGlass size={14} weight="bold" className="search-icon" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search topics (e.g., SSL, Domain Age, Phishing, Fast-Flux)..."
                className="drawer-search-input"
              />
              {searchQuery && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => setSearchQuery('')}
                >
                  <X size={12} weight="bold" />
                </button>
              )}
            </div>

            {/* Quick list of glossary entries when searching */}
            <div className="glossary-chips-cloud">
              {glossaryEntries.map(entry => (
                <button
                  key={entry.id}
                  type="button"
                  className={`glossary-chip-btn ${entry.id === activeTopicId ? 'active' : ''}`}
                  onClick={() => onSelectTopic(entry.id)}
                >
                  {entry.title.split('(')[0].trim()}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Scrollable Modal Body Section */}
        <div className="modal-body-section explainer-modal-body">
          {/* Active Topic Header Card */}
          <div className="active-topic-card">
            <div className="topic-meta-row">
              <span className={`topic-severity-badge sev-${currentTopic.severity.toLowerCase()}`}>
                <span className="micro-sev-dot" />
                {currentTopic.severity}
              </span>
              <span className="topic-technical-term">
                <code>{currentTopic.technicalTerm}</code>
              </span>
            </div>
            <h3 className="topic-title">{currentTopic.title}</h3>
          </div>

          {/* Dynamic Live Telemetry Callout */}
          {liveTelemetry && (
            <div className="telemetry-live-callout">
              <div className="telemetry-live-header">
                <Pulse size={14} weight="bold" />
                <span>WHAT WE FOUND IN YOUR URL</span>
              </div>
              <p className="telemetry-live-text">{liveTelemetry}</p>
            </div>
          )}

          {/* 4-Part Structured Educational Breakdown (Monochrome Aesthetic) */}
          <div className="four-part-guide-stack">
            {/* Part 1: In Plain English */}
            <div className="four-part-card card-plain-english">
              <div className="part-header">
                <span className="part-icon-wrap">
                  <Lightbulb size={16} weight="bold" />
                </span>
                <span className="part-title">In Plain English</span>
              </div>
              <p className="part-text">{currentTopic.inPlainEnglish.definition}</p>
              {currentTopic.inPlainEnglish.analogy && (
                <div className="part-analogy-box">
                  <span className="analogy-label">REAL-WORLD ANALOGY:</span>
                  <p className="analogy-text">{currentTopic.inPlainEnglish.analogy}</p>
                </div>
              )}
            </div>

            {/* Part 2: The Attacker's Trick */}
            <div className="four-part-card card-attacker-trick">
              <div className="part-header">
                <span className="part-icon-wrap">
                  <MaskSad size={16} weight="bold" />
                </span>
                <span className="part-title">The Attacker's Trick</span>
              </div>
              <p className="part-text">{currentTopic.theAttackersTrick}</p>
            </div>

            {/* Part 3: What Could Happen to You */}
            <div className="four-part-card card-personal-danger">
              <div className="part-header">
                <span className="part-icon-wrap">
                  <ShieldWarning size={16} weight="bold" />
                </span>
                <span className="part-title">What Could Happen to You</span>
              </div>
              <p className="part-text">{currentTopic.whatCouldHappenToYou}</p>
            </div>

            {/* Part 4: What You Should Do */}
            <div className="four-part-card card-action-advice">
              <div className="part-header">
                <span className="part-icon-wrap">
                  <ShieldCheck size={16} weight="bold" />
                </span>
                <span className="part-title">What You Should Do</span>
              </div>
              <p className="part-text">{currentTopic.whatYouShouldDo}</p>
            </div>
          </div>
        </div>

        {/* Modal Footer (matching InfoModal) */}
        <div className="modal-footer-section explainer-modal-footer">
          <span className="drawer-footer-note">
            <Info size={13} weight="bold" /> Passive heuristics evaluated in isolated sandbox containers.
          </span>
          <button type="button" className="mech-btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
