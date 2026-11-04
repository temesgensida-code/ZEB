import React, { useState, useEffect, useMemo } from 'react'
import {
  X,
  BookOpen,
  Warning,
  ShieldWarning,
  ShieldCheck,
  Lightbulb,
  MaskHappy,
  MaskSad,
  LockKey,
  MagnifyingGlass,
  CheckCircle,
  Pulse,
  Info,
  ArrowsClockwise,

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

  // Prevent background body scroll when drawer is open
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
    <div className="explainer-drawer-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div
        className="explainer-drawer-panel"
        onClick={e => e.stopPropagation()}
      >
        {/* Mobile touch drag indicator */}
        <div className="drawer-handle-bar-mobile" />

        {/* Drawer Top Navigation Header */}
        <div className="drawer-top-header">
          <div className="drawer-header-left">
            <div className="drawer-icon-bubble">
              <BookOpen size={18} weight="bold" />
            </div>
            <div>
              <span className="drawer-eyebrow">SECURITY ADVISOR & GLOSSARY</span>
              <h2 className="drawer-main-title">Explain This Risk</h2>
            </div>
          </div>
          <button
            type="button"
            className="drawer-close-btn"
            onClick={onClose}
            aria-label="Close Security Explainer"
          >
            <X size={18} weight="bold" />
          </button>
        </div>

        {/* Tabs: Issues in Current Scan vs. Security Glossary */}
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
                      {item.title.split('(')[0].trim()}
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

        {/* Active Topic Body Content */}
        <div className="drawer-scroll-body">
          {/* Active Topic Header Card */}
          <div className="active-topic-card">
            <div className="topic-meta-row">
              <span className={`topic-severity-badge sev-${currentTopic.severity.toLowerCase()}`}>
                {currentTopic.severity} SEVERITY
              </span>
              <span className="topic-technical-term">
                Technical: <code>{currentTopic.technicalTerm}</code>
              </span>
            </div>
            <h3 className="topic-title">{currentTopic.title}</h3>
          </div>

          {/* Dynamic Live Telemetry Callout */}
          {liveTelemetry && (
            <div className="telemetry-live-callout">
              <div className="telemetry-live-header">
                <Pulse size={15} weight="bold" />
                <span>What We Found in Your URL</span>
              </div>
              <p className="telemetry-live-text">{liveTelemetry}</p>
            </div>
          )}

          {/* 4-Part Structured Educational Breakdown */}
          <div className="four-part-guide-stack">
            {/* Part 1: In Plain English */}
            <div className="four-part-card card-plain-english">
              <div className="part-header">
                <span className="part-icon-wrap icon-lightbulb">
                  <Lightbulb size={16} weight="bold" />
                </span>
                <span className="part-title">In Plain English</span>
              </div>
              <p className="part-text">{currentTopic.inPlainEnglish.definition}</p>
              {currentTopic.inPlainEnglish.analogy && (
                <div className="part-analogy-box">
                  <span className="analogy-label">💡 REAL-WORLD ANALOGY:</span>
                  <p className="analogy-text">{currentTopic.inPlainEnglish.analogy}</p>
                </div>
              )}
            </div>

            {/* Part 2: The Attacker's Trick */}
            <div className="four-part-card card-attacker-trick">
              <div className="part-header">
                <span className="part-icon-wrap icon-trick">
                  <MaskSad size={16} weight="bold" />
                </span>
                <span className="part-title">The Attacker's Trick</span>
              </div>
              <p className="part-text">{currentTopic.theAttackersTrick}</p>
            </div>

            {/* Part 3: What Could Happen to You */}
            <div className="four-part-card card-personal-danger">
              <div className="part-header">
                <span className="part-icon-wrap icon-danger">
                  <ShieldWarning size={16} weight="bold" />
                </span>
                <span className="part-title">What Could Happen to You</span>
              </div>

              <p className="part-text">{currentTopic.whatCouldHappenToYou}</p>
            </div>

            {/* Part 4: What You Should Do */}
            <div className="four-part-card card-action-advice">
              <div className="part-header">
                <span className="part-icon-wrap icon-shield">
                  <ShieldCheck size={16} weight="bold" />
                </span>
                <span className="part-title">What You Should Do</span>
              </div>
              <p className="part-text">{currentTopic.whatYouShouldDo}</p>
            </div>
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="drawer-footer-row">
          <span className="drawer-footer-note">
            <Info size={13} weight="bold" /> Passively verified in isolated cloud environment.
          </span>
          <button type="button" className="mech-btn" onClick={onClose}>
            Close Explainer
          </button>
        </div>
      </div>
    </div>
  )
}
